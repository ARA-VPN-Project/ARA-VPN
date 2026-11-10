// Package controlstore is the control plane's local persistence: nodes,
// devices and enrollment state in SQLite (WAL), plus an append-only audit
// trail. One control service with a local DB is the documented MVP shape —
// no external database (docs/PRIORITIES.md).
package controlstore

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite handle.
type Store struct {
	db *sql.DB
}

// Open creates/opens the control database with WAL mode and busy timeout.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// SQLite is single-writer: serialize in-process access through ONE
	// connection (concurrent federation reports otherwise hit BUSY on
	// lock upgrade); cross-process access is covered by busy_timeout.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateInvites(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateLinks(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateTransport(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateFederation(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateProfileBudgets(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateRotateGrace(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateSubscriptionActivity(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateAccountArchive(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_meta (
			key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			notes TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES accounts(id),
			name TEXT NOT NULL,
			created_at TEXT NOT NULL,
			revoked_at TEXT,
			enrollment_used_at TEXT,
			identity_pubkey TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			country TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('ru','foreign')),
			priority INTEGER NOT NULL DEFAULT 100,
			created_at TEXT NOT NULL,
			revoked_at TEXT,
			identity_pubkey TEXT NOT NULL DEFAULT '')`,
		`INSERT OR IGNORE INTO schema_meta(key,value) VALUES ('schema_version','1')`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// columns added after the first release: tolerate existing databases
	_, _ = s.db.Exec(`ALTER TABLE devices ADD COLUMN vless_uuid TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE nodes ADD COLUMN ingress_addr TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE nodes ADD COLUMN ingress_sni TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE nodes ADD COLUMN remote_panel TEXT NOT NULL DEFAULT ''`)
	return nil
}

// Account is a billing/limits scope.
type Account struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Notes     string    `json:"notes,omitempty"`
}

// Device is one enrolled client identity under an account.
type Device struct {
	ID          string     `json:"id"`
	AccountID   string     `json:"account_id"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	IdentityPub string     `json:"identity_pubkey,omitempty"`
	VlessUUID   string     `json:"vless_uuid,omitempty"`
	ExpiresUnix int64      `json:"expires_unix,omitempty"`
}

// Node is one exit/edge node in the registry. IngressAddr non-empty means
// the node ALSO accepts client VPN connections (role vs country vs
// ingress are independent: a DE node can be ingress+exit — a "direct"
// profile — while an RU node is the transit hub ingress).
type Node struct {
	ID          string     `json:"id"`
	Country     string     `json:"country"`
	Role        string     `json:"role"`
	Priority    int        `json:"priority"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	IdentityPub string     `json:"identity_pubkey,omitempty"`
	IngressAddr string     `json:"ingress_addr,omitempty"`
	IngressSNI  string     `json:"ingress_sni,omitempty"`
	RemotePanel string     `json:"remote_panel,omitempty"` // federation origin
}

// CreateAccount registers an account scope.
func (s *Store) CreateAccount(id, notes string) (*Account, error) {
	if id == "" || strings.ContainsAny(id, " \t/") {
		return nil, fmt.Errorf("VALIDATION_FAILED: invalid account id")
	}
	_, err := s.db.Exec(`INSERT INTO accounts(id, created_at, notes) VALUES (?,?,?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), notes)
	if err != nil {
		return nil, err
	}
	return &Account{ID: id, CreatedAt: time.Now().UTC(), Notes: notes}, nil
}

// CreateDevice enrolls a device and returns a one-time enrollment secret.
// The secret is returned exactly once and is never stored in plaintext
// (docs/SECURITY.md: bootstrap invitation one-time, short TTL).
func (s *Store) CreateDevice(accountID, name string) (*Device, string, error) {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE id=?`, accountID).Scan(&exists); err != nil {
		return nil, "", err
	}
	if exists == 0 {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: unknown account %q", accountID)
	}
	devID, err := randomID("dev")
	if err != nil {
		return nil, "", err
	}
	secret, err := randomSecret(32)
	if err != nil {
		return nil, "", err
	}
	uuid, err := randomSecret(16)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(`INSERT INTO devices(id, account_id, name, created_at, identity_pubkey, vless_uuid) VALUES (?,?,?,?,?,?)`,
		devID, accountID, name, now.Format(time.RFC3339Nano), "sha256:"+sha256Hex(secret), formatUUID(uuid))
	if err != nil {
		return nil, "", err
	}
	return &Device{ID: devID, AccountID: accountID, Name: name, CreatedAt: now, VlessUUID: formatUUID(uuid)}, secret, nil
}

// formatUUID renders 16 random bytes as the canonical 8-4-4-4-12 form.
// B09: all 16 RANDOM BYTES are used directly (their hex representation) —
// the previous version hex-encoded the hex string again, halving entropy.
func formatUUID(b string) string {
	if len(b) < 16 {
		return ""
	}
	// b is the 32-char lowercase hex of the 16 random bytes: all 128 bits
	// of entropy are spread across the canonical 8-4-4-4-12 form.
	h := b
	if len(h) < 32 {
		return ""
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ConsumeEnrollment atomically marks the device's one-time enrollment as
// used (review R02). The check-then-set is a single conditional UPDATE
// guarded by revoked_at IS NULL AND enrollment_used_at IS NULL AND the
// secret hash; exactly one concurrent caller can match (RowsAffected==1).
// The uniform refusal message deliberately does not reveal which
// condition failed — wrong secret, replay and revoked device are
// indistinguishable to the caller.
func (s *Store) ConsumeEnrollment(deviceID, secret string) error {
	if deviceID == "" || secret == "" {
		return fmt.Errorf("AUTH_FAILED: enrollment refused")
	}
	res, err := s.db.Exec(
		`UPDATE devices SET enrollment_used_at=?
		 WHERE id=? AND revoked_at IS NULL AND enrollment_used_at IS NULL
		   AND identity_pubkey=? AND (expires_unix=0 OR expires_unix>unixepoch())`,
		time.Now().UTC().Format(time.RFC3339Nano), deviceID, "sha256:"+sha256Hex(secret))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("AUTH_FAILED: enrollment refused")
	}
	return nil
}

// RevokeDevice marks the device revoked; existing sessions must be
// terminated by the data plane within the documented revoke latency.
func (s *Store) RevokeDevice(id string) error {
	res, err := s.db.Exec(`UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("VALIDATION_FAILED: device %q not found or already revoked", id)
	}
	return nil
}

func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT id, account_id, name, created_at, revoked_at, identity_pubkey, COALESCE(vless_uuid,''), expires_unix FROM devices ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var created string
		var revoked *string
		if err := rows.Scan(&d.ID, &d.AccountID, &d.Name, &created, &revoked, &d.IdentityPub, &d.VlessUUID, &d.ExpiresUnix); err != nil {
			return nil, err
		}
		d.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if revoked != nil {
			t, _ := time.Parse(time.RFC3339Nano, *revoked)
			d.RevokedAt = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddNode registers an exit node (no ingress).
func (s *Store) AddNode(id, country, role string, priority int) (*Node, error) {
	return s.AddNodeFull(id, country, role, priority, "", "")
}

// AddNodeFull registers a node with optional client ingress.
func (s *Store) AddNodeFull(id, country, role string, priority int, ingressAddr, ingressSNI string) (*Node, error) {
	if role != "ru" && role != "foreign" {
		return nil, fmt.Errorf("VALIDATION_FAILED: role must be ru|foreign")
	}
	if id == "" || strings.ContainsAny(id, " \t/") {
		return nil, fmt.Errorf("VALIDATION_FAILED: invalid node id")
	}
	_, err := s.db.Exec(`INSERT INTO nodes(id, country, role, priority, created_at, ingress_addr, ingress_sni) VALUES (?,?,?,?,?,?,?)`,
		id, country, role, priority, time.Now().UTC().Format(time.RFC3339Nano), ingressAddr, ingressSNI)
	if err != nil {
		return nil, err
	}
	return &Node{ID: id, Country: country, Role: role, Priority: priority, CreatedAt: time.Now().UTC(),
		IngressAddr: ingressAddr, IngressSNI: ingressSNI}, nil
}

// GetNode returns one active node.
func (s *Store) GetNode(id string) (*Node, error) {
	rows, err := s.db.Query(`SELECT id, country, role, priority, created_at, revoked_at, identity_pubkey, ingress_addr, ingress_sni, remote_panel FROM nodes WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("VALIDATION_FAILED: node %q not found", id)
	}
	return scanNode(rows)
}

// SetNodeIngress enables/disables the client ingress of a node.
func (s *Store) SetNodeIngress(id, addr, sni string) error {
	if addr != "" {
		host, port, err := net.SplitHostPort(addr)
		number, numberErr := strconv.Atoi(port)
		if err != nil || numberErr != nil || host == "" || strings.ContainsAny(host, " /\t\r\n") || number < 1 || number > 65535 {
			return fmt.Errorf("VALIDATION_FAILED: ingress address must be host:port")
		}
	} else {
		sni = ""
	}
	if strings.ContainsAny(sni, " /\t\r\n") {
		return fmt.Errorf("VALIDATION_FAILED: TLS SNI must be a certificate name")
	}
	res, err := s.db.Exec(`UPDATE nodes SET ingress_addr=?, ingress_sni=? WHERE id=? AND revoked_at IS NULL AND COALESCE(remote_panel,'')=''`, addr, sni, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("VALIDATION_FAILED: node %q not found", id)
	}
	return nil
}

// UpsertRemoteNode stores a federation-shared node (origin panel recorded;
// never overwrites a local node's identity fields).
func (s *Store) UpsertRemoteNode(n *Node, panelID string) error {
	if n.ID == "" || (n.Role != "ru" && n.Role != "foreign") {
		return fmt.Errorf("VALIDATION_FAILED: remote node incomplete")
	}
	var exists int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=?`, n.ID).Scan(&exists)
	if exists == 1 {
		var owner string
		_ = s.db.QueryRow(`SELECT remote_panel FROM nodes WHERE id=?`, n.ID).Scan(&owner)
		if owner != panelID {
			return fmt.Errorf("CONFLICT: node %s already exists locally (not owned by panel %s)", n.ID, panelID)
		}
		_, err := s.db.Exec(`UPDATE nodes SET country=?, role=?, priority=?, ingress_addr=?, ingress_sni=?, remote_panel=? WHERE id=?`,
			n.Country, n.Role, n.Priority, n.IngressAddr, n.IngressSNI, panelID, n.ID)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO nodes(id, country, role, priority, created_at, ingress_addr, ingress_sni, remote_panel) VALUES (?,?,?,?,?,?,?,?)`,
		n.ID, n.Country, n.Role, n.Priority, time.Now().UTC().Format(time.RFC3339Nano), n.IngressAddr, n.IngressSNI, panelID)
	return err
}

// QueryRow is the narrow escape hatch for single-value reads by the
// service layer.
func (s *Store) QueryRow(q string, arg any, dest *string) error {
	return s.db.QueryRow(q, arg).Scan(dest)
}

// Exec is the narrow escape hatch for service-layer cross-table updates.
func (s *Store) Exec(q string, args ...any) (any, error) {
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// RevokeNode quarantines a node from new assignments.
func (s *Store) RevokeNode(id string) error {
	res, err := s.db.Exec(`UPDATE nodes SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("VALIDATION_FAILED: node %q not found or already revoked", id)
	}
	return nil
}

func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT id, country, role, priority, created_at, revoked_at, identity_pubkey, ingress_addr, ingress_sni, remote_panel FROM nodes ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func scanNode(rows rowScanner) (*Node, error) {
	var n Node
	var created string
	var revoked *string
	if err := rows.Scan(&n.ID, &n.Country, &n.Role, &n.Priority, &created, &revoked, &n.IdentityPub, &n.IngressAddr, &n.IngressSNI, &n.RemotePanel); err != nil {
		return nil, err
	}
	n.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if revoked != nil {
		t, _ := time.Parse(time.RFC3339Nano, *revoked)
		n.RevokedAt = &t
	}
	return &n, nil
}

func randomID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(b[:]), nil
}

// RandomSecret exposes the crypto-random secret generator (hex) for
// service-layer credential issuance; the caller stores only its hash.
func RandomSecret(n int) (string, error) { return randomSecret(n) }

// RandomID exposes the store's identifier generator for service-layer
// objects (transport profiles) whose plan is hashed before insert.
func RandomID(prefix string) (string, error) { return randomID(prefix) }

func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
