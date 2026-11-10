// Transport profiles and their protected credentials (schema v2,
// docs/TRANSPORT_PROFILES.md). The profile row carries the typed protocol/
// transport/security fields plus a credential REFERENCE; the secret itself
// lives in the secrets table of the same 0700-state SQLite store, is never
// returned by list/GET endpoints, never logged and never rendered into
// profile JSON. Migration from v1 is additive: existing links keep
// working (tcp = the legacy VLESS+TLS transit); udp links without an
// explicit hysteria2 profile are left untouched but refuse to render
// until the operator defines one — no silent credential guessing.
package controlstore

import (
	"encoding/json"
	"fmt"
	"time"

	"aravpn/core/transportprofile"
)

// TransportProfile is the stored row; validation is delegated to the
// core typed model so the store can never persist a combination the
// renderer would refuse.
type TransportProfile = transportprofile.Profile

func (s *Store) migrateTransport() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS transport_profiles (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL REFERENCES nodes(id),
			role TEXT NOT NULL CHECK (role IN ('ingress','transit')),
			protocol TEXT NOT NULL CHECK (protocol IN ('vless','trojan','hysteria2')),
			transport TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
			security TEXT NOT NULL CHECK (security IN ('tls','reality')),
			tls_json TEXT NOT NULL,
			credential_ref TEXT NOT NULL,
			created_at TEXT NOT NULL,
			revoked_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			ref TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate transport: %w", err)
		}
	}
	// schema_version bump after the additive migration; idempotent
	if _, err := s.db.Exec(`INSERT INTO schema_meta(key,value) VALUES ('schema_version','2')
		ON CONFLICT(key) DO UPDATE SET value='2' WHERE value<'2'`); err != nil {
		return err
	}
	return nil
}

// InsertTransportProfile stores an ALREADY-validated profile with a fixed
// id (the plan executor path: the plan was hashed with this exact id).
// Idempotent on the same id+content; a conflicting row is an error.
func (s *Store) InsertTransportProfile(p *TransportProfile, now time.Time) error {
	if p == nil || p.ID == "" {
		return fmt.Errorf("VALIDATION_FAILED: profile and id are required")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if p.CredentialRef == "" {
		p.CredentialRef = TransitSecretRef(p.ID)
	}
	tlsJSON, err := json.Marshal(p.TLS)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO transport_profiles(id, node_id, role, protocol, transport, security, tls_json, credential_ref, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO NOTHING`,
		p.ID, p.NodeID, string(p.Role), string(p.Protocol), string(p.Transport), string(p.Security),
		string(tlsJSON), p.CredentialRef, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	cur, err := s.GetTransportProfile(p.ID)
	if err != nil {
		return err
	}
	if cur.Protocol != p.Protocol || cur.Security != p.Security || cur.NodeID != p.NodeID {
		return fmt.Errorf("CONFLICT: transport profile %s exists with different content", p.ID)
	}
	return nil
}

// AddTransportProfileWithID stores an already-validated profile keeping
// the caller's stable id (declarative topology: doc ref → stable id).
func (s *Store) AddTransportProfileWithID(p *TransportProfile, now time.Time) (*TransportProfile, error) {
	if p == nil || p.ID == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: profile id is required")
	}
	p.CredentialRef = TransitSecretRef(p.ID)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Role != transportprofile.RoleTransit {
		return nil, fmt.Errorf("VALIDATION_FAILED: control store accepts transit profiles only (got %s)", p.Role)
	}
	var nodeExists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=? AND revoked_at IS NULL`, p.NodeID).Scan(&nodeExists); err != nil {
		return nil, err
	}
	if nodeExists == 0 {
		return nil, fmt.Errorf("VALIDATION_FAILED: unknown or revoked node %q", p.NodeID)
	}
	tlsJSON, err := json.Marshal(p.TLS)
	if err != nil {
		return nil, err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	_, err = s.db.Exec(`INSERT INTO transport_profiles(id, node_id, role, protocol, transport, security, tls_json, credential_ref, created_at)
		VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		p.ID, p.NodeID, string(p.Role), string(p.Protocol), string(p.Transport), string(p.Security),
		string(tlsJSON), p.CredentialRef, p.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	return s.GetTransportProfile(p.ID)
}

// NodeExists reports whether an active node with this id exists.
func (s *Store) NodeExists(id string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=? AND revoked_at IS NULL`, id).Scan(&n)
	return n > 0, err
}

const transitSecretPrefix = "arasec://transit/"

// TransitSecretRef is the credential reference for a transit profile.
func TransitSecretRef(profileID string) string { return transitSecretPrefix + profileID }

// AddTransportProfile validates and stores one profile. The credential
// reference is derived from the profile id; the secret value is set
// separately via SetTransitSecret.
func (s *Store) AddTransportProfile(p *TransportProfile) (*TransportProfile, error) {
	if p == nil {
		return nil, fmt.Errorf("VALIDATION_FAILED: profile is required")
	}
	id, err := randomID("tp")
	if err != nil {
		return nil, err
	}
	p.ID = id
	p.CredentialRef = TransitSecretRef(p.ID)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Role != transportprofile.RoleTransit {
		// the control store manages exit-side transit profiles; client
		// ingress profiles live in the client profile store
		return nil, fmt.Errorf("VALIDATION_FAILED: control store accepts transit profiles only (got %s)", p.Role)
	}
	var nodeExists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=? AND revoked_at IS NULL`, p.NodeID).Scan(&nodeExists); err != nil {
		return nil, err
	}
	if nodeExists == 0 {
		return nil, fmt.Errorf("VALIDATION_FAILED: unknown or revoked node %q", p.NodeID)
	}
	tlsJSON, err := json.Marshal(p.TLS)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO transport_profiles(id, node_id, role, protocol, transport, security, tls_json, credential_ref, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		p.ID, p.NodeID, string(p.Role), string(p.Protocol), string(p.Transport), string(p.Security),
		string(tlsJSON), p.CredentialRef, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GetTransportProfile loads one active (or revoked) profile.
func (s *Store) GetTransportProfile(id string) (*TransportProfile, error) {
	row := s.db.QueryRow(`SELECT id, node_id, role, protocol, transport, security, tls_json, credential_ref, created_at, COALESCE(revoked_at,'')
		FROM transport_profiles WHERE id=?`, id)
	return scanTransportProfile(row.Scan)
}

// ListTransportProfiles returns profiles, optionally filtered by node.
func (s *Store) ListTransportProfiles(nodeID string) ([]TransportProfile, error) {
	q := `SELECT id, node_id, role, protocol, transport, security, tls_json, credential_ref, created_at, COALESCE(revoked_at,'')
		FROM transport_profiles`
	args := []any{}
	if nodeID != "" {
		q += ` WHERE node_id=?`
		args = append(args, nodeID)
	}
	q += ` ORDER BY created_at`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TransportProfile
	for rows.Next() {
		p, err := scanTransportProfile(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func scanTransportProfile(scan func(dest ...any) error) (*TransportProfile, error) {
	var p TransportProfile
	var role, protocol, transport, security, tlsJSON, created, revoked string
	if err := scan(&p.ID, &p.NodeID, &role, &protocol, &transport, &security, &tlsJSON, &p.CredentialRef, &created, &revoked); err != nil {
		return nil, err
	}
	p.Role = transportprofile.Role(role)
	p.Protocol = transportprofile.Protocol(protocol)
	p.Transport = transportprofile.Transport(transport)
	p.Security = transportprofile.Security(security)
	if tlsJSON != "" && tlsJSON != "null" {
		p.TLS = &transportprofile.TLS{}
		if err := json.Unmarshal([]byte(tlsJSON), p.TLS); err != nil {
			return nil, fmt.Errorf("transport profile %s: tls_json: %w", p.ID, err)
		}
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if revoked != "" {
		t, _ := time.Parse(time.RFC3339Nano, revoked)
		p.RevokedAt = &t
	}
	return &p, nil
}

// RevokeTransportProfile soft-revokes the profile. Links referencing it
// keep their reference but fail validation on use (revoked profile),
// which is the honest state: nothing is silently re-pointed.
func (s *Store) RevokeTransportProfile(id string) error {
	res, err := s.db.Exec(`UPDATE transport_profiles SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("VALIDATION_FAILED: transport profile %q not found or already revoked", id)
	}
	return nil
}

// SetTransitSecret stores the credential value for a transit profile
// reference. The profile row itself may not exist yet: secrets are staged
// at PLAN time while the profile row is created at APPLY time; the
// executor's Check verifies the staged secret before inserting the
// profile. The value is stored as given (rotation replaces it).
func (s *Store) SetTransitSecret(profileID, value string) error {
	if profileID == "" || value == "" {
		return fmt.Errorf("VALIDATION_FAILED: profile id and value are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO secrets(ref, value, created_at, updated_at) VALUES (?,?,?,?)
		ON CONFLICT(ref) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		TransitSecretRef(profileID), value, now, now)
	return err
}

// TransitSecret resolves the credential reference. Callers keep the value
// in memory only and render it exclusively into 0600 engine configs.
func (s *Store) TransitSecret(profileID string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM secrets WHERE ref=?`, TransitSecretRef(profileID)).Scan(&value)
	if err != nil {
		return "", fmt.Errorf("VALIDATION_FAILED: no credential stored for profile %s", profileID)
	}
	return value, nil
}

// DeleteTransitSecret removes the credential (used when a profile is
// deleted in tests or rotated out).
func (s *Store) DeleteTransitSecret(profileID string) error {
	_, err := s.db.Exec(`DELETE FROM secrets WHERE ref=?`, TransitSecretRef(profileID))
	return err
}

// SchemaVersion returns the stored schema version (0 = absent).
func (s *Store) SchemaVersion() (int, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&v)
	if err != nil {
		return 0, err
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}
