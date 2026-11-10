// Federation and shared subscriptions (docs/FEDERATION.md): panel links
// (one-time invites, stored public keys, limited scopes, revocation),
// multi-profile HTTPS subscriptions with ONE authoritative owner panel,
// per-subscription quota ledger shared by every serving node, and
// ownership transfer that moves identity/devices/limits/usage atomically
// — a copied user with a fresh budget is structurally impossible because
// the used-bytes ledger travels WITH the subscription.
package controlstore

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

func (s *Store) migrateFederation() error {
	if err := s.migrateRoutePorts(); err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS link_invites (
			token_hash TEXT PRIMARY KEY,
			invited_panel TEXT NOT NULL,
			scopes TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			used_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS linked_panels (
			panel_id TEXT PRIMARY KEY,
			public_key TEXT NOT NULL,
			scopes TEXT NOT NULL,
			linked_at TEXT NOT NULL,
			revoked_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS subscriptions (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES accounts(id),
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			owner_panel TEXT NOT NULL,
			limits_bytes INTEGER,
			created_at TEXT NOT NULL,
			expires_at TEXT,
			revoked_at TEXT,
			transferred_to TEXT)`,
		`CREATE TABLE IF NOT EXISTS hidden_subscriptions (
			subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id))`,
		`CREATE TABLE IF NOT EXISTS subscription_profiles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
			seq INTEGER NOT NULL,
			label_ru TEXT NOT NULL,
			label_en TEXT NOT NULL,
			kind TEXT NOT NULL CHECK (kind IN ('direct','transit')),
			node_id TEXT NOT NULL,
			ingress_addr TEXT NOT NULL,
			sni TEXT NOT NULL,
			protocol TEXT NOT NULL,
			created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sub_quota (
			subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id),
			used_bytes INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sub_leases (
			id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL,
			holder TEXT NOT NULL,
			device_id TEXT NOT NULL DEFAULT '',
			amount INTEGER NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('issued','consumed','closed')),
			epoch TEXT NOT NULL,
			issued_at TEXT NOT NULL,
			expires_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_sub_leases_sub ON sub_leases(subscription_id, state)`,
		`CREATE TABLE IF NOT EXISTS fed_ops (
			op_key TEXT PRIMARY KEY,
			response_json TEXT NOT NULL,
			created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sub_quota_device (
			subscription_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			used_bytes INTEGER NOT NULL DEFAULT 0,
			limit_bytes INTEGER,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (subscription_id, device_id))`,
		`CREATE TABLE IF NOT EXISTS sub_rate (
			subscription_id TEXT PRIMARY KEY,
			download_bps INTEGER,
			upload_bps INTEGER,
			updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS edge_configs (
			panel_id TEXT PRIMARY KEY,
			config_json TEXT NOT NULL,
			config_hash TEXT NOT NULL,
			updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS edge_sub_delegation (
			panel_id TEXT NOT NULL,
			subscription_id TEXT NOT NULL,
			granted_by TEXT NOT NULL,
			granted_at TEXT NOT NULL,
			PRIMARY KEY (panel_id, subscription_id))`,
		`CREATE TABLE IF NOT EXISTS sub_migrations (
			migration_id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL,
			from_panel TEXT NOT NULL,
			to_panel TEXT NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('prepared','committed','activated')),
			snapshot_used INTEGER NOT NULL DEFAULT 0,
			final_used INTEGER,
			created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sub_rate_rights (
			subscription_id TEXT NOT NULL,
			holder TEXT NOT NULL,
			down_bps INTEGER NOT NULL,
			up_bps INTEGER NOT NULL,
			expires_at TEXT NOT NULL,
			PRIMARY KEY (subscription_id, holder))`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate federation: %w", err)
		}
	}
	// subscriptions.active: 0 = imported pending authority switch
	_, _ = s.db.Exec(`ALTER TABLE subscriptions ADD COLUMN active INTEGER NOT NULL DEFAULT 1`)
	// fed_ops.op_digest (B02/interim): digest of the operation content
	// bound to the stable op identity; a different body under the same
	// identity is a CONFLICT, not a new operation.
	_, _ = s.db.Exec(`ALTER TABLE fed_ops ADD COLUMN op_digest TEXT NOT NULL DEFAULT ''`)
	// subscription_profiles.route_port (B23): dedicated Edge access port
	// pinned to the profile's route (0 = default access endpoint).
	_, _ = s.db.Exec(`ALTER TABLE subscription_profiles ADD COLUMN route_port INTEGER NOT NULL DEFAULT 0`)
	// subscriptions.fetch_base: the target panel's public base URL, set at
	// transfer; the moved notice points installed clients there (client
	// auto-follow, docs/FEDERATION.md)
	_, _ = s.db.Exec(`ALTER TABLE subscriptions ADD COLUMN fetch_base TEXT NOT NULL DEFAULT ''`)
	return s.migrateDeviceSlots()
}

// ---- panel links ----

func HashToken(tok string) string { h := sha256.Sum256([]byte(tok)); return hex.EncodeToString(h[:]) }

// CreateLinkInvite stores a one-time federation invite (hashed) and
// returns the plaintext token once.
func (s *Store) CreateLinkInvite(invitedPanel, scopes string, ttl time.Duration) (string, error) {
	tok, err := randomSecret(24)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(`INSERT INTO link_invites(token_hash, invited_panel, scopes, created_at, expires_at)
		VALUES (?,?,?,?,?)`, HashToken(tok), invitedPanel, scopes,
		now.Format(time.RFC3339Nano), now.Add(ttl).Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	return tok, nil
}

// RedeemLinkInvite atomically consumes the invite and registers the
// linking panel. Unknown/expired/used/revoked are one uniform refusal.
func (s *Store) RedeemLinkInvite(token, panelID, pubKey string) (string, error) {
	if token == "" || panelID == "" || pubKey == "" {
		return "", fmt.Errorf("AUTH_FAILED: link invite refused")
	}
	now := time.Now().UTC()
	res, err := s.db.Exec(`UPDATE link_invites SET used_at=?
		WHERE token_hash=? AND used_at IS NULL AND expires_at > ?`,
		now.Format(time.RFC3339Nano), HashToken(token), now.Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", fmt.Errorf("AUTH_FAILED: link invite refused")
	}
	// B07: the invite is bound to the invited panel id recorded at
	// creation; a different panel redeeming the token is refused BEFORE
	// any state changes.
	var scopes, invited string
	if err := s.db.QueryRow(`SELECT scopes, invited_panel FROM link_invites WHERE token_hash=?`, HashToken(token)).Scan(&scopes, &invited); err != nil {
		return "", err
	}
	if invited != "" && invited != panelID {
		return "", fmt.Errorf("AUTH_FAILED: link invite was issued for panel %q, not %q", invited, panelID)
	}
	// an already-trusted link is never silently re-keyed/revoked-reset by
	// an unrelated invite: re-link/key rotation is a separate explicit op.
	var existingPub string
	var existingRevoked any
	if err := s.db.QueryRow(`SELECT public_key, revoked_at FROM linked_panels WHERE panel_id=?`, panelID).Scan(&existingPub, &existingRevoked); err == nil && existingPub != "" {
		return "", fmt.Errorf("CONFLICT: panel %q is already linked with a different key; revoke it explicitly before re-linking", panelID)
	}
	if _, err := s.db.Exec(`INSERT INTO linked_panels(panel_id, public_key, scopes, linked_at) VALUES (?,?,?,?)
		ON CONFLICT(panel_id) DO UPDATE SET public_key=excluded.public_key, scopes=excluded.scopes`,
		panelID, pubKey, scopes, now.Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	return scopes, nil
}

// AddLinkedPanel registers a link locally (the redeeming side stores the
// inviting panel's identity from the redeem response — the link is MUTUAL:
// both panels can call each other with their own keys).
func (s *Store) AddLinkedPanel(panelID, pubKey, scopes string) error {
	if panelID == "" || pubKey == "" {
		return fmt.Errorf("VALIDATION_FAILED: panel id and public key are required")
	}
	_, err := s.db.Exec(`INSERT INTO linked_panels(panel_id, public_key, scopes, linked_at) VALUES (?,?,?,?)
		ON CONFLICT(panel_id) DO UPDATE SET public_key=excluded.public_key, scopes=excluded.scopes, revoked_at=NULL`,
		panelID, pubKey, scopes, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// LinkedPanelPubKey returns (public_key, scopes) for an active link.
func (s *Store) LinkedPanelPubKey(panelID string) (string, string, error) {
	var pub, scopes string
	err := s.db.QueryRow(`SELECT public_key, scopes FROM linked_panels WHERE panel_id=? AND revoked_at IS NULL`, panelID).
		Scan(&pub, &scopes)
	if err != nil {
		return "", "", fmt.Errorf("AUTH_FAILED: panel %q is not linked", panelID)
	}
	return pub, scopes, nil
}

// ListLinkedPanels returns all links (including revoked, for the panel UI).
type PanelLink struct {
	PanelID   string     `json:"panel_id"`
	PublicKey string     `json:"public_key"`
	Scopes    string     `json:"scopes"`
	LinkedAt  time.Time  `json:"linked_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) ListLinkedPanels() ([]PanelLink, error) {
	rows, err := s.db.Query(`SELECT panel_id, public_key, scopes, linked_at, COALESCE(revoked_at,'') FROM linked_panels ORDER BY linked_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PanelLink
	for rows.Next() {
		var p PanelLink
		var at, rev string
		if err := rows.Scan(&p.PanelID, &p.PublicKey, &p.Scopes, &at, &rev); err != nil {
			return nil, err
		}
		p.LinkedAt, _ = time.Parse(time.RFC3339Nano, at)
		if rev != "" {
			t, _ := time.Parse(time.RFC3339Nano, rev)
			p.RevokedAt = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokeLinkedPanel tears the link down; the remote panel is disabled on
// FIRST refusal locally even if the remote call fails.
func (s *Store) RevokeLinkedPanel(panelID string) error {
	res, err := s.db.Exec(`UPDATE linked_panels SET revoked_at=? WHERE panel_id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), panelID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("VALIDATION_FAILED: link %q not found or already revoked", panelID)
	}
	return nil
}

// ---- subscriptions ----

// Subscription is one shared multi-profile user subscription.
type Subscription struct {
	MaxDevices    *int       `json:"max_devices,omitempty"`
	ID            string     `json:"id"`
	AccountID     string     `json:"account_id"`
	Name          string     `json:"name"`
	OwnerPanel    string     `json:"owner_panel"`
	LimitsBytes   *int64     `json:"limits_bytes,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	TransferredTo string     `json:"transferred_to,omitempty"`
	// UsedBytes is the shared ledger value (filled by list/get helpers).
	UsedBytes int64 `json:"used_bytes,omitempty"`
	// Active=false marks an IMPORTED-PENDING copy (ownership transfer in
	// flight): it exists durably but is NOT an authority until activated.
	Active *bool `json:"active,omitempty"`
	// Transfer payload extras (device usage/limits and shared rate travel
	// with the subscription; never reset by the move).
	PrimaryDeviceID string            `json:"primary_device_id,omitempty"`
	DeviceUsage     map[string]int64  `json:"device_usage,omitempty"`
	DeviceLimits    map[string]*int64 `json:"device_limits,omitempty"`
	RateDownBPS     *int64            `json:"rate_down_bps,omitempty"`
	RateUpBPS       *int64            `json:"rate_up_bps,omitempty"`
}

// SubscriptionProfile is one catalog entry (direct or transit).
type SubscriptionProfile struct {
	SourcePanel string `json:"source_panel,omitempty"`
	EdgeNodeID  string `json:"edge_node_id,omitempty"`
	LimitBytes  *int64 `json:"limit_bytes,omitempty"`
	Seq         int    `json:"seq"`
	LabelRU     string `json:"label_ru"`
	LabelEn     string `json:"label_en"`
	Kind        string `json:"kind"` // direct | transit
	NodeID      string `json:"node_id"`
	IngressAddr string `json:"ingress_addr"`
	SNI         string `json:"sni"`
	Protocol    string `json:"protocol"`
	// SubscriptionID is filled by all-rows listings (route grants).
	SubscriptionID string `json:"subscription_id,omitempty"`
	// RoutePort (B23): the dedicated Edge access port pinned to THIS
	// route (ingress+exit binding on the wire). 0 = the Edge's default
	// access endpoint with policy-selected exit.
	RoutePort   int    `json:"route_port,omitempty"`
	DownloadBPS *int64 `json:"download_bps,omitempty"`
	UploadBPS   *int64 `json:"upload_bps,omitempty"`
}

// CreateSubscription registers the subscription; ownerPanel is the
// AUTHORITATIVE state owner. Token is returned once.
func (s *Store) CreateSubscription(accountID, name, ownerPanel string, limitsBytes *int64, ttl time.Duration) (*Subscription, string, error) {
	return s.CreateSubscriptionWithProfiles(accountID, name, ownerPanel, limitsBytes, ttl, nil, nil)
}

func (s *Store) CreateSubscriptionWithProfiles(accountID, name, ownerPanel string, limitsBytes *int64, ttl time.Duration, maxDevices *int, profiles []SubscriptionProfile) (*Subscription, string, error) {
	return s.createSubscription(accountID, name, ownerPanel, limitsBytes, ttl, maxDevices, profiles, false)
}

// ProvisionLocalSubscription issues a dedicated credential in the same transaction as the account and catalog.
func (s *Store) ProvisionLocalSubscription(accountID, name, ownerPanel string, limitsBytes *int64, ttl time.Duration, maxDevices *int, profiles []SubscriptionProfile) (*Subscription, string, error) {
	return s.createSubscription(accountID, name, ownerPanel, limitsBytes, ttl, maxDevices, profiles, true)
}

func (s *Store) createSubscription(accountID, name, ownerPanel string, limitsBytes *int64, ttl time.Duration, maxDevices *int, profiles []SubscriptionProfile, provision bool) (*Subscription, string, error) {
	if limitsBytes != nil && *limitsBytes < 0 {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: subscription quota must be non-negative")
	}
	if maxDevices != nil && *maxDevices <= 0 {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: max_devices must be positive")
	}
	if provision {
		if accountID == "" || len(accountID) > 80 || strings.ContainsAny(accountID, " \t\r\n/") || strings.TrimSpace(name) == "" {
			return nil, "", fmt.Errorf("VALIDATION_FAILED: account and subscription name required")
		}
	} else {
		var acc int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE id=?`, accountID).Scan(&acc); err != nil {
			return nil, "", err
		}
		if acc == 0 {
			return nil, "", fmt.Errorf("VALIDATION_FAILED: unknown account %q", accountID)
		}
	}
	if ownerPanel == "" {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: owner_panel is required")
	}
	id, err := randomID("sub")
	if err != nil {
		return nil, "", err
	}
	token, err := randomSecret(24)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	var exp any
	if ttl > 0 {
		exp = now.Add(ttl).Format(time.RFC3339Nano)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var primary string
	if provision {
		if _, err := tx.Exec(`INSERT INTO accounts(id, created_at) VALUES (?,?) ON CONFLICT(id) DO NOTHING`, accountID, now.Format(time.RFC3339Nano)); err != nil {
			return nil, "", err
		}
		primary, err = randomID("dev")
		if err != nil {
			return nil, "", err
		}
		uuid, err := randomSecret(16)
		if err != nil {
			return nil, "", err
		}
		if _, err := tx.Exec(`INSERT INTO devices(id, account_id, name, created_at, vless_uuid) VALUES (?,?,?,?,?)`,
			primary, accountID, name, now.Format(time.RFC3339Nano), formatUUID(uuid)); err != nil {
			return nil, "", err
		}
	}
	if _, err := tx.Exec(`INSERT INTO subscriptions(id, account_id, name, token_hash, owner_panel, limits_bytes, created_at, expires_at, max_devices, primary_device_id)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, id, accountID, name, HashToken(token), ownerPanel, limitsBytes,
		now.Format(time.RFC3339Nano), exp, maxDevices, primary); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(`INSERT INTO sub_quota(subscription_id, used_bytes, updated_at) VALUES (?,?,?)`,
		id, 0, now.Format(time.RFC3339Nano)); err != nil {
		return nil, "", err
	}
	if err := replaceSubscriptionProfiles(tx, id, profiles); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	sub := &Subscription{ID: id, AccountID: accountID, Name: name, OwnerPanel: ownerPanel,
		LimitsBytes: limitsBytes, MaxDevices: maxDevices, CreatedAt: now}
	if ttl > 0 {
		t := now.Add(ttl)
		sub.ExpiresAt = &t
	}
	return sub, token, nil
}

func scanSubscription(scan func(...any) error) (*Subscription, error) {
	var sub Subscription
	var created, exp, rev string
	var active int
	if err := scan(&sub.ID, &sub.AccountID, &sub.Name, &sub.OwnerPanel, &sub.LimitsBytes, &created, &exp, &rev, &sub.TransferredTo, &active, &sub.MaxDevices, &sub.PrimaryDeviceID); err != nil {
		return nil, err
	}
	a := active != 0
	sub.Active = &a

	sub.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if exp != "" {
		t, _ := time.Parse(time.RFC3339Nano, exp)
		sub.ExpiresAt = &t
	}
	if rev != "" {
		t, _ := time.Parse(time.RFC3339Nano, rev)
		sub.RevokedAt = &t
	}
	return &sub, nil
}

const subCols = `id, account_id, name, owner_panel, limits_bytes, created_at, COALESCE(expires_at,''), COALESCE(revoked_at,''), COALESCE(transferred_to,''), active, max_devices, primary_device_id`

// CreateSubscriptionImported inserts a FULL subscription document with a
// fixed id and the SAME token hash (federation transfer: identity, token,
// limits and usage travel with the user; the new panel becomes the
// authoritative owner). A copied user with a fresh budget is impossible:
// the used-bytes ledger is part of this insert.
func (s *Store) CreateSubscriptionImported(sub *Subscription, tokenHash string) error {
	if sub.ID == "" || sub.AccountID == "" || sub.OwnerPanel == "" || tokenHash == "" {
		return fmt.Errorf("VALIDATION_FAILED: imported subscription incomplete")
	}
	created := sub.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	var exp any
	if sub.ExpiresAt != nil {
		exp = sub.ExpiresAt.Format(time.RFC3339Nano)
	}
	// idempotent re-import: a PENDING copy is updated in place; an ACTIVE
	// copy means the transfer already committed — refuse (no divergence)
	var active int
	var existingOwner string
	err := s.db.QueryRow(`SELECT active, owner_panel FROM subscriptions WHERE id=?`, sub.ID).Scan(&active, &existingOwner)
	if err == nil {
		if active == 1 {
			return fmt.Errorf("CONFLICT: subscription %s already active on this panel", sub.ID)
		}
		if _, err := s.db.Exec(`UPDATE subscriptions SET account_id=?, name=?, token_hash=?, owner_panel=?, limits_bytes=?, expires_at=?, max_devices=?
			WHERE id=?`, sub.AccountID, sub.Name, tokenHash, sub.OwnerPanel, sub.LimitsBytes, exp, sub.MaxDevices, sub.ID); err != nil {
			return err
		}
	} else {
		if _, err := s.db.Exec(`INSERT INTO subscriptions(id, account_id, name, token_hash, owner_panel, limits_bytes, created_at, expires_at, active, max_devices)
			VALUES (?,?,?,?,?,?,?,?,0,?)`, sub.ID, sub.AccountID, sub.Name, tokenHash, sub.OwnerPanel,
			sub.LimitsBytes, created.Format(time.RFC3339Nano), exp, sub.MaxDevices); err != nil {
			return err
		}
	}
	if err := s.SetQuotaUsed(sub.ID, sub.UsedBytes); err != nil {
		return err
	}
	// device usage/limits and rate travel WITH the user
	_, _ = s.db.Exec(`DELETE FROM sub_quota_device WHERE subscription_id=?`, sub.ID)
	for dev, st := range sub.DeviceUsage {
		lim := sub.DeviceLimits[dev]
		if _, err := s.db.Exec(`INSERT INTO sub_quota_device(subscription_id, device_id, used_bytes, limit_bytes, updated_at) VALUES (?,?,?,?,?)
			ON CONFLICT(subscription_id, device_id) DO UPDATE SET used_bytes=excluded.used_bytes, limit_bytes=excluded.limit_bytes`,
			sub.ID, dev, st, lim, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	rd, ru := sub.RateDownBPS, sub.RateUpBPS
	return s.SetSubscriptionRate(sub.ID, rd, ru)
}

// GetSubscription by id.
func (s *Store) GetSubscription(id string) (*Subscription, error) {
	row := s.db.QueryRow(`SELECT `+subCols+` FROM subscriptions WHERE id=?`, id)
	return scanSubscription(row.Scan)
}

// FindSubscriptionByToken resolves the fetch token (constant-time compare
// happens via hash equality of a SHA-256 — no plaintext is stored).
func (s *Store) FindSubscriptionByToken(token string) (*Subscription, error) {
	row := s.db.QueryRow(`SELECT `+subCols+` FROM subscriptions WHERE token_hash=? AND revoked_at IS NULL`, HashToken(token))
	sub, err := scanSubscription(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("AUTH_FAILED: subscription token is invalid, expired or revoked")
	}
	return sub, nil
}

// ListSubscriptions returns subscriptions visible to the operator.
func (s *Store) ListSubscriptions() ([]Subscription, error) {
	rows, err := s.db.Query(`SELECT ` + subCols + ` FROM subscriptions WHERE id NOT IN (SELECT subscription_id FROM hidden_subscriptions) ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Subscription
	for rows.Next() {
		sub, err := scanSubscription(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, *sub)
	}
	return out, rows.Err()
}

// ListSubscriptionProfilesAll returns every subscription's profiles
// (edge compiler: per-subscription route grants and route ports).
func (s *Store) ListSubscriptionProfilesAll() ([]SubscriptionProfile, error) {
	rows, err := s.db.Query(`SELECT subscription_id, seq, label_ru, label_en, kind, node_id, ingress_addr, COALESCE(sni,''), protocol, route_port, download_bps, upload_bps, limit_bytes FROM subscription_profiles ORDER BY subscription_id, seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubscriptionProfile
	for rows.Next() {
		var p SubscriptionProfile
		var subID string
		if err := rows.Scan(&subID, &p.Seq, &p.LabelRU, &p.LabelEn, &p.Kind, &p.NodeID, &p.IngressAddr, &p.SNI, &p.Protocol, &p.RoutePort, &p.DownloadBPS, &p.UploadBPS, &p.LimitBytes); err != nil {
			return nil, err
		}
		p.SubscriptionID = subID
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetSubscriptionProfiles replaces the catalog atomically.
func (s *Store) SetSubscriptionProfiles(subID string, profs []SubscriptionProfile) error {
	if _, err := s.GetSubscription(subID); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := replaceSubscriptionProfiles(tx, subID, profs); err != nil {
		return err
	}
	return tx.Commit()
}

// SetOwnedSubscriptionProfiles verifies ownership within the same transaction as the update.
func (s *Store) SetOwnedSubscriptionProfiles(id, owner string, profiles []SubscriptionProfile) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE subscriptions SET name=name WHERE id=? AND owner_panel=? AND active=1 AND revoked_at IS NULL AND COALESCE(transferred_to,'')=''`, id, owner)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("CONFLICT: subscription is not active on this owner")
	}
	if err := replaceSubscriptionProfiles(tx, id, profiles); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceSubscriptionProfiles(tx *sql.Tx, subID string, profs []SubscriptionProfile) error {
	if _, err := tx.Exec(`DELETE FROM subscription_profiles WHERE subscription_id=?`, subID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i, p := range profs {
		if p.LimitBytes != nil && *p.LimitBytes < 0 {
			return fmt.Errorf("VALIDATION_FAILED: negative profile limit")
		}
		if p.LabelRU == "" || p.LabelEn == "" || (p.Kind != "direct" && p.Kind != "transit") ||
			p.NodeID == "" || p.IngressAddr == "" || p.Protocol == "" {
			return fmt.Errorf("VALIDATION_FAILED: subscription_profiles[%d] incomplete", i)
		}
		if _, err := tx.Exec(`INSERT INTO subscription_profiles(subscription_id, seq, label_ru, label_en, kind, node_id, ingress_addr, sni, protocol, route_port, download_bps, upload_bps, limit_bytes, created_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, subID, i+1, p.LabelRU, p.LabelEn, p.Kind, p.NodeID, p.IngressAddr, p.SNI, p.Protocol, p.RoutePort, p.DownloadBPS, p.UploadBPS, p.LimitBytes, now); err != nil {
			return err
		}
	}
	return nil
}

// ListSubscriptionProfiles returns the ordered catalog.
func (s *Store) ListSubscriptionProfiles(subID string) ([]SubscriptionProfile, error) {
	rows, err := s.db.Query(`SELECT seq, label_ru, label_en, kind, node_id, ingress_addr, COALESCE(sni,''), protocol, route_port, download_bps, upload_bps, limit_bytes
		FROM subscription_profiles WHERE subscription_id=? ORDER BY seq`, subID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubscriptionProfile
	for rows.Next() {
		var p SubscriptionProfile
		if err := rows.Scan(&p.Seq, &p.LabelRU, &p.LabelEn, &p.Kind, &p.NodeID, &p.IngressAddr, &p.SNI, &p.Protocol, &p.RoutePort, &p.DownloadBPS, &p.UploadBPS, &p.LimitBytes); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokeSubscription kills the token; serving nodes learn it through the
// quota/report refusal (authoritative owner), so data-plane access ends.
func (s *Store) RevokeSubscription(id string) error {
	res, err := s.db.Exec(`UPDATE subscriptions SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("VALIDATION_FAILED: subscription %q not found or already revoked", id)
	}
	return nil
}

// ---- shared quota ledger (authoritative owner, lease registry) ----
//
// The owner never exposes the global remaining as spendable credit: every
// serving holder receives a DURABLE LEASE (unique id, amount, epoch,
// expiry, state issued/consumed/closed) and may admit offline ONLY within
// its own still-open leases. Invariant enforced inside one transaction:
//   used_total + Σ(open leases) + new_grant ≤ limit.
// Consumption reporting moves open-lease bytes to used exactly once per
// logical operation (fed_ops idempotency lives at the handler/store
// boundary; the lease math itself never double-charges because a lease
// closes only when its consumption is recorded against it).

// RateRightTTL bounds how long a rate right stays live without renewal;
// after it expires the residual frees for other holders (leave/partition).
const RateRightTTL = 30 * time.Second

// LeaseTTL bounds how long an issued-but-never-reported lease stays open.
// Expired leases are counted AS CONSUMED (conservative: a crashed holder
// never frees budget it may have been spending).
const LeaseTTL = 10 * time.Minute

// subQuotaMonth is the UTC "YYYY-MM" epoch key for period rollover.
func subQuotaMonth(now time.Time) string { return now.UTC().Format("2006-01") }

// QuotaReport is one atomic lease operation for holder (deviceID doubles
// as the holder key; the real handler passes panel+"|"+device): report
// `used` bytes of actual consumption and request a new lease of `reserve`
// bytes. Returns the GLOBAL remaining (display only — it is NOT offline
// spendable credit) and the exhausted flag. A reserve larger than the
// remaining budget yields a strictly smaller grant (explicitly bounded),
// never an overflow of the counter.
func (s *Store) QuotaReport(subID, deviceID string, used, reserve int64) (remaining *int64, exhausted bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	remaining, exhausted, _, err = s.quotaReportTx(tx, subID, deviceID, used, reserve, 0, 0, true)
	if err != nil {
		return nil, false, err
	}
	return remaining, exhausted, tx.Commit()
}

// quotaReportTx is the lease-op body on an OPEN transaction (the handler
// runs it inside WithFedOpTx so the idempotency record and the mutation
// commit atomically). Returns the granted amount as well.
func (s *Store) quotaReportTx(tx *sql.Tx, subID, deviceID string, used, reserve, ru, foreign int64, observe bool) (remaining *int64, exhausted bool, granted int64, err error) {
	if used < 0 || reserve < 0 || ru < 0 || foreign < 0 || ru > used || foreign > used-ru {
		return nil, false, 0, fmt.Errorf("VALIDATION_FAILED: negative usage")
	}
	// tx-scoped read: with a single pooled connection, any s.db use inside
	// an open tx would self-deadlock
	row := tx.QueryRow(`SELECT `+subCols+` FROM subscriptions WHERE id=?`, subID)
	sub, err := scanSubscription(row.Scan)
	if err != nil {
		return nil, false, 0, err
	}
	if sub.RevokedAt != nil {
		return nil, true, 0, fmt.Errorf("AUTH_FAILED: subscription revoked")
	}
	// B03 lifecycle/authority guard inside the SAME admission transaction:
	// expired and not-yet-activated (imported pending) subscriptions get
	// NO new budget.
	if sub.ExpiresAt != nil && sub.ExpiresAt.Before(time.Now().UTC()) {
		return nil, true, 0, fmt.Errorf("AUTH_FAILED: subscription expired at %s", sub.ExpiresAt.Format(time.RFC3339))
	}
	if sub.Active != nil && !*sub.Active {
		return nil, true, 0, fmt.Errorf("AUTH_FAILED: subscription is a pending transfer copy (inactive)")
	}
	now := time.Now().UTC()
	devKey := deviceID
	if i := strings.LastIndex(deviceID, "|"); i >= 0 {
		devKey = deviceID[i+1:]
	}
	if err := guardDeviceLive(tx, devKey, subID); err != nil {
		return nil, true, 0, err
	}
	month := subQuotaMonth(now)

	// period rollover: fresh budget, old leases die with the epoch
	var epoch string
	_ = tx.QueryRow(`SELECT epoch FROM sub_leases WHERE subscription_id=? ORDER BY issued_at DESC LIMIT 1`, subID).Scan(&epoch)
	if epoch != "" && epoch != month {
		if _, err := tx.Exec(`UPDATE sub_leases SET state='closed' WHERE subscription_id=? AND state='issued'`, subID); err != nil {
			return nil, false, 0, err
		}
		if _, err := tx.Exec(`UPDATE sub_quota SET used_bytes=0, updated_at=? WHERE subscription_id=?`, now.Format(time.RFC3339Nano), subID); err != nil {
			return nil, false, 0, err
		}
		if _, err := tx.Exec(`UPDATE sub_quota_device SET used_bytes=0, updated_at=? WHERE subscription_id=?`, now.Format(time.RFC3339Nano), subID); err != nil {
			return nil, false, 0, err
		}
	}
	epoch = month

	if used > 0 {
		if _, err := tx.Exec(`UPDATE sub_quota SET used_bytes=used_bytes+?, updated_at=? WHERE subscription_id=?`,
			used, now.Format(time.RFC3339Nano), subID); err != nil {
			return nil, false, 0, err
		}
		if observe {
			if err := recordSubscriptionActivity(tx, subID, devKey, used, ru, foreign, now); err != nil {
				return nil, false, 0, err
			}
		}
		if _, err := tx.Exec(`INSERT INTO sub_quota_device(subscription_id, device_id, used_bytes, updated_at) VALUES (?,?,?,?)
			ON CONFLICT(subscription_id, device_id) DO UPDATE SET used_bytes=used_bytes+excluded.used_bytes, updated_at=excluded.updated_at`,
			subID, devKey, used, now.Format(time.RFC3339Nano)); err != nil {
			return nil, false, 0, err
		}
		// consumption closes THIS holder's oldest open leases
		rows, err := tx.Query(`SELECT id, amount FROM sub_leases
			WHERE subscription_id=? AND holder=? AND state='issued' ORDER BY issued_at`, subID, deviceID)
		if err != nil {
			return nil, false, 0, err
		}
		type leaseRow struct {
			id     string
			amount int64
		}
		var open []leaseRow
		for rows.Next() {
			var l leaseRow
			if err := rows.Scan(&l.id, &l.amount); err != nil {
				rows.Close()
				return nil, false, 0, err
			}
			open = append(open, l)
		}
		rows.Close()
		left := used
		closedExtra := int64(0)
		for _, l := range open {
			if left <= 0 {
				break
			}
			if _, err := tx.Exec(`UPDATE sub_leases SET state='consumed' WHERE id=?`, l.id); err != nil {
				return nil, false, 0, err
			}
			applied := l.amount
			if left < applied {
				applied = left
			}
			left -= applied
			// a PARTIALLY consumed lease is closed whole: its uncovered
			// remainder moves to used (conservative — the owner never
			// undercounts spend; offline partial leases settle at the
			// next report, which is the common full-consumption case)
			closedExtra += l.amount - applied
		}
		if closedExtra > 0 {
			if _, err := tx.Exec(`UPDATE sub_quota SET used_bytes=used_bytes+? WHERE subscription_id=?`, closedExtra, subID); err != nil {
				return nil, false, 0, err
			}
			devKey := deviceID
			if i := strings.LastIndex(deviceID, "|"); i >= 0 {
				devKey = deviceID[i+1:]
			}
			if _, err := tx.Exec(`UPDATE sub_quota_device SET used_bytes=used_bytes+? WHERE subscription_id=? AND device_id=?`, closedExtra, subID, devKey); err != nil {
				return nil, false, 0, err
			}
		}
		// consumption beyond own open leases is charged to used anyway:
		// Σopen+used ≤ limit holds, overspend is visible, never hidden
	}

	// FED03: expired leases are settled ATOMICALLY and ONCE — the whole
	// unreported amount moves to used (account AND the holder's device
	// budget). A crashed holder may have spent it: the owner never frees
	// unreported spend. A LATE report for the same bytes is charged again
	// (conservative over-count, never under-count); old-epoch leases are
	// closed by the rollover above and never settle into a new month.
	expRows, err := tx.Query(`SELECT amount, device_id FROM sub_leases
		WHERE subscription_id=? AND state='issued' AND expires_at < ?`, subID, now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, false, 0, err
	}
	type expLease struct {
		amount   int64
		deviceID string
	}
	var expired []expLease
	for expRows.Next() {
		var l expLease
		if err := expRows.Scan(&l.amount, &l.deviceID); err != nil {
			expRows.Close()
			return nil, false, 0, err
		}
		expired = append(expired, l)
	}
	expRows.Close()
	if len(expired) > 0 {
		// close ALL expired issued leases in one statement; the amounts
		// were captured above, so the settlement happens exactly once
		if _, err := tx.Exec(`UPDATE sub_leases SET state='consumed'
			WHERE subscription_id=? AND state='issued' AND expires_at < ?`, subID, now.Format(time.RFC3339Nano)); err != nil {
			return nil, false, 0, err
		}
		var settledTotal int64
		settledByDevice := map[string]int64{}
		for _, l := range expired {
			settledTotal += l.amount
			devKey := l.deviceID
			if i := strings.LastIndex(devKey, "|"); i >= 0 {
				devKey = devKey[i+1:]
			}
			settledByDevice[devKey] += l.amount
		}
		if _, err := tx.Exec(`UPDATE sub_quota SET used_bytes=used_bytes+?, updated_at=? WHERE subscription_id=?`,
			settledTotal, now.Format(time.RFC3339Nano), subID); err != nil {
			return nil, false, 0, err
		}
		for dev, amt := range settledByDevice {
			if _, err := tx.Exec(`INSERT INTO sub_quota_device(subscription_id, device_id, used_bytes, updated_at) VALUES (?,?,?,?)
				ON CONFLICT(subscription_id, device_id) DO UPDATE SET used_bytes=used_bytes+excluded.used_bytes, updated_at=excluded.updated_at`,
				subID, dev, amt, now.Format(time.RFC3339Nano)); err != nil {
				return nil, false, 0, err
			}
		}
	}

	var usedTotal int64
	if err := tx.QueryRow(`SELECT used_bytes FROM sub_quota WHERE subscription_id=?`, subID).Scan(&usedTotal); err != nil {
		return nil, false, 0, err
	}
	var openTotal int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued'`, subID).Scan(&openTotal); err != nil {
		return nil, false, 0, err
	}

	grant := int64(0)
	exhausted = false
	// FED04: the AUTHORITATIVE device budget bounds the grant TOO — the
	// outstanding device leases of THIS device count against it, so two
	// edges serving one device can never receive rights above its budget.
	var devLimit *int64
	var devUsed int64
	_ = tx.QueryRow(`SELECT used_bytes, limit_bytes FROM sub_quota_device WHERE subscription_id=? AND device_id=?`, subID, devKey).Scan(&devUsed, &devLimit)
	var devOpen int64
	_ = tx.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND device_id=? AND state='issued'`, subID, devKey).Scan(&devOpen)
	if sub.LimitsBytes == nil {
		grant = reserve
	} else {
		avail := *sub.LimitsBytes - usedTotal - openTotal
		if avail <= 0 {
			exhausted = true
		} else {
			grant = reserve
			if grant > avail {
				grant = avail // explicitly bounded grant, never an overflow
			}
			if devLimit != nil {
				devAvail := *devLimit - devUsed - devOpen
				if devAvail < 0 {
					devAvail = 0
				}
				if grant > devAvail {
					grant = devAvail
				}
			}
			if grant > 0 {
				leaseID, err := randomID("ls")
				if err != nil {
					return nil, false, 0, err
				}
				if _, err := tx.Exec(`INSERT INTO sub_leases(id, subscription_id, holder, device_id, amount, state, epoch, issued_at, expires_at)
					VALUES (?,?,?,?,?,?,?,?,?)`,
					leaseID, subID, deviceID, devKey, grant, "issued", epoch,
					now.Format(time.RFC3339Nano), now.Add(LeaseTTL).Format(time.RFC3339Nano)); err != nil {
					return nil, false, 0, err
				}
				avail -= grant
			}
			if avail <= 0 {
				exhausted = true
			}
		}
		rem := *sub.LimitsBytes - usedTotal - openTotal - grant
		if rem < 0 {
			rem = 0
		}
		remaining = &rem
	}
	return remaining, exhausted, grant, nil
}

// QuotaOpResponse is the full authoritative answer for one lease op.
type QuotaOpResponse struct {
	DeviceExpiresUnix int64  `json:"device_expires_unix,omitempty"`
	LeaseExpiresUnix  int64  `json:"lease_expires_unix,omitempty"`
	Remaining         *int64 `json:"remaining_bytes"`
	Exhausted         bool   `json:"exhausted"`
	Granted           int64  `json:"granted"`
	DeviceRemaining   *int64 `json:"device_remaining_bytes"`
	DeviceExhausted   bool   `json:"device_exhausted"`
	RateDownBPS       *int64 `json:"rate_share_down_bps"`
	RateUpBPS         *int64 `json:"rate_share_up_bps"`
}

// WithFedOpTx runs ONE mutation atomically with its idempotency record:
// fn executes INSIDE the transaction that reserves the op key, so a
// replay (same panel+nonce or same client op_id) either sees the recorded
// response or waits for it — it can never re-execute the mutation.
// Durable across restarts; storage bounded by retention purge.
func (s *Store) WithFedOpTx(opKey string, fn func(tx *sql.Tx) (any, error)) (res any, replayed bool, err error) {
	return s.WithFedOpTxDigest(opKey, "", fn)
}

// WithFedOpTxDigest (B02/interim): the op identity (opKey) and the digest
// of its content are stored together. Exact retry (same identity+digest)
// returns the recorded response; the SAME identity with a DIFFERENT
// digest is a CONFLICT — an id must never authorize a second mutation.
func (s *Store) WithFedOpTxDigest(opKey, digest string, fn func(tx *sql.Tx) (any, error)) (res any, replayed bool, err error) {
	if opKey == "" {
		tx, terr := s.db.Begin()
		if terr != nil {
			return nil, false, terr
		}
		defer tx.Rollback()
		res, err = fn(tx)
		if err != nil {
			return nil, false, err
		}
		return res, false, tx.Commit()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	// first statement is a WRITE: it takes SQLite's write lock, so a
	// concurrent replay serializes here until this tx commits
	cutoff := time.Now().UTC().Add(-2 * LeaseTTL).Format(time.RFC3339Nano)
	activityCutoff := time.Now().UTC().Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM fed_ops WHERE (op_key NOT LIKE 'activity:%' AND created_at < ?)
		OR (op_key LIKE 'activity:%' AND created_at < ?)`, cutoff, activityCutoff); err != nil {
		return nil, false, err
	}
	var stored, storedDigest string
	serr := tx.QueryRow(`SELECT response_json, op_digest FROM fed_ops WHERE op_key=?`, opKey).Scan(&stored, &storedDigest)
	if serr == nil {
		if stored != "" {
			// B02/interim: same identity, different content → CONFLICT
			if digest != "" && storedDigest != "" && storedDigest != digest {
				tx.Rollback()
				return nil, false, fmt.Errorf("CONFLICT: operation identity %q was already used with different content", opKey)
			}
			tx.Rollback()
			var prev any
			if jerr := json.Unmarshal([]byte(stored), &prev); jerr == nil {
				return prev, true, nil
			}
			return nil, false, fmt.Errorf("INTERNAL: stored fed op response undecodable")
		}
		// reserved but unfinished: torn record; treat as not executed
	} else if serr.Error() != "sql: no rows in result set" {
		return nil, false, serr
	}
	// Column order is (op_key, response_json, created_at, op_digest):
	// the digest belongs to op_digest and the timestamp to created_at —
	// the swapped order made created_at empty, so every replay purge
	// deleted the record and double-charged (B02/interim root cause).
	if _, err := tx.Exec(`INSERT INTO fed_ops(op_key, response_json, created_at, op_digest) VALUES (?,?,?,?)`,
		opKey, "", time.Now().UTC().Format(time.RFC3339Nano), digest); err != nil {
		return nil, false, err
	}
	res, err = fn(tx) // SAME tx: the mutation and the key commit atomically
	if err != nil {
		return nil, false, err // rollback: the key dies too, op is retryable
	}
	b, jerr := json.Marshal(res)
	if jerr != nil {
		return nil, false, jerr
	}
	if _, err := tx.Exec(`UPDATE fed_ops SET response_json=?, op_digest=? WHERE op_key=?`, string(b), digest, opKey); err != nil {
		return nil, false, err
	}
	return res, false, tx.Commit()
}

// QuotaReportOp is the handler entry: one idempotent lease op (QuotaReport
// + authoritative device and rate-share view for THIS holder). opKey is
// the CLIENT's stable operation identity ("op:<op_id>") or the handler's
// nonce key ("nonce:<panel>:<nonce>") — NEVER derived from content, or a
// legitimate second identical report would be misread as a replay.
func (s *Store) QuotaReportOp(opKey, subID, deviceID string, used, reserve int64) (*QuotaOpResponse, bool, error) {
	return s.QuotaReportOpDigest(opKey, "", subID, deviceID, used, reserve)
}

// QuotaReportOpDigest binds the stable operation identity to the digest of
// its content (B02/interim).
func (s *Store) QuotaReportOpDigest(opKey, digest, subID, deviceID string, used, reserve int64) (*QuotaOpResponse, bool, error) {
	return s.QuotaReportRouted(opKey, digest, subID, deviceID, used, reserve, 0, 0, true)
}

func (s *Store) QuotaReportRouted(opKey, digest, subID, deviceID string, used, reserve, ru, foreign int64, observe bool) (*QuotaOpResponse, bool, error) {
	// holder = panel|device: the AUTHORITATIVE device ledger is keyed by
	// the DEVICE id, the lease by the holder
	devKey := deviceID
	if i := strings.LastIndex(deviceID, "|"); i >= 0 {
		devKey = deviceID[i+1:]
	}
	var grantedDown, grantedUp int64
	res, replayed, err := s.WithFedOpTxDigest(opKey, digest, func(tx *sql.Tx) (any, error) {
		remaining, exhausted, grant, err := s.quotaReportTx(tx, subID, deviceID, used, reserve, ru, foreign, observe)
		if err != nil {
			return nil, err
		}
		resp := &QuotaOpResponse{Remaining: remaining, Exhausted: exhausted, Granted: grant}
		if err := tx.QueryRow(`SELECT COALESCE((SELECT expires_unix FROM devices WHERE id=?),0)`, devKey).Scan(&resp.DeviceExpiresUnix); err != nil {
			return nil, err
		}
		if grant > 0 {
			resp.LeaseExpiresUnix = time.Now().Add(LeaseTTL).Unix()
			if resp.DeviceExpiresUnix > 0 && resp.DeviceExpiresUnix < resp.LeaseExpiresUnix {
				resp.LeaseExpiresUnix = resp.DeviceExpiresUnix
			}
		}
		var devUsed int64
		var devLimit *int64
		if err := tx.QueryRow(`SELECT used_bytes, limit_bytes FROM sub_quota_device WHERE subscription_id=? AND device_id=?`, subID, devKey).Scan(&devUsed, &devLimit); err == nil && devLimit != nil {
			dr := *devLimit - devUsed
			if dr < 0 {
				dr = 0
			}
			resp.DeviceRemaining = &dr
			resp.DeviceExhausted = dr <= 0
		}
		var rd, ru *int64
		_ = tx.QueryRow(`SELECT download_bps, upload_bps FROM sub_rate WHERE subscription_id=?`, subID).Scan(&rd, &ru)
		if rd != nil || ru != nil {
			// FED05: rate RIGHTS are leases with expiry keyed by the
			// PANEL (one right per serving edge, independent of how many
			// devices it serves); the sum of simultaneously LIVE rights
			// never exceeds the subscription rate. A joining holder
			// receives only the RESIDUAL until the existing holders renew
			// at the reduced share (acknowledged redistribution).
			nowR := time.Now().UTC()
			rateHolder := deviceID
			if i := strings.Index(deviceID, "|"); i > 0 {
				rateHolder = deviceID[:i]
			}
			if _, err := tx.Exec(`DELETE FROM sub_rate_rights WHERE subscription_id=? AND expires_at < ?`,
				subID, nowR.Format(time.RFC3339Nano)); err != nil {
				return nil, err
			}
			var othersDown, othersUp int64
			if err := tx.QueryRow(`SELECT COALESCE(SUM(down_bps),0), COALESCE(SUM(up_bps),0)
				FROM sub_rate_rights WHERE subscription_id=? AND holder<>? AND expires_at >= ?`,
				subID, rateHolder, nowR.Format(time.RFC3339Nano)).Scan(&othersDown, &othersUp); err != nil {
				return nil, err
			}
			// live holders = live rate rights ∪ holders with OPEN byte
			// leases (a leasing holder is ACTIVE even before its first
			// rate renewal — this prevents the joiner from claiming the
			// full rate while another edge is mid-flight) ∪ self; all
			// normalized to the PANEL key
			var liveHolders int64
			if err := tx.QueryRow(`SELECT COUNT(DISTINCT holder) FROM (
					SELECT holder FROM sub_rate_rights WHERE subscription_id=? AND expires_at >= ?
					UNION
					SELECT DISTINCT substr(holder,1,instr(holder||'|','|')-1) FROM sub_leases
						WHERE subscription_id=? AND state='issued'
					UNION
					SELECT ?
				)`, subID, nowR.Format(time.RFC3339Nano), subID, rateHolder).Scan(&liveHolders); err != nil {
				return nil, err
			}
			if liveHolders < 1 {
				liveHolders = 1
			}
			if rd != nil {
				desired := *rd / liveHolders
				residual := *rd - othersDown
				if residual < 0 {
					residual = 0
				}
				share := desired
				if share > residual {
					share = residual
				}
				share &= ^int64(7) // multiple of 8 bit/s
				if share < 0 {
					share = 0
				}
				resp.RateDownBPS = &share
				grantedDown = share
			}
			if ru != nil {
				desired := *ru / liveHolders
				residual := *ru - othersUp
				if residual < 0 {
					residual = 0
				}
				share := desired
				if share > residual {
					share = residual
				}
				share &= ^int64(7)
				if share < 0 {
					share = 0
				}
				resp.RateUpBPS = &share
				grantedUp = share
			}
			if _, err := tx.Exec(`INSERT INTO sub_rate_rights(subscription_id, holder, down_bps, up_bps, expires_at) VALUES (?,?,?,?,?)
				ON CONFLICT(subscription_id, holder) DO UPDATE SET down_bps=excluded.down_bps, up_bps=excluded.up_bps, expires_at=excluded.expires_at`,
				subID, rateHolder, grantedDown, grantedUp, nowR.Add(RateRightTTL).Format(time.RFC3339Nano)); err != nil {
				return nil, err
			}
		}
		return resp, nil
	})
	if err != nil {
		return nil, false, err
	}
	if resp, ok := res.(*QuotaOpResponse); ok {
		return resp, replayed, nil
	}
	// replayed: the stored response comes back as a generic map —
	// round-trip it into the typed view (byte-identical semantics)
	b, merr := json.Marshal(res)
	if merr != nil {
		return nil, false, merr
	}
	var out QuotaOpResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, false, err
	}
	return &out, replayed, nil
}

// SetSubscriptionDeviceLimit sets the AUTHORITATIVE per-device budget
// (nil = unlimited) on the owner ledger.
func (s *Store) SetSubscriptionDeviceLimit(subID, deviceID string, limit *int64) error {
	if limit != nil && *limit < 0 {
		return fmt.Errorf("VALIDATION_FAILED: device limit must be non-negative")
	}
	if _, err := s.GetSubscription(subID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO sub_quota_device(subscription_id, device_id, used_bytes, limit_bytes, updated_at) VALUES (?,?,0,?,?)
		ON CONFLICT(subscription_id, device_id) DO UPDATE SET limit_bytes=excluded.limit_bytes, updated_at=excluded.updated_at`,
		subID, deviceID, limit, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// SetSubscriptionRate sets the AUTHORITATIVE shared rate for the
// subscription (nil = unlimited); serving edges get rate/active-holders.
func (s *Store) SetSubscriptionRate(subID string, downBPS, upBPS *int64) error {
	if (downBPS != nil && *downBPS < 0) || (upBPS != nil && *upBPS < 0) {
		return fmt.Errorf("VALIDATION_FAILED: configured rates must be non-negative")
	}
	if _, err := s.GetSubscription(subID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO sub_rate(subscription_id, download_bps, upload_bps, updated_at) VALUES (?,?,?,?)
		ON CONFLICT(subscription_id) DO UPDATE SET download_bps=excluded.download_bps, upload_bps=excluded.upload_bps, updated_at=excluded.updated_at`,
		subID, downBPS, upBPS, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// SubscriptionRate returns the shared rate config.
func (s *Store) SubscriptionRate(subID string) (*int64, *int64, error) {
	var d, u *int64
	err := s.db.QueryRow(`SELECT download_bps, upload_bps FROM sub_rate WHERE subscription_id=?`, subID).Scan(&d, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil // no rate configured = unlimited
	}
	return d, u, err
}

// SetQuotaUsed moves the accumulated usage WITH the subscription
// (ownership transfer must never reset the spend).
func (s *Store) SetQuotaUsed(subID string, used int64) error {
	_, err := s.db.Exec(`INSERT INTO sub_quota(subscription_id, used_bytes, updated_at) VALUES (?,?,?)
		ON CONFLICT(subscription_id) DO UPDATE SET used_bytes=excluded.used_bytes, updated_at=excluded.updated_at`,
		subID, used, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ActivateImportedSubscription flips an imported copy to the active
// authority and applies the FINAL usage delta (source-side spend between
// snapshot and switch travels with the user). Idempotent.
func (s *Store) ActivateImportedSubscription(subID string, finalUsed int64, profileSpends ...map[string]ProfileSpend) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active int
	if err := tx.QueryRow(`SELECT active FROM subscriptions WHERE id=?`, subID).Scan(&active); err != nil {
		return err
	}
	if active == 1 {
		return tx.Commit() // already authoritative: idempotent no-op
	}
	if _, err := tx.Exec(`UPDATE sub_quota SET used_bytes=?, updated_at=? WHERE subscription_id=?`,
		finalUsed, time.Now().UTC().Format(time.RFC3339Nano), subID); err != nil {
		return err
	}
	if len(profileSpends) > 0 {
		for key, p := range profileSpends[0] {
			if p.Committed < 0 || len(key) != 64 {
				return fmt.Errorf("VALIDATION_FAILED: profile transfer budget")
			}
			if _, err := tx.Exec(`INSERT INTO profile_budget(subscription_id,profile_key,epoch,committed) VALUES(?,?,?,?) ON CONFLICT(subscription_id,profile_key) DO UPDATE SET epoch=excluded.epoch,committed=excluded.committed`, subID, key, p.Epoch, p.Committed); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`UPDATE subscriptions SET active=1 WHERE id=?`, subID); err != nil {
		return err
	}
	return tx.Commit()
}

// LoadSubscriptionTransferState gathers device usage/limits and rate for
// the transfer payload (they travel WITH the user — never reset).
func (s *Store) LoadSubscriptionTransferState(subID string) (map[string]int64, map[string]*int64, *int64, *int64, error) {
	usage := map[string]int64{}
	limits := map[string]*int64{}
	rows, err := s.db.Query(`SELECT device_id, used_bytes, limit_bytes FROM sub_quota_device WHERE subscription_id=?`, subID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var dev string
		var used int64
		var lim *int64
		if err := rows.Scan(&dev, &used, &lim); err != nil {
			return nil, nil, nil, nil, err
		}
		usage[dev] = used
		limits[dev] = lim
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, nil, err
	}
	rd, ru, err := s.SubscriptionRate(subID)
	return usage, limits, rd, ru, err
}

// MigratedDevice is one account device identity carried by a transfer.
type MigratedDevice struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	VlessUUID   string `json:"vless_uuid"`
	CreatedAt   string `json:"created_at"`
	ExpiresUnix int64  `json:"expires_unix,omitempty"`
}

// LoadAccountDevices gathers the account's active device identities for
// the transfer payload (FED06: credentials travel WITH the user).
func (s *Store) LoadAccountDevices(accountID string) ([]MigratedDevice, error) {
	rows, err := s.db.Query(`SELECT id, name, COALESCE(vless_uuid,''), created_at, expires_unix FROM devices
		WHERE account_id=? AND revoked_at IS NULL`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MigratedDevice
	for rows.Next() {
		var d MigratedDevice
		if err := rows.Scan(&d.ID, &d.Name, &d.VlessUUID, &d.CreatedAt, &d.ExpiresUnix); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ImportAccountDevices re-creates the migrated identities on the target
// panel: same ids and UUIDs (identity continuity), enrollment closed
// (enrollment_used_at set — the invitation flow is not re-runnable).
func (s *Store) ImportAccountDevices(accountID string, devices []MigratedDevice) error {
	for _, d := range devices {
		if d.ID == "" || d.VlessUUID == "" {
			return fmt.Errorf("VALIDATION_FAILED: migrated device incomplete")
		}
		if _, err := s.db.Exec(`INSERT INTO devices(id, account_id, name, created_at, revoked_at, enrollment_used_at, identity_pubkey, vless_uuid, expires_unix)
			VALUES (?,?,?,?,NULL,?,'migrated',?,?) ON CONFLICT(id) DO NOTHING`,
			d.ID, accountID, d.Name, d.CreatedAt, time.Now().UTC().Format(time.RFC3339Nano), d.VlessUUID, d.ExpiresUnix); err != nil {
			return err
		}
	}
	return nil
}

// CreateMigration records the durable prepare phase of an ownership
// transfer.
func (s *Store) CreateMigration(migrationID, subID, fromPanel, toPanel string, snapshotUsed int64) error {
	_, err := s.db.Exec(`INSERT INTO sub_migrations(migration_id, subscription_id, from_panel, to_panel, state, snapshot_used, created_at)
		VALUES (?,?,?,?, 'prepared', ?, ?) ON CONFLICT(migration_id) DO NOTHING`,
		migrationID, subID, fromPanel, toPanel, snapshotUsed, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// CommitMigration marks the source side flipped (authority moved).
func (s *Store) CommitMigration(migrationID string, finalUsed int64) error {
	res, err := s.db.Exec(`UPDATE sub_migrations SET state='committed', final_used=? WHERE migration_id=? AND state='prepared'`,
		finalUsed, migrationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("VALIDATION_FAILED: migration %q not prepared", migrationID)
	}
	return nil
}

// FlipSubscriptionToTarget performs the authority switch ATOMICALLY: the
// final usage snapshot and the owner change carry ONE transactional
// boundary (review FED06), and the migration row commits in the same tx.
// Outstanding offline leases are budget OBLIGATIONS: they are folded into
// the final usage so the target inherits them instead of forgetting them.
func (s *Store) FlipSubscriptionToTarget(migrationID, subID, targetPanel string, extraUsed int64, fetchBase ...string) (finalUsed int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var usedTotal int64
	if err := tx.QueryRow(`SELECT used_bytes FROM sub_quota WHERE subscription_id=?`, subID).Scan(&usedTotal); err != nil {
		return 0, err
	}
	var openObligations int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued'`, subID).Scan(&openObligations); err != nil {
		return 0, err
	}
	finalUsed = usedTotal + openObligations
	var base any
	if len(fetchBase) != 0 {
		base = fetchBase[0]
	}
	changed, err := tx.Exec(`UPDATE sub_migrations SET state='committed', final_used=?
		WHERE migration_id=? AND subscription_id=? AND to_panel=? AND state='prepared'`,
		finalUsed, migrationID, subID, targetPanel)
	if err != nil {
		return 0, err
	}
	if n, err := changed.RowsAffected(); err != nil || n != 1 {
		return 0, fmt.Errorf("CONFLICT: migration is not prepared for this subscription and target")
	}
	changed, err = tx.Exec(`UPDATE subscriptions SET owner_panel=?, transferred_to=?, fetch_base=COALESCE(?,fetch_base)
		WHERE id=? AND COALESCE(transferred_to,'')='' AND revoked_at IS NULL
		AND owner_panel=(SELECT from_panel FROM sub_migrations WHERE migration_id=?)`,
		targetPanel, targetPanel, base, subID, migrationID)
	if err != nil {
		return 0, err
	}
	if n, err := changed.RowsAffected(); err != nil || n != 1 {
		return 0, fmt.Errorf("CONFLICT: source no longer owns the subscription")
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	_ = extraUsed
	return finalUsed, nil
}

// MarkMigrationActivated records the target's confirmation; further
// transfer retries are then a durable no-op.
func (s *Store) MarkMigrationActivated(migrationID string) error {
	res, err := s.db.Exec(`UPDATE sub_migrations SET state='activated' WHERE migration_id=? AND state='committed'`, migrationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// already activated or unknown: verify which
		var state string
		if qerr := s.db.QueryRow(`SELECT state FROM sub_migrations WHERE migration_id=?`, migrationID).Scan(&state); qerr == nil && state == "activated" {
			return nil
		}
	}
	return nil
}

// FindLatestMigration returns the latest migration for (sub, target):
// id + state + final_used (nil when prepared). Empty id = none.
func (s *Store) FindLatestMigration(subID, toPanel string) (string, string, *int64, error) {
	row := s.db.QueryRow(`SELECT migration_id, state, final_used FROM sub_migrations
		WHERE subscription_id=? AND to_panel=? ORDER BY created_at DESC LIMIT 1`, subID, toPanel)
	var id, state string
	var fin *int64
	if err := row.Scan(&id, &state, &fin); err != nil {
		return "", "", nil, nil // none
	}
	return id, state, fin, nil
}

// GetMigration returns a migration row by id as a TYPED contract
// (product-completion 02.11: positional returns let the activate handler
// mistake the importing target (to_panel) for the driving source and
// reject every legitimate activation).
type Migration struct {
	ID           string `json:"migration_id"`
	State        string `json:"state"`
	SubID        string `json:"subscription_id"`
	FromPanel    string `json:"from_panel"`
	ToPanel      string `json:"to_panel"`
	SnapshotUsed int64  `json:"snapshot_used"`
	FinalUsed    *int64 `json:"final_used,omitempty"`
}

func (s *Store) GetMigration(migrationID string) (*Migration, error) {
	m := &Migration{ID: migrationID}
	err := s.db.QueryRow(`SELECT state, subscription_id, from_panel, to_panel, snapshot_used, final_used
		FROM sub_migrations WHERE migration_id=?`, migrationID).
		Scan(&m.State, &m.SubID, &m.FromPanel, &m.ToPanel, &m.SnapshotUsed, &m.FinalUsed)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ErrPendingImportOwned refuses an import that would replace another
// panel's prepared transfer (product-completion: a pending copy is bound
// to its recorded source, not a free slot for any peer with the
// subscriptions scope).
var ErrPendingImportOwned = errors.New("CONFLICT: pending import owned by another transfer")

// PrepareSubscriptionImport creates or updates the INACTIVE imported copy
// and binds (source → target, subscription, migration, snapshot) in ONE
// transaction, before the first mutation. The same source may retry the
// same migration id (idempotent CAS refresh of the snapshot); any other
// peer — or a pending copy with no prepared migration behind it — is
// refused without touching token, usage or identity.
func (s *Store) PrepareSubscriptionImport(sub *Subscription, tokenHash string, profiles []SubscriptionProfile, devices []MigratedDevice, migrationID, sourcePanel string, used int64) error {
	if sub.ID == "" || sub.AccountID == "" || sub.OwnerPanel == "" || tokenHash == "" || migrationID == "" {
		return fmt.Errorf("VALIDATION_FAILED: imported subscription incomplete")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active int
	switch err := tx.QueryRow(`SELECT active FROM subscriptions WHERE id=?`, sub.ID).Scan(&active); {
	case err == nil && active == 1:
		return fmt.Errorf("CONFLICT: subscription %s already active on this panel", sub.ID)
	case err == nil:
		var from, mid string
		switch qerr := tx.QueryRow(`SELECT from_panel, migration_id FROM sub_migrations
			WHERE subscription_id=? AND state='prepared' ORDER BY created_at DESC LIMIT 1`, sub.ID).Scan(&from, &mid); {
		case qerr == nil:
			if from != sourcePanel || mid != migrationID {
				return ErrPendingImportOwned
			}
			// same source, same migration: durable retry — refresh the
			// snapshot and credentials of the PENDING copy only
			if _, uerr := tx.Exec(`UPDATE subscriptions SET account_id=?, name=?, token_hash=?, owner_panel=?, limits_bytes=?, max_devices=?
				WHERE id=? AND active=0`,
				sub.AccountID, sub.Name, tokenHash, sub.OwnerPanel, sub.LimitsBytes, sub.MaxDevices, sub.ID); uerr != nil {
				return uerr
			}
			if _, uerr := tx.Exec(`UPDATE sub_migrations SET snapshot_used=? WHERE migration_id=? AND state='prepared'`,
				used, migrationID); uerr != nil {
				return uerr
			}
		case qerr == sql.ErrNoRows:
			// an inactive copy with no prepared migration has no authority
			// chain: it is not a free slot
			return ErrPendingImportOwned
		default:
			return qerr
		}
	case err == sql.ErrNoRows:
		created := sub.CreatedAt
		if created.IsZero() {
			created = time.Now().UTC()
		}
		var exp any
		if sub.ExpiresAt != nil {
			exp = sub.ExpiresAt.Format(time.RFC3339Nano)
		}
		if _, ierr := tx.Exec(`INSERT INTO subscriptions(id, account_id, name, token_hash, owner_panel, limits_bytes, created_at, expires_at, active, max_devices)
			VALUES (?,?,?,?,?,?,?,?,0,?)`, sub.ID, sub.AccountID, sub.Name, tokenHash, sub.OwnerPanel,
			sub.LimitsBytes, created.Format(time.RFC3339Nano), exp, sub.MaxDevices); ierr != nil {
			return ierr
		}
		if _, ierr := tx.Exec(`INSERT INTO sub_migrations(migration_id, subscription_id, from_panel, to_panel, state, snapshot_used, created_at)
			VALUES (?,?,?,?, 'prepared', ?, ?) ON CONFLICT(migration_id) DO NOTHING`,
			migrationID, sub.ID, sourcePanel, sub.OwnerPanel, used, time.Now().UTC().Format(time.RFC3339Nano)); ierr != nil {
			return ierr
		}
	default:
		return err
	}
	if _, uerr := tx.Exec(`INSERT INTO sub_quota(subscription_id, used_bytes, updated_at) VALUES (?,?,?)
		ON CONFLICT(subscription_id) DO UPDATE SET used_bytes=excluded.used_bytes, updated_at=excluded.updated_at`,
		sub.ID, used, time.Now().UTC().Format(time.RFC3339Nano)); uerr != nil {
		return uerr
	}
	if sub.PrimaryDeviceID != "" {
		if _, err := tx.Exec(`UPDATE subscriptions SET primary_device_id=? WHERE id=?`, sub.PrimaryDeviceID, sub.ID); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM sub_quota_device WHERE subscription_id=?`, sub.ID); err != nil {
		return err
	}
	devicesWithQuota := make(map[string]bool)
	for id := range sub.DeviceUsage {
		devicesWithQuota[id] = true
	}
	for id := range sub.DeviceLimits {
		devicesWithQuota[id] = true
	}
	for id := range devicesWithQuota {
		limit := sub.DeviceLimits[id]
		if sub.DeviceUsage[id] < 0 || (limit != nil && *limit < 0) {
			return fmt.Errorf("VALIDATION_FAILED: invalid imported device quota")
		}
		if _, err := tx.Exec(`INSERT INTO sub_quota_device(subscription_id,device_id,used_bytes,limit_bytes,updated_at) VALUES (?,?,?,?,?)`,
			sub.ID, id, sub.DeviceUsage[id], limit, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO sub_rate(subscription_id,download_bps,upload_bps,updated_at) VALUES (?,?,?,?)
		ON CONFLICT(subscription_id) DO UPDATE SET download_bps=excluded.download_bps, upload_bps=excluded.upload_bps, updated_at=excluded.updated_at`,
		sub.ID, sub.RateDownBPS, sub.RateUpBPS, now); err != nil {
		return err
	}
	// catalog replace (tx-scoped SetSubscriptionProfiles)
	if _, derr := tx.Exec(`DELETE FROM subscription_profiles WHERE subscription_id=?`, sub.ID); derr != nil {
		return derr
	}
	for i := range profiles {
		p := profiles[i]
		if _, ierr := tx.Exec(`INSERT INTO subscription_profiles(subscription_id, seq, label_ru, label_en, kind, node_id, ingress_addr, sni, protocol, route_port, download_bps, upload_bps, limit_bytes, created_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			sub.ID, p.Seq, p.LabelRU, p.LabelEn, p.Kind, p.NodeID, p.IngressAddr, p.SNI, p.Protocol, p.RoutePort, p.DownloadBPS, p.UploadBPS, p.LimitBytes, now); ierr != nil {
			return ierr
		}
	}
	// migrated identities (idempotent)
	for _, d := range devices {
		if d.ID == "" || d.VlessUUID == "" {
			return fmt.Errorf("VALIDATION_FAILED: migrated device incomplete")
		}
		if _, ierr := tx.Exec(`INSERT INTO devices(id, account_id, name, created_at, revoked_at, enrollment_used_at, identity_pubkey, vless_uuid, expires_unix)
			VALUES (?,?,?,?,NULL,?,'migrated',?,?) ON CONFLICT(id) DO NOTHING`,
			d.ID, sub.AccountID, d.Name, d.CreatedAt, now, d.VlessUUID, d.ExpiresUnix); ierr != nil {
			return ierr
		}
	}
	if sub.MaxDevices != nil {
		var registered int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM devices WHERE account_id=? AND revoked_at IS NULL`, sub.AccountID).Scan(&registered); err != nil {
			return err
		}
		if registered > *sub.MaxDevices {
			return fmt.Errorf("CONFLICT: DEVICE_SLOTS_FULL on target panel")
		}
	}
	return tx.Commit()
}

// RoutePortHashBase derives the collision-probe START for an exit id
// (C04): a function of the ROUTE IDENTITY only — adding or removing other
// exits never remaps a published endpoint.
func RoutePortHashBase(nodeID string) int {
	h := fnv.New32a()
	h.Write([]byte(nodeID))
	return 40000 + int(h.Sum32()%24000)
}

// route_ports (C04): a DURABLE registry route identity (edge, exit) →
// dedicated port. A published endpoint NEVER remaps because the exit set
// changed: the allocation happens once and survives add/remove/rename of
// other exits; deleting the exit frees the binding.
func (s *Store) migrateRoutePorts() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS route_ports (
		edge_node_id TEXT NOT NULL,
		node_id TEXT NOT NULL,
		port INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (edge_node_id, node_id))`)
	return err
}

// AllocateRoutePort returns the stable port for (edge, exit), allocating
// one on first use. Allocation probes from the exit's hash base and skips
// ports already bound to OTHER routes of this edge and the well-known
// management range.
func (s *Store) AllocateRoutePort(edgeNodeID, nodeID string) (int, error) {
	if err := s.migrateRoutePorts(); err != nil {
		return 0, err
	}
	var port int
	err := s.db.QueryRow(`SELECT port FROM route_ports WHERE edge_node_id=? AND node_id=?`, edgeNodeID, nodeID).Scan(&port)
	if err == nil {
		return port, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	taken := map[int]bool{}
	rows, err := s.db.Query(`SELECT port FROM route_ports WHERE edge_node_id=?`, edgeNodeID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return 0, err
		}
		taken[p] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	base := RoutePortHashBase(nodeID)
	for i := 0; i < 24000; i++ {
		cand := base + i
		if cand > 65535 {
			return 0, fmt.Errorf("VALIDATION_FAILED: route port space exhausted for edge %s", edgeNodeID)
		}
		if !taken[cand] {
			if _, ierr := s.db.Exec(`INSERT INTO route_ports(edge_node_id, node_id, port, created_at) VALUES (?,?,?,?)`,
				edgeNodeID, nodeID, cand, time.Now().UTC().Format(time.RFC3339Nano)); ierr != nil {
				return 0, ierr
			}
			return cand, nil
		}
	}
	return 0, fmt.Errorf("VALIDATION_FAILED: no free route port for %s on edge %s", nodeID, edgeNodeID)
}

// RoutePortOf returns the allocated port (false when never allocated).
func (s *Store) RoutePortOf(edgeNodeID, nodeID string) (int, bool) {
	var port int
	if err := s.db.QueryRow(`SELECT port FROM route_ports WHERE edge_node_id=? AND node_id=?`, edgeNodeID, nodeID).Scan(&port); err != nil {
		return 0, false
	}
	return port, true
}

// FreeRoutePortsOf removes the route bindings of a deleted node.
func (s *Store) FreeRoutePortsOf(nodeID string) error {
	if err := s.migrateRoutePorts(); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM route_ports WHERE node_id=?`, nodeID)
	return err
}

// GrantEdgeSubscriptionDelegation records that panel_id's edge is an
// authorized serving edge for the subscription (B05: quota/dispatch
// delegation is per-object, granted by the owner at edge-config apply).
func (s *Store) GrantEdgeSubscriptionDelegation(panelID, subID, grantedBy string) error {
	_, err := s.db.Exec(`INSERT INTO edge_sub_delegation(panel_id, subscription_id, granted_by, granted_at)
		VALUES (?,?,?,?) ON CONFLICT(panel_id, subscription_id) DO NOTHING`,
		panelID, subID, grantedBy, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// EdgeSubscriptionDelegated reports whether the edge is authorized.
func (s *Store) EdgeSubscriptionDelegated(panelID, subID string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM edge_sub_delegation WHERE panel_id=? AND subscription_id=?`,
		panelID, subID).Scan(&n)
	return n > 0
}

// StoreEdgeConfig keeps the latest edge config document for federation
// dispatch (the serving edge pulls it signed).
func (s *Store) StoreEdgeConfig(panelID, configJSON, hash string) error {
	_, err := s.db.Exec(`INSERT INTO edge_configs(panel_id, config_json, config_hash, updated_at) VALUES (?,?,?,?)
		ON CONFLICT(panel_id) DO UPDATE SET config_json=excluded.config_json, config_hash=excluded.config_hash, updated_at=excluded.updated_at`,
		panelID, configJSON, hash, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// EdgeConfigFor returns (config_json, hash) for a panel.
func (s *Store) EdgeConfigFor(panelID string) (string, string, error) {
	var cj, h string
	err := s.db.QueryRow(`SELECT config_json, config_hash FROM edge_configs WHERE panel_id=?`, panelID).Scan(&cj, &h)
	return cj, h, err
}

// QuotaUsage returns (used_total, limit) for the subscription.
func (s *Store) QuotaUsage(subID string) (int64, *int64, error) {
	sub, err := s.GetSubscription(subID)
	if err != nil {
		return 0, nil, err
	}
	var total int64
	if err := s.db.QueryRow(`SELECT used_bytes FROM sub_quota WHERE subscription_id=?`, subID).Scan(&total); err != nil {
		return 0, nil, err
	}
	return total, sub.LimitsBytes, nil
}

// SetSubscriptionFetchBase records where the installed client should
// fetch after the transfer (the old panel signs the pointer by serving
// it; the client validates the destination independently).
func (s *Store) SetSubscriptionFetchBase(subID, base string) error {
	_, err := s.db.Exec(`UPDATE subscriptions SET fetch_base=? WHERE id=?`, base, subID)
	return err
}

// SubscriptionFetchBase returns the recorded follow base.
func (s *Store) SubscriptionFetchBase(subID string) (string, error) {
	var b string
	err := s.db.QueryRow(`SELECT fetch_base FROM subscriptions WHERE id=?`, subID).Scan(&b)
	return b, err
}

// guardDeviceLive (B04/interim): the subscription's account device
// registry decides. If the panel knows ANY devices for the subscription's
// account, the holder must be one of them, live — a revoked, foreign, or
// unregistered device never acquires budget. If the account has NO
// registered devices, holders are edge-local synthetic ids and the check
// passes (their authorization lives in the Edge identity table).
func guardDeviceLive(tx *sql.Tx, devKey, subID string) error {
	var subAccount string
	if err := tx.QueryRow(`SELECT account_id FROM subscriptions WHERE id=?`, subID).Scan(&subAccount); err != nil {
		return err
	}
	var total, allowed int
	if err := tx.QueryRow(`SELECT COUNT(*),COUNT(CASE WHEN id=? AND revoked_at IS NULL
		AND (expires_unix=0 OR expires_unix>unixepoch()) THEN 1 END) FROM devices WHERE account_id=?`,
		devKey, subAccount).Scan(&total, &allowed); err != nil {
		return err
	}
	if total == 0 || allowed == 1 {
		return nil
	}
	return fmt.Errorf("AUTH_FAILED: %w", ErrDeviceAccess)

}

// RegisterTestDevice is the exported explicit-id device registration used
// by package-external fixtures (cmd tests) that must control device ids.
func (s *Store) RegisterTestDevice(account, id string) error {
	_, err := s.db.Exec(`INSERT INTO devices(id, account_id, name, created_at, identity_pubkey, vless_uuid)
		VALUES (?,?,'fixture',?,'','')
		ON CONFLICT(id) DO NOTHING`, id, account, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
