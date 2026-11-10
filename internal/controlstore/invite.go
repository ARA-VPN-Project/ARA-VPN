package controlstore

// Invites (docs/CLIENT_INVITES_QR.md): single-use enrollment links with
// TTL and revocation. The server stores ONLY the SHA-256 of the invite
// token; the plaintext token is shown once at creation. Redeem is a
// single conditional UPDATE — replay/expiry/revocation/concurrent redeem
// are indistinguishable refusals.

import (
	"fmt"
	"time"
)

// Invite is one single-use enrollment token.
type Invite struct {
	ID         string     `json:"id"`
	DeviceID   string     `json:"device_id"`
	AccountID  string     `json:"account_id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) migrateInvites() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS invites (
		id TEXT PRIMARY KEY,
		device_id TEXT NOT NULL REFERENCES devices(id),
		account_id TEXT NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		consumed_at TEXT,
		revoked_at TEXT)`)
	return err
}

// CreateInvite mints a one-time token for an existing device. The
// plaintext token is returned exactly once and never stored.
func (s *Store) CreateInvite(deviceID string, ttl time.Duration) (*Invite, string, error) {
	var accountID, revoked string
	err := s.db.QueryRow(`SELECT account_id, COALESCE(revoked_at,'') FROM devices WHERE id=?`, deviceID).
		Scan(&accountID, &revoked)
	if err != nil {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: unknown device %q", deviceID)
	}
	if revoked != "" {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: device %q is revoked", deviceID)
	}
	id, err := randomID("inv")
	if err != nil {
		return nil, "", err
	}
	token, err := randomSecret(32)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)
	if _, err := s.db.Exec(`INSERT INTO invites(id, device_id, account_id, token_hash, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
		id, deviceID, accountID, sha256Hex(token), now.Format(time.RFC3339Nano), exp.Format(time.RFC3339Nano)); err != nil {
		return nil, "", err
	}
	return &Invite{ID: id, DeviceID: deviceID, AccountID: accountID, CreatedAt: now, ExpiresAt: exp}, token, nil
}

// RedeemInvite atomically consumes a valid, unexpired, unrevoked token
// and returns the device identity for the client profile. Replay, expiry,
// revocation and concurrent redeem are the same refusal.
func (s *Store) RedeemInvite(token string) (*Device, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`UPDATE invites SET consumed_at=?
		WHERE token_hash=? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM devices d WHERE d.id=invites.device_id AND d.revoked_at IS NULL AND (d.expires_unix=0 OR d.expires_unix>unixepoch()))`,
		now.Format(time.RFC3339Nano), sha256Hex(token), now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("AUTH_FAILED: invite is invalid, expired, revoked or already used")
	}
	var d Device
	var created, revoked string
	err = s.db.QueryRow(`SELECT id, account_id, name, created_at, COALESCE(revoked_at,''), vless_uuid, expires_unix FROM devices
		WHERE id=(SELECT device_id FROM invites WHERE token_hash=?)`, sha256Hex(token)).
		Scan(&d.ID, &d.AccountID, &d.Name, &created, &revoked, &d.VlessUUID, &d.ExpiresUnix)
	if err != nil {
		return nil, fmt.Errorf("AUTH_FAILED: invite is invalid, expired, revoked or already used")
	}
	d.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if revoked != "" || d.ExpiresUnix > 0 && now.Unix() >= d.ExpiresUnix {
		return nil, fmt.Errorf("AUTH_FAILED: invite is invalid, expired, revoked or already used")
	}
	return &d, nil
}

// RevokeInvite invalidates an outstanding token.
func (s *Store) RevokeInvite(id string) error {
	res, err := s.db.Exec(`UPDATE invites SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("not found or already revoked: %s", id)
	}
	return nil
}

// ListInvites returns recent invites (audit view; no secrets).
func (s *Store) ListInvites() ([]Invite, error) {
	rows, err := s.db.Query(`SELECT id, device_id, account_id, created_at, expires_at,
		consumed_at, revoked_at FROM invites ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		var created, exp, consumed, revoked string
		if err := rows.Scan(&inv.ID, &inv.DeviceID, &inv.AccountID, &created, &exp, &consumed, &revoked); err != nil {
			return nil, err
		}
		inv.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		inv.ExpiresAt, _ = time.Parse(time.RFC3339Nano, exp)
		if consumed != "" {
			t, _ := time.Parse(time.RFC3339Nano, consumed)
			inv.ConsumedAt = &t
		}
		if revoked != "" {
			t, _ := time.Parse(time.RFC3339Nano, revoked)
			inv.RevokedAt = &t
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}
