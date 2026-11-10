package controlstore

// Links: Edge→Exit associations with per-hop transport (docs/TRANSPORTS.md
// — Client→Edge and Edge→Exit are configured independently) and failover
// priority. The control plane is the source of truth; the rendered edge
// config is derived from devices[] + links.

import (
	"fmt"
	"time"
)

// Link is one Edge→Exit association. Transport stays the NETWORK transport
// (tcp|udp); the wire protocol choice is the referenced transport profile
// (ProfileID). Legacy semantics: a tcp link with no profile renders the
// historical VLESS+TLS transit; a udp link REQUIRES an explicitly defined
// hysteria2 profile — credentials are never guessed
// (docs/TRANSPORT_PROFILES.md migration section).
type Link struct {
	ID        string    `json:"id"`
	EdgeID    string    `json:"edge_id"`
	ExitID    string    `json:"exit_id"`
	Transport string    `json:"transport"` // tcp | udp
	Priority  int       `json:"priority"`  // lower = preferred
	ProfileID *string   `json:"profile_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) migrateLinks() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS links (
		id TEXT PRIMARY KEY,
		edge_id TEXT NOT NULL,
		exit_id TEXT NOT NULL,
		transport TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
		priority INTEGER NOT NULL DEFAULT 100,
		created_at TEXT NOT NULL,
		revoked_at TEXT)`)
	if err != nil {
		return err
	}
	// column added in the transport-profile migration: tolerate databases
	// created before it (same pattern as devices.vless_uuid)
	_, _ = s.db.Exec(`ALTER TABLE links ADD COLUMN profile_id TEXT REFERENCES transport_profiles(id)`)
	return nil
}

// AddLink creates an Edge→Exit association. A udp link must reference an
// explicitly defined hysteria2 transport profile; tcp may stay nil (the
// legacy VLESS+TLS transit) or reference a vless/trojan profile.
func (s *Store) AddLink(edgeID, exitID, transport string, priority int, profileID *string) (*Link, error) {
	if transport != "tcp" && transport != "udp" {
		return nil, fmt.Errorf("VALIDATION_FAILED: transport must be tcp or udp")
	}
	if transport == "udp" && profileID == nil {
		return nil, fmt.Errorf("VALIDATION_FAILED: udp link requires an explicitly defined hysteria2 transport profile (credentials are never guessed)")
	}
	if profileID != nil {
		if err := s.checkLinkProfile(exitID, transport, *profileID); err != nil {
			return nil, err
		}
	}
	id, err := randomID("lnk")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err := s.db.Exec(`INSERT INTO links(id, edge_id, exit_id, transport, priority, profile_id, created_at) VALUES (?,?,?,?,?,?,?)`,
		id, edgeID, exitID, transport, priority, profileID, now.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	return &Link{ID: id, EdgeID: edgeID, ExitID: exitID, Transport: transport, Priority: priority, ProfileID: profileID, CreatedAt: now}, nil
}

// checkLinkProfile validates profile↔link consistency: the profile must
// belong to the link's exit, be active and carry the link's network
// transport (trojan/vless→tcp, hysteria2→udp).
func (s *Store) checkLinkProfile(exitID, transport, profileID string) error {
	p, err := s.GetTransportProfile(profileID)
	if err != nil {
		return err
	}
	if p.NodeID != exitID {
		return fmt.Errorf("VALIDATION_FAILED: transport profile %s belongs to node %s, not exit %s", profileID, p.NodeID, exitID)
	}
	if p.RevokedAt != nil {
		return fmt.Errorf("VALIDATION_FAILED: transport profile %s is revoked", profileID)
	}
	if string(p.Transport) != transport {
		return fmt.Errorf("VALIDATION_FAILED: transport profile %s is %s, link transport is %s", profileID, p.Transport, transport)
	}
	return nil
}

// SetLinkProfile switches the transport profile of an active link
// (protocol change on the Edge→Exit hop). The network transport of the
// new profile must match the link's transport; use a new link for a
// tcp↔udp change.
func (s *Store) SetLinkProfile(linkID string, profileID *string) (*Link, error) {
	l, err := s.GetLink(linkID)
	if err != nil {
		return nil, err
	}
	if l.RevokedAt != nil {
		return nil, fmt.Errorf("VALIDATION_FAILED: link %s is revoked", linkID)
	}
	if profileID != nil {
		if err := s.checkLinkProfile(l.ExitID, l.Transport, *profileID); err != nil {
			return nil, err
		}
	} else if l.Transport == "udp" {
		return nil, fmt.Errorf("VALIDATION_FAILED: udp link requires an explicitly defined hysteria2 transport profile")
	}
	if _, err := s.db.Exec(`UPDATE links SET profile_id=? WHERE id=? AND revoked_at IS NULL`, profileID, linkID); err != nil {
		return nil, err
	}
	return s.GetLink(linkID)
}

// GetLink returns one active link by id.
func (s *Store) GetLink(id string) (*Link, error) {
	rows, err := s.db.Query(`SELECT id, edge_id, exit_id, transport, priority, profile_id, created_at, COALESCE(revoked_at,'') FROM links WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("not found: %s", id)
	}
	l, err := scanLink(rows)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// FindLink returns the active link between an edge and an exit, or nil.
func (s *Store) FindLink(edgeID, exitID string) (*Link, error) {
	rows, err := s.db.Query(`SELECT id, edge_id, exit_id, transport, priority, profile_id, created_at, COALESCE(revoked_at,'')
		FROM links WHERE edge_id=? AND exit_id=? AND revoked_at IS NULL ORDER BY priority LIMIT 1`, edgeID, exitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	return scanLink(rows)
}

// RevokeLink removes the association (soft revoke).
func (s *Store) RevokeLink(id string) error {
	res, err := s.db.Exec(`UPDATE links SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("not found or already revoked: %s", id)
	}
	return nil
}

// ListLinks returns active links.
func (s *Store) ListLinks() ([]Link, error) {
	rows, err := s.db.Query(`SELECT id, edge_id, exit_id, transport, priority, profile_id, created_at, COALESCE(revoked_at,'') FROM links ORDER BY priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		if l.RevokedAt == nil {
			out = append(out, *l)
		}
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanLink(rows rowScanner) (*Link, error) {
	var l Link
	var created, revoked string
	var profileID *string
	if err := rows.Scan(&l.ID, &l.EdgeID, &l.ExitID, &l.Transport, &l.Priority, &profileID, &created, &revoked); err != nil {
		return nil, err
	}
	l.ProfileID = profileID
	l.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if revoked != "" {
		t, _ := time.Parse(time.RFC3339Nano, revoked)
		l.RevokedAt = &t
	}
	return &l, nil
}
