package service

// Panel identity for the local state dir: every Control Center (and every
// CLI working on a control state dir) owns an Ed25519 identity used for
// mutual federation authentication. Admin/operator tokens are NEVER used
// for federation and federation keys never grant local admin rights.

import (
	"fmt"
	"path/filepath"
	"strings"

	"aravpn/core/fedauth"
)

// PanelRedeem establishes the same HTTPS-authenticated federation link for
// console and API operators. The invite token is never persisted locally.
func (s *Service) PanelRedeem(base, token string) (map[string]any, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if err := ValidateFedBase(base); err != nil {
		return nil, err
	}
	if token == "" || len(token) > 128 {
		return nil, fmt.Errorf("VALIDATION_FAILED: invite token required")
	}
	identity := s.PanelIdentity()
	if identity == nil {
		return nil, fmt.Errorf("VALIDATION_FAILED: initialize the panel identity")
	}
	out, err := NewFedCall(base, identity).PostRedeem(token, identity.PanelID, identity.PublicHex())
	if err != nil {
		return nil, err
	}
	id, _ := out["panel_id"].(string)
	key, _ := out["public_key"].(string)
	scopes, _ := out["scopes"].(string)
	if id == "" || id == identity.PanelID || key == "" || scopes == "" {
		return nil, fmt.Errorf("AUTH_FAILED: invalid peer identity")
	}
	store, err := s.OpenControlStore()
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if err := store.AddLinkedPanel(id, key, scopes); err != nil {
		return nil, err
	}
	return out, nil
}

// PanelIdentity loads (does not create) the local panel identity.
func (s *Service) PanelIdentity() *fedauth.Identity {
	id, _ := fedauth.LoadOrCreate(s.State.Root, "")
	return id
}

// PanelID returns the local panel id ("" when the state dir has none).
func (s *Service) PanelID() string {
	id := s.PanelIdentity()
	if id == nil {
		return ""
	}
	return id.PanelID
}

// PanelInit creates the panel identity for this state dir.
func (s *Service) PanelInit(panelID string) (*fedauth.Identity, error) {
	return fedauth.LoadOrCreate(s.State.Root, panelID)
}

func panelIdentityPath(root string) string { return filepath.Join(root, "panel_identity.json") }
