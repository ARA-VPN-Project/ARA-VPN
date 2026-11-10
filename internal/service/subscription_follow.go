// Client auto-follow after a subscription ownership transfer (review
// 2026-11-01, "автоматическое обновление установленного клиента"): the
// installed client keeps fetching its catalog by the UNCHANGED token. On
// a MOVED notice it follows to the base recorded by its OWN trusted
// panel, validates the destination payload independently, and keeps the
// last good catalog as LKG. Scope preservation: the new catalog must
// carry the SAME device identity (UUID) the client was enrolled with —
// a catalog for a different user is refused. Rights never widen: the
// catalog is data, the enforcement stays on the serving edges.
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// SubscriptionFollowResult reports one follow attempt.
type SubscriptionFollowResult struct {
	Followed       bool   `json:"followed"`           // switched to the new owner base
	CatalogOK      bool   `json:"catalog_ok"`         // a valid catalog is in place
	LKGUsed        bool   `json:"lkg_used,omitempty"` // served from the last good catalog
	Base           string `json:"base"`               // the base the catalog came from
	Hash           string `json:"hash,omitempty"`     // sha256 of the stored catalog
	Profiles       int    `json:"profiles,omitempty"`
	ProfileApplied bool   `json:"profile_applied,omitempty"` // catalog applied to profiles/default.json
	Error          string `json:"error,omitempty"`
}

func (s *StateDir) SubscriptionDir() string { return filepath.Join(s.Root, "subscription") }

// SubscriptionFollow fetches the catalog for token; follows ONE moved
// hop to a base recorded by the trusted panel; validates the payload
// (schema + the enrolled device identity); stores catalog.json with the
// previous one as LKG. Never auto-accepts an invalid or foreign catalog.
func SubscriptionFollow(stateDir StateDir, client *http.Client, token, base, enrolledUUID string) (*SubscriptionFollowResult, error) {
	if token == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: subscription token required")
	}
	res := &SubscriptionFollowResult{}
	if err := os.MkdirAll(stateDir.SubscriptionDir(), 0o700); err != nil {
		return nil, err
	}
	fetch := func(b string) (map[string]any, error) {
		req, err := http.NewRequest(http.MethodGet, SubscriptionTokenURL(b, token), nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("AUTH_FAILED: subscription token refused by the panel")
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("catalog undecodable (HTTP %d): %w", resp.StatusCode, err)
		}
		if resp.StatusCode != http.StatusOK {
			if msg, _ := out["error"].(string); msg != "" {
				return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
			}
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return out, nil
	}
	catalog, err := fetch(base)
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	if moved, _ := catalog["moved"].(bool); moved {
		target, _ := catalog["fetch_base"].(string)
		if target == "" {
			res.Error = "moved notice without fetch_base: operator handoff incomplete"
			return res, nil
		}
		// follow ONE hop, only to the base the TRUSTED panel recorded
		catalog, err = fetch(target)
		if err != nil {
			// keep the LKG; retry happens on the next follow
			res.Followed = true
			res.Error = fmt.Sprintf("follow fetch failed: %v", err)
			return res, nil
		}
		res.Followed = true
		base = target
	}
	if err := validateFollowedCatalog(catalog, enrolledUUID); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	b, _ := json.MarshalIndent(catalog, "", "  ")
	sum := sha256.Sum256(b)
	res.Hash = hex.EncodeToString(sum[:])
	res.Base = base
	if profiles, ok := catalog["profiles"].([]any); ok {
		res.Profiles = len(profiles)
	}
	dir := stateDir.SubscriptionDir()
	// previous good catalog becomes the LKG
	if prev, err := os.ReadFile(filepath.Join(dir, "catalog.json")); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "lkg.json"), prev, 0o600)
	} else {
		res.LKGUsed = true // first fetch: nothing older exists
	}
	tmp := filepath.Join(dir, "catalog.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	if err := os.Rename(tmp, filepath.Join(dir, "catalog.json")); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	res.CatalogOK = true
	return res, nil
}

// validateFollowedCatalog checks the schema and the SCOPE: the catalog
// must carry the client's own enrolled identity — a catalog for a
// different user never replaces the local one.
func validateFollowedCatalog(catalog map[string]any, enrolledUUID string) error {
	if catalog["schema"] != "ara.subscription/v1" {
		return fmt.Errorf("VALIDATION_FAILED: catalog schema %v unsupported", catalog["schema"])
	}
	profs, ok := catalog["profiles"].([]any)
	if !ok || len(profs) == 0 {
		return fmt.Errorf("VALIDATION_FAILED: catalog has no profiles")
	}
	uuids := map[string]bool{}
	for i, p := range profs {
		pm, ok := p.(map[string]any)
		if !ok {
			return fmt.Errorf("VALIDATION_FAILED: profile %d malformed", i)
		}
		cfg, ok := pm["client_config"].(map[string]any)
		if !ok {
			return fmt.Errorf("VALIDATION_FAILED: profile %d has no client_config", i)
		}
		obs, ok := cfg["outbounds"].([]any)
		if !ok || len(obs) == 0 {
			return fmt.Errorf("VALIDATION_FAILED: profile %d has no outbound", i)
		}
		ob, ok := obs[0].(map[string]any)
		if !ok {
			return fmt.Errorf("VALIDATION_FAILED: profile %d outbound malformed", i)
		}
		if u, ok := ob["uuid"].(string); ok {
			uuids[u] = true
		}
	}
	if enrolledUUID != "" && !uuids[enrolledUUID] {
		return fmt.Errorf("AUTH_FAILED: catalog does not carry this device's identity (scope check failed)")
	}
	return nil
}

// SubscriptionLKGPath is where the last good catalog lives.
func (s *StateDir) SubscriptionLKGPath() string {
	return filepath.Join(s.SubscriptionDir(), "lkg.json")
}

var _ = time.Now
