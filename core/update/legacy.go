// legacy.go — ЗАМЕДЛЕННЫЙ (устаревший) однодокументный формат метаданных
// обновлений. Он НЕ является TUF и НЕ принимается VerifyTUF (стандартный
// TUF-верификатор — tuf.go поверх go-tuf/v2). Типы и SignRole сохранены
// только для: (а) отрицательной регрессии подмены корня, (б) совместимости
// overlay-тестов независимого ревью, (в) legacy-пути --metadata.

package update

// TUF role chain (task F): the single signed-metadata document is not TUF.
// This implements the role separation: root (keys + threshold, self-pinned
// rotation), timestamp (freshness, short expiry), snapshot (role versions)
// and targets (artifact hashes). Verification walks root → timestamp →
// snapshot → targets with per-role monotonic versions (anti-rollback) and
// per-role expiry (freeze protection). Keys are separate per role.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sort"
	"fmt"
	"os"
	"time"
)

// Role names.
const (
	RoleRoot      = "root"
	RoleTimestamp = "timestamp"
	RoleSnapshot  = "snapshot"
	RoleTargets   = "targets"
)

// tufSigned is the common envelope of one signed role document.
type tufSigned struct {
	Role       string        `json:"role"`
	Version    int           `json:"version"`
	ExpiresAt  time.Time     `json:"expires_at"`
	SignedAny  json.RawMessage `json:"signed"`
	Signatures []Signature   `json:"signatures"`
}

func (t *tufSigned) payload() ([]byte, error) {
	cp := struct {
		Role      string          `json:"role"`
		Version   int             `json:"version"`
		ExpiresAt time.Time       `json:"expires_at"`
		SignedAny json.RawMessage `json:"signed"`
	}{t.Role, t.Version, t.ExpiresAt.UTC(), t.SignedAny}
	// canonical via json.Marshal: Go maps/structs marshal deterministically
	return json.Marshal(cp)
}

// RootSigned carries the trusted key set and threshold per role.
type RootSigned struct {
	Type       string            `json:"type"` // root
	Keys       map[string]string `json:"keys"`    // keyID → hex pubkey
	RoleKeyIDs map[string][]string `json:"role_key_ids"` // role → signing keyIDs
	Threshold  map[string]int    `json:"threshold"`    // role → required distinct signatures
}

// TimestampSigned points at the current snapshot.
type TimestampSigned struct {
	Type           string `json:"type"`
	SnapshotVer    int    `json:"snapshot_version"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
}

// SnapshotSigned pins the versions of the other roles.
type SnapshotSigned struct {
	Type       string `json:"type"`
	TargetsVer int    `json:"targets_version"`
	RootVer    int    `json:"root_version"`
}

// TargetsSigned is the target artifact table (reuses Target).
type TargetsSigned struct {
	Type    string   `json:"type"`
	Targets []Target `json:"targets"`
}

// SignRole signs one role document with the role key.
func SignRole(role string, version int, expires time.Time, signed any, keyID string, priv ed25519.PrivateKey) ([]byte, error) {
	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	doc := tufSigned{Role: role, Version: version, ExpiresAt: expires.UTC(), SignedAny: raw}
	payload, err := doc.payload()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, payload)
	doc.Signatures = []Signature{{KeyID: keyID, Sig: hex.EncodeToString(sig)}}
	return json.MarshalIndent(doc, "", "  ")
}

// VerifyRole checks one role document: trusted keys for the role, distinct
// signatures threshold, expiry, and returns the version + signed payload.
func VerifyRole(role string, data []byte, now time.Time, keyIDToPub map[string]string, threshold int) (int, json.RawMessage, error) {
	var doc tufSigned
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, nil, fmt.Errorf("%s: malformed: %w", role, err)
	}
	if doc.Role != role {
		return 0, nil, fmt.Errorf("%s: document is %q", role, doc.Role)
	}
	if now.After(doc.ExpiresAt.UTC()) {
		return 0, nil, fmt.Errorf("%s expired at %s", role, doc.ExpiresAt.Format(time.RFC3339))
	}
	payload, err := doc.payload()
	if err != nil {
		return 0, nil, err
	}
	seen := map[string]bool{}
	for _, s := range doc.Signatures {
		pubHex, trusted := keyIDToPub[s.KeyID]
		if !trusted {
			continue
		}
		pub, derr := hex.DecodeString(pubHex)
		if derr != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		sig, derr2 := hex.DecodeString(s.Sig)
		if derr2 != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
			seen[s.KeyID] = true
		}
	}
	if len(seen) < threshold {
		return 0, nil, fmt.Errorf("%s: %d distinct valid signatures, threshold %d", role, len(seen), threshold)
	}
	return doc.Version, doc.SignedAny, nil
}

// LoadRootFile reads a root role document.
func LoadRootFile(path string) ([]byte, *tufSigned, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc tufSigned
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, err
	}
	return b, &doc, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func roleKeys(all map[string]string, kids []string) map[string]string {
	out := map[string]string{}
	for _, kid := range kids {
		if pub, ok := all[kid]; ok {
			out[kid] = pub
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
