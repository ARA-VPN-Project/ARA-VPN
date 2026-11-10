// Package update implements the signed-update trust model
// (docs/UPDATES.md): ed25519-signed metadata with expiry, version
// monotonicity (anti-rollback), target hash+length checks and
// platform/arch/component target selection.
//
// TRUST NOTE: this is the metadata CONTRACT and verification order for ARA.
// The signing format is a documented subset (single root key, thresholds
// recorded in metadata) intended for dev/test keys. Production must use a
// mature TUF implementation (root rotation, 2-of-3 offline root threshold,
// timestamp/snapshot roles); that integration is tracked in
// docs/IMPLEMENTATION_STATUS.md and must land before any production
// release. No cryptography is invented here: signatures are stdlib
// ed25519 over canonical JSON.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Metadata is the signed top-level document. SignedBytes covers everything
// except the signature fields themselves.
// DEV/TEST TRUST BOUNDARY (ADR 0004, executed per review R13/R14): this
// format is a bounded development verifier, NOT production TUF. It
// supports a trusted key SET with a distinct-key signature threshold, but
// has no root rotation, offline key ceremonies, timestamp/snapshot roles
// or mirror-consistency guarantees. Production releases require the TUF
// integration tracked in ADR 0004; a Threshold above the number of
// trusted keys is rejected as unsupported rather than weakened.
type Metadata struct {
	Version   int       `json:"version"` // monotonically increasing
	ExpiresAt time.Time `json:"expires_at"`
	Channel   string    `json:"channel"` // stable | beta | dev
	// RootPubKey is the single-key form; RootPubKeys is the multi-key
	// trusted set. If RootPubKeys is empty, RootPubKey becomes the only
	// trusted key. Verification counts DISTINCT trusted keys.
	RootPubKey  string      `json:"root_pubkey,omitempty"`
	RootPubKeys []string    `json:"root_pubkeys,omitempty"`
	Threshold   int         `json:"threshold"` // required distinct signatures
	Targets     []Target    `json:"targets"`
	Signatures  []Signature `json:"signatures"`
}

// trustedKeys returns the normalized trusted key set.
func (m *Metadata) trustedKeys() []string {
	if len(m.RootPubKeys) > 0 {
		return m.RootPubKeys
	}
	if m.RootPubKey != "" {
		return []string{m.RootPubKey}
	}
	return nil
}

// Target is one releasable artifact.
type Target struct {
	Component   string `json:"component"` // ara-client | ara-agent | ara-control | ara-core | ui
	OS          string `json:"os"`        // linux (future: darwin, windows, android, ios)
	Arch        string `json:"arch"`      // amd64 | arm64
	Format      string `json:"format"`    // deb | docker | tar
	Version     string `json:"version"`
	MinCoreAPI  int    `json:"min_core_api"`
	SchemaRange string `json:"schema_range"` // e.g. "1-1"
	Length      int64  `json:"length"`
	SHA256      string `json:"sha256"`
	URL         string `json:"url"`
}

// Signature is one detached ed25519 signature over the canonical metadata.
type Signature struct {
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"` // hex
}

// signedPayload returns the canonical serialization covered by signatures:
// the metadata document without the Signatures field.
type signedDoc struct {
	Version     int       `json:"version"`
	ExpiresAt   time.Time `json:"expires_at"`
	Channel     string    `json:"channel"`
	RootPubKey  string    `json:"root_pubkey,omitempty"`
	RootPubKeys []string  `json:"root_pubkeys,omitempty"`
	Threshold   int       `json:"threshold"`
	Targets     []Target  `json:"targets"`
}

func (m *Metadata) signedPayload() ([]byte, error) {
	d := signedDoc{
		Version: m.Version, ExpiresAt: m.ExpiresAt, Channel: m.Channel,
		RootPubKey: m.RootPubKey, RootPubKeys: m.RootPubKeys,
		Threshold: m.Threshold, Targets: m.Targets,
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	// normalize: round-trip through map so field order is deterministic
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// Sign produces a signature over the canonical payload with a dev/test
// private key. Key management (offline root, rotation) is the release
// process's responsibility and is not implemented in this build.
func (m *Metadata) Sign(keyID string, priv ed25519.PrivateKey) error {
	payload, err := m.signedPayload()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	m.Signatures = append(m.Signatures, Signature{KeyID: keyID, Sig: hex.EncodeToString(sig)})
	return nil
}

// Verify performs the full check chain and returns the selected target.
// Order matters and is tested: trusted-key-set anchor check → expiry →
// threshold feasibility → channel enforcement → distinct-key signatures →
// target selection → artifact hash+length. The artifact check is part of
// Verify for convenience but is a DISTINCT property from metadata
// verification (review R14): metadata validity never validates artifact
// bytes that were not hashed into the metadata.
func (m *Metadata) Verify(trustedRootsHex []string, sel Selector, artifact []byte) (*Target, error) {
	keys := m.trustedKeys()
	trusted := map[string]bool{}
	for _, k := range trustedRootsHex {
		trusted[k] = true
	}
	for _, k := range keys {
		if !trusted[k] {
			return nil, fmt.Errorf("UPDATE_SIGNATURE_INVALID: metadata names a key outside the embedded trust anchor")
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("UPDATE_SIGNATURE_INVALID: metadata has no trusted key")
	}
	if time.Now().UTC().After(m.ExpiresAt.UTC()) {
		return nil, fmt.Errorf("UPDATE_EXPIRED: metadata expired at %s", m.ExpiresAt.Format(time.RFC3339))
	}
	if m.Threshold < 1 {
		return nil, fmt.Errorf("UPDATE_SIGNATURE_INVALID: threshold must be >= 1")
	}
	if m.Threshold > len(keys) {
		// Dev verifier bound (ADR 0004): a threshold the trusted set can
		// never meet is unsupported configuration, never a weak pass.
		return nil, fmt.Errorf("UNSUPPORTED_CAPABILITY: threshold %d exceeds %d trusted keys; production requires the TUF integration", m.Threshold, len(keys))
	}
	if sel.Channel != "" && m.Channel != sel.Channel {
		return nil, fmt.Errorf("UPDATE_CHANNEL_MISMATCH: metadata channel %q does not match requested channel %q", m.Channel, sel.Channel)
	}
	payload, err := m.signedPayload()
	if err != nil {
		return nil, err
	}
	verifiedBy := map[string]bool{} // distinct trusted keys that signed
	for _, s := range m.Signatures {
		sig, derr := hex.DecodeString(s.Sig)
		if derr != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		for _, k := range keys {
			pub, perr := hex.DecodeString(k)
			if perr != nil || len(pub) != ed25519.PublicKeySize {
				continue
			}
			if ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
				verifiedBy[k] = true // duplicates collapse to one vote
				break
			}
		}
	}
	if len(verifiedBy) < m.Threshold {
		return nil, fmt.Errorf("UPDATE_SIGNATURE_INVALID: %d distinct trusted keys signed, threshold %d", len(verifiedBy), m.Threshold)
	}
	t, err := sel.Select(m.Targets)
	if err != nil {
		return nil, err
	}
	if len(artifact) > 0 {
		if t.Length > 0 && int64(len(artifact)) != t.Length {
			return nil, fmt.Errorf("UPDATE_SIGNATURE_INVALID: length mismatch (metadata %d, artifact %d)", t.Length, len(artifact))
		}
		sum := sha256.Sum256(artifact)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), t.SHA256) {
			return nil, fmt.Errorf("UPDATE_SIGNATURE_INVALID: artifact hash mismatch")
		}
	}
	return t, nil
}

// Selector chooses the target for the running platform.
type Selector struct {
	Component string
	Channel   string
	OS        string // default runtime.GOOS
	Arch      string // default installed package architecture
	CoreAPI   int
	SchemaVer int
}

// Debian labels the supported Linux ARMv7 hard-float package armhf.
func installedArchitecture() string {
	if runtime.GOOS == "linux" && runtime.GOARCH == "arm" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "GOARM" && (setting.Value == "7" || setting.Value == "7,hardfloat") {
					return "armhf"
				}
			}
		}
	}
	return runtime.GOARCH
}

// Select implements the documented compatibility matrix: exact os/arch/
// component/channel match, versioned schema range and core API floor. It
// refuses cross-arch and cross-component installs (acceptance T19).
func (s Selector) Select(targets []Target) (*Target, error) {
	osName, arch := s.OS, s.Arch
	if osName == "" {
		osName = runtime.GOOS
	}
	if arch == "" {
		arch = installedArchitecture()
	}
	var candidates []Target
	for _, t := range targets {
		// channel is a metadata-level property; targets inherit it
		if t.Component != s.Component || t.OS != osName || t.Arch != arch {
			continue
		}
		if s.CoreAPI > 0 && t.MinCoreAPI > s.CoreAPI {
			continue
		}
		if s.SchemaVer > 0 && !schemaInRange(t.SchemaRange, s.SchemaVer) {
			continue
		}
		candidates = append(candidates, t)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("UNSUPPORTED_CAPABILITY: no signed target for %s/%s/%s channel %s", s.Component, osName, arch, s.Channel)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return CompareVersions(candidates[i].Version, candidates[j].Version) > 0
	})
	return &candidates[0], nil
}

// CompareVersions orders semantic versions descending-safe: it returns >0
// if a is newer than b. Dotted numeric release segments compare
// numerically (0.1.10 > 0.1.9 > 0.1.2, review R14); a pre-release is
// older than the corresponding release (1.0.0-rc1 < 1.0.0); unparsable
// versions compare as the empty version 0.0.0 with the raw string as
// tie-breaker, never panicking.
func CompareVersions(a, b string) int {
	va, pa, ca := parseSemverFull(a)
	vb, pb, cb := parseSemverFull(b)
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			if va[i] > vb[i] {
				return 1
			}
			return -1
		}
	}
	// a release outranks its own pre-releases
	if pa != pb {
		if pa {
			return 1
		}
		return -1
	}
	// both releases (numeric segments already equal, raw tie-break is
	// safe for the v-prefix case) or both pre-releases: compare the
	// pre-release identifiers segment by segment, numerics as numbers
	return comparePrerelease(ca, cb)
}

// comparePrerelease orders dotted identifiers with numeric comparison
// inside segments ("rc2" < "rc10"); empty prerelease is impossible here
// because both sides are prereleases at this point.
func comparePrerelease(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "-"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "-"), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an > bn {
					return 1
				}
				return -1
			}
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return len(as) - len(bs)
}

// parseSemverFull returns [major,minor,patch], whether the version is a
// release (no pre-release suffix), and the raw suffix ("-rc1", "+build")
// for tie-breaking. The optional leading "v" is accepted. Unparsable
// numeric segments degrade to 0.0.0 so comparisons never panic.
func parseSemverFull(v string) ([3]int, bool, string) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	suffix := ""
	isRelease := true
	if i := strings.IndexByte(v, '-'); i >= 0 {
		isRelease = false
		suffix = v[i:]
		v = v[:i]
	} else if i := strings.IndexByte(v, '+'); i >= 0 {
		suffix = v[i:]
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, isRelease, suffix
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, isRelease, suffix
		}
		out[i] = n
	}
	return out, isRelease, suffix
}

func schemaInRange(rng string, v int) bool {
	if rng == "" {
		return true
	}
	lo, hi, ok := strings.Cut(rng, "-")
	if !ok {
		return fmt.Sprint(v) == strings.TrimSpace(rng)
	}
	var loN, hiN int
	if _, err := fmt.Sscanf(lo, "%d", &loN); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(hi, "%d", &hiN); err != nil {
		return false
	}
	return v >= loN && v <= hiN
}

// CheckAntiRollback refuses metadata older than the last trusted version
// the updater already accepted (freeze/rollback defense; the accepted
// version persists locally).
func CheckAntiRollback(m *Metadata, lastTrustedVersion int) error {
	if m.Version < lastTrustedVersion {
		return fmt.Errorf("UPDATE_SIGNATURE_INVALID: metadata version %d older than trusted %d (rollback refused)", m.Version, lastTrustedVersion)
	}
	return nil
}

// LoadFile reads metadata from disk (dev/test path; production fetches
// from the mirror or GitHub with identical verification).
func LoadFile(path string) (*Metadata, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("metadata unreadable: %w", err)
	}
	return &m, nil
}
