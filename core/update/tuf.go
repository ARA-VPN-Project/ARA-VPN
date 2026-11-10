package update

// Standard TUF verification on the maintained library go-tuf/v2
// (github.com/theupdateframework/go-tuf/v2, Apache-2.0, version/hash
// pinned in go.sum and third_party.lock.json). Replaces the former
// hand-rolled single-document scheme after an accepted-review blocker:
// the old path let an attacker-signed root self-authorize by listing an
// unused trusted public key in root.Keys.
//
// Trust model here (standard TUF):
//   - Bootstrap: the OFFLINE anchor (hex ed25519 keys) materializes an
//     in-memory root whose ROOT role = anchor keys, threshold = n-of-n.
//     An incoming root is accepted only if it carries valid signatures
//     from that anchor set. Metadata can never define its own acceptance.
//   - Rotation: the last durably-verified root (carried in RepoState,
//     persisted across restarts) authorizes the next root: the new root
//     must verify under BOTH the previous trusted root (old keys/
//     threshold) and its own declared root keys (new threshold), with a
//     strictly increasing version.
//   - timestamp/snapshot/targets are verified by the trusted root's
//     per-role keys/thresholds via the library's VerifyDelegate
//     (canonical-JSON signatures, distinct-key threshold).
//   - Freeze: per-role expiry checked at verification time.
//   - Anti-rollback: per-role monotonic versions against RepoState.
//   - Artifacts: targets pin sha256+length; selection honors
//     os/arch/component/channel/core-api/schema-range via target Custom.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func hexDecodeString(s string) ([]byte, error) { return hex.DecodeString(s) }
func hexEncodeString(b []byte) string          { return hex.EncodeToString(b) }

// Role file names inside the repository directory.
const (
	RoleFileRoot      = "root.json"
	RoleFileTimestamp = "timestamp.json"
	RoleFileSnapshot  = "snapshot.json"
	RoleFileTargets   = "targets.json"
)

// RepoState is the durable trust/anti-rollback anchor: per-role versions
// plus the last trusted ROOT document (so rotation authorizes across
// restarts without re-touching the offline anchor).
type RepoState struct {
	RoleVersions    map[string]int `json:"role_versions"`
	TrustedRootJSON []byte         `json:"trusted_root_json,omitempty"`
}

// Clone returns a deep-enough copy for state transitions.
func (r RepoState) Clone() RepoState {
	m := map[string]int{}
	for k, v := range r.RoleVersions {
		m[k] = v
	}
	return RepoState{RoleVersions: m, TrustedRootJSON: append([]byte(nil), r.TrustedRootJSON...)}
}

func loadRootMeta(path string) (*metadata.Metadata[metadata.RootType], []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	m, err := metadata.Root().FromBytes(b)
	if err != nil {
		return nil, nil, fmt.Errorf("not valid TUF root: %w", err)
	}
	return m, b, nil
}

// anchorRoot materializes the offline trust anchor as a TUF root: keys are
// the anchor's ed25519 public keys; the ROOT role lists all of them with
// threshold n-of-n. Signatures verified against this delegator prove
// offline-anchor authorization.
func anchorRoot(anchor []string) (*metadata.Metadata[metadata.RootType], error) {
	if len(anchor) == 0 {
		return nil, errors.New("anchor: no offline keys")
	}
	keys := map[string]*metadata.Key{}
	ids := make([]string, 0, len(anchor))
	for i, hexPub := range anchor {
		pubBytes, err := decodeHexKey(hexPub)
		if err != nil {
			return nil, fmt.Errorf("anchor key %d: %w", i, err)
		}
		k, err := metadata.KeyFromPublicKey(ed25519.PublicKey(pubBytes))
		if err != nil {
			return nil, fmt.Errorf("anchor key %d: %w", i, err)
		}
		id, err := k.ID()
		if err != nil {
			return nil, err
		}
		keys[id] = k
		ids = append(ids, id)
	}
	root := &metadata.RootType{
		Type: "root", SpecVersion: "1.0.0", ConsistentSnapshot: false,
		Version: 1, Expires: time.Now().Add(time.Hour), Keys: keys,
		Roles: map[string]*metadata.Role{
			"root": {KeyIDs: ids, Threshold: len(ids)}, // n-of-n offline quorum
		},
	}
	return &metadata.Metadata[metadata.RootType]{Signed: *root}, nil
}

func decodeHexKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	b, err := hexDecode(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key must be %d-byte ed25519 public key", ed25519.PublicKeySize)
	}
	return b, nil
}

// VerifyTUF walks the role chain in dir. prev carries the last trusted
// state (versions + trusted root JSON); RepoState{} means bootstrap.
// bindChildToParent checks the child file bytes against the parent's
// signed MetaFiles entry: every DECLARED constraint (length, each hash
// algorithm) must match the actual bytes; an absent entry declares
// nothing. A parent signed with a legitimate key but describing
// different child bytes is refused here, before the child is trusted
// (spotcheck 2026-10-30: version pinning alone did not bind the parent
// to child content).
func bindChildToParent(role, file string, childBytes []byte, parent *metadata.MetaFiles) error {
	if parent == nil {
		return nil // no constraint declared by this parent
	}
	if parent.Length > 0 && int64(len(childBytes)) != parent.Length {
		return fmt.Errorf("%s: length mismatch against signed parent meta (declared %d, actual %d)", role, parent.Length, len(childBytes))
	}
	for alg, want := range parent.Hashes {
		switch alg {
		case "sha256":
			sum := sha256.Sum256(childBytes)
			if !strings.EqualFold(hexEncodeString(sum[:]), hexEncodeString(want)) {
				return fmt.Errorf("%s: sha256 mismatch against signed parent meta", role)
			}
		default:
			return fmt.Errorf("%s: unsupported hash algorithm %q in signed parent meta", role, alg)
		}
	}
	return nil
}

// verifyRoleBound reads the role file, binds its bytes to the parent's
// signed meta entry, then verifies the delegate signature, expiry and
// per-role anti-rollback. Returns the typed metadata and its version.
func verifyRoleBound[T metadata.Roles](proto *metadata.Metadata[T], role, dir, file string, parent *metadata.MetaFiles, trusted *metadata.Metadata[metadata.RootType], prev RepoState, now time.Time) (*metadata.Metadata[T], int, error) {
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", role, err)
	}
	if err := bindChildToParent(role, file, b, parent); err != nil {
		return nil, 0, err
	}
	m, err := proto.FromBytes(b)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: not valid TUF metadata: %w", role, err)
	}
	if err := trusted.VerifyDelegate(role, m); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", role, err)
	}
	// Expires/Version are uniform across role types; read them through
	// the canonical JSON of the signed portion (type-safe across the union)
	blob, merr := json.Marshal(m.Signed)
	if merr != nil {
		return nil, 0, fmt.Errorf("%s: marshal signed: %w", role, merr)
	}
	var head struct {
		Expires time.Time `json:"expires"`
		Version int64     `json:"version"`
	}
	if merr := json.Unmarshal(blob, &head); merr != nil {
		return nil, 0, fmt.Errorf("%s: signed head: %w", role, merr)
	}
	if now.After(head.Expires.UTC()) {
		return nil, 0, fmt.Errorf("%s expired at %s", role, head.Expires.Format(time.RFC3339))
	}
	ver := int(head.Version)
	if prev.RoleVersions[role] > ver {
		return nil, 0, fmt.Errorf("%s rollback: %d < trusted %d", role, ver, prev.RoleVersions[role])
	}
	return m, ver, nil
}

// VerifyTUF walks the role chain in dir. prev carries the last trusted
// state (versions + trusted root JSON); RepoState{} means bootstrap.
func VerifyTUF(dir string, anchor []string, sel Selector, artifact []byte, prev RepoState, now time.Time) (*Target, RepoState, error) {
	if len(anchor) == 0 {
		return nil, RepoState{}, errors.New("tuf: offline anchor is empty")
	}
	rootMeta, rootBytes, err := loadRootMeta(filepath.Join(dir, RoleFileRoot))
	if err != nil {
		return nil, RepoState{}, fmt.Errorf("root: %w", err)
	}

	// ---- root acceptance: bootstrap or dual-signed rotation ----
	var trusted *metadata.Metadata[metadata.RootType]
	if len(prev.TrustedRootJSON) == 0 {
		anchorMeta, aerr := anchorRoot(anchor)
		if aerr != nil {
			return nil, RepoState{}, aerr
		}
		if err := anchorMeta.VerifyDelegate("root", rootMeta); err != nil {
			return nil, RepoState{}, fmt.Errorf("root is NOT authorized by the offline anchor: %w", err)
		}
		trusted = rootMeta
	} else {
		prevMeta, perr := metadata.Root().FromBytes(prev.TrustedRootJSON)
		if perr != nil {
			return nil, RepoState{}, fmt.Errorf("persisted trusted root unreadable: %w", perr)
		}
		// (a) previous trusted root authorizes the new root
		if err := prevMeta.VerifyDelegate("root", rootMeta); err != nil {
			return nil, RepoState{}, fmt.Errorf("root rotation not authorized by the previous trusted root: %w", err)
		}
		// (b) the new root is also signed per its own declared root keys
		if err := rootMeta.VerifyDelegate("root", rootMeta); err != nil {
			return nil, RepoState{}, fmt.Errorf("root rotation not self-signed per its own threshold: %w", err)
		}
		trusted = rootMeta
	}
	if now.After(trusted.Signed.Expires.UTC()) {
		return nil, RepoState{}, fmt.Errorf("root expired at %s", trusted.Signed.Expires.Format(time.RFC3339))
	}
	if rootVer := int(trusted.Signed.Version); prev.RoleVersions["root"] > rootVer {
		return nil, RepoState{}, fmt.Errorf("root rollback: %d < trusted %d", rootVer, prev.RoleVersions["root"])
	}
	rootRole := trusted.Signed.Roles["root"]
	if rootRole == nil {
		return nil, RepoState{}, errors.New("root: no root role entry")
	}

	// ---- role chain: bytes bound to signed parent meta at every hop ----
	tsMeta, tsVer, err := verifyRoleBound(metadata.Timestamp(), "timestamp", dir, RoleFileTimestamp, nil, trusted, prev, now)
	if err != nil {
		return nil, RepoState{}, err
	}
	snMeta, snVer, err := verifyRoleBound(metadata.Snapshot(), "snapshot", dir, RoleFileSnapshot, tsMeta.Signed.Meta["snapshot.json"], trusted, prev, now)
	if err != nil {
		return nil, RepoState{}, err
	}
	// B36: a signed document with a MISSING parent meta entry is a typed
	// verification error — never a nil-map panic.
	if snMeta.Signed.Meta == nil || snMeta.Signed.Meta["targets.json"] == nil || snMeta.Signed.Meta["root.json"] == nil {
		return nil, RepoState{}, errors.New("snapshot: missing required parent meta entries (targets.json/root.json)")
	}
	tgMeta, tgVer, err := verifyRoleBound(metadata.Targets(), "targets", dir, RoleFileTargets, snMeta.Signed.Meta["targets.json"], trusted, prev, now)
	if err != nil {
		return nil, RepoState{}, err
	}
	// the snapshot also pins the trusted root document bytes when declared
	if err := bindChildToParent("root", RoleFileRoot, rootBytes, snMeta.Signed.Meta["root.json"]); err != nil {
		return nil, RepoState{}, err
	}

	// ---- cross-role pinning (standard TUF) ----
	if tsMeta.Signed.Meta == nil || tsMeta.Signed.Meta["snapshot.json"] == nil {
		return nil, RepoState{}, errors.New("timestamp: missing required meta entry (snapshot.json)")
	}
	if tsMeta.Signed.Meta["snapshot.json"].Version != int64(snVer) {
		return nil, RepoState{}, fmt.Errorf("snapshot: version %d, timestamp points at %d", snVer, tsMeta.Signed.Meta["snapshot.json"].Version)
	}
	if snMeta.Signed.Meta["targets.json"].Version != int64(tgVer) {
		return nil, RepoState{}, fmt.Errorf("targets: version %d, snapshot points at %d", tgVer, snMeta.Signed.Meta["targets.json"].Version)
	}
	if snMeta.Signed.Meta["root.json"].Version != int64(trusted.Signed.Version) {
		return nil, RepoState{}, fmt.Errorf("snapshot: root version %d != trusted %d", snMeta.Signed.Meta["root.json"].Version, trusted.Signed.Version)
	}

	// ---- target selection + artifact binding ----
	t, err := selectFromTargets(tgMeta, sel)
	if err != nil {
		return nil, RepoState{}, err
	}
	if len(artifact) > 0 {
		sum := sha256.Sum256(artifact)
		if !strings.EqualFold(hexEncodeString(sum[:]), t.SHA256) {
			return nil, RepoState{}, errors.New("artifact hash mismatch against targets")
		}
		if t.Length > 0 && int64(len(artifact)) != t.Length {
			return nil, RepoState{}, errors.New("artifact length mismatch against targets")
		}
	}

	newState := RepoState{
		RoleVersions: map[string]int{
			"root":      maxInt(prev.RoleVersions["root"], int(trusted.Signed.Version)),
			"timestamp": maxInt(prev.RoleVersions["timestamp"], tsVer),
			"snapshot":  maxInt(prev.RoleVersions["snapshot"], snVer),
			"targets":   maxInt(prev.RoleVersions["targets"], tgVer),
		},
		TrustedRootJSON: append([]byte(nil), rootBytes...),
	}
	return t, newState, nil
}

// ---- target selection from go-tuf TargetsType ----

func selectFromTargets(tgMeta *metadata.Metadata[metadata.TargetsType], sel Selector) (*Target, error) {
	// B35: an unset selector defaults to the TARGET installation
	// platform (the running host for installed updaters) — without
	// this the highest version of ANY OS could be chosen.
	osName, arch := sel.OS, sel.Arch
	if osName == "" {
		osName = runtime.GOOS
	}
	if arch == "" {
		arch = installedArchitecture()
	}
	var candidates []Target
	for _, tf := range tgMeta.Signed.Targets {
		var cust struct {
			Component   string `json:"component"`
			OS          string `json:"os"`
			Arch        string `json:"arch"`
			Channel     string `json:"channel"`
			Format      string `json:"format"`
			Version     string `json:"version"`
			MinCoreAPI  int    `json:"min_core_api"`
			SchemaRange string `json:"schema_range"`
		}
		if tf.Custom != nil && len(*tf.Custom) > 0 {
			if err := json.Unmarshal(*tf.Custom, &cust); err != nil {
				continue
			}
		}
		if sel.Component != "" && cust.Component != sel.Component {
			continue
		}
		if osName != "" && cust.OS != osName {
			continue
		}
		if arch != "" && cust.Arch != arch {
			continue
		}
		if sel.Channel != "" && cust.Channel != sel.Channel {
			continue
		}
		if sel.CoreAPI > 0 && cust.MinCoreAPI > sel.CoreAPI {
			continue
		}
		if sel.SchemaVer > 0 && !schemaInRange(cust.SchemaRange, sel.SchemaVer) {
			continue
		}
		sha, ok := tf.Hashes["sha256"]
		if !ok {
			continue
		}
		candidates = append(candidates, Target{
			Component: cust.Component, OS: cust.OS, Arch: cust.Arch,
			Format: cust.Format, Version: cust.Version,
			MinCoreAPI: cust.MinCoreAPI, SchemaRange: cust.SchemaRange,
			Length: tf.Length, SHA256: hexEncode(sha), URL: tf.Path,
		})
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("UNSUPPORTED_CAPABILITY: no signed target for %s/%s/%s channel %s",
			sel.Component, osName, arch, sel.Channel)
	}
	best := candidates[0]
	for _, c := range candidates[1:] {
		if CompareVersions(c.Version, best.Version) > 0 {
			best = c
		}
	}
	return &best, nil
}

// helpers used by the builder (ara-release) and tests

// hexDecode is hex.DecodeString (kept local for readability).
func hexDecode(s string) ([]byte, error) {
	return hexDecodeString(s)
}

func hexEncode(b []byte) string { return hexEncodeString(b) }
