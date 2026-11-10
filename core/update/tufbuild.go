package update

// BuildTUFRepo writes a standard TUF role repository (go-tuf/v2 format):
// root/timestamp/snapshot/targets, each signed with its own ed25519 key.
// Used by ara-release (lab/test signing) and the regression tests.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

// TUFKeys holds one ed25519 seed and the matching go-tuf key per role.
type TUFKeys struct {
	Root ed25519.PrivateKey
	TS   ed25519.PrivateKey
	SN   ed25519.PrivateKey
	TG   ed25519.PrivateKey

	RootKey *tufmeta.Key
	TSKey   *tufmeta.Key
	SNKey   *tufmeta.Key
	TGKey   *tufmeta.Key
}

// NewTUFKeys derives the four role keys from seeds.
func NewTUFKeys(rootSeed, tsSeed, snSeed, tgSeed [32]byte) (TUFKeys, error) {
	keysOf := func(seed [32]byte) (ed25519.PrivateKey, *tufmeta.Key, error) {
		priv := ed25519.NewKeyFromSeed(seed[:])
		k, err := tufmeta.KeyFromPublicKey(priv.Public().(ed25519.PublicKey))
		return priv, k, err
	}
	out := TUFKeys{}
	var err error
	if out.Root, out.RootKey, err = keysOf(rootSeed); err != nil {
		return out, err
	}
	if out.TS, out.TSKey, err = keysOf(tsSeed); err != nil {
		return out, err
	}
	if out.SN, out.SNKey, err = keysOf(snSeed); err != nil {
		return out, err
	}
	if out.TG, out.TGKey, err = keysOf(tgSeed); err != nil {
		return out, err
	}
	return out, nil
}

// AnchorPubKey returns the hex ed25519 public key of the root role (the
// offline anchor content).
func AnchorPubKey(k TUFKeys) string {
	pub := k.Root.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

// signerOf wraps the ed25519 private key into the sigstore signer that
// go-tuf's Metadata.Sign accepts (signature.Signer: SignMessage+PublicKey).
func signerOf(priv ed25519.PrivateKey) (signature.Signer, error) {
	return ed25519Signer{priv: priv}, nil
}

// ed25519Signer is a minimal signature.Signer for tests/tools.
type ed25519Signer struct{ priv ed25519.PrivateKey }

func (e ed25519Signer) SignMessage(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
	data, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(e.priv, data), nil
}
func (e ed25519Signer) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return e.priv.Public(), nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// BuildTUFRepo writes root/timestamp/snapshot/targets for the supplied targets.
// version is shared by all roles (monotonic). Parent meta entries carry
// the EXPLICIT length and sha256 of the actual child file bytes, so the
// verifier can bind parent declarations to child content at every hop
// (spotcheck 2026-10-30).
func BuildTUFRepo(dir string, k TUFKeys, version int, rootValidity, roleValidity time.Duration, targetsToSign ...Target) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	now := time.Now().UTC()
	rootSigner, err := signerOf(k.Root)
	if err != nil {
		return err
	}
	tsSigner, err := signerOf(k.TS)
	if err != nil {
		return err
	}
	snSigner, err := signerOf(k.SN)
	if err != nil {
		return err
	}
	tgSigner, err := signerOf(k.TG)
	if err != nil {
		return err
	}
	rootID, err := k.RootKey.ID()
	if err != nil {
		return err
	}
	tsID, err := k.TSKey.ID()
	if err != nil {
		return err
	}
	snID, err := k.SNKey.ID()
	if err != nil {
		return err
	}
	tgID, err := k.TGKey.ID()
	if err != nil {
		return err
	}

	// --- root (signed first: snapshot pins its file bytes) ---
	rootDoc := &tufmeta.RootType{
		Type: "root", SpecVersion: "1.0.0", ConsistentSnapshot: false,
		Version: int64(version), Expires: now.Add(rootValidity),
		Keys: map[string]*tufmeta.Key{
			rootID: k.RootKey, tsID: k.TSKey, snID: k.SNKey, tgID: k.TGKey,
		},
		Roles: map[string]*tufmeta.Role{
			"root":      {KeyIDs: []string{rootID}, Threshold: 1},
			"timestamp": {KeyIDs: []string{tsID}, Threshold: 1},
			"snapshot":  {KeyIDs: []string{snID}, Threshold: 1},
			"targets":   {KeyIDs: []string{tgID}, Threshold: 1},
		},
	}
	rootMeta := &tufmeta.Metadata[tufmeta.RootType]{Signed: *rootDoc}
	if _, err := rootMeta.Sign(rootSigner); err != nil {
		return err
	}
	rootBytes, err := rootMeta.ToBytes(false)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, RoleFileRoot), rootBytes, 0o600); err != nil {
		return err
	}
	rootSum := sha256.Sum256(rootBytes)

	// --- targets ---
	targets := &tufmeta.TargetsType{
		Type: "targets", SpecVersion: "1.0.0", Version: int64(version),
		Expires: now.Add(roleValidity), Targets: map[string]*tufmeta.TargetFiles{},
	}
	for _, t := range targetsToSign {
		name := filepath.Base(t.URL)
		if targets.Targets[name] != nil {
			return fmt.Errorf("duplicate release target %q", name)
		}
		cust := json.RawMessage(fmt.Sprintf(
			`{"component":%q,"os":%q,"arch":%q,"channel":%q,"format":%q,"version":%q,"min_core_api":%d,"schema_range":%q}`,
			t.Component, t.OS, t.Arch, channelOf(t.Format), t.Format, t.Version, t.MinCoreAPI, t.SchemaRange))
		targets.Targets[name] = &tufmeta.TargetFiles{
			Path: t.URL, Length: t.Length, Custom: &cust,
			Hashes: map[string]tufmeta.HexBytes{"sha256": tufmeta.HexBytes(mustHexDec(t.SHA256))},
		}
	}
	tgMeta := &tufmeta.Metadata[tufmeta.TargetsType]{Signed: *targets}
	if _, err := tgMeta.Sign(tgSigner); err != nil {
		return err
	}
	tgBytes, err := tgMeta.ToBytes(false)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, RoleFileTargets), tgBytes, 0o600); err != nil {
		return err
	}
	tgSum := sha256.Sum256(tgBytes)

	// --- snapshot: pins versions AND explicit length+sha256 of the
	// actual root.json / targets.json file bytes ---
	snapshot := &tufmeta.SnapshotType{
		Type: "snapshot", SpecVersion: "1.0.0", Version: int64(version),
		Expires: now.Add(roleValidity),
		Meta: map[string]*tufmeta.MetaFiles{
			"root.json": {
				Version: int64(version), Length: int64(len(rootBytes)),
				Hashes: map[string]tufmeta.HexBytes{"sha256": rootSum[:]},
			},
			"targets.json": {
				Version: int64(version), Length: int64(len(tgBytes)),
				Hashes: map[string]tufmeta.HexBytes{"sha256": tgSum[:]},
			},
		},
	}
	snMeta := &tufmeta.Metadata[tufmeta.SnapshotType]{Signed: *snapshot}
	if _, err := snMeta.Sign(snSigner); err != nil {
		return err
	}
	snBytes, err := snMeta.ToBytes(false)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, RoleFileSnapshot), snBytes, 0o600); err != nil {
		return err
	}
	snSum := sha256.Sum256(snBytes)

	// --- timestamp: pins the snapshot version AND its file bytes ---
	timestamp := &tufmeta.TimestampType{
		Type: "timestamp", SpecVersion: "1.0.0", Version: int64(version),
		Expires: now.Add(roleValidity),
		Meta: map[string]*tufmeta.MetaFiles{
			"snapshot.json": {
				Version: int64(version), Length: int64(len(snBytes)),
				Hashes: map[string]tufmeta.HexBytes{"sha256": snSum[:]},
			},
		},
	}
	tsMeta := &tufmeta.Metadata[tufmeta.TimestampType]{Signed: *timestamp}
	if _, err := tsMeta.Sign(tsSigner); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, RoleFileTimestamp), tsMeta)
}

func mustHexDec(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// channelOf: the lab matrix uses the release channel equal to the format
// family today; a real repo config would carry it explicitly.
func channelOf(format string) string { return "stable" }
