package update

// TUF role-chain regressions on go-tuf/v2 (standard format). Includes the
// negative regression for the accepted-review blocker: a root signed by an
// attacker key with the trusted public key copied in as an inert entry
// must be refused — in BOTH the legacy single-doc format and a hostile
// STANDARD-format root built directly on go-tuf structures.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
	metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

func seed32(t *testing.T, n byte) [32]byte {
	t.Helper()
	var s [32]byte
	for i := range s {
		s[i] = n
	}
	return s
}

func testKeys(t *testing.T) TUFKeys {
	t.Helper()
	k, err := NewTUFKeys(seed32(t, 1), seed32(t, 2), seed32(t, 3), seed32(t, 4))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testTarget(artifact []byte, version string) Target {
	sum := sha256.Sum256(artifact)
	return Target{
		Component: "ara-client", OS: "linux", Arch: "amd64", Format: "deb",
		Version: version, MinCoreAPI: 1, SchemaRange: "1-1",
		Length: int64(len(artifact)), SHA256: hex.EncodeToString(sum[:]), URL: "https://u/ara.deb",
	}
}

// signStd signs a standard TUF metadata document with a private key and
// writes it to dir/name.
func signStd[T metadata.Roles](t *testing.T, meta *tufmeta.Metadata[T], priv ed25519.PrivateKey, dir, name string) {
	t.Helper()
	if _, err := meta.Sign(ed25519Signer{priv: priv}); err != nil {
		t.Fatal(err)
	}
	b, err := meta.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testSelector() Selector {
	return Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64", CoreAPI: 1, SchemaVer: 1}
}

func TestTUFFullChainAndSelection(t *testing.T) {
	dir := t.TempDir()
	k := testKeys(t)
	now := time.Now()
	artifact := []byte("review-only-inert-test-data")
	if err := BuildTUFRepo(dir, k, 3, 365*24*time.Hour, 24*time.Hour, testTarget(artifact, "0.4.0")); err != nil {
		t.Fatal(err)
	}
	tgt, st, err := VerifyTUF(dir, []string{AnchorPubKey(k)}, testSelector(), nil, RepoState{}, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tgt.Version != "0.4.0" || st.RoleVersions["targets"] < 3 {
		t.Fatalf("selected: %+v state=%+v", tgt, st)
	}
	// artifact binding
	if _, _, err := VerifyTUF(dir, []string{AnchorPubKey(k)}, testSelector(), artifact, RepoState{}, now); err != nil {
		t.Fatalf("artifact verify: %v", err)
	}
	bad := append([]byte(nil), artifact...)
	bad[0] ^= 0xff
	if _, _, err := VerifyTUF(dir, []string{AnchorPubKey(k)}, testSelector(), bad, RepoState{}, now); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}

// BLOCKER REGRESSION (spotcheck 2026-10-30): legacy single-doc repo signed
// entirely by an attacker key with the trusted public key as an inert
// root.Keys entry must be refused.
func TestTUFAnchorSubstitutionLegacyFormatRefused(t *testing.T) {
	trustedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	anchor := hex.EncodeToString(trustedPub)
	dir := t.TempDir()
	now := time.Now()
	root := RootSigned{
		Type: "root",
		Keys: map[string]string{"known-public-only": anchor, "other": hex.EncodeToString(otherPub)},
		RoleKeyIDs: map[string][]string{},
		Threshold:  map[string]int{},
	}
	for _, role := range []string{RoleRoot, RoleTimestamp, RoleSnapshot, RoleTargets} {
		root.RoleKeyIDs[role] = []string{"other"}
		root.Threshold[role] = 1
	}
	exp := now.Add(time.Hour)
	artifact := []byte("inert")
	sum := sha256.Sum256(artifact)
	sign := func(role string, payload any) []byte {
		b, e := SignRole(role, 1, exp, payload, "other", otherPriv)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(dir, role+".json"), b, 0o600); e != nil {
			t.Fatal(e)
		}
		return b
	}
	target := Target{
		Component: "ara-client", OS: "linux", Arch: "amd64", Format: "deb",
		Version: "99.0.0", MinCoreAPI: 1, SchemaRange: "1-1",
		Length: int64(len(artifact)), SHA256: hex.EncodeToString(sum[:]),
		URL: "https://example.invalid/inert.deb",
	}
	sign(RoleRoot, root)
	sign(RoleTargets, TargetsSigned{Type: "targets", Targets: []Target{target}})
	snRaw := sign(RoleSnapshot, SnapshotSigned{Type: "snapshot", TargetsVer: 1, RootVer: 1})
	snHash := sha256.Sum256(snRaw)
	sign(RoleTimestamp, TimestampSigned{Type: "timestamp", SnapshotVer: 1, SnapshotSHA256: hex.EncodeToString(snHash[:])})
	if _, _, err := VerifyTUF(dir, []string{anchor}, testSelector(), artifact, RepoState{}, now); err == nil {
		t.Fatal("UNTRUSTED SIGNER ACCEPTED (legacy format): the trusted private key was never used")
	}
}

// BLOCKER REGRESSION, standard-format variant: a hostile root built
// directly on go-tuf structures, signed ONLY by the attacker key, with
// the trusted public key present as an inert Keys entry — must be refused.
func TestTUFAnchorSubstitutionStandardFormatRefused(t *testing.T) {
	trustedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)
	anchor := hex.EncodeToString(trustedPub)

	trustedKey, _ := tufmeta.KeyFromPublicKey(trustedPub)
	atkKey, _ := tufmeta.KeyFromPublicKey(attackerPub)
	now := time.Now()

	root := &tufmeta.RootType{
		Type: "root", SpecVersion: "1.0.0", Version: 1, Expires: now.Add(time.Hour),
		Keys: map[string]*tufmeta.Key{"trusted-inert": trustedKey, "attacker": atkKey},
		Roles: map[string]*tufmeta.Role{
			"root":      {KeyIDs: []string{"attacker"}, Threshold: 1},
			"timestamp": {KeyIDs: []string{"attacker"}, Threshold: 1},
			"snapshot":  {KeyIDs: []string{"attacker"}, Threshold: 1},
			"targets":   {KeyIDs: []string{"attacker"}, Threshold: 1},
		},
	}
	rootMeta := &tufmeta.Metadata[tufmeta.RootType]{Signed: *root}
	dir := t.TempDir()
	signStd(t, rootMeta, attackerPriv, dir, RoleFileRoot)
	// the rest of the chain is fully attacker-signed too
	artifact := []byte("inert")
	sum := sha256.Sum256(artifact)
	_ = sum
	cust := json.RawMessage(`{"component":"ara-client","os":"linux","arch":"amd64","channel":"stable","version":"99.0.0"}`)
	targets := &tufmeta.TargetsType{Type: "targets", SpecVersion: "1.0.0", Version: 1, Expires: now.Add(time.Hour),
		Targets: map[string]*tufmeta.TargetFiles{"inert.deb": {Path: "https://example.invalid/inert.deb", Length: int64(len(artifact)), Hashes: map[string]tufmeta.HexBytes{"sha256": sum[:]}, Custom: &cust}}}
	tgMeta := &tufmeta.Metadata[tufmeta.TargetsType]{Signed: *targets}
	signStd(t, tgMeta, attackerPriv, dir, RoleFileTargets)
	snapshot := &tufmeta.SnapshotType{Type: "snapshot", SpecVersion: "1.0.0", Version: 1, Expires: now.Add(time.Hour),
		Meta: map[string]*tufmeta.MetaFiles{"targets.json": {Version: 1}, "root.json": {Version: 1}}}
	snMeta := &tufmeta.Metadata[tufmeta.SnapshotType]{Signed: *snapshot}
	signStd(t, snMeta, attackerPriv, dir, RoleFileSnapshot)
	timestamp := &tufmeta.TimestampType{Type: "timestamp", SpecVersion: "1.0.0", Version: 1, Expires: now.Add(time.Hour),
		Meta: map[string]*tufmeta.MetaFiles{"snapshot.json": {Version: 1}}}
	tsMeta := &tufmeta.Metadata[tufmeta.TimestampType]{Signed: *timestamp}
	signStd(t, tsMeta, attackerPriv, dir, RoleFileTimestamp)

	if _, _, err := VerifyTUF(dir, []string{anchor}, testSelector(), artifact, RepoState{}, now); err == nil {
		t.Fatal("UNTRUSTED SIGNER ACCEPTED (standard format): the trusted private key was never used")
	}
}

func TestTUFRollbackRefusedPerRole(t *testing.T) {
	dir := t.TempDir()
	k := testKeys(t)
	now := time.Now()
	if err := BuildTUFRepo(dir, k, 5, 365*24*time.Hour, 24*time.Hour, testTarget([]byte("x"), "0.4.0")); err != nil {
		t.Fatal(err)
	}
	sel := testSelector()
	anchor := []string{AnchorPubKey(k)}
	prev := RepoState{RoleVersions: map[string]int{"root": 6, "timestamp": 6, "snapshot": 5, "targets": 5}}
	if _, _, err := VerifyTUF(dir, anchor, sel, nil, prev, now); err == nil {
		t.Fatal("root rollback accepted")
	}
	prev = RepoState{RoleVersions: map[string]int{"timestamp": 6}}
	if _, _, err := VerifyTUF(dir, anchor, sel, nil, prev, now); err == nil {
		t.Fatal("timestamp rollback accepted")
	}
}

func TestTUFExpiryFrozen(t *testing.T) {
	dir := t.TempDir()
	k := testKeys(t)
	now := time.Now()
	if err := BuildTUFRepo(dir, k, 1, 365*24*time.Hour, 24*time.Hour, testTarget([]byte("x"), "0.4.0")); err != nil {
		t.Fatal(err)
	}
	sel := testSelector()
	anchor := []string{AnchorPubKey(k)}
	if _, _, err := VerifyTUF(dir, anchor, sel, nil, RepoState{}, now); err != nil {
		t.Fatalf("fresh verify failed: %v", err)
	}
	if _, _, err := VerifyTUF(dir, anchor, sel, nil, RepoState{}, now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired role metadata accepted (freeze protection absent)")
	}
}

// Rotation: the new root is signed by BOTH the previous trusted root and
// its own new key (dual signature, standard TUF steps 1–2); the persisted
// trusted root survives "restart" (fresh VerifyTUF call carrying state).
func TestTUFRootRotationWithPersistedTrust(t *testing.T) {
	dir := t.TempDir()
	k1 := testKeys(t)
	now := time.Now()
	artifact := []byte("payload")
	if err := BuildTUFRepo(dir, k1, 1, 365*24*time.Hour, 24*time.Hour, testTarget(artifact, "0.3.0")); err != nil {
		t.Fatal(err)
	}
	anchor := []string{AnchorPubKey(k1)}
	tgt, state, err := VerifyTUF(dir, anchor, testSelector(), nil, RepoState{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Version != "0.3.0" || len(state.TrustedRootJSON) == 0 {
		t.Fatalf("bootstrap did not persist the trusted root: %+v", state)
	}

	// rotated repo: new root key; root signed by OLD root AND new root;
	// other roles signed by new role keys
	k2, err := NewTUFKeys(seed32(t, 11), seed32(t, 12), seed32(t, 13), seed32(t, 14))
	if err != nil {
		t.Fatal(err)
	}
	buildRotated(t, dir, k1, k2, 2, now, testTarget(artifact, "0.3.1"))

	// carrying state: rotation authorized; new version selected
	tgt2, state2, err := VerifyTUF(dir, anchor, testSelector(), nil, state, now)
	if err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	if tgt2.Version != "0.3.1" {
		t.Fatalf("rotated target: %+v", tgt2)
	}
	if state2.RoleVersions["root"] != 2 {
		t.Fatalf("root version not advanced: %+v", state2)
	}

	// restart simulation: fresh call with the persisted state keeps trust
	if _, _, err := VerifyTUF(dir, anchor, testSelector(), nil, state2, now); err != nil {
		t.Fatalf("post-restart verify: %v", err)
	}

	// anti-rollback: serving v1 after v2 is refused via persisted versions
	if err := BuildTUFRepo(dir, k1, 1, 365*24*time.Hour, 24*time.Hour, testTarget(artifact, "0.3.0")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyTUF(dir, anchor, testSelector(), nil, state2, now); err == nil {
		t.Fatal("rollback to v1 accepted after rotation")
	}
}

func buildRotated(t *testing.T, dir string, kOld, kNew TUFKeys, version int, now time.Time, tget Target) {
	t.Helper()
	if err := BuildTUFRepo(dir, kNew, version, 365*24*time.Hour, 24*time.Hour, tget); err != nil {
		t.Fatal(err)
	}
	// re-sign the root with BOTH keys: load the new root doc, add the old
	// root's signature over the same payload, keeping the new threshold=1
	// (either of the two authorized signers satisfies the new root) and
	// ALSO verify under the old root (dual requirement checked in VerifyTUF
	// via prevMeta.VerifyDelegate — for that, the old root's key must be a
	// signer; append its signature to the same document)
	rootPath := filepath.Join(dir, RoleFileRoot)
	b, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	var meta tufmeta.Metadata[tufmeta.RootType]
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	if _, err := meta.Sign(ed25519Signer{priv: kOld.Root}); err != nil {
		t.Fatal(err)
	}
	nb, err := meta.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, nb, 0o600); err != nil {
		t.Fatal(err)
	}
	// the snapshot binds the root file bytes: after the dual signature the
	// root file changed, so the snapshot's root.json entry (length+sha256)
	// must be refreshed and snapshot+timestamp re-signed by the NEW roles
	rootSum := sha256.Sum256(nb)
	snPath := filepath.Join(dir, RoleFileSnapshot)
	sb, err := os.ReadFile(snPath)
	if err != nil {
		t.Fatal(err)
	}
	var snMeta tufmeta.Metadata[tufmeta.SnapshotType]
	if err := json.Unmarshal(sb, &snMeta); err != nil {
		t.Fatal(err)
	}
	snMeta.Signed.Meta["root.json"] = &tufmeta.MetaFiles{
		Version: 2, Length: int64(len(nb)),
		Hashes: map[string]tufmeta.HexBytes{"sha256": rootSum[:]},
	}
	snMeta.ClearSignatures()
	if _, err := snMeta.Sign(ed25519Signer{priv: kNew.SN}); err != nil {
		t.Fatal(err)
	}
	snb, err := snMeta.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(snPath, snb, 0o600)
	snSum := sha256.Sum256(snb)
	tsPath := filepath.Join(dir, RoleFileTimestamp)
	tb, err := os.ReadFile(tsPath)
	if err != nil {
		t.Fatal(err)
	}
	var tsMeta tufmeta.Metadata[tufmeta.TimestampType]
	if err := json.Unmarshal(tb, &tsMeta); err != nil {
		t.Fatal(err)
	}
	tsMeta.Signed.Meta["snapshot.json"] = &tufmeta.MetaFiles{
		Version: 2, Length: int64(len(snb)),
		Hashes: map[string]tufmeta.HexBytes{"sha256": snSum[:]},
	}
	tsMeta.ClearSignatures()
	if _, err := tsMeta.Sign(ed25519Signer{priv: kNew.TS}); err != nil {
		t.Fatal(err)
	}
	tsb, _ := tsMeta.ToBytes(false)
	os.WriteFile(tsPath, tsb, 0o600)
}

func TestTUFChannelMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	k := testKeys(t)
	now := time.Now()
	if err := BuildTUFRepo(dir, k, 1, 365*24*time.Hour, 24*time.Hour, testTarget([]byte("x"), "0.4.0")); err != nil {
		t.Fatal(err)
	}
	sel := testSelector()
	sel.Channel = "beta"
	if _, _, err := VerifyTUF(dir, []string{AnchorPubKey(k)}, sel, nil, RepoState{}, now); err == nil {
		t.Fatal("channel mismatch accepted")
	}
}
