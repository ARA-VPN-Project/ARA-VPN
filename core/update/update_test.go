package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func testMeta(t *testing.T) (*Metadata, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootHex := hex.EncodeToString(pub)
	m := &Metadata{
		Version:    5,
		ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
		Channel:    "stable",
		RootPubKey: rootHex,
		Threshold:  1,
		Targets: []Target{
			{Component: "ara-client", OS: "linux", Arch: "amd64", Version: "1.2.0",
				MinCoreAPI: 1, SchemaRange: "1-1", Length: 11, SHA256: "", URL: "https://mirror.invalid/ara-client_1.2.0.deb"},
			{Component: "ara-client", OS: "linux", Arch: "arm64", Version: "1.2.0",
				MinCoreAPI: 1, SchemaRange: "1-1", URL: "https://mirror.invalid/ara-client_arm64.deb"},
			{Component: "ara-control", OS: "linux", Arch: "amd64", Version: "1.2.0",
				MinCoreAPI: 1, SchemaRange: "1-2", URL: "https://mirror.invalid/ara-control.deb"},
		},
	}
	return m, priv, rootHex
}

func TestSignAndVerifyHappyPath(t *testing.T) {
	m, priv, root := testMeta(t)
	if err := m.Sign("root", priv); err != nil {
		t.Fatal(err)
	}
	sel := Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64", CoreAPI: 1, SchemaVer: 1}
	// hash not yet recorded: verify selection without artifact bytes
	tgt, err := m.Verify([]string{root}, sel, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tgt.Version != "1.2.0" || tgt.Arch != "amd64" {
		t.Fatalf("target: %+v", tgt)
	}
	// artifact hash must be recorded correctly by the signer side
	sum := sha256HexBytes([]byte("hello-world"))
	m2, priv2, root2 := testMeta(t)
	m2.Targets[0].SHA256 = sum
	if err := m2.Sign("root", priv2); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Verify([]string{root2}, sel, []byte("hello-world")); err != nil {
		t.Fatalf("verify with hash: %v", err)
	}
	if _, err := m2.Verify([]string{root2}, sel, []byte("tampered!!!")); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	_ = priv
}

func TestWrongArchAndComponentRefused(t *testing.T) {
	m, priv, root := testMeta(t)
	m.Sign("root", priv)
	sel := Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "riscv64"}
	if _, err := m.Verify([]string{root}, sel, nil); err == nil {
		t.Fatal("wrong arch accepted")
	}
	sel = Selector{Component: "ara-ios-ext", Channel: "stable", OS: "ios", Arch: "arm64"}
	if _, err := m.Verify([]string{root}, sel, nil); err == nil {
		t.Fatal("component outside matrix accepted")
	}
}

func TestExpiredAndTamperedRefused(t *testing.T) {
	m, priv, root := testMeta(t)
	m.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	m.Sign("root", priv)
	if _, err := m.Verify([]string{root}, Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64"}, nil); err == nil {
		t.Fatal("expired metadata accepted")
	}

	m2, priv2, root2 := testMeta(t)
	m2.Sign("root", priv2)
	m2.Targets[0].Version = "9.9.9" // tamper after signing
	if _, err := m2.Verify([]string{root2}, Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64"}, nil); err == nil {
		t.Fatal("tampered metadata accepted")
	}

	m3, priv3, root3 := testMeta(t)
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	m3.Sign("root", other) // signed by the wrong key
	_ = priv3
	if _, err := m3.Verify([]string{root3}, Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64"}, nil); err == nil {
		t.Fatal("wrong-key signature accepted")
	}
}

func TestForeignRootKeyRefused(t *testing.T) {
	m, priv, _ := testMeta(t)
	m.Sign("root", priv)
	_, attackerPub, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := m.Verify([]string{hex.EncodeToString(attackerPub)}, Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64"}, nil); err == nil {
		t.Fatal("metadata pinned to a foreign root accepted")
	}
}

func TestAntiRollback(t *testing.T) {
	m, _, _ := testMeta(t)
	m.Version = 4
	if err := CheckAntiRollback(m, 5); err == nil {
		t.Fatal("rollback accepted")
	}
	m.Version = 5
	if err := CheckAntiRollback(m, 5); err != nil {
		t.Fatalf("same version refused: %v", err)
	}
	m.Version = 6
	if err := CheckAntiRollback(m, 5); err != nil {
		t.Fatalf("newer version refused: %v", err)
	}
}

func TestSchemaRange(t *testing.T) {
	if !schemaInRange("1-1", 1) || schemaInRange("1-1", 2) {
		t.Fatal("range 1-1 wrong")
	}
	if !schemaInRange("1-2", 2) || schemaInRange("1-2", 3) {
		t.Fatal("range 1-2 wrong")
	}
	if !schemaInRange("", 99) {
		t.Fatal("empty range must accept")
	}
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// R13 regression: duplicate signatures from one key count once; a real
// multi-key trusted set with distinct signatures satisfies the threshold.
func TestUpdateDistinctKeysRequiredForThreshold(t *testing.T) {
	m, priv, root := testMeta(t)
	m.Threshold = 2
	if err := m.Sign("root", priv); err != nil {
		t.Fatal(err)
	}
	m.Signatures = append(m.Signatures, m.Signatures[0]) // duplicate
	sel := Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64"}
	if _, err := m.Verify([]string{root}, sel, nil); err == nil {
		t.Fatal("duplicate signature from one key satisfied threshold 2")
	}
	// a genuinely distinct second trusted key with its own signature passes
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	root2 := hex.EncodeToString(func() []byte { p := priv2.Public().(ed25519.PublicKey); return []byte(p) }())
	m2, priv3, root3 := testMeta(t)
	m2.Threshold = 2
	m2.RootPubKeys = []string{root3, root2}
	m2.Sign("k1", priv3)
	m2.Sign("k2", priv2)
	if _, err := m2.Verify([]string{root3, root2}, sel, nil); err != nil {
		t.Fatalf("two distinct trusted signatures refused: %v", err)
	}
	// one of two distinct keys is below threshold 2
	m3, priv4, root4 := testMeta(t)
	m3.Threshold = 2
	m3.RootPubKeys = []string{root4, root2}
	m3.Sign("k1", priv4)
	if _, err := m3.Verify([]string{root4, root2}, sel, nil); err == nil {
		t.Fatal("one distinct signature below threshold 2 accepted")
	}
	// a threshold the trusted set can never meet is refused as unsupported
	m4, priv5, root5 := testMeta(t)
	m4.Threshold = 3
	m4.Sign("root", priv5)
	if _, err := m4.Verify([]string{root5}, sel, nil); err == nil {
		t.Fatal("unreachable threshold accepted")
	}
}

// R14 regression: the requested channel must match the metadata channel.
func TestUpdateChannelEnforced(t *testing.T) {
	m, priv, root := testMeta(t)
	m.Sign("root", priv)
	sel := Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64"}
	mDev, privDev, rootDev := testMeta(t)
	mDev.Channel = "dev"
	mDev.Sign("root", privDev)
	if _, err := mDev.Verify([]string{rootDev}, sel, nil); err == nil {
		t.Fatal("stable selector accepted dev metadata")
	}
	if _, err := m.Verify([]string{root}, sel, nil); err != nil {
		t.Fatalf("matching channel refused: %v", err)
	}
}

// R14 regression: versions order semantically, not lexicographically.
func TestUpdateSemverOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int // CompareVersions(a,b)
	}{
		{"0.1.10", "0.1.9", 1},
		{"0.1.2", "0.1.10", -1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-rc.2", "1.0.0-rc.10", -1}, // numeric segment compare (semver)
		{"1.0.0-alpha", "1.0.0-beta", -1}, // lexicographic for identifiers
		{"2.0.0", "10.0.0", -1},
		{"v1.2.3", "1.2.3", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	// selection picks the semantically newest within the same minor:
	// lexicographically "0.1.9" > "0.1.10", semantically not
	m, priv, root := testMeta(t)
	m.Targets = append(m.Targets,
		Target{Component: "ara-client", OS: "linux", Arch: "amd64", Version: "1.2.10", SchemaRange: "1-1"},
		Target{Component: "ara-client", OS: "linux", Arch: "amd64", Version: "1.2.9", SchemaRange: "1-1"})
	m.Sign("root", priv)
	sel := Selector{Component: "ara-client", Channel: "stable", OS: "linux", Arch: "amd64"}
	tgt, err := m.Verify([]string{root}, sel, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Version != "1.2.10" {
		t.Fatalf("lexicographic pick: %s (want 1.2.10)", tgt.Version)
	}
}
