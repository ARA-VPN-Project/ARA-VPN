// Command ara-release signs release metadata for the update workflow
// (lab/test trust only): single-doc legacy mode (--out metadata.json) or
// the full TUF role repository (--tuf-dir DIR: root/timestamp/snapshot/
// targets with separate per-role keys). Production keys are provided out
// of band; this tool never publishes anything.
package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aravpn/core/update"
)

func main() {
	bundle := flag.String("bundle", "", "output signed release ZIP from comma-separated ARA .deb paths in -artifact")
	tufDir := flag.String("tuf-dir", "", "build a TUF role repository in this directory")
	tufRootKey := flag.String("tuf-root-key", "", "hex ed25519 seed for the root role")
	tufTSKey := flag.String("tuf-ts-key", "", "hex ed25519 seed for the timestamp role")
	tufSNKey := flag.String("tuf-sn-key", "", "hex ed25519 seed for the snapshot role")
	tufTGKey := flag.String("tuf-tg-key", "", "hex ed25519 seed for the targets role")
	tufVersion := flag.Int("tuf-version", 1, "monotonic version for all roles")
	tufOutRoot := flag.String("tuf-out-anchor", "", "write the offline anchor file (root public key hex)")
	out := flag.String("out", "metadata.json", "signed metadata output (legacy mode)")
	version := flag.String("version", "", "metadata version (monotonic int)")
	semver := flag.String("semver", "", "artifact semver")
	channel := flag.String("channel", "stable", "channel")
	arch := flag.String("arch", "amd64", "Debian architecture for single-artifact metadata")
	component := flag.String("component", "ara-client", "component")
	artifact := flag.String("artifact", "", "artifact file to hash")
	key := flag.String("key", "", "hex ed25519 private key (seed)")
	keyID := flag.String("key-id", "root-1", "signing key id")
	url := flag.String("url", "", "artifact download URL")
	expires := flag.Duration("expires", 7*24*time.Hour, "metadata validity")
	flag.Parse()
	switch *arch {
	case "amd64", "arm64", "armhf":
	default:
		releaseError(fmt.Errorf("unsupported Debian architecture %q", *arch))
	}
	if *tufDir != "" {
		runTUF(*tufDir, *bundle, *tufRootKey, *tufTSKey, *tufSNKey, *tufTGKey, *tufVersion, *tufOutRoot, *semver, *artifact, *url, *channel, *component, *arch)
		return
	}
	if *bundle != "" {
		fmt.Fprintln(os.Stderr, "-bundle requires -tuf-dir and role keys")
		os.Exit(2)
	}
	if *version == "" || *semver == "" || *artifact == "" || *key == "" || *url == "" {
		fmt.Fprintln(os.Stderr, "usage: ara-release -version 3 -semver 0.3.0 -artifact f.deb -key <hex> -url https://... | -tuf-dir DIR -tuf-*-key ...")
		os.Exit(2)
	}
	seed, derr := hex.DecodeString(strings.TrimSpace(*key))
	if derr != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "bad key: need 32-byte hex ed25519 seed")
		os.Exit(2)
	}
	data, aerr := os.ReadFile(*artifact)
	if aerr != nil {
		fmt.Fprintln(os.Stderr, aerr)
		os.Exit(2)
	}
	sum := sha256.Sum256(data)
	var ver int
	fmt.Sscanf(*version, "%d", &ver)
	m := update.Metadata{
		Version:   ver,
		ExpiresAt: time.Now().UTC().Add(*expires),
		Channel:   *channel,
		Threshold: 1,
		Targets: []update.Target{{
			Component: *component, OS: "linux", Arch: *arch, Format: "deb",
			Version: *semver, MinCoreAPI: 1, SchemaRange: "1-1",
			Length: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), URL: *url,
		}},
	}
	priv := ed25519.NewKeyFromSeed(seed)
	// the metadata must name its root public keys (the trusted anchor set);
	// the signature covers them, so key substitution breaks verification
	pub, _ := priv.Public().(ed25519.PublicKey)
	m.RootPubKeys = []string{hex.EncodeToString(pub)}
	if serr := m.Sign(*keyID, priv); serr != nil {
		fmt.Fprintln(os.Stderr, serr)
		os.Exit(2)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if werr := os.WriteFile(*out, append(b, '\n'), 0o600); werr != nil {
		fmt.Fprintln(os.Stderr, werr)
		os.Exit(2)
	}
	fmt.Println("signed metadata:", *out)
	fmt.Println("root_pubkey:", hex.EncodeToString(pub))
}

func runTUF(dir, bundle, rootKeyHex, tsKeyHex, snKeyHex, tgKeyHex string, version int, anchorOut, semver, artifactPath, url, channel, component, singleArch string) {
	if rootKeyHex == "" || tsKeyHex == "" || snKeyHex == "" || tgKeyHex == "" || semver == "" || artifactPath == "" || (bundle == "" && url == "") {
		fmt.Fprintln(os.Stderr, "tuf mode requires -tuf-dir, -tuf-root-key, -tuf-ts-key, -tuf-sn-key, -tuf-tg-key, -semver, -artifact, -url")
		os.Exit(2)
	}
	seed := func(hexSeed string) [32]byte {
		b, err := hex.DecodeString(strings.TrimSpace(hexSeed))
		if err != nil || len(b) != ed25519.SeedSize {
			fmt.Fprintln(os.Stderr, "bad key seed: need 32-byte hex")
			os.Exit(2)
		}
		var out [32]byte
		copy(out[:], b)
		return out
	}
	keys, err := update.NewTUFKeys(seed(rootKeyHex), seed(tsKeyHex), seed(snKeyHex), seed(tgKeyHex))
	if err != nil {
		releaseError(err)
	}
	var targets []update.Target
	files := []string{filepath.Join(dir, update.RoleFileRoot), filepath.Join(dir, update.RoleFileTimestamp), filepath.Join(dir, update.RoleFileSnapshot), filepath.Join(dir, update.RoleFileTargets)}
	for _, path := range strings.Split(artifactPath, ",") {
		if bundle == "" && path != artifactPath {
			releaseError(fmt.Errorf("multiple packages require -bundle"))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			releaseError(err)
		}
		comp, targetURL, arch := component, url, singleArch
		if bundle != "" {
			targetURL = filepath.Base(path)
			pieces := strings.Split(strings.TrimSuffix(targetURL, ".deb"), "_")
			if !strings.HasSuffix(targetURL, ".deb") || len(pieces) != 3 || pieces[1] != semver || pieces[2] == "" {
				releaseError(fmt.Errorf("expected Debian package name component_%s_arch.deb", semver))
			}
			switch pieces[0] {
			case "ara", "ara-edge", "ara-control", "ara-engine":
			default:
				releaseError(fmt.Errorf("unknown ARA package %q", pieces[0]))
			}
			comp, arch = pieces[0], pieces[2]
			files = append(files, path)
		}
		sum := sha256.Sum256(data)
		targets = append(targets, update.Target{
			Component: comp, OS: "linux", Arch: arch, Format: "deb",
			Version: semver, MinCoreAPI: 1, SchemaRange: "1-1",
			Length: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), URL: targetURL,
		})
	}
	if err := update.BuildTUFRepo(dir, keys, version, 365*24*time.Hour, 24*time.Hour, targets...); err != nil {
		releaseError(err)
	}
	if bundle != "" {
		if err := writeBundle(bundle, files); err != nil {
			releaseError(err)
		}
	}
	if anchorOut != "" {
		if err := os.WriteFile(anchorOut, []byte(update.AnchorPubKey(keys)+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	fmt.Println("tuf repo:", dir, "version:", version)
	fmt.Println("root_pubkey:", update.AnchorPubKey(keys))
}

func releaseError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func writeBundle(path string, files []string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		f.Close()
		if !done {
			os.Remove(path)
		}
	}()
	w := zip.NewWriter(f)
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		entry, err := w.Create(filepath.Base(name))
		if err != nil {
			return err
		}
		if _, err := entry.Write(data); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	done = true
	return nil
}
