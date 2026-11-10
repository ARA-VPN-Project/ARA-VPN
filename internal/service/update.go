package service

// Update workflow (docs/UPDATES.md, task F): check → verify → download →
// stage; the artifact install is left to the OS package manager after
// verification — ARA must not grow a second competing updater. The pinned
// trust root is an operator-provided file (ed25519 keys, one hex per
// line); last-trusted version is persisted for anti-rollback.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"aravpn/core/update"
)

// UpdateState is the durable anti-rollback anchor.
type UpdateState struct {
	StateVersion      int       `json:"state_version"`
	LastTrustedVer    int       `json:"last_trusted_version"`
	LastTrustedSemver string    `json:"last_trusted_semver,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (s *Service) updateStatePath() string {
	return filepath.Join(s.State.Root, "updates", "state.json")
}

func (s *Service) LoadUpdateState() (*UpdateState, error) {
	st := &UpdateState{StateVersion: 1, LastTrustedVer: 0}
	b, err := os.ReadFile(s.updateStatePath())
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("update state corrupt: %w", err)
	}
	return st, nil
}

func (s *Service) saveUpdateState(st *UpdateState) error {
	if err := os.MkdirAll(filepath.Dir(s.updateStatePath()), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := s.updateStatePath() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.updateStatePath())
}

// LoadTrustedRoots reads the operator trust anchors (one hex ed25519 key
// per line; blank lines and #comments ignored).
func LoadTrustedRoots(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trusted root unreadable: %w", err)
	}
	var roots []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := hex.DecodeString(line); err != nil {
			return nil, fmt.Errorf("trusted root: bad hex key")
		}
		roots = append(roots, line)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("trusted root: no keys")
	}
	return roots, nil
}

// UpdateCheckTUF verifies the full TUF role chain in repoDir against the
// offline anchor and the persisted per-role versions.
func (s *Service) UpdateCheckTUF(repoDir string, trustedRootKeys []string, sel update.Selector, artifactPath string) (*update.Target, update.RepoState, error) {
	prev, err := s.LoadRepoState()
	if err != nil {
		return nil, update.RepoState{}, err
	}
	var artifact []byte
	if artifactPath != "" {
		if artifact, err = os.ReadFile(artifactPath); err != nil {
			return nil, update.RepoState{}, fmt.Errorf("artifact unreadable: %w", err)
		}
	}
	return update.VerifyTUF(repoDir, trustedRootKeys, sel, artifact, prev, time.Now())
}

// LoadRepoState reads the TUF per-role version anchor.
func (s *Service) LoadRepoState() (update.RepoState, error) {
	st := update.RepoState{RoleVersions: map[string]int{}}
	b, err := os.ReadFile(filepath.Join(s.State.Root, "updates", "tuf-state.json"))
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("tuf state corrupt: %w", err)
	}
	return st, nil
}

// acquireUpdateLock serializes TUF trust-state writers (flock on a lock
// file in the updates dir).
func (s *Service) acquireUpdateLock() (func(), error) {
	dir := filepath.Join(s.State.Root, "updates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "update.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// AnchorTUF verifies again while holding the writer lock so an older
// concurrent release cannot replace the current trust state.
func (s *Service) AnchorTUF(repoDir string, roots []string, sel update.Selector) error {
	unlock, err := s.acquireUpdateLock()
	if err != nil {
		return err
	}
	defer unlock()
	_, state, err := s.UpdateCheckTUF(repoDir, roots, sel, "")
	if err != nil {
		return err
	}
	return s.writeRepoState(state)
}

func (s *Service) writeRepoState(state update.RepoState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return DurableFileWrite(filepath.Join(s.State.Root, "updates", "tuf-state.json"), append(data, '\n'))
}

// UpdateStageTUF verifies the artifact against the TUF chain and stages
// it; the per-role anchors are persisted only after a successful staging
// (a crash before the anchor write repeats the verification, never skips it).
func (s *Service) UpdateStageTUF(repoDir string, trustedRootKeys []string, sel update.Selector, artifactPath string) (string, error) {
	unlock, err := s.acquireUpdateLock()
	if err != nil {
		return "", err
	}
	defer unlock()
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return "", err
	}
	prev, err := s.LoadRepoState()
	if err != nil {
		return "", err
	}
	t, newState, err := update.VerifyTUF(repoDir, trustedRootKeys, sel, artifact, prev, time.Now())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(artifact)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), t.SHA256) {
		return "", fmt.Errorf("VERIFICATION_FAILED: artifact hash mismatch")
	}
	name := filepath.Base(t.URL)
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("VERIFICATION_FAILED: invalid package name")
	}
	staged := filepath.Join(s.State.Root, "updates", name)
	if err := DurableFileWrite(staged, artifact); err != nil {
		return "", err
	}
	if err := s.writeRepoState(newState); err != nil {
		return "", err
	}
	return staged, nil
}

// UpdateCheck loads and verifies metadata against the trusted root and the
// anti-rollback anchor, then selects the target for this platform.
func (s *Service) UpdateCheck(metaPath string, trustedRoots []string, sel update.Selector, artifactPath string) (*update.Target, *update.Metadata, error) {
	m, err := update.LoadFile(metaPath)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.LoadUpdateState()
	if err != nil {
		return nil, nil, err
	}
	var artifact []byte
	if artifactPath != "" {
		artifact, err = os.ReadFile(artifactPath)
		if err != nil {
			return nil, nil, fmt.Errorf("artifact unreadable: %w", err)
		}
	}
	t, err := m.Verify(trustedRoots, sel, artifact)
	if err != nil {
		return nil, nil, err
	}
	// G01 like-for-like anti-rollback: the PACKAGE semver against the last
	// trusted package semver. The previous comparison of the metadata
	// document version against a semver-derived number refused every
	// legitimate second update.
	if st.LastTrustedSemver != "" && update.CompareVersions(t.Version, st.LastTrustedSemver) < 0 {
		return nil, nil, fmt.Errorf("UPDATE_SIGNATURE_INVALID: package version %s older than trusted %s (rollback refused)", t.Version, st.LastTrustedSemver)
	}
	return t, m, nil
}

// UpdateStage copies the verified artifact into the state updates dir with
// its hash checked at copy time, records the trusted version and returns
// the staged path for the package manager.
func (s *Service) UpdateStage(t *update.Target, artifactPath string, trustedSemver string) (string, error) {
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(artifact)
	if got := hex.EncodeToString(sum[:]); got != strings.ToLower(t.SHA256) {
		return "", fmt.Errorf("VERIFICATION_FAILED: artifact hash %s != metadata %s", got, t.SHA256)
	}
	dir := filepath.Join(s.State.Root, "updates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	staged := filepath.Join(dir, filepath.Base(t.URL))
	tmp := staged + ".tmp"
	if err := os.WriteFile(tmp, artifact, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, staged); err != nil {
		return "", err
	}
	st, err := s.LoadUpdateState()
	if err != nil {
		return "", err
	}
	// anti-rollback anchor (G01): never step back from the last trusted
	// package semver — enforced like-for-like in UpdateCheck
	if st.LastTrustedSemver == "" || update.CompareVersions(t.Version, st.LastTrustedSemver) > 0 {
		st.LastTrustedVer = mVersion(t.Version)
		st.LastTrustedSemver = t.Version
		st.UpdatedAt = time.Now().UTC()
		if err := s.saveUpdateState(st); err != nil {
			return "", err
		}
	}
	return staged, nil
}

// mVersion derives the coarse monotonic int from a semver (major*10000 +
// minor*100 + patch) for the durable anchor.
func mVersion(semver string) int {
	var a, b, c int
	if _, err := fmt.Sscanf(semver, "%d.%d.%d", &a, &b, &c); err != nil {
		return 0
	}
	return a*10000 + b*100 + c
}
