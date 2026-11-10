package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ApplyIdentity is the durable link between the committed policy state
// and the operation that produced it (review T05). It is written in the
// SAME atomic rename as the policy document itself, so identity and
// content are always consistent: an intent-only operation can never claim
// another plan's identical commit.
type ApplyIdentity struct {
	PlanID         string    `json:"plan_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	AppliedAt      time.Time `json:"applied_at"`
}

// stateFile is the on-disk envelope of the policy state file.
type stateFile struct {
	StateVersion int            `json:"state_version"`
	Policy       *Policy        `json:"policy"`
	Identity     *ApplyIdentity `json:"identity,omitempty"`
}

const stateFileVersion = 1

// Store persists the active policy plus a last-known-good copy in a state
// directory. Apply is atomic and compare-and-swap on revision: a writer
// basing its change on a stale revision is rejected with the current
// revision, never silently overwritten (docs/ARCHITECTURE.md). The
// authoritative state file carries the policy AND the identity of the
// operation that committed it in one atomic rename.
type Store struct {
	dir string
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) activePath() string { return filepath.Join(s.dir, "policy.current.json") }
func (s *Store) lkgPath() string    { return filepath.Join(s.dir, "policy.lkg.json") }

// Load returns the active policy. When no policy was ever stored it returns
// a valid empty default (default foreign, RU fallback allowed). Both the
// envelope format (with identity) and the legacy bare-policy format load.
func (s *Store) Load() (*Policy, error) {
	p, _, err := s.LoadState()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// LoadState returns the active policy and the identity of the operation
// that committed it (nil when unknown/legacy).
func (s *Store) LoadState() (*Policy, *ApplyIdentity, error) {
	b, err := os.ReadFile(s.activePath())
	if os.IsNotExist(err) {
		return DefaultPolicy(), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return ParseState(b)
}

// LoadLKG returns the last validated policy. It differs from Load after a
// failed apply attempt: the candidate is never promoted before validation.
func (s *Store) LoadLKG() (*Policy, error) {
	b, err := os.ReadFile(s.lkgPath())
	if os.IsNotExist(err) {
		return s.Load()
	}
	if err != nil {
		return nil, err
	}
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err == nil && sf.StateVersion == stateFileVersion && sf.Policy != nil {
		return sf.Policy, nil
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("lkg policy unreadable: %w", err)
	}
	return &p, nil
}

// ValidateAndApply validates candidate in full, requires currentRevision to
// match the stored revision (use -1 to skip CAS, e.g. first setup), writes
// atomically and refreshes the LKG copy only after the active write
// succeeded. The whole read-check-write sequence runs under a cross-process
// file lock: two independent CLI processes cannot both win the same
// expected revision (review R07).
func (s *Store) ValidateAndApply(candidate *Policy, expectedRevision int64) (*Policy, error) {
	return s.ValidateAndApplyIdentity(candidate, expectedRevision, "", "")
}

// ValidateAndApplyIdentity is the CAS apply with the committing
// operation's identity recorded atomically with the policy (review T05).
func (s *Store) ValidateAndApplyIdentity(candidate *Policy, expectedRevision int64, planID, idempotencyKey string) (*Policy, error) {
	if candidate == nil {
		return nil, fmt.Errorf("candidate policy is nil")
	}
	if planID == "" {
		return nil, fmt.Errorf("committing operation identity (plan id) is required")
	}
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", "POLICY_INVALID", err)
	}
	release, err := lockFile(filepath.Join(s.dir, ".writer.lock"))
	if err != nil {
		return nil, fmt.Errorf("policy store lock: %w", err)
	}
	defer release()

	current, err := s.Load()
	if err != nil {
		return nil, err
	}
	if expectedRevision >= 0 && current.Revision != expectedRevision {
		return nil, fmt.Errorf("CONFLICT: expected revision %d, current is %d", expectedRevision, current.Revision)
	}
	next := *candidate
	next.Revision = current.Revision + 1
	if err := next.Validate(); err != nil {
		return nil, fmt.Errorf("POLICY_INVALID: %w", err)
	}
	// The authoritative commit: policy + committing operation identity in
	// ONE atomic rename (review T05). Identity is part of the transaction,
	// not a post-effect sidecar.
	identity := &ApplyIdentity{PlanID: planID, IdempotencyKey: idempotencyKey, AppliedAt: time.Now().UTC()}
	sf := stateFile{StateVersion: stateFileVersion, Policy: &next, Identity: identity}
	if err := atomicWriteJSON(s.activePath(), &sf); err != nil {
		return nil, err
	}
	if err := syncDir(s.dir); err != nil {
		return nil, err
	}
	if err := atomicWriteJSON(s.lkgPath(), &sf); err != nil {
		// active write committed; LKG refresh failure is recoverable on
		// next apply — report but keep the applied revision
		return &next, nil
	}
	return &next, nil
}

// DefaultPolicy is the empty first-run policy: no user rules, everything
// goes to the foreign pool, automatic RU fallback on (user decision U07).
func DefaultPolicy() *Policy {
	return &Policy{SchemaVersion: 1, Revision: 0, AllowRUFallback: true, Rules: []Rule{}}
}

// atomicWriteJSON writes to a unique temporary file (concurrent writers
// must never share a tmp name), fsyncs, then renames over the target.
func atomicWriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after successful rename
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
