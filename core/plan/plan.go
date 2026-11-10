// Package plan implements the plan/apply discipline required for every
// mutation (docs/CLI_AUTOMATION.md): a plan is computed read-only, hashed,
// time-limited and checked against preconditions before apply. Apply
// executes exactly the validated plan and refuses stale, expired,
// tampered or replayed plans.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Plan is one staged mutation of a given kind (policy, limits, tls, setup,
// update). Changes carry the kind-specific typed payload as JSON; the
// executor registry decodes it.
type Plan struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind"` // "policy" | "limits" | "tls" | "setup" | "update"
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Preconditions  map[string]string `json:"preconditions"` // key => expected value
	Changes        json.RawMessage   `json:"changes"`
	IdempotencyKey string            `json:"idempotency_key"`
}

// DefaultTTL bounds how long a reviewed plan stays applicable.
const DefaultTTL = 15 * time.Minute

// Hash computes the canonical plan hash: SHA-256 over sorted-key canonical
// JSON of the plan document. The hash is what the operator reviews and
// what apply verifies, so serialization must be deterministic.
func (p *Plan) Hash() (string, error) {
	b, err := canonicalJSON(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalJSON produces the deterministic serialization covered by the
// plan hash: object keys sorted at every level, numbers preserved
// verbatim. The decoder uses json.Number so int64 values above the
// float64 mantissa (e.g. quota bytes ≥ 2^53) are never rounded — two
// distinct approved configurations must never share a review hash
// (review R12).
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// Executor applies one plan kind. Check receives the parsed preconditions
// and must verify them against live state (ports, revisions, files); Apply
// performs the mutation and must be idempotent under the plan's
// idempotency key.
type Executor interface {
	Kind() string
	Check(p *Plan, now time.Time) error
	Apply(p *Plan, now time.Time) (Result, error)
}

// EffectRecognizer lets an executor confirm that a plan's effect is
// ALREADY present in live state. It runs when the recorded receipt is
// missing after a mid-apply failure (crash or disk-full between the
// mutation and the receipt write, review R06): the retry must recognize
// its own committed effect instead of failing with a stale-precondition
// conflict or mutating a second time.
type EffectRecognizer interface {
	RecognizeAlreadyApplied(p *Plan) (Result, bool)
}

// Result is the executor's outcome record.
type Result struct {
	Applied     bool              `json:"applied"`
	NewRevision int64             `json:"new_revision,omitempty"`
	Summary     map[string]string `json:"summary,omitempty"`
}

// Registry binds executors and persists staged plans plus the applied
// history (idempotency).
type Registry struct {
	dir       string
	executors map[string]Executor
}

func NewRegistry(dir string) (*Registry, error) {
	if err := os.MkdirAll(filepath.Join(dir, "plans"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "applied"), 0o700); err != nil {
		return nil, err
	}
	return &Registry{dir: dir, executors: map[string]Executor{}}, nil
}

func (r *Registry) Register(e Executor) { r.executors[e.Kind()] = e }

func (r *Registry) planPath(id string) string {
	return filepath.Join(r.dir, "plans", id+".json")
}

func (r *Registry) appliedPath(key string) string {
	return filepath.Join(r.dir, "applied", key+".json")
}

// Stage persists a new plan. Staging does not touch live state.
func (r *Registry) Stage(p *Plan) (string, error) {
	if p.ID == "" {
		return "", fmt.Errorf("plan id is required")
	}
	if p.IdempotencyKey == "" {
		return "", fmt.Errorf("idempotency key is required")
	}
	if p.ExpiresAt.IsZero() {
		p.ExpiresAt = p.CreatedAt.Add(DefaultTTL)
	}
	if _, ok := r.executors[p.Kind]; !ok {
		return "", fmt.Errorf("UNSUPPORTED_CAPABILITY: no executor for plan kind %q", p.Kind)
	}
	return p.Hash()
}

// Save writes the plan document after Stage validated it.
func (r *Registry) Save(p *Plan) error {
	return writeJSON(r.planPath(p.ID), p)
}

// LoadPlan reads a staged plan by id.
func (r *Registry) LoadPlan(id string) (*Plan, error) {
	b, err := os.ReadFile(r.planPath(id))
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("plan %s unreadable: %w", id, err)
	}
	return &p, nil
}

// Apply executes a staged plan under the full discipline:
//   - presentedHash must match the stored plan (tamper detection),
//   - the plan must not be expired,
//   - an executor for the kind must exist,
//   - executor.Check must pass preconditions against live state,
//   - idempotency: a previously applied idempotency key returns the
//     recorded result instead of re-applying.
func (r *Registry) Apply(planID, presentedHash string, now time.Time) (*Result, error) {
	p, err := r.LoadPlan(planID)
	if err != nil {
		return nil, fmt.Errorf("PLAN_STALE: %w", err)
	}
	realHash, err := p.Hash()
	if err != nil {
		return nil, err
	}
	if presentedHash != realHash {
		return nil, fmt.Errorf("VERIFICATION_FAILED: plan hash mismatch (presented %s, actual %s)", short(presentedHash), short(realHash))
	}
	if now.After(p.ExpiresAt) {
		return nil, fmt.Errorf("PLAN_EXPIRED: expired at %s", p.ExpiresAt.Format(time.RFC3339))
	}
	exec, ok := r.executors[p.Kind]
	if !ok {
		return nil, fmt.Errorf("UNSUPPORTED_CAPABILITY: no executor for plan kind %q", p.Kind)
	}
	// idempotency first: retries after a crash mid-apply must not
	// double-apply even when the executor would be partially idempotent.
	// An unreadable/corrupt receipt is NOT treated as proof of anything:
	// the flow falls through to recognition or a fresh apply.
	if rec, err := os.ReadFile(r.appliedPath(p.IdempotencyKey)); err == nil {
		var prev Result
		if json.Unmarshal(rec, &prev) == nil && prev.Applied {
			return &prev, nil
		}
	}
	if err := exec.Check(p, now); err != nil {
		// The effect may already be present from an earlier apply of THIS
		// plan whose receipt write failed (review R06). Recognition is
		// identified by the plan id recorded with the effect itself —
		// not by content alone: a different plan with identical content
		// keeps its genuine conflict, and a plan that was never applied
		// cannot claim the current state.
		if rec, ok := r.recognize(exec, p); ok {
			appliedPath := r.appliedPath(p.IdempotencyKey)
			// a failed receipt write may have left an unusable artifact
			// (directory/torn file): replace it with the real receipt.
			// This records an already-committed effect; it is not a new
			// mutation.
			if info, serr := os.Lstat(appliedPath); serr == nil && !info.Mode().IsRegular() {
				if rerr := os.RemoveAll(appliedPath); rerr != nil {
					return nil, fmt.Errorf("effect already applied but receipt trace cannot be replaced: %w", rerr)
				}
			}
			if werr := writeJSONAtomic(appliedPath, rec); werr != nil {
				return nil, fmt.Errorf("effect already applied but receipt still unwritable: %w", werr)
			}
			return &rec, nil
		}
		return nil, fmt.Errorf("CONFLICT: precondition failed: %w", err)
	}
	res, err := exec.Apply(p, now)
	if err != nil {
		return nil, err
	}
	if err := writeJSONAtomic(r.appliedPath(p.IdempotencyKey), res); err != nil {
		return nil, fmt.Errorf("applied but result not recorded: %w", err)
	}
	return &res, nil
}

func (r *Registry) recognize(exec Executor, p *Plan) (Result, bool) {
	rec, ok := exec.(EffectRecognizer)
	if !ok {
		return Result{}, false
	}
	return rec.RecognizeAlreadyApplied(p)
}

// PreconditionKeys returns sorted precondition keys (stable explain output).
func (p *Plan) PreconditionKeys() []string {
	keys := make([]string, 0, len(p.Preconditions))
	for k := range p.Preconditions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func writeJSON(path string, v any) error {
	return writeJSONAtomic(path, v)
}

// WriteJSONAtomic is the package's durable atomic JSON writer, shared with
// the service-layer executors so effect metadata and receipts use one
// crash-safe path.
func WriteJSONAtomic(path string, v any) error { return writeJSONAtomic(path, v) }

// writeJSONAtomic writes tmp-then-rename with an fsync of the file; the
// rename itself is atomic, so readers never see a half-written document
// (plan artifacts and receipts).
func writeJSONAtomic(path string, v any) error {
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
