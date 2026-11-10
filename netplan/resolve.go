package netplan

// Operator resolution (task B / review P3): pending plans stay fenced
// until a human inspects the durable evidence and confirms a TYPED,
// per-outcome resolution plan. The plan binds:
//   plan ID + journaled plan hash (what was reviewed),
//   one entry per unknown outcome (step number + apply|undo attempt),
//   a fingerprint of the inspection snapshot (what the operator SAW),
//   the decision and the actor/evidence.
// ResolveOperator re-enters the transaction lock, re-checks the hash and
// fingerprint against the freshly loaded journal immediately before
// applying, journals every confirmation durably, then finishes the plan
// by the ordinary machinery (as-applied → rollback, as-not-applied →
// resume). Nothing deletes journal records; a stale/mixed/partial plan is
// refused; legacy journals stay pending (no intents → no provable state).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"aravpn/core/policy"
)

// Decisions for one unknown outcome.
const (
	DecisionApplied    = "applied"    // effect verified present → undo it
	DecisionNotApplied = "not_applied" // effect verified absent → may retry
)

// Attempt distinguishes which operation of a step the decision covers.
type Attempt string

const (
	AttemptApply Attempt = "apply"
	AttemptUndo  Attempt = "undo"
)

// ResolutionEntry is one confirmed outcome.
type ResolutionEntry struct {
	Step     int     `json:"step"`
	Attempt  Attempt `json:"attempt"` // apply | undo
	Decision string  `json:"decision"` // applied | not_applied
}

// ResolutionPlan is the typed operator decision document.
type ResolutionPlan struct {
	PlanID      string            `json:"plan_id"`
	PlanHash    string            `json:"plan_hash"`    // hash the operator reviewed
	Fingerprint string            `json:"fingerprint"`  // sha256 of the inspection snapshot
	Entries     []ResolutionEntry `json:"entries"`
	Actor       string            `json:"actor"`
	Evidence    string            `json:"evidence"`
}

// Inspection is the evidence package for one non-terminal plan. Its
// canonical serialization IS the fingerprint the operator confirms.
type Inspection struct {
	PlanID   string     `json:"plan_id"`
	State    string     `json:"state"`
	PlanHash string     `json:"plan_hash,omitempty"`
	Steps    []StepInfo `json:"steps,omitempty"`
}

// StepInfo is one journaled step for inspection.
type StepInfo struct {
	Step   int    `json:"step"`
	Kind   string `json:"kind"`
	Status string `json:"status,omitempty"`
	Undo   string `json:"undo,omitempty"`
}

// unknownOutcomes lists every unknown apply/undo outcome of a run.
func unknownOutcomes(run *PlanRun) []ResolutionEntry {
	var out []ResolutionEntry
	if run == nil {
		return out
	}
	for i, st := range run.Steps {
		if st == nil {
			continue
		}
		// attempted-unknown on replay: intent journaled, no applied result
		if st.intent && st.applied == "" {
			out = append(out, ResolutionEntry{Step: i, Attempt: AttemptApply, Decision: ""})
		} else if st.applied == StatusOK && st.undo == undoUnknown {
			out = append(out, ResolutionEntry{Step: i, Attempt: AttemptUndo, Decision: ""})
		}
	}
	return out
}

// buildInspection constructs the canonical inspection snapshot for one
// non-terminal run. Its canonical serialization IS the fingerprint the
// operator confirms; both Inspect and ResolveOperator use this builder so
// the fingerprint always binds the exact reviewed state.
func buildInspection(run *PlanRun) (Inspection, error) {
	ins := Inspection{PlanID: run.PlanID, PlanHash: run.PlanHash}
	switch {
	case run.Legacy:
		ins.State = "legacy"
	case run.unknownEffectSteps() != nil:
		ins.State = "attempted-unknown"
	default:
		undoUnknownFound := false
		recoveryStarted := run.RecoveryStarted
		for _, st := range run.Steps {
			if st != nil && st.undo == undoUnknown {
				undoUnknownFound = true
			}
		}
		switch {
		case undoUnknownFound:
			ins.State = "undo-unknown"
		case recoveryStarted:
			ins.State = "recovery-in-progress"
		default:
			ins.State = "unknown"
		}
	}
	// deterministic step order: run.Steps is a map, and the fingerprint
	// must be stable across LoadRuns calls (random map order would change
	// the serialization between Inspect and ResolveOperator)
	idx := make([]int, 0, len(run.Steps))
	for i := range run.Steps {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		st := run.Steps[i]
		if st == nil {
			continue
		}
		si := StepInfo{Step: i, Status: st.applied, Undo: undoName(st.undo)}
		if run.Plan != nil && i < len(run.Plan.Ops) {
			si.Kind = string(run.Plan.Ops[i].Kind)
		}
		ins.Steps = append(ins.Steps, si)
	}
	return ins, nil
}

// FingerprintOf computes the canonical fingerprint of an inspection.
func FingerprintOf(ins Inspection) (string, error) {
	b, err := json.Marshal(ins)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Inspect returns the evidence for every non-terminal plan plus the
// fingerprint each resolution must quote. Read-only: no records are
// written and no lock beyond the shared read of the journal.
func Inspect(j *StepJournal) ([]Inspection, []string, error) {
	release, err := policy.LockDir(filepath.Dir(j.lockPath()))
	if err != nil {
		return nil, nil, fmt.Errorf("journal read lock: %w", err)
	}
	defer release()
	runs, err := j.LoadRuns()
	if err != nil {
		return nil, nil, fmt.Errorf("journal unreadable: %w", err)
	}
	ids := make([]string, 0, len(runs))
	for id := range runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Inspection
	var fingerprints []string
	for _, id := range ids {
		run := runs[id]
		if run.Committed || run.Recovered {
			continue
		}
		ins, err := buildInspection(run)
		if err != nil {
			return nil, nil, err
		}
		fp, ferr := FingerprintOf(ins)
		if ferr != nil {
			return nil, nil, ferr
		}
		fingerprints = append(fingerprints, fp)
		out = append(out, ins)
	}
	return out, fingerprints, nil
}


// ResolveOperator applies a typed resolution plan: hash + fingerprint are
// re-checked against the freshly loaded journal inside the transaction
// lock; every entry is journaled (actor + evidence) before the plan is
// finished by the ordinary machinery. Entries must cover EXACTLY the set
// of unknown outcomes — stale, mixed, partial or extra confirmations are
// refused.
func ResolveOperator(j *StepJournal, exec Executor, plan ResolutionPlan) (string, error) {
	if plan.Evidence == "" {
		return "", errors.New("resolve: evidence of the operator's verification is required")
	}
	if plan.PlanID == "" || plan.PlanHash == "" || plan.Fingerprint == "" {
		return "", errors.New("resolve: plan_id, plan_hash and fingerprint are required")
	}
	actor := plan.Actor
	if actor == "" {
		actor = "operator"
	}
	release, err := policy.LockDir(filepath.Dir(j.lockPath()))
	if err != nil {
		return "", fmt.Errorf("journal transaction lock: %w", err)
	}
	defer release()

	runs, err := j.LoadRuns()
	if err != nil {
		return "", fmt.Errorf("journal unreadable: %w", err)
	}
	run, ok := runs[plan.PlanID]
	if !ok {
		return "", fmt.Errorf("resolve: plan %s not found in journal", plan.PlanID)
	}
	if run.Committed || run.Recovered {
		return "", fmt.Errorf("resolve: plan %s is already terminal; nothing to resolve", plan.PlanID)
	}
	if run.Plan == nil {
		return "", fmt.Errorf("resolve: plan %s has no journaled plan; keep pending", plan.PlanID)
	}
	hash, err := planContentHash(run.Plan)
	if err != nil || hash != run.PlanHash {
		return "", fmt.Errorf("resolve: plan %s hash mismatch on recheck; refusing", plan.PlanID)
	}
	if run.PlanHash != plan.PlanHash {
		return "", fmt.Errorf("resolve: reviewed hash %q != current %q; re-inspect and retry", plan.PlanHash, run.PlanHash)
	}
	if run.Legacy {
		return "", fmt.Errorf("resolve: plan %s is legacy-schema (no step intents); provable resolution impossible — keep pending", plan.PlanID)
	}

	// the fingerprint must match the CURRENT journal state under this
	// lock: it binds the decision to the exact snapshot the operator
	// reviewed; stale/wrong fingerprints refuse without any record write
	ins, ferr := buildInspection(run)
	if ferr != nil {
		return "", ferr
	}
	currentFP, ferr := FingerprintOf(ins)
	if ferr != nil {
		return "", ferr
	}
	if plan.Fingerprint != currentFP {
		return "", fmt.Errorf("resolve: fingerprint mismatch (reviewed %q, current %q); re-inspect and retry", plan.Fingerprint, currentFP)
	}

	// the plan must cover EXACTLY the currently-unknown outcomes
	want := unknownOutcomes(run)
	if len(want) == 0 {
		return "", fmt.Errorf("resolve: plan %s has no unknown outcomes to confirm", plan.PlanID)
	}
	if len(plan.Entries) != len(want) {
		return "", fmt.Errorf("resolve: %d entries for %d unknown outcomes; partial/mixed resolution refused", len(plan.Entries), len(want))
	}
	seen := map[ResolutionEntry]bool{}
	for _, e := range plan.Entries {
		if e.Decision != DecisionApplied && e.Decision != DecisionNotApplied {
			return "", fmt.Errorf("resolve: bad decision %q", e.Decision)
		}
		matched := false
		for _, w := range want {
			if w.Step == e.Step && w.Attempt == e.Attempt && !seen[w] {
				seen[w] = true
				matched = true
				break
			}
		}
		if !matched {
			return "", fmt.Errorf("resolve: entry step %d/%s does not match an unknown outcome", e.Step, e.Attempt)
		}
	}

	// journal every confirmation durably BEFORE executing anything
	for _, e := range plan.Entries {
		rec := stepRec{Kind: KindOperatorConfirm, PlanID: plan.PlanID, Step: e.Step,
			Status: string(e.Attempt) + ":" + e.Decision,
			Reason: fmt.Sprintf("%s | fingerprint %s | evidence: %s", actor, plan.Fingerprint, plan.Evidence)}
		if err := j.append(rec); err != nil {
			return "", fmt.Errorf("resolve: confirm not journaled: %w", err)
		}
	}

	// re-load WITH the confirmations and finish by the ordinary machinery
	runs, err = j.LoadRuns()
	if err != nil {
		return "", fmt.Errorf("resolve: journal reload failed: %w", err)
	}
	run = runs[plan.PlanID]
	// finish per the dominant confirmed attempt: undo confirmations close
	// the plan by rollback; apply confirmations resume execution
	hasUndo := false
	for _, e := range plan.Entries {
		if e.Attempt == AttemptUndo {
			hasUndo = true
		}
	}
	if hasUndo {
		// confirmed undo outcomes: the plan is being rolled back
		if _, err := recoverLocked(j, exec); err != nil {
			return "recovering", fmt.Errorf("resolve: rollback after confirmation reported: %v", err)
		}
		return "recovered", nil
	}
	// apply outcomes: as-applied entries keep effects; not-applied retry
	res := executeLocked(run.Plan, j, exec)
	if res.Err != nil {
		return "executing", fmt.Errorf("resolve: resume failed: %v", res.Err)
	}
	return "committed", nil
}

// undoName renders a step's undo state for inspection output.
func undoName(u undoAttempt) string {
	switch u {
	case undoDone:
		return "done"
	case undoUnknown:
		return "unknown"
	case undoFailed:
		return "failed"
	}
	return "none"
}

var _ = time.Now
