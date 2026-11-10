package netplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"aravpn/core/policy"
	"strings"
)

// Plan application/recovery lifecycle — one unified model with durable
// evidence (review round5):
//
//	Plan:
//	  ABSENT       no plan_begin
//	  BEGUN        plan_begin (v2), non-terminal; recovery candidate
//	  ROLLING-BACK plan_begin + any undo attempt recorded (irreversible:
//	               plan_commit is FORBIDDEN from this point on, W02)
//	  COMMITTED    plan_commit — terminal success (only before rollback)
//	  RECOVERED    recovered record — terminal rollback
//	  UNRESOLVED   unresolved record — pending operator; stays pending
//	               (repeated Recover keeps reporting it, W01)
//	  LEGACY-pending  plan_begin of the PRE-INTENT schema (no version):
//	               absence of intent proves nothing there, so recovery
//	               refuses and the plan stays pending (W03)
//
//	Step (v2 writer journals step_intent BEFORE each command):
//	  not-started        no intent, no result — provably never run
//	  attempted-unknown  intent without result — effect unknown
//	  applied-ok/failed  step_result
//
//	Undo attempt = state of the LATEST undo per step:
//	  none → unknown (intent w/o result) → done | failed (retryable)
//
// Fence (W01): Execute refuses while ANY other plan is non-terminal
// (begun / rolling-back / unresolved / legacy-pending) — known-ok
// effects, known failures and unknown undos all fence. A new plan on
// freed coordinates is allowed only after the old recovery reached a
// terminal state, and that old recovery never touches it again.
//
// Execute and Recover hold one cross-process lock over the whole
// operation and re-read state after acquiring it.
const (
	KindPlanBegin  = "plan_begin"
	KindStepIntent = "step_intent"
	KindStepResult = "step_result"
	KindPlanCommit = "plan_commit"
	KindUndoIntent = "undo_intent"
	KindUndoResult = "undo_result"
	KindRecovered  = "recovered"
	KindUnresolved = "unresolved"
	// KindOperatorConfirm journals the operator's verified decision about
	// one unknown outcome (netplan/resolve.go); replay applies it and
	// lifts the corresponding fence.
	KindOperatorConfirm = "operator_confirm"
)

// SchemaVersion is the netplan journal schema of this writer: v2 journals
// step_intent for every attempt. Journals whose plan_begin lacks the
// version belong to the pre-intent writer and are treated as legacy
// (W03): their non-terminal plans stay pending, because "no intent" in
// that format does not prove "no attempt".
const SchemaVersion = 2

const (
	StatusOK      = "ok"
	StatusFail    = "failed"
	StatusUnknown = "unknown" // attempt started; outcome not established
)

// Outcome contract for external operations (review X01). An Executor
// returns an error; the CALLER classifies it:
//
//	*NoEffectError  — the operation provably failed BEFORE any effect
//	                  could happen (e.g. the process never started, or the
//	                  kernel rejected a single atomic request);
//	any other error — UNKNOWN: the effect may have happened (signal after
//	                  the work, lost acknowledgement, unclassified
//	                  failure). Unknown never counts as no-effect.
//
// NoEffectError preserves the original cause via Unwrap.
type NoEffectError struct {
	Err error
}

func (e *NoEffectError) Error() string {
	if e.Err == nil {
		return "operation failed before any effect"
	}
	return e.Err.Error()
}

func (e *NoEffectError) Unwrap() error { return e.Err }

// NoEffect wraps a proven pre-effect failure so the journal can treat it
// as a known no-op instead of an ambiguous outcome.
func NoEffect(err error) error { return &NoEffectError{Err: err} }

// classifyErr maps an executor error to its durable step/undo status.
func classifyErr(err error) string {
	var ne *NoEffectError
	if errors.As(err, &ne) {
		return StatusFail
	}
	return StatusUnknown
}

type stepRec struct {
	Kind   string    `json:"kind"`
	PlanID string    `json:"plan_id"`
	Owner  string    `json:"owner,omitempty"`
	Step   int       `json:"step,omitempty"`
	Status string    `json:"status,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Plan   *Plan     `json:"plan,omitempty"`
	Op     Op        `json:"op,omitempty"`
	V      int       `json:"v,omitempty"` // journal schema version (plan_begin)
	At     time.Time `json:"at"`
}

type undoAttempt int

const (
	undoNone undoAttempt = iota
	undoUnknown
	undoDone
	undoFailed
)

type stepState struct {
	confirmNotApplied bool
	intent  bool
	applied string
	undo    undoAttempt
}

// PlanRun summarizes one plan's durable history.
type PlanRun struct {
	PlanID          string
	Owner           string
	Plan            *Plan
	PlanHash        string
	Legacy          bool // plan_begin of the pre-intent schema (W03)
	Steps           map[int]*stepState
	Committed       bool
	Recovered       bool
	Unresolved      bool
	RecoveryStarted bool // any undo attempt recorded (W02: commit forbidden)
}

func (r *PlanRun) step(i int) *stepState {
	if r.Steps == nil {
		r.Steps = map[int]*stepState{}
	}
	s := r.Steps[i]
	if s == nil {
		s = &stepState{}
		r.Steps[i] = s
	}
	return s
}

// Terminal reports whether the plan reached a final state.
func (r *PlanRun) Terminal() bool { return r.Committed || r.Recovered || r.Unresolved }

// unknownEffectSteps returns started-but-unresolved steps (v2 evidence).
func (r *PlanRun) unknownEffectSteps() []int {
	var out []int
	for i := 0; i < len(r.Plan.Ops); i++ {
		st := r.Steps[i]
		if st != nil && st.intent && st.applied == "" {
			out = append(out, i)
		}
	}
	return out
}

// StepJournal is the durable per-step log of plan applications.
type StepJournal struct {
	path string
}

func (j *StepJournal) lockPath() string { return j.path + ".lock" }

func OpenStepJournal(stateDir string) (*StepJournal, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	return &StepJournal{path: filepath.Join(stateDir, "netplan.journal.jsonl")}, nil
}

func (j *StepJournal) append(rec stepRec) error {
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	rec.At = currentTime()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// LoadRuns replays the journal. A torn final line is an error.
func (j *StepJournal) LoadRuns() (map[string]*PlanRun, error) {
	b, err := os.ReadFile(j.path)
	if os.IsNotExist(err) {
		return map[string]*PlanRun{}, nil
	}
	if err != nil {
		return nil, err
	}
	runs := map[string]*PlanRun{}
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var rec stepRec
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("journal line unreadable: %w (operator inspection required)", err)
		}
		r := runs[rec.PlanID]
		if r == nil {
			r = &PlanRun{PlanID: rec.PlanID, Steps: map[int]*stepState{}}
			runs[rec.PlanID] = r
		}
		switch rec.Kind {
		case KindPlanBegin:
			if rec.Plan != nil {
				r.Plan = rec.Plan
				r.Owner = rec.Plan.Owner
				r.PlanHash = rec.Plan.Hash
				r.Legacy = rec.V != SchemaVersion
			}
		case KindStepIntent:
			r.step(rec.Step).intent = true
		case KindStepResult:
			if rec.Status == StatusUnknown {
				// attempted, outcome not established: stays unknown
				// (applied stays empty; unknownEffectSteps detects it)
				continue
			}
			r.step(rec.Step).applied = rec.Status
		case KindUndoIntent:
			r.step(rec.Step).undo = undoUnknown
			r.RecoveryStarted = true
		case KindUndoResult:
			switch rec.Status {
			case StatusOK:
				r.step(rec.Step).undo = undoDone
			case StatusUnknown:
				r.step(rec.Step).undo = undoUnknown
			default:
				r.step(rec.Step).undo = undoFailed
			}
			r.RecoveryStarted = true
		case KindPlanCommit:
			r.Committed = true
		case KindRecovered:
			r.Recovered = true
		case KindUnresolved:
			r.Unresolved = true
		case KindOperatorConfirm:
			// Status carries "attempt:decision" (e.g. "undo:applied");
			// apply the decision to the matching unknown outcome
			st := r.step(rec.Step)
			attempt, decision, cut := strings.Cut(rec.Status, ":")
			if !cut {
				continue // malformed confirm: keep the fence, never guess
			}
			switch decision {
			case DecisionApplied:
				if attempt == string(AttemptUndo) && st.undo == undoUnknown {
					st.undo = undoDone
				} else if attempt == string(AttemptApply) && st.intent && st.applied == "" {
					st.applied = StatusOK
				}
			case DecisionNotApplied:
				if attempt == string(AttemptUndo) && st.undo == undoUnknown {
					st.undo = undoNone
				} else if attempt == string(AttemptApply) && st.intent && st.applied == "" {
					st.applied = StatusFail
					st.confirmNotApplied = true
				}
			}
			// a journaled operator decision lifts the unresolved fence:
			// the evidence chain is complete (inspect → decision)
			r.Unresolved = false
		}
	}
	return runs, nil
}

// Executor performs one validated operation.
type Executor interface {
	Do(op Op) error
}

// ApplyResult reports the durable outcome of one plan application.
type ApplyResult struct {
	AppliedSteps int
	FailedStep   int
	Err          error
}

func planContentHash(p *Plan) (string, error) {
	cp := *p
	cp.Hash = ""
	return cp.ContentHash()
}

// Execute applies a validated plan under the journal transaction lock.
func Execute(p *Plan, j *StepJournal, exec Executor) ApplyResult {
	release, err := policy.LockDir(filepath.Dir(j.lockPath()))
	if err != nil {
		return ApplyResult{FailedStep: -1, Err: fmt.Errorf("journal transaction lock: %w", err)}
	}
	defer release()
	return executeLocked(p, j, exec)
}

// executeLocked is the Execute body for a caller that already holds the
// journal transaction lock (operator resolution finishes plans inline).
func executeLocked(p *Plan, j *StepJournal, exec Executor) ApplyResult {
	if err := p.Validate(); err != nil {
		return ApplyResult{FailedStep: -1, Err: err}
	}
	hash, err := planContentHash(p)
	if err != nil {
		return ApplyResult{FailedStep: -1, Err: err}
	}
	runs, err := j.LoadRuns()
	if err != nil {
		return ApplyResult{FailedStep: -1, Err: fmt.Errorf("journal unreadable: %w", err)}
	}

	var prior *PlanRun
	if r, ok := runs[p.ID]; ok {
		prior = r
	}

	// W01 fence: while ANY other plan is non-terminal — begun with
	// known-ok effects, known failures, unknown apply or unknown undo —
	// new conflicting plans are refused until recovery/permission.
	for id, run := range runs {
		// committed and recovered plans release the coordinates;
		// unresolved and begun/recovering plans fence them.
		if id != p.ID && !run.Committed && !run.Recovered {
			if run.Unresolved {
				return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan %s is unresolved (operator resolution required); new network mutations are blocked", id)}
			}
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan %s is not terminal (apply/recovery incomplete); run recovery before new network mutations", id)}
		}
	}

	// V06/W01/W02: same-ID handling by its durable state.
	if run, ok := runs[p.ID]; ok {
		switch {
		case run.PlanHash != "" && run.PlanHash != hash:
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("CONFLICT: plan id %q was already used with different content; use a new plan id", p.ID)}
		case run.Unresolved:
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan %s is unresolved (operator resolution required)", p.ID)}
		case run.Legacy && !run.Terminal():
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan %s belongs to the legacy journal schema and is not terminal; operator inspection required", p.ID)}
		case run.Committed:
			return ApplyResult{AppliedSteps: len(p.Ops), FailedStep: -1} // idempotent
		case run.Recovered:
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("CONFLICT: plan id %q was already applied and recovered; use a new plan id", p.ID)}
		case run.RecoveryStarted:
			// W02: once rollback began it is irreversible — commit is
			// impossible even if every apply result reads ok.
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan %s recovery has started (rollback phase); commit is forbidden — run recovery to completion", p.ID)}
		default:
			if len(run.unknownEffectSteps()) > 0 {
				return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan %s has unknown step outcome (crash window); run recovery or operator resolution before re-execution", p.ID)}
			}
			allOK := true
			resumable := true
			for i := 0; i < len(p.Ops); i++ {
				st := run.Steps[i]
				if st == nil || st.applied != StatusOK {
					allOK = false
					if st == nil || !st.confirmNotApplied {
						resumable = false
					}
				}
			}
			if resumable {
				// operator-confirmed absent effects: the step loop below
				// retries exactly those steps
				break
			}
			if allOK {
				// W02: allowed only because recovery has not started.
				if err := j.append(stepRec{Kind: KindPlanCommit, PlanID: p.ID}); err != nil {
					return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan_commit not journaled: %w", err)}
				}
				return ApplyResult{AppliedSteps: len(p.Ops), FailedStep: -1}
			}
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("CONFLICT: plan %s has an incomplete previous execution; run recovery first", p.ID)}
		}
	}

	if prior == nil {
		begun := *p
		begun.Hash = hash
		if err := j.append(stepRec{Kind: KindPlanBegin, PlanID: p.ID, Plan: &begun, V: SchemaVersion}); err != nil {
			return ApplyResult{FailedStep: -1, Err: fmt.Errorf("plan_begin write failed: %w", err)}
		}
	}
	for i, op := range p.Ops {
		if err := j.append(stepRec{Kind: KindStepIntent, PlanID: p.ID, Step: i, Op: op}); err != nil {
			return ApplyResult{AppliedSteps: i, FailedStep: i, Err: fmt.Errorf("step %d intent not journaled: %w", i, err)}
		}
		if err := exec.Do(op); err != nil {
			// X01: only a PROVEN pre-effect failure is a known failed
			// step; everything else stays attempted-unknown.
			status := classifyErr(err)
			_ = j.append(stepRec{Kind: KindStepResult, PlanID: p.ID, Step: i, Op: op, Status: status, Reason: err.Error()})
			if status == StatusUnknown {
				return ApplyResult{AppliedSteps: i, FailedStep: i, Err: fmt.Errorf("step %d (%s) outcome unknown (the command may have taken effect): %w", i, op.Kind, err)}
			}
			return ApplyResult{AppliedSteps: i, FailedStep: i, Err: fmt.Errorf("step %d (%s) failed: %w", i, op.Kind, err)}
		}
		if err := j.append(stepRec{Kind: KindStepResult, PlanID: p.ID, Step: i, Op: op, Status: StatusOK}); err != nil {
			return ApplyResult{AppliedSteps: i + 1, FailedStep: i, Err: fmt.Errorf("step %d applied but result not journaled: %w", i, err)}
		}
	}
	if err := j.append(stepRec{Kind: KindPlanCommit, PlanID: p.ID}); err != nil {
		return ApplyResult{AppliedSteps: len(p.Ops), FailedStep: -1, Err: fmt.Errorf("steps applied but plan_commit not journaled: %w", err)}
	}
	return ApplyResult{AppliedSteps: len(p.Ops), FailedStep: -1}
}

// Recover rolls back known effects of non-terminal plans under the same
// transaction lock. Pending plans keep reporting an explicit error on
// every call (W01: never an indistinguishable empty success).
func Recover(j *StepJournal, exec Executor) ([]string, error) {
	release, err := policy.LockDir(filepath.Dir(j.lockPath()))
	if err != nil {
		return nil, fmt.Errorf("journal transaction lock: %w", err)
	}
	defer release()
	return recoverLocked(j, exec)
}

// recoverLocked is the Recover body for a lock-holding caller.
func recoverLocked(j *StepJournal, exec Executor) ([]string, error) {
	runs, err := j.LoadRuns()
	if err != nil {
		return nil, err
	}
	var fullyRecovered []string
	var firstErr error
	setErr := func(format string, args ...any) {
		if firstErr == nil {
			firstErr = fmt.Errorf(format, args...)
		}
	}
	for id, run := range runs {
		if run.Committed || run.Recovered {
			continue
		}
		if run.Unresolved {
			// W01: pending stays visible to the caller on every call
			setErr("plan %s is unresolved (pending operator resolution)", id)
			continue
		}
		if run.Plan == nil {
			setErr("recover %s: no durable plan_begin; operator inspection required", id)
			continue
		}
		if err := run.Plan.Validate(); err != nil {
			setErr("recover %s: journaled plan no longer valid: %v", id, err)
			continue
		}
		if hash, herr := planContentHash(run.Plan); herr != nil || hash != run.PlanHash {
			setErr("recover %s: journaled plan hash mismatch; refusing", id)
			continue
		}
		// W03: pre-intent (legacy) plans cannot prove that commands never
		// ran — absence of intent is evidence only in the v2 schema.
		if run.Legacy {
			if err := j.append(stepRec{Kind: KindUnresolved, PlanID: id,
				Reason: "legacy journal schema (no step intents); operator inspection required"}); err != nil {
				setErr("recover %s: unresolved marker not journaled: %v", id, err)
				continue
			}
			run.Unresolved = true
			setErr("recover %s: legacy journal plan requires operator inspection (possible effects are not provable)", id)
			continue
		}

		var okSteps []int
		for i, st := range run.Steps {
			if st.applied == StatusOK {
				okSteps = append(okSteps, i)
			}
		}
		sort.Ints(okSteps)
		for a, b := 0, len(okSteps)-1; a < b; a, b = a+1, b-1 {
			okSteps[a], okSteps[b] = okSteps[b], okSteps[a]
		}

		allDone := true
		for _, i := range okSteps {
			st := run.Steps[i]
			switch st.undo {
			case undoDone:
				continue
			case undoUnknown:
				// W01/W02: unknown undo outcome fences the plan; mark
				// unresolved so new mutations stay blocked.
				setErr("recover %s step %d: undo outcome unknown from a previous attempt; operator inspection required", id, i)
				allDone = false
				continue
			}
			op := run.Plan.Ops[i]
			inv := invertOp(op)
			if err := inv.validateAgainstScope(run.Plan.Scope); err != nil {
				setErr("recover %s step %d: undo outside recorded scope: %v", id, i, err)
				allDone = false
				continue
			}
			if err := j.append(stepRec{Kind: KindUndoIntent, PlanID: id, Step: i, Op: inv}); err != nil {
				setErr("recover %s step %d: undo intent not journaled: %v", id, i, err)
				allDone = false
				continue
			}
			if err := exec.Do(inv); err != nil {
				// X01: a proven no-effect (delete did not run) is retryable;
				// an unknown outcome fences the plan (never repeated).
				status := classifyErr(err)
				_ = j.append(stepRec{Kind: KindUndoResult, PlanID: id, Step: i, Op: inv, Status: status, Reason: err.Error()})
				if status == StatusUnknown {
					run.step(i).undo = undoUnknown
					run.RecoveryStarted = true
					setErr("recover %s step %d: undo outcome unknown (the delete may have taken effect): %v", id, i, err)
				} else {
					run.step(i).undo = undoFailed
					setErr("recover %s step %d: undo failed: %v", id, i, err)
				}
				allDone = false
				continue
			}
			if err := j.append(stepRec{Kind: KindUndoResult, PlanID: id, Step: i, Op: inv, Status: StatusOK}); err != nil {
				setErr("recover %s step %d: undo result not journaled: %v", id, i, err)
				allDone = false
				continue
			}
			run.step(i).undo = undoDone
		}

		if unknown := run.unknownEffectSteps(); len(unknown) > 0 {
			if !run.Unresolved {
				if err := j.append(stepRec{Kind: KindUnresolved, PlanID: id,
					Reason: "step outcome unknown after crash; operator inspection required"}); err != nil {
					setErr("recover %s: unresolved marker not journaled: %v", id, err)
					continue
				}
				run.Unresolved = true
			}
			setErr("recover %s: pending operator resolution (unknown step outcome at %v)", id, unknown)
			continue
		}
		if !allDone {
			// W01: a failed undo leaves an unknown-undo-or-retryable
			// state; if any undo is unknown, fence the plan durably.
			fenced := false
			for _, st := range run.Steps {
				if st != nil && st.undo == undoUnknown {
					fenced = true
					break
				}
			}
			if fenced && !run.Unresolved {
				if err := j.append(stepRec{Kind: KindUnresolved, PlanID: id,
					Reason: "undo outcome unknown; operator inspection required"}); err != nil {
					setErr("recover %s: unresolved marker not journaled: %v", id, err)
					continue
				}
				run.Unresolved = true
			}
			continue
		}
		if err := j.append(stepRec{Kind: KindRecovered, PlanID: id}); err != nil {
			setErr("recover %s: terminal record not journaled: %v", id, err)
			continue
		}
		run.Recovered = true
		fullyRecovered = append(fullyRecovered, id)
	}
	return fullyRecovered, firstErr
}

func invertOp(op Op) Op {
	out := op
	switch op.Kind {
	case OpAddRoute:
		out.Kind = OpDelRoute
	case OpAddRule:
		out.Kind = OpDelRule
	case OpAddNftTable:
		out.Kind = OpDelNftTable
	case OpAddQdisc:
		out.Kind = OpDelQdisc
	}
	return out
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
