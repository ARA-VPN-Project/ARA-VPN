package netplan

// Operator resolution regressions (task B): inspect → decision → durable
// finish for attempted-unknown apply, unknown undo and legacy journals.
// Unknown ownership must never be cleared by journal deletion or blind
// deletes — only by journaled operator confirmations with evidence.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// unknownExecutor applies the first N ops, then fails with an unknown
// outcome on the (N+1)th — the crash window.
type unknownExecutor struct {
	fakeExecutor
	unknownOn OpKind
	once      bool
}

func (u *unknownExecutor) Do(op Op) error {
	if op.Kind == u.unknownOn && !u.once {
		u.once = true
		return errors.New("signal during apply: outcome unknown")
	}
	return u.fakeExecutor.Do(op)
}

func opAdd() Op { return Op{Kind: OpAddRoute, Owner: "test", Table: "52100", Prefix: "10.90.0.0/24", Gateway: "10.0.0.1", Device: "ara0", Priority: 100} }
func opDel() Op { return invertOp(opAdd()) }

func mkPlan(t *testing.T, id string, ops ...Op) *Plan {
	t.Helper()
	p := &Plan{ID: id, Owner: "test", Scope: testScope(), Ops: ops, CreatedAt: time.Now().UTC()}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveAttemptedUnknownAsAppliedRollsBack(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenStepJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	exec := &unknownExecutor{fakeExecutor: fakeExecutor{}, unknownOn: OpDelRoute}
	// plan: add route then delete it; the DEL goes unknown
	p := mkPlan(t, "resolve-applied", opAdd(), opDel())
	if res := Execute(p, j, exec); res.Err == nil {
		t.Fatal("expected the unknown del to fail the plan")
	}
	insp, fps, err := Inspect(j)
	if err != nil || len(insp) != 1 {
		t.Fatalf("inspect: %v (%d)", err, len(insp))
	}
	if insp[0].State != "attempted-unknown" && insp[0].State != "undo-unknown" {
		t.Fatalf("inspect state: %s", insp[0].State)
	}
	if fps[0] == "" {
		t.Fatal("inspect must produce a fingerprint")
	}
	// resolve WITHOUT evidence is refused
	plan := ResolutionPlan{PlanID: p.ID, PlanHash: insp[0].PlanHash, Fingerprint: fps[0],
		Entries: []ResolutionEntry{{Step: 1, Attempt: AttemptUndo, Decision: DecisionApplied}}, Actor: "op"}
	if _, err := ResolveOperator(j, exec, plan); err == nil {
		t.Fatal("empty evidence must be refused")
	}
	plan.Evidence = "checked: route 10.90.0.0/24 absent via ip route show table 52100"
	// partial plan (only one entry for two unknowns? here both steps unknown)
	full := ResolutionPlan{PlanID: p.ID, PlanHash: plan.PlanHash, Fingerprint: plan.Fingerprint,
		Actor: "op", Evidence: plan.Evidence}
	// build entries for every unknown outcome
	var want []ResolutionEntry
	runs, lerr := j.LoadRuns()
	if lerr != nil {
		t.Fatal(lerr)
	}
	for i, st := range runs[p.ID].Steps {
		if st == nil {
			continue
		}
		if st.intent && st.applied == "" {
			want = append(want, ResolutionEntry{Step: i, Attempt: AttemptApply, Decision: DecisionApplied})
		} else if st.applied == StatusOK && st.undo == undoUnknown {
			want = append(want, ResolutionEntry{Step: i, Attempt: AttemptUndo, Decision: DecisionApplied})
		}
	}
	if len(want) == 0 {
		t.Fatal("expected unknown outcomes")
	}
	// mixed/partial plan refused
	if _, err := ResolveOperator(j, exec, ResolutionPlan{PlanID: full.PlanID, PlanHash: full.PlanHash,
		Fingerprint: full.Fingerprint, Actor: "op", Evidence: full.Evidence,
		Entries: want[:len(want)-1]}); err == nil {
		t.Fatal("partial resolution must be refused")
	}
	full.Entries = want
	state, err := ResolveOperator(j, exec, full)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// apply confirmations with "applied" semantics commit the plan; the
	// re-execution of the SAME plan id is then IDEMPOTENT (plan_commit
	// replay), never a re-run of the operations
	if state != "committed" {
		t.Fatalf("resolve state: %s", state)
	}
	if res := Execute(p, j, exec); res.Err != nil || res.AppliedSteps != len(p.Ops) {
		t.Fatalf("idempotent re-execution must succeed: %+v", res)
	}
}

func TestResolveAttemptedUnknownAsNotAppliedResumes(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenStepJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	exec := &unknownExecutor{fakeExecutor: fakeExecutor{}, unknownOn: OpDelRoute}
	p := mkPlan(t, "resolve-resume", opAdd(), opDel())
	if res := Execute(p, j, exec); res.Err == nil {
		t.Fatal("expected unknown failure")
	}
	// operator verified the delete never ran: resume commits the plan
	insp, fps, err := Inspect(j)
	if err != nil || len(insp) == 0 {
		t.Fatal(insp, err)
	}
	var entries []ResolutionEntry
	runs, _ := j.LoadRuns()
	for i, st := range runs[p.ID].Steps {
		if st == nil {
			continue
		}
		if st.intent && st.applied == "" {
			entries = append(entries, ResolutionEntry{Step: i, Attempt: AttemptApply, Decision: DecisionNotApplied})
		} else if st.applied == StatusOK && st.undo == undoUnknown {
			entries = append(entries, ResolutionEntry{Step: i, Attempt: AttemptUndo, Decision: DecisionNotApplied})
		}
	}
	t.Logf("DEBUG entries=%+v state_of_steps:", entries)
	runs2, _ := j.LoadRuns()
	for i, st := range runs2[p.ID].Steps {
		t.Logf("DEBUG step %d: intent=%v applied=%q undo=%v", i, st != nil && st.intent, st.applied, st.undo)
	}
	state, err := ResolveOperator(j, exec, ResolutionPlan{PlanID: p.ID, PlanHash: insp[0].PlanHash,
		Fingerprint: fps[0], Entries: entries, Actor: "op",
		Evidence: "verified: del never reached the kernel (strace log)"})
	if err != nil || state != "committed" {
		t.Fatalf("resolve as-not-applied: state=%s err=%v", state, err)
	}
}

func TestResolveUndoUnknownFencedUntilDecision(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenStepJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	// step 1 applies ok; step 2 fails with a KNOWN no-effect (duplicate
	// add) leaving the plan non-terminal with one real effect; the undo
	// of step 1 then goes unknown (undoUnknownExecutor).
	opAdd2 := opAdd()
	opAdd2.Prefix = "10.91.0.0/24"
	exec := &undoUnknownExecutor{fakeExecutor: fakeExecutor{
		failOn: map[OpKind]error{},
	}, failSecondAdd: true}
	p := mkPlan(t, "resolve-undo", opAdd(), opAdd2)
	if res := Execute(p, j, exec); res.Err == nil {
		t.Fatal("expected known failure on step 2")
	}
	// a plain Recover must NOT silently succeed: it stays fenced
	if _, err := Recover(j, exec); err == nil {
		t.Fatal("recover must report the unknown-undo fence")
	}
	insp, _, _ := Inspect(j)
	if len(insp) == 0 || insp[0].State != "undo-unknown" {
		t.Fatalf("inspect: %+v", insp)
	}
	// operator confirms the undo DID run: plan closes as recovered
	insp, fps, ierr := Inspect(j)
	if ierr != nil || len(insp) == 0 {
		t.Fatal(insp, ierr)
	}
	var entries []ResolutionEntry
	runs, _ := j.LoadRuns()
	for i, st := range runs[p.ID].Steps {
		if st == nil {
			continue
		}
		if st.intent && st.applied == "" {
			entries = append(entries, ResolutionEntry{Step: i, Attempt: AttemptApply, Decision: DecisionApplied})
		} else if st.applied == StatusOK && st.undo == undoUnknown {
			entries = append(entries, ResolutionEntry{Step: i, Attempt: AttemptUndo, Decision: DecisionApplied})
		}
	}
	state, err := ResolveOperator(j, exec, ResolutionPlan{PlanID: p.ID, PlanHash: insp[0].PlanHash,
		Fingerprint: fps[0], Entries: entries, Actor: "op", Evidence: "route absent from table 52100"})
	if err != nil || state != "recovered" {
		t.Fatalf("resolve undo as-applied: state=%s err=%v", state, err)
	}
}

type undoUnknownExecutor struct {
	fakeExecutor
	undone        bool
	failSecondAdd bool
	adds          int
}

func (u *undoUnknownExecutor) Do(op Op) error {
	if op.Kind == OpAddRoute {
		u.adds++
		if u.failSecondAdd && u.adds == 2 {
			return NoEffect(errors.New("duplicate add refused"))
		}
	}
	if op.Kind == OpDelRoute && !u.undone {
		u.undone = true
		return errors.New("process killed mid-undo: outcome unknown")
	}
	return u.fakeExecutor.Do(op)
}

func TestResolveLegacyStaysPending(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenStepJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{}
	// forge a legacy plan_begin (no version field)
	legacy := &Plan{ID: "legacy-1", Owner: "test", Scope: testScope(), Ops: []Op{opAdd()}}
	legacy.Hash = mustHash(t, legacy)
	if err := j.append(stepRec{Kind: KindPlanBegin, PlanID: "legacy-1",
		Plan: legacy, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Inspect(j); err != nil {
		t.Fatal(err)
	}
	// operator resolution must REFUSE legacy per-step confirmation
	insp, _, _ := Inspect(j)
	if len(insp) == 0 {
		t.Fatal("legacy plan missing from inspection")
	}
	if _, err := ResolveOperator(j, exec, ResolutionPlan{PlanID: "legacy-1", PlanHash: insp[0].PlanHash,
		Fingerprint: "fp", Entries: []ResolutionEntry{{Step: 0, Attempt: AttemptApply, Decision: DecisionApplied}},
		Actor: "op", Evidence: "checked"}); err == nil {
		t.Fatal("legacy plan must not be confirmable step-wise")
	}
	if len(insp) != 1 || insp[0].State != "legacy" {
		t.Fatalf("legacy plan must stay pending: %+v", insp)
	}
}

func mustHash(t *testing.T, p *Plan) string {
	t.Helper()
	h, err := planContentHash(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var _ = context.Background
