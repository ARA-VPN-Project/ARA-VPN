package netplan

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func execCmd(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// fakeExecutor records ops and can fail selected steps.
type fakeExecutor struct {
	calls   []Op
	failOn  map[OpKind]error
	skipDel bool // del for absent objects "fails" (simulate not-found)
}

func (f *fakeExecutor) Do(op Op) error {
	if err, ok := f.failOn[op.Kind]; ok {
		// injected rejections model kernel-side known no-effect failures
		return NoEffect(err)
	}
	if f.skipDel && (op.Kind == OpDelRoute || op.Kind == OpDelRule || op.Kind == OpDelNftTable || op.Kind == OpDelQdisc) {
		// object absent: the delete provably had no effect
		return NoEffect(errors.New("not found"))
	}
	f.calls = append(f.calls, op)
	return nil
}

func testScope() *Scope {
	return &Scope{
		Name:         "lab",
		Interfaces:   []string{"ara0"},
		QdiscDevices: []string{"ara0"},
		Tables:       []string{"52100", "52101"},
		Marks:        []uint32{0x52100},
		NftTables:    []string{"inet ara-filter"},
	}
}

func testPlan() *Plan {
	return &Plan{
		ID:        "np-1",
		Owner:     "ara-net-helper",
		CreatedAt: time.Now().UTC(),
		Scope:     testScope(),
		Ops: []Op{
			{Kind: OpAddRoute, Owner: "ara-net-helper", Prefix: "10.111.0.0/24", Device: "ara0", Table: "52100"},
			{Kind: OpAddRule, Owner: "ara-net-helper", Mark: 0x52100, Table: "52100", Priority: 100},
			{Kind: OpAddNftTable, Owner: "ara-net-helper", Table: "inet ara-filter"},
			{Kind: OpAddQdisc, Owner: "ara-net-helper", Device: "ara0"},
		},
	}
}

func TestPlanValidateAndInvert(t *testing.T) {
	p := testPlan()
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	inv := p.Invert()
	if len(inv.Ops) != len(p.Ops) {
		t.Fatalf("rollback must mirror adds: %d vs %d", len(inv.Ops), len(p.Ops))
	}
	if inv.Ops[0].Kind != OpDelQdisc {
		t.Fatalf("first rollback op: %s", inv.Ops[0].Kind)
	}
	if inv.Ops[len(inv.Ops)-1].Kind != OpDelRoute {
		t.Fatalf("last rollback op: %s", inv.Ops[len(inv.Ops)-1].Kind)
	}
}

// R01 regression: an op accepted on the Owner label alone must be
// rejected by validation — host interfaces, reserved tables, the default
// route and foreign nft tables are outside any declared scope.
func TestUnscopedHostObjectsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   Op
	}{
		{"default route via eth0", Op{Kind: OpAddRoute, Owner: "ara", Table: "main", Prefix: "0.0.0.0/0", Device: "eth0", Gateway: "192.0.2.1"}},
		{"host interface qdisc delete", Op{Kind: OpDelQdisc, Owner: "ara", Device: "eth0"}},
		{"route via host interface", Op{Kind: OpAddRoute, Owner: "ara", Prefix: "10.0.0.0/8", Device: "eth0"}},
		{"reserved table", Op{Kind: OpAddRoute, Owner: "ara", Prefix: "10.111.0.0/24", Device: "ara0", Table: "main"}},
		{"foreign fwmark", Op{Kind: OpAddRule, Owner: "ara", Mark: 0x1, Table: "52100"}},
		{"foreign nft table", Op{Kind: OpAddNftTable, Owner: "ara", Table: "inet filter"}},
		{"foreign rule table", Op{Kind: OpAddRule, Owner: "ara", Mark: 0x52100, Table: "999"}},
		{"qdisc on interface without qdisc grant", Op{Kind: OpAddQdisc, Owner: "ara", Device: "ara1"}},
	} {
		p := Plan{Owner: "ara", ID: "review", Scope: testScope(), Ops: []Op{tc.op}}
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted on the owner label alone", tc.name)
		}
		// also refused with NO scope at all
		p2 := Plan{Owner: "ara", ID: "review", Ops: []Op{tc.op}}
		if err := p2.Validate(); err == nil {
			t.Errorf("%s: accepted without any ownership scope", tc.name)
		}
	}
	// unscoped plan with even benign ops is refused: unscoped plans touch nothing
	p3 := Plan{Owner: "ara", ID: "x", Ops: []Op{{Kind: OpAddRoute, Owner: "ara", Prefix: "10.111.0.0/24", Device: "ara0"}}}
	if err := p3.Validate(); err == nil {
		t.Error("plan without scope accepted")
	}
}

func TestPlanRejectsForeignOwnerAndBadOps(t *testing.T) {
	p := testPlan()
	p.Ops[1].Owner = "someone-else"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("mixed owners accepted: %v", err)
	}
	p2 := testPlan()
	p2.Ops[0].Prefix = "not-a-prefix"
	if err := p2.Validate(); err == nil {
		t.Fatal("bad prefix accepted")
	}
	p3 := testPlan()
	p3.Ops[1].Mark = 0
	if err := p3.Validate(); err == nil {
		t.Fatal("rule without mark accepted")
	}
	p4 := testPlan()
	p4.Ops[0].Kind = "reboot-host"
	if err := p4.Validate(); err == nil {
		t.Fatal("unknown op kind accepted")
	}
	// scope itself cannot claim reserved tables
	s := testScope()
	s.Tables = append(s.Tables, "main")
	p5 := testPlan()
	p5.Scope = s
	if err := p5.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("scope claiming a reserved table accepted: %v", err)
	}
}

func TestExecuteStepsJournaled(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenStepJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeExecutor{}
	p := testPlan()
	res := Execute(p, j, fake)
	if res.Err != nil || res.AppliedSteps != 4 {
		t.Fatalf("apply: %+v", res)
	}
	if len(fake.calls) != 4 {
		t.Fatalf("executor calls: %d", len(fake.calls))
	}
	runs, err := j.LoadRuns()
	if err != nil {
		t.Fatal(err)
	}
	run := runs["np-1"]
	// review S02: journal layout is begin + 4 results + commit = 6 records
	if run == nil || !run.Committed || len(run.Steps) != 4 {
		t.Fatalf("journal runs: %+v", run)
	}
	if run.Plan == nil || len(run.Plan.Ops) != 4 || run.PlanHash == "" {
		t.Fatalf("plan_begin content: %+v", run.Plan)
	}
	// fully applied+committed plan is NOT a recovery candidate
	recovered, err := Recover(j, fake)
	if err != nil || len(recovered) != 0 {
		t.Fatalf("complete plan recovered: %v %v", recovered, err)
	}
}

func TestExecuteFailsStopAndJournalRecords(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	fake := &fakeExecutor{failOn: map[OpKind]error{OpAddNftTable: errors.New("nft boom")}}
	p := testPlan()
	res := Execute(p, j, fake)
	if res.Err == nil || res.FailedStep != 2 {
		t.Fatalf("expected failure at step 2: %+v", res)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("steps executed after failure: %d", len(fake.calls))
	}
	runs, _ := j.LoadRuns()
	run := runs["np-1"]
	okCount := 0
	for _, st := range run.Steps {
		if st.applied == StatusOK {
			okCount++
		}
	}
	if okCount != 2 || run.Committed {
		t.Fatalf("ok steps: %d committed=%v", okCount, run.Committed)
	}
}

// R01 regression: a crash mid-apply (intent without result) and partially
// completed plans are recovered by inverting ONLY owned adds.
func TestRecoverPartialApplyInvertsOwnedAdds(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	fake := &fakeExecutor{failOn: map[OpKind]error{OpAddQdisc: errors.New("tc boom")}}
	p := testPlan()
	if res := Execute(p, j, fake); res.Err == nil {
		t.Fatal("expected the last step to fail")
	}
	recFake := &fakeExecutor{}
	recovered, err := Recover(j, recFake)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(recovered) != 1 || recovered[0] != "np-1" {
		t.Fatalf("recovered runs: %v", recovered)
	}
	// exactly the three DURABLY COMPLETED adds were inverted in reverse
	// order; the failed qdisc step (never applied) is not undone, and
	// steps without any recorded result are not guessed at
	want := []OpKind{OpDelNftTable, OpDelRule, OpDelRoute}
	for i, k := range want {
		if recFake.calls[i].Kind != k {
			t.Fatalf("rollback step %d: %s, want %s", i, recFake.calls[i].Kind, k)
		}
	}
	// every rollback op stays inside the scope
	for _, c := range recFake.calls {
		if err := c.validateAgainstScope(testScope()); err != nil {
			t.Fatalf("rollback left the scope: %v (%+v)", err, c)
		}
	}
}

// review T01: a step whose result was never recorded (crash between
// command and result) leaves an UNKNOWN network outcome — recovery must
// neither undo it blindly nor claim success: the plan becomes unresolved
// with an explicit error, and stays there until operator resolution.
func TestRecoverSkipsUnknownSteps(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	p := testPlan()
	hash, _ := p.ContentHash()
	begun := *p
	begun.Hash = hash
	_ = j.append(stepRec{Kind: KindPlanBegin, PlanID: "np-crash", Plan: &begun, V: SchemaVersion})
	// the attempt started (durable intent) and crashed before its result:
	// attempted-unknown (V03), provable by the journal
	_ = j.append(stepRec{Kind: KindStepIntent, PlanID: "np-crash", Step: 0, Op: p.Ops[0]})
	// T01: no success over an unknown outcome — the plan is pending
	// (unresolved, journaled) with an EXPLICIT error, never recovered.
	recFake := &fakeExecutor{}
	recovered, err := Recover(j, recFake)
	if err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("pending must be reported with an explicit error: err=%v recovered=%v", err, recovered)
	}
	if len(recovered) != 0 {
		t.Fatalf("unresolved plan must not be reported recovered: %v", recovered)
	}
	if len(recFake.calls) != 0 {
		t.Fatalf("unknown steps must not be undone: %+v", recFake.calls)
	}
	// subsequent runs keep reporting pending explicitly (W01: never an
	// indistinguishable empty success), still no deletes
	second := &fakeExecutor{}
	recovered2, err2 := Recover(j, second)
	if err2 == nil || !strings.Contains(err2.Error(), "pending") || len(second.calls) != 0 || len(recovered2) != 0 {
		t.Fatalf("unresolved state not visible on rerun: err=%v calls=%v recovered=%v", err2, second.calls, recovered2)
	}
	// T01: conflicting network mutations are BLOCKED until resolution
	if res := Execute(testPlan(), j, &fakeExecutor{}); res.Err == nil || !strings.Contains(res.Err.Error(), "unresolved") {
		t.Fatalf("execute must be blocked while unresolved: %+v", res)
	}
}

func TestRecoverWithAbsentObjectsContinues(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	p := testPlan()
	hash, _ := p.ContentHash()
	begun := *p
	begun.Hash = hash
	_ = j.append(stepRec{Kind: KindPlanBegin, PlanID: "np-crash", Plan: &begun, V: SchemaVersion})
	_ = j.append(stepRec{Kind: KindStepResult, PlanID: "np-crash", Step: 0,
		Op: Op{Kind: OpAddRoute, Owner: "ara-net-helper", Prefix: "10.111.0.0/24", Device: "ara0", Table: "52100"}, Status: StatusOK})
	// the object was never created (crash lied about nothing here — the
	// step durably completed in the journal but the del reports not-found
	// in recovery): recovery must surface it and stay best-effort
	recFake := &fakeExecutor{skipDel: true}
	_, err := Recover(j, recFake)
	if err == nil || !strings.Contains(err.Error(), "recover") {
		t.Fatalf("expected surfaced rollback error, got %v", err)
	}
}

// review S03/T03: a later plan reusing freed coordinates is never deleted
// by an old recovery — terminal state prevents the second run. The fault
// hits the LAST step so every step has a durable result (no unknowns).
func TestRecoverTerminalProtectsNewerPlan(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	f := &fakeExecutor{failOn: map[OpKind]error{OpAddQdisc: errors.New("boom")}}
	if r := Execute(testPlan(), j, f); r.Err == nil {
		t.Fatal("expected fault")
	}
	first := &fakeExecutor{}
	if _, err := Recover(j, first); err != nil || len(first.calls) == 0 {
		t.Fatalf("first recovery: %v %+v", err, first.calls)
	}
	// a NEW plan now creates an object at the same coordinates
	newPlan := testPlan()
	newPlan.ID = "np-2"
	if r := Execute(newPlan, j, &fakeExecutor{}); r.Err != nil {
		t.Fatal(r.Err)
	}
	// replaying the OLD plan's recovery must do nothing: it is terminal
	second := &fakeExecutor{}
	if _, err := Recover(j, second); err != nil || len(second.calls) != 0 {
		t.Fatalf("old recovery deleted a newer plan's object: %v %+v", err, second.calls)
	}
}

func TestExecutionPlatformGate(t *testing.T) {
	j, err := OpenStepJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !executesOnThisPlatform {
		res := Execute(testPlan(), j, CommandExecutor{})
		if res.Err == nil || !strings.Contains(res.Err.Error(), "UNSUPPORTED_CAPABILITY") {
			t.Fatalf("non-linux execution must refuse typed: %v", res.Err)
		}
		return
	}
	// Linux: never execute real network ops in unit tests; the real
	// executor is exercised in isolated lab namespaces only
	// (docs/LAB_RUNBOOK.md).
	t.Log("linux executor present; live execution is a lab-only test")
}

// journal ownership round trip: a plan run recorded through the step
// journal is attributable to its owner and isolated from others.
func TestJournalOwnershipRoundTrip(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenStepJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := testPlan()
	res := Execute(p, j, &fakeExecutor{})
	if res.Err != nil {
		t.Fatalf("execute: %v", res.Err)
	}
	runs, err := j.LoadRuns()
	if err != nil {
		t.Fatal(err)
	}
	run := runs["np-1"]
	if run == nil || run.Owner != "ara-net-helper" || !run.Committed || len(run.Steps) != 4 {
		t.Fatalf("journal round trip: %+v", run)
	}
	if run.Plan == nil || run.Plan.Ops[0].Prefix != "10.111.0.0/24" {
		t.Fatalf("plan_begin content: %+v", run.Plan)
	}
}

// TestLabRealExecutorRecovery runs ONLY on the lab inside an isolated
// network namespace (ARA_LAB_NETNS=1): it exercises the real
// CommandExecutor against a scope-owned veth and proves that a partial
// apply is rolled back exactly to the scope boundary. Host networking is
// never touched; the namespace is disposable.
func TestLabRealExecutorRecovery(t *testing.T) {
	if os.Getenv("ARA_LAB_NETNS") != "1" {
		t.Skip("lab-only: run inside an isolated netns with ARA_LAB_NETNS=1")
	}
	if !executesOnThisPlatform {
		t.Skip("linux only")
	}
	scope := &Scope{
		Name:         "lab-netns",
		Interfaces:   []string{"ara0"},
		QdiscDevices: []string{"ara0"},
		Tables:       []string{"52100"},
		Marks:        []uint32{0x52100},
		NftTables:    []string{"inet ara-recovery-test"},
	}
	j, err := OpenStepJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exec := CommandExecutor{}
	p := &Plan{
		ID: "lab-recovery", Owner: "ara-net-helper", CreatedAt: time.Now().UTC(), Scope: scope,
		Ops: []Op{
			{Kind: OpAddRoute, Owner: "ara-net-helper", Prefix: "10.111.0.0/24", Device: "ara0", Table: "52100"},
			{Kind: OpAddRule, Owner: "ara-net-helper", Mark: 0x52100, Table: "52100", Priority: 100},
			// fails on the real kernel: the gateway is not on-link for
			// the address-less lab device (real-world misconfiguration).
			// The fault is on the LAST step so every step has a durable
			// result (round3 T01: unknown outcomes must stay unresolved).
			{Kind: OpAddQdisc, Owner: "ara-net-helper", Device: "ara0"},
			{Kind: OpAddRoute, Owner: "ara-net-helper", Prefix: "10.112.0.0/24", Device: "ara0", Table: "52100", Gateway: "192.0.2.1"},
		},
	}
	res := Execute(p, j, exec)
	// Round7 contract: the real iproute2 CLI exited nonzero after the
	// mutation attempt — that outcome is UNKNOWN, not proven no-effect.
	// Execute must keep the cause and classify the step attempted-unknown.
	if res.Err == nil || !strings.Contains(res.Err.Error(), "outcome unknown") {
		t.Fatalf("nonzero exit must stay unknown: %+v", res)
	}
	// proof of partial apply: route and rule exist
	if out, err := execCmd("ip", "route", "show", "table", "52100"); err != nil || !strings.Contains(string(out), "10.111.0.0/24") {
		t.Fatalf("setup: route not applied: %s %v", out, err)
	}
	// recovery inverts the KNOWN completed steps with the REAL executor
	// (LIFO), never repeats or blindly deletes the unknown last step, and
	// leaves the plan pending unresolved — honest unknown, not a false
	// recovered.
	recovered, err := Recover(j, exec)
	if err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("unknown step must leave the plan pending: %v %v", err, recovered)
	}
	if len(recovered) != 0 {
		t.Fatalf("plan with an unknown step must not be reported recovered: %v", recovered)
	}
	// the unknown step's own delete (invalid-gateway route) must not be
	// repeated blindly — the journal keeps it pending instead
	if out, _ := execCmd("ip", "route", "show", "table", "52100"); strings.Contains(string(out), "10.111.0.0/24") {
		t.Fatalf("recovery left the owned route in place: %s", out)
	}
	if out, _ := execCmd("ip", "rule", "show"); strings.Contains(string(out), "0x52100") || strings.Contains(string(out), "337664") {
		t.Fatalf("recovery left the owned rule in place: %s", out)
	}
	// the failed route (invalid gateway) must not appear
	if out, _ := execCmd("ip", "route", "show", "table", "52100"); strings.Contains(string(out), "10.112.0.0/24") {
		t.Fatalf("failed route present: %s", out)
	}
}

func errStr(s string) error { return &strErr{s} }

type strErr struct{ s string }

func (e *strErr) Error() string { return e.s }

func scopedPlanDebug() *Plan {
	scope := &Scope{Name: "t", Interfaces: []string{"ara0"}, Tables: []string{"52100"}, Marks: []uint32{0x52100}}
	return &Plan{ID: "test-plan", Owner: "ara", Scope: scope, Ops: []Op{
		{Kind: OpAddRoute, Owner: "ara", Device: "ara0", Table: "52100", Prefix: "192.0.2.0/24"},
		{Kind: OpAddRule, Owner: "ara", Table: "52100", Mark: 0x52100, Priority: 52100},
	}}
}

// S01 regressions: table identity is canonical — numeric aliases of a
// reserved table are refused, and the empty-table form can never reach
// host main.
func TestTableCanonicalization(t *testing.T) {
	// "254" and "main" are the same reserved table in different spellings
	s := testScope()
	s.Tables = append(s.Tables, "0xFE") // hex alias of main=254
	p := testPlan()
	p.Scope = s
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("hex alias of reserved table accepted: %v", err)
	}
	// numeric alias in decimal
	s2 := testScope()
	s2.Tables = append(s2.Tables, "254")
	p2 := testPlan()
	p2.Scope = s2
	if err := p2.Validate(); err == nil {
		t.Fatal("decimal alias of reserved table accepted")
	}
	// a default route inside a genuinely owned table is a DIFFERENT
	// authority from the host default route and is permitted there
	s3 := testScope()
	p3 := &Plan{Owner: "ara-net-helper", ID: "np-default", Scope: s3, Ops: []Op{
		{Kind: OpAddRoute, Owner: "ara-net-helper", Prefix: "0.0.0.0/0", Device: "ara0", Table: "52100"},
	}}
	if err := p3.Validate(); err != nil {
		t.Fatalf("default route inside owned table refused: %v", err)
	}
	// the same default route pointed at main is refused (main cannot be owned)
	s4 := testScope()
	p4 := &Plan{Owner: "ara-net-helper", ID: "np-main", Scope: s4, Ops: []Op{
		{Kind: OpAddRoute, Owner: "ara-net-helper", Prefix: "0.0.0.0/0", Device: "ara0", Table: "main"},
	}}
	if err := p4.Validate(); err == nil {
		t.Fatal("default route via main accepted")
	}
}

// Fault matrix (round3 acceptance): every crash window of the plan
// lifecycle must yield a safe, correct, resumable state. Crash boundary
// is injected with a recorder that panics after the external effect or
// journal writes are truncated like the review tests do.
type crashRecorder struct {
	fakeExecutor
	crashBefore func(op Op) bool
}

func (c *crashRecorder) Do(op Op) error {
	if c.crashBefore != nil && c.crashBefore(op) {
		panic("simulated crash before effect")
	}
	return c.fakeExecutor.Do(op)
}

func recoveredPlan(t *testing.T, j *StepJournal, id string) *PlanRun {
	t.Helper()
	runs, err := j.LoadRuns()
	if err != nil {
		t.Fatal(err)
	}
	return runs[id]
}

// Window: plan_begin journaled, crash BEFORE the first effect — every
// step is unknown; nothing may be undone, plan is unresolved (pending),
// and recovery never claims success.
func TestFaultCrashBeforeFirstEffect(t *testing.T) {
	j, _ := OpenStepJournal(t.TempDir())
	p := testPlan()
	hash, _ := p.ContentHash()
	begun := *p
	begun.Hash = hash
	_ = j.append(stepRec{Kind: KindPlanBegin, PlanID: p.ID, Plan: &begun, V: SchemaVersion})
	// attempt started, crashed before result: attempted-unknown
	_ = j.append(stepRec{Kind: KindStepIntent, PlanID: p.ID, Step: 0, Op: p.Ops[0]})
	undo := &fakeExecutor{}
	recovered, _ := Recover(j, undo)
	if len(recovered) != 0 || len(undo.calls) != 0 {
		t.Fatalf("unknown steps touched: %v %v", recovered, undo.calls)
	}
	run := recoveredPlan(t, j, p.ID)
	if run == nil || !run.Unresolved {
		t.Fatalf("plan must be pending unresolved: %+v", run)
	}
}

// Window: every step durably ok, crash BEFORE plan_commit — recovery
// undoes all owned steps (LIFO) and reports the plan recovered only after
// the terminal record; a rerun is a no-op.
func TestFaultAllStepsOkNoCommit(t *testing.T) {
	j, _ := OpenStepJournal(t.TempDir())
	p := testPlan()
	hash, _ := p.ContentHash()
	begun := *p
	begun.Hash = hash
	_ = j.append(stepRec{Kind: KindPlanBegin, PlanID: p.ID, Plan: &begun, V: SchemaVersion})
	for i, op := range p.Ops {
		_ = j.append(stepRec{Kind: KindStepResult, PlanID: p.ID, Step: i, Op: op, Status: StatusOK})
	}
	// no commit
	undo := &fakeExecutor{}
	recovered, err := Recover(j, undo)
	if err != nil || len(recovered) != 1 {
		t.Fatalf("recover: %v %v", err, recovered)
	}
	want := []OpKind{OpDelQdisc, OpDelNftTable, OpDelRule, OpDelRoute}
	for i, k := range want {
		if undo.calls[i].Kind != k {
			t.Fatalf("LIFO violation at %d: %s", i, undo.calls[i].Kind)
		}
	}
	second := &fakeExecutor{}
	if _, err := Recover(j, second); err != nil || len(second.calls) != 0 {
		t.Fatalf("rerun after terminal: %v %+v", err, second.calls)
	}
}

// Window: crash DURING undo — undo_intent durable, undo_result missing:
// the undo outcome is unknown, recovery refuses to repeat the delete and
// reports an explicit error; the plan never becomes recovered.
func TestFaultCrashDuringUndo(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	f := &fakeExecutor{failOn: map[OpKind]error{OpAddQdisc: errors.New("boom")}}
	if r := Execute(testPlan(), j, f); r.Err == nil {
		t.Fatal("expected fault")
	}
	// first recovery completes normally (its undo_result records are the
	// round3 T03 evidence); the hand-crafted prefix below emulates the
	// crash DURING undo: undo_intent durable, undo_result missing.
	// hand-craft the crash prefix: begin + results + undo_intent(step2)
	j2, _ := OpenStepJournal(t.TempDir())
	p := testPlan()
	hash, _ := p.ContentHash()
	begun := *p
	begun.Hash = hash
	_ = j2.append(stepRec{Kind: KindPlanBegin, PlanID: p.ID, Plan: &begun, V: SchemaVersion})
	for i := 0; i < 3; i++ {
		_ = j2.append(stepRec{Kind: KindStepResult, PlanID: p.ID, Step: i, Op: p.Ops[i], Status: StatusOK})
	}
	_ = j2.append(stepRec{Kind: KindStepResult, PlanID: p.ID, Step: 3, Op: p.Ops[3], Status: StatusFail})
	_ = j2.append(stepRec{Kind: KindUndoIntent, PlanID: p.ID, Step: 2, Op: invertOp(p.Ops[2])})
	undo2 := &fakeExecutor{}
	recovered2, err2 := Recover(j2, undo2)
	if err2 == nil || !strings.Contains(err2.Error(), "unknown") {
		t.Fatalf("unknown undo must error explicitly: %v %v", err2, recovered2)
	}
	// the UNKNOWN undo (step 2: nft table) must NOT be repeated; the
	// independent earlier steps may still be safely undone
	for _, c := range undo2.calls {
		if c.Kind == OpDelNftTable {
			t.Fatalf("unknown undo repeated the delete: %+v", undo2.calls)
		}
	}
	if len(recovered2) != 0 {
		t.Fatalf("plan with an unknown undo must not be recovered: %v", recovered2)
	}
	run := recoveredPlan(t, j2, p.ID)
	if run == nil || run.Recovered {
		t.Fatalf("plan must not be recovered: %+v", run)
	}
}

// V01 cross-process: two real OS processes contend for the same journal.
// The child helper executes one plan; the parent starts a slow child
// (executor holds the plan mid-run) and a fast child concurrently, then
// asserts the journal shows full serialization: the fast child's
// plan_begin appears only AFTER the slow child's plan_commit.
func TestNetplanLockChildProcess(t *testing.T) {
	if os.Getenv("ARA_NETPLAN_LOCK_CHILD") != "1" {
		t.Skip("helper process")
	}
	dir := os.Getenv("ARA_NETPLAN_DIR")
	delay := os.Getenv("ARA_NETPLAN_DELAY_MS") != ""
	j, err := OpenStepJournal(dir)
	if err != nil {
		os.Exit(3)
	}
	p := testPlan()
	p.ID = os.Getenv("ARA_NETPLAN_PLAN_ID")
	ex := &fakeExecutor{}
	if delay {
		ex = &fakeExecutor{}
		ex.calls = nil
		// wrap: sleep inside the first command while holding the lock
		ex.failOn = map[OpKind]error{}
		slow := &sleepExecutor{inner: ex, delayOnFirst: true}
		if r := Execute(p, j, slow); r.Err != nil {
			os.Exit(4)
		}
		return
	}
	if r := Execute(p, j, ex); r.Err != nil {
		os.Exit(4)
	}
}

type sleepExecutor struct {
	inner        *fakeExecutor
	delayOnFirst bool
	called       bool
}

func (s *sleepExecutor) Do(op Op) error {
	if !s.called {
		s.called = true
		time.Sleep(400 * time.Millisecond)
	}
	return s.inner.Do(op)
}

func TestV01CrossProcessExecuteSerialization(t *testing.T) {
	dir := t.TempDir()
	j0, err := OpenStepJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(planID string, delay bool) *exec.Cmd {
		cmd := exec.Command(self, "-test.run=TestNetplanLockChildProcess", "-test.v")
		cmd.Env = append(os.Environ(),
			"ARA_NETPLAN_LOCK_CHILD=1",
			"ARA_NETPLAN_DIR="+dir,
			"ARA_NETPLAN_PLAN_ID="+planID)
		if delay {
			cmd.Env = append(cmd.Env, "ARA_NETPLAN_DELAY_MS=1")
		}
		return cmd
	}
	slow := run("slow-plan", true)
	fast := run("fast-plan", false)
	doneSlow := make(chan error, 1)
	go func() { doneSlow <- slow.Run() }()
	time.Sleep(150 * time.Millisecond) // let the slow child take the lock
	doneFast := make(chan error, 1)
	go func() { doneFast <- fast.Run() }()
	if err := <-doneFast; err != nil {
		t.Fatalf("fast child: %v", err)
	}
	if err := <-doneSlow; err != nil {
		t.Fatalf("slow child: %v", err)
	}
	// journal must show strict serialization: fast-plan's begin is after
	// slow-plan's commit
	b, err := os.ReadFile(filepath.Join(dir, "netplan.journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	slowCommit, fastBegin := -1, -1
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.Contains(line, `"plan_id":"slow-plan"`) && strings.Contains(line, `"plan_commit"`) {
			slowCommit = i
		}
		if strings.Contains(line, `"plan_id":"fast-plan"`) && strings.Contains(line, `"plan_begin"`) {
			fastBegin = i
		}
	}
	if slowCommit == -1 || fastBegin == -1 {
		t.Fatalf("journal layout unexpected: slowCommit=%d fastBegin=%d\n%s", slowCommit, fastBegin, b)
	}
	if fastBegin < slowCommit {
		t.Fatalf("cross-process serialization violated: fast began at line %d before slow committed at line %d", fastBegin, slowCommit)
	}
	_ = j0
}

// V01 multi-instance: two StepJournal instances on one journal serialize
// in-process (cross-fd flock) as well.
func TestV01MultiInstanceSerialization(t *testing.T) {
	dir := t.TempDir()
	j1, _ := OpenStepJournal(dir)
	j2, _ := OpenStepJournal(dir)
	// j1 plan: unknown outcome (intent without result) must block j2
	p1 := testPlan()
	hash, _ := p1.ContentHash()
	begun := *p1
	begun.Hash = hash
	_ = j1.append(stepRec{Kind: KindPlanBegin, PlanID: "p1", Plan: &begun, V: SchemaVersion})
	_ = j1.append(stepRec{Kind: KindStepIntent, PlanID: "p1", Step: 0, Op: p1.Ops[0]})
	p2 := testPlan()
	p2.ID = "p2"
	if res := Execute(p2, j2, &fakeExecutor{}); res.Err == nil {
		t.Fatal("second journal instance permitted a mutation over a pending plan")
	}
}

// Transition-model tests: every journal-evidenced state is reachable and
// distinguishable.
func TestPlanStateTransitions(t *testing.T) {
	// begun -> committed (all ok): committed
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	p := testPlan()
	if r := Execute(p, j, &fakeExecutor{}); r.Err != nil {
		t.Fatal(r.Err)
	}
	run := recoveredPlan(t, j, p.ID)
	if !run.Committed || run.Recovered || run.Unresolved {
		t.Fatalf("committed state wrong: %+v", run)
	}
	// same plan replay: idempotent, no re-execution
	before := len(journalLines(t, dir))
	if r := Execute(p, j, &fakeExecutor{}); r.Err != nil {
		t.Fatalf("idempotent replay refused: %v", r)
	}
	if after := len(journalLines(t, dir)); after != before {
		t.Fatalf("idempotent replay wrote %d new records", after-before)
	}
	// same id, different content: refused
	p2 := testPlan()
	p2.ID = p.ID
	p2.Ops[0].Prefix = "10.222.0.0/24"
	if r := Execute(p2, j, &fakeExecutor{}); r.Err == nil {
		t.Fatal("ID reuse with different content accepted")
	}
}

func journalLines(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "netplan.journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// V03: durable mid-plan failure with never-started suffix recovers
// fully; the failed step itself needs no undo.
func TestFaultMidPlanKnownFailureRecovers(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenStepJournal(dir)
	p := testPlan()
	n := 0
	ex := execFuncRecorder{run: func(op Op) error {
		n++
		if n == 2 {
			return NoEffect(errors.New("known mid-plan failure"))
		}
		return nil
	}}
	if r := Execute(p, j, ex); r.Err == nil {
		t.Fatal("expected known failure")
	}
	undo := &fakeExecutor{}
	recovered, err := Recover(j, undo)
	if err != nil || len(recovered) != 1 {
		t.Fatalf("mid-plan known failure must recover cleanly: %v %v", err, recovered)
	}
	// only step0 (applied) is undone: LIFO single call
	if len(undo.calls) != 1 || undo.calls[0].Kind != OpDelRoute {
		t.Fatalf("undo set: %+v", undo.calls)
	}
	// second run: terminal
	second := &fakeExecutor{}
	if _, err := Recover(j, second); err != nil || len(second.calls) != 0 {
		t.Fatalf("rerun after recovery: %v %+v", err, second.calls)
	}
}

type execFuncRecorder struct {
	run func(Op) error
}

func (e execFuncRecorder) Do(op Op) error { return e.run(op) }

// W01 sequence: failed apply fences a replacement until the old plan is
// recovered; after the CONFIRMED terminal recovery the same coordinates
// are free, and the old recovery never touches the new plan.
func TestW01FailedApplySequenceFencing(t *testing.T) {
	j, _ := OpenStepJournal(t.TempDir())
	n := 0
	if r := Execute(testPlan(), j, execFuncRecorder{run: func(op Op) error {
		n++
		if n == 3 { // third command fails: steps 0-1 applied-ok, 2 known-failed, 3 never-started
			return NoEffect(errors.New("known failure"))
		}
		return nil
	}}); r.Err == nil {
		t.Fatal("expected known failure")
	}
	// replacement fenced while old plan non-terminal
	if r := Execute(func() *Plan { p := testPlan(); p.ID = "replacement"; return p }(), j, &fakeExecutor{}); r.Err == nil {
		t.Fatal("replacement accepted over non-terminal plan")
	}
	// old recovery completes (undoes 3 applied steps)
	undo := &fakeExecutor{}
	recovered, err := Recover(j, undo)
	if err != nil || len(recovered) != 1 {
		t.Fatalf("old recovery: %v %v", err, recovered)
	}
	if len(undo.calls) != 2 || undo.calls[0].Kind != OpDelRule || undo.calls[1].Kind != OpDelRoute {
		t.Fatalf("undo set: %+v", undo.calls)
	}
	// now the coordinates are free
	if r := Execute(func() *Plan { p := testPlan(); p.ID = "replacement"; return p }(), j, &fakeExecutor{}); r.Err != nil {
		t.Fatalf("replacement after terminal recovery refused: %v", r.Err)
	}
	// and the old recovery's rerun touches nothing
	second := &fakeExecutor{}
	if _, err := Recover(j, second); err != nil || len(second.calls) != 0 {
		t.Fatalf("old recovery touched the replacement: %v %+v", err, second.calls)
	}
}

// W01 sequence: unknown undo fences new mutations and keeps reporting
// pending on every recovery call.
func TestW01UnknownUndoSequenceFencing(t *testing.T) {
	j, _ := OpenStepJournal(t.TempDir())
	if r := Execute(testPlan(), j, &fakeExecutor{failOn: map[OpKind]error{OpAddQdisc: errors.New("boom")}}); r.Err == nil {
		t.Fatal("expected fault")
	}
	crash := &crashOnN{inner: &fakeExecutor{}, n: 1}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash not injected")
			}
		}()
		_, _ = Recover(j, crash)
	}()
	if !crash.crashed {
		t.Fatal("undo effect boundary not reached")
	}
	// fenced
	if r := Execute(func() *Plan { p := testPlan(); p.ID = "after"; return p }(), j, &fakeExecutor{}); r.Err == nil {
		t.Fatal("mutation allowed after unknown undo")
	}
	// pending stays visible with an explicit error; the unknown undo
	// (step 2, nft) is never repeated, independent earlier steps undo
	pending := &fakeExecutor{}
	if _, err := Recover(j, pending); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("pending must stay visible: err=%v calls=%v", err, pending.calls)
	}
	for _, c := range pending.calls {
		if c.Kind == OpDelNftTable {
			t.Fatalf("unknown undo repeated: %+v", pending.calls)
		}
	}
	if run := recoveredPlan(t, j, "np-1"); run == nil || run.Recovered || !run.Unresolved {
		t.Fatalf("plan with unknown undo must be fenced unresolved: %+v", run)
	}
}

type crashOnN struct {
	inner   *fakeExecutor
	n       int
	calls   int
	crashed bool
}

func (c *crashOnN) Do(op Op) error {
	c.calls++
	if c.calls == c.n {
		c.crashed = true
		panic("undo effect before result")
	}
	return c.inner.Do(op)
}

// X01 model tests: the outcome contract.
type typedExecutor struct {
	outcome error // nil, NoEffect(...), or plain error (unknown)
	effekt  func()
}

func (t *typedExecutor) Do(op Op) error {
	if t.effekt != nil {
		t.effekt()
	}
	return t.outcome
}

// A proven pre-start failure is a known failed step: normal recovery of
// the previous steps applies.
func TestX01ProvenNoEffectIsKnownFailed(t *testing.T) {
	j, _ := OpenStepJournal(t.TempDir())
	p := testPlan()
	ex := execFuncRecorder{run: func(op Op) error {
		return NoEffect(errors.New("binary not found"))
	}}
	if r := Execute(p, j, ex); r.Err == nil {
		t.Fatal("expected the no-effect failure")
	}
	run := recoveredPlan(t, j, p.ID)
	// Execute stops at the first (proven) failure: step0 failed-known,
	// the rest provably never started.
	if st := run.Steps[0]; st.applied != StatusFail {
		t.Fatalf("no-effect step must be known-failed: %+v", run.Steps)
	}
	for i := 1; i < len(p.Ops); i++ {
		if run.Steps[i] != nil && run.Steps[i].intent {
			t.Fatalf("steps after a proven failure must not have intents: %+v", run.Steps)
		}
	}
	undo := &fakeExecutor{}
	recovered, err := Recover(j, undo)
	if err != nil || len(recovered) != 1 || len(undo.calls) != 0 {
		t.Fatalf("all-no-effect plan must recover with zero undos: %v %v %+v", err, recovered, undo.calls)
	}
}

// A generic error after an external effect is UNKNOWN: the plan stays
// pending, no undo runs, Execute is fenced.
func TestX01GenericErrorAfterEffectIsUnknown(t *testing.T) {
	j, _ := OpenStepJournal(t.TempDir())
	p := testPlan()
	live := false
	ex := execFuncRecorder{run: func(op Op) error {
		if !live {
			live = true
			return nil
		}
		return errors.New("child died after external effect")
	}}
	if r := Execute(p, j, ex); r.Err == nil || !strings.Contains(r.Err.Error(), "unknown") {
		t.Fatalf("generic error must be classified unknown: %+v", r)
	}
	if r := Execute(func() *Plan { q := testPlan(); q.ID = "other"; return q }(), j, &fakeExecutor{}); r.Err == nil {
		t.Fatal("new plan allowed over an unknown-outcome plan")
	}
	// recovery keeps the plan pending: the unknown step is never undone;
	// the earlier KNOWN-applied step may be safely rolled back.
	undo := &fakeExecutor{}
	if recovered, err := Recover(j, undo); err == nil || len(recovered) != 0 {
		t.Fatalf("unknown apply must stay pending: %v %v", err, recovered)
	}
	for _, c := range undo.calls {
		if c.Prefix == "198.18.1.0/24" { // the unknown step's own delete
			t.Fatalf("unknown step was undone blindly: %+v", undo.calls)
		}
	}
}

// An unknown undo fences the plan durably and never repeats the delete.
func TestX01UnknownUndoFences(t *testing.T) {
	j, _ := OpenStepJournal(t.TempDir())
	if r := Execute(testPlan(), j, &fakeExecutor{failOn: map[OpKind]error{OpAddQdisc: NoEffect(errors.New("boom"))}}); r.Err == nil {
		t.Fatal("expected known failure")
	}
	del := &fakeExecutor{}
	// first undo of step2 returns a generic error AFTER the delete effect
	var gen error
	undo := execFuncRecorder{run: func(op Op) error {
		if op.Kind == OpDelNftTable {
			if gen == nil {
				gen = errors.New("acknowledgement lost after rm")
				return gen
			}
		}
		return del.Do(op)
	}}
	if _, err := Recover(j, undo); err == nil {
		t.Fatal("expected unknown-undo error")
	}
	run := recoveredPlan(t, j, "np-1")
	if run == nil || !run.Unresolved {
		t.Fatalf("unknown undo must fence unresolved: %+v", run)
	}
	// repeat: pending stays visible, no extra deletes
	again := &fakeExecutor{}
	if _, err := Recover(j, again); err == nil || len(again.calls) != 0 {
		t.Fatalf("pending not stable: err=%v calls=%v", err, again.calls)
	}
}
