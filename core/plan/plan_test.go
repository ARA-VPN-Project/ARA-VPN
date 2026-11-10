package plan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fakeExecutor struct {
	kind           string
	checkErr       error
	applyErr       error
	applied        []string
	revision       int64
	failFirstApply bool
}

func (f *fakeExecutor) Kind() string { return f.kind }
func (f *fakeExecutor) Check(p *Plan, now time.Time) error {
	if p.Preconditions["policy.revision"] != "7" {
		return errStr("policy.revision moved")
	}
	return f.checkErr
}
func (f *fakeExecutor) Apply(p *Plan, now time.Time) (Result, error) {
	if f.failFirstApply && len(f.applied) == 0 {
		f.applied = append(f.applied, p.ID)
		return Result{}, errStr("crash mid-apply")
	}
	f.applied = append(f.applied, p.ID)
	f.revision++
	return Result{Applied: true, NewRevision: f.revision, Summary: map[string]string{"rules": "3"}}, nil
}

type errStr string

func (e errStr) Error() string { return string(e) }

func newPlan(kind string, ttl time.Duration) *Plan {
	return &Plan{
		ID:             "pl-test-1",
		Kind:           kind,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(ttl),
		Preconditions:  map[string]string{"policy.revision": "7", "port.tcp.8443": "free"},
		Changes:        json.RawMessage(`{"rules":3}`),
		IdempotencyKey: "idem-1",
	}
}

func TestHashStableAndSensitive(t *testing.T) {
	p := newPlan("policy", time.Minute)
	h1, err := p.Hash()
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := p.Hash()
	if h1 != h2 {
		t.Fatal("hash unstable")
	}
	p.Changes = json.RawMessage(`{"rules":4}`)
	h3, _ := p.Hash()
	if h1 == h3 {
		t.Fatal("hash ignored changes")
	}
	if strings.ContainsAny(h1, "ghijklmnopqrstuvwxyz") == false && len(h1) != 64 {
		t.Fatalf("hash not sha256 hex: %q", h1)
	}
}

func TestApplyFullDiscipline(t *testing.T) {
	dir := t.TempDir()
	reg, err := NewRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{kind: "policy"}
	reg.Register(exec)

	p := newPlan("policy", time.Minute)
	if _, err := reg.Stage(p); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(p); err != nil {
		t.Fatal(err)
	}
	hash, _ := p.Hash()

	// tampered hash refused
	if _, err := reg.Apply(p.ID, "deadbeef", time.Now()); err == nil || !strings.Contains(err.Error(), "VERIFICATION_FAILED") {
		t.Fatalf("tampered hash accepted: %v", err)
	}
	// unknown plan refused
	if _, err := reg.Apply("pl-missing", hash, time.Now()); err == nil {
		t.Fatal("unknown plan applied")
	}
	// happy path
	res, err := reg.Apply(p.ID, hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.NewRevision != 1 {
		t.Fatalf("result: %+v", res)
	}
	// replay with the same key returns the recorded result, no re-apply
	res2, err := reg.Apply(p.ID, hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewRevision != 1 || len(exec.applied) != 1 {
		t.Fatalf("idempotency broken: applied %v", exec.applied)
	}
}

func TestApplyExpired(t *testing.T) {
	dir := t.TempDir()
	reg, _ := NewRegistry(dir)
	reg.Register(&fakeExecutor{kind: "policy"})
	p := newPlan("policy", -time.Minute) // already expired
	if _, err := reg.Stage(p); err != nil {
		t.Fatal(err)
	}
	reg.Save(p)
	hash, _ := p.Hash()
	if _, err := reg.Apply(p.ID, hash, time.Now()); err == nil || !strings.Contains(err.Error(), "PLAN_EXPIRED") {
		t.Fatalf("expired plan applied: %v", err)
	}
}

func TestApplyPreconditionFailure(t *testing.T) {
	dir := t.TempDir()
	reg, _ := NewRegistry(dir)
	exec := &fakeExecutor{kind: "policy", checkErr: errStr("port took over")}
	reg.Register(exec)
	p := newPlan("policy", time.Minute)
	p.Preconditions["policy.revision"] = "8" // drifted
	reg.Stage(p)
	reg.Save(p)
	hash, _ := p.Hash()
	if _, err := reg.Apply(p.ID, hash, time.Now()); err == nil || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("precondition breach applied: %v", err)
	}
	if len(exec.applied) != 0 {
		t.Fatal("executor ran despite failed precondition")
	}
}

func TestApplyCrashMidwayThenIdempotentRetry(t *testing.T) {
	dir := t.TempDir()
	reg, _ := NewRegistry(dir)
	exec := &fakeExecutor{kind: "policy", failFirstApply: true}
	reg.Register(exec)
	p := newPlan("policy", time.Minute)
	reg.Stage(p)
	reg.Save(p)
	hash, _ := p.Hash()
	if _, err := reg.Apply(p.ID, hash, time.Now()); err == nil {
		t.Fatal("expected mid-apply failure")
	}
	// retry after the crash must succeed exactly once
	res, err := reg.Apply(p.ID, hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatalf("retry: %+v", res)
	}
	if len(exec.applied) != 2 { // failed attempt + successful retry
		t.Fatalf("apply count: %v", exec.applied)
	}
}

func TestStageUnknownKindRefused(t *testing.T) {
	reg, _ := NewRegistry(t.TempDir())
	if _, err := reg.Stage(newPlan("teleport", time.Minute)); err == nil {
		t.Fatal("unknown kind staged")
	}
}
