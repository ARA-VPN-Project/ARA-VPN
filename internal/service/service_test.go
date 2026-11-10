// Contract tests for the service layer: the same plan/apply discipline the
// CLI exposes, exercised through the typed API (acceptance T02/T03 partial,
// plan hash/expiry/CAS behavior end to end).
package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aravpn/core/health"
	"aravpn/core/limits"
	"aravpn/core/policy"
	"aravpn/core/routing"
)

func osWriteFile(path string, b []byte, mode os.FileMode) error {
	return os.WriteFile(path, b, mode)
}

var _ = routing.RoleRU

func newTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := New(StateDir{Root: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func candPolicy() *policy.Policy {
	return &policy.Policy{
		SchemaVersion:   1,
		AllowRUFallback: true,
		Rules: []policy.Rule{
			{ID: "r1", Enabled: true, DomainExact: []string{"Local.Example."}, Action: policy.ActionRUExit},
		},
	}
}

func TestPolicyValidateNormalizesAndApplies(t *testing.T) {
	svc := newTestService(t)
	p := candPolicy()
	if err := svc.PolicyValidate(p); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p.Rules[0].DomainExact[0] != "local.example" {
		t.Fatalf("normalization did not reach the stored candidate: %v", p.Rules[0].DomainExact)
	}

	planDoc, hash, err := svc.PolicyPlan(candPolicy(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if planDoc.Preconditions["policy.revision"] != "0" {
		t.Fatalf("precondition: %v", planDoc.Preconditions)
	}
	res, err := svc.PolicyApply(planDoc.ID, hash)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.Applied || res.NewRevision != 1 {
		t.Fatalf("result: %+v", res)
	}
	// applied policy on disk is normalized
	cur, _ := svc.PolicyGet()
	if cur.Rules[0].DomainExact[0] != "local.example" {
		t.Fatalf("stored policy not normalized: %+v", cur.Rules[0])
	}
	// idempotent retry returns the same recorded revision
	res2, err := svc.PolicyApply(planDoc.ID, hash)
	if err != nil || res2.NewRevision != 1 {
		t.Fatalf("idempotent retry: %+v %v", res2, err)
	}
}

func TestPolicyCASRejectsDriftedRevision(t *testing.T) {
	svc := newTestService(t)
	// first change: rev 0 -> 1
	p1, h1, _ := svc.PolicyPlan(candPolicy(), time.Now().UTC())
	if _, err := svc.PolicyApply(p1.ID, h1); err != nil {
		t.Fatal(err)
	}
	// a plan staged before the first apply is now stale
	p2, h2, _ := svc.PolicyPlan(candPolicy(), time.Now().UTC().Add(-time.Minute))
	// apply p1 again? no: apply p2 must check revision 0 vs current 1
	// p2 was staged at revision... staged BEFORE p1 applied? It was staged
	// after (see order): force drift by staging, then applying another.
	p3, h3, _ := svc.PolicyPlan(candPolicy(), time.Now().UTC())
	if _, err := svc.PolicyApply(p3.ID, h3); err != nil {
		t.Fatalf("p3 on rev1: %v", err)
	}
	// p2 still expects revision 0 -> conflict
	if _, err := svc.PolicyApply(p2.ID, h2); err == nil || !strings.Contains(err.Error(), "revision moved") {
		t.Fatalf("stale plan applied: %v", err)
	}
}

func TestPolicyPlanExpiredRefused(t *testing.T) {
	svc := newTestService(t)
	past := time.Now().UTC().Add(-2 * plan_TTL)
	// build directly with an already-expired TTL by backdating CreatedAt
	p, hash, err := svc.PolicyPlan(candPolicy(), past)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PolicyApply(p.ID, hash); err == nil || !strings.Contains(err.Error(), "PLAN_EXPIRED") {
		t.Fatalf("expired plan applied: %v", err)
	}
}

const plan_TTL = 20 * time.Minute // > DefaultTTL so a backdated plan is expired

func TestInvalidPolicyNeverTouchesState(t *testing.T) {
	svc := newTestService(t)
	bad := candPolicy()
	bad.Rules[0].Action = "NOT_AN_ACTION"
	if _, _, err := svc.PolicyPlan(bad, time.Now().UTC()); err == nil {
		t.Fatal("invalid candidate staged")
	}
	cur, err := svc.PolicyGet()
	if err != nil || cur.Revision != 0 || len(cur.Rules) != 0 {
		t.Fatalf("state changed by rejected candidate: %+v %v", cur, err)
	}
}

func TestLimitsPlanApplyAndUsage(t *testing.T) {
	svc := newTestService(t)
	two := int64(2000)
	cfg := &LimitsConfig{
		SchemaVersion: 1,
		AccountID:     "a1",
		DeviceID:      "d1",
		Device:        DeviceLimits{TotalBytes: &two},
		Period:        limits.DefaultPeriod(),
	}
	p, hash, err := svc.LimitsPlan(cfg, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LimitsApply(p.ID, hash); err != nil {
		t.Fatalf("limits apply: %v", err)
	}
	view, err := svc.LimitsShow()
	if err != nil {
		t.Fatal(err)
	}
	if view.DeviceTotal == nil || *view.DeviceTotal != 2000 {
		t.Fatalf("device total: %+v", view)
	}
	if view.Remaining == nil || *view.Remaining != 2000 {
		t.Fatalf("remaining: %+v", view)
	}
	// quota state feeds routing: charge the full quota via the journal
	jr, err := limits.OpenFileJournal(svc.State.LimitsDir())
	if err != nil {
		t.Fatal(err)
	}
	q, err := limits.NewQuotaTracker(limits.ScopeID{AccountID: "a1", DeviceID: "d1"},
		limits.QuotaConfig{TotalBytes: &two, Period: limits.DefaultPeriod()}, jr, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.Reserve(2000, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	st, err := svc.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.QuotaExhausted {
		t.Fatalf("status must report quota exhaustion: %+v", st)
	}
}

func TestStatusHonestOnUnknownHealth(t *testing.T) {
	svc := newTestService(t)
	st, err := svc.Status()
	if err != nil {
		t.Fatal(err)
	}
	// fresh install: nothing probed, topology minimal RU-only. Status must
	// not claim a working exit.
	if st.Mode != "offline" && st.Mode != "blocked" {
		t.Fatalf("fresh status mode %q must not imply a working VPN", st.Mode)
	}
	for _, n := range st.Topology {
		if n.Health != "unknown" {
			t.Fatalf("fresh health must be unknown: %+v", n)
		}
	}
}

func TestTopologyValidation(t *testing.T) {
	svc := newTestService(t)
	bad := Topology{SchemaVersion: 1, Exits: []routing.Exit{}} // no RU exit
	b, _ := json.Marshal(bad)
	if err := osWrite(svc.State.TopoPath(), b); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LoadTopology(); err == nil {
		t.Fatal("topology without RU exit accepted")
	}
}

func osWrite(path string, b []byte) error {
	return osWriteFile(path, b, 0o600)
}

// R10 regression: a fresh snapshot envelope must not make an old node
// observation eligible for new flows.
func TestSnapshotHonoursIndividualObservationAge(t *testing.T) {
	svc := newTestService(t)
	now := time.Now()
	b, _ := json.Marshal(map[string]any{
		"updated_at": now,
		"nodes": map[string]map[string]any{
			"nl": {"state": "healthy", "last_change": now.Add(-time.Hour), "last_observation": now.Add(-time.Hour)},
			"ru": {"state": "healthy", "last_change": now, "last_observation": now},
		},
	})
	if err := osWriteFile(svc.State.HealthPath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	hs, err := svc.LoadHealthSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if hs["nl"] == health.Healthy {
		t.Fatal("fresh envelope made an hour-old node observation healthy")
	}
	if hs["ru"] != health.Healthy {
		t.Fatalf("fresh observation degraded: %v", hs["ru"])
	}
	// future timestamps are treated as unknown, never eligible
	b, _ = json.Marshal(map[string]any{
		"updated_at": now,
		"nodes": map[string]map[string]any{
			"nl": {"state": "healthy", "last_observation": now.Add(time.Hour)},
		},
	})
	osWriteFile(svc.State.HealthPath(), b, 0o600)
	hs, _ = svc.LoadHealthSnapshot()
	if hs["nl"] != health.Unknown {
		t.Fatalf("future observation accepted: %v", hs["nl"])
	}
	// down survives per-node expiry (safe direction)
	b, _ = json.Marshal(map[string]any{
		"updated_at": now,
		"nodes": map[string]map[string]any{
			"nl": {"state": "down", "last_observation": now.Add(-time.Hour)},
		},
	})
	osWriteFile(svc.State.HealthPath(), b, 0o600)
	hs, _ = svc.LoadHealthSnapshot()
	if hs["nl"] != health.Down {
		t.Fatalf("down state must not be resurrected by load: %v", hs["nl"])
	}
}
