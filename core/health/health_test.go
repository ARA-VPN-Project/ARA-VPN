package health

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func newTracker(t *testing.T) *Tracker {
	t.Helper()
	tr, err := NewTracker(DefaultConfig(), t0)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestThreeFailuresThenDown(t *testing.T) {
	tr := newTracker(t)
	tr.RecordSuccess(t0.Add(1 * time.Second))
	if got := tr.Effective(t0.Add(1 * time.Second)).State; got != Healthy {
		t.Fatalf("after first success: %s", got)
	}
	tr.RecordFailure(t0.Add(6*time.Second), FailTimeout, "")
	if got := tr.Effective(t0.Add(6 * time.Second)).State; got != Suspect {
		t.Fatalf("1 failure: %s, want suspect", got)
	}
	tr.RecordFailure(t0.Add(11*time.Second), FailTimeout, "")
	if got := tr.Effective(t0.Add(11 * time.Second)).State; got != Suspect {
		t.Fatalf("2 failures: %s, want suspect", got)
	}
	tr.RecordFailure(t0.Add(16*time.Second), FailTimeout, "")
	if got := tr.Effective(t0.Add(16 * time.Second)).State; got != Down {
		t.Fatalf("3 failures: %s, want down", got)
	}
	// one success does not bring a down node back
	tr.RecordSuccess(t0.Add(21 * time.Second))
	if got := tr.Effective(t0.Add(21 * time.Second)).State; got != Down {
		t.Fatalf("down + 1 success: %s, want still down", got)
	}
}

func TestRecoveryRequiresTwoSuccessesAndStabilityWindow(t *testing.T) {
	tr := newTracker(t)
	tr.RecordSuccess(t0)
	for i := 1; i <= 3; i++ {
		tr.RecordFailure(t0.Add(time.Duration(i)*5*time.Second), FailTimeout, "")
	}
	base := t0.Add(16 * time.Second)
	if got := tr.Effective(base).State; got != Down {
		t.Fatalf("setup: %s, want down", got)
	}
	tr.RecordSuccess(base.Add(5 * time.Second))
	tr.RecordSuccess(base.Add(10 * time.Second))
	recAt := base.Add(10 * time.Second)
	if got := tr.Effective(recAt).State; got != Recovering {
		t.Fatalf("after 2 successes: %s, want recovering", got)
	}
	// stability window not yet elapsed: not eligible for new flows
	if tr.Effective(recAt).State.EligibleForNewFlow() {
		t.Fatal("recovering node selected for new flows before stability window")
	}
	// a failure during the window resets progress
	tr.RecordFailure(recAt.Add(5*time.Second), FailTimeout, "")
	if got := tr.Effective(recAt.Add(5 * time.Second)).State; got != Suspect {
		t.Fatalf("failure during recovery: %s, want suspect", got)
	}
	// R09: after a failure inside the window, one success returns the
	// node to recovering with a FRESH window, never straight to healthy
	tr.RecordSuccess(recAt.Add(10 * time.Second))
	if got := tr.Effective(recAt.Add(10 * time.Second)).State; got != Recovering {
		t.Fatalf("suspect + 1 success after broken recovery: %s, want recovering (fresh window)", got)
	}
	// probes continue every 5 s through the fresh window (started at
	// recAt+10s); check 25s into it BEFORE the 30s probe would promote
	for d := 15; d <= 35; d += 5 {
		tr.RecordSuccess(recAt.Add(time.Duration(d) * time.Second))
	}
	if got := tr.Effective(recAt.Add(35 * time.Second)).State; got != Recovering {
		t.Fatalf("fresh stability window not enforced: %s at 25s into window, want recovering", got)
	}
	// the 30th second of the window legitimately promotes to healthy
	tr.RecordSuccess(recAt.Add(40 * time.Second))
	if got := tr.Effective(recAt.Add(40 * time.Second)).State; got != Healthy {
		t.Fatalf("window completed without promotion: %s", got)
	}
	// a failure AFTER the completed window is ordinary hysteresis:
	// healthy node -> suspect -> one success -> healthy
	tr.RecordFailure(recAt.Add(46*time.Second), FailTimeout, "")
	if got := tr.Effective(recAt.Add(46 * time.Second)).State; got != Suspect {
		t.Fatalf("post-window failure: %s, want suspect", got)
	}
	tr.RecordSuccess(recAt.Add(47 * time.Second))
	if got := tr.Effective(recAt.Add(47 * time.Second)).State; got != Healthy {
		t.Fatalf("post-window single failure + success: %s, want healthy", got)
	}
	// full down path again, then clean recovery
	for i := 1; i <= 3; i++ {
		tr.RecordFailure(recAt.Add(time.Duration(50+i*5)*time.Second), FailTimeout, "")
	}
	down2 := recAt.Add(65 * time.Second)
	if got := tr.Effective(down2).State; got != Down {
		t.Fatalf("second down: %s, want down", got)
	}
	tr.RecordSuccess(down2.Add(5 * time.Second))
	tr.RecordSuccess(down2.Add(10 * time.Second))
	rec2 := down2.Add(10 * time.Second)
	if got := tr.Effective(rec2).State; got != Recovering {
		t.Fatalf("second recovery: %s, want recovering", got)
	}
	if tr.Effective(rec2).State.EligibleForNewFlow() {
		t.Fatal("recovering node eligible before stability window elapsed")
	}
	// probes continue every 5 s through the stability window
	for d := 5; d <= 25; d += 5 {
		tr.RecordSuccess(rec2.Add(time.Duration(d) * time.Second))
	}
	if got := tr.Effective(rec2.Add(25 * time.Second)).State; got != Recovering {
		t.Fatalf("at 25s of window: %s, want still recovering", got)
	}
	tr.RecordSuccess(rec2.Add(30 * time.Second))
	healthyAt := rec2.Add(31 * time.Second)
	if got := tr.Effective(healthyAt).State; got != Healthy {
		t.Fatalf("after stability window: %s, want healthy", got)
	}
	if !tr.Effective(healthyAt).State.EligibleForNewFlow() {
		t.Fatal("healthy node not eligible")
	}
}

func TestObservationExpiryToUnknown(t *testing.T) {
	tr := newTracker(t)
	tr.RecordSuccess(t0)
	stale := t0.Add(DefaultConfig().MaxObservationAge + time.Second)
	if got := tr.Effective(stale).State; got != Unknown {
		t.Fatalf("stale healthy: %s, want unknown", got)
	}
	// expiry must not resurrect a quarantined node
	tr.RecordFailure(t0.Add(1*time.Second), FailAuth, "device credential rejected")
	q := t0.Add(2 * time.Second)
	if got := tr.Effective(q).State; got != Quarantined {
		t.Fatalf("auth failure: %s, want quarantined", got)
	}
	if got := tr.Effective(stale.Add(time.Hour)).State; got != Quarantined {
		t.Fatalf("quarantine expired by age: %s, want quarantined", got)
	}
	if got := tr.Effective(stale.Add(time.Hour)).State.EligibleForNewFlow(); got {
		t.Fatal("quarantined node eligible for new flows")
	}
}

func TestQuarantineLifecycle(t *testing.T) {
	tr := newTracker(t)
	tr.RecordSuccess(t0)
	tr.Quarantine(t0.Add(time.Second), "tls certificate mismatch")
	if got := tr.Effective(t0.Add(2 * time.Second)).State; got != Quarantined {
		t.Fatalf("quarantine: %s", got)
	}
	tr.ReleaseQuarantine(t0.Add(3 * time.Second))
	got := tr.Effective(t0.Add(3 * time.Second))
	if got.State != Unknown {
		t.Fatalf("after release: %s, want unknown (must re-prove health)", got)
	}
	if got.State.EligibleForNewFlow() {
		t.Fatal("released node eligible before any successful probe")
	}
	tr.RecordSuccess(t0.Add(4 * time.Second))
	if got := tr.Effective(t0.Add(4 * time.Second)).State; got != Healthy {
		t.Fatalf("after post-release probe: %s", got)
	}
}

func TestFailuresDoNotResurrectQuarantineViaTransportKinds(t *testing.T) {
	tr := newTracker(t)
	tr.RecordFailure(t0, FailTLS, "bad cert")
	if got := tr.Effective(t0).State; got != Quarantined {
		t.Fatalf("tls failure: %s", got)
	}
	tr.RecordFailure(t0.Add(time.Second), FailTimeout, "")
	if got := tr.Effective(t0.Add(time.Second)).State; got != Quarantined {
		t.Fatalf("transport failure changed quarantine: %s", got)
	}
}

func TestStartupUnknownNeverHealthyByAssumption(t *testing.T) {
	tr := newTracker(t)
	got := tr.Effective(t0.Add(100 * time.Hour))
	if got.State != Unknown || got.Age < time.Hour {
		t.Fatalf("never-probed node: %+v", got)
	}
	if got.State.EligibleForNewFlow() {
		t.Fatal("unknown selected for new flows")
	}
}

func TestUnknownDoesNotCountAsHealthyAfterRestart(t *testing.T) {
	// Sticky selection consumes Effective(); a restarted tracker with no
	// observations must not report healthy even though state == unknown
	// from creation.
	tr := newTracker(t)
	s := tr.Effective(t0)
	if s.State != Unknown || !s.LastChange.Equal(t0) {
		t.Fatalf("fresh tracker snapshot: %+v", s)
	}
}
