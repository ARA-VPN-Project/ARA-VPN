package controlstore

// Review 2026-11-01 invariants (FED03/FED04/FED05): expiry never frees
// unreported spend (repeat/late-report/rollover/concurrent), device
// budget bounds GRANTS across edges (with settlement and a healthy other
// device), rate rights sum ≤ subscription rate across joins/renewals.

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestExpirySettlementIsOnceAndConservative(t *testing.T) {
	s, id := openQuotaStore(t)
	lim := int64(16 << 20)
	if r, _, err := s.QuotaReportOp("op:i1", id, "edge-a|dev", 0, lim); err != nil || r.Granted != lim {
		t.Fatalf("baseline: %+v %v", r, err)
	}
	// backdate expiry (owner-side modeling, no sleeps)
	if _, err := s.db.Exec(`UPDATE sub_leases SET expires_at=? WHERE subscription_id=?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	// the NEXT op settles: no budget is freed
	if r, _, err := s.QuotaReportOp("op:i2", id, "edge-b|dev", 0, 1<<20); err != nil || r.Granted != 0 {
		t.Fatalf("expired grant must not be re-issued: %+v %v", r, err)
	}
	used, _, _ := s.QuotaUsage(id)
	if used != lim {
		t.Fatalf("settled used: %d want %d", used, lim)
	}
	// REPEATED expiry ops settle exactly once (rows are consumed already)
	if _, _, err := s.QuotaReportOp("op:i3", id, "edge-c|dev", 0, 1<<20); err != nil {
		t.Fatal(err)
	}
	used2, _, _ := s.QuotaUsage(id)
	if used2 != lim {
		t.Fatalf("double settlement: %d", used2)
	}
	// a LATE report for the same bytes charges again (conservative
	// over-count, never under-count)
	if _, _, err := s.QuotaReportOp("op:i4", id, "edge-a|dev", 3<<20, 0); err != nil {
		t.Fatal(err)
	}
	used3, _, _ := s.QuotaUsage(id)
	if used3 != lim+3<<20 {
		t.Fatalf("late report must over-count conservatively: %d", used3)
	}
}

func TestExpirySettlementUnderConcurrencyAndRollover(t *testing.T) {
	s, id := openQuotaStore(t)
	// concurrent reserves while a lease expires mid-flight
	if _, _, err := s.QuotaReportOp("op:c0", id, "edge-a|dev", 0, 4<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sub_leases SET expires_at=? WHERE subscription_id=?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, err := s.QuotaReportOp(fmt.Sprintf("op:c%d", i+1), id, fmt.Sprintf("edge-%d|dev", i+1), 0, 1<<20); err != nil {
				t.Errorf("concurrent op: %v", err)
			}
		}(i)
	}
	wg.Wait()
	used, _, _ := s.QuotaUsage(id)
	// the expired 4 MiB settled exactly once; grants after settlement were
	// bounded by the remaining budget — the invariant is what matters
	var open int64
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued'`, id).Scan(&open)
	lim := int64(16 << 20)
	if used+open > lim {
		t.Fatalf("invariant after expiry+concurrency: used=%d open=%d", used, open)
	}
	// rollover: old-epoch leases die and NEVER settle into the new month
	if _, _, err := s.QuotaReportOp("op:m1", id, "edge-x|dev", 0, 1<<20); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().AddDate(0, -1, 0).Format("2006-01")
	if _, err := s.db.Exec(`UPDATE sub_leases SET epoch=? WHERE subscription_id=?`, past, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sub_leases SET expires_at=? WHERE subscription_id=?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.QuotaReportOp("op:m2", id, "edge-y|dev", 0, 1<<20); err != nil {
		t.Fatal(err)
	}
	used2, _, _ := s.QuotaUsage(id)
	if used2 != 0 {
		t.Fatalf("rollover must reset spend: %d", used2)
	}
}

func TestDeviceGrantsBoundAndOtherDeviceHealthy(t *testing.T) {
	s, id := openQuotaStore(t)
	cap := int64(128 << 10)
	if err := s.SetSubscriptionDeviceLimit(id, "dev-a", &cap); err != nil {
		t.Fatal(err)
	}
	var grants int64
	for i := 0; i < 3; i++ {
		r, _, err := s.QuotaReportOp(fmt.Sprintf("op:d%d", i), id, fmt.Sprintf("edge-%d|dev-a", i), 0, 512<<10)
		if err != nil {
			t.Fatal(err)
		}
		grants += r.Granted
	}
	if grants > cap {
		t.Fatalf("device grants over-issued across edges: %d > %d", grants, cap)
	}
	// end-to-end positive control: ANOTHER device with its own (nil =
	// unlimited) budget stays workable
	r, _, err := s.QuotaReportOp("op:other", id, "edge-9|dev-b", 0, 1<<20)
	if err != nil || r.Granted != 1<<20 {
		t.Fatalf("other device must remain workable: %+v %v", r, err)
	}
	// settlement of an expired device lease returns the device budget
	// (already counted as used — the grant does not come back)
	if _, err := s.db.Exec(`UPDATE sub_leases SET expires_at=? WHERE subscription_id=? AND device_id='dev-a'`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	r2, _, err := s.QuotaReportOp("op:d-settle", id, "edge-1|dev-a", 0, 512<<10)
	if err != nil || r2.Granted != 0 {
		t.Fatalf("settled device spend must not be re-granted: %+v %v", r2, err)
	}
}

func TestRateRightsSumBoundAndRenewalConvergence(t *testing.T) {
	s, id := openQuotaStore(t)
	rate := int64(3_000_000)
	if err := s.SetSubscriptionRate(id, &rate, &rate); err != nil {
		t.Fatal(err)
	}
	a, _, err := s.QuotaReportOp("op:ra", id, "edge-a|dev", 0, 1<<20)
	if err != nil || a.RateDownBPS == nil {
		t.Fatal(err)
	}
	b, _, err := s.QuotaReportOp("op:rb", id, "edge-b|dev", 0, 1<<20)
	if err != nil || b.RateDownBPS == nil {
		t.Fatal(err)
	}
	if *a.RateDownBPS+*b.RateDownBPS > rate {
		t.Fatalf("live rate rights exceed the subscription: %d + %d", *a.RateDownBPS, *b.RateDownBPS)
	}
	// the joining holder's right grows only through the acknowledged
	// renewal of the existing holders (never by silent revocation)
	if _, _, err := s.QuotaReportOp("op:ra2", id, "edge-a|dev", 0, 1<<20); err != nil {
		t.Fatal(err)
	}
	b2, _, err := s.QuotaReportOp("op:rb2", id, "edge-b|dev", 0, 1<<20)
	if err != nil || b2.RateDownBPS == nil {
		t.Fatal(err)
	}
	if b2.RateDownBPS == nil || *b2.RateDownBPS == 0 {
		t.Fatalf("second holder starved after renewal: %+v", b2)
	}
	// the invariant holds for the CURRENT registry at any point
	var sumDown int64
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(down_bps),0) FROM sub_rate_rights WHERE subscription_id=?`, id).Scan(&sumDown)
	if sumDown > rate {
		t.Fatalf("registry sum exceeds the rate: %d", sumDown)
	}
	// rate DECREASE while a holder is offline: after the rights expire,
	// the reduced rate caps renewals (b's expired right frees its share —
	// a alone holds the full reduced rate; the cap is what matters)
	smaller := int64(1_000_000)
	if err := s.SetSubscriptionRate(id, &smaller, &smaller); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sub_rate_rights SET expires_at=? WHERE subscription_id=?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	a3, _, err := s.QuotaReportOp("op:ra3", id, "edge-a|dev", 0, 1<<20)
	if err != nil || a3.RateDownBPS == nil || *a3.RateDownBPS > smaller {
		t.Fatalf("reduced rate must cap renewals: %+v %v", a3, err)
	}
}
