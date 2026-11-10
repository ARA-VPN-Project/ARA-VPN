package controlstore

// Deeper invariants for the lease-registry quota (review FED01/FED02):
// Σ(open leases)+used ≤ limit under concurrency, offline spend confined
// to issued leases, last-byte exhaustion, month rollover, per-device
// authoritative limits, shared-rate split, and replay/retry semantics
// (same op_id via a NEW nonce must not double-charge; concurrent replays
// serialize through WithFedOpTx).

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openQuotaStore(t *testing.T) (*Store, string) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.CreateAccount("a", ""); err != nil {
		t.Fatal(err)
	}
	lim := int64(16 << 20)
	sub, _, err := s.CreateSubscription("a", "t", "owner", &lim, 0)
	if err != nil {
		t.Fatal(err)
	}
	// B04/interim adaptation (documented): admission requires a
	// panel-registered live device; fixtures register the literal device
	// ids they reference (explicit ids, since CreateDevice mints random
	// ones).
	for _, d := range []string{"dev", "dev-a", "dev-b", "dev-1", "dev-2", "e", "e2", "edge-a", "edge-b", "edge-c", "edge-d", "edge-0", "edge-1", "edge-2", "edge-3", "edge-4", "edge-5", "edge-6", "edge-7", "edge-x", "edge-y"} {
		if err := s.registerTestDevice("a", d); err != nil {
			t.Fatal(err)
		}
	}
	return s, sub.ID
}

func TestLeaseInvariantUnderParallelHolders(t *testing.T) {
	s, sub := openQuotaStore(t)
	// 8 holders report+reserve concurrently; the Σ invariant must hold
	// after every committed op (checked at the end over the final state,
	// which is the strongest observable without hooking the tx).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			holder := fmt.Sprintf("edge-%d", i)
			for round := 0; round < 4; round++ {
				if _, _, err := s.QuotaReport(sub, holder, 300<<10, 200<<10); err != nil {
					t.Errorf("holder %d round %d: %v", i, round, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	var usedTotal, openTotal int64
	_ = s.db.QueryRow(`SELECT used_bytes FROM sub_quota WHERE subscription_id=?`, sub).Scan(&usedTotal)
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued'`, sub).Scan(&openTotal)
	lim := int64(16 << 20)
	if usedTotal+openTotal > lim {
		t.Fatalf("invariant violated: used=%d open=%d limit=%d", usedTotal, openTotal, lim)
	}
	// every holder's leases are visible and bounded by its consumption
	var holders int64
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT holder) FROM sub_leases WHERE subscription_id=? AND state='issued'`, sub).Scan(&holders)
	if holders != 8 {
		t.Fatalf("expected 8 distinct holders, got %d", holders)
	}
}

func TestOfflineSpendConfinedToIssuedLeases(t *testing.T) {
	s, sub := openQuotaStore(t)
	// one tiny lease issued; the holder consumes it; no new grants are
	// possible (owner gone in the real world → here: reserve 0). The
	// owner-side must show used == exactly the lease amount.
	if _, ex, err := s.QuotaReport(sub, "edge-1", 0, 1<<20); err != nil || ex {
		t.Fatalf("lease: %v", err)
	}
	var open int64
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued'`, sub).Scan(&open)
	if open != 1<<20 {
		t.Fatalf("lease not registered: %d", open)
	}
	// consume exactly the lease
	if _, _, err := s.QuotaReport(sub, "edge-1", 1<<20, 0); err != nil {
		t.Fatalf("consume: %v", err)
	}
	var used int64
	_ = s.db.QueryRow(`SELECT used_bytes FROM sub_quota WHERE subscription_id=?`, sub).Scan(&used)
	if used != 1<<20 {
		t.Fatalf("used must be exactly the consumed lease: %d", used)
	}
	// partial consumption of a lease closes it WHOLE (remainder counted
	// as used — conservative, never undercounted)
	if _, _, err := s.QuotaReport(sub, "edge-2", 0, 2<<20); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.QuotaReport(sub, "edge-2", 700<<10, 0); err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRow(`SELECT used_bytes FROM sub_quota WHERE subscription_id=?`, sub).Scan(&used)
	if used != 1<<20+2<<20 {
		t.Fatalf("partial lease must settle whole: used=%d want=%d", used, 1<<20+2<<20)
	}
}

func TestLastByteExhaustionAndBoundedGrant(t *testing.T) {
	s := openTest(t)
	if _, err := s.CreateAccount("a", ""); err != nil {
		t.Fatal(err)
	}
	lim := int64(1000)
	subObj, _, _ := s.CreateSubscription("a", "t", "owner", &lim, 0)
	sub := subObj.ID
	for _, d := range []string{"e", "e2"} {
		if err := s.registerTestDevice("a", d); err != nil {
			t.Fatal(err)
		}
	}
	// request more than the budget: explicitly bounded grant; after
	// issuing it the budget is fully allocated → exhausted=true is the
	// honest "no further credit" flag (remaining=0)
	rem, ex, err := s.QuotaReport(sub, "e", 0, 10_000)
	if err != nil || !ex || rem == nil || *rem != 0 {
		t.Fatalf("bounded grant: rem=%v ex=%v err=%v", rem, ex, err)
	}
	var granted int64
	_ = s.db.QueryRow(`SELECT amount FROM sub_leases WHERE subscription_id=?`, sub).Scan(&granted)
	if granted != 1000 {
		t.Fatalf("grant must be capped by the budget: %d", granted)
	}
	// the last byte: after consuming the grant, the next reserve refuses
	if _, ex2, err := s.QuotaReport(sub, "e", 1000, 100); err != nil || !ex2 {
		t.Fatalf("consume grant: ex2=%v err=%v", ex2, err)
	}
	_, ex, err = s.QuotaReport(sub, "e2", 0, 100)
	if err != nil || !ex {
		t.Fatalf("exhaustion flag: ex=%v err=%v", ex, err)
	}
	var open int64
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued'`, sub).Scan(&open)
	if open != 0 {
		t.Fatalf("exhausted ledger must not issue leases: open=%d", open)
	}
}

func TestMonthRolloverResetsBudget(t *testing.T) {
	s := openTest(t)
	if _, err := s.CreateAccount("a", ""); err != nil {
		t.Fatal(err)
	}
	lim := int64(1 << 20)
	subObj, _, _ := s.CreateSubscription("a", "t", "owner", &lim, 0)
	sub := subObj.ID
	// burn the budget in the CURRENT month
	if _, _, err := s.QuotaReport(sub, "e", 0, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.QuotaReport(sub, "e", 1<<20, 0); err != nil {
		t.Fatal(err)
	}
	if _, ex, _ := s.QuotaReport(sub, "e", 0, 100); !ex {
		t.Fatal("expected exhaustion before rollover")
	}
	for _, d := range []string{"edge-x", "edge-y", "e"} {
		if err := s.registerTestDevice("a", d); err != nil {
			t.Fatal(err)
		}
	}
	// simulate the previous month: backdate the epoch of the leases and
	// the used counter, then report — the rollover must reset everything
	past := time.Now().UTC().AddDate(0, -1, 0).Format("2006-01")
	if _, err := s.db.Exec(`UPDATE sub_leases SET epoch=? WHERE subscription_id=?`, past, sub); err != nil {
		t.Fatal(err)
	}
	rem, ex, err := s.QuotaReport(sub, "e", 0, 100<<10)
	if err != nil || ex {
		t.Fatalf("post-rollover report: rem=%v ex=%v err=%v", rem, ex, err)
	}
	var used int64
	_ = s.db.QueryRow(`SELECT used_bytes FROM sub_quota WHERE subscription_id=?`, sub).Scan(&used)
	if used != 0 {
		t.Fatalf("rollover must reset used: %d", used)
	}
	var open int64
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued' AND epoch=?`, sub, past).Scan(&open)
	if open != 0 {
		t.Fatalf("previous-month leases must die at rollover: %d", open)
	}
}

func TestAuthoritativeDeviceLimit(t *testing.T) {
	s, subID := openQuotaStore(t)
	sub := subID
	if err := s.SetSubscriptionDeviceLimit(sub, "dev-1", int64p(1 << 20)); err != nil {
		t.Fatal(err)
	}
	resp, _, err := s.QuotaReportOp("op:d1", sub, "edge-a|dev-1", 0, 512<<10)
	if err != nil || resp.DeviceRemaining == nil || *resp.DeviceRemaining != 1<<20 {
		t.Fatalf("device remaining reflects REPORTED usage only: %+v %v", resp, err)
	}
	// the device draws its budget through TWO edges — the owner view is
	// per-device, not per-edge; 600 KiB reported of 1 MiB
	if _, _, err := s.QuotaReportOp("op:d2", sub, "edge-b|dev-1", 400<<10, 512<<10); err != nil {
		t.Fatal(err)
	}
	resp, _, err = s.QuotaReportOp("op:d3", sub, "edge-a|dev-1", 200<<10, 0)
	if err != nil || resp.DeviceExhausted || resp.DeviceRemaining == nil || *resp.DeviceRemaining != 112<<10 {
		t.Fatalf("device usage must aggregate across edges: got_rem=%d exhausted=%v err=%v",
			*resp.DeviceRemaining, resp.DeviceExhausted, err)
	}
	// 424 KiB expected from reported usage, MINUS the conservative
	// whole-lease settlement: d3's 200 KiB consumption closed edge-a's
	// 512 KiB lease whole → +312 KiB settled → rem = 112 KiB
	// over the device budget → exhausted for THIS device only
	resp, _, err = s.QuotaReportOp("op:d5", sub, "edge-a|dev-1", 500<<10, 0)
	if err != nil || !resp.DeviceExhausted {
		t.Fatalf("device exhausted across edges: %+v %v", resp, err)
	}
	// a DIFFERENT device is unaffected by dev-1's exhaustion
	resp2, _, err := s.QuotaReportOp("op:d4", sub, "edge-a|dev-2", 0, 100<<10)
	if err != nil || resp2.DeviceExhausted {
		t.Fatalf("other device must be unaffected: %+v %v", resp2, err)
	}
}

func int64p(v int64) *int64 { return &v }

func TestSharedRateSplitAcrossHolders(t *testing.T) {
	s, sub := openQuotaStore(t)
	three := int64(3_000_000)
	one := int64(1_000_000)
	if err := s.SetSubscriptionRate(sub, &three, &one); err != nil {
		t.Fatal(err)
	}
	// single holder gets the full rate (leases register the holders)
	r1, _, err := s.QuotaReportOp("op:r1", sub, "edge-a|dev", 0, 1<<10)
	if err != nil || r1.RateDownBPS == nil || *r1.RateDownBPS != three {
		t.Fatalf("single holder rate: %+v %v", r1, err)
	}
	// a second holder halves the share
	if _, _, err := s.QuotaReportOp("op:r2", sub, "edge-b|dev", 0, 1<<10); err != nil {
		t.Fatal(err)
	}
	r2, _, err := s.QuotaReportOp("op:r3", sub, "edge-a|dev", 0, 1<<10)
	if err != nil || r2.RateDownBPS == nil {
		t.Fatalf("split rate: err=%v", err)
	}
	if *r2.RateDownBPS != three/2 {
		t.Fatalf("split rate deref: down=%d (want %d)", *r2.RateDownBPS, three/2)
	}
	if r2.RateUpBPS == nil {
		t.Fatalf("split up rate: nil")
	}
	if *r2.RateUpBPS != one/2 {
		t.Fatalf("split up rate deref: up=%d (want %d)", *r2.RateUpBPS, one/2)
	}
}

func TestReplayAndNewNonceSameOpId(t *testing.T) {
	s, sub := openQuotaStore(t)
	// same op id, different nonces (lost-response retry): charged once
	opKey := "op:rq-abc"
	if _, _, err := s.QuotaReportOp(opKey, sub, "edge-a|dev", 500<<10, 0); err != nil {
		t.Fatal(err)
	}
	resp, replayed, err := s.QuotaReportOp(opKey, sub, "edge-a|dev", 500<<10, 0)
	if err != nil || !replayed {
		t.Fatalf("same-op retry must replay: replayed=%v err=%v", replayed, err)
	}
	used, _, _ := s.QuotaUsage(sub)
	if used != 500<<10 {
		t.Fatalf("retry double-charged: used=%d", used)
	}
	// a genuinely NEW op with the same content charges again (correct)
	if _, _, err := s.QuotaReportOp("op:rq-def", sub, "edge-a|dev", 500<<10, 0); err != nil {
		t.Fatal(err)
	}
	used, _, _ = s.QuotaUsage(sub)
	if used != 2*(500<<10) {
		t.Fatalf("new op must charge: used=%d want=%d", used, 2*(500<<10))
	}
	_ = resp
}

func TestConcurrentReplaysSerialize(t *testing.T) {
	s, sub := openQuotaStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.QuotaReportOp("op:same", sub, "edge-a|dev", 100<<10, 0)
			if err != nil {
				t.Errorf("concurrent op: %v", err)
			}
		}()
	}
	wg.Wait()
	used, _, _ := s.QuotaUsage(sub)
	if used != 100<<10 {
		t.Fatalf("concurrent replays double-charged: used=%d want=%d", used, 100<<10)
	}
}

func TestWithFedOpRollbackOnFailure(t *testing.T) {
	s := openTest(t)
	boom := fmt.Errorf("boom")
	if _, _, err := s.WithFedOpTx("op:x", func(_ *sql.Tx) (any, error) { return nil, boom }); err == nil {
		t.Fatal("error must propagate")
	}
	// the op key died with the failed tx: retryable
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM fed_ops WHERE op_key='op:x'`).Scan(&n)
	if n != 0 {
		t.Fatalf("failed op must not leave a key: %d", n)
	}
	res, replayed, err := s.WithFedOpTx("op:x", func(_ *sql.Tx) (any, error) { return map[string]any{"ok": true}, nil })
	if err != nil || replayed {
		t.Fatalf("retry after failure: %v %v", replayed, err)
	}
	b, _ := json.Marshal(res)
	if string(b) != `{"ok":true}` {
		t.Fatalf("retry result: %s", b)
	}
}

func TestTransferImportInactiveThenActivate(t *testing.T) {
	// source and target are SEPARATE stores (different panels)
	srcPath := filepath.Join(t.TempDir(), "src.db")
	tgtPath := filepath.Join(t.TempDir(), "tgt.db")
	src, err := Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	tgt, err := Open(tgtPath)
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Close()
	for _, st := range []*Store{src, tgt} {
		if _, err := st.CreateAccount("a", ""); err != nil {
			t.Fatal(err)
		}
	}
	lim := int64(5 << 20)
	subObj, _, err := src.CreateSubscription("a", "u", "ru-1", &lim, 0)
	if err != nil {
		t.Fatal(err)
	}
	sub := subObj.ID
	// spend accrues on the source
	if _, _, err := src.QuotaReport(sub, "ru-1|edge-a|dev", 2<<20, 1<<20); err != nil {
		t.Fatal(err)
	}
	used, _, _ := src.QuotaUsage(sub)
	// prepare on the source + import on the target (inactive, owner=target)
	if err := src.CreateMigration("mig-1", sub, "ru-1", "de-1", used); err != nil {
		t.Fatal(err)
	}
	imp := &Subscription{ID: sub, AccountID: "a", Name: subObj.Name, OwnerPanel: "de-1",
		LimitsBytes: &lim, CreatedAt: subObj.CreatedAt, UsedBytes: used,
		DeviceUsage: map[string]int64{"dev": 2 << 20}}
	if err := tgt.CreateSubscriptionImported(imp, "hash-1"); err != nil {
		t.Fatal(err)
	}
	got, err := tgt.GetSubscription(sub)
	if err != nil || got.OwnerPanel != "de-1" {
		t.Fatalf("imported owner: %+v %v", got, err)
	}
	if got.Active == nil || *got.Active {
		t.Fatal("imported copy must be inactive")
	}
	// while inactive, the source's spend continues; the activate applies
	// the FINAL delta (spend between snapshot and switch travels)
	if err := src.SetQuotaUsed(sub, used+7<<10); err != nil {
		t.Fatal(err)
	}
	if err := tgt.ActivateImportedSubscription(sub, used+7<<10); err != nil {
		t.Fatal(err)
	}
	final, _, _ := tgt.QuotaUsage(sub)
	if final != used+7<<10 {
		t.Fatalf("final usage: %d want %d", final, used+7<<10)
	}
	got, _ = tgt.GetSubscription(sub)
	if got.Active == nil || !*got.Active {
		t.Fatal("activated copy must be active")
	}
	// idempotent activate + idempotent re-import refusal once active
	if err := tgt.ActivateImportedSubscription(sub, used+7<<10); err != nil {
		t.Fatalf("idempotent activate: %v", err)
	}
	if err := tgt.CreateSubscriptionImported(imp, "hash-1"); err == nil {
		t.Fatal("re-import onto an ACTIVE copy must refuse")
	}
	// migration states on the source
	mig, err := src.GetMigration("mig-1")
	if err != nil || mig.State != "prepared" {
		t.Fatalf("migration: %+v %v", mig, err)
	}
	if err := src.CommitMigration("mig-1", used+7<<10); err != nil {
		t.Fatal(err)
	}
	if err := src.CommitMigration("mig-1", 0); err == nil {
		t.Fatal("double commit must refuse")
	}
}

// registerTestDevice inserts a device row with an EXPLICIT id — the id is
// what the quota admission guard checks, so fixtures must control it.
func (s *Store) registerTestDevice(account, id string) error {
	_, err := s.db.Exec(`INSERT INTO devices(id, account_id, name, created_at, identity_pubkey, vless_uuid)
		VALUES (?,?,'fixture',?,'','')
		ON CONFLICT(id) DO NOTHING`, id, account, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
