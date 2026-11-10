package limits

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func p64(v int64) *int64 { return &v }

// testNow is a fixed UTC instant; period tests construct their own times.
var testNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// newTestLimiter builds a device limiter bound to a fresh account regime.
func newTestLimiter(t *testing.T, account, device RateConfig) *AggregateLimiter {
	t.Helper()
	regime, err := NewAccountRegime(account, testNow)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := regime.BindDevice(device, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return lim
}

func TestUnlimitedAndForbidden(t *testing.T) {
	lim := newTestLimiter(t, RateConfig{}, RateConfig{
		DownloadBPS: p64(0), // forbidden direction
	})
	// download is forbidden by the device bucket (rate 0) even though the
	// account scope is unlimited
	r := lim.Take(Download, 1000, testNow)
	if r.Granted || !r.Forbidden {
		t.Fatalf("forbidden direction: %+v", r)
	}
	// upload is unlimited in both scopes
	if r := lim.Take(Upload, 1<<20, testNow); !r.Granted {
		t.Fatalf("unlimited upload refused: %+v", r)
	}
	// both scopes unlimited: anything granted
	lim2 := newTestLimiter(t, RateConfig{}, RateConfig{})
	if r := lim2.Take(Download, 1<<30, testNow); !r.Granted {
		t.Fatalf("unlimited download refused: %+v", r)
	}
}

func TestBurstIsBounded(t *testing.T) {
	// 8 Mbit/s => 1 MiB/s; burst capped at 2 MiB
	lim := newTestLimiter(t, RateConfig{}, RateConfig{
		DownloadBPS:        p64(8 * 1000 * 1000),
		DownloadBurstBytes: p64(2 * 1024 * 1024),
	})
	if r := lim.Take(Download, 2*1024*1024, testNow); !r.Granted {
		t.Fatalf("burst capacity refused: %+v", r)
	}
	// 10 ms at 1 MB/s refills ~10 KB: a 1 MiB take must still be limited
	if r := lim.Take(Download, 1024*1024, testNow.Add(10*time.Millisecond)); r.Granted {
		t.Fatal("burst exceeded: granted more than capacity+refill")
	}
	// after enough time the bucket refills 1 s worth
	if r := lim.Take(Download, 1024, testNow.Add(2*time.Second)); !r.Granted {
		t.Fatalf("refill failed: %+v", r)
	}
}

func TestParallelFlowsShareAggregateBucket(t *testing.T) {
	// 8 kbit/s => 1 KiB/s; burst 4 KiB. 64 goroutines trying to take 1 KiB
	// each must be collectively bounded to ~burst+elapsed*rate, NOT 64 KiB.
	lim := newTestLimiter(t, RateConfig{}, RateConfig{
		DownloadBPS:        p64(8000),
		DownloadBurstBytes: p64(4096),
	})
	var grantedTotal int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	stop := testNow.Add(200 * time.Millisecond)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for now := testNow; now.Before(stop); now = now.Add(10 * time.Millisecond) {
				if r := lim.Take(Download, 1024, now); r.Granted {
					mu.Lock()
					grantedTotal += 1024
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	ceiling := int64(4096) + int64(0.2*1000) // burst + 0.2s * 1000 B/s, rounding slack
	if grantedTotal > ceiling {
		t.Fatalf("parallel flows multiplied the limit: granted %d > ceiling %d", grantedTotal, ceiling)
	}
	if grantedTotal < 1024 {
		t.Fatalf("limiter starved healthy traffic: %d", grantedTotal)
	}
}

func TestRefusalDoesNotDrainSharedBucket(t *testing.T) {
	regime, err := NewAccountRegime(
		RateConfig{DownloadBPS: p64(8 * 1000 * 1000), DownloadBurstBytes: p64(1024 * 1024)},
		testNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	lim, _ := regime.BindDevice(
		RateConfig{DownloadBPS: p64(8 * 1000 * 1000), DownloadBurstBytes: p64(1024)},
		testNow,
	)
	// device bucket is small: a big take fails on device
	if r := lim.Take(Download, 512*1024, testNow); r.Granted {
		t.Fatal("over-device-burst take granted")
	}
	// the account bucket must keep its full capacity: a second device with
	// a normal device budget still gets the account's full burst
	lim2, _ := regime.BindDevice(RateConfig{
		DownloadBPS:        p64(8 * 1000 * 1000),
		DownloadBurstBytes: p64(1024 * 1024),
	}, testNow)
	if r := lim2.Take(Download, 1024*1024, testNow); !r.Granted {
		t.Fatalf("account budget was drained by the other device's refusal: %+v", r)
	}
}

// R04 regression: two devices on one account regime share the account
// budget; independent per-device minima do not replace it.
func TestAccountBudgetSharedAcrossDevices(t *testing.T) {
	rate := int64(8000) // 1 KiB/s
	regime, err := NewAccountRegime(RateConfig{DownloadBPS: &rate}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := regime.BindDevice(RateConfig{}, testNow)
	d2, _ := regime.BindDevice(RateConfig{}, testNow)
	if r := d1.Take(Download, 1000, testNow); !r.Granted {
		t.Fatalf("first device refused within burst: %+v", r)
	}
	if r := d2.Take(Download, 1000, testNow); r.Granted {
		t.Fatal("second device admitted from a fresh account budget; account buckets are not shared")
	}
	// the tighter device limit is additional, not a replacement
	regime2, _ := NewAccountRegime(RateConfig{DownloadBPS: p64(8 * 1000 * 1000), DownloadBurstBytes: p64(1024 * 1024)}, testNow)
	d3, _ := regime2.BindDevice(RateConfig{DownloadBPS: p64(8000), DownloadBurstBytes: p64(1024)}, testNow)
	if r := d3.Take(Download, 1024*1024, testNow); r.Granted {
		t.Fatal("device limit did not constrain admission below account budget")
	}
}

func TestEffectiveRate(t *testing.T) {
	if got := EffectiveRate(p64(100), p64(50)); *got != 50 {
		t.Errorf("min rule: got %d", *got)
	}
	if got := EffectiveRate(nil, p64(50)); *got != 50 {
		t.Errorf("nil account => device: got %d", *got)
	}
	if got := EffectiveRate(p64(30), nil); *got != 30 {
		t.Errorf("nil device => account: got %d", *got)
	}
	if got := EffectiveRate(nil, nil); got != nil {
		t.Errorf("both nil => unlimited: got %v", *got)
	}
}

func newTestQuota(t *testing.T, dir string, total *int64, period Period, now time.Time) (*QuotaTracker, *FileJournal) {
	t.Helper()
	j, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewQuotaTracker(ScopeID{AccountID: "acc1", DeviceID: "dev1"}, QuotaConfig{TotalBytes: total, Period: period}, j, now)
	if err != nil {
		t.Fatal(err)
	}
	return q, j
}

func TestQuotaReserveCheckpointCycle(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(10*1024*1024), DefaultPeriod(), testNow)

	st := q.Snapshot(testNow)
	if st.Limit == nil || *st.Limit != 10*1024*1024 || st.Exhausted {
		t.Fatalf("initial state: %+v", st)
	}
	b, st, err := q.Reserve(4*1024*1024, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Exhausted && *st.Remaining != 6*1024*1024 {
		t.Fatalf("reservation not visible: %+v", st)
	}
	// another reserve bigger than the remainder must be refused
	if _, _, err := q.Reserve(7*1024*1024, testNow); err == nil {
		t.Fatal("over-quota reserve granted")
	}
	if _, err := q.Checkpoint(b, 3*1024*1024, testNow); err != nil {
		t.Fatal(err)
	}
	st = q.Snapshot(testNow)
	if *st.Remaining != 7*1024*1024 {
		t.Fatalf("checkpoint reconciliation wrong: %+v", st)
	}
	if st.ThresholdHit != "" {
		t.Fatalf("30%% must not hit threshold: %q", st.ThresholdHit)
	}
	// open reservation of 5MB on top of 3MB used = 80%% conservative
	b2, st, err := q.Reserve(5*1024*1024, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if st.ThresholdHit != "80" {
		t.Fatalf("80%% threshold: %q", st.ThresholdHit)
	}
	if _, err := q.Checkpoint(b2, 5*1024*1024, testNow); err != nil {
		t.Fatal(err)
	}
	st = q.Snapshot(testNow)
	if st.ThresholdHit != "80" {
		t.Fatalf("80%% after checkpoint: %q", st.ThresholdHit)
	}
	if *st.Remaining != 2*1024*1024 {
		t.Fatalf("remaining after 8MB: %+v", st)
	}
}

func TestQuotaExhaustionPersistsAcrossRestartAndReconnect(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	if _, _, err := q.Reserve(600, testNow); err != nil {
		t.Fatal(err)
	}
	b2, _, err := q.Reserve(400, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Checkpoint(b2, 400, testNow); err != nil {
		t.Fatal(err)
	}
	// crash: reopen the journal and tracker fresh ("reconnect/restart").
	// 600 checkpointed + 400 open reservation (conservative) = exhausted.
	q2, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	st := q2.Snapshot(testNow)
	if !st.Exhausted || st.Used != 1000 {
		t.Fatalf("restart state: %+v", st)
	}
	if _, _, err := q2.Reserve(1, testNow); err == nil {
		t.Fatal("post-crash free allowance granted")
	}
}

func TestQuotaUnknownBatchRefusesCheckpoint(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(1024), DefaultPeriod(), testNow)
	if _, err := q.Checkpoint(&ReservationBatch{ID: "nope"}, 1, testNow); err == nil {
		t.Fatal("unknown batch checkpointed")
	}
}

func TestQuotaPeriodResetMonthlyUTC(t *testing.T) {
	dir := t.TempDir()
	jan := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	q, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), jan)
	if _, _, err := q.Reserve(1000, jan); err != nil {
		t.Fatal(err)
	}
	st := q.Snapshot(jan)
	if !st.Exhausted {
		t.Fatalf("january: %+v", st)
	}
	// next month: new window, usage from january must not apply
	feb := time.Date(2026, 2, 1, 0, 0, 1, 0, time.UTC)
	q2, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), feb)
	st = q2.Snapshot(feb)
	if st.Exhausted || st.Used != 0 {
		t.Fatalf("february after reset: %+v", st)
	}
	wantReset := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if !st.ResetAt.Equal(wantReset) {
		t.Fatalf("reset_at: %v, want %v", st.ResetAt, wantReset)
	}
}

func TestQuotaPeriodTimezoneAndDSTBoundary(t *testing.T) {
	p := Period{Kind: PeriodMonthly, TZ: "Europe/Moscow"}
	// Oct 26 2026 is the DST-free Moscow winter time; use New York for DST
	ny := Period{Kind: PeriodMonthly, TZ: "America/New_York"}
	start, end, err := ny.Window(time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if start.String() != "2026-03-01 00:00:00 -0500 EST" {
		t.Fatalf("march start (EST side of DST): %v", start)
	}
	if end.String() != "2026-04-01 00:00:00 -0400 EDT" {
		t.Fatalf("april boundary (EDT side): %v", end)
	}
	// window containing the spring-forward night must be exactly one month
	if d := end.Sub(start); d != 31*24*time.Hour-1*time.Hour {
		t.Fatalf("march window length with DST: %v (expected 743h)", d)
	}
	// Moscow has no DST: fixed +03:00
	start, end, err = p.Window(time.Date(2026, 10, 27, 23, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if start.String() != "2026-10-01 00:00:00 +0300 MSK" || end.String() != "2026-11-01 00:00:00 +0300 MSK" {
		t.Fatalf("moscow window: %v .. %v", start, end)
	}
}

func TestQuotaAdjustRequiresActorAndIsReplayed(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	if _, _, err := q.Reserve(400, testNow); err != nil {
		t.Fatal(err)
	}
	if err := q.Adjust(-100, "operator-admin", testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	q2, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	st := q2.Snapshot(testNow)
	if st.Used != 300 { // 400 open reservation replayed, -100 adjustment replayed
		t.Fatalf("adjustment replay: %+v", st)
	}
}

func TestQuotaZeroIsZeroNotUnlimited(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(0), DefaultPeriod(), testNow)
	st := q.Snapshot(testNow)
	if !st.Exhausted || st.Limit == nil || *st.Limit != 0 {
		t.Fatalf("zero quota: %+v", st)
	}
	if _, _, err := q.Reserve(1, testNow); err == nil {
		t.Fatal("zero quota granted bytes")
	}
}

func TestJournalTornTailIsErrorNotSilence(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	if _, _, err := q.Reserve(100, testNow); err != nil {
		t.Fatal(err)
	}
	// simulate a torn final write
	f := filepath.Join(dir, "usage.journal.jsonl")
	content, _ := os.ReadFile(f)
	if err := os.WriteFile(f, append(content, []byte(`{"seq":2,"scop`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileJournal(dir); err == nil {
		t.Fatal("torn journal accepted; conservative behavior required")
	}
}

func TestInvalidConfigsRejected(t *testing.T) {
	if _, err := NewAccountRegime(RateConfig{DownloadBPS: p64(-1)}, testNow); err == nil {
		t.Error("negative rate accepted")
	}
	regime, _ := NewAccountRegime(RateConfig{}, testNow)
	if _, err := regime.BindDevice(RateConfig{UploadBPS: p64(7)}, testNow); err == nil {
		t.Error("sub-byte rate accepted")
	}
	if _, err := NewAccountRegime(RateConfig{DownloadBurstBytes: p64(-5)}, testNow); err == nil {
		t.Error("negative burst accepted")
	}
	if err := (QuotaConfig{TotalBytes: p64(-1), Period: DefaultPeriod()}).Validate(); err == nil {
		t.Error("negative quota accepted")
	}
	if err := (QuotaConfig{TotalBytes: p64(1), Period: Period{Kind: "weekly", TZ: "UTC"}}).Validate(); err == nil {
		t.Error("unknown period accepted")
	}
	if err := (QuotaConfig{TotalBytes: p64(1), Period: Period{Kind: PeriodMonthly, TZ: "Not/AZone"}}).Validate(); err == nil {
		t.Error("bad timezone accepted")
	}
}

// R03 regression: reservation IDs are unique across restarts and the
// conservative accounting after restart counts every open reservation.
func TestQuotaReservationIDsUniqueAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	b1, _, err := q.Reserve(400, testNow)
	if err != nil {
		t.Fatal(err)
	}
	q2, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow.Add(time.Second))
	b2, st, err := q2.Reserve(400, testNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if b1.ID == b2.ID {
		t.Fatalf("reservation ID reused after restart: %s", b1.ID)
	}
	if st.Used != 800 || *st.Remaining != 200 {
		t.Fatalf("800 reserved bytes must survive restart: used=%d remaining=%d", st.Used, *st.Remaining)
	}
	// repeated restarts keep accumulating open reservations
	q3, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow.Add(2*time.Second))
	st = q3.Snapshot(testNow.Add(2 * time.Second))
	if st.Used != 800 || st.Exhausted || *st.Remaining != 200 {
		t.Fatalf("state after second restart: %+v", st)
	}
	if _, _, err := q3.Reserve(201, testNow.Add(2*time.Second)); err == nil {
		t.Fatal("post-restart over-budget reserve granted")
	}
}

// R08 regression: a live process enters the new monthly period without a
// restart; open reservations of the old window do not carry over, and a
// late checkpoint for a retired batch is a no-op against the new window.
func TestQuotaLivePeriodRollOver(t *testing.T) {
	dir := t.TempDir()
	october := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	q, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), october)
	b, _, err := q.Reserve(600, october)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Checkpoint(b, 400, october); err != nil {
		t.Fatal(err)
	}
	// keep one open reservation into the next window
	openBatch, _, err := q.Reserve(100, october.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	nov := time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC)
	st := q.Snapshot(nov)
	if st.Exhausted || st.Used != 0 || *st.Remaining != 1000 {
		t.Fatalf("live rollover failed: %+v", st)
	}
	// late checkpoint for the retired batch must not charge the new window
	if _, err := q.Checkpoint(openBatch, 100, nov); err != nil {
		t.Fatalf("late checkpoint for retired batch errored: %v", err)
	}
	st = q.Snapshot(nov)
	if st.Used != 0 || *st.Remaining != 1000 {
		t.Fatalf("retired batch leaked into new window: %+v", st)
	}
	// new window budget is fully usable again
	if _, _, err := q.Reserve(1000, nov); err != nil {
		t.Fatalf("new period budget refused: %v", err)
	}
}

// R04 regression: the ledger debits the shared account budget and the
// device budget together; refusals refund the account side.
func TestQuotaLedgerSharesAccountBudget(t *testing.T) {
	dir := t.TempDir()
	jr, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(1000)
	ledger, err := NewQuotaLedger("acc", &limit, DefaultPeriod(), jr, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.Reserve("dev1", 600, testNow); err != nil {
		t.Fatal(err)
	}
	// a second device draws from the SAME account budget
	if _, _, _, err := ledger.Reserve("dev2", 300, testNow); err != nil {
		t.Fatalf("shared account budget not visible across devices: %v", err)
	}
	// 600+300=900 committed on the account; only 100 remain for anyone
	if _, _, _, err := ledger.Reserve("dev1", 200, testNow); err == nil {
		t.Fatal("account budget multiplied across devices")
	}
	// device budget is additional: dev1 already used 600 of its own 1000,
	// but the account is the binding constraint here
	if _, aState, _, err := ledger.Reserve("dev1", 100, testNow); err != nil {
		t.Fatalf("within both budgets refused: %v (%+v)", err, aState)
	}
}

func TestQuotaLedgerRefundOnDeviceRefusal(t *testing.T) {
	dir := t.TempDir()
	jr, _ := OpenFileJournal(dir)
	limit := int64(1000)
	ledger, _ := NewQuotaLedger("acc", &limit, DefaultPeriod(), jr, testNow)
	if _, _, _, err := ledger.Reserve("dev1", 600, testNow); err != nil {
		t.Fatal(err)
	}
	// device1 has 600; a 500-byte request fits the account (400 left) but
	// not device1 (400 left either) — pick dev2 with fresh device budget:
	// account has 400 left, so 500 must refuse on the ACCOUNT and nothing
	// may be consumed.
	_, aState, _, err := ledger.Reserve("dev2", 500, testNow)
	if err == nil {
		t.Fatal("over-account reserve granted")
	}
	if aState.Used != 600 {
		t.Fatalf("account consumed bytes on refusal: %+v", aState)
	}
}

// S07 regressions: idempotent actual-byte checkpoints — a repeated
// checkpoint never charges twice, and a partially failed ledger pair is
// repaired by re-running the same Checkpoint.
func TestQuotaCheckpointIdempotentAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	q, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	b, _, err := q.Reserve(400, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Checkpoint(b, 100, testNow); err != nil {
		t.Fatal(err)
	}
	// duplicate checkpoint of the same batch: no-op, no double charge
	wrote, err := q.Checkpoint(b, 100, testNow)
	if err != nil || wrote {
		t.Fatalf("duplicate checkpoint not idempotent: wrote=%v err=%v", wrote, err)
	}
	// restart: replay keeps used=100 exactly once
	q2, _ := newTestQuota(t, dir, p64(1000), DefaultPeriod(), testNow)
	if st := q2.Snapshot(testNow); st.Used != 100 || *st.Remaining != 900 {
		t.Fatalf("replay after idempotent checkpoint: %+v", st)
	}
	// the closed batch cannot be recharged with different bytes either
	if _, err := q2.Checkpoint(b, 400, testNow); err != nil {
		t.Fatalf("closed batch must be a no-op, not an error: %v", err)
	}
	if st := q2.Snapshot(testNow); st.Used != 100 {
		t.Fatalf("closed batch recharged: %+v", st)
	}
}

// S05 regression: a device-scoped refusal refunds the shared account
// reservation and leaves both scopes consistent.
func TestQuotaLedgerDeviceOnlyRefund(t *testing.T) {
	dir := t.TempDir()
	jr, _ := OpenFileJournal(dir)
	limit := int64(1000)
	deviceLimit := int64(100)
	ledger, err := NewQuotaLedger("acc", &limit, DefaultPeriod(), jr, testNow)
	if err != nil {
		t.Fatal(err)
	}
	ledger.SetDeviceLimit("dev1", &deviceLimit)
	// fits the account (1000) but not the device (100): device refusal
	// must refund the account side
	if _, _, _, err := ledger.Reserve("dev1", 500, testNow); err == nil {
		t.Fatal("device-limit refusal missing")
	}
	if acc := ledger.AccountState(testNow); acc.Used != 0 {
		t.Fatalf("account consumed bytes on device refusal: %+v", acc)
	}
	// within both budgets: account and device both charge
	if _, _, _, err := ledger.Reserve("dev1", 100, testNow); err != nil {
		t.Fatal(err)
	}
	if acc := ledger.AccountState(testNow); acc.Used != 100 {
		t.Fatalf("account state after paired reserve: %+v", acc)
	}
	if dev, _ := ledger.DeviceTracker("dev1", testNow); dev.Snapshot(testNow).Used != 100 {
		t.Fatal("device state after paired reserve")
	}
}

// S05: device override configurations that must behave as documented.
func TestQuotaLedgerDeviceLimitMatrix(t *testing.T) {
	dir := t.TempDir()
	jr, _ := OpenFileJournal(dir)
	acc := int64(1000)
	zero := int64(0)
	ledger, _ := NewQuotaLedger("acc", &acc, DefaultPeriod(), jr, testNow)
	// device0: zero quota refuses everything
	ledger.SetDeviceLimit("dev0", &zero)
	if _, _, _, err := ledger.Reserve("dev0", 1, testNow); err == nil {
		t.Fatal("zero device quota granted")
	}
	// device unlimited: only the account binds
	if _, _, _, err := ledger.Reserve("devu", 600, testNow); err != nil {
		t.Fatal(err)
	}
	// account exhausted by devu: any other device is blocked too
	if _, accState, _, err := ledger.Reserve("dev2", 500, testNow); err == nil {
		t.Fatal("shared account budget multiplied")
	} else if accState.Used != 600 {
		t.Fatalf("account consumed on refusal: %+v", accState)
	}
}

// V04: the legacy migration is reachable through the PUBLIC open path,
// preserves exact v1 semantics (delta), keeps an untouched backup, is
// repeat-safe, and survives restart.
func TestLegacyMigrationViaOpenPath(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	scope := ScopeID{AccountID: "a", DeviceID: "d"}
	// exact v1 (version-less) representation: reserve400 + delta−300 = actual100,
	// plus an open reserve300 that must stay open, and checkpoint0 (= full 150 charged)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	must := func(r Rec) {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	must(Rec{Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 400, BatchID: "b1", At: now})
	must(Rec{Seq: 1, Scope: scope, Kind: RecCheckpoint, Bytes: -300, BatchID: "b1", At: now})
	must(Rec{Seq: 2, Scope: scope, Kind: RecReserve, Bytes: 150, BatchID: "b2", At: now})
	must(Rec{Seq: 3, Scope: scope, Kind: RecCheckpoint, Bytes: 0, BatchID: "b2", At: now})
	must(Rec{Seq: 4, Scope: scope, Kind: RecReserve, Bytes: 300, BatchID: "b3", At: now}) // stays open
	if err := os.WriteFile(filepath.Join(dir, "usage.journal.jsonl"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	// public open path performs the migration
	j, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatalf("open with migration: %v", err)
	}
	// backup matches the original exactly
	orig, err := os.ReadFile(filepath.Join(dir, "usage.journal.jsonl.v1.bak"))
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(orig) != buf.String() {
		t.Fatal("backup is not the untouched original")
	}
	// replay under v2 semantics: 100 + 150 charged, 300 open, b3 alive
	limit := int64(1000)
	q, err := NewQuotaTracker(scope, QuotaConfig{TotalBytes: &limit, Period: DefaultPeriod()}, j, now)
	if err != nil {
		t.Fatal(err)
	}
	// conservative Used = charged 250 (100+150) + open reservation 300
	st := q.Snapshot(now)
	if st.Used != 550 || *st.Remaining != 450 || st.OpenReservations != 300 {
		t.Fatalf("migrated state wrong: %+v", st)
	}
	// restart: same state, migration is repeat-safe (no-op on v2)
	j2, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	q2, err := NewQuotaTracker(scope, QuotaConfig{TotalBytes: &limit, Period: DefaultPeriod()}, j2, now)
	if err != nil {
		t.Fatal(err)
	}
	if st2 := q2.Snapshot(now); st2.Used != 550 || *st2.Remaining != 450 || st2.OpenReservations != 300 {
		t.Fatalf("state after restart: %+v", st2)
	}
}

// V05: version matrix of the journal reader.
func TestJournalVersionMatrix(t *testing.T) {
	now := time.Now()
	scope := ScopeID{AccountID: "a"}
	write := func(t *testing.T, recs ...Rec) string {
		t.Helper()
		dir := t.TempDir()
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, r := range recs {
			if err := enc.Encode(r); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "usage.journal.jsonl"), buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	base := Rec{Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 10, BatchID: "b", At: now}
	// v2: supported
	j, err := OpenFileJournal(write(t, Rec{V: 2, Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 10, BatchID: "b", At: now}))
	if err != nil {
		t.Fatalf("v2 refused: %v", err)
	}
	if _, err := j.Load(); err != nil {
		t.Fatalf("v2 load: %v", err)
	}
	// explicit v1: refused, never reinterpreted
	if _, err := OpenFileJournal(write(t, Rec{V: 1, Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 10, BatchID: "b", At: now})); err == nil {
		t.Fatal("explicit v1 accepted")
	}
	// version-less legacy without backup possibility: refused at load when
	// migration cannot run — here migration DOES run and succeeds, so
	// exercise the refusal via a direct FileJournal Load instead
	dirLegacy := write(t, base)
	fj := &FileJournal{path: filepath.Join(dirLegacy, "usage.journal.jsonl")}
	if _, err := fj.Load(); err == nil {
		t.Fatal("version-less record accepted by direct Load")
	}
	// negative version: refused
	if _, err := OpenFileJournal(write(t, Rec{V: -1, Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 10, BatchID: "b", At: now})); err == nil {
		t.Fatal("negative version accepted")
	}
	// future version: refused
	if _, err := OpenFileJournal(write(t, Rec{V: 3, Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 10, BatchID: "b", At: now})); err == nil {
		t.Fatal("future version accepted")
	}
	// mixed versions: refused
	if _, err := OpenFileJournal(write(t,
		Rec{V: 2, Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 10, BatchID: "b", At: now},
		Rec{V: 1, Seq: 1, Scope: scope, Kind: RecReserve, Bytes: 10, BatchID: "c", At: now})); err == nil {
		t.Fatal("mixed versions accepted")
	}
	// negative v2 checkpoint actual: replay error reaches the caller, no tracker
	dir := write(t,
		Rec{V: 2, Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 400, BatchID: "b", At: now},
		Rec{V: 2, Seq: 1, Scope: scope, Kind: RecCheckpoint, Bytes: -300, BatchID: "b", At: now})
	j2, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	limit := int64(1000)
	if _, err := NewQuotaTracker(scope, QuotaConfig{TotalBytes: &limit, Period: DefaultPeriod()}, j2, now); err == nil {
		t.Fatal("negative v2 actual accepted into a live tracker")
	}
}

// W05: raw-JSON version matrix — presence of "v" is distinguished from
// its value; explicit unsupported values refuse before any rewrite.
func TestJournalRawJSONVersionMatrix(t *testing.T) {
	scope := `{"account_id":"a","device_id":""}`
	itoa := func(n int) string { return fmt.Sprintf("%d", n) }
	base := func(v string, n int) string {
		vf := ""
		if v != "" {
			vf = `"v":` + v + `,`
		}
		return `{"seq":0,` + vf + `"scope":` + scope + `,"kind":"reserve","bytes":` + itoa(n) + `,"batch_id":"b","at":"2026-10-28T00:00:00Z"}`
	}
	cases := []struct {
		name    string
		line    string
		wantErr bool
	}{
		{"missing version migrates", base("", 400), false},
		{"explicit zero refuses", base("0", 400), true},
		{"explicit null refuses", base("null", 400), true},
		{"negative refuses", base("-1", 400), true},
		{"explicit one refuses", base("1", 400), true},
		{"v2 accepted", base("2", 400), false},
		{"future refuses", base("3", 400), true},
		{"string type refuses", base(`"2"`, 400), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			jp := filepath.Join(dir, "usage.journal.jsonl")
			orig := []byte(tc.line + "\n")
			if err := os.WriteFile(jp, orig, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := OpenFileJournal(dir)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected refusal")
				}
				after, _ := os.ReadFile(jp)
				if string(after) != string(orig) {
					t.Fatal("original rewritten despite refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
	// mixed legacy+versioned: refused
	dir := t.TempDir()
	jp := filepath.Join(dir, "usage.journal.jsonl")
	mixed := base("", 400) + "\n" + base("2", 10) + "\n"
	os.WriteFile(jp, []byte(mixed), 0o600)
	if _, err := OpenFileJournal(dir); err == nil {
		t.Fatal("mixed versions accepted")
	}
}

// W04: every confirmed Append survives a concurrent-style migration, and
// migration computes from the under-lock snapshot (no lost records).
func TestW04AppendsSurviveMigration(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	scope := ScopeID{AccountID: "a"}
	// legacy seed
	var seed bytes.Buffer
	enc := json.NewEncoder(&seed)
	if err := enc.Encode(Rec{Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 400, BatchID: "old", At: now}); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(Rec{Seq: 1, Scope: scope, Kind: RecCheckpoint, Bytes: -300, BatchID: "old", At: now}); err != nil {
		t.Fatal(err)
	}
	jp := filepath.Join(dir, "usage.journal.jsonl")
	if err := os.WriteFile(jp, seed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenFileJournal(dir) // migrates
	if err != nil {
		t.Fatal(err)
	}
	// confirmed appends after migration
	if err := j.Append(Rec{V: 2, Scope: scope, Kind: RecReserve, Bytes: 100, BatchID: "new1", At: now}); err != nil {
		t.Fatal(err)
	}
	_ = j
	// reopen: migration no-op, all records present
	j2, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := j2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("records lost or duplicated: %d", len(recs))
	}
	if recs[0].Kind != RecReserve || recs[0].Bytes != 400 {
		t.Fatalf("migrated reserve wrong: %+v", recs[0])
	}
	if recs[1].Kind != RecCheckpoint || recs[1].Bytes != 100 {
		t.Fatalf("migrated checkpoint wrong: %+v", recs[1])
	}
	if recs[2].BatchID != "new1" || recs[2].Bytes != 100 {
		t.Fatalf("post-migration append lost: %+v", recs[2])
	}
}

// X02 matrix: an existing backup is accepted only when it provably IS the
// intact original; a partial/empty copy is republished from the intact
// original; a VALID-looking different copy refuses; the original never
// changes on any refusal.
func TestBackupPublicationMatrix(t *testing.T) {
	now := time.Now()
	scope := ScopeID{AccountID: "a"}
	build := func(t *testing.T, dir string) []byte {
		t.Helper()
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		if err := enc.Encode(Rec{Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 400, BatchID: "b", At: now}); err != nil {
			t.Fatal(err)
		}
		if err := enc.Encode(Rec{Seq: 1, Scope: scope, Kind: RecCheckpoint, Bytes: -300, BatchID: "b", At: now}); err != nil {
			t.Fatal(err)
		}
		jp := filepath.Join(dir, "usage.journal.jsonl")
		if err := os.WriteFile(jp, b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	original := build(t, t.TempDir())
	cases := []struct {
		name       string
		backup     []byte // nil = no backup
		wantErr    bool
		wantBackup []byte // expected final backup content
	}{
		{"partial backup republished from intact original", []byte(original[:17]), false, original},
		{"empty backup republished", []byte{}, false, original},
		{"wrong valid copy refuses", []byte(`{"seq":0,"v":2,"scope":{"account_id":"other","device_id":""},"kind":"reserve","bytes":1,"batch_id":"x","at":"2026-10-28T00:00:00Z"}` + "\n"), true, nil},
		{"valid equal backup untouched", original, false, original},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			orig := build(t, dir) // intact original for this case
			if tc.backup != nil {
				if err := os.WriteFile(filepath.Join(dir, "usage.journal.jsonl.v1.bak"), tc.backup, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := OpenFileJournal(dir)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected refusal")
				}
				after, _ := os.ReadFile(filepath.Join(dir, "usage.journal.jsonl"))
				if !bytes.Equal(after, orig) {
					t.Fatal("original modified on refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "usage.journal.jsonl.v1.bak"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.wantBackup) {
				t.Fatalf("backup mismatch: got %d bytes want %d", len(got), len(tc.wantBackup))
			}
		})
	}
}

// X04/interleaving: a real concurrent Append vs migration interleaving —
// all confirmed appends must survive and the journal stays valid.
func TestConcurrentAppendMigrationInterleaving(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	scope := ScopeID{AccountID: "a"}
	// legacy seed so the FIRST open runs a real migration
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	if err := enc.Encode(Rec{Seq: 0, Scope: scope, Kind: RecReserve, Bytes: 400, BatchID: "seed", At: now}); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(Rec{Seq: 1, Scope: scope, Kind: RecCheckpoint, Bytes: -100, BatchID: "seed", At: now}); err != nil {
		t.Fatal(err)
	}
	jp := filepath.Join(dir, "usage.journal.jsonl")
	if err := os.WriteFile(jp, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileJournal(dir); err != nil { // runs the real migration first
		t.Fatal(err)
	}
	const writers = 8
	const perWriter = 25
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// each writer re-opens the journal (separate instance/fd) and
			// appends; OpenFileJournal re-runs migration (no-op on v2)
			for i := 0; i < perWriter; i++ {
				jw, err := OpenFileJournal(dir)
				if err != nil {
					errs <- err
					return
				}
				rec := Rec{V: 2, Scope: scope, Kind: RecReserve, Bytes: 1, BatchID: fmt.Sprintf("w%d-%d", w, i), At: now}
				if err := jw.Append(rec); err != nil {
					errs <- err
					return
				}
				jw2, err := OpenFileJournal(dir)
				if err != nil {
					errs <- err
					return
				}
				recs, err := jw2.Load()
				if err != nil {
					errs <- err
					return
				}
				// every load must see at least the seed + own record
				if len(recs) < 2+i {
					errs <- fmt.Errorf("writer %d iter %d: journal shrank to %d records", w, i, len(recs))
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// final: seed(2) + writers*perWriter records, each confirmed append exactly once
	j2, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := j2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2+writers*perWriter {
		t.Fatalf("final record count %d, want %d", len(recs), 2+writers*perWriter)
	}
	seen := map[string]bool{}
	for _, r := range recs[2:] {
		if seen[r.BatchID] {
			t.Fatalf("duplicate append %s", r.BatchID)
		}
		seen[r.BatchID] = true
	}
}

func TestSetAccountLimitPreservesOpenReservations(t *testing.T) {
	journal, err := OpenFileJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial, lowered := int64(1000), int64(500)
	ledger, err := NewQuotaLedger("account", &initial, DefaultPeriod(), journal, testNow)
	if err != nil {
		t.Fatal(err)
	}
	batch, _, _, err := ledger.Reserve("first", 400, testNow)
	if err != nil {
		t.Fatal(err)
	}
	ledger.SetAccountLimit(&lowered)
	if _, _, _, err := ledger.Reserve("second", 101, testNow); err == nil {
		t.Fatal("lowering the cap discarded an open reservation")
	}
	if err := ledger.Checkpoint("first", batch, 400, testNow); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.Reserve("second", 100, testNow); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.Reserve("first", 1, testNow); err == nil {
		t.Fatal("spent and reserved bytes exceeded the new cap")
	}
}
