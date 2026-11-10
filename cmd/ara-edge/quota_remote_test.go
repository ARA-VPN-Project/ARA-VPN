package main

// Edge-side invariants for the remote quota ledger (review FED01): own
// leases are the ONLY offline credit; a crash persists the write-through
// consumption; NOT_OWNER/revocation is a sticky stop, not a cached-credit
// fallback; op_id retries are exactly-once.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aravpn/core/limits"
	"aravpn/internal/controlstore"
)

func facade(t *testing.T, st *controlstore.Store, subID string, seq *int64) *httptest.Server {
	t.Helper()
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Device string `json:"device_id"`
			Used   int64  `json:"used_bytes"`
			Reserve int64 `json:"reserve_bytes"`
			OpID   string `json:"op_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		opKey := "fixture:" + q.OpID
		if opKey == "fixture:" {
			opKey = "fixture:" + fmt_Sprint(atomic.AddInt64(seq, 1))
		}
		resp, _, err := st.QuotaReportOp(opKey, subID, q.Device, q.Used, q.Reserve)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(h.Close)
	return h
}

func fmt_Sprint(v int64) string { return time.Unix(0, v).Format("150405.000000000") }

func seqUnused() *int64 { return nil }

func openSub(t *testing.T) (*controlstore.Store, string, int64) {
	t.Helper()
	st, err := controlstore.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateAccount("a", ""); err != nil {
		t.Fatal(err)
	}
	lim := int64(16 << 20)
	sub, _, err := st.CreateSubscription("a", "t", "owner", &lim, 0)
	if err != nil {
		t.Fatal(err)
	}
	// B04/interim adaptation (documented): admission requires a
	// panel-registered live device with the literal id the fixtures use;
	// the guard checks the bare device part of the panel|device holder
	// against this registry (this file reserves for dev / dev-a / dev-b).
	for _, id := range []string{"dev", "dev-a", "dev-b"} {
		if err := st.RegisterTestDevice("a", id); err != nil {
			t.Fatal(err)
		}
	}
	return st, sub.ID, lim
}

// TestOwnLeasesAreTheOnlyOfflineCredit: with the owner reachable the edge
// accumulates grants; after the owner dies it may spend ONLY what it
// holds, never the global remaining.
func TestOwnLeasesAreTheOnlyOfflineCredit(t *testing.T) {
	st, sub, limit := openSub(t)
	seq := int64(0)
	h := facade(t, st, sub, &seq)
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h.URL,
		PanelID: "edge-x", LeaseBytes: 1 << 20}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const chunk = 512 << 10
	// ONE online round: grants 1 MiB, consumes 512 KiB (reported later);
	// the remaining 512 KiB of the OWN lease is the only offline credit
	b, _, _, err := edge.Reserve("dev", chunk, time.Now())
	if err != nil || b == nil {
		t.Fatal(err)
	}
	_ = edge.Checkpoint("dev", b, b.Reserved, time.Now())
	h.Close() // owner gone
	admitted := int64(0)
	for i := 0; i < 100; i++ {
		b, _, _, err := edge.Reserve("dev", chunk, time.Now())
		if err != nil || b == nil || b.Reserved <= 0 {
			break
		}
		admitted += b.Reserved
		_ = edge.Checkpoint("dev", b, b.Reserved, time.Now())
	}
	// offline spend must be bounded by the un-consumed half of the own
	// lease (512 KiB), NOT by the global remaining (16 MiB)
	if admitted > 1<<20 {
		t.Fatalf("offline spend exceeded own leases: admitted=%d", admitted)
	}
	if admitted != chunk {
		t.Fatalf("edge must spend exactly its un-consumed lease offline: admitted=%d", admitted)
	}
	_ = limit
}

// TestCrashPreservesWriteThroughConsumption: a restarted ledger (same
// state dir) must not rediscover spendable credit its predecessor spent.
func TestCrashPreservesWriteThroughConsumption(t *testing.T) {
	st, sub, _ := openSub(t)
	seq := int64(0)
	h := facade(t, st, sub, &seq)
	dir := t.TempDir()
	cfg := remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h.URL, PanelID: "edge-y", LeaseBytes: 1 << 20}
	edge, err := newRemoteQuotaLedger(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	const chunk = 512 << 10
	b, _, _, err := edge.Reserve("dev", chunk, time.Now())
	if err != nil || b == nil {
		t.Fatal(err)
	}
	_ = edge.Checkpoint("dev", b, chunk, time.Now())
	// simulate a crash: a NEW ledger instance on the same state dir
	edge2, err := newRemoteQuotaLedger(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	st2 := edge2.AccountState(time.Now())
	if st2.Remaining == nil || *st2.Remaining > 1<<20-chunk {
		t.Fatalf("restart must keep the write-through consumption: %+v", st2)
	}
	h.Close()
}

// TestStickyStopOnNotOwner: after ownership transfer the edge STOPS; the
// stop survives restarts; it is never treated as a network error.
func TestStickyStopOnNotOwner(t *testing.T) {
	st, sub, _ := openSub(t)
	var seq int64
	h := facadeNOTOwner(t, st, sub, &seq)
	dir := t.TempDir() // ONE state dir: the stop state is durable there
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h.URL,
		PanelID: "edge-z", LeaseBytes: 1 << 20}, dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = edge.Reserve("dev", 512<<10, time.Now())
	if err == nil || !strings.Contains(err.Error(), "NOT_OWNER") {
		t.Fatalf("NOT_OWNER must surface: %v", err)
	}
	// sticky: subsequent reserves refuse even if the owner comes back
	h.Close()
	h2 := facade(t, st, sub, &seq) // healthy owner now
	defer h2.Close()
	_, stt, _, err := edge.Reserve("dev", 512<<10, time.Now())
	if err == nil || !stt.Exhausted || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("stop must be sticky: %v %+v", err, stt)
	}
	// survives restart on the SAME state dir (a fresh dir is a fresh
	// deployment, documented in FEDERATION.md)
	edge2, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h2.URL,
		PanelID: "edge-z", LeaseBytes: 1 << 20}, dir)
	if err != nil {
		t.Fatal(err)
	}
	_, stt2, _, err := edge2.Reserve("dev", 512<<10, time.Now())
	if err == nil || !stt2.Exhausted || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("stop must survive restart: %v %+v", err, stt2)
	}
}

func facadeNOTOwner(t *testing.T, st *controlstore.Store, subID string, seq *int64) *httptest.Server {
	t.Helper()
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "NOT_OWNER", "owner": "someone-else"})
	}))
	t.Cleanup(h.Close)
	return h
}

// TestRevokedSubscriptionStopsEdge: 401 from the owner → sticky stop.
func TestRevokedSubscriptionStopsEdge(t *testing.T) {
	_, sub, _ := openSub(t)
	_ = sub
	_ = seqUnused()
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{"error": "AUTH_FAILED: subscription revoked"})
	}))
	defer h.Close()
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h.URL,
		PanelID: "edge-r", LeaseBytes: 1 << 20}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = edge.Reserve("dev", 512<<10, time.Now())
	if err == nil || !strings.Contains(err.Error(), "stopping") {
		t.Fatalf("revocation must stop the edge: %v", err)
	}
	_ = errors.Is
}

// TestOpIdRetryExactlyOnce: a lost response retried with the SAME op id
// (new nonce) is answered from the owner's record; the edge clears the
// pending delta exactly once.
func TestOpIdRetryExactlyOnce(t *testing.T) {
	st, sub, _ := openSub(t)
	var reports int64
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Device string `json:"device_id"`
			Used   int64  `json:"used_bytes"`
			Reserve int64 `json:"reserve_bytes"`
			OpID   string `json:"op_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Used > 0 {
			atomic.AddInt64(&reports, 1)
		}
		resp, _, err := st.QuotaReportOp("fixture:"+q.OpID, sub, q.Device, q.Used, q.Reserve)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer h.Close()
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h.URL,
		PanelID: "edge-o", LeaseBytes: 1 << 20}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const chunk = 512 << 10
	// two local admissions exactly consume the 1 MiB lease; only the
	// THIRD reserve (lease exhausted) carries the pending report
	for i := 0; i < 2; i++ {
		b, _, _, err := edge.Reserve("dev", chunk, time.Now())
		if err != nil || b == nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if err := edge.Checkpoint("dev", b, chunk, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	b3, _, _, err := edge.Reserve("dev", chunk, time.Now())
	if err != nil || b3 == nil {
		t.Fatalf("third reserve: %v", err)
	}
	if reports != 1 {
		t.Fatalf("consumption must be reported once: %d", reports)
	}
	used, _, _ := st.QuotaUsage(sub)
	if used != 2*chunk {
		t.Fatalf("owner ledger: used=%d want=%d", used, 2*chunk)
	}
}

// TestLeasesArePerDeviceOnEdge (FED04 edge side): one device's grants are
// not spendable by another device on the same edge — admission draws only
// from the device's own outstanding leases, offline included.
func TestLeasesArePerDeviceOnEdge(t *testing.T) {
	st, sub, _ := openSub(t)
	var seq int64
	h := facade(t, st, sub, &seq)
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h.URL,
		PanelID: "edge-pd", LeaseBytes: 1 << 20}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const chunk = 512 << 10
	b, _, _, err := edge.Reserve("dev-a", chunk, time.Now())
	if err != nil || b == nil {
		t.Fatal(err)
	}
	_ = edge.Checkpoint("dev-a", b, b.Reserved, time.Now())
	h.Close() // owner gone: only outstanding leases are spendable
	// dev-b has NO outstanding leases: nothing to spend, even though the
	// edge holds dev-a's credit
	b2, st2, _, err := edge.Reserve("dev-b", chunk, time.Now())
	if err == nil && b2 != nil && b2.Reserved > 0 {
		t.Fatalf("device-b spent device-a's grant: %+v", b2)
	}
	if st2.Remaining == nil || *st2.Remaining != 0 {
		t.Fatalf("device-b must see zero own credit: %+v", st2)
	}
	// dev-a keeps spending exactly its own un-consumed half
	b3, _, _, err := edge.Reserve("dev-a", chunk, time.Now())
	if err != nil || b3 == nil || b3.Reserved != chunk {
		t.Fatalf("device-a own credit: %v %+v", err, b3)
	}
}

// TestRateShareChainToLimiter: the share the owner grants must translate
// into a WORKING limiter (never a forbidden direction) across the decay
// path — review FED05 "обновление поколения не должно бесконечно
// пополнять token-burst" and the observed download refusal.
func TestRateShareChainToLimiter(t *testing.T) {
	st, sub, _ := openSub(t)
	rate := int64(375000)
	if err := st.SetSubscriptionRate(sub, &rate, &rate); err != nil {
		t.Fatal(err)
	}
	var seq int64
	h := facade(t, st, sub, &seq)
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: sub, OwnerURL: h.URL,
		PanelID: "edge-rt", LeaseBytes: 1 << 20}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const chunk = 512 << 10
	// burn a lease so the edge reports and receives its share
	b, _, _, err := edge.Reserve("dev", chunk, time.Now())
	if err != nil || b == nil {
		t.Fatal(err)
	}
	_ = edge.Checkpoint("dev", b, b.Reserved, time.Now())
	b2, _, _, err := edge.Reserve("dev", chunk, time.Now())
	if err != nil || b2 == nil {
		t.Fatal(err)
	}
	down, up, gen := edge.RateShare()
	if gen == 0 || down == nil || up == nil {
		t.Fatalf("no share after report: %v %v gen=%d", down, up, gen)
	}
	if *down <= 0 || *up <= 0 {
		t.Fatalf("zero share would forbid the direction: down=%d up=%d", *down, *up)
	}
	// the share must build a WORKING limiter (Take grants, not forbidden)
	regime, err := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: down, UploadBPS: up}, time.Now())
	if err != nil {
		t.Fatalf("regime from share: %v", err)
	}
	lim, err := regime.BindDevice(limits.RateConfig{DownloadBPS: down, UploadBPS: up}, time.Now())
	if err != nil {
		t.Fatalf("bind from share: %v", err)
	}
	if r := lim.Take(limits.Download, 16<<10, time.Now()); !r.Granted {
		t.Fatalf("share-built limiter refuses download: %+v (share=%d)", r, *down)
	}
	// the decay path keeps the direction workable too
	stale := time.Now().Unix() - 4*int64(rateRightTTL.Seconds())
	edge.mu.Lock()
	edge.rateUpdateAt = stale
	edge.mu.Unlock()
	d2, _, gen2 := edge.RateShare()
	if d2 == nil || *d2 <= 0 {
		t.Fatalf("decayed share must stay positive: %v", d2)
	}
	regime2, err := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: d2, UploadBPS: up}, time.Now())
	if err != nil {
		t.Fatalf("decayed regime: %v", err)
	}
	lim2, _ := regime2.BindDevice(limits.RateConfig{DownloadBPS: d2, UploadBPS: up}, time.Now())
	// the decayed share SHAPES (RetryAfter) — only a forbidden direction
	// would be a defect
	if r := lim2.Take(limits.Download, 16<<10, time.Now()); r.Forbidden {
		t.Fatalf("decayed limiter forbids download: %+v (share=%d)", r, *d2)
	}
	_ = gen2
}

// Review 2026-11-01 rate checklist (FED07/FED08): explicit rate right
// states, per-direction independence, deadline expiry, restart
// persistence, and no burst re-minting on repeated renewals.

// zero right on a NEW holder must forbid; a LATER positive grant must
// admit; down and up are independent.
func TestZeroRightThenLaterPositiveGrant(t *testing.T) {
	zero, pos := int64(0), int64(200000) // multiple of 8 bit/s
	var share atomic.Value // stores [2]*int64
	share.Store([2]*int64{&zero, &zero})
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh := share.Load().([2]*int64)
		json.NewEncoder(w).Encode(map[string]any{"granted": 1048576,
			"rate_share_down_bps": sh[0], "rate_share_up_bps": sh[1]})
	}))
	defer h.Close()
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: "s", OwnerURL: h.URL,
		PanelID: "edge-z", LeaseBytes: 1 << 20}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edge.reportAndRequest("dev", 1<<20); err != nil {
		t.Fatal(err)
	}
	down, up, _ := edge.RateShare()
	if down == nil || *down != 0 || up == nil || *up != 0 {
		t.Fatalf("zero rights must be explicit: %v %v", down, up)
	}
	reg, err := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: down, UploadBPS: up}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lim, _ := reg.BindDevice(limits.RateConfig{}, time.Now())
	if lim.Take(limits.Download, 1024, time.Now()).Granted {
		t.Fatal("zero right admits download")
	}
	if lim.Take(limits.Upload, 1024, time.Now()).Granted {
		t.Fatal("zero right admits upload")
	}
	// later positive grant for DOWN only: up stays zero. Documented
	// adaptation: since B01 the reserve path skips the owner round-trip when
	// own credit already covers the request, so rate-share refresh (this
	// step) goes through the same n=0 sync call the periodic sync uses.
	posCopy := pos
	share.Store([2]*int64{&posCopy, &zero})
	if _, err := edge.reportAndRequest("dev", 0); err != nil {
		t.Fatal(err)
	}
	down2, up2, _ := edge.RateShare()
	if down2 == nil || *down2 != pos {
		t.Fatalf("positive down grant: %v", down2)
	}
	if up2 == nil || *up2 != 0 {
		t.Fatalf("up must stay explicitly zero: %v", up2)
	}
	reg2, _ := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: down2, UploadBPS: up2}, time.Now())
	lim2, _ := reg2.BindDevice(limits.RateConfig{}, time.Now())
	if !lim2.Take(limits.Download, 1024, time.Now()).Granted {
		t.Fatal("positive down right must admit")
	}
	if lim2.Take(limits.Upload, 1024, time.Now()).Granted {
		t.Fatal("zero up right must still forbid")
	}
}

// expiry: a right whose deadline passed is enforced as ZERO — the owner
// freed and redistributed it (no 1/8 floor forever); restart keeps the
// state (the deadline is durable).
func TestRateRightExpiresByDeadline(t *testing.T) {
	pos := int64(187500)
	var share atomic.Value
	share.Store([2]*int64{&pos, &pos})
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh := share.Load().([2]*int64)
		json.NewEncoder(w).Encode(map[string]any{"granted": 1048576,
			"rate_share_down_bps": sh[0], "rate_share_up_bps": sh[1]})
	}))
	defer h.Close()
	dir := t.TempDir()
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: "s", OwnerURL: h.URL,
		PanelID: "edge-e", LeaseBytes: 1 << 20}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edge.reportAndRequest("dev", 1<<20); err != nil {
		t.Fatal(err)
	}
	// force the deadline into the past (durable state edit — no sleeps)
	edge.mu.Lock()
	edge.st.RateDeadlineDown = time.Now().Unix() - 10
	edge.st.RateDeadlineUp = time.Now().Unix() - 10
	_ = edge.persistLocked() // the deadline is durable state
	edge.mu.Unlock()
	down, up, _ := edge.RateShare()
	if down == nil || *down != 0 || up == nil || *up != 0 {
		t.Fatalf("expired rights must enforce zero: %v %v", down, up)
	}
	// restart on the same state dir: the deadline survives
	edge2, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: "s", OwnerURL: h.URL,
		PanelID: "edge-e", LeaseBytes: 1 << 20}, dir)
	if err != nil {
		t.Fatal(err)
	}
	down2, _, _ := edge2.RateShare()
	if down2 == nil || *down2 != 0 {
		t.Fatalf("expired right must stay zero after restart: %v", down2)
	}
}

// same share and frequent renewals never mint another burst (FED08 on
// the edge side): the limiter state is preserved, not rebuilt.
func TestFrequentRenewalsDoNotMintBursts(t *testing.T) {
	pos := int64(1000000)
	var share atomic.Value
	share.Store([2]*int64{&pos, &pos})
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh := share.Load().([2]*int64)
		json.NewEncoder(w).Encode(map[string]any{"granted": 1 << 20,
			"rate_share_down_bps": sh[0], "rate_share_up_bps": sh[1]})
	}))
	defer h.Close()
	edge, err := newRemoteQuotaLedger(remoteQuotaConfig{SubscriptionID: "s", OwnerURL: h.URL,
		PanelID: "edge-m", LeaseBytes: 1 << 20}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// repeated reports with the SAME share: RateShare must not change the
	// effective value (gen stable)
	if _, err := edge.reportAndRequest("dev", 1<<20); err != nil {
		t.Fatal(err)
	}
	d1, _, g1 := edge.RateShare()
	for i := 0; i < 5; i++ {
		if _, err := edge.reportAndRequest("dev", 0); err != nil {
			t.Fatal(err)
		}
	}
	d2, _, g2 := edge.RateShare()
	if d1 == nil || d2 == nil || *d1 != *d2 {
		t.Fatalf("same share must not change: %v → %v", d1, d2)
	}
	if g2 != g1 {
		t.Fatalf("generation must reflect real changes only: %d → %d", g1, g2)
	}
	// the datapath chain: same-rate reapply must not re-mint the burst
	// (documented adaptation: since B20 the rebind is per-ACCOUNT)
	dp := &edgeDatapath{}
	dp.applyAccountRate("legacy", d1, d1)
	start := time.Now()
	if !dp.limiter.Take(limits.Download, 125000, start).Granted {
		t.Fatal("initial burst refused")
	}
	dp.applyAccountRate("legacy", d1, d1) // same share again
	if now := time.Now(); now.Sub(start) < time.Second {
		if dp.limiter.Take(limits.Download, 125000, now).Granted {
			t.Fatal("same-rate reapply minted a second burst")
		}
	}
}
