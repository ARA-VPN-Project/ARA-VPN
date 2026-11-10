package limits

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ReservationBatch is the durable budget batch reserved from the quota
// before any payload passes. Batch sizing bounds the maximum possible
// overcount (crash before checkpoint counts the whole batch as used);
// usage is never undercounted, the documented deviation is conservative
// (docs/LIMITS_QUOTAS.md).
type ReservationBatch struct {
	ID       string
	Reserved int64
}

// newBatchID returns a globally unique durable reservation identifier,
// independent of journal sequencing (review R03: after a restart the
// journal sequence restarts its meaning, but reservation identity must
// never collide — a collision would silently replace an open reservation
// and give away its bytes).
func newBatchID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure must never degrade into a predictable or
		// reused identifier: refuse the reservation instead.
		return ""
	}
	return "r-" + hex.EncodeToString(b[:])
}

// QuotaTracker enforces one scope's volume quota against a durable journal.
// usage = checkpoints + open reservations (conservative after crash).
type QuotaTracker struct {
	mu          sync.Mutex
	scope       ScopeID
	cfg         QuotaConfig
	jr          Journal
	seq         uint64 // highest journal seq this process observed
	open        map[string]*ReservationBatch
	closed      map[string]bool // batch IDs durably checkpointed: replay/retry is a no-op (review S07)
	retired     map[string]bool // batches of a closed period: late checkpoints are no-ops
	used        int64           // checkpointed usage in the current window
	windowStart time.Time
}

// NewQuotaTracker loads the journal and reconstructs state. Records outside
// the current period window are ignored for enforcement but preserved on
// disk for audit.
func NewQuotaTracker(scope ScopeID, cfg QuotaConfig, jr Journal, now time.Time) (*QuotaTracker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	recs, err := jr.Load()
	if err != nil {
		return nil, err
	}
	start, _, err := cfg.Period.Window(now)
	if err != nil {
		return nil, err
	}
	t := &QuotaTracker{
		scope:       scope,
		cfg:         cfg,
		jr:          jr,
		open:        map[string]*ReservationBatch{},
		closed:      map[string]bool{},
		retired:     map[string]bool{},
		windowStart: start,
	}
	for _, r := range recs {
		if r.Seq >= t.seq {
			t.seq = r.Seq
		}
		if r.Scope != scope || r.At.Before(start) {
			continue
		}
		// V05: a corrupt record must reach the caller as an error —
		// a tracker over a rejected journal is never returned.
		if err := t.applyReplayLocked(r); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *QuotaTracker) applyReplayLocked(r Rec) error {
	switch r.Kind {
	case RecReserve:
		t.open[r.BatchID] = &ReservationBatch{ID: r.BatchID, Reserved: r.Bytes}
	case RecCheckpoint:
		// v2 actual semantics: a negative charged amount is a corrupt
		// record, not an allowance (review T07)
		if r.V >= 2 && r.Bytes < 0 {
			return fmt.Errorf("journal record seq %d: negative checkpoint actual %d is invalid", r.Seq, r.Bytes)
		}
		// v2 semantics: a checkpoint record carries the ACTUAL charged
		// bytes for its scope. Applying it twice must not charge twice
		// (review S07): a batch already in closed is skipped, an open
		// batch is closed with the recorded actual, an unknown positive
		// record counts conservatively. Negative records are ignored —
		// they must never create free allowance.
		if t.closed[r.BatchID] {
			return nil
		}
		if b := t.open[r.BatchID]; b != nil {
			t.used += r.Bytes
			delete(t.open, r.BatchID)
			t.closed[r.BatchID] = true
		} else if r.Bytes > 0 {
			t.used += r.Bytes
			t.closed[r.BatchID] = true
		}
	case RecAdjust:
		t.used += r.Bytes
	}
	return nil
}

// rollWindowLocked switches to the period containing now when the tracker
// has lived past its boundary (review R08: a running process must enter
// the new period without a restart). Open reservations of the closed
// window belong to the closed budget: they are retired, not carried into
// the new window, and a late checkpoint referencing them is a recorded
// no-op (their transfer either happened inside the old window's budget or
// never happened).
func (t *QuotaTracker) rollWindowLocked(now time.Time) error {
	start, _, err := t.cfg.Period.Window(now)
	if err != nil {
		return err
	}
	if !start.After(t.windowStart) {
		return nil // still inside (or before) the known window
	}
	for id := range t.open {
		t.retired[id] = true
	}
	t.open = map[string]*ReservationBatch{}
	t.used = 0
	t.windowStart = start
	return nil
}

// State is the published quota view.
type State struct {
	Limit            *int64    `json:"limit_bytes"` // nil = unlimited
	Used             int64     `json:"used_bytes"`
	Remaining        *int64    `json:"remaining_bytes"` // nil = unlimited
	ResetAt          time.Time `json:"reset_at"`
	Exhausted        bool      `json:"exhausted"`
	OpenReservations int64     `json:"open_reservations_bytes"`
	ThresholdHit     string    `json:"threshold_hit,omitempty"` // "", "80", "95", "100"
}

// Snapshot returns the current quota state, rolling the period window if
// the tracker has lived past its boundary.
func (t *QuotaTracker) Snapshot(now time.Time) State {
	t.mu.Lock()
	defer t.mu.Unlock()
	_ = t.rollWindowLocked(now)
	return t.snapshotLocked(now)
}

func (t *QuotaTracker) snapshotLocked(now time.Time) State {
	s := State{ResetAt: mustReset(t.cfg.Period, now)}
	if t.cfg.TotalBytes == nil {
		return s
	}
	limit := *t.cfg.TotalBytes
	open := int64(0)
	for _, b := range t.open {
		open += b.Reserved
	}
	s.Limit = &limit
	conservative := t.used + open
	s.Used = conservative
	s.OpenReservations = open
	rem := limit - conservative
	if rem < 0 {
		rem = 0
	}
	s.Remaining = &rem
	s.Exhausted = rem <= 0
	s.ThresholdHit = thresholdLabel(conservative, limit)
	return s
}

func mustReset(p Period, now time.Time) time.Time {
	end, err := p.ResetAt(now)
	if err != nil {
		return time.Time{}
	}
	return end
}

func thresholdLabel(used, limit int64) string {
	if limit <= 0 {
		return "100"
	}
	switch r := float64(used) / float64(limit); {
	case r >= 1:
		return "100"
	case r >= 0.95:
		return "95"
	case r >= 0.80:
		return "80"
	default:
		return ""
	}
}

// Reserve durably books n bytes and returns the batch to reconcile with
// Checkpoint after actual transfer. It refuses when the durable remainder
// cannot cover the batch: no chargeable traffic passes on an unverifiable
// budget, and a disk-full journal is a hard stop, not unlimited
// (docs/LIMITS_QUOTAS.md).
func (t *QuotaTracker) Reserve(n int64, now time.Time) (*ReservationBatch, State, error) {
	batchID := newBatchID()
	if batchID == "" {
		return nil, State{}, fmt.Errorf("QUOTA_UNSAFE: cannot generate a unique reservation id")
	}
	return t.ReserveWithID(batchID, n, now)
}

// ReserveWithID books n bytes under a caller-provided globally unique id.
// The ledger uses it so the account scope and the device scope share one
// reservation identity and the pair can be reconciled (and replayed after
// a crash) with the same identifier.
func (t *QuotaTracker) ReserveWithID(batchID string, n int64, now time.Time) (*ReservationBatch, State, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n < 0 {
		return nil, State{}, fmt.Errorf("negative reservation")
	}
	if err := t.rollWindowLocked(now); err != nil {
		return nil, State{}, err
	}
	if t.cfg.TotalBytes == nil {
		return &ReservationBatch{ID: batchID}, t.snapshotLocked(now), nil
	}
	limit := *t.cfg.TotalBytes
	committed := t.used
	for _, b := range t.open {
		committed += b.Reserved
	}
	if committed+n > limit {
		return nil, t.snapshotLocked(now), fmt.Errorf("QUOTA_EXHAUSTED: %d bytes requested, %d remain", n, limit-committed)
	}
	rec := Rec{Scope: t.scope, Kind: RecReserve, Bytes: n, BatchID: batchID, At: now.UTC()}
	if err := t.jr.Append(rec); err != nil {
		// durable failure: refuse chargeable traffic rather than continue
		// on an unverifiable budget.
		return nil, t.snapshotLocked(now), fmt.Errorf("quota journal unavailable: %w", err)
	}
	t.open[batchID] = &ReservationBatch{ID: batchID, Reserved: n}
	return &ReservationBatch{ID: batchID, Reserved: n}, t.snapshotLocked(now), nil
}

// Checkpoint closes a reservation with the bytes actually admitted. The
// journal record stores the ACTUAL bytes (v2, review S07): replay and
// retry are idempotent — a batch in closed is skipped, so a checkpoint
// that already reached the journal can never be charged twice, and a
// partially failed pair (ledger: account committed, device not) is
// repaired by re-running the same Checkpoint. A checkpoint for a batch
// retired with its closed period is a recorded no-op against the new
// window. Returns whether a NEW journal record was written.
func (t *QuotaTracker) Checkpoint(batch *ReservationBatch, actual int64, now time.Time) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_ = t.rollWindowLocked(now)
	if t.cfg.TotalBytes == nil {
		return false, nil
	}
	if t.closed[batch.ID] {
		return false, nil // already durably checkpointed
	}
	if t.retired[batch.ID] {
		t.closed[batch.ID] = true
		rec := Rec{Scope: t.scope, Kind: RecCheckpoint, Bytes: 0, BatchID: batch.ID, At: now.UTC()}
		if err := t.jr.Append(rec); err != nil {
			t.closed[batch.ID] = false
			return false, fmt.Errorf("quota journal unavailable: %w", err)
		}
		return true, nil
	}
	open, ok := t.open[batch.ID]
	if !ok {
		return false, fmt.Errorf("checkpoint for unknown batch %q", batch.ID)
	}
	if actual < 0 || actual > open.Reserved {
		return false, fmt.Errorf("checkpoint %d outside reserved %d", actual, open.Reserved)
	}
	rec := Rec{Scope: t.scope, Kind: RecCheckpoint, Bytes: actual, BatchID: batch.ID, At: now.UTC()}
	if err := t.jr.Append(rec); err != nil {
		return false, fmt.Errorf("quota journal unavailable: %w", err)
	}
	t.used += actual
	delete(t.open, batch.ID)
	t.closed[batch.ID] = true
	return true, nil
}

// SetLimit atomically updates the quota limit of a LIVE tracker without
// touching usage, open reservations or the journal (review T08): lowering
// to 0 forbids new reservations immediately, raising/null restores
// capacity, and spent history survives restarts.
func (t *QuotaTracker) SetLimit(newLimit *int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg.TotalBytes = newLimit
}

// Adjust applies an operator correction with audit metadata. Adjustments
// are journaled and replayed; they require the control plane's operator
// role (enforced by callers).
func (t *QuotaTracker) Adjust(delta int64, actor string, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	_ = t.rollWindowLocked(now)
	if t.cfg.TotalBytes == nil {
		return fmt.Errorf("adjustment applies only to limited scopes")
	}
	rec := Rec{Scope: t.scope, Kind: RecAdjust, Bytes: delta, At: now.UTC(), Actor: actor}
	if err := t.jr.Append(rec); err != nil {
		return fmt.Errorf("quota journal unavailable: %w", err)
	}
	t.used += delta
	return nil
}

// QuotaLedger is the single authoritative owner of volume accounting for
// one account and its devices (review R04): one shared journal, one
// account-scope tracker and per-device trackers. Every admission debits
// the shared account budget and the device budget atomically — a refusal
// on either side refunds the other, so device count cannot multiply the
// account budget and no device can bypass it.
type QuotaLedger struct {
	account ScopeID
	limit   *int64
	period  Period
	jr      Journal

	mu           sync.Mutex
	accountT     *QuotaTracker
	devices      map[string]*QuotaTracker
	deviceLimits map[string]*int64
}

// NewQuotaLedger builds the ledger from the shared journal. The account
// scope (empty DeviceID) is the shared budget across all devices.
func NewQuotaLedger(accountID string, limit *int64, period Period, jr Journal, now time.Time) (*QuotaLedger, error) {
	accountScope := ScopeID{AccountID: accountID}
	at, err := NewQuotaTracker(accountScope, QuotaConfig{TotalBytes: limit, Period: period}, jr, now)
	if err != nil {
		return nil, err
	}
	return &QuotaLedger{
		account:      accountScope,
		limit:        limit,
		period:       period,
		jr:           jr,
		accountT:     at,
		devices:      map[string]*QuotaTracker{},
		deviceLimits: map[string]*int64{},
	}, nil
}

// AccountState returns the shared account-scope snapshot: the budget of
// the whole account including every device's committed spend and open
// reservations (review S05).
func (l *QuotaLedger) AccountState(now time.Time) State {
	return l.accountT.Snapshot(now)
}

// DeviceTracker returns (creating on first use) the device-scope tracker.
func (l *QuotaLedger) DeviceTracker(deviceID string, now time.Time) (*QuotaTracker, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.deviceTrackerLocked(deviceID, now)
}

func (l *QuotaLedger) deviceTrackerLocked(deviceID string, now time.Time) (*QuotaTracker, error) {
	if t, ok := l.devices[deviceID]; ok {
		return t, nil
	}
	// effective device limit: explicit override, otherwise the account
	// limit keeps per-device accounting meaningful in the shared journal
	deviceLimit := l.limit
	if ov, ok := l.deviceLimits[deviceID]; ok {
		deviceLimit = ov
	}
	t, err := NewQuotaTracker(ScopeID{AccountID: l.account.AccountID, DeviceID: deviceID},
		QuotaConfig{TotalBytes: deviceLimit, Period: l.period}, l.jr, now)
	if err != nil {
		return nil, err
	}
	l.devices[deviceID] = t
	return t, nil
}

// Reserve debits both scopes. The account reservation is journaled first;
// if the device scope then refuses, the account reservation is checkpointed
// back to zero so refusals never consume the shared budget.
func (l *QuotaLedger) Reserve(deviceID string, n int64, now time.Time) (*ReservationBatch, State, State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	dev, err := l.deviceTrackerLocked(deviceID, now)
	if err != nil {
		return nil, State{}, State{}, err
	}
	batchID := newBatchID()
	if batchID == "" {
		return nil, State{}, State{}, fmt.Errorf("QUOTA_UNSAFE: cannot generate a unique reservation id")
	}
	ab, aState, err := l.accountT.ReserveWithID(batchID, n, now)
	if err != nil {
		return nil, aState, State{}, err
	}
	db, dState, err := dev.ReserveWithID(batchID, n, now)
	if err != nil {
		// release the account-side reservation; journal stays consistent
		if _, cerr := l.accountT.Checkpoint(ab, 0, now); cerr != nil {
			return nil, aState, dState, fmt.Errorf("account refund failed after device refusal: %v (device error: %w)", cerr, err)
		}
		return nil, l.accountT.Snapshot(now), dState, err
	}
	return db, aState, dState, nil
}

// SetAccountLimit updates the shared budget while preserving open reservations and usage.
func (l *QuotaLedger) SetAccountLimit(limit *int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limit = limit
	l.accountT.SetLimit(limit)
	for id, tracker := range l.devices {
		if _, overridden := l.deviceLimits[id]; !overridden {
			tracker.SetLimit(limit)
		}
	}
}

// SetDeviceLimit overrides the volume limit of one device (additional to
// the shared account budget; review S05/S07/T08). nil = unlimited. The
// update applies to an ALREADY CREATED live tracker atomically — spent
// usage and open reservations are preserved, a lowered limit (0)
// immediately forbids new reservations. Devices without an override
// inherit the account limit so that per-device accounting stays
// meaningful in the shared journal.
func (l *QuotaLedger) SetDeviceLimit(deviceID string, limit *int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.deviceLimits[deviceID] = limit
	if t, ok := l.devices[deviceID]; ok {
		t.SetLimit(limit)
	}
}

// Checkpoint reconciles BOTH scopes for the same transfer. Each scope
// writes its own idempotent checkpoint record carrying the ACTUAL bytes;
// a failure after the first scope's record leaves that scope closed and
// the other open, and re-running the same Checkpoint repairs exactly the
// open one without charging anything twice (review S07).
func (l *QuotaLedger) Checkpoint(deviceID string, batch *ReservationBatch, actual int64, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	dev, err := l.deviceTrackerLocked(deviceID, now)
	if err != nil {
		return err
	}
	if _, err := l.accountT.Checkpoint(batch, actual, now); err != nil {
		return err
	}
	_, err = dev.Checkpoint(batch, actual, now)
	return err
}
