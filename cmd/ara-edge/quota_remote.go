// Remote shared quota for serving edges (docs/FEDERATION.md): the
// subscription's OWNER panel keeps the single authoritative ledger; every
// serving edge receives DURABLE LEASES (unique grant per request, capped
// by the global budget) and may admit offline ONLY within its own
// still-open lease amounts. Properties (review FED01):
//   - the global remaining is DISPLAY data, never spendable credit;
//   - every admission is written through to the local lease state BEFORE
//     the batch is returned, so a crash cannot over-admit after restart;
//   - consumption reports are idempotent by a stable op_id (the client
//     half of FED02): a lost response is retried with the SAME op id and
//     the owner replays the recorded response — bytes are charged once;
//   - revoked subscription / NOT_OWNER is a STICKY STOP, never a network
//     error that falls back to arbitrary cached credit;
//   - owner unreachable ⇒ serve strictly from own outstanding leases;
//     no outstanding lease ⇒ block.
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aravpn/core/fedauth"
	"aravpn/core/limits"
)

// quotaLedger is the enforcement surface ara-edge needs. The local
// QuotaLedger and the remote reservation ledger both implement it.
type quotaLedger interface {
	SetDeviceLimit(deviceID string, limit *int64)
	AccountState(now time.Time) limits.State
	Reserve(deviceID string, n int64, now time.Time) (*limits.ReservationBatch, limits.State, limits.State, error)
	Checkpoint(deviceID string, batch *limits.ReservationBatch, actual int64, now time.Time) error
}

// rateRightTTL mirrors the owner's RateRightTTL: without a renewal the
// enforced share decays (halved per TTL, floored at an eighth).
const rateRightTTL = 30 * time.Second

// remoteQuotaConfig lives in edge config: {"subscription_id","owner_url","panel_id","lease_bytes"}.
type remoteQuotaConfig struct {
	SubscriptionID string `json:"subscription_id"`
	OwnerURL       string `json:"owner_url"`
	PanelID        string `json:"panel_id"`
	LeaseBytes     int64  `json:"lease_bytes,omitempty"`
	// InviteToken is the ONE-TIME federation invite issued by the owner
	// panel for this edge: on the first "panel not linked" refusal the
	// edge redeems it itself (scope: quota) and retries.
	InviteToken string `json:"invite_token,omitempty"`
	// StateFile (B20): per-subscription ledger snapshot filename inside
	// the edge state dir — several served subscriptions must never share
	// one snapshot file (that would spend one credit twice).
	StateFile string `json:"state_file,omitempty"`
}

// remoteLease is one locally-held grant. Consumed is written through at
// Reserve time: the admission is durable BEFORE any payload flows, so a
// crash mid-transfer can only UNDER-use the grant, never exceed it.
type remoteLease struct {
	ID       string `json:"id"`
	Amount   int64  `json:"amount"`
	Consumed int64  `json:"consumed"`
	Expires  int64  `json:"expires_unix"`
}

func (l *remoteLease) available(now time.Time) int64 {
	if now.Unix() >= l.Expires {
		return 0
	}
	a := l.Amount - l.Consumed
	if a < 0 {
		return 0
	}
	return a
}

// pendingReport is the un-acked consumption report: durable until the
// owner acks; retried with the SAME op id for exactly-once semantics.
type pendingReport struct {
	OpID          string `json:"op_id"`
	ConsumedDelta int64  `json:"consumed_delta"`
	RUBytes       int64  `json:"ru_bytes,omitempty"`
	ForeignBytes  int64  `json:"foreign_bytes,omitempty"`
	ReserveBytes  int64  `json:"reserve_bytes,omitempty"`
	OpenedAt      int64  `json:"opened_at_unix"`
}

type remoteState struct {
	// Leases are PER DEVICE (review FED04): one device's grants never
	// give any other device the right to spend.
	Leases          map[string][]remoteLease `json:"leases"`
	DeviceRemaining map[string]int64         `json:"device_remaining"`
	// Pending is the un-acked consumption report PER DEVICE (exactly-once
	// op id per logical operation).
	Pending          map[string]*pendingReport `json:"pending,omitempty"`
	InFlight         map[string]*pendingReport `json:"in_flight,omitempty"`
	Activity         map[string]*pendingReport `json:"activity,omitempty"`
	ActivityInFlight map[string]*pendingReport `json:"activity_in_flight,omitempty"`
	// Rate rights are EXPLICIT per direction (review FED07): nil = the
	// owner has never sent rate information for this direction (a
	// rate-less subscription — honestly unlimited), 0 = an explicit no
	// right (forbidden), >0 = a finite right valid until its deadline.
	// A zero renewal NEVER extends the deadline of a previous right, and
	// an expired right is enforced as zero — the owner has redistributed
	// it; the old 1/8-floor-forever is gone.
	RateDownBps      *int64 `json:"rate_down_bps,omitempty"`
	RateUpBps        *int64 `json:"rate_up_bps,omitempty"`
	RateDeadlineDown int64  `json:"rate_deadline_down_unix,omitempty"`
	RateDeadlineUp   int64  `json:"rate_deadline_up_unix,omitempty"`
	Stopped          string `json:"stopped,omitempty"`
	StoppedAt        int64  `json:"stopped_at_unix,omitempty"`
}

type remoteQuotaLedger struct {
	cfg    remoteQuotaConfig
	ident  *fedauth.Identity
	client *http.Client

	mu           sync.Mutex
	st           remoteState
	statePath    string
	rateGen      uint64
	lastEffDown  *int64 // last EFFECTIVE values returned by RateShare
	lastEffUp    *int64
	rateUpdateAt int64 // unix: last owner confirmation of the share
	// B01: per-holder serialization of report/reserve operations — two
	// concurrent callers of one device share ONE owner round-trip (the
	// second waits and applies the same reply), instead of duplicating
	// the granted lease.
	opsMu sync.Mutex
	ops   map[string]*sync.Mutex
}

func newRemoteQuotaLedger(cfg remoteQuotaConfig, stateDir string) (*remoteQuotaLedger, error) {
	if cfg.SubscriptionID == "" || cfg.OwnerURL == "" || cfg.PanelID == "" {
		return nil, fmt.Errorf("edge config: quota_remote requires subscription_id, owner_url and panel_id")
	}
	if cfg.LeaseBytes <= 0 {
		cfg.LeaseBytes = 1 << 20 // 1 MiB leases: bounded owner round-trips
	}
	ident, err := fedauth.LoadOrCreate(stateDir, cfg.PanelID)
	if err != nil {
		return nil, fmt.Errorf("edge quota_remote identity: %w", err)
	}
	name := cfg.StateFile
	if name == "" {
		name = "quota_remote.json"
	}
	r := &remoteQuotaLedger{cfg: cfg, ident: ident,
		client:    &http.Client{Timeout: 5 * time.Second},
		statePath: filepath.Join(stateDir, name),
		ops:       map[string]*sync.Mutex{}}
	if b, err := os.ReadFile(r.statePath); err == nil {
		_ = json.Unmarshal(b, &r.st) // corrupt/absent state = zero rights (safe)
	}
	if r.st.Leases == nil {
		r.st.Leases = map[string][]remoteLease{}
	}
	if r.st.DeviceRemaining == nil {
		r.st.DeviceRemaining = map[string]int64{}
	}
	if r.st.Pending == nil {
		r.st.Pending = map[string]*pendingReport{}
	}
	return r, nil
}

// holderMu returns the per-device operation mutex (B01 singleflight).
func (r *remoteQuotaLedger) holderMu(deviceID string) *sync.Mutex {
	r.opsMu.Lock()
	defer r.opsMu.Unlock()
	if r.ops == nil {
		r.ops = map[string]*sync.Mutex{}
	}
	m, ok := r.ops[deviceID]
	if !ok {
		m = &sync.Mutex{}
		r.ops[deviceID] = m
	}
	return m
}

// persistLocked writes the lease state durably (0600, atomic rename).
func (r *remoteQuotaLedger) persistLocked() error {
	if r.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(&r.st, "", "  ")
	if err != nil {
		return err
	}
	// B10: fsync(file)+rename+fsync(dir) — lease state must survive power
	// loss before any payload is admitted against it; errors propagate so
	// admission fail-closes instead of pretending persistence.
	return durableFileWrite(r.statePath, append(b, '\n'))
}

func (r *remoteQuotaLedger) SetDeviceLimit(string, *int64) {} // limits live on the owner

func (r *remoteQuotaLedger) AccountState(time.Time) limits.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := limits.State{}
	if r.st.Stopped != "" {
		st.Exhausted = true
		return st
	}
	// display state: the max credit across devices (enforcement itself is
	// strictly per device in Reserve)
	now := time.Now()
	avail := int64(0)
	for dev := range r.st.Leases {
		if a := r.ownAvailableLocked(dev, now); a > avail {
			avail = a
		}
	}
	rem := avail
	st.Remaining = &rem
	return st
}

// ownAvailableLocked sums THIS device's unexpired lease credit only.
func (r *remoteQuotaLedger) ownAvailableLocked(deviceID string, now time.Time) int64 {
	avail := int64(0)
	for i := range r.st.Leases[deviceID] {
		avail += r.st.Leases[deviceID][i].available(now)
	}
	if avail < 0 {
		avail = 0
	}
	return avail
}

// RenewRate refreshes the rate right without payload traffic (a zero
// report+reserve): the escape from a zero share — without it a starved
// edge would never generate the report that lets the owner redistribute.
// Rate-limited to one attempt per 5 seconds.
func (r *remoteQuotaLedger) RenewRate(deviceID string) {
	r.mu.Lock()
	if r.st.Stopped != "" {
		r.mu.Unlock()
		return
	}
	now := time.Now().Unix()
	if now-r.rateUpdateAt < 5 {
		r.mu.Unlock()
		return // a fresh confirmation already covers this window
	}
	// effective down right (same rule as RateShare): alive → no probe
	d := r.st.RateDownBps
	alive := d != nil && *d > 0 && (r.st.RateDeadlineDown == 0 || now < r.st.RateDeadlineDown)
	if alive {
		r.mu.Unlock()
		return // the right is alive; traffic reports will renew it
	}
	// an IDLE edge must not claim a share: the probe requires actual
	// service activity (open leases or pending consumption) — otherwise
	// startup probes would grab the whole rate budget before any traffic
	serving := len(r.st.Pending) > 0
	if !serving {
		for _, ls := range r.st.Leases {
			if len(ls) > 0 {
				serving = true
				break
			}
		}
	}
	if !serving {
		r.mu.Unlock()
		return
	}
	probeDevice := deviceID
	if probeDevice == "" {
		for dev := range r.st.Leases {
			probeDevice = dev
			break
		}
	}
	r.mu.Unlock()
	_, _ = r.reportAndRequest(probeDevice, 0)
}

// RateShare returns the EFFECTIVE per-direction rights: nil = the owner
// never sent rate information for the direction (rate-less subscription),
// 0 = explicit no right or an EXPIRED right (enforced as zero — the owner
// has redistributed it; a stale right never stays positive forever), >0 =
// a finite right within its deadline. The generation changes when an
// EFFECTIVE value changes — never merely because another response
// arrived.
func (r *remoteQuotaLedger) RateShare() (*int64, *int64, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().Unix()
	effective := func(v *int64, deadline int64) *int64 {
		if v == nil {
			return nil
		}
		if *v <= 0 {
			zero := int64(0)
			return &zero
		}
		if deadline > 0 && now >= deadline {
			zero := int64(0)
			return &zero // expired: the owner freed and redistributed it
		}
		return v
	}
	down := effective(r.st.RateDownBps, r.st.RateDeadlineDown)
	up := effective(r.st.RateUpBps, r.st.RateDeadlineUp)
	changed := false
	if !sameRatePtr(down, r.lastEffDown) || !sameRatePtr(up, r.lastEffUp) {
		changed = true
	}
	r.lastEffDown, r.lastEffUp = down, up
	if changed {
		r.rateGen++
	}
	return down, up, r.rateGen
}

func sameRatePtr(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// takeLocked consumes n from THIS device's leases, earliest expiry first,
// with a write-through persist. Returns what was actually taken.
func (r *remoteQuotaLedger) takeLocked(deviceID string, n int64, now time.Time) (int64, error) {
	nowU := now.Unix()
	keep := r.st.Leases[deviceID][:0]
	for _, l := range r.st.Leases[deviceID] {
		if l.Expires <= nowU || l.Consumed >= l.Amount {
			continue
		}
		keep = append(keep, l)
	}
	r.st.Leases[deviceID] = append([]remoteLease(nil), keep...)
	remaining := n
	for i := range r.st.Leases[deviceID] {
		if remaining <= 0 {
			break
		}
		l := &r.st.Leases[deviceID][i]
		free := l.Amount - l.Consumed
		if free <= 0 {
			continue
		}
		take := free
		if remaining < take {
			take = remaining
		}
		l.Consumed += take
		remaining -= take
	}
	if err := r.persistLocked(); err != nil {
		return n - remaining, err
	}
	return n - remaining, nil
}

// redeemInvite consumes the one-time invite (token-authenticated).
func (r *remoteQuotaLedger) redeemInvite() error {
	body, _ := json.Marshal(map[string]any{
		"token": r.cfg.InviteToken, "panel_id": r.ident.PanelID,
		"public_key": r.ident.PublicHex(),
	})
	resp, err := r.client.Post(r.cfg.OwnerURL+"/api/fed/v1/link/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("redeem HTTP %d", resp.StatusCode)
	}
	return nil
}

type quotaHTTPResponse struct {
	AccessChecked     bool   `json:"access_checked"`
	ActivityAccepted  bool   `json:"activity_accepted"`
	DeviceExpiresUnix int64  `json:"device_expires_unix,omitempty"`
	LeaseExpiresUnix  int64  `json:"lease_expires_unix,omitempty"`
	Remaining         *int64 `json:"remaining_bytes"`
	Exhausted         bool   `json:"exhausted"`
	Granted           int64  `json:"granted"`
	DeviceRemaining   *int64 `json:"device_remaining_bytes"`
	DeviceExhausted   bool   `json:"device_exhausted"`
	RateDownBPS       *int64 `json:"rate_share_down_bps"`
	RateUpBPS         *int64 `json:"rate_share_up_bps"`
	Error             string `json:"error"`
	Owner             string `json:"owner"`
}

// reportAndRequest sends the pending consumption (op_id idempotent) and
// requests a new lease. It is SERIALIZED per device (holder mutex): two
// concurrent reserves of one device share one owner round-trip — the
// loser re-checks its own credit after the winner's lease lands and skips
// the owner call entirely, so one owner grant is never applied twice
// (review B01). Failure classification:
//   - revoked / not linked (401) and NOT_OWNER (409) → STICKY STOP;
//   - network / 5xx → transient (caller degrades to own leases only).
func (r *remoteQuotaLedger) reportAndRequest(deviceID string, n int64) (*quotaHTTPResponse, error) {
	// B01: per-device singleflight for the whole owner round-trip.
	hm := r.holderMu(deviceID)
	hm.Lock()
	defer hm.Unlock()
	return r.reportAndRequestHeld(deviceID, n)
}

// reportAndRequestHeld is the owner round-trip core for callers already
// holding the device's holder mutex (Reserve's singleflight section);
// acquiring it again here would self-deadlock on a non-reentrant Mutex.
func (r *remoteQuotaLedger) reportAndRequestHeld(deviceID string, n int64) (*quotaHTTPResponse, error) {
	r.mu.Lock()
	if n > 0 {
		// a positive request is skipped when own credit already covers it —
		// the winner of the race landed its lease while we waited
		if own := r.ownAvailableLocked(deviceID, time.Now()); own >= n {
			r.mu.Unlock()
			return &quotaHTTPResponse{Granted: 0, Remaining: &own}, nil
		}
	}
	if r.st.Stopped != "" {
		r.mu.Unlock()
		return nil, fmt.Errorf("quota stopped")
	}
	if r.st.InFlight == nil {
		r.st.InFlight = map[string]*pendingReport{}
	}
	if r.st.InFlight[deviceID] == nil {
		queued := r.st.Pending[deviceID]
		if queued == nil {
			queued = &pendingReport{OpID: "op-" + batchTag(), OpenedAt: time.Now().Unix()}
		}
		report := *queued
		report.ReserveBytes = n
		r.st.InFlight[deviceID] = &report
		delete(r.st.Pending, deviceID)
		if err := r.persistLocked(); err != nil {
			if r.st.Pending == nil {
				r.st.Pending = map[string]*pendingReport{}
			}
			r.st.Pending[deviceID] = queued
			delete(r.st.InFlight, deviceID)
			r.mu.Unlock()
			return nil, err
		}
	}
	pending := *r.st.InFlight[deviceID]
	r.mu.Unlock()

	out, status, err := r.postReport(deviceID, pending, false, false)
	if err != nil {
		return nil, err
	}
	if status == http.StatusForbidden && out.Error == "DEVICE_ACCESS_DENIED" {
		r.mu.Lock()
		delete(r.st.Leases, deviceID)
		delete(r.st.InFlight, deviceID)
		delete(r.st.Pending, deviceID)
		err := r.persistLocked()
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("device access denied")
	}
	if status == http.StatusUnauthorized {
		// first contact with a not-yet-linked edge identity: redeem the
		// operator-issued one-time invite and retry ONCE; anything else
		// (revoked subscription, stale link) is a STICKY stop
		if strings.Contains(out.Error, "not linked") && r.cfg.InviteToken != "" {
			if rerr := r.redeemInvite(); rerr != nil {
				if serr := r.stop("invite redeem failed: "+rerr.Error(), true); serr != nil {
					return nil, fmt.Errorf("invite redeem failed: %w; durable stop record failed: %w", rerr, serr)
				}
				return nil, fmt.Errorf("invite redeem failed: %w", rerr)
			}
			return r.reportAndRequestHeld(deviceID, n)
		}
		serr := r.stop("revoked or unlinked: "+out.Error, true)
		if serr != nil {
			return nil, fmt.Errorf("quota refused (stopping): %s; durable stop record failed: %w", out.Error, serr)
		}
		return nil, fmt.Errorf("quota refused (stopping): %s", out.Error)
	}
	if status == http.StatusConflict && out.Error == "NOT_OWNER" {
		if serr := r.stop("ownership moved (NOT_OWNER): re-point edge config to the new owner", true); serr != nil {
			return nil, fmt.Errorf("quota owner moved (NOT_OWNER): durable stop record failed: %w", serr)
		}
		return nil, fmt.Errorf("quota owner moved (NOT_OWNER): stopping; re-point edge config")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("quota report HTTP %d: %s", status, out.Error)
	}
	// success: the op is acked — the pending delta is durably cleared;
	// a crash BEFORE this persist replays with the SAME op id (safe)
	r.mu.Lock()
	delete(r.st.InFlight, deviceID)
	if out.DeviceRemaining != nil {
		r.st.DeviceRemaining[deviceID] = *out.DeviceRemaining
	} else {
		delete(r.st.DeviceRemaining, deviceID)
	}
	// FED07: directions update INDEPENDENTLY; an explicit zero is STORED
	// (a byte lease is not a rate entitlement — a new node with zero share
	// must not become unlimited); a positive grant (re)starts the
	// deadline; a zero renewal does NOT extend a previous right's
	// deadline — it expires on schedule and is then enforced as zero.
	if out.RateDownBPS != nil {
		if *out.RateDownBPS > 0 {
			r.st.RateDownBps = out.RateDownBPS
			r.st.RateDeadlineDown = time.Now().Add(rateRightTTL).Unix()
		} else if r.st.RateDownBps == nil || *r.st.RateDownBps != 0 {
			r.st.RateDownBps = out.RateDownBPS // explicit zero (or reduced-to-zero)
		}
	}
	if out.RateUpBPS != nil {
		if *out.RateUpBPS > 0 {
			r.st.RateUpBps = out.RateUpBPS
			r.st.RateDeadlineUp = time.Now().Add(rateRightTTL).Unix()
		} else if r.st.RateUpBps == nil || *r.st.RateUpBps != 0 {
			r.st.RateUpBps = out.RateUpBPS
		}
	}
	r.rateUpdateAt = time.Now().Unix()
	if out.DeviceExpiresUnix > 0 {
		for i := range r.st.Leases[deviceID] {
			l := &r.st.Leases[deviceID][i]
			if out.DeviceExpiresUnix < l.Expires {
				l.Expires = out.DeviceExpiresUnix
			}
		}
	}
	if out.Granted > 0 {
		expiry := out.LeaseExpiresUnix
		if expiry == 0 {
			expiry = time.Now().Add(10 * time.Minute).Unix()
		} // older owner
		if expiry > time.Now().Unix() {
			r.st.Leases[deviceID] = append(r.st.Leases[deviceID], remoteLease{
				ID: "ls-" + batchTag(), Amount: out.Granted, Expires: expiry,
			})
		}
	}
	r.rateUpdateAt = time.Now().Unix()
	perr := r.persistLocked()
	r.mu.Unlock()
	if perr != nil {
		return &out, perr
	}
	return &out, nil
}

// stop marks the ledger stopped and writes the durable stop record. It
// takes r.mu itself: callers hold only their per-DEVICE holder mutex,
// which does not protect the shared stopped state (product-completion:
// two concurrent owner revocations raced st.Stopped/persist). Persist
// failures are reported, never dropped — a silent loss would resurrect
// spendable credit after restart.
func (r *remoteQuotaLedger) stop(reason string, persist bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.st.Stopped == "" {
		r.st.Stopped = reason
		r.st.StoppedAt = time.Now().Unix()
		if persist {
			if perr := r.persistLocked(); perr != nil {
				return perr
			}
		}
	}
	return nil
}

// Reserve admits n bytes: own outstanding leases first (offline-safe),
// then a lease request; failures degrade to own-leases-only, never to
// global-remaining reuse.
func (r *remoteQuotaLedger) Reserve(deviceID string, n int64, now time.Time) (*limits.ReservationBatch, limits.State, limits.State, error) {
	r.mu.Lock()
	if r.st.Stopped != "" {
		st := limits.State{Exhausted: true}
		r.mu.Unlock()
		return nil, st, st, fmt.Errorf("quota stopped: %s", r.st.Stopped)
	}
	now = time.Now()
	// authoritative device cap (owner's cache)
	if devRem, ok := r.st.DeviceRemaining[deviceID]; ok && devRem <= 0 {
		zero := int64(0)
		st := limits.State{Exhausted: true, Remaining: &zero}
		r.mu.Unlock()
		return nil, st, st, nil
	}
	own := r.ownAvailableLocked(deviceID, now)
	if own >= n {
		got, err := r.takeLocked(deviceID, n, now)
		if err != nil {
			r.mu.Unlock()
			return nil, limits.State{}, limits.State{}, err
		}
		if got < n {
			st := limits.State{Remaining: &got}
			r.mu.Unlock()
			return nil, st, st, nil // enforcer shrinks to the granted amount
		}
		st := r.stateLocked(deviceID, own)
		r.mu.Unlock()
		return &limits.ReservationBatch{ID: "rq-" + batchTag(), Reserved: n}, st, limits.State{}, nil
	}
	r.mu.Unlock()

	// B01 singleflight: concurrent reserves of ONE device share a single
	// owner round-trip. The twin's reply lands in the shared state; after
	// acquiring the holder mutex re-check own credit before dialing.
	hm := r.holderMu(deviceID)
	hm.Lock()
	r.mu.Lock()
	now = time.Now()
	if own := r.ownAvailableLocked(deviceID, now); own >= n {
		got, terr := r.takeLocked(deviceID, n, now)
		if terr != nil {
			r.mu.Unlock()
			hm.Unlock()
			return nil, limits.State{}, limits.State{}, terr
		}
		if got >= n {
			st := r.stateLocked(deviceID, own)
			r.mu.Unlock()
			hm.Unlock()
			return &limits.ReservationBatch{ID: "rq-" + batchTag(), Reserved: n}, st, limits.State{}, nil
		}
		// short take: fall through with the remaining need below
	}
	r.mu.Unlock()

	// need a new lease: report pending consumption + request
	want := n
	if want < r.cfg.LeaseBytes {
		want = r.cfg.LeaseBytes
	}
	resp, err := r.reportAndRequestHeld(deviceID, want)
	defer hm.Unlock()
	if err != nil {
		// offline degradation: strictly within THIS device's outstanding
		// leases (FED04: another device's grants are not spendable here)
		r.mu.Lock()
		if r.st.Stopped != "" {
			st := limits.State{Exhausted: true}
			r.mu.Unlock()
			return nil, st, st, err
		}
		own := r.ownAvailableLocked(deviceID, time.Now())
		if own <= 0 {
			zero := int64(0)
			st := limits.State{Exhausted: true, Remaining: &zero}
			r.mu.Unlock()
			return nil, st, st, fmt.Errorf("quota owner unreachable and no outstanding lease: %w", err)
		}
		st := limits.State{Remaining: &own}
		r.mu.Unlock()
		return nil, st, st, nil // enforcer shrinks into own rights
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if devRem, ok := r.st.DeviceRemaining[deviceID]; ok && devRem <= 0 {
		zero := int64(0)
		st := limits.State{Exhausted: true, Remaining: &zero}
		return nil, st, st, nil
	}
	own = r.ownAvailableLocked(deviceID, now)
	if own <= 0 {
		zero := int64(0)
		st := limits.State{Exhausted: resp.Exhausted, Remaining: &zero}
		return nil, st, st, nil
	}
	st := r.stateLocked(deviceID, own)
	if own < n {
		return nil, limits.State{Remaining: &own}, st, nil // shrink path
	}
	got, terr := r.takeLocked(deviceID, n, now)
	if terr != nil {
		return nil, limits.State{}, limits.State{}, terr
	}
	if got < n {
		st2 := limits.State{Remaining: &got}
		return nil, st2, st, nil
	}
	return &limits.ReservationBatch{ID: "rq-" + batchTag(), Reserved: n}, st, limits.State{}, nil
}

func (r *remoteQuotaLedger) stateLocked(deviceID string, avail int64) limits.State {
	st := limits.State{Remaining: &avail}
	if d, ok := r.st.DeviceRemaining[deviceID]; ok && d < avail {
		dv := d
		st.Remaining = &dv
	}
	return st
}

// Checkpoint records the bytes actually consumed by an admitted batch and
// queues them into the durable pending report. The authoritative close
// happens when the owner acks the op (exactly once by op id). Local lease
// consumption was already written through at Reserve time.
func (r *remoteQuotaLedger) Checkpoint(deviceID string, batch *limits.ReservationBatch, actual int64, now time.Time) error {
	return r.checkpointRouted(deviceID, batch, actual, now, "")
}

func (r *remoteQuotaLedger) checkpointRouted(deviceID string, batch *limits.ReservationBatch, actual int64, now time.Time, role string) error {
	if batch == nil || actual <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.st.Pending == nil {
		r.st.Pending = map[string]*pendingReport{}
	}
	if r.st.Pending[deviceID] == nil {
		r.st.Pending[deviceID] = &pendingReport{OpID: "op-" + batchTag(), OpenedAt: now.Unix()}
	}
	r.st.Pending[deviceID].ConsumedDelta += actual
	if r.st.Activity == nil {
		r.st.Activity = map[string]*pendingReport{}
	}
	p := r.st.Activity[deviceID]
	if p == nil || now.Unix()-p.OpenedAt > 7*86400 {
		p = &pendingReport{OpID: "act-" + batchTag(), OpenedAt: now.Unix()}
		r.st.Activity[deviceID] = p
	}
	p.ConsumedDelta += actual
	switch role {
	case "ru":
		p.RUBytes += actual
	case "foreign":
		p.ForeignBytes += actual
	}

	return r.persistLocked()
}

func batchTag() string {
	var b [6]byte
	_, _ = crand.Read(b[:])
	return fmt.Sprintf("%x", b[:])
}

func (r *remoteQuotaLedger) flushPending(ctx context.Context) {
	r.mu.Lock()
	pending := map[string]bool{}
	if r.st.Stopped == "" {
		for id := range r.st.Activity {
			pending[id] = true
		}
		for id := range r.st.ActivityInFlight {
			pending[id] = true
		}
	}
	r.mu.Unlock()
	for id := range pending {
		if ctx.Err() != nil {
			return
		}
		r.flushDeviceActivity(id)
	}
}

func (r *remoteQuotaLedger) flushDeviceActivity(id string) {
	hm := r.holderMu(id)
	hm.Lock()
	defer hm.Unlock()
	r.mu.Lock()
	if r.st.ActivityInFlight == nil {
		r.st.ActivityInFlight = map[string]*pendingReport{}
	}
	p := r.st.ActivityInFlight[id]
	if p == nil {
		p = r.st.Activity[id]
		if p == nil {
			r.mu.Unlock()
			return
		}
		r.st.ActivityInFlight[id] = p
		delete(r.st.Activity, id)
		if err := r.persistLocked(); err != nil {
			r.st.Activity[id] = p
			delete(r.st.ActivityInFlight, id)
			r.mu.Unlock()
			return
		}
	}
	report := *p
	r.mu.Unlock()
	out, status, err := r.postReport(id, report, true, false)
	if err != nil {
		return
	}
	if !out.ActivityAccepted && !(status == http.StatusForbidden &&
		(out.Error == "ACTIVITY_EXPIRED" || out.Error == "ACTIVITY_DENIED" || out.Error == "DEVICE_ACCESS_DENIED")) {
		return
	}
	r.mu.Lock()
	delete(r.st.ActivityInFlight, id)
	if out.Error == "DEVICE_ACCESS_DENIED" {
		delete(r.st.Leases, id)
	}
	if err := r.persistLocked(); err != nil {
		r.st.ActivityInFlight[id] = p
	}
	r.mu.Unlock()
}

func (r *remoteQuotaLedger) postReport(deviceID string, pending pendingReport, activity, access bool) (quotaHTTPResponse, int, error) {
	body, _ := json.Marshal(map[string]any{
		"subscription_id": r.cfg.SubscriptionID,
		"device_id":       r.ident.PanelID + "|" + deviceID,
		"used_bytes":      pending.ConsumedDelta,
		"ru_bytes":        pending.RUBytes, "foreign_bytes": pending.ForeignBytes,
		"reserve_bytes":     pending.ReserveBytes,
		"separate_activity": !activity,
		"activity_only":     activity,
		"access_check":      access,
		"activity_at":       map[bool]int64{true: pending.OpenedAt}[activity],
		"op_id":             pending.OpID,
	})
	path := "/api/fed/v1/quota/report"
	ts := time.Now().Unix()
	nonce := "q-" + batchTag()
	req, err := http.NewRequest(http.MethodPost, r.cfg.OwnerURL+path, bytes.NewReader(body))
	if err != nil {
		return quotaHTTPResponse{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ARA-Panel", r.ident.PanelID)
	req.Header.Set("X-ARA-Timestamp", fmt.Sprint(ts))
	req.Header.Set("X-ARA-Nonce", nonce)
	req.Header.Set("X-ARA-Signature", r.ident.Sign(http.MethodPost, path, ts, nonce, body))
	resp, err := r.client.Do(req)
	if err != nil {
		return quotaHTTPResponse{}, 0, err
	}
	defer resp.Body.Close()
	var out quotaHTTPResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&out); err != nil {
		return quotaHTTPResponse{}, 0, err
	}
	return out, resp.StatusCode, nil
}

func (r *remoteQuotaLedger) checkUsedDevices(ctx context.Context) []string {
	r.mu.Lock()
	var ids []string
	if r.st.Stopped == "" {
		now := time.Now().Unix()
		for id, leases := range r.st.Leases {
			for _, lease := range leases {
				if lease.Expires > now {
					ids = append(ids, id)
					break
				}
			}
		}
	}
	r.mu.Unlock()
	var denied []string
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		hm := r.holderMu(id)
		hm.Lock()
		report := pendingReport{OpID: "access-" + batchTag(), OpenedAt: time.Now().Unix()}
		out, status, err := r.postReport(id, report, true, true)
		if err == nil && (out.AccessChecked || status == http.StatusForbidden && out.Error == "DEVICE_ACCESS_DENIED") {
			r.mu.Lock()
			if out.AccessChecked {
				if out.DeviceExpiresUnix > 0 {
					for i := range r.st.Leases[id] {
						l := &r.st.Leases[id][i]
						if out.DeviceExpiresUnix < l.Expires {
							l.Expires = out.DeviceExpiresUnix
						}
					}
				}
			} else {
				delete(r.st.Leases, id)
				denied = append(denied, id)
			}
			_ = r.persistLocked()
			r.mu.Unlock()
		}
		hm.Unlock()
	}
	return denied
}
