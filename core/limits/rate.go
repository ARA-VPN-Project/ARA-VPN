// Package limits implements identity-bound rate and volume enforcement
// (docs/LIMITS_QUOTAS.md): aggregate token buckets per account/device for
// download and upload, and crash-safe quota accounting with durable
// reservations. Limits bind to authenticated identity, never to IP or port,
// and survive reconnect/restart/exit-switch without reset.
//
// Ownership of state (review R04): the ACCOUNT budget is owned by exactly
// one AccountRegime shared by every device of that account; device buckets
// are additional per-device constraints on top. Two limiters built from the
// same regime cannot multiply the account allowance, and no combination of
// independent per-device minima can replace the shared account budget.
package limits

import (
	"sync"
	"time"
)

// Direction of user payload.
type Direction string

const (
	Download Direction = "download"
	Upload   Direction = "upload"
)

// RateConfig holds one scope's rate limits. nil = unlimited;
// 0 = direction forbidden (never treated as unlimited). Rates are bit/s
// with explicit Mbps display in UI; burst is bytes.
type RateConfig struct {
	DownloadBPS        *int64 `json:"download_bps,omitempty"`
	UploadBPS          *int64 `json:"upload_bps,omitempty"`
	DownloadBurstBytes *int64 `json:"download_burst_bytes,omitempty"` // default: 1s worth of rate, bounded
	UploadBurstBytes   *int64 `json:"upload_burst_bytes,omitempty"`
}

// Validate exposes the config check to the service layer.
func (c RateConfig) Validate() error { return c.validate() }

func (c RateConfig) validate() error {
	for _, p := range []*int64{c.DownloadBPS, c.UploadBPS} {
		if p == nil {
			continue
		}
		if *p < 0 {
			return errNegativeRate
		}
		// sub-byte rates are meaningless; require multiples of 8 bit/s
		if *p > 0 && *p%8 != 0 {
			return errSubByteRate
		}
	}
	for _, p := range []*int64{c.DownloadBurstBytes, c.UploadBurstBytes} {
		if p != nil && *p < 0 {
			return errNegativeBurst
		}
	}
	return nil
}

type limitsError string

func (e limitsError) Error() string { return string(e) }

const (
	errNegativeRate  = limitsError("rate must be >= 0 bit/s (0 = forbidden, null = unlimited)")
	errSubByteRate   = limitsError("rate must be a multiple of 8 bit/s")
	errNegativeBurst = limitsError("burst must be >= 0 bytes")
)

// bpsToBytesPerSec converts the configured bit/s into bytes/s.
func bpsToBytesPerSec(bps int64) float64 { return float64(bps) / 8.0 }

// bucket is one token bucket measured in bytes. It is the shared aggregate
// for a scope+direction: parallel flows all draw from the same bucket, so
// connection count, IPv4/IPv6 mix or exit switches cannot multiply the
// limit (docs/LIMITS_QUOTAS.md, acceptance T10).
type bucket struct {
	mu        sync.Mutex
	rate      float64 // bytes/s, 0 = forbidden
	capacity  float64
	tokens    float64
	last      time.Time
	unlimited bool
}

func newBucket(bps *int64, burst *int64, now time.Time) *bucket {
	if bps == nil {
		return &bucket{unlimited: true, last: now}
	}
	rate := bpsToBytesPerSec(*bps)
	capacity := rate // default burst: one second of sustained rate
	if burst != nil {
		capacity = float64(*burst)
	}
	if capacity < 1 {
		capacity = 1 // a forbidden direction still gets a 1-byte floor so rejection is well-defined
	}
	return &bucket{rate: rate, capacity: capacity, tokens: capacity, last: now}
}

// TakeResult reports one admission decision.
type TakeResult struct {
	Granted      bool
	DeficitBytes int64         // missing bytes when not granted (rate-limited)
	Forbidden    bool          // configured rate is 0
	RetryAfter   time.Duration // time until the deficit refills
}

// Take admits n bytes against the aggregate bucket or refuses them.
// Refusal is a shaping signal for the data plane (drop/backpressure); the
// bucket never goes negative.
func (b *bucket) Take(n int64, now time.Time) TakeResult {
	if b.unlimited {
		return TakeResult{Granted: true}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate == 0 {
		return TakeResult{Forbidden: true}
	}
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.rate
		b.last = now
	}
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	if float64(n) <= b.tokens {
		b.tokens -= float64(n)
		return TakeResult{Granted: true}
	}
	deficit := float64(n) - b.tokens
	return TakeResult{
		DeficitBytes: int64(deficit + 0.5),
		RetryAfter:   time.Duration(deficit / b.rate * float64(time.Second)),
	}
}

func (b *bucket) refund(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += float64(n)
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}

// AccountRegime owns the account-level budget for one account. Every
// device of the account binds to the SAME regime, so their Take calls draw
// from one shared pair of account buckets regardless of limiter instances.
type AccountRegime struct {
	accountDL, accountUL *bucket
	mu                   sync.Mutex
}

// NewAccountRegime creates the single authoritative account-level state.
// One regime per account for the process lifetime is the caller's
// contract; BindDevice always shares it.
func NewAccountRegime(account RateConfig, now time.Time) (*AccountRegime, error) {
	if err := account.validate(); err != nil {
		return nil, err
	}
	return &AccountRegime{
		accountDL: newBucket(account.DownloadBPS, account.DownloadBurstBytes, now),
		accountUL: newBucket(account.UploadBPS, account.UploadBurstBytes, now),
	}, nil
}

// AggregateLimiter enforces one device's limits plus its account's shared
// budget. Device buckets are additional constraints; they can only make
// admission stricter than the account regime, never looser.
type AggregateLimiter struct {
	regime             *AccountRegime
	deviceDL, deviceUL *bucket
}

// BindDevice builds a device limiter attached to the shared regime.
func (a *AccountRegime) BindDevice(device RateConfig, now time.Time) (*AggregateLimiter, error) {
	if err := device.validate(); err != nil {
		return nil, err
	}
	return &AggregateLimiter{
		regime:   a,
		deviceDL: newBucket(device.DownloadBPS, device.DownloadBurstBytes, now),
		deviceUL: newBucket(device.UploadBPS, device.UploadBurstBytes, now),
	}, nil
}

// RebindAccount replaces the shared account rate while CARRYING OVER the
// current token state (capped by the new capacity): a control-plane rate
// update never mints new tokens out of itself (review FED08). Device
// buckets are untouched — additional device rate limits survive the
// actualization. A transition from an unlimited account legitimately
// seeds the first full bucket (the first granted right).
func (l *AggregateLimiter) RebindAccount(account RateConfig, now time.Time) error {
	if err := account.validate(); err != nil {
		return err
	}
	l.regime.mu.Lock()
	defer l.regime.mu.Unlock()
	carry := func(old *bucket) (float64, bool) {
		if old.unlimited {
			return 0, false // no meaningful token state to carry
		}
		old.mu.Lock()
		defer old.mu.Unlock()
		if el := now.Sub(old.last).Seconds(); el > 0 {
			old.tokens += el * old.rate
			old.last = now
			if old.tokens > old.capacity {
				old.tokens = old.capacity
			}
		}
		return old.tokens, true
	}
	dlTokens, dlHad := carry(l.regime.accountDL)
	ulTokens, ulHad := carry(l.regime.accountUL)
	reseat := func(old *bucket, rate *int64, burst *int64, tokens float64, had bool) *bucket {
		nb := newBucket(rate, burst, now)
		if had && !nb.unlimited {
			nb.mu.Lock()
			if tokens < nb.tokens {
				nb.tokens = tokens // never mint beyond the carried state
			}
			nb.mu.Unlock()
		}
		return nb
	}
	l.regime.accountDL = reseat(l.regime.accountDL, account.DownloadBPS, account.DownloadBurstBytes, dlTokens, dlHad)
	l.regime.accountUL = reseat(l.regime.accountUL, account.UploadBPS, account.UploadBurstBytes, ulTokens, ulHad)
	return nil
}

// RebindDevice replaces this device's own rate buckets while carrying the
// current token state (capped by the new capacity): a reload that changes
// a device rate must not mint a fresh burst (B12 analog for devices).
// The shared account budget is untouched.
func (l *AggregateLimiter) RebindDevice(device RateConfig, now time.Time) error {
	if err := device.validate(); err != nil {
		return err
	}
	l.regime.mu.Lock()
	defer l.regime.mu.Unlock()
	carry := func(old *bucket) (float64, bool) {
		if old.unlimited {
			return 0, false
		}
		old.mu.Lock()
		defer old.mu.Unlock()
		if el := now.Sub(old.last).Seconds(); el > 0 {
			old.tokens += el * old.rate
			old.last = now
			if old.tokens > old.capacity {
				old.tokens = old.capacity
			}
		}
		return old.tokens, true
	}
	dlTokens, dlHad := carry(l.deviceDL)
	ulTokens, ulHad := carry(l.deviceUL)
	reseat := func(old *bucket, rate *int64, burst *int64, tokens float64, had bool) *bucket {
		nb := newBucket(rate, burst, now)
		if had && !nb.unlimited {
			nb.mu.Lock()
			if tokens < nb.tokens {
				nb.tokens = tokens
			}
			nb.mu.Unlock()
		}
		return nb
	}
	l.deviceDL = reseat(l.deviceDL, device.DownloadBPS, device.DownloadBurstBytes, dlTokens, dlHad)
	l.deviceUL = reseat(l.deviceUL, device.UploadBPS, device.UploadBurstBytes, ulTokens, ulHad)
	return nil
}

// Take admits n bytes only if BOTH the shared account budget and this
// device's own budget grant them. A device-side refusal refunds the
// account reservation: refusals must not drain the shared budget for
// traffic that never transferred.
func (l *AggregateLimiter) Take(dir Direction, n int64, now time.Time) TakeResult {
	if n < 0 {
		return TakeResult{Forbidden: true}
	}
	l.regime.mu.Lock()
	defer l.regime.mu.Unlock()
	var account, device *bucket
	switch dir {
	case Download:
		account, device = l.regime.accountDL, l.deviceDL
	case Upload:
		account, device = l.regime.accountUL, l.deviceUL
	default:
		return TakeResult{Forbidden: true}
	}
	ra := account.Take(n, now)
	if !ra.Granted {
		return ra
	}
	rd := device.Take(n, now)
	if !rd.Granted {
		account.refund(n)
		return rd
	}
	return TakeResult{Granted: true}
}

// EffectiveRate returns the tighter of account/device rate for a direction
// (nil-aware), for status display. It is a display helper only: actual
// enforcement uses the shared regime, not a per-device minimum.
func EffectiveRate(account, device *int64) *int64 {
	switch {
	case account == nil:
		return device
	case device == nil:
		return account
	case *account <= *device:
		return account
	default:
		return device
	}
}

// TakeWithProfile applies an independent profile cap in addition to the
// shared account and device budgets. A rejected admission spends no tokens.
func (l *AggregateLimiter) TakeWithProfile(profile *AggregateLimiter, dir Direction, n int64, now time.Time) TakeResult {
	if profile == nil {
		return l.Take(dir, n, now)
	}
	if l.regime == profile.regime || n < 0 {
		return TakeResult{Forbidden: true}
	}
	profile.regime.mu.Lock()
	defer profile.regime.mu.Unlock()
	var b *bucket
	switch dir {
	case Download:
		b = profile.regime.accountDL
	case Upload:
		b = profile.regime.accountUL
	default:
		return TakeResult{Forbidden: true}
	}
	if r := b.Take(n, now); !r.Granted {
		return r
	}
	r := l.Take(dir, n, now)
	if !r.Granted {
		b.refund(n)
	}
	return r
}
