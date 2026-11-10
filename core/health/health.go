// Package health implements the per-node health state machine
// (docs/FAILOVER.md): failure counting with hysteresis, recovery with a
// stability window, observation expiry and quarantine on security failures.
//
// The tracker consumes probe outcomes and never performs probes itself;
// probe scheduling, jitter and endpoints belong to the agent. All state
// transitions are derived from observations with monotonic timestamps, so
// the whole machine is deterministic under an injected clock and unit
// testable offline.
package health

import (
	"fmt"
	"sync"
	"time"
)

// State is the effective health of one node as published to selectors.
type State string

const (
	Healthy     State = "healthy"
	Suspect     State = "suspect"
	Down        State = "down"
	Recovering  State = "recovering"
	Unknown     State = "unknown"
	Quarantined State = "quarantined"
)

// EligibleForNewFlow reports whether the state may receive new foreign
// flows. Recovering means the stability window has not elapsed yet, so a
// higher-priority recovering node is still not selected
// (docs/FAILOVER.md). Unknown and quarantined nodes are never selected;
// a stale observation must not masquerade as healthy.
func (s State) EligibleForNewFlow() bool {
	return s == Healthy
}

// FailureKind distinguishes probe failure causes. Only transport-level
// kinds advance the down counter; auth/security kinds quarantine the
// profile instead. RTT to Edge is deliberately not a kind here — Edge RTT
// says nothing about Exit Internet reachability (docs/FAILOVER.md).
type FailureKind string

const (
	FailTimeout     FailureKind = "timeout"      // listener/probe timeout or blackhole
	FailConnRefused FailureKind = "conn_refused" // listener down
	FailNetwork     FailureKind = "network"      // unreachable / ICMP denied
	FailTLS         FailureKind = "tls"          // handshake/certificate failure
	FailAuth        FailureKind = "auth"         // credentials rejected
	FailServer      FailureKind = "server"       // 5xx from canary
)

// Quarantines reports whether a failure kind is a security failure that
// must quarantine the profile rather than count toward down.
func (k FailureKind) Quarantines() bool {
	return k == FailAuth || k == FailTLS
}

// Config bounds all timings; values are the documented lab starting
// parameters and may be tuned by config within safe limits.
type Config struct {
	FailThreshold      int           // consecutive failures => down (start: 3)
	RecoverThreshold   int           // consecutive successes to leave down (start: 2)
	StabilityWindow    time.Duration // failure-free time required while recovering (start: 30s)
	MaxObservationAge  time.Duration // older last observation => unknown (start: 15s)
	InitialProbeWindow time.Duration // startup bounded probe window (start: 8s)
}

// DefaultConfig returns the FAILOVER.md starting parameters.
func DefaultConfig() Config {
	return Config{
		FailThreshold:      3,
		RecoverThreshold:   2,
		StabilityWindow:    30 * time.Second,
		MaxObservationAge:  15 * time.Second,
		InitialProbeWindow: 8 * time.Second,
	}
}

func (c Config) validate() error {
	if c.FailThreshold < 1 || c.RecoverThreshold < 1 {
		return fmt.Errorf("health thresholds must be >= 1")
	}
	if c.StabilityWindow < 0 || c.MaxObservationAge <= 0 {
		return fmt.Errorf("health windows must be positive")
	}
	return nil
}

type trackerState struct {
	state             State
	consecFails       int
	consecOK          int
	recoveringSince   time.Time
	stabilityRequired bool // node once went down: every return to healthy must pass the full window again (review R09)
	lastObservation   time.Time
	lastChange        time.Time
	created           time.Time
	quarantineReason  string
	lastFailureKind   FailureKind
}

// Tracker is the state machine for exactly one node. It is safe for
// concurrent use; a mutex is enough because probes per node are serial.
type Tracker struct {
	mu  sync.Mutex
	st  trackerState
	cfg Config
}

// NewTracker starts a node in unknown state: "health unknown" is the
// documented startup state, never healthy by assumption.
func NewTracker(cfg Config, now time.Time) (*Tracker, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Tracker{cfg: cfg, st: trackerState{state: Unknown, created: now, lastChange: now}}, nil
}

// RecordSuccess records one successful end-to-end probe.
func (t *Tracker) RecordSuccess(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.st.lastObservation = now
	t.st.consecFails = 0
	t.st.consecOK++
	switch t.st.state {
	case Down:
		if t.st.consecOK >= t.cfg.RecoverThreshold {
			t.st.state = Recovering
			t.st.recoveringSince = now
			t.st.stabilityRequired = true
			t.st.lastChange = now
		}
	case Recovering:
		if t.stabilityElapsedLocked(now) {
			t.st.state = Healthy
			t.st.stabilityRequired = false
			t.st.lastChange = now
		}
	case Suspect:
		if t.st.stabilityRequired {
			// A node that is working its way back from down owes the
			// full stability window again; a single success must not
			// bypass it (review R09). Re-enter the window from now.
			t.st.state = Recovering
			t.st.recoveringSince = now
			t.st.lastChange = now
		} else {
			t.st.state = Healthy
			t.st.lastChange = now
		}
	case Unknown:
		t.st.state = Healthy
		t.st.lastChange = now
	case Healthy, Quarantined:
		// no transition; quarantine requires explicit operator release
	}
}

// RecordFailure records one failed probe. Security-kind failures
// (auth/TLS) quarantine immediately; transport failures count toward the
// configured threshold. A single broken canary must not flip the node by
// itself — multi-endpoint canary deduplication is the probe layer's
// responsibility, not the tracker's.
func (t *Tracker) RecordFailure(now time.Time, kind FailureKind, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.st.lastObservation = now
	t.st.lastFailureKind = kind
	if kind.Quarantines() {
		t.st.state = Quarantined
		t.st.quarantineReason = detail
		t.st.lastChange = now
		return
	}
	t.st.consecOK = 0
	t.st.consecFails++
	if t.st.state == Recovering {
		// A failure inside the stability window restarts the whole window:
		// the node owes the full failure-free period again from its next
		// success (review R09). The flag survives until healthy.
		t.st.stabilityRequired = true
	}
	switch t.st.state {
	case Healthy, Unknown, Recovering, Suspect:
		t.st.state = Suspect
		if t.st.consecFails >= t.cfg.FailThreshold {
			t.st.state = Down
		}
		t.st.lastChange = now
	case Down, Quarantined:
		// already unavailable
	}
}

// Quarantine marks the node unavailable for security reasons with a typed
// reason. It never auto-recovers; ReleaseQuarantine is an operator action.
func (t *Tracker) Quarantine(now time.Time, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.st.state = Quarantined
	t.st.quarantineReason = reason
	t.st.lastChange = now
}

func (t *Tracker) ReleaseQuarantine(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.st.state == Quarantined {
		t.st.state = Unknown
		t.st.consecFails = 0
		t.st.consecOK = 0
		t.st.stabilityRequired = false
		t.st.quarantineReason = ""
		t.st.lastObservation = time.Time{}
		t.st.lastChange = now
	}
}

// stabilityElapsedLocked reports whether the recovering node has gone the
// full window without a recorded failure. Stability is the absence of
// failures, so the promotion may fire on read as well as on the next
// success; a failure during the window resets the state earlier.
func (t *Tracker) stabilityElapsedLocked(now time.Time) bool {
	return t.st.state == Recovering && now.Sub(t.st.recoveringSince) >= t.cfg.StabilityWindow
}

// Snapshot is the published view of one node at a point in time. JSON keys
// are the agent→CLI health.json contract and must not be renamed without a
// schema version bump.
type Snapshot struct {
	State            State         `json:"state"`
	LastChange       time.Time     `json:"last_change"`
	LastObservation  time.Time     `json:"last_observation"`
	Age              time.Duration `json:"age"` // 0 if never observed
	QuarantineReason string        `json:"quarantine_reason,omitempty"`
	LastFailureKind  FailureKind   `json:"last_failure_kind,omitempty"`
}

// Effective returns the state after applying stability promotion and
// observation expiry: a recovering node whose window elapsed reports
// healthy; an old observation degrades the state to unknown rather than
// keeping the node eligible forever.
func (t *Tracker) Effective(now time.Time) Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.st.state
	if t.stabilityElapsedLocked(now) {
		st = Healthy
		// read-side promotion also clears the debt: the window passed
		t.st.state = Healthy
		t.st.stabilityRequired = false
		t.st.lastChange = now
	}
	s := Snapshot{
		State:            st,
		LastChange:       t.st.lastChange,
		LastObservation:  t.st.lastObservation,
		QuarantineReason: t.st.quarantineReason,
		LastFailureKind:  t.st.lastFailureKind,
	}
	if !t.st.lastObservation.IsZero() {
		s.Age = now.Sub(t.st.lastObservation)
		if s.Age > t.cfg.MaxObservationAge && st != Quarantined && st != Down {
			s.State = Unknown
		}
	} else {
		// startup window elapsed without any observation: still unknown;
		// explicit marker keeps UI honest about "never probed".
		s.Age = now.Sub(t.st.created)
	}
	return s
}
