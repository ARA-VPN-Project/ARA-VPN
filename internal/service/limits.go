package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aravpn/core/limits"
	"aravpn/core/plan"
	"aravpn/core/policy"
	"aravpn/internal/txlog"
)

// limitsTx is the audit-trail record; the AUTHORITATIVE identity lives in
// limits.state.json committed atomically with the config (review T06).
type limitsTx struct {
	Kind           string       `json:"kind"` // apply | applied
	PlanID         string       `json:"plan_id"`
	IdempotencyKey string       `json:"idempotency_key"`
	Config         LimitsConfig `json:"config"`
}

const limitsTxApply = "apply"

// limitsIdentity mirrors policy.ApplyIdentity for the limits state.
type limitsIdentity struct {
	PlanID         string    `json:"plan_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	AppliedAt      time.Time `json:"applied_at"`
}

type limitsStateFile struct {
	StateVersion int             `json:"state_version"`
	Config       *LimitsConfig   `json:"config"`
	Identity     *limitsIdentity `json:"identity,omitempty"`
}

const limitsStateVersion = 1

func (l *limitsExecutor) txlog() *txlog.Log {
	dir := l.svc.State.Root
	lg, _ := txlog.Open(filepath.Join(dir, "limits.txlog.jsonl"))
	return lg
}

// loadLimitsState reads the authoritative state file (legacy bare config
// also loads, with nil identity).
func (s *Service) loadLimitsState() (*LimitsConfig, *limitsIdentity, error) {
	b, err := os.ReadFile(s.State.LimitsPath())
	if os.IsNotExist(err) {
		return &LimitsConfig{
			SchemaVersion: 1,
			AccountID:     "default-account",
			DeviceID:      "default-device",
			Period:        limits.DefaultPeriod(),
		}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var sf limitsStateFile
	if err := json.Unmarshal(b, &sf); err == nil && sf.StateVersion == limitsStateVersion && sf.Config != nil {
		if err := sf.Config.Validate(); err != nil {
			return nil, nil, err
		}
		return sf.Config, sf.Identity, nil
	}
	var c LimitsConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, nil, fmt.Errorf("limits state unreadable: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, nil, fmt.Errorf("POLICY_INVALID: %w", err)
	}
	return &c, nil, nil
}

// commitLimitsState atomically writes config + identity as ONE rename
// under the caller-held directory lock (review T06: the whole
// read→precondition→effect→identity transaction is serialized).
func (s *Service) commitLimitsState(c *LimitsConfig, id *limitsIdentity) error {
	sf := limitsStateFile{StateVersion: limitsStateVersion, Config: c, Identity: id}
	b, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(s.State.Root, ".limits.state.json.tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.State.LimitsPath())
}

// LimitsConfig is the on-disk limits document: one account scope, one
// device scope, both enforced jointly. nil rates/quota = unlimited;
// 0 = forbidden (docs/LIMITS_QUOTAS.md).
type LimitsConfig struct {
	SchemaVersion int           `json:"schema_version"`
	AccountID     string        `json:"account_id"`
	DeviceID      string        `json:"device_id"`
	Account       AccountLimits `json:"account"`
	Device        DeviceLimits  `json:"device"`
	Period        limits.Period `json:"period"`
}

// AccountLimits / DeviceLimits carry both rate and volume.
type AccountLimits struct {
	Rate       limits.RateConfig `json:"rate"`
	TotalBytes *int64            `json:"total_bytes,omitempty"`
}

type DeviceLimits struct {
	Rate       limits.RateConfig `json:"rate"`
	TotalBytes *int64            `json:"total_bytes,omitempty"`
}

func (c *LimitsConfig) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("limits schema_version %d unsupported", c.SchemaVersion)
	}
	if err := c.Account.Rate.Validate(); err != nil {
		return fmt.Errorf("account rate: %w", err)
	}
	if err := c.Device.Rate.Validate(); err != nil {
		return fmt.Errorf("device rate: %w", err)
	}
	if c.Account.TotalBytes != nil && *c.Account.TotalBytes < 0 {
		return fmt.Errorf("account total_bytes must be >= 0")
	}
	if c.Device.TotalBytes != nil && *c.Device.TotalBytes < 0 {
		return fmt.Errorf("device total_bytes must be >= 0")
	}
	if _, err := c.Period.Location(); err != nil {
		return fmt.Errorf("period: %w", err)
	}
	return nil
}

// LoadLimitsConfig reads the authoritative limits state (envelope with
// identity or legacy bare config; review T06); missing file = unlimited
// everything.
func (s *Service) LoadLimitsConfig() (*LimitsConfig, error) {
	c, _, err := s.loadLimitsState()
	return c, err
}

// saveLimitsConfig replaces the limits document atomically (tmp + fsync +
// rename): readers never see a truncated config and a crash cannot leave
// a half-written file (review S06 TOCTOU fix).
func (s *Service) saveLimitsConfig(c *LimitsConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(s.State.Root, ".limits.json.tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.State.LimitsPath())
}

// effectiveQuotaBytes returns the tighter of account/device totals.
func effectiveQuotaBytes(account, device *int64) *int64 {
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

// LimitsShow is the user-facing usage view.
type LimitsShow struct {
	AccountID    string    `json:"account_id"`
	DeviceID     string    `json:"device_id"`
	DownloadBPS  *int64    `json:"download_bps"`
	UploadBPS    *int64    `json:"upload_bps"`
	AccountTotal *int64    `json:"account_total_bytes"`
	DeviceTotal  *int64    `json:"device_total_bytes"`
	Used         int64     `json:"used_bytes"`
	Remaining    *int64    `json:"remaining_bytes"`
	ResetAt      time.Time `json:"reset_at"`
	Timezone     string    `json:"timezone"`
	Exhausted    bool      `json:"exhausted"`
	Threshold    string    `json:"threshold_hit,omitempty"`
}

// LimitsShow computes status from config plus the durable journal. It
// never trusts client-side reports of usage. Volume accounting reads the
// AUTHORITATIVE shared state (review S05): Used is the whole account's
// committed spend (every device), Remaining is the tighter of the
// account and this device's remainders, Exhausted is account OR device.
func (s *Service) LimitsShow() (*LimitsShow, error) {
	cfg, err := s.LoadLimitsConfig()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	view := &LimitsShow{
		AccountID:    cfg.AccountID,
		DeviceID:     cfg.DeviceID,
		DownloadBPS:  effectiveRate(cfg.Account.Rate.DownloadBPS, cfg.Device.Rate.DownloadBPS),
		UploadBPS:    effectiveRate(cfg.Account.Rate.UploadBPS, cfg.Device.Rate.UploadBPS),
		AccountTotal: cfg.Account.TotalBytes,
		DeviceTotal:  cfg.Device.TotalBytes,
		Timezone:     periodTZ(cfg.Period),
	}
	if cfg.Account.TotalBytes == nil && cfg.Device.TotalBytes == nil {
		view.ResetAt, _ = cfg.Period.ResetAt(now)
		return view, nil
	}
	jr, err := limits.OpenFileJournal(s.State.LimitsDir())
	if err != nil {
		return nil, err
	}
	ledger, err := limits.NewQuotaLedger(cfg.AccountID, cfg.Account.TotalBytes, cfg.Period, jr, now)
	if err != nil {
		return nil, err
	}
	ledger.SetDeviceLimit(cfg.DeviceID, cfg.Device.TotalBytes)
	dev, err := ledger.DeviceTracker(cfg.DeviceID, now)
	if err != nil {
		return nil, err
	}
	acc := ledger.AccountState(now)
	dst := dev.Snapshot(now)
	view.ResetAt = acc.ResetAt
	if acc.ResetAt.IsZero() {
		view.ResetAt = dst.ResetAt
	}
	view.Used = acc.Used
	// tighter of the two remaining budgets; nil = unlimited
	switch {
	case acc.Remaining == nil:
		view.Remaining = dst.Remaining
	case dst.Remaining == nil:
		view.Remaining = acc.Remaining
	case *acc.Remaining <= *dst.Remaining:
		view.Remaining = acc.Remaining
	default:
		view.Remaining = dst.Remaining
	}
	view.Exhausted = acc.Exhausted || dst.Exhausted
	// threshold reflects the binding budget (the lower remaining)
	if acc.ThresholdHit != "" && (dst.ThresholdHit == "" || acc.ThresholdHit > dst.ThresholdHit) {
		view.Threshold = acc.ThresholdHit
	} else {
		view.Threshold = dst.ThresholdHit
	}
	return view, nil
}

func effectiveRate(a, b *int64) *int64 {
	return limits.EffectiveRate(a, b)
}

func periodTZ(p limits.Period) string {
	if p.TZ == "" {
		return "UTC"
	}
	return p.TZ
}

// limitsExecutor is the plan.Executor for the "limits" kind. Preconditions:
// the stored limits revision must match what the plan was computed from.
type limitsExecutor struct {
	svc *Service
}

func (l *limitsExecutor) Kind() string { return "limits" }

type limitsChanges struct {
	ExpectedConfigHash string       `json:"expected_config_hash"`
	Config             LimitsConfig `json:"config"`
}

func (l *limitsExecutor) Check(p *plan.Plan, now time.Time) error {
	var ch limitsChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return fmt.Errorf("plan changes unreadable: %w", err)
	}
	cur, err := l.svc.LoadLimitsConfig()
	if err != nil {
		return err
	}
	h, err := hashLimits(cur)
	if err != nil {
		return err
	}
	if ch.ExpectedConfigHash != h {
		return fmt.Errorf("limits changed since plan (expected %s, current %s)", shortHash(ch.ExpectedConfigHash), shortHash(h))
	}
	return ch.Config.Validate()
}

// RecognizeAlreadyApplied implements plan.EffectRecognizer (review S06 +
// T06): identity is the state file's apply identity committed atomically
// with the config. A DIFFERENT stale plan with identical target content
// cannot borrow another plan's successful effect — it keeps its genuine
// CONFLICT.
func (l *limitsExecutor) RecognizeAlreadyApplied(p *plan.Plan) (plan.Result, bool) {
	var ch limitsChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return plan.Result{}, false
	}
	cur, id, err := l.svc.loadLimitsState()
	if err != nil || id == nil {
		return plan.Result{}, false
	}
	if id.PlanID != p.ID || id.IdempotencyKey != p.IdempotencyKey {
		return plan.Result{}, false
	}
	h, err := hashLimits(cur)
	if err != nil {
		return plan.Result{}, false
	}
	chHash, err := hashLimits(&ch.Config)
	if err != nil {
		return plan.Result{}, false
	}
	if h != chHash {
		return plan.Result{}, false
	}
	_ = l.txlog().Append(limitsTx{Kind: "applied", PlanID: p.ID, IdempotencyKey: p.IdempotencyKey, Config: ch.Config})
	return plan.Result{Applied: true, Summary: map[string]string{"limits": "applied"}}, true
}

// Apply runs the WHOLE limits transaction under the cross-process state
// directory lock (review T06): re-read → precondition re-check → effect →
// identity commit. A plan whose base state moved by the time the lock was
// acquired loses with a CONFLICT; exactly one of many concurrent plans
// against the same base state commits, and a retry of the winner
// recognizes its own committed identity.
func (l *limitsExecutor) Apply(p *plan.Plan, now time.Time) (plan.Result, error) {
	var ch limitsChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return plan.Result{}, err
	}
	release, err := policy.LockDir(l.svc.State.Root)
	if err != nil {
		return plan.Result{}, fmt.Errorf("limits state lock: %w", err)
	}
	defer release()

	// precondition re-check INSIDE the transaction
	cur, _, err := l.svc.loadLimitsState()
	if err != nil {
		return plan.Result{}, err
	}
	curHash, err := hashLimits(cur)
	if err != nil {
		return plan.Result{}, err
	}
	if ch.ExpectedConfigHash != curHash {
		return plan.Result{}, fmt.Errorf("CONFLICT: limits base state moved (expected %s, current %s)", shortHash(ch.ExpectedConfigHash), shortHash(curHash))
	}
	if err := ch.Config.Validate(); err != nil {
		return plan.Result{}, fmt.Errorf("POLICY_INVALID: %w", err)
	}
	// audit trail; authoritative identity is the state file commit
	if err := l.txlog().Append(limitsTx{Kind: limitsTxApply, PlanID: p.ID, IdempotencyKey: p.IdempotencyKey, Config: ch.Config}); err != nil {
		return plan.Result{}, fmt.Errorf("limits txlog intent write failed: %w", err)
	}
	id := &limitsIdentity{PlanID: p.ID, IdempotencyKey: p.IdempotencyKey, AppliedAt: now.UTC()}
	if err := l.svc.commitLimitsState(&ch.Config, id); err != nil {
		return plan.Result{}, err
	}
	if err := l.txlog().Append(limitsTx{Kind: "applied", PlanID: p.ID, IdempotencyKey: p.IdempotencyKey, Config: ch.Config}); err != nil {
		return plan.Result{Applied: true, Summary: map[string]string{"limits": "applied"}},
			fmt.Errorf("applied but outcome marker not recorded: %w", err)
	}
	return plan.Result{Applied: true, Summary: map[string]string{"limits": "applied"}}, nil
}

func hashLimits(c *LimitsConfig) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256Sum(b)), nil
}

func shortHash(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// LimitsPlan stages a limits change as a plan document.
func (s *Service) LimitsPlan(candidate *LimitsConfig, now time.Time) (*plan.Plan, string, error) {
	if err := candidate.Validate(); err != nil {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: %w", err)
	}
	cur, err := s.LoadLimitsConfig()
	if err != nil {
		return nil, "", err
	}
	curHash, err := hashLimits(cur)
	if err != nil {
		return nil, "", err
	}
	ch, err := json.Marshal(limitsChanges{ExpectedConfigHash: curHash, Config: *candidate})
	if err != nil {
		return nil, "", err
	}
	p := &plan.Plan{
		ID:             NewPlanID("limits"),
		Kind:           "limits",
		CreatedAt:      now.UTC(),
		ExpiresAt:      now.UTC().Add(plan.DefaultTTL),
		Preconditions:  map[string]string{"limits.hash": curHash},
		Changes:        ch,
		IdempotencyKey: NewPlanID("idem"),
	}
	hash, err := p.Hash()
	if err != nil {
		return nil, "", err
	}
	reg, err := s.planRegistry()
	if err != nil {
		return nil, "", err
	}
	if _, err := reg.Stage(p); err != nil {
		return nil, "", err
	}
	if err := reg.Save(p); err != nil {
		return nil, "", err
	}
	return p, hash, nil
}

// LimitsApply applies a staged limits plan under the full plan discipline.
func (s *Service) LimitsApply(planID, hash string) (*plan.Result, error) {
	reg, err := s.planRegistry()
	if err != nil {
		return nil, err
	}
	return reg.Apply(planID, hash, time.Now().UTC())
}
