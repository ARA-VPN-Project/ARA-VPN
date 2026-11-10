// Command ara-edge is the ARA Edge data-plane component for the lab
// vertical slice: it terminates authenticated VLESS/TLS (TCP profile) and
// SOCKS5 (UDP-profile relay, TCP-only) access, enforces per-connection
// identity (VLESS device UUID; SOCKS5 RFC 1929 user/pass), per-identity
// policy and account/device rate/quota limits on real copied bytes,
// verifies domain destinations through resolution + system ACL before any
// egress (dial is pinned to the verified IP), selects the exit via the
// accepted core/routing policy with live END-TO-END health probes (VLESS
// handshake + HTTP roundtrip to the exit's own canary), and forwards
// traffic to the selected exit over a second authenticated VLESS/TLS hop
// (sing-box exit + freedom outbound).
//
// It does not run as root, does not touch host routing, and exposes no
// management surface except a local status JSON file. Transport-over-UDP
// profiles terminate on the sing-box edge process and are relayed to this
// component's SOCKS5 TCP listener (authenticated); inner UDP is not
// supported by the v1 slice and is never released outside the tunnel.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"aravpn/core/health"
	"aravpn/core/limits"
	"aravpn/core/policy"
	"aravpn/core/routing"
	"aravpn/core/speedtest"
	"aravpn/internal/backbone"
	"aravpn/internal/controlstore"
	"aravpn/internal/edgeconfval"
	"aravpn/internal/transport"
)

// speedtestBudgets mirrors service.SpeedtestBudgetPresets for the
// edge-side admin runner (byte/duration bounds before the server caps).
// speedtestBurstExtra: sampling window extra beyond the last direction.
const speedtestBurstExtra = 2 * time.Second

var speedtestBudgets = map[string]speedtest.Budget{
	"quick":    {BytesPerDirection: 8 << 20, Duration: 10 * time.Second, RTTProbes: 16, WarmupDuration: time.Second},
	"extended": {BytesPerDirection: 64 << 20, Duration: 20 * time.Second, RTTProbes: 24, WarmupDuration: 2 * time.Second},
}

type exitNode struct {
	Backbone  *backbone.Binding `json:"backbone,omitempty"`
	ID        string            `json:"id"`
	Country   string            `json:"country"`
	Role      string            `json:"role"`
	Priority  int               `json:"priority"`
	SOCKSAddr string            `json:"socks_addr"`
	ProbeAddr string            `json:"probe_addr"`
	// DNSAddr is the resolver reachable from THIS exit's network scope
	// (host:port); domain destinations are resolved through the exit via
	// DNS over TCP. Empty = domain destinations are refused for this exit.
	DNSAddr string `json:"dns_addr"`
	// ProbeExpect is the canary body marker a healthy probe must contain
	// (full HTTP roundtrip); default "CANARY".
	ProbeExpect string `json:"probe_expect"`
}

// rateConf mirrors limits.RateConfig in edge config. null = unlimited;
// 0 is rejected in product configuration (a forbidden direction is policy
// BLOCK, not a quota) while the core keeps supporting it for tests.
type rateConf struct {
	DownloadBPS        *int64 `json:"download_bps"`
	UploadBPS          *int64 `json:"upload_bps"`
	DownloadBurstBytes *int64 `json:"download_burst_bytes,omitempty"`
	UploadBurstBytes   *int64 `json:"upload_burst_bytes,omitempty"`
}

func (r *rateConf) validate(where string) error {
	if r == nil {
		return nil
	}
	// B14: 0 is a VALID product value meaning "direction forbidden" (the
	// core keeps null=unlimited); the old blanket rejection confused the
	// three states. Only negatives are invalid here.
	for _, f := range []struct {
		name string
		p    *int64
	}{{"download_bps", r.DownloadBPS}, {"upload_bps", r.UploadBPS}} {
		if f.p != nil && *f.p < 0 {
			return fmt.Errorf("%s %s: negative rate is invalid", where, f.name)
		}
	}
	return r.toRateConfig().Validate()
}

func (r *rateConf) toRateConfig() limits.RateConfig {
	if r == nil {
		return limits.RateConfig{}
	}
	return limits.RateConfig{
		DownloadBPS:        r.DownloadBPS,
		UploadBPS:          r.UploadBPS,
		DownloadBurstBytes: r.DownloadBurstBytes,
		UploadBurstBytes:   r.UploadBurstBytes,
	}
}

// deviceAuth is one statically configured device identity. The UUID
// authenticates VLESS access; the SOCKSUser/SOCKSPass pair authenticates
// SOCKS5 access; both map to the same DeviceID used for enforcement.
type deviceAuth struct {
	UUID        string    `json:"uuid"`
	DeviceID    string    `json:"device_id"`
	SOCKSUser   string    `json:"socks_user,omitempty"`
	SOCKSPass   string    `json:"socks_pass,omitempty"`
	QuotaBytes  *int64    `json:"quota_bytes,omitempty"`
	ExpiresUnix int64     `json:"expires_unix,omitempty"`
	Rate        *rateConf `json:"rate,omitempty"`
	// B20: identity→budget mapping. Every device belongs to exactly ONE
	// subscription context (unique UUID across contexts is validated), so
	// its traffic draws from that subscription's ledger and its account's
	// shared rate regime — never another account's budget.
	SubID     string `json:"subscription_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
}

// subContext is one served subscription: its own quota ledger (B20) and
// its account's shared rate regime. Devices listed here authenticate only
// into this context.
type subContext struct {
	SubscriptionID string    `json:"subscription_id"`
	AccountID      string    `json:"account_id,omitempty"`
	AccountRate    *rateConf `json:"account_rate,omitempty"`
	// OwnerURL (C09): this context's OWN authoritative budget endpoint —
	// ledgers of different owner panels never share one OwnerURL.
	OwnerURL string `json:"owner_url,omitempty"`
	// Routes (C05): exits THIS subscription may reach through pinned
	// route listeners; enforced server-side before any egress.
	Routes            []string         `json:"routes,omitempty"`
	LocalPinnedRoutes []string         `json:"local_pinned_routes,omitempty"`
	PolicyRouting     bool             `json:"policy_routing,omitempty"`
	LocalQuota        *int64           `json:"-"`
	Devices           []deviceAuth     `json:"devices"`
	ProfileBudgets    map[int]string   `json:"profile_budgets,omitempty"`
	ProfileRates      map[int]rateConf `json:"profile_rates,omitempty"`
}

// routeAllowed reports whether the subscription context grants the pinned
// exit (C05): the catalog hiding a route is not authorization.
func (c *subContext) routeAllowed(exitID string) bool {
	for _, r := range c.Routes {
		if r == exitID {
			return true
		}
	}
	return false
}

// routeListen (B23): a dedicated client-facing listener pinned to one
// exit. The exit choice is NOT health/priority-based: the published route
// is the configured edge→exit binding; a down exit refuses connections
// instead of silently rerouting.
type routeListen struct {
	Listen string `json:"listen"`
	ExitID string `json:"exit_id"`
}

type edgeConfig struct {
	TrojanIngress          bool              `json:"trojan_ingress,omitempty"`
	LocalPanel             *localPanelSource `json:"local_panel,omitempty"`
	localSubscriptionsHash [32]byte
	AccessListen           string `json:"access_listen"`
	SOCKSListen            string `json:"socks_listen"`
	TLSCert                string `json:"tls_cert"`
	TLSKey                 string `json:"tls_key"`
	CACert                 string `json:"ca_cert"`
	// DeviceUUID is the legacy single-device identity; it is normalized
	// into Devices at load time.
	DeviceUUID  string       `json:"device_uuid"`
	Devices     []deviceAuth `json:"devices"`
	AccountRate *rateConf    `json:"account_rate"`
	PolicyFile  string       `json:"policy_file"`
	// B15: LAN exceptions are EXPLICIT operator configuration; the lab
	// canary CIDRs are enabled only by the test-scope flag below.
	LANExceptions         []string   `json:"lan_exceptions,omitempty"`
	AllowLabLANExceptions bool       `json:"allow_lab_lan_exceptions,omitempty"`
	StateDir              string     `json:"state_dir"`
	StatusFile            string     `json:"status_file"`
	Exits                 []exitNode `json:"exits"`
	ProbeIntervalS        int        `json:"probe_interval_s"`
	StabilityWindowS      int        `json:"stability_window_s"`
	ProbeTimeoutMs        int        `json:"probe_timeout_ms"`
	CurrentForeign        string     `json:"current_foreign_id"`
	QuotaBytes            int64      `json:"quota_bytes"`
	// QuotaRemote switches the shared-volume accounting to the owning
	// panel's authoritative ledger (federation mode); nil = local journal.
	QuotaRemote *remoteQuotaConfig `json:"quota_remote,omitempty"`
	// B20: per-subscription serving contexts (each with its own ledger).
	// Empty = legacy single-context config (normalized at load).
	Subscriptions []subContext `json:"subscriptions,omitempty"`
	// B23: dedicated pinned-exit route listeners.
	Routes []routeListen `json:"routes,omitempty"`
	// B21: the panel-published accepted policy (source of truth); when
	// present it overrides the local policy_file.
	Policy *policy.Policy `json:"policy,omitempty"`

	configPath     string `json:"-"`
	configSnapshot string `json:"-"` // H01: sha256 of the loaded/validated bytes
}

// normalizeSubscriptionContexts flattens the per-subscription contexts
// into the flat device table (every device tagged with its budget owner)
// and validates that an identity maps to exactly one subscription — two
// contexts claiming one UUID would make budget routing ambiguous.
func (c *edgeConfig) normalizeSubscriptionContexts() error {
	if len(c.Subscriptions) == 0 && c.LocalPanel == nil {
		sub := ""
		if c.QuotaRemote != nil {
			sub = c.QuotaRemote.SubscriptionID
		}
		c.Subscriptions = []subContext{{
			SubscriptionID: sub, AccountRate: c.AccountRate, Devices: c.Devices,
		}}
	}
	// The explicit `devices` field is authoritative for the device rows
	// (B04 reload semantics: an operator edit to devices — add, remove or
	// per-device quota/rate change — must take effect), while the contexts
	// carry the budget mapping. Rebuild context membership from `devices`:
	// a device keeps the context that already claimed its UUID; a new
	// device joins the primary context.
	if len(c.Devices) > 0 {
		ctxOfUUID := map[string]int{}
		for ci := range c.Subscriptions {
			for _, d := range c.Subscriptions[ci].Devices {
				ctxOfUUID[strings.ToLower(d.UUID)] = ci
			}
		}
		for ci := range c.Subscriptions {
			c.Subscriptions[ci].Devices = nil
		}
		for _, d := range c.Devices {
			ci, known := ctxOfUUID[strings.ToLower(d.UUID)]
			if !known {
				ci = 0 // new identities serve the primary context
			}
			c.Subscriptions[ci].Devices = append(c.Subscriptions[ci].Devices, d)
		}
	}
	seen := map[string]string{}
	var flat []deviceAuth
	for _, ctx := range c.Subscriptions {
		for _, d := range ctx.Devices {
			key := strings.ToLower(d.UUID)
			if prev, dup := seen[key]; dup {
				return fmt.Errorf("VALIDATION_FAILED: device uuid %s claimed by subscriptions %s and %s (identity must map to exactly one budget)", d.UUID, prev, ctx.SubscriptionID)
			}
			seen[key] = ctx.SubscriptionID
			d.SubID = ctx.SubscriptionID
			d.AccountID = ctx.AccountID
			flat = append(flat, d)
		}
	}
	c.Devices = flat
	return nil
}

func (c *edgeConfig) validate() error {
	// F02: the runtime enforces the SHARED typed identity/exit rules
	// (internal/edgeconfval) on the same JSON shape the sync validates —
	// the two paths cannot drift.
	if b, err := json.Marshal(struct {
		Devices []deviceAuth `json:"devices"`
		Exits   []exitNode   `json:"exits"`
	}{c.Devices, c.Exits}); err == nil {
		if err := edgeconfval.Validate(b); err != nil {
			// the runtime keeps its own wording for the legacy
			// device_uuid shortcut; shared rules apply on top
			if len(c.Devices) > 0 {
				return err
			}
		}
	}
	if c.DeviceUUID == "" && len(c.Devices) == 0 && c.LocalPanel == nil {
		return fmt.Errorf("edge config: devices or device_uuid are required")
	}
	if len(c.Exits) == 0 {
		return fmt.Errorf("edge config: exits are required")
	}
	if c.QuotaBytes == 0 {
		return fmt.Errorf("edge config: quota_bytes is required")
	}
	if c.DeviceUUID != "" && len(c.Devices) == 0 {
		c.Devices = []deviceAuth{{UUID: c.DeviceUUID, DeviceID: c.DeviceUUID}}
	}
	seenUUID, seenID, seenUser := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.UUID == "" {
			return fmt.Errorf("edge config: devices[%d].uuid is required", i)
		}
		if d.DeviceID == "" {
			d.DeviceID = d.UUID
		}
		if seenUUID[strings.ToLower(d.UUID)] {
			return fmt.Errorf("edge config: duplicate device uuid %s", d.UUID)
		}
		seenUUID[strings.ToLower(d.UUID)] = true
		if seenID[d.DeviceID] {
			return fmt.Errorf("edge config: duplicate device_id %s", d.DeviceID)
		}
		seenID[d.DeviceID] = true
		if d.SOCKSUser != "" {
			if seenUser[d.SOCKSUser] {
				return fmt.Errorf("edge config: duplicate socks_user %s", d.SOCKSUser)
			}
			seenUser[d.SOCKSUser] = true
			if d.SOCKSPass == "" {
				return fmt.Errorf("edge config: socks_user %s requires socks_pass", d.SOCKSUser)
			}
		}
		if err := d.Rate.validate("device rate"); err != nil {
			return err
		}
		// B14: device quota_bytes 0 = the device may not spend — a valid
		// explicit override (the ledger treats 0 as exhausted-from-start).
	}
	if err := c.AccountRate.validate("account_rate"); err != nil {
		return err
	}
	for _, e := range c.Exits {
		if e.DNSAddr != "" {
			if _, _, err := parseHostPort(e.DNSAddr); err != nil {
				return fmt.Errorf("edge config: exit %s dns_addr %q must be host:port", e.ID, e.DNSAddr)
			}
		}
	}
	if c.ProbeIntervalS == 0 {
		c.ProbeIntervalS = 2
	}
	return nil
}

func tlsCACertFlag(path string) *tls.Config {
	ca, err := os.ReadFile(path)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return &tls.Config{RootCAs: pool, ServerName: "edge.ara.lab", MinVersion: tls.VersionTLS12}
}

var tlsCACertFlagPath string

func dpExitTLS(path string) *tls.Config { return tlsCACertFlag(path) }

func loadConfig(path string) (*edgeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c edgeConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if err := c.loadLocalSubscriptions(); err != nil {
		return nil, err
	}
	if err := c.normalizeSubscriptionContexts(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	// H01: the snapshot identity is the sha256 of the EXACT bytes this
	// load parsed and validated — serving ack names these bytes, never a
	// later re-read of the path (which may hold an unaccepted publication).
	sum := sha256.Sum256(b)
	c.configSnapshot = fmt.Sprintf("%x", sum)
	c.configPath = path
	return &c, nil
}

// loadPolicy resolves the edge policy. A supplied policy that is unreadable
// or invalid is a hard startup error (TR05): it must never silently become
// the permissive embedded default, and the accepted core store envelope
// format is enforced as-is. The embedded default is only for processes
// configured without a policy file (first run / lab fixtures).
// loadPolicyFor resolves the enforced policy: the panel-PUBLISHED document
// (B21: the accepted source of truth travels with the generated config)
// takes precedence; the operator-managed policy_file is the fallback for
// standalone edges.
func loadPolicyFor(cfg *edgeConfig) (*policy.Policy, error) {
	if cfg.Policy != nil {
		if err := cfg.Policy.Validate(); err != nil {
			return nil, fmt.Errorf("published policy invalid: %w", err)
		}
		return cfg.Policy, nil
	}
	return loadPolicy(cfg.PolicyFile)
}

func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return defaultEdgePolicy(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy file unreadable: %w", err)
	}
	p, _, err := policy.ParseState(b)
	if err != nil {
		return nil, fmt.Errorf("policy invalid: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("policy invalid: %w", err)
	}
	return p, nil
}

// defaultEdgePolicy is the embedded lab fallback used ONLY when no policy
// file is configured. It is not the operator's LKG.
func defaultEdgePolicy() *policy.Policy {
	return &policy.Policy{
		SchemaVersion:   1,
		Revision:        1,
		AllowRUFallback: true,
		Rules: []policy.Rule{
			{ID: "ru-net", Enabled: true, CIDR: []string{"10.71.0.0/16"}, Action: policy.ActionRUExit},
		},
	}
}

type exitProbeMeasurement struct {
	at time.Time
	ms *float64
}

type edgeDatapath struct {
	profileLimiters   map[localProfileKey]*limits.AggregateLimiter
	profilePools      map[localProfileKey]*profilePool
	localActivityMu   sync.Mutex
	localActivity     map[localActivityKey]localActivityCount
	localConnections  map[string]int
	downloadBytes     atomic.Uint64
	uploadBytes       atomic.Uint64
	probeMeasurements sync.Map // exit ID → exitProbeMeasurement

	mu                 sync.Mutex
	cfgPtr             atomic.Pointer[edgeConfig]
	localPanelVerified atomic.Int64
	cfg                *edgeConfig
	pol                *policy.Policy
	acl                policy.SystemACL
	topo               routing.Topology
	health             map[string]*health.Tracker

	// limiter is the limiter of the slice's primary device; devices with
	// explicit rate configs get their own AggregateLimiter in limiters,
	// all bound to the one shared account regime.
	limiter  *limits.AggregateLimiter
	limiters map[string]*limits.AggregateLimiter
	quota    quotaLedger
	// B20: per-subscription ledgers and per-account rate regimes. A
	// device's flows draw from ledgers[device.SubID] and the limiter of
	// accounts[device.AccountID] — budgets and rates never leak across.
	ledgers         map[string]quotaLedger
	remoteRates     map[string]*remoteQuotaLedger
	accountRegimes  map[string]*limits.AccountRegime
	accountLimiters map[string]*limits.AggregateLimiter
	byDeviceID      map[string]deviceAuth
	remoteApplied   map[string][2]*int64 // accountID → last applied (down, up)
	gen             uint64
	// remoteRate exposes the owner's authoritative rate split (federation
	// mode); the datapath rebinds limiters when the EFFECTIVE share
	// changes.
	remoteRate interface {
		RateShare() (*int64, *int64, uint64)
		RenewRate(deviceID string)
	}
	// remoteRateApplied remembers the last applied share: re-applying the
	// same right must not rebuild the limiter (a control-plane event
	// never mints a fresh token burst — review FED08).
	remoteRateDown *int64
	remoteRateUp   *int64

	devices    map[string]deviceAuth // lowercased uuid → device
	socksUsers map[string]deviceAuth // socks user → device
	ident      map[net.Conn]string   // authenticated device per live conn

	// resolveExit resolves a domain inside the given exit's DNS scope;
	// replaced in tests. The default sends DNS over TCP through the exit
	// hop — never the edge host's own resolver.
	resolveExit func(ctx context.Context, e exitNode, host string) ([]netip.Addr, error)
}

func newDatapath(cfg *edgeConfig) (*edgeDatapath, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	pol, err := loadPolicyFor(cfg)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	hcfg := health.DefaultConfig()
	if cfg.StabilityWindowS > 0 {
		hcfg.StabilityWindow = time.Duration(cfg.StabilityWindowS) * time.Second
	}
	// slice topology: canaries live in 10.71/16 (RU) and 10.72/16
	// (foreign) — explicit administrator LAN exceptions for the lab,
	// everything else private/metadata stays denied (docs/SECURITY.md)
	// B15: LAN exceptions are EXPLICIT operator configuration; the old
	// built-in 10.71/10.72 lab CIDRs never leak into production behavior.
	lanExceptions := cfg.LANExceptions
	if len(lanExceptions) == 0 && cfg.AllowLabLANExceptions {
		lanExceptions = []string{"10.71.0.0/16", "10.72.0.0/16"} // lab scope only
	}
	dp := &edgeDatapath{
		cfg:             cfg,
		cfgPtr:          atomic.Pointer[edgeConfig]{},
		pol:             pol,
		acl:             policy.SystemACL{DenyNonGlobal: true, LANExceptions: lanExceptions},
		health:          map[string]*health.Tracker{},
		limiters:        map[string]*limits.AggregateLimiter{},
		ledgers:         map[string]quotaLedger{},
		remoteRates:     map[string]*remoteQuotaLedger{},
		accountRegimes:  map[string]*limits.AccountRegime{},
		accountLimiters: map[string]*limits.AggregateLimiter{},
		remoteApplied:   map[string][2]*int64{},
		byDeviceID:      map[string]deviceAuth{},
		devices:         map[string]deviceAuth{},
		socksUsers:      map[string]deviceAuth{},
		ident:           map[net.Conn]string{},
		resolveExit:     dnsOverTCPThroughExit,
	}
	applyExitProbeDefaults(cfg)
	dp.topo = routing.Topology{CurrentForeignID: cfg.CurrentForeign}
	for i := range cfg.Exits {
		e := &cfg.Exits[i]
		role := routing.RoleForeign
		if e.Role == "ru" {
			role = routing.RoleRU
		}
		dp.topo.Exits = append(dp.topo.Exits, routing.Exit{ID: e.ID, Country: e.Country, Priority: e.Priority, Role: role})
		tr, err := health.NewTracker(hcfg, now)
		if err != nil {
			return nil, err
		}
		dp.health[e.ID] = tr
	}
	for _, d := range cfg.Devices {
		dp.devices[strings.ToLower(d.UUID)] = d
		dp.byDeviceID[d.DeviceID] = d
		if d.SOCKSUser != "" {
			dp.socksUsers[d.SOCKSUser] = d
		}
	}
	if err := dp.buildContexts(now); err != nil {
		return nil, err
	}
	dp.publishConfig(cfg)
	return dp, nil
}

// buildContexts creates one quota ledger per subscription context and one
// aggregate rate regime per ACCOUNT (B20: rate/burst never multiply by
// subscriptions, profiles or processes — devices of one account share the
// account limiter; per-device rate overrides bind into it).
func (dp *edgeDatapath) buildContexts(now time.Time) error {
	cfg := dp.cfg
	// configs constructed directly (tests, embedded fixtures) bypass
	// loadConfig: normalize here as well (idempotent)
	if err := cfg.normalizeSubscriptionContexts(); err != nil {
		return err
	}
	jr, err := limits.OpenFileJournal(cfg.StateDir)
	if err != nil {
		return err
	}
	legacyAccount := cfg.DeviceUUID
	if legacyAccount == "" && len(cfg.Devices) > 0 {
		legacyAccount = cfg.Devices[0].DeviceID
	}
	for ci := range cfg.Subscriptions {
		ctx := &cfg.Subscriptions[ci]
		subID := ctx.SubscriptionID
		if subID == "" {
			subID = "local"
			ctx.SubscriptionID = subID
		}
		account := ctx.AccountID
		if account == "" {
			account = legacyAccount
			ctx.AccountID = account
		}
		if cfg.QuotaRemote != nil && dp.ledgers[subID] == nil {
			rc := *cfg.QuotaRemote
			rc.SubscriptionID = subID
			if ctx.OwnerURL != "" {
				// C09: the context's OWN authoritative budget endpoint
				rc.OwnerURL = ctx.OwnerURL
			}
			// per-subscription snapshot file: two ledgers never share one
			// state file (a shared file would spend one credit twice)
			rc.StateFile = fmt.Sprintf("quota-remote-%s.json", sanitizeStateName(subID))
			if subID == cfg.QuotaRemote.SubscriptionID {
				rc.StateFile = "quota_remote.json" // continuity for the primary
			}
			q, rerr := newRemoteQuotaLedger(rc, cfg.StateDir)
			if rerr != nil {
				return rerr
			}
			dp.ledgers[subID] = q
			dp.remoteRates[subID] = q
		} else if dp.ledgers[subID] == nil {
			total := cfg.QuotaBytes
			limit := &total
			if cfg.LocalPanel != nil {
				limit = localLedgerLimit(ctx.LocalQuota)
			}
			q, qerr := limits.NewQuotaLedger(account, limit, limits.DefaultPeriod(), jr, now)
			if qerr != nil {
				return qerr
			}
			dp.ledgers[subID] = q
		}
		if _, exists := dp.accountLimiters[account]; !exists {
			rate := ctx.AccountRate
			if rate == nil {
				rate = cfg.AccountRate
			}
			regime, rerr := limits.NewAccountRegime(rate.toRateConfig(), now)
			if rerr != nil {
				return rerr
			}
			dp.accountRegimes[account] = regime
			// the account limiter carries the context primary's device
			// buckets (legacy shape); every OTHER device binds its own
			// limiter below
			var primary deviceAuth
			if len(ctx.Devices) > 0 {
				primary = ctx.Devices[0]
			}
			lim, berr := regime.BindDevice(primary.Rate.toRateConfig(), now)
			if berr != nil {
				return berr
			}
			dp.accountLimiters[account] = lim
			if primary.Rate != nil && primary.DeviceID != "" {
				dp.limiters[primary.DeviceID] = lim
			}
		}
	}
	if err := dp.buildProfileLimiters(now); err != nil {
		return err
	}
	if dp.quota == nil {
		if dp.ledgers["local"] != nil {
			dp.quota = dp.ledgers["local"]
		} else {
			for _, led := range dp.ledgers {
				dp.quota = led
				break
			}
		}
	}
	// per-device limiters and per-ledger device quota overrides
	for _, d := range cfg.Devices {
		led := dp.ledgerFor(d.SubID)
		if led == nil {
			led = dp.quota
		}
		if led != nil {
			led.SetDeviceLimit(d.DeviceID, d.QuotaBytes)
		}
		if d.Rate == nil {
			continue
		}
		if existing, has := dp.limiters[d.DeviceID]; has {
			// carried limiter: re-bind the device buckets WITH token
			// carry-over — a reload never mints a fresh device burst
			if err := existing.RebindDevice(d.Rate.toRateConfig(), now); err != nil {
				return err
			}
			continue
		}
		acc := d.AccountID
		if acc == "" {
			acc = legacyAccount
		}
		regime := dp.accountRegimes[acc]
		if regime == nil {
			continue // no override: the device shares the account limiter
		}
		l, berr := regime.BindDevice(d.Rate.toRateConfig(), now)
		if berr != nil {
			return berr
		}
		dp.limiters[d.DeviceID] = l
	}
	if dp.limiter == nil {
		if len(cfg.Devices) > 0 {
			d := cfg.Devices[0]
			acc := d.AccountID
			if acc == "" {
				acc = legacyAccount
			}
			dp.limiter = dp.accountLimiters[acc]
		}
		if dp.limiter == nil {
			for _, l := range dp.accountLimiters {
				dp.limiter = l
				break
			}
		}
	}
	return nil
}

func sanitizeStateName(s string) string {
	b := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b = append(b, r)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "unnamed"
	}
	return string(b)
}

// ledgerFor returns the quota ledger of the device's subscription context.
func (dp *edgeDatapath) ledgerFor(subID string) quotaLedger {
	if subID == "" {
		return dp.quota
	}
	dp.mu.Lock()
	defer dp.mu.Unlock()
	return dp.ledgers[subID]
}

// quotaFor resolves the flow's budget: the device's own subscription
// ledger (B20) — never another subscription's or account's. Callers may
// pass either the device id or the legacy UUID; when the identity is
// unknown the single-ledger edge falls back to its only budget.
func (dp *edgeDatapath) quotaFor(deviceID string) quotaLedger {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	if led := dp.quotaForLocked(deviceID); led != nil {
		return led
	}
	if d, ok := dp.devices[strings.ToLower(deviceID)]; ok && d.SubID != "" {
		if led, ok := dp.ledgers[d.SubID]; ok {
			return led
		}
	}
	if len(dp.ledgers) == 1 {
		for _, led := range dp.ledgers {
			return led
		}
	}
	return dp.quota
}

// applyRemoteRate rebinds the aggregate limiters to the owner's
// authoritative rate split (federation mode): the SHARED account rate is
// divided across active serving edges by the owner; each edge enforces
// its share locally, so parallel RU+DE traffic cannot exceed the global
// budget beyond token-bucket burst tolerance.
// configSnapshot atomically loads the published config snapshot (I02).
func (dp *edgeDatapath) configSnapshot() *edgeConfig {
	if p := dp.cfgPtr.Load(); p != nil {
		return p
	}
	return dp.cfg
}

// publishConfig atomically publishes a new config snapshot (I02).
func (dp *edgeDatapath) publishConfig(cfg *edgeConfig) {
	dp.cfg = cfg
	dp.cfgPtr.Store(cfg)
}

// applyAccountRate rebinds ONE account's regime to the owner's
// authoritative rate share (federation mode, B20): multiple served
// subscriptions of the same account contribute the TIGHTEST share (a
// redistributed right never becomes looser than any of its sources).
func (dp *edgeDatapath) applyAccountRate(account string, down, up *int64) {
	now := time.Now()
	dp.mu.Lock()
	defer dp.mu.Unlock()
	if dp.remoteApplied == nil {
		dp.remoteApplied = map[string][2]*int64{}
	}
	if dp.accountLimiters == nil {
		dp.accountLimiters = map[string]*limits.AggregateLimiter{}
	}
	if prev, ok := dp.remoteApplied[account]; ok &&
		sameRatePtr(prev[0], down) && sameRatePtr(prev[1], up) {
		return // same right: keep buckets and their token state
	}
	lim := dp.accountLimiters[account]
	if lim == nil {
		lim = dp.limiter
	}
	if lim == nil {
		regime, err := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: down, UploadBPS: up}, now)
		if err != nil {
			log.Printf("remote rate: %v", err)
			return
		}
		lim2, err := regime.BindDevice(limits.RateConfig{}, now)
		if err != nil {
			log.Printf("remote rate bind: %v", err)
			return
		}
		dp.accountLimiters[account] = lim2
		lim = lim2
		dp.limiter = lim2 // legacy alias: the first created regime is the default limiter
	} else if err := lim.RebindAccount(limits.RateConfig{DownloadBPS: down, UploadBPS: up}, now); err != nil {
		log.Printf("remote rate rebind: %v", err)
		return
	}
	dp.remoteApplied[account] = [2]*int64{down, up}
	if dp.limiter == lim || dp.limiter == nil {
		dp.remoteRateDown, dp.remoteRateUp = down, up
	}
}

// runRemoteRateSync polls every served subscription's rate share and
// rebinds the owning account's regime on change.
// syncRemoteAccountRates uses the CURRENT ledger set, including after a
// reload. A flow refreshes its expired right before the first rate decision;
// it must not be rejected merely because the background tick has not run.
func (dp *edgeDatapath) syncRemoteAccountRates(deviceID string) {
	dp.mu.Lock()
	rates := make(map[string]*remoteQuotaLedger, len(dp.remoteRates))
	accounts := make(map[string]string)
	target := dp.byDeviceID[deviceID].SubID
	for sub, q := range dp.remoteRates {
		rates[sub] = q
	}
	for _, d := range dp.byDeviceID {
		accounts[d.SubID] = d.AccountID
	}
	dp.mu.Unlock()
	type aggregate struct {
		down, up *int64
		set      bool
	}
	grouped := map[string]aggregate{}
	for sub, q := range rates {
		down, up, _ := q.RateShare()
		if down == nil || *down == 0 || up != nil && *up == 0 {
			if sub == target {
				q.RenewRate(deviceID)
			} else if deviceID == "" {
				q.RenewRate("")
			}
			down, up, _ = q.RateShare()
		}
		account := accounts[sub]
		if account == "" {
			account = "legacy"
		}
		a := grouped[account]
		if !a.set {
			a = aggregate{down, up, true}
		} else {
			a.down = tightestRate(a.down, down)
			a.up = tightestRate(a.up, up)
		}
		grouped[account] = a
	}
	for account, a := range grouped {
		dp.applyAccountRate(account, a.down, a.up)
	}
}
func (dp *edgeDatapath) runRemoteRateSync(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			dp.syncRemoteAccountRates("")
		}
	}
}

// tightestRate returns the stricter of two shares (nil = no information;
// 0 = explicit zero; positive = finite). An explicit zero always wins.
func tightestRate(a, b *int64) *int64 {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *a == 0:
		return a
	case *b == 0:
		return b
	case *a <= *b:
		return a
	default:
		return b
	}
}

// primaryDevice is the legacy single-device entry point for the default
// limiter; multi-device rate selection happens per connection in
// limiterFor (static config until enrollment lands in a later phase).
func (dp *edgeDatapath) primaryDevice() deviceAuth {
	cfg := dp.configSnapshot()
	for _, d := range cfg.Devices {
		if strings.EqualFold(d.UUID, cfg.DeviceUUID) {
			return d
		}
	}
	return cfg.Devices[0]
}

func (dp *edgeDatapath) limiterFor(deviceID string) *limits.AggregateLimiter {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	if l, ok := dp.limiters[deviceID]; ok {
		return l
	}
	if d, ok := dp.byDeviceID[deviceID]; ok && d.AccountID != "" {
		if l, ok := dp.accountLimiters[d.AccountID]; ok {
			return l
		}
	}
	return dp.limiter
}

func (dp *edgeDatapath) socksAuthConfigured() bool {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	return len(dp.socksUsers) > 0
}

func (dp *edgeDatapath) lookupUUID(uuid [16]byte) (deviceAuth, bool) {
	// B04: the RELOADED identity table is authoritative; dp.cfg.Devices is
	// only the startup snapshot and keeps serving revoked uuids after a
	// config-driven revoke.
	dp.mu.Lock()
	defer dp.mu.Unlock()
	for _, d := range dp.devices {
		if uuidBytes(d.UUID) == uuid && (d.ExpiresUnix == 0 || time.Now().Unix() < d.ExpiresUnix) {
			return d, true
		}
	}
	return deviceAuth{}, false
}

func (dp *edgeDatapath) lookupSOCKSUser(user string) (deviceAuth, bool) {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	d, ok := dp.socksUsers[user]
	return d, ok && (d.ExpiresUnix == 0 || time.Now().Unix() < d.ExpiresUnix)
}

func (dp *edgeDatapath) bindIdentity(conn net.Conn, dev deviceAuth) {
	dp.mu.Lock()
	dp.ident[conn] = dev.DeviceID
	dp.mu.Unlock()
}

func (dp *edgeDatapath) identityFor(conn net.Conn) (string, bool) {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	id, ok := dp.ident[conn]
	return id, ok
}

func uuidBytes(s string) [16]byte {
	var u [16]byte
	nib := func(c byte) byte {
		switch {
		case c >= '0' && c <= '9':
			return c - '0'
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10
		}
		return 0
	}
	i := 0
	for _, c := range []byte(s) {
		if c == '-' {
			continue
		}
		if i >= 32 {
			break
		}
		if i%2 == 0 {
			u[i/2] = nib(c) << 4
		} else {
			u[i/2] |= nib(c)
		}
		i++
	}
	return u
}

func (dp *edgeDatapath) exitTLS() *tls.Config {
	ca, err := os.ReadFile(dp.configSnapshot().CACert)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return &tls.Config{RootCAs: pool, ServerName: "edge.ara.lab", MinVersion: tls.VersionTLS12}
}

// ProbeError carries the health failure classification for a failed probe
// (auth/TLS quarantine immediately; transport kinds count toward down).
type ProbeError struct {
	Kind health.FailureKind
	Err  error
}

func (p *ProbeError) Error() string { return p.Err.Error() }
func (p *ProbeError) Unwrap() error { return p.Err }

// SOCKSStatusError is the exit hop's CONNECT refusal with its RFC 1928 REP
// code; REP=2 (not allowed by ruleset) is an authorization failure for the
// health classifier.
type SOCKSStatusError struct{ Rep byte }

func (e *SOCKSStatusError) Error() string {
	return fmt.Sprintf("socks: CONNECT rejected, code %d", e.Rep)
}

func probeFailureKind(err error) health.FailureKind {
	var pe *ProbeError
	if errors.As(err, &pe) {
		return pe.Kind
	}
	var se *SOCKSStatusError
	if errors.As(err, &se) {
		if se.Rep == 2 {
			return health.FailAuth
		}
		return health.FailConnRefused
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return health.FailTimeout
	}
	if strings.Contains(err.Error(), "connect: connection refused") {
		return health.FailConnRefused
	}
	return health.FailNetwork
}

const probeMaxResponse = 8 * 1024

// probeExit proves the exit path END-TO-END: a full HTTP roundtrip to the
// exit's own canary through the exit hop — a "200" substring in the first
// Read is not a roundtrip (review gate): the response must be a complete
// HTTP/1.x status line AND contain the canary body marker.
func (dp *edgeDatapath) probeExit(e exitNode, timeout time.Duration) error {
	if e.ProbeAddr == "" {
		return &ProbeError{health.FailServer, fmt.Errorf("exit %s has no probe_addr configured", e.ID)}
	}
	host, portStr, err := net.SplitHostPort(e.ProbeAddr)
	if err != nil {
		return &ProbeError{health.FailServer, fmt.Errorf("probe addr: %w", err)}
	}
	port, _ := strconv.Atoi(portStr)
	conn, err := e.dialSOCKS(context.Background(), host, port, timeout)
	if err != nil {
		return &ProbeError{probeFailureKind(err), fmt.Errorf("dial: %w", err)}
	}
	defer conn.Close()
	req := "GET /canary.txt HTTP/1.0\r\nHost: canary\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return &ProbeError{health.FailNetwork, fmt.Errorf("probe write: %w", err)}
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var resp bytes.Buffer
	buf := make([]byte, 1024)
	for {
		n, rerr := conn.Read(buf)
		if n > 0 {
			if resp.Len()+n > probeMaxResponse {
				return &ProbeError{health.FailServer, fmt.Errorf("probe: response exceeds %d bytes", probeMaxResponse)}
			}
			resp.Write(buf[:n])
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || resp.Len() > 0 {
				break // completed response or connection closed after data
			}
			return &ProbeError{health.FailTimeout, fmt.Errorf("probe read: %w", rerr)}
		}
	}
	data := resp.Bytes()
	if !bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return &ProbeError{health.FailServer, fmt.Errorf("probe: not an HTTP response: %q", truncateForLog(data))}
	}
	line := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		line = data[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 || fields[1] != "200" {
		return &ProbeError{health.FailServer, fmt.Errorf("probe: status %q", truncateForLog(line))}
	}
	expect := e.ProbeExpect
	if expect == "" {
		expect = "CANARY"
	}
	if !bytes.Contains(data, []byte(expect)) {
		// false positive: a 200 header without the real canary body does
		// not prove the full path
		return &ProbeError{health.FailServer, fmt.Errorf("probe: 200 without %q body (false positive)", expect)}
	}
	return nil
}

func truncateForLog(b []byte) string {
	if len(b) > 48 {
		return string(b[:48]) + "…"
	}
	return string(b)
}

func (dp *edgeDatapath) runProbes(ctx context.Context) {
	to := 1500 * time.Millisecond
	cfg := dp.configSnapshot()
	if cfg.ProbeTimeoutMs > 0 {
		to = time.Duration(cfg.ProbeTimeoutMs) * time.Millisecond
	}
	probeOnce := func() {
		now := time.Now()
		for _, e := range cfg.Exits {
			tr := dp.health[e.ID]
			if tr == nil {
				continue
			}
			start := time.Now()
			err := dp.probeExit(e, to)
			at := time.Now()
			measurement := exitProbeMeasurement{at: at}
			if err != nil {
				kind := probeFailureKind(err)
				log.Printf("probe %s (%s): %v", e.ID, kind, err)
				tr.RecordFailure(now, kind, err.Error())
			} else {
				tr.RecordSuccess(now)
				ms := float64(at.Sub(start)) / float64(time.Millisecond)
				measurement.ms = &ms
			}
			dp.probeMeasurements.Store(e.ID, measurement)
		}
	}
	probeOnce()
	t := time.NewTicker(time.Duration(cfg.ProbeIntervalS) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probeOnce()
		}
	}
}

// selectExit applies the accepted policy + live health snapshot + quota
// state; ACL checks for the (verified) destination IP happen inside
// routing.Decide.
func (dp *edgeDatapath) selectExit(d policy.Destination) (exitNode, routing.Decision, error) {
	return dp.selectExitFor(d, "", "")
}

// selectExitFor adds the flow's device context (B20: exhaustion is the
// device's OWN subscription budget) and the pinned route exit (B23: the
// published route binding overrides health/priority choice; a down pinned
// exit REFUSES instead of silently rerouting to another country).
func (dp *edgeDatapath) selectExitFor(d policy.Destination, deviceID, pinned string) (exitNode, routing.Decision, error) {
	dp.mu.Lock()
	topo := dp.topo
	cfg := *dp.cfg
	// reload() swaps pol under dp.mu: the Decide inputs must be read in the
	// same critical section or a concurrent reload races the reader.
	pol, acl := dp.pol, dp.acl
	device := dp.byDeviceID[deviceID]
	led := dp.quotaForLocked(deviceID)
	dp.gen++
	gen := dp.gen
	dp.mu.Unlock()
	var subscription *subContext
	if device.SubID != "" {
		for i := range cfg.Subscriptions {
			if cfg.Subscriptions[i].SubscriptionID == device.SubID {
				subscription = &cfg.Subscriptions[i]
				break
			}
		}
	}
	if cfg.LocalPanel != nil && deviceID != "" && (subscription == nil || pinned == "" && !subscription.PolicyRouting || time.Since(time.Unix(0, dp.localPanelVerified.Load())) > 15*time.Second) {
		return exitNode{}, routing.Decision{}, fmt.Errorf("BLOCK by policy (listener not granted)")
	}
	if pinned == "" && subscription != nil && subscription.PolicyRouting {
		exits := make([]routing.Exit, 0, len(topo.Exits))
		for _, exit := range topo.Exits {
			if exit.Role == routing.RoleRU || subscription.routeAllowed(exit.ID) {
				exits = append(exits, exit)
			}
		}
		topo.Exits = exits
	}
	hs := routing.Snapshot{}
	now := time.Now()
	for id, tr := range dp.health {
		hs[id] = tr.Effective(now).State
	}
	quotaState := routing.QuotaState{}
	if led != nil {
		if st := led.AccountState(now); st.Exhausted {
			quotaState.Exhausted = true
		}
	}
	if cfg.LocalPanel != nil && pinned != "" {
		// Preserve the original first-match BLOCK result. The pinned profile
		// changes the exit only after destination ACL and quota are evaluated.
		if baseline := routing.Decide(topo, hs, pol, acl, d, quotaState, gen); baseline.ActualAction == policy.ActionBlock &&
			(baseline.Action == policy.ActionBlock && baseline.MatchedRuleID != "" || quotaState.Exhausted) {
			return exitNode{}, baseline, fmt.Errorf("BLOCK by policy (%s)", baseline.Reason)
		}
		for _, e := range topo.Exits {
			if e.ID != pinned {
				continue
			}
			if e.Role == routing.RoleRU {
				topo.Exits = []routing.Exit{e}
				pol = &policy.Policy{SchemaVersion: 1, DefaultAction: policy.ActionRUExit}
			} else {
				pol = &policy.Policy{SchemaVersion: 1, DefaultAction: policy.ActionForeignExit, DefaultExitID: pinned, ForeignExitFallback: pol.ForeignExitFallback}
			}
			break
		}
	}
	dec := routing.Decide(topo, hs, pol, acl, d, quotaState, gen)
	if dec.ActualAction == policy.ActionBlock {
		return exitNode{}, dec, fmt.Errorf("BLOCK by policy (%s)", dec.Reason)
	}
	if cfg.LocalPanel == nil && dec.ActualAction == policy.ActionForeignExit && pinned != "" && pinned != dec.ExitID {
		dec.ActualAction, dec.Mode, dec.Reason = policy.ActionBlock, routing.ModeBlocked, "PINNED_PROFILE_CONFLICT"
		return exitNode{}, dec, fmt.Errorf("BLOCK by policy (profile pins %s, rule selects %s)", pinned, dec.ExitID)
	}
	if dec.ActualAction == policy.ActionForeignExit && pinned == "" && device.SubID != "" {
		if subscription == nil || !subscription.routeAllowed(dec.ExitID) {
			dec.ActualAction, dec.Mode, dec.Reason = policy.ActionBlock, routing.ModeBlocked, "ROUTE_NOT_GRANTED"
			return exitNode{}, dec, fmt.Errorf("BLOCK by policy (route %s is not granted to this subscription)", dec.ExitID)
		}
	}
	if pinned != "" {
		// C05: the route grant is enforced SERVER-SIDE from the device's
		// subscription context — changing server_port in a client config
		// cannot reach an exit the subscription was never granted. The
		// routing decision (ACL/BLOCK/RU policy) still applies above.
		dp.mu.Lock()
		var allowed bool
		if d, ok := dp.byDeviceID[deviceID]; ok {
			snap := dp.configSnapshot()
			for si := range snap.Subscriptions {
				if snap.Subscriptions[si].SubscriptionID == d.SubID {
					context := &snap.Subscriptions[si]
					if snap.LocalPanel != nil {
						allowed = slices.Contains(context.LocalPinnedRoutes, pinned)
					} else {
						allowed = context.routeAllowed(pinned)
					}
					break
				}
			}
		}
		dp.mu.Unlock()
		if deviceID != "" && !allowed {
			return exitNode{}, dec, fmt.Errorf("BLOCK by policy (route %s is not granted to this subscription)", pinned)
		}
		if cfg.LocalPanel == nil {
			tr, known := dp.health[pinned]
			if !known || tr.Effective(now).State != health.Healthy {
				return exitNode{}, dec, fmt.Errorf("BLOCK by policy (pinned route exit %s unavailable)", pinned)
			}
			dec.ExitID = pinned
		}
	}
	for _, e := range cfg.Exits {
		if e.ID == dec.ExitID {
			return e, dec, nil
		}
	}
	return exitNode{}, dec, fmt.Errorf("no exit node for decision %s", dec.ExitID)
}

// quotaForLocked is quotaFor for callers already holding dp.mu.
func (dp *edgeDatapath) quotaForLocked(deviceID string) quotaLedger {
	if d, ok := dp.byDeviceID[deviceID]; ok && d.SubID != "" {
		if led, ok := dp.ledgers[d.SubID]; ok {
			return led
		}
	}
	return dp.quota
}

// enforcer applies rate admission and durable reservation→write→checkpoint
// on real bytes for one authenticated device in one direction.
type enforcer struct {
	profilePort    int
	profileGrantID string
	profileGranted int64
	profileExpires int64
	localKey       localActivityKey
	dp             *edgeDatapath
	deviceID       string
	dir            limits.Direction
	exitRole       string
	// open durable reservation batch (batched accounting): ONE durable
	// Reserve+Checkpoint pair per quotaBatchBytes instead of per relay
	// buffer — a per-buffer journal fsync capped a loopback flow at
	// ~31 Mbit/s (measured, bench_compare.sh), while the batch keeps the
	// documented conservative property: a crash overcounts by at most the
	// open batch's unconsumed reservation (docs/LIMITS_QUOTAS.md).
	batch         *limits.ReservationBatch
	batchUsed     int64
	batchReserved int64
	profilePool   *profilePool
}

// quotaBatchBytes is one durable reservation batch. It bounds both the
// journal fsync rate (one per batch) and the crash overcount.
const quotaBatchBytes = 512 * 1024

// closeBatch checkpoints the open batch with the bytes actually consumed.
func (e *enforcer) closeBatch(now time.Time) error {
	if e.batch == nil {
		return nil
	}
	ledger := e.dp.quotaFor(e.deviceID)
	var err error
	if remote, ok := ledger.(*remoteQuotaLedger); ok {
		err = remote.checkpointRouted(e.deviceID, e.batch, e.batchUsed, now, e.exitRole)
	} else {
		err = ledger.Checkpoint(e.deviceID, e.batch, e.batchUsed, now)
	}
	if err != nil {
		e.batch = nil
		return fmt.Errorf("quota checkpoint failed: %w", err)
	}
	e.dp.noteLocalTraffic(e.localKey, e.exitRole, e.batchUsed)
	e.batch = nil
	return nil
}

// admitBatch closes the exhausted batch and reserves the next one, sized
// down to the remaining allowance near the quota edge so the final slice
// of a nearly-exhausted budget is still transferable.
func (e *enforcer) admitBatch(now time.Time) error {
	if err := e.closeBatch(now); err != nil {
		return err
	}
	want := int64(quotaBatchBytes)
	b, st, _, err := e.dp.quotaFor(e.deviceID).Reserve(e.deviceID, want, now)
	if err != nil {
		if st.Remaining != nil && *st.Remaining > 0 && *st.Remaining < want {
			b, _, _, err = e.dp.quotaFor(e.deviceID).Reserve(e.deviceID, *st.Remaining, now)
			want = *st.Remaining
		}
		if err != nil {
			return fmt.Errorf("quota admission refused: %w", err)
		}
	}
	e.batch = b
	e.batchUsed = 0
	e.batchReserved = want

	return nil
}

// relay copies one direction, admitting every buffer through the shared
// account/device rate limiter (in-memory, per chunk) and the durable quota
// ledger (per batch) before the bytes leave. Any enforcement or checkpoint
// error stops the direction with an error — accounting failures are never
// treated as a successful checkpoint.
func (e *enforcer) relay(dst io.Writer, src io.Reader) (int64, error) {
	defer func() { _ = e.closeBatch(time.Now()) }()
	var total int64
	defer func() {
		// charge the unconsumed tail of the open batch on flow end
		_ = e.closeBatch(time.Now())
	}()
	buf := make([]byte, 16*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			written, err := e.pass(dst, buf[:n])
			total += written
			if e.dir == limits.Download {
				e.dp.downloadBytes.Add(uint64(written))
			} else {
				e.dp.uploadBytes.Add(uint64(written))
			}
			if err != nil {
				return total, err
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				// flow end: charge the open batch tail; an accounting
				// failure is still an error, not a silent success
				if cerr := e.closeBatch(time.Now()); cerr != nil {
					return total, cerr
				}
				return total, nil
			}
			return total, rerr
		}
	}
}

var errRateLimited = errors.New("rate limit refused the direction")

// rateChunk bounds one rate-admission slice: a bucket whose capacity is
// smaller than a full read must pace in slices instead of waiting for a
// refill it can never hold.
const rateChunk = 1024

// pass admits one buffer through rate + quota and writes it fully; the
// durable batch is charged with the bytes actually written.
func (e *enforcer) pass(dst io.Writer, b []byte) (int64, error) {
	now := time.Now()
	e.dp.mu.Lock()
	dev, registered := e.dp.byDeviceID[e.deviceID]
	e.dp.mu.Unlock()
	if e.dp.configSnapshot().LocalPanel != nil && (!registered || now.Sub(time.Unix(0, e.dp.localPanelVerified.Load())) > 15*time.Second) {
		return 0, errors.New("local device authorization unavailable")
	}
	if registered && dev.ExpiresUnix > 0 && now.Unix() >= dev.ExpiresUnix {
		return 0, errors.New("device credential expired")
	}
	if e.profilePool != nil {
		if err := e.profilePool.ensure(e); err != nil {
			return 0, err
		}
	}
	if e.batch == nil || e.batchUsed >= e.batchReserved {
		if err := e.admitBatch(now); err != nil {
			return 0, err
		}
	}
	e.dp.syncRemoteAccountRates(e.deviceID)
	lim := e.dp.limiterFor(e.deviceID)
	profile := e.dp.profileLimiter(e.deviceID, e.profilePort)
	off := 0
	for off < len(b) {
		n := len(b) - off
		if n > rateChunk {
			n = rateChunk
		}
		take := lim.TakeWithProfile(profile, e.dir, int64(n), now)
		if take.Granted {
			off += n
			continue
		}
		if take.Forbidden {
			return 0, fmt.Errorf("%w: %s direction", errRateLimited, e.dir)
		}
		// shaping: wait out the deficit instead of busy-looping; the cap
		// keeps one stalled bucket from pinning the flow forever between
		// re-admission attempts
		wait := take.RetryAfter
		if wait <= 0 || wait > time.Second {
			wait = time.Second
		}
		time.Sleep(wait)
		now = time.Now()
	}
	if e.batch == nil || e.batchUsed >= e.batchReserved {
		if err := e.admitBatch(now); err != nil {
			return 0, err
		}
	}
	// one buffer never exceeds the batch: reads are 16 KiB, batches 512 KiB
	consume := int64(len(b))
	if e.batchUsed+consume > e.batchReserved {
		consume = e.batchReserved - e.batchUsed
	}
	if e.profilePool != nil {
		var err error
		consume, err = e.profilePool.take(e, consume)
		if err != nil {
			return 0, err
		}
	}
	written, werr := writeAll(dst, b[:consume])
	e.batchUsed += int64(written)
	if werr != nil {
		if cerr := e.closeBatch(now); cerr != nil {
			return int64(written), cerr
		}
		return int64(written), werr
	}
	if int64(len(b)) > consume {
		// read larger than the batch tail: reserve and continue inline
		rest, err := e.pass(dst, b[consume:])
		return int64(written) + rest, err
	}
	if e.batchUsed >= e.batchReserved {
		if err := e.closeBatch(now); err != nil {
			return int64(written), err
		}
	}
	return int64(written), nil
}

func writeAll(w io.Writer, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := w.Write(b[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (dp *edgeDatapath) handleVLESS(conn net.Conn) {
	defer conn.Close()
	defer dp.unbind(conn)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	uuid, cmd, addrStr, port, err := transport.ParseRequest(conn)
	if err != nil {
		log.Printf("vless: bad request: %v", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	dev, ok := dp.lookupUUID(uuid)
	if !ok {
		log.Printf("vless: identity rejected")
		return
	}
	if cmd != 1 {
		// unsupported command: never relay it as TCP; acknowledge the
		// frame (standard peers expect a response) and stop
		_ = transport.WriteAccept(conn)
		log.Printf("vless: unsupported command %d refused", cmd)
		return
	}
	dp.bindIdentity(conn, dev)
	if err := transport.WriteAccept(conn); err != nil {
		return
	}
	dp.forward(conn, addrStr, port, "vless")
}

// handleVLESSPinned serves a B23 route listener: same VLESS handling, but
// the egress is pinned to the route's exit.
func (dp *edgeDatapath) handleVLESSPinned(conn net.Conn, exitID string) {
	defer conn.Close()
	defer dp.unbind(conn)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	uuid, cmd, addrStr, port, err := transport.ParseRequest(conn)
	if err != nil {
		log.Printf("vless: bad request: %v", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	dev, ok := dp.lookupUUID(uuid)
	if !ok {
		log.Printf("vless: identity rejected")
		return
	}
	if cmd != 1 {
		_ = transport.WriteAccept(conn)
		log.Printf("vless: unsupported command %d refused", cmd)
		return
	}
	dp.bindIdentity(conn, dev)
	if err := transport.WriteAccept(conn); err != nil {
		return
	}
	dp.forwardPinned(conn, addrStr, port, "vless-route", exitID)
}

func (dp *edgeDatapath) unbind(conn net.Conn) {
	dp.mu.Lock()
	delete(dp.ident, conn)
	dp.mu.Unlock()
}

func (dp *edgeDatapath) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	defer dp.unbind(conn)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	// RFC 1928 method negotiation: the full METHODS list is consumed
	// before selection (TR02: leftover method bytes corrupted CONNECT)
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 5 {
		return
	}
	nmethods := int(hdr[1])
	if nmethods == 0 {
		_, _ = conn.Write([]byte{5, 0xFF})
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	offered := map[byte]bool{}
	for _, m := range methods {
		offered[m] = true
	}
	switch {
	case offered[2] && dp.socksAuthConfigured():
		_, _ = conn.Write([]byte{5, 2})
		dev, ok := dp.socksAuth(conn)
		if !ok {
			return
		}
		dp.bindIdentity(conn, dev)
	case offered[0]:
		// no-auth is negotiable, but identity stays unbound: the CONNECT
		// below is refused (TR03 — anonymous clients get no egress)
		_, _ = conn.Write([]byte{5, 0})
	default:
		_, _ = conn.Write([]byte{5, 0xFF})
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return
	}
	if req[0] != 5 {
		return
	}
	if req[1] != 1 { // CONNECT only; never interpret other commands as TCP
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	addrStr, port, err := socksReadAddr(conn, req[3])
	if err != nil {
		_, _ = conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	// success is reported only after the egress is really established
	ref := dp.relayEgress(conn, addrStr, port, "socks-relay", func() {
		_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	})
	if ref != nil {
		_, _ = conn.Write([]byte{5, ref.rep, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

// socksAuth performs the RFC 1929 username/password subnegotiation and
// binds the matching device on success.
func (dp *edgeDatapath) socksAuth(conn net.Conn) (deviceAuth, bool) {
	refuse := func() (deviceAuth, bool) {
		_, _ = conn.Write([]byte{1, 1})
		return deviceAuth{}, false
	}
	var h [2]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil || h[0] != 1 {
		return refuse()
	}
	user := make([]byte, h[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return refuse()
	}
	var pl [1]byte
	if _, err := io.ReadFull(conn, pl[:]); err != nil {
		return refuse()
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return refuse()
	}
	dev, ok := dp.lookupSOCKSUser(string(user))
	if !ok || subtle.ConstantTimeCompare([]byte(dev.SOCKSPass), pass) != 1 {
		return refuse()
	}
	_, _ = conn.Write([]byte{1, 0})
	return dev, true
}

func socksReadAddr(conn net.Conn, atyp byte) (string, int, error) {
	switch atyp {
	case 1:
		var b [6]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[0:4]).String(), int(b[4])<<8 | int(b[5]), nil
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, errors.New("socks: empty domain")
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(conn, d); err != nil {
			return "", 0, err
		}
		var po [2]byte
		if _, err := io.ReadFull(conn, po[:]); err != nil {
			return "", 0, err
		}
		return string(d), int(po[0])<<8 | int(po[1]), nil
	case 4:
		var b [18]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[0:16]).String(), int(b[16])<<8 | int(b[17]), nil
	}
	return "", 0, fmt.Errorf("socks: unsupported atyp %d", atyp)
}

// egressRefusal reports a refusal that happened before any egress byte
// flowed. rep is the SOCKS REP code for socks-relay callers.
type egressRefusal struct {
	rep    byte
	reason string
}

// forward is the identity-bound egress path for VLESS: identity, verified
// destination, exit selection, dial and bidirectional relay.
func (dp *edgeDatapath) forward(src net.Conn, addrStr string, port int, via string) {
	dp.forwardPinned(src, addrStr, port, via, "")
}

// forwardPinned relays through the pinned route listener's exit (B23);
// unpinned flows keep health/priority-driven selection.
func (dp *edgeDatapath) forwardPinned(src net.Conn, addrStr string, port int, via, pinned string) {
	_ = dp.relayEgressPinned(src, addrStr, port, via, nil, pinned)
}

// relayEgress performs identity→verification→policy→dial→relay. onEstablished
// (SOCKS: the success reply) runs only after the exit connection is really
// established. Every refusal happens before any payload leaves the process.
func (dp *edgeDatapath) relayEgress(src net.Conn, addrStr string, port int, via string, onEstablished func()) *egressRefusal {
	return dp.relayEgressPinned(src, addrStr, port, via, onEstablished, "")
}

func (dp *edgeDatapath) relayEgressPinned(src net.Conn, addrStr string, port int, via string, onEstablished func(), pinned string) *egressRefusal {
	deviceID, ok := dp.identityFor(src)
	if !ok {
		log.Printf("%s: %s:%d refused: no authenticated identity", via, addrStr, port)
		return &egressRefusal{rep: 2, reason: "NO_IDENTITY"}
	}
	dstIP := net.ParseIP(addrStr)
	var dialHost string
	var exit exitNode
	var dec routing.Decision
	if dstIP != nil {
		a, ok := toNetip(dstIP)
		if !ok {
			return &egressRefusal{rep: 8, reason: "BAD_ADDRESS"}
		}
		dialHost = a.String()
		e, d, err := dp.selectExitFor(policy.Destination{IP: a, Proto: policy.ProtoTCP, Port: port}, deviceID, pinned)
		if err != nil {
			log.Printf("%s: %s:%d no egress: %v", via, addrStr, port, err)
			return &egressRefusal{rep: 2, reason: d.Reason}
		}
		exit, dec = e, d
	} else {
		// the route is decided by the trusted NAME before any DNS query;
		// a BLOCK never resolves (DNSScope none). The domain is then
		// resolved INSIDE the chosen exit's scope (DNS over TCP through
		// the exit hop), every answer is ACL-verified, and the dial is
		// pinned to the first verified address — no second, unverified
		// resolution can happen at the egress (TR06, ROUTING_DNS.md).
		e, d, err := dp.selectExitFor(policy.Destination{Domain: addrStr, Proto: policy.ProtoTCP, Port: port}, deviceID, pinned)
		if err != nil {
			log.Printf("%s: %q no egress: %v", via, addrStr, err)
			return &egressRefusal{rep: 2, reason: d.Reason}
		}
		exit, dec = e, d
		verified, rerr := dp.resolveViaExit(exit, addrStr)
		if rerr != nil {
			log.Printf("%s: %q refused: %v", via, addrStr, rerr)
			return &egressRefusal{rep: 1, reason: "DESTINATION_DENIED"}
		}
		pinned := verified[0]
		dialHost = pinned.String()
		log.Printf("%s: %q resolved in exit %s scope as %s", via, addrStr, exit.ID, dialHost)
	}
	exitConn, err := exit.dialSOCKS(context.Background(), dialHost, port, 5*time.Second)
	if err != nil {
		log.Printf("%s: exit %s dial %s:%d failed: %v", via, exit.ID, dialHost, port, err)
		return &egressRefusal{rep: 5, reason: "EXIT_DIAL_FAILED"}
	}
	defer exitConn.Close()
	log.Printf("%s: %s:%d via %s (%s) gen=%d reason=%s", via, dialHost, port, exit.ID, exit.Country, dec.Generation, dec.Reason)
	if onEstablished != nil {
		onEstablished()
	}
	var localKey localActivityKey
	if dp.configSnapshot().LocalPanel != nil {
		dp.mu.Lock()
		localKey = localActivityKey{sub: dp.byDeviceID[deviceID].SubID, device: deviceID}
		if dp.localConnections == nil {
			dp.localConnections = map[string]int{}
		}
		dp.localConnections[localKey.sub]++
		dp.mu.Unlock()
		defer func() {
			dp.mu.Lock()
			dp.localConnections[localKey.sub]--
			if dp.localConnections[localKey.sub] == 0 {
				delete(dp.localConnections, localKey.sub)
			}
			dp.mu.Unlock()
		}()
	}
	profilePort := 0
	if pinned != "" {
		if _, p, err := net.SplitHostPort(src.LocalAddr().String()); err == nil {
			profilePort, _ = strconv.Atoi(p)
		}
	}
	pool := dp.acquireProfilePool(deviceID, profilePort)
	if pool != nil {
		defer pool.release()
	}
	done := make(chan relayEnd, 2)
	go func() {
		e := &enforcer{dp: dp, deviceID: deviceID, dir: limits.Download, exitRole: exit.Role, localKey: localKey, profilePort: profilePort, profilePool: pool}
		n, err := e.relay(src, exitConn) // exit→client
		done <- relayEnd{download: true, n: n, err: err}
	}()
	go func() {
		e := &enforcer{dp: dp, deviceID: deviceID, dir: limits.Upload, exitRole: exit.Role, localKey: localKey, profilePort: profilePort, profilePool: pool}
		n, err := e.relay(exitConn, src) // client→exit
		done <- relayEnd{download: false, n: n, err: err}
	}()
	first := <-done
	if first.err == nil {
		// half-close: the side that saw EOF lets its peer see EOF too,
		// while the opposite direction keeps draining
		if first.download {
			closeWrite(src)
		} else {
			closeWrite(exitConn)
		}
	} else {
		// hard error (limit/accounting/write): stop both directions now;
		// an enforcement failure must be visible, never a silent close
		log.Printf("%s: relay %s error after %d bytes: %v", via, relayDirName(first.download), first.n, first.err)
		_ = src.Close()
		_ = exitConn.Close()
	}
	second := <-done
	if second.err != nil {
		log.Printf("%s: relay %s error after %d bytes: %v", via, relayDirName(second.download), second.n, second.err)
	}
	return nil
}

func relayDirName(download bool) string {
	if download {
		return "download"
	}
	return "upload"
}

type relayEnd struct {
	download bool
	n        int64
	err      error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// resolveVerified was retired in favour of resolveViaExit
// (docs/ROUTING_DNS.md): domain resolution happens inside the chosen
// exit's DNS scope, never on the edge host's own resolver.

func (dp *edgeDatapath) lanExcepted(ip netip.Addr) bool {
	for _, c := range dp.acl.LANExceptions {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

func toNetip(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte(v4)), true
	}
	if v6 := ip.To16(); v6 != nil {
		return netip.AddrFrom16([16]byte(v6)), true
	}
	return netip.Addr{}, false
}

func (e exitNode) socksEndpoint() string {
	if e.Backbone != nil {
		return e.Backbone.SOCKSAddr
	}
	return e.SOCKSAddr
}

// dialSOCKS reaches the exit's SOCKS5 listener. A bound backbone never
// falls back to an unbound socket, including for DNS and health probes.
func (e exitNode) dialSOCKS(ctx context.Context, dstHost string, dstPort int, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	if e.Backbone != nil {
		if err := bindTunnel(&dialer, e.Backbone.Interface); err != nil {
			return nil, err
		}
	}
	conn, err := dialer.DialContext(ctx, "tcp", e.socksEndpoint())
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// greeting: one method, no-auth
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 5 || resp[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks: bad method %x %x", resp[0], resp[1])
	}
	// request: CONNECT
	p := net.ParseIP(dstHost)
	var req []byte
	if p != nil {
		if v4 := p.To4(); v4 != nil {
			req = []byte{5, 1, 0, 1, v4[0], v4[1], v4[2], v4[3], byte(dstPort >> 8), byte(dstPort)}
		} else {
			v6 := p.To16()
			req = append([]byte{5, 1, 0, 4}, v6...)
			req = append(req, byte(dstPort>>8), byte(dstPort))
		}
	} else {
		req = append([]byte{5, 1, 0, 3, byte(len(dstHost))}, []byte(dstHost)...)
		req = append(req, byte(dstPort>>8), byte(dstPort))
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	ans := make([]byte, 4)
	if _, err := io.ReadFull(conn, ans); err != nil {
		conn.Close()
		return nil, err
	}
	if ans[1] != 0 {
		conn.Close()
		return nil, &SOCKSStatusError{Rep: ans[1]}
	}
	// skip bound addr per ATYP
	switch ans[3] {
	case 1:
		var b [6]byte
		io.ReadFull(conn, b[:])
	case 3:
		var l [1]byte
		io.ReadFull(conn, l[:])
		rest := make([]byte, int(l[0])+2)
		io.ReadFull(conn, rest)
	case 4:
		var b [18]byte
		io.ReadFull(conn, b[:])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// staticProjection marshals the reload-STATIC serving fields of a config
// (H01): endpoints, topology binding, routes, TLS material and output
// paths. Changes here require a planned restart; everything else is
// applied by reload. Exits are marshaled fully — address/role/priority
// changes are endpoint changes.
type staticProjection struct {
	AccessListen   string        `json:"access_listen"`
	SOCKSListen    string        `json:"socks_listen"`
	TLSCert        string        `json:"tls_cert"`
	TLSKey         string        `json:"tls_key"`
	CACert         string        `json:"ca_cert"`
	Exits          []exitNode    `json:"exits"`
	Routes         []routeListen `json:"routes"`
	CurrentForeign string        `json:"current_foreign_id"`
	StateDir       string        `json:"state_dir"`
	StatusFile     string        `json:"status_file"`
}

// applyExitProbeDefaults fills the deterministic lab-canary probe endpoints
// for exits that declare none (H01): shared by newDatapath AND reload, so
// the static projection of a fresh config matches the running one — the
// default is a runtime derived value, not a document change.
func applyExitProbeDefaults(cfg *edgeConfig) {
	for i := range cfg.Exits {
		if cfg.Exits[i].ProbeAddr == "" {
			if cfg.Exits[i].Role == "ru" {
				cfg.Exits[i].ProbeAddr = "10.71.1.1:8000"
			} else {
				cfg.Exits[i].ProbeAddr = "10.72.1.1:8000"
			}
		}
	}
}

func servingStaticProjection(c *edgeConfig) string {
	b, err := json.Marshal(staticProjection{
		AccessListen: c.AccessListen, SOCKSListen: c.SOCKSListen,
		TLSCert: c.TLSCert, TLSKey: c.TLSKey, CACert: c.CACert,
		Exits: c.Exits, Routes: c.Routes,
		CurrentForeign: c.CurrentForeign, StateDir: c.StateDir, StatusFile: c.StatusFile,
	})
	if err != nil {
		return "" // marshal of plain fields cannot fail; equal-fallback keeps old state
	}
	return string(b)
}

// reload re-reads the policy and the device table under the datapath
// mutex; any error keeps the previous running state (invalid input never
// degrades a running data plane).
func (dp *edgeDatapath) reload() error {
	// F02/G03 source fix: the policy resolves from the FRESH config (an
	// embedded new policy must not stay stale from the old snapshot).
	fresh, err := loadConfig(dp.configSnapshot().configPath)
	if err != nil {
		return err
	}
	return dp.reloadConfig(fresh)
}

func (dp *edgeDatapath) reloadConfig(fresh *edgeConfig) error {
	pol, err := loadPolicyFor(fresh)
	if err != nil {
		return err
	}
	// H01: static serving fields (endpoints/topology/routes/grant-bearing
	// routes) are NOT hot-reloadable — a changed static projection requires
	// a planned restart. Runtime defaults (probe endpoints) are applied to
	// fresh first so the projection compares document semantics, not
	// derived values.
	applyExitProbeDefaults(fresh)
	if projOld, projNew := servingStaticProjection(dp.configSnapshot()), servingStaticProjection(fresh); projOld != projNew {
		return fmt.Errorf("RESTART_REQUIRED: static serving fields changed (endpoints/topology/routes) — restart ara-edge to apply; previous state kept")
	}
	devices := map[string]deviceAuth{}
	socksUsers := map[string]deviceAuth{}
	byDeviceID := map[string]deviceAuth{}
	for _, d := range fresh.Devices {
		devices[strings.ToLower(d.UUID)] = d
		byDeviceID[d.DeviceID] = d
		if d.SOCKSUser != "" {
			socksUsers[d.SOCKSUser] = d
		}
	}
	// B20: new/changed subscription contexts get their ledgers created
	// BEFORE the swap; existing ledgers of unchanged subscriptions keep
	// their durable spend state (a reload never resets accounting).
	now := time.Now()
	tmp := &edgeDatapath{cfg: fresh, ledgers: map[string]quotaLedger{}, remoteRates: map[string]*remoteQuotaLedger{},
		accountRegimes: map[string]*limits.AccountRegime{}, accountLimiters: map[string]*limits.AggregateLimiter{},
		remoteApplied: map[string][2]*int64{}, limiters: map[string]*limits.AggregateLimiter{},
		byDeviceID: byDeviceID, devices: devices, socksUsers: socksUsers}
	dp.mu.Lock()
	for si := range fresh.Subscriptions {
		subID := fresh.Subscriptions[si].SubscriptionID
		if subID == "" {
			subID = "local"
		}
		if led, ok := dp.ledgers[subID]; ok {
			tmp.ledgers[subID] = led
			if q, ok := led.(*remoteQuotaLedger); ok {
				tmp.remoteRates[subID] = q
			}
		}
	}
	tmp.quota = dp.quota
	tmp.profileLimiters = dp.profileLimiters
	// rate state carries over (B12: a reload never mints a fresh burst):
	// the account regimes hold the account token buckets; device limiters
	// are re-bound against the carried regimes below
	for acc, r := range dp.accountRegimes {
		tmp.accountRegimes[acc] = r
	}
	for acc, l := range dp.accountLimiters {
		tmp.accountLimiters[acc] = l
	}
	for acc, ap := range dp.remoteApplied {
		tmp.remoteApplied[acc] = ap
	}
	for dev, l := range dp.limiters {
		tmp.limiters[dev] = l
	}
	if dp.limiter != nil {
		tmp.limiter = dp.limiter
	}
	dp.mu.Unlock()
	if err := tmp.buildContexts(now); err != nil {
		return err
	}
	dp.mu.Lock()
	if fresh.LocalPanel != nil {
		for _, ctx := range fresh.Subscriptions {
			if ledger, ok := tmp.ledgers[ctx.SubscriptionID].(*limits.QuotaLedger); ok {
				ledger.SetAccountLimit(localLedgerLimit(ctx.LocalQuota))
			}
		}
	}
	dp.pol = pol
	// B04(edge half): the reloaded identity table is authoritative —
	// removed/rotated UUIDs stop authenticating at the next connection.
	dp.devices = devices
	dp.socksUsers = socksUsers
	dp.byDeviceID = byDeviceID
	// H01: dynamic-only reload swaps the whole config snapshot — the new
	// document is now fully applied, so its serving ack is honest.
	dp.publishConfig(fresh)
	dp.ledgers = tmp.ledgers
	dp.profileLimiters = tmp.profileLimiters
	dp.remoteRates = tmp.remoteRates
	dp.accountRegimes = tmp.accountRegimes
	dp.accountLimiters = tmp.accountLimiters
	dp.limiters = tmp.limiters
	dp.remoteApplied = tmp.remoteApplied
	dp.quota = tmp.quota
	if tmp.limiter != nil {
		dp.limiter = tmp.limiter
	}
	dp.mu.Unlock()
	// B12: re-applying the SAME rate config must not mint a fresh burst;
	// carry token state via RebindAccount instead of new AccountRegime.
	dp.mu.Lock()
	for acc, lim := range dp.accountLimiters {
		var rate *rateConf
		for si := range fresh.Subscriptions {
			if fresh.Subscriptions[si].AccountID == acc {
				rate = fresh.Subscriptions[si].AccountRate
				break
			}
		}
		if rate == nil {
			rate = fresh.AccountRate
		}
		if rate == nil {
			continue
		}
		if err := lim.RebindAccount(rate.toRateConfig(), now); err != nil {
			dp.mu.Unlock()
			return fmt.Errorf("rate rebind: %w", err)
		}
	}
	// B13: device quota overrides apply to the LIVE ledger (reduce/zero/
	// clear) without resetting usage or open reservations.
	for _, d := range fresh.Devices {
		if d, ok := dp.byDeviceID[d.DeviceID]; ok {
			if led := dp.quotaForLocked(d.DeviceID); led != nil {
				led.SetDeviceLimit(d.DeviceID, d.QuotaBytes)
			}
		}
	}
	dp.mu.Unlock()
	return nil
}

func (dp *edgeDatapath) writeStatus() {
	// I02: load the published snapshot atomically — this reader races
	// reload's publication and must never tear the config.
	cfg := dp.configSnapshot()
	if cfg.StatusFile == "" {
		return
	}
	now := time.Now()
	type nodeStatus struct {
		ID        string    `json:"id"`
		Country   string    `json:"country"`
		Role      string    `json:"role"`
		Priority  int       `json:"priority"`
		State     string    `json:"state"`
		LastError string    `json:"last_error,omitempty"`
		ProbeAt   time.Time `json:"probe_at"`
		ProbeMs   *float64  `json:"probe_ms,omitempty"`
	}
	out := struct {
		GeneratedAt        time.Time                          `json:"generated_at"`
		Nodes              []nodeStatus                       `json:"nodes"`
		Instance           string                             `json:"instance"`
		DownloadBytes      uint64                             `json:"download_bytes"`
		UploadBytes        uint64                             `json:"upload_bytes"`
		TLSCertPath        string                             `json:"tls_cert_path,omitempty"`
		CurrentForeign     string                             `json:"current_foreign_id,omitempty"`
		RoutePorts         map[string]int                     `json:"route_ports,omitempty"`
		LocalSubscriptions map[string]localSubscriptionStatus `json:"local_subscriptions,omitempty"`
	}{
		GeneratedAt: now, Instance: servingInstanceNonce, LocalSubscriptions: dp.localSubscriptionStatus(now),
		TLSCertPath: cfg.TLSCert, CurrentForeign: cfg.CurrentForeign,
		DownloadBytes: dp.downloadBytes.Load(), UploadBytes: dp.uploadBytes.Load(),
	}
	out.RoutePorts = map[string]int{}
	for _, rt := range cfg.Routes {
		_, port, err := net.SplitHostPort(rt.Listen)
		if err == nil {
			out.RoutePorts[rt.ExitID], _ = strconv.Atoi(port)
		}
	}

	for _, e := range cfg.Exits {
		tr := dp.health[e.ID]
		st := health.Unknown
		var lastErr string
		if tr != nil {
			snap := tr.Effective(now)
			st = snap.State
			lastErr = string(snap.LastFailureKind)
			if snap.QuarantineReason != "" {
				lastErr = snap.QuarantineReason
			}
		}
		node := nodeStatus{ID: e.ID, Country: e.Country, Role: e.Role, Priority: e.Priority, State: string(st), LastError: lastErr}
		if probe, ok := dp.probeMeasurements.Load(e.ID); ok {
			m := probe.(exitProbeMeasurement)
			node.ProbeAt, node.ProbeMs = m.at, m.ms
		}
		out.Nodes = append(out.Nodes, node)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	f, err := os.CreateTemp(filepath.Dir(cfg.StatusFile), ".status-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return
	}
	_, writeErr := f.Write(b)
	if closeErr := f.Close(); writeErr == nil && closeErr == nil {
		_ = os.Rename(tmp, cfg.StatusFile)
	}
}

// servingGeneration counts accepted config loads/reloads in THIS process;
// it distinguishes a stale receipt (previous process) from fresh readiness
// of the current instance (H01/I03).
var servingGen atomic.Uint64

// servingInstanceNonce is a per-process random nonce: pid alone is
// recyclable, the nonce is not (I03).
var servingInstanceNonce = func() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}()

// ServingReceipt is the single ATOMIC authoritative serving acknowledgment
// (I03): snapshot hash, policy revision, process instance (nonce+pid),
// accepted generation and timestamp — written as ONE file with file+dir
// fsync, replacing the separate hash/meta pair.
type ServingReceipt struct {
	Instance       string `json:"instance"`
	Generation     uint64 `json:"generation"`
	ConfigSHA256   string `json:"config_sha256"`
	PolicyRevision int64  `json:"policy_revision,omitempty"`
	AcceptedAt     string `json:"accepted_at"`
}

// recordServingHash writes the identity of the LOADED AND VALIDATED byte
// snapshot (H01) as one atomic receipt — never a re-read of the config
// path. The legacy serving.hash hex file is kept for compatibility with
// existing sync consumers. Errors are returned, never dropped.
func recordServingHash(cfg *edgeConfig) error {
	if cfg.configSnapshot == "" {
		return fmt.Errorf("serving ack: config snapshot identity unknown (config was not loaded through loadConfig)")
	}
	gen := servingGen.Add(1)
	dir := cfg.StateDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	rev := int64(0)
	if cfg.Policy != nil {
		rev = cfg.Policy.Revision
	}
	receipt := ServingReceipt{
		Instance:       servingInstanceNonce + "/pid" + fmt.Sprint(os.Getpid()),
		Generation:     gen,
		ConfigSHA256:   cfg.configSnapshot,
		PolicyRevision: rev,
		AcceptedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	body, _ := json.MarshalIndent(receipt, "", "  ")
	writeDurable := func(name string, body []byte) error {
		p := filepath.Join(dir, name)
		f, err := os.CreateTemp(dir, ".serving-*")
		if err != nil {
			return err
		}
		tmp := f.Name()
		defer os.Remove(tmp)
		if _, err := f.Write(body); err != nil {
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
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		if err := os.Rename(tmp, p); err != nil {
			d.Close()
			return err
		}
		if err := d.Sync(); err != nil {
			d.Close()
			return err
		}
		return d.Close()
	}
	if err := writeDurable("serving.receipt.json", append(body, '\n')); err != nil {
		return err
	}
	// legacy hex hash — auxiliary compatibility for existing sync readers
	return writeDurable("serving.hash", []byte(cfg.configSnapshot+"\n"))
}

// dynamicTLSServingConfig serves the certificate pair with LIVE reload
// (B32): GetCertificate re-reads the files on mtime change, so a renewed
// pair takes effect on new handshakes without a process restart; a bad
// staged write keeps serving the previous pair. When a chain.pem sits next
// to the certificate it is served together (B33 fullchain — a bare leaf
// breaks strict clients).
func dynamicTLSServingConfig(certPath, keyPath string) *tls.Config {
	var mu sync.Mutex
	var cached *tls.Certificate
	var certMod, keyMod, chainMod time.Time
	chainPath := filepath.Join(filepath.Dir(certPath), "chain.pem")
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			now := time.Now()
			valid := func(cert *tls.Certificate) bool {
				return cert != nil && cert.Leaf != nil && !now.Before(cert.Leaf.NotBefore) && now.Before(cert.Leaf.NotAfter)
			}
			retain := func(err error) (*tls.Certificate, error) {
				if valid(cached) {
					return cached, nil
				}
				return nil, err
			}
			cst, e1 := os.Stat(certPath)
			kst, e2 := os.Stat(keyPath)
			var chm time.Time
			if st, err := os.Stat(chainPath); err == nil {
				chm = st.ModTime()
			}
			if valid(cached) && e1 == nil && e2 == nil &&
				cst.ModTime().Equal(certMod) && kst.ModTime().Equal(keyMod) && chm.Equal(chainMod) {
				return cached, nil
			}
			certPEM, err := os.ReadFile(certPath)
			if err != nil {
				return retain(err)
			}
			if b, err := os.ReadFile(chainPath); err == nil {
				certPEM = append(certPEM, b...)
			} else if !os.IsNotExist(err) {
				return retain(err)
			}
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				return retain(err)
			}
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return retain(fmt.Errorf("tls serving pair: %w", err))
			}
			if cert.Leaf == nil {
				cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					return retain(err)
				}
			}
			if !valid(&cert) {
				return retain(fmt.Errorf("tls serving pair: certificate outside its validity period"))
			}
			cached = &cert
			if e1 == nil {
				certMod = cst.ModTime()
			}
			if e2 == nil {
				keyMod = kst.ModTime()
			}
			chainMod = chm
			return cached, nil
		},
	}
}

func main() {
	conf := flag.String("config", "", "edge config JSON")
	probeMode := flag.String("probe", "", "debug: probe <server> <inner-addr> <port> and exit")
	probeCA := flag.String("probe-ca", "", "debug: CA cert path for probe mode")
	// speedtest: the admin Edge→Exit measurement (runs standalone, no
	// datapath start); the path crosses the exit's real transit adapter
	stExit := flag.String("speedtest-exit", "", "speedtest: measure this exit through its transit adapter and exit")
	stEndpoint := flag.String("speedtest-endpoint", "", "speedtest: testpoint host:port as dialed behind the exit")
	stToken := flag.String("speedtest-token-file", "", "speedtest: bearer token file for the testpoint")
	stBudget := flag.String("speedtest-budget", "quick", "speedtest: quick|extended")
	flag.Parse()
	if *stExit != "" {
		if *conf == "" || *stEndpoint == "" || *stToken == "" {
			log.Fatal("speedtest requires -config, -speedtest-exit, -speedtest-endpoint and -speedtest-token-file")
		}
		cfg, err := loadConfig(*conf)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		token, err := os.ReadFile(*stToken)
		if err != nil {
			log.Fatalf("token: %v", err)
		}
		budget, ok := speedtestBudgets[strings.TrimSpace(*stBudget)]
		if !ok {
			log.Fatal("budget must be quick|extended")
		}
		var audit *controlstore.Audit
		if cfg.StateDir != "" {
			audit, _ = controlstore.OpenAudit(cfg.StateDir)
		}
		if err := runExitSpeedtest(cfg, *stExit, *stEndpoint, strings.TrimSpace(string(token)), *stBudget, budget, audit); err != nil {
			log.Fatalf("speedtest: %v", err)
		}
		return
	}
	if *probeMode != "" {
		parts := strings.Fields(*probeMode)
		if len(parts) != 3 {
			log.Fatal("probe usage: -probe <server> <addr> <port>")
		}
		port, _ := strconv.Atoi(parts[2])
		t0 := time.Now()
		conn, err := transport.DialVLESS(tlsCACertFlag(*probeCA), parts[0], uuidBytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), parts[1], port, 3*time.Second)
		if err != nil {
			log.Fatalf("probe dial: %v", err)
		}
		fmt.Fprintf(conn, "GET /canary.txt HTTP/1.0\r\nHost: canary\r\n\r\n")
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, rerr := conn.Read(buf)
		fmt.Printf("elapsed_ms=%d read_n=%d read_err=%v body=%q\n", time.Since(t0).Milliseconds(), n, rerr, string(buf[:min(n, 24)]))
		return
	}
	if *conf == "" {
		log.Fatal("usage: ara-edge -config edge.json")
	}
	cfg, err := loadConfig(*conf)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		log.Fatalf("state dir: %v", err)
	}
	dp, err := newDatapath(cfg)
	if err != nil {
		log.Fatalf("datapath: %v", err)
	}

	dp.localPanelVerified.Store(time.Now().UnixNano())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// SIGHUP: live reload of the operator-editable state — policy (through
	// the accepted store parser, invalid file keeps the LKG running) and
	// device identities/rates. The quota ledger is NOT recreated: durable
	// usage survives the reload.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current := dp.configSnapshot()
				if current.LocalPanel == nil {
					continue
				}
				next, err := loadConfig(current.configPath)
				if err != nil {
					log.Printf("local subscription refresh: %v", err)
				} else if next.configSnapshot == current.configSnapshot {
					if next.localSubscriptionsHash != current.localSubscriptionsHash {
						if err := dp.reloadConfig(next); err != nil {
							log.Printf("local subscription apply: %v", err)
							continue
						}
					}
					dp.localPanelVerified.Store(time.Now().UnixNano())
				}
				continue
			case <-hup:
			}
			if err := dp.reload(); err != nil {
				log.Printf("reload: %v (previous state kept)", err)
			} else {
				// G03: the NEW config was accepted — the serving
				// acknowledgment moves to its hash
				if serr := recordServingHash(dp.configSnapshot()); serr != nil {
					log.Printf("reload: serving hash: %v", serr)
				}
				log.Printf("reload: policy and devices refreshed")
			}
		}
	}()
	go dp.runProbes(ctx)
	go dp.runRemoteRateSync(ctx)
	go dp.runQuotaReportFlush(ctx)
	go dp.reportLocalTraffic(ctx)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				dp.writeStatus()
			}
		}
	}()

	var wg sync.WaitGroup
	if cfg.AccessListen != "" {
		if _, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Fatalf("tls: %v", err)
		}
		tlsSrv := dynamicTLSServingConfig(cfg.TLSCert, cfg.TLSKey)
		ln, err := tls.Listen("tcp", cfg.AccessListen, tlsSrv)
		if err != nil {
			log.Fatalf("vless listen: %v", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go dp.handleAccess(conn, "")
			}
		}()
		log.Printf("vless/tls access on %s", cfg.AccessListen)
	}
	// B23: dedicated pinned-exit route listeners — one client-facing
	// endpoint per published edge→exit route. The binding is the
	// configured route policy: an unhealthy pinned exit refuses instead
	// of silently rerouting to another country.
	for i := range cfg.Routes {
		rt := cfg.Routes[i]
		if rt.ExitID == "" {
			log.Fatalf("route listener %s: exit_id required", rt.Listen)
		}
		known := false
		for _, e := range cfg.Exits {
			if e.ID == rt.ExitID {
				known = true
				break
			}
		}
		if !known {
			log.Fatalf("route listener %s: exit %s is not a configured exit", rt.Listen, rt.ExitID)
		}
		tlsSrv := dynamicTLSServingConfig(cfg.TLSCert, cfg.TLSKey)
		ln, err := tls.Listen("tcp", rt.Listen, tlsSrv)
		if err != nil {
			log.Fatalf("route listen %s: %v", rt.Listen, err)
		}
		wg.Add(1)
		go func(ln net.Listener, exitID string) {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go dp.handleAccess(conn, exitID)
			}
		}(ln, rt.ExitID)
		log.Printf("vless/tls route on %s → exit %s (pinned)", rt.Listen, rt.ExitID)
	}
	// G03/H01: the SERVING acknowledgment is recorded only after all
	// serving components (datapath, access/route listeners) are up.
	if err := recordServingHash(cfg); err != nil {
		log.Fatalf("serving hash: %v", err)
	}
	if cfg.SOCKSListen != "" {
		// a SOCKS listener without any configured device credential would
		// only ever serve refusals — that is a config error, not a mode
		if !dp.socksAuthConfigured() {
			log.Fatalf("socks listen %s requires at least one device with socks_user/socks_pass (anonymous relay is not permitted)", cfg.SOCKSListen)
		}
		ln, err := net.Listen("tcp", cfg.SOCKSListen)
		if err != nil {
			log.Fatalf("socks listen: %v", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go dp.handleSOCKS(conn)
			}
		}()
		log.Printf("socks relay on %s (authenticated)", cfg.SOCKSListen)
	}
	dp.writeStatus()
	<-ctx.Done()
	log.Printf("ara-edge stopping")
}

func (dp *edgeDatapath) runQuotaReportFlush(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dp.mu.Lock()
			ledgers := make([]*remoteQuotaLedger, 0, len(dp.remoteRates))
			for _, ledger := range dp.remoteRates {
				ledgers = append(ledgers, ledger)
			}
			dp.mu.Unlock()
			for _, ledger := range ledgers {
				if ctx.Err() != nil {
					return
				}
				for _, device := range ledger.checkUsedDevices(ctx) {
					dp.mu.Lock()
					var conns []net.Conn
					for conn, id := range dp.ident {
						if id == device && dp.quotaForLocked(id) == ledger {
							conns = append(conns, conn)
						}
					}
					dp.mu.Unlock()
					for _, conn := range conns {
						_ = conn.Close()
					}
				}
				ledger.flushPending(ctx)
			}
		}
	}
}
