// Package routing is the offline decision oracle: given the policy, a
// health snapshot of the topology and a destination, it returns the actual
// egress for a new flow with a stable reason code and DNS scope
// (docs/FAILOVER.md "Алгоритм новых потоков").
//
// It performs no I/O and no probing: the agent feeds it computed health
// snapshots, which keeps the whole decision layer deterministic and unit
// testable. Probe production, expiry and flow drain live in the agent.
package routing

import (
	"fmt"
	"net/netip"
	"sort"

	"aravpn/core/health"
	"aravpn/core/policy"
)

// Role distinguishes the two logical egress roles. RU Edge and RU Exit may
// share one Debian host in the MVP but remain separate roles with separate
// ACLs (docs/PROJECT_SCOPE.md U05).
type Role string

const (
	RoleRU      Role = "ru"
	RoleForeign Role = "foreign"
)

// Exit is one egress node of the topology.
type Exit struct {
	ID       string
	Country  string // observed egress country, e.g. "RU", "NL"
	Priority int    // lower = preferred for foreign pool
	Role     Role
}

// Mode is the user-visible egress mode shown in UI/CLI
// (docs/FAILOVER.md "Пользовательский результат").
type Mode string

const (
	ModeForeign        Mode = "foreign"
	ModeReserveForeign Mode = "reserve_foreign"
	// ModeDirect (B39): explicit client-side DIRECT egress.
	ModeDirect Mode = "direct"
	// ModeRU is a NORMAL russian egress chosen by an explicit RU rule —
	// it is a different user-visible state from ModeRUFallback, which is
	// the emergency path when the foreign pool is down (review R11:
	// reporting a normal RU route as "foreign" lies to the user).
	ModeRU         Mode = "ru_exit"
	ModeRUFallback Mode = "ru_fallback"
	ModeOffline    Mode = "offline"
	ModeBlocked    Mode = "blocked"
)

// Reason codes are stable contract values (docs/DIAGNOSTICS.md).
const (
	ReasonMatchedRule    = "MATCHED_RULE"
	ReasonDefaultForeign = "DEFAULT_FOREIGN"
	// ReasonDefaultDirect / direct-mode reason (B39): explicit client-side
	// DIRECT rule matched.
	ReasonMatchedDirect      = "MATCHED_DIRECT"
	ReasonAllForeignDown     = "ALL_FOREIGN_DOWN_RU_FALLBACK"
	ReasonRUHealthy          = "RU_RULE_HEALTHY"
	ReasonNoEgress           = "NO_EGRESS_AVAILABLE"
	ReasonRUFallbackDisabled = "RU_FALLBACK_DISABLED_BY_RULE"
	ReasonAccessDown         = "ACCESS_PATH_DOWN_OFFLINE"
	ReasonNonGlobalDenied    = "NON_GLOBAL_DESTINATION_DENIED"
	ReasonQuotaExhausted     = "QUOTA_EXHAUSTED"
	ReasonNoHealthyRU        = "NO_HEALTHY_RU_EXIT"
	ReasonSelectedExitDown   = "SELECTED_EXIT_UNAVAILABLE"
)

// DNSScope names which resolver path a DNS lookup for this flow must use;
// it is part of the route, not a global resolver (docs/ROUTING_DNS.md).
type DNSScope string

const (
	DNSViaExit   DNSScope = ""     // filled with the chosen exit id prefix
	DNSScopeNone DNSScope = "none" // blocked: no resolution permitted
)

// Decision is the complete explainable result for one new flow.
type Decision struct {
	Action          policy.Action // desired action from policy
	ActualAction    policy.Action // final: RU_EXIT or BLOCK; actual egress class
	Mode            Mode
	ExitID          string
	RequestedExitID string
	Country         string
	Reason          string
	MatchedRuleID   string // empty => default action
	AllowRUFallback bool
	DNSScope        string // "ru:<exit-id>" | "exit:<exit-id>" | "none"
	Generation      uint64
}

// Topology is the configured exit set plus selection state.
type Topology struct {
	Exits []Exit
	// CurrentForeignID is the sticky current foreign exit; it stays
	// selected while healthy, regardless of better pings elsewhere.
	CurrentForeignID string
	// AccessDown means the client→RU Edge path is unavailable: the kill
	// switch keeps everything offline, LOCAL_DIRECT is never enabled.
	AccessDown bool
}

// Snapshot is the health view consumed by Decide: node id → effective
// state. Values must come from health.Tracker.Effective() so expiry and
// stability promotion are already applied.
type Snapshot map[string]health.State

// QuotaState gates all data traffic: when exhausted, user data is blocked
// on every path including RU fallback while bounded management stays up
// (docs/LIMITS_QUOTAS.md).
type QuotaState struct {
	Exhausted bool
}

var nonGlobal = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// IsNonGlobal reports whether addr is loopback, private, link-local,
// multicast, unspecified or documentation space. TEST-NET ranges are
// included deliberately: user proxy traffic to documentation ranges is a
// misconfiguration, and cloud metadata (169.254.169.254) is link-local.
func IsNonGlobal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	for _, p := range nonGlobal {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// Decide computes the routing decision for one new flow. nowOnly is unused;
// generation is supplied by the caller (agent path generation counter) and
// echoed into the DNS scope binding.
func Decide(topo Topology, hs Snapshot, pol *policy.Policy, acl policy.SystemACL, d policy.Destination, quota QuotaState, generation uint64) Decision {
	dec := Decision{Generation: generation, Action: policy.ActionForeignPool}

	// 0. Access path down => offline for everything; the kill switch
	// forbids bypass and the local direct egress is never enabled.
	if topo.AccessDown {
		return blocked(dec, policy.ActionBlock, ModeOffline, ReasonAccessDown)
	}
	// 0a. Quota exhaustion blocks data on all paths, including RU
	// fallback; it is not a health failure and must not trigger failover.
	if quota.Exhausted {
		return blocked(dec, policy.ActionBlock, ModeBlocked, ReasonQuotaExhausted)
	}
	// 1. System ACL: non-global destinations are denied for user proxy
	// traffic unless explicitly excepted by an administrator LAN policy.
	if d.IP.IsValid() && acl.DenyNonGlobal && IsNonGlobal(d.IP) && !lanExcepted(acl, d.IP) {
		return blocked(dec, policy.ActionBlock, ModeBlocked, ReasonNonGlobalDenied)
	}

	// 2. Desired action from ordered user rules (first match).
	ev := pol.Evaluate(d)
	dec.Action = ev.Action
	dec.MatchedRuleID = ev.MatchedRuleID
	dec.RequestedExitID = ev.ExitID
	dec.AllowRUFallback = ev.AllowRUFallback

	switch ev.Action {
	case policy.ActionBlock:
		return blocked(dec, policy.ActionBlock, ModeBlocked, ReasonMatchedRule)

	case policy.ActionDirect:
		// B39: explicit client-side DIRECT — matched traffic leaves via
		// the host's own network with its own DNS scope. It is a first-
		// class configured decision, not a fallback, and it is never
		// entered automatically by RU/foreign/Edge failures.
		dec.ActualAction = policy.ActionDirect
		dec.Mode = ModeDirect
		dec.ExitID = ""
		dec.Country = ""
		dec.DNSScope = "direct"
		dec.Reason = ReasonMatchedDirect
		return dec

	case policy.ActionRUExit:
		// A RU rule never tries the foreign pool.
		ru := pickRU(topo, hs)
		if ru == nil {
			return blocked(dec, policy.ActionBlock, ModeBlocked, ReasonNoHealthyRU)
		}
		dec.ActualAction = policy.ActionRUExit
		dec.Mode = ModeRU
		dec.ExitID = ru.ID
		dec.Country = ru.Country
		dec.Reason = ReasonRUHealthy
		dec.DNSScope = "ru:" + ru.ID
		return dec

	case policy.ActionForeignExit:
		for _, exit := range topo.Exits {
			if exit.ID == ev.ExitID && exit.Role == RoleForeign && hs[exit.ID].EligibleForNewFlow() {
				dec.ActualAction = policy.ActionForeignExit
				dec.Mode = ModeForeign
				dec.ExitID = exit.ID
				dec.Country = exit.Country
				dec.Reason = ReasonMatchedRule
				dec.DNSScope = "exit:" + exit.ID
				return dec
			}
		}
		switch pol.ForeignExitFallback {
		case policy.ExitFallbackForeign, policy.ExitFallbackForeignThenRU:
			if f := pickForeign(topo, hs); f != nil && f.exit.ID != ev.ExitID {
				dec.ActualAction, dec.Mode, dec.Reason = policy.ActionForeignExit, ModeReserveForeign, "SELECTED_EXIT_FALLBACK_FOREIGN"
				dec.ExitID, dec.Country, dec.DNSScope = f.exit.ID, f.exit.Country, "exit:"+f.exit.ID
				return dec
			}
		}
		if pol.ForeignExitFallback == policy.ExitFallbackRU || pol.ForeignExitFallback == policy.ExitFallbackForeignThenRU {
			if ru := pickRU(topo, hs); ru != nil {
				dec.ActualAction, dec.Mode, dec.Reason = policy.ActionRUExit, ModeRUFallback, "SELECTED_EXIT_FALLBACK_RU"
				dec.ExitID, dec.Country, dec.DNSScope = ru.ID, ru.Country, "ru:"+ru.ID
				dec.AllowRUFallback = true
				return dec
			}
		}
		return blocked(dec, ev.Action, ModeBlocked, ReasonSelectedExitDown)

	default: // FOREIGN_POOL
		f := pickForeign(topo, hs)
		if f != nil {
			dec.ActualAction = policy.ActionForeignPool
			dec.ExitID = f.exit.ID
			dec.Country = f.exit.Country
			if f.reserve {
				dec.Mode = ModeReserveForeign
			} else {
				dec.Mode = ModeForeign
			}
			if dec.MatchedRuleID != "" {
				dec.Reason = ReasonMatchedRule
			} else {
				dec.Reason = ReasonDefaultForeign
			}
			dec.DNSScope = "exit:" + f.exit.ID
			return dec
		}
		// No healthy foreign exit. Automatic RU fallback is the agreed
		// standard behavior (U07): no dialogs, new flows go RU now.
		if dec.AllowRUFallback {
			ru := pickRU(topo, hs)
			if ru != nil {
				dec.ActualAction = policy.ActionRUExit
				dec.Mode = ModeRUFallback
				dec.ExitID = ru.ID
				dec.Country = ru.Country
				dec.Reason = ReasonAllForeignDown
				dec.DNSScope = "ru:" + ru.ID
				return dec
			}
			return blocked(dec, ev.Action, ModeOffline, ReasonNoEgress)
		}
		if ev.ExplicitFallbackOverride {
			return blocked(dec, ev.Action, ModeBlocked, ReasonRUFallbackDisabled)
		}
		return blocked(dec, ev.Action, ModeOffline, ReasonNoEgress)
	}
}

func blocked(dec Decision, desired policy.Action, mode Mode, reason string) Decision {
	dec.Action = desired
	dec.ActualAction = policy.ActionBlock
	dec.Mode = mode
	dec.Reason = reason
	dec.ExitID = ""
	dec.Country = ""
	dec.DNSScope = string(DNSScopeNone)
	return dec
}

func lanExcepted(acl policy.SystemACL, ip netip.Addr) bool {
	for _, c := range acl.LANExceptions {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

func pickRU(topo Topology, hs Snapshot) *Exit {
	var rus []Exit
	for _, e := range topo.Exits {
		if e.Role != RoleRU {
			continue
		}
		if hs[e.ID].EligibleForNewFlow() {
			rus = append(rus, e)
		}
	}
	if len(rus) == 0 {
		return nil
	}
	sort.Slice(rus, func(i, j int) bool { return rus[i].ID < rus[j].ID })
	return &rus[0]
}

type foreignPick struct {
	exit    Exit
	reserve bool // chosen exit is not the primary-priority configured exit
}

// pickForeign implements sticky selection: keep the current foreign exit
// while it is healthy; otherwise take the first healthy by (priority, id).
// It never switches because of a better ping alone. Reserve mode compares
// against the best priority among *configured* foreign exits: serving from
// a reserve node while the primary is down is a distinct user-facing state
// (docs/FAILOVER.md "Пользовательский результат").
func pickForeign(topo Topology, hs Snapshot) *foreignPick {
	var healthy []Exit
	primary := -1
	for _, e := range topo.Exits {
		if e.Role != RoleForeign {
			continue
		}
		if primary < 0 || e.Priority < primary {
			primary = e.Priority
		}
		if hs[e.ID].EligibleForNewFlow() {
			healthy = append(healthy, e)
		}
	}
	if len(healthy) == 0 {
		return nil
	}
	sort.Slice(healthy, func(i, j int) bool {
		if healthy[i].Priority != healthy[j].Priority {
			return healthy[i].Priority < healthy[j].Priority
		}
		return healthy[i].ID < healthy[j].ID
	})
	for i := range healthy {
		if healthy[i].ID == topo.CurrentForeignID {
			return &foreignPick{exit: healthy[i], reserve: healthy[i].Priority > primary}
		}
	}
	return &foreignPick{exit: healthy[0], reserve: healthy[0].Priority > primary}
}

// ExplainView renders a Decision for `ara route explain` (read-only, no
// network request to the destination).
func (d Decision) ExplainView() map[string]any {
	return map[string]any{
		"matched_rule_id":   d.MatchedRuleID,
		"desired_action":    string(d.Action),
		"actual_action":     string(d.ActualAction),
		"mode":              string(d.Mode),
		"exit_id":           d.ExitID,
		"requested_exit_id": d.RequestedExitID,
		"country":           d.Country,
		"reason_code":       d.Reason,
		"allow_ru_fallback": d.AllowRUFallback,
		"dns_scope":         d.DNSScope,
		"generation":        d.Generation,
	}
}

// ValidateTopology checks exit list invariants before use.
func ValidateTopology(topo Topology) error {
	seen := map[string]bool{}
	hasRU := false
	for _, e := range topo.Exits {
		if e.ID == "" {
			return fmt.Errorf("exit id is required")
		}
		if seen[e.ID] {
			return fmt.Errorf("duplicate exit id %q", e.ID)
		}
		seen[e.ID] = true
		if e.Role == RoleRU {
			hasRU = true
		}
	}
	if !hasRU {
		return fmt.Errorf("topology requires at least one RU exit")
	}
	if topo.CurrentForeignID != "" && !seen[topo.CurrentForeignID] {
		return fmt.Errorf("current foreign exit %q is not in topology", topo.CurrentForeignID)
	}
	return nil
}
