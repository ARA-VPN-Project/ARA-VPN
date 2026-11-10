package routing

import (
	"net/netip"
	"strings"
	"testing"

	"aravpn/core/health"
	"aravpn/core/policy"
)

func baseTopology() Topology {
	return Topology{
		Exits: []Exit{
			{ID: "nl-a", Country: "NL", Priority: 1, Role: RoleForeign},
			{ID: "nl-b", Country: "NL", Priority: 2, Role: RoleForeign},
			{ID: "ru-e", Country: "RU", Priority: 0, Role: RoleRU},
		},
		CurrentForeignID: "nl-a",
	}
}

func allHealthy(t Topology) Snapshot {
	s := Snapshot{}
	for _, e := range t.Exits {
		s[e.ID] = health.Healthy
	}
	return s
}

func stdPolicy() *policy.Policy {
	p := policy.DefaultPolicy()
	p.Revision = 7
	p.Rules = []policy.Rule{
		{ID: "ru-local", Enabled: true, DomainExact: []string{"local.example"}, Action: policy.ActionRUExit},
		{ID: "block-ads", Enabled: true, DomainExact: []string{"ads.example"}, Action: policy.ActionBlock},
		{ID: "strict-media", Enabled: true, DomainSuffix: []string{"strict.example"}, Action: policy.ActionForeignPool, AllowRUFallback: boolPtr(false)},
	}
	return p
}

func boolPtr(b bool) *bool { return &b }

func acl() policy.SystemACL { return policy.SystemACL{DenyNonGlobal: true} }

func dest(domain string) policy.Destination {
	return policy.Destination{Domain: domain, Proto: policy.ProtoTCP, Port: 443}
}

func TestHealthyDefaultGoesStickyForeign(t *testing.T) {
	topo := baseTopology()
	d := Decide(topo, allHealthy(topo), stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 1)
	if d.Mode != ModeForeign || d.ExitID != "nl-a" || d.Country != "NL" {
		t.Fatalf("default: %+v", d)
	}
	if d.Reason != ReasonDefaultForeign || d.MatchedRuleID != "" {
		t.Fatalf("reason: %+v", d)
	}
	if d.DNSScope != "exit:nl-a" {
		t.Fatalf("dns scope: %q", d.DNSScope)
	}
	// matched rule keeps its rule id in explain
	d = Decide(topo, allHealthy(topo), stdPolicy(), acl(), dest("media.strict.example"), QuotaState{}, 1)
	if d.MatchedRuleID != "strict-media" || d.Reason != ReasonMatchedRule {
		t.Fatalf("rule explain: %+v", d)
	}
}

func TestNamedExitRulesKeepServicesAndDNSOnSeparateExits(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	p := policy.DefaultPolicy()
	p.Rules = []policy.Rule{
		{ID: "video", Enabled: true, DomainSuffix: []string{"video.example"}, Action: policy.ActionForeignExit, ExitID: "nl-a"},
		{ID: "work", Enabled: true, DomainSuffix: []string{"work.example"}, Action: policy.ActionForeignExit, ExitID: "nl-b"},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for domain, target := range map[string]string{"cdn.video.example": "nl-a", "api.work.example": "nl-b"} {
		d := Decide(topo, hs, p, acl(), dest(domain), QuotaState{}, 1)
		if d.ExitID != target || d.DNSScope != "exit:"+target || d.AllowRUFallback {
			t.Fatalf("%s: %+v", domain, d)
		}
	}
	hs["nl-b"] = health.Down
	d := Decide(topo, hs, p, acl(), dest("api.work.example"), QuotaState{}, 2)
	if d.ActualAction != policy.ActionBlock || d.ExitID != "" || d.DNSScope != "none" || d.RequestedExitID != "nl-b" {
		t.Fatalf("a strict exit fell back: %+v", d)
	}
}

func TestFirstForeignDownFallsToReserve(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	hs["nl-a"] = health.Down
	d := Decide(topo, hs, stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 2)
	if d.ExitID != "nl-b" || d.Mode != ModeReserveForeign {
		t.Fatalf("reserve selection: %+v", d)
	}
	// sticky: when nl-a recovers it must become the choice again only
	// because it is both current and healthy (priority order preserved)
	hs["nl-a"] = health.Healthy
	d = Decide(topo, hs, stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 3)
	if d.ExitID != "nl-a" || d.Mode != ModeForeign {
		t.Fatalf("sticky return: %+v", d)
	}
}

func TestStickyCurrentKeptWhileHealthy(t *testing.T) {
	// nl-b is current but nl-a has better priority; healthy current wins.
	topo := baseTopology()
	topo.CurrentForeignID = "nl-b"
	d := Decide(topo, allHealthy(topo), stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 1)
	if d.ExitID != "nl-b" {
		t.Fatalf("sticky current overridden by priority: %+v", d)
	}
	if d.Mode != ModeReserveForeign {
		t.Fatalf("using worse-priority exit must display reserve mode: %+v", d)
	}
}

func TestAllForeignDownAutoRUFallbackWithoutPrompt(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	hs["nl-a"] = health.Down
	hs["nl-b"] = health.Down
	d := Decide(topo, hs, stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 4)
	if d.ActualAction != policy.ActionRUExit || d.Mode != ModeRUFallback || d.ExitID != "ru-e" {
		t.Fatalf("ru fallback: %+v", d)
	}
	if d.Reason != ReasonAllForeignDown {
		t.Fatalf("fallback reason: %q", d.Reason)
	}
	if d.DNSScope != "ru:ru-e" {
		t.Fatalf("fallback dns scope: %q", d.DNSScope)
	}
	// unknown is not healthy: must also trigger fallback, not selection
	hs["nl-a"] = health.Unknown
	hs["nl-b"] = health.Unknown
	d = Decide(topo, hs, stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 5)
	if d.Mode != ModeRUFallback {
		t.Fatalf("unknown treated as eligible: %+v", d)
	}
}

func TestStrictRuleBlocksInsteadOfRUFallback(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	hs["nl-a"] = health.Down
	hs["nl-b"] = health.Down
	d := Decide(topo, hs, stdPolicy(), acl(), dest("site.strict.example"), QuotaState{}, 6)
	if d.ActualAction != policy.ActionBlock || d.Reason != ReasonRUFallbackDisabled {
		t.Fatalf("strict rule: %+v", d)
	}
	// profile-level switch off produces NO_EGRESS instead (different code)
	p := stdPolicy()
	p.AllowRUFallback = false
	p.Rules = nil
	d = Decide(topo, hs, p, acl(), dest("unknown.example"), QuotaState{}, 7)
	if d.ActualAction != policy.ActionBlock || d.Reason != ReasonNoEgress {
		t.Fatalf("profile strict: %+v", d)
	}
}

func TestRecoveryReturnsNewFlowsToForeign(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	hs["nl-a"] = health.Down
	hs["nl-b"] = health.Down
	// during the outage flows went RU
	d := Decide(topo, hs, stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 8)
	if d.Mode != ModeRUFallback {
		t.Fatalf("setup: %+v", d)
	}
	// nl-a becomes healthy again (recovery window passed in health pkg):
	// NEW flows go foreign again
	hs["nl-a"] = health.Healthy
	d = Decide(topo, hs, stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 9)
	if d.Mode != ModeForeign || d.ExitID != "nl-a" {
		t.Fatalf("recovery: %+v", d)
	}
}

func TestRUPathDownMeansOfflineNoDirect(t *testing.T) {
	topo := baseTopology()
	topo.AccessDown = true
	d := Decide(topo, allHealthy(topo), stdPolicy(), acl(), dest("unknown.example"), QuotaState{}, 10)
	if d.Mode != ModeOffline || d.ActualAction != policy.ActionBlock {
		t.Fatalf("access down: %+v", d)
	}
	if d.Reason != ReasonAccessDown {
		t.Fatalf("offline reason: %q", d.Reason)
	}
	// even RU_EXIT rules cannot bypass
	d = Decide(topo, allHealthy(topo), stdPolicy(), acl(), dest("local.example"), QuotaState{}, 11)
	if d.Mode != ModeOffline {
		t.Fatalf("ru rule during access down: %+v", d)
	}
}

func TestRURuleWithRUDownBlocksNeverForeign(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	hs["ru-e"] = health.Down
	d := Decide(topo, hs, stdPolicy(), acl(), dest("local.example"), QuotaState{}, 12)
	if d.ActualAction != policy.ActionBlock || d.Reason != ReasonNoHealthyRU {
		t.Fatalf("ru rule with ru down: %+v", d)
	}
	if d.ExitID != "" {
		t.Fatalf("blocked flow must have no exit: %+v", d)
	}
}

func TestQuotaExhaustedBlocksAllPathsIncludingRUFallback(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	hs["nl-a"] = health.Down
	hs["nl-b"] = health.Down
	d := Decide(topo, hs, stdPolicy(), acl(), dest("unknown.example"), QuotaState{Exhausted: true}, 13)
	if d.ActualAction != policy.ActionBlock || d.Reason != ReasonQuotaExhausted {
		t.Fatalf("quota block: %+v", d)
	}
	// even a RU_EXIT rule is blocked for data while quota exhausted
	d = Decide(topo, hs, stdPolicy(), acl(), dest("local.example"), QuotaState{Exhausted: true}, 14)
	if d.ActualAction != policy.ActionBlock {
		t.Fatalf("quota must outrank ru rule: %+v", d)
	}
}

func TestNonGlobalDestinationsDenied(t *testing.T) {
	topo := baseTopology()
	cases := []struct {
		ip string
		ok bool // allowed through?
	}{
		{"169.254.169.254", false}, // cloud metadata
		{"127.0.0.1", false},
		{"10.1.2.3", false},
		{"192.168.1.1", false},
		{"fe80::1", false},
		{"::1", false},
		{"203.0.113.9", false}, // TEST-NET-3: user proxy misconfig
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := IsNonGlobal(ip); got == c.ok {
			t.Errorf("IsNonGlobal(%s) = %v, want %v", c.ip, got, !c.ok)
		}
		d := Decide(topo, allHealthy(topo), stdPolicy(), acl(), policy.Destination{IP: ip, Proto: policy.ProtoTCP, Port: 443}, QuotaState{}, 15)
		if c.ok && d.ActualAction != policy.ActionForeignPool {
			t.Errorf("global %s blocked: %+v", c.ip, d)
		}
		if !c.ok && (d.ActualAction != policy.ActionBlock || d.Reason != ReasonNonGlobalDenied) {
			t.Errorf("non-global %s allowed: %+v", c.ip, d)
		}
	}
	// LAN exception re-enables an administrator-approved range
	a := policy.SystemACL{DenyNonGlobal: true, LANExceptions: []string{"192.168.1.0/24"}}
	ip := netip.MustParseAddr("192.168.1.50")
	d := Decide(topo, allHealthy(topo), stdPolicy(), a, policy.Destination{IP: ip, Proto: policy.ProtoTCP, Port: 443}, QuotaState{}, 16)
	if d.ActualAction != policy.ActionForeignPool {
		t.Errorf("lan exception not honored: %+v", d)
	}
	// exception is prefix-exact, not a blanket private pass
	ip2 := netip.MustParseAddr("192.168.2.50")
	d = Decide(topo, allHealthy(topo), stdPolicy(), a, policy.Destination{IP: ip2, Proto: policy.ProtoTCP, Port: 443}, QuotaState{}, 17)
	if d.ActualAction != policy.ActionBlock {
		t.Errorf("lan exception leaked to other ranges: %+v", d)
	}
}

func TestBlockRuleStopsImmediately(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	hs["nl-a"] = health.Down
	hs["nl-b"] = health.Down
	// BLOCK ends immediately: no RU fallback attempt for a blocked rule
	d := Decide(topo, hs, stdPolicy(), acl(), dest("ads.example"), QuotaState{}, 18)
	if d.Reason != ReasonMatchedRule || d.Mode != ModeBlocked {
		t.Fatalf("block rule: %+v", d)
	}
}

func TestValidateTopology(t *testing.T) {
	if err := ValidateTopology(baseTopology()); err != nil {
		t.Fatalf("valid topology rejected: %v", err)
	}
	topo := baseTopology()
	topo.Exits = topo.Exits[:2]
	if err := ValidateTopology(topo); err == nil || !strings.Contains(err.Error(), "RU exit") {
		t.Fatalf("no-ru topology accepted: %v", err)
	}
	topo = baseTopology()
	topo.CurrentForeignID = "nl-z"
	if err := ValidateTopology(topo); err == nil {
		t.Fatal("unknown current exit accepted")
	}
}

func TestBlockDefaultKeepsNamedRulesAndDeniesUnmatched(t *testing.T) {
	topo := baseTopology()
	p := policy.DefaultPolicy()
	p.DefaultAction = policy.ActionBlock
	p.Rules = []policy.Rule{{ID: "media", Enabled: true, DomainSuffix: []string{"video.example"}, Action: policy.ActionForeignExit, ExitID: "nl-b"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	hs := allHealthy(topo)
	matched := Decide(topo, hs, p, acl(), dest("cdn.video.example"), QuotaState{}, 1)
	if matched.ExitID != "nl-b" {
		t.Fatalf("matched traffic: %+v", matched)
	}
	unmatched := Decide(topo, hs, p, acl(), dest("example.net"), QuotaState{}, 1)
	if unmatched.ActualAction != policy.ActionBlock || unmatched.ExitID != "" {
		t.Fatalf("unmatched traffic: %+v", unmatched)
	}
}

func TestNamedExitConfiguredFallback(t *testing.T) {
	topo := baseTopology()
	hs := allHealthy(topo)
	p := policy.DefaultPolicy()
	p.DefaultAction, p.DefaultExitID = policy.ActionForeignExit, "nl-a"
	for _, tc := range []struct {
		fallback     policy.ExitFallback
		backup, want string
	}{
		{policy.ExitFallbackBlock, "nl-b", ""},
		{policy.ExitFallbackRU, "nl-b", "ru-e"},
		{policy.ExitFallbackForeign, "nl-b", "nl-b"},
		{policy.ExitFallbackForeignThenRU, "ru-e", "ru-e"},
	} {
		p.ForeignExitFallback = tc.fallback
		healthy := Snapshot{"nl-a": health.Healthy, tc.backup: hs[tc.backup], "ru-e": hs["ru-e"]}
		d := Decide(topo, healthy, p, acl(), dest("service.example"), QuotaState{}, 1)
		if d.ExitID != "nl-a" {
			t.Fatalf("healthy primary changed: %+v", d)
		}
		healthy["nl-a"] = health.Down
		d = Decide(topo, healthy, p, acl(), dest("service.example"), QuotaState{}, 1)
		if d.ExitID != tc.want || d.ActualAction == policy.ActionDirect {
			t.Fatalf("%s got %+v, want %q", tc.fallback, d, tc.want)
		}
	}
}
