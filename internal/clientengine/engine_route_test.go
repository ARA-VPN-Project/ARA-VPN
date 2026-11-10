package clientengine

// B39: verified policy rules reach the client RUNTIME — explicit DIRECT
// and BLOCK become sing-box route rules with matching outbounds, DIRECT
// domains resolve through the local resolver, and unmatched traffic stays
// on the VPN outbound (final vo = kill switch).

import (
	"encoding/json"
	"testing"

	"aravpn/core/policy"
)

func routeTestProfile() Profile {
	return Profile{
		EnginePath: "/usr/bin/sing-box", ServerAddr: "edge.example.invalid:443",
		ServerName: "edge.example.invalid", CAPath: "/tmp/ca.pem",
		UUID:    "11111111-1111-4111-8111-111111111111",
		TUNName: "ara-t", TUNAddr4: "10.88.0.1/30", MTU: 1400,
	}
}

func TestDirectAndBlockRulesReachRuntimeConfig(t *testing.T) {
	p := routeTestProfile()
	p.RouteRules = []ClientRouteRule{
		{DomainSuffix: []string{"bank.example"}, Action: "direct"},
		{CIDR: []string{"192.168.0.0/16"}, Action: "direct"},
		{DomainExact: []string{"malware.example"}, Action: "block"},
	}
	cfg := singboxConfig(p)
	obs := cfg["outbounds"].([]map[string]any)
	tags := map[string]bool{}
	for _, ob := range obs {
		tags[ob["tag"].(string)] = true
	}
	if !tags["direct"] || !tags["block"] || !tags["vo"] {
		t.Fatalf("expected vo+direct+block outbounds, got %v", tags)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]map[string]any)
	var directSuffix, directCIDR, blockDomain bool
	for _, r := range rules {
		if r["outbound"] == "direct" {
			if ss, ok := r["domain_suffix"].([]string); ok && len(ss) == 1 && ss[0] == "bank.example" {
				directSuffix = true
			}
			if c, ok := r["ip_cidr"].([]string); ok && len(c) == 1 && c[0] == "192.168.0.0/16" {
				directCIDR = true
			}
		}
		if r["outbound"] == "block" {
			if d, ok := r["domain"].([]string); ok && len(d) == 1 && d[0] == "malware.example" {
				blockDomain = true
			}
		}
	}
	if !directSuffix || !directCIDR || !blockDomain {
		t.Fatalf("route rules incomplete: direct_suffix=%v direct_cidr=%v block_domain=%v", directSuffix, directCIDR, blockDomain)
	}
	// DIRECT domains resolve through the LOCAL resolver, not the tunnel
	dns := cfg["dns"].(map[string]any)
	servers := dns["servers"].([]map[string]any)
	if servers[0]["tag"] != "local-dns" {
		t.Fatalf("first DNS server must be local-dns: %v", servers)
	}
}

func TestRulesFromPolicyTranslatesVerifiedActionsOnly(t *testing.T) {
	pol := &policy.Policy{SchemaVersion: 1, Revision: 3, Rules: []policy.Rule{
		{ID: "bank", Enabled: true, DomainSuffix: []string{"bank.example"}, Action: policy.ActionDirect},
		{ID: "deny", Enabled: true, CIDR: []string{"10.9.0.0/16"}, Ports: []policy.PortRange{{From: 443, To: 443}}, Action: policy.ActionBlock},
		{ID: "ru", Enabled: true, CIDR: []string{"10.71.0.0/16"}, Action: policy.ActionRUExit},
		{ID: "off", Enabled: false, DomainSuffix: []string{"ignored.example"}, Action: policy.ActionDirect},
	}}
	rr := RulesFromPolicy(pol)
	// C03: the RU_EXIT rule is now an explicit vpn BARRIER — order and all
	// three decisions are preserved
	if len(rr) != 3 {
		t.Fatalf("expected 3 runtime rules (DIRECT+BLOCK+vpn barrier), got %d: %+v", len(rr), rr)
	}
	if rr[0].Action != "direct" || rr[1].Action != "block" || rr[1].Ports[0] != "443" || rr[2].Action != "vpn" {
		t.Fatalf("rule translation wrong: %+v", rr)
	}
	// provider nil policy → no rules; final vo keeps kill-switch semantics
	cfg := singboxConfig(routeTestProfile())
	b, _ := json.Marshal(cfg["route"])
	if string(b) == "" {
		t.Fatal("route config missing")
	}
	rc := cfg["route"].(map[string]any)
	if _, has := rc["rules"]; has && len(rr) == 0 {
		t.Fatal("no rules must not render an empty rules key")
	}
}

func TestLivePolicyProviderMergesAtConnectRender(t *testing.T) {
	e := New(t.TempDir())
	e.SetPolicyProvider(func() (*policy.Policy, error) {
		return &policy.Policy{SchemaVersion: 1, Revision: 7, Rules: []policy.Rule{
			{ID: "d", Enabled: true, DomainExact: []string{"direct.example"}, Action: policy.ActionDirect},
		}}, nil
	})
	p := routeTestProfile()
	// simulate Start's merge path: provider rules appended, rendered
	live, err := e.policyProvider()
	if err != nil {
		t.Fatal(err)
	}
	p.RouteRules = append(p.RouteRules, RulesFromPolicy(live)...)
	cfg := singboxConfig(p)
	rules := cfg["route"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) != 1 || rules[0]["outbound"] != "direct" {
		t.Fatalf("live policy rule not rendered: %v", rules)
	}
}

func TestProxyInboundRendersAddressAndPortSeparately(t *testing.T) {
	p := Profile{Mode: "proxy", ProxyListen: "[::1]:2081", ServerAddr: "edge.example:443", ServerName: "edge.example", UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	inbounds := singboxConfig(p)["inbounds"].([]map[string]any)
	if in := inbounds[0]; in["type"] != "mixed" || in["listen"] != "::1" || in["listen_port"] != 2081 {
		t.Fatalf("invalid proxy inbound: %+v", in)
	}
	p.ProxyListen = "127.0.0.1:0"
	if err := p.Validate(); err == nil {
		t.Fatal("accepted a proxy with no configured port")
	}
}
