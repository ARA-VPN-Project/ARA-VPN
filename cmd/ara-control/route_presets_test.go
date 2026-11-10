package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"aravpn/core/policy"
)

func TestTelegramPresetAddsNetworksToExistingDomainRule(t *testing.T) {
	existing := policy.Rule{ID: "preset-telegram-suffix", Enabled: true, DomainSuffix: []string{"telegram.org"}, Action: policy.ActionForeignPool}
	draft, err := addRoutePresets(policy.Policy{SchemaVersion: 1, Rules: []policy.Rule{existing}}, []string{"telegram"})
	if err != nil {
		t.Fatal(err)
	}
	rules := draft.Candidate.Rules
	if len(rules) != 3 || rules[0].ID != existing.ID || len(rules[0].DomainSuffix) != 1 || rules[1].ID != "preset-telegram-cidr" ||
		rules[1].Action != policy.ActionForeignPool || len(rules[1].CIDR) != 14 {
		t.Fatalf("unexpected Telegram rules: %+v", rules)
	}
	for _, addr := range []string{"149.154.167.50", "2001:b28:f23d::1"} {
		if !rules[1].Match(policy.Destination{IP: netip.MustParseAddr(addr)}).Matched {
			t.Errorf("Telegram IP without a hostname did not match: %s", addr)
		}
	}
	if rules[1].Match(policy.Destination{IP: netip.MustParseAddr("149.154.176.1")}).Matched {
		t.Fatal("neighboring address matched Telegram networks")
	}
	if !rules[2].Match(policy.Destination{Domain: "cdn-telegram.org"}).Matched {
		t.Fatal("extended Telegram domains did not match")
	}
}

func TestRoutePresetExamplesMatch(t *testing.T) {
	seen := map[string]bool{}
	for _, preset := range routePresets {
		if seen[preset.ID] {
			t.Fatalf("duplicate preset %s", preset.ID)
		}
		seen[preset.ID] = true
		draft, err := addRoutePresets(policy.Policy{SchemaVersion: 1}, []string{preset.ID})
		if err != nil {
			t.Fatalf("%s: %v", preset.ID, err)
		}
		if len(draft.Candidate.Rules) == 0 {
			t.Fatalf("%s has no rules", preset.ID)
		}
		for _, host := range preset.Examples {
			matched := false
			for _, rule := range draft.Candidate.Rules {
				matched = matched || rule.Match(policy.Destination{Domain: host}).Matched
			}
			if !matched {
				t.Errorf("%s does not match its example %s", preset.ID, host)
			}
		}
	}
}

func TestPresetsPreserveManualRulesAndSeparateSharedHosts(t *testing.T) {
	existing := policy.Policy{SchemaVersion: 1, Revision: 3, AllowRUFallback: true, Rules: []policy.Rule{
		{ID: "operator", Enabled: true, DomainExact: []string{"chatgpt.com"}, Action: policy.ActionBlock},
	}}
	draft, err := addRoutePresets(existing, []string{"openai", "apple"})
	if err != nil {
		t.Fatal(err)
	}
	rules := draft.Candidate.Rules
	if len(existing.Rules) != 1 || rules[0].ID != "operator" ||
		draft.Candidate.Revision != 3 || !draft.Candidate.AllowRUFallback {
		t.Fatalf("unexpected merge: %+v", draft)
	}
	assertPresetRoute(t, draft.Candidate, "auth.openai.com", policy.ActionForeignPool)
	assertPresetRoute(t, draft.Candidate, "setup.workos.com", policy.ActionForeignPool)
	assertPresetRoute(t, draft.Candidate, "another.workos.com", "")
	assertPresetRoute(t, draft.Candidate, "apple-pay-gateway.apple.com", policy.ActionForeignPool)
	again, err := addRoutePresets(draft.Candidate, []string{"apple", "openai"})
	if err != nil || len(again.Added) != 0 || len(again.Candidate.Rules) != len(rules) {
		t.Fatalf("repeated merge was not idempotent: %+v, %v", again, err)
	}
}

func TestExpandedCatalogKeepsExistingRulesAndExactHostsScoped(t *testing.T) {
	var selected []string
	for _, preset := range routePresets {
		if slices.Contains(strings.Fields(preset.Pack), "attachment") {
			selected = append(selected, preset.ID)
		}
	}
	current := policy.Policy{SchemaVersion: 1, Rules: []policy.Rule{{
		ID: "preset-google-suffix", Enabled: false, DomainSuffix: []string{"google.com"}, Action: policy.ActionForeignPool,
	}}}
	draft, err := addRoutePresets(current, selected)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Candidate.Rules[0].Enabled || !slices.Equal(draft.Candidate.Rules[0].DomainSuffix, current.Rules[0].DomainSuffix) {
		t.Fatal("modified existing Google rule was overwritten")
	}
	assertPresetRoute(t, draft.Candidate, "music.apple.com", policy.ActionForeignPool)
	assertPresetRoute(t, draft.Candidate, "edge.musickit.net", policy.ActionForeignPool)
	assertPresetRoute(t, draft.Candidate, "gmail.com", policy.ActionForeignPool)
	assertPresetRoute(t, draft.Candidate, "github-cloud.s3.amazonaws.com", policy.ActionForeignPool)
	assertPresetRoute(t, draft.Candidate, "another-bucket.s3.amazonaws.com", "")
	assertPresetRoute(t, draft.Candidate, "chat.deepseek.com", "")
	assertPresetRoute(t, draft.Candidate, "kimi.ai", "")
}

func assertPresetRoute(t *testing.T, candidate policy.Policy, domain string, expected policy.Action) {
	t.Helper()
	var got policy.Action
	for _, rule := range candidate.Rules {
		if rule.Match(policy.Destination{Domain: domain}).Matched {
			got = rule.Action
			break
		}
	}
	if got != expected {
		t.Errorf("%s matched action %q, want %q", domain, got, expected)
	}
}
