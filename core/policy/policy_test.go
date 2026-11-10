package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustCanonical(t *testing.T, s string) string {
	t.Helper()
	c, err := CanonicalDomain(s)
	if err != nil {
		t.Fatalf("CanonicalDomain(%q): %v", s, err)
	}
	return c
}

func TestCanonicalDomain(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"EXAMPLE.RU.", "example.ru", false},
		{"Пример.РФ", "xn--e1afmkfd.xn--p1ai", false},
		{"Bücher.Example.COM", "xn--bcher-kva.example.com", false},
		{"a.example.ru", "a.example.ru", false},
		{"*.example.ru", "", true},
		{"example.ru/parse", "", true},
		{"example.ru:443", "", true},
		{"", "", true},
		{"bad_domain.example", "", true}, // underscore rejected by IDNA lookup profile
		{"xn--bad.example", "", true},    // invalid punycode label
	}
	for _, c := range cases {
		got, err := CanonicalDomain(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("CanonicalDomain(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("CanonicalDomain(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("CanonicalDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchesSuffixLabelBoundary(t *testing.T) {
	cases := []struct {
		host, suffix string
		want         bool
	}{
		{"example.ru", "example.ru", true},
		{"a.example.ru", "example.ru", true},
		{"badexample.ru", "example.ru", false},
		{"example.ru.evil.test", "example.ru", false},
		{"ru", "example.ru", false},
		{"deep.a.example.ru", "a.example.ru", true},
	}
	for _, c := range cases {
		if got := MatchesSuffix(c.host, c.suffix); got != c.want {
			t.Errorf("MatchesSuffix(%q,%q)=%v want %v", c.host, c.suffix, got, c.want)
		}
	}
}

func testPolicy() *Policy {
	yes := true
	return &Policy{
		SchemaVersion:   1,
		Revision:        3,
		AllowRUFallback: true,
		Rules: []Rule{
			{ID: "r1", Enabled: true, DomainExact: []string{"local.example"}, Action: ActionRUExit},
			{ID: "r2", Enabled: true, DomainSuffix: []string{"media.example"}, Action: ActionForeignPool},
			{ID: "r3", Enabled: true, DomainExact: []string{"blocked.example"}, Action: ActionBlock},
			{ID: "r4", Enabled: true, DomainSuffix: []string{"gov.ru"}, CIDR: []string{"203.0.113.0/24"}, Proto: ProtoTCP, Ports: []PortRange{{443, 443}}, Action: ActionRUExit},
			{ID: "r5", Enabled: false, DomainExact: []string{"disabled.example"}, Action: ActionRUExit},
			{ID: "r6", Enabled: true, DomainSuffix: []string{"strict.example"}, Action: ActionForeignPool, AllowRUFallback: &yes},
		},
	}
}

func TestEvaluateFirstMatchAndOrAnd(t *testing.T) {
	p := testPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// exact match, first-match wins over later rules
	ev := p.Evaluate(Destination{Domain: "local.example", Proto: ProtoTCP, Port: 443})
	if ev.Action != ActionRUExit || ev.MatchedRuleID != "r1" {
		t.Errorf("local.example: got %+v", ev)
	}
	// suffix matches subdomains only on label boundary
	if ev := p.Evaluate(Destination{Domain: "cdn.media.example"}); ev.MatchedRuleID != "r2" {
		t.Errorf("cdn.media.example: got %+v", ev)
	}
	if ev := p.Evaluate(Destination{Domain: "badmedia.example"}); ev.MatchedRuleID != "" || ev.Action != ActionForeignPool {
		t.Errorf("badmedia.example: got %+v (want default foreign)", ev)
	}
	// disabled rule is skipped
	if ev := p.Evaluate(Destination{Domain: "disabled.example"}); ev.MatchedRuleID != "" {
		t.Errorf("disabled.example: got %+v", ev)
	}
	// AND across types: r4 requires domain AND cidr AND proto AND port together
	d := Destination{Domain: "www.gov.ru", IP: netip.MustParseAddr("203.0.113.7"), Proto: ProtoTCP, Port: 443}
	if ev := p.Evaluate(d); ev.MatchedRuleID != "r4" {
		t.Errorf("gov.ru full match: got %+v", ev)
	}
	d.Domain = "other.example"
	if ev := p.Evaluate(d); ev.MatchedRuleID == "r4" {
		t.Errorf("cidr matched without domain condition: %+v", ev)
	}
	d.Domain = "www.gov.ru"
	d.Port = 8080
	if ev := p.Evaluate(d); ev.MatchedRuleID == "r4" {
		t.Errorf("matched outside port range: %+v", ev)
	}
	// domain unknown => domain rules cannot match; CIDR-only rule can
	ipOnly := Destination{IP: netip.MustParseAddr("203.0.113.9"), Proto: ProtoTCP, Port: 443}
	if ev := p.Evaluate(ipOnly); ev.MatchedRuleID != "" {
		t.Errorf("ip-only destination matched domain rule: %+v", ev)
	}
	// rule-level strict override resolves against profile default
	ev = p.Evaluate(Destination{Domain: "x.strict.example"})
	if ev.MatchedRuleID != "r6" || !ev.AllowRUFallback {
		t.Errorf("strict.example: got %+v", ev)
	}
}

func TestValidateRejectsWholeDocument(t *testing.T) {
	p := testPolicy()
	p.Rules = append(p.Rules, Rule{ID: "bad", Enabled: true, DomainExact: []string{"BAD Example."}, Action: ActionRUExit})
	if err := p.Validate(); err == nil {
		t.Fatal("non-canonical domain accepted")
	}
	if !strings.Contains(errString(p.Validate()), "bad") {
		t.Logf("error: %v", p.Validate())
	}

	p2 := testPolicy()
	p2.SchemaVersion = 99
	if err := p2.Validate(); err == nil || !strings.Contains(errString(err), "schema_version") {
		t.Errorf("schema_version mismatch not rejected: %v", err)
	}

	p3 := testPolicy()
	p3.Rules = append(p3.Rules, Rule{ID: "dup", Enabled: true, DomainExact: []string{"a.example"}, Action: ActionBlock},
		Rule{ID: "dup", Enabled: true, DomainExact: []string{"b.example"}, Action: ActionBlock})
	if err := p3.Validate(); err == nil || !strings.Contains(errString(err), "duplicate") {
		t.Errorf("duplicate id not rejected: %v", err)
	}

	p4 := testPolicy()
	p4.Rules = append(p4.Rules, Rule{ID: "catchall", Enabled: true, Action: ActionBlock})
	if err := p4.Validate(); err == nil {
		t.Error("rule without conditions accepted; catch-all must be the default action")
	}

	// non-canonical CIDR (host bits set) must be rejected
	p5 := testPolicy()
	p5.Rules[0].CIDR = []string{"203.0.113.7/24"}
	if err := p5.Validate(); err == nil {
		t.Error("CIDR with host bits accepted")
	}
}

func TestStoreCASAndLKG(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	def, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if def.Revision != 0 || !def.AllowRUFallback || len(def.Rules) != 0 {
		t.Fatalf("default policy wrong: %+v", def)
	}

	good := testPolicy()
	applied, err := s.ValidateAndApplyIdentity(good, 0, "test-plan", "test-idem")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied.Revision != 1 {
		t.Fatalf("revision after apply = %d, want 1", applied.Revision)
	}

	// stale writer with expected revision 0 must be rejected
	if _, err := s.ValidateAndApplyIdentity(testPolicy(), 0, "stale-plan", "stale-idem"); err == nil || !strings.Contains(errString(err), "CONFLICT") {
		t.Fatalf("stale CAS accepted: %v", err)
	}

	// invalid candidate must not touch active or LKG
	bad := testPolicy()
	bad.Rules[0].Action = "SOMETHING"
	if _, err := s.ValidateAndApplyIdentity(bad, 1, "bad-plan", "bad-idem"); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	cur, _ := s.Load()
	if cur.Revision != 1 {
		t.Fatalf("failed apply changed revision: %d", cur.Revision)
	}
	lkg, _ := s.LoadLKG()
	if lkg.Revision != 1 {
		t.Fatalf("lkg changed by failed apply: %d", lkg.Revision)
	}

	// file permissions must stay private (policy contains site lists)
	info, err := os.Stat(filepath.Join(dir, "state", "policy.current.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("policy file mode = %o, want 600", perm)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
