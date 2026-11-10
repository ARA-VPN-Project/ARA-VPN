package controlstore

import (
	"path/filepath"
	"strings"
	"testing"

	"aravpn/core/transportprofile"
)

func openWithNodes(t *testing.T) *Store {
	t.Helper()
	s := openTest(t)
	for _, n := range []struct{ id, country, role string }{
		{"edge-ru", "RU", "ru"},
		{"exit-ru", "RU", "ru"},
		{"foreign-a", "NL", "foreign"},
	} {
		if _, err := s.AddNode(n.id, n.country, n.role, 10); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func trojanProfile(nodeID string) *transportprofile.Profile {
	return &transportprofile.Profile{
		NodeID: nodeID, Role: transportprofile.RoleTransit,
		Protocol: transportprofile.ProtocolTrojan, Transport: transportprofile.TransportTCP,
		Security: transportprofile.SecurityTLS,
		TLS:      &transportprofile.TLS{ServerName: "edge.ara.lab", CAPath: "/etc/ara/ca.crt"},
	}
}

func TestTransportProfileLifecycle(t *testing.T) {
	s := openWithNodes(t)
	p, err := s.AddTransportProfile(trojanProfile("foreign-a"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if p.CredentialRef != TransitSecretRef(p.ID) {
		t.Fatalf("credential ref not derived: %q", p.CredentialRef)
	}
	if v, err := s.SchemaVersion(); err != nil || v < 2 {
		t.Fatalf("schema version after migration: %d %v", v, err)
	}
	// unknown node refused
	if _, err := s.AddTransportProfile(trojanProfile("nope")); err == nil ||
		!strings.HasPrefix(err.Error(), "VALIDATION_FAILED") && !strings.Contains(err.Error(), "nope") {
		t.Fatalf("unknown node accepted: %v", err)
	}
	// REALITY refused by the typed capability rule
	reality := trojanProfile("foreign-a")
	reality.Security = transportprofile.SecurityREALITY
	if _, err := s.AddTransportProfile(reality); err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_CAPABILITY") {
		t.Fatalf("reality profile accepted: %v", err)
	}
	// list filters by node
	if ps, _ := s.ListTransportProfiles("foreign-a"); len(ps) != 1 {
		t.Fatalf("list by node: %d", len(ps))
	}
	if ps, _ := s.ListTransportProfiles(""); len(ps) != 1 {
		t.Fatalf("list all: %d", len(ps))
	}
	// roundtrip keeps typed fields
	got, err := s.GetTransportProfile(p.ID)
	if err != nil || got.Protocol != transportprofile.ProtocolTrojan || got.TLS.ServerName != "edge.ara.lab" {
		t.Fatalf("roundtrip: %v %+v", err, got)
	}
	if err := s.RevokeTransportProfile(p.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.RevokeTransportProfile(p.ID); err == nil {
		t.Fatal("double revoke accepted")
	}
}

func TestSecretsStoredButNeverInProfiles(t *testing.T) {
	s := openWithNodes(t)
	p, _ := s.AddTransportProfile(trojanProfile("foreign-a"))
	if err := s.SetTransitSecret(p.ID, "trojan-password-value"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	got, err := s.TransitSecret(p.ID)
	if err != nil || got != "trojan-password-value" {
		t.Fatalf("secret roundtrip: %q %v", got, err)
	}
	// rotation replaces the value
	if err := s.SetTransitSecret(p.ID, "rotated"); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if v, _ := s.TransitSecret(p.ID); v != "rotated" {
		t.Fatalf("rotation failed: %q", v)
	}
	// profile listing never carries the value
	ps, _ := s.ListTransportProfiles("")
	for _, pr := range ps {
		if strings.Contains(pr.CredentialRef, "rotated") {
			t.Fatal("secret value leaked into credential_ref")
		}
	}
	// a secret may be staged before its profile row exists (plan-time
	// staging); resolution without a staged value stays a typed error
	if err := s.SetTransitSecret("tp-staged", "x"); err != nil {
		t.Fatalf("plan-time staging refused: %v", err)
	}
	if _, err := s.TransitSecret("tp-absent"); err == nil ||
		!strings.HasPrefix(err.Error(), "VALIDATION_FAILED") {
		t.Fatalf("missing secret must be typed: %v", err)
	}
}

func TestLinkProfileValidation(t *testing.T) {
	s := openWithNodes(t)
	tj, _ := s.AddTransportProfile(trojanProfile("foreign-a"))
	_ = s.SetTransitSecret(tj.ID, "pw")
	hy := trojanProfile("foreign-a")
	hy.Protocol = transportprofile.ProtocolHysteria2
	hy.Transport = transportprofile.TransportUDP
	hp, _ := s.AddTransportProfile(hy)
	_ = s.SetTransitSecret(hp.ID, "pw2")

	// legacy tcp link without a profile is the documented VLESS+TLS default
	l, err := s.AddLink("edge-ru", "foreign-a", "tcp", 1, nil)
	if err != nil || l.ProfileID != nil {
		t.Fatalf("legacy tcp link: %v %+v", err, l)
	}
	// udp without profile refused — credentials are never guessed
	if _, err := s.AddLink("edge-ru", "foreign-a", "udp", 2, nil); err == nil ||
		!strings.Contains(err.Error(), "hysteria2") {
		t.Fatalf("udp link without profile accepted: %v", err)
	}
	// udp with the hysteria2 profile works
	ul, err := s.AddLink("edge-ru", "foreign-a", "udp", 2, &hp.ID)
	if err != nil {
		t.Fatalf("udp link with profile: %v", err)
	}
	// protocol switch on the same tcp link: trojan profile
	if _, err := s.SetLinkProfile(l.ID, &tj.ID); err != nil {
		t.Fatalf("set profile: %v", err)
	}
	got, _ := s.GetLink(l.ID)
	if got.ProfileID == nil || *got.ProfileID != tj.ID {
		t.Fatalf("profile not switched: %+v", got)
	}
	// mismatched transport refused (trojan profile is tcp)
	if _, err := s.SetLinkProfile(ul.ID, &tj.ID); err == nil {
		t.Fatal("udp link accepted a tcp profile")
	}
	// foreign node profile refused
	other := trojanProfile("exit-ru")
	op, _ := s.AddTransportProfile(other)
	if _, err := s.SetLinkProfile(l.ID, &op.ID); err == nil ||
		!strings.Contains(err.Error(), "belongs to node") {
		t.Fatalf("cross-node profile accepted: %v", err)
	}
	// revoked profile refused
	_ = s.RevokeTransportProfile(tj.ID)
	if _, err := s.SetLinkProfile(l.ID, &tj.ID); err == nil {
		t.Fatal("revoked profile accepted")
	}
}

func TestLegacyDBMigratesAdditively(t *testing.T) {
	// an existing database must survive reopen: the v2 migration is
	// additive and idempotent, previously stored links stay readable
	dbPath := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []struct{ id, country, role string }{
		{"edge-ru", "RU", "ru"}, {"foreign-a", "NL", "foreign"},
	} {
		if _, err := s.AddNode(n.id, n.country, n.role, 10); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.AddLink("edge-ru", "foreign-a", "tcp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if v, err := s2.SchemaVersion(); err != nil || v < 2 {
		t.Fatalf("reopened version: %d %v", v, err)
	}
	links, err := s2.ListLinks()
	if err != nil || len(links) != 1 || links[0].ID != l.ID || links[0].ProfileID != nil {
		t.Fatalf("links after reopen: %v %+v", err, links)
	}
	// the migrated link keeps the documented legacy meaning: tcp with no
	// profile renders the historical VLESS+TLS transit
	// (docs/TRANSPORT_PROFILES.md); no profile row was guessed into
	// existence
	ps, _ := s2.ListTransportProfiles("")
	if len(ps) != 0 {
		t.Fatalf("migration must not invent profiles: %+v", ps)
	}
}
