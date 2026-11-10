package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aravpn/core/transportprofile"
	"aravpn/internal/controlstore"
)

func transitTestService(t *testing.T) *Service {
	t.Helper()
	svc := newTestService(t)
	st, err := svc.OpenControlStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, n := range []struct{ id, country, role string }{
		{"edge-ru", "RU", "ru"}, {"foreign-a", "NL", "foreign"}, {"foreign-b", "DE", "foreign"},
	} {
		if _, err := st.AddNode(n.id, n.country, n.role, 10); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.AddLink("edge-ru", "foreign-a", "tcp", 1, nil); err != nil {
		t.Fatal(err)
	}
	return svc
}

func testEndpoint() transportprofile.Endpoint {
	return transportprofile.Endpoint{Host: "10.62.0.2", Port: 443}
}

func tlsParams() transportprofile.TLS {
	return transportprofile.TLS{ServerName: "edge.ara.lab", CAPath: "/etc/ara/ca.crt"}
}

func mustLink(t *testing.T, st *controlstore.Store, edge, exit string) *controlstore.Link {
	t.Helper()
	l, err := st.FindLink(edge, exit)
	if err != nil || l == nil {
		t.Fatalf("link %s→%s: %v", edge, exit, err)
	}
	return l
}

func mustProfile(t *testing.T, st *controlstore.Store, node, protocol string) *controlstore.TransportProfile {
	t.Helper()
	ps, err := st.ListTransportProfiles(node)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ps {
		if string(ps[i].Protocol) == protocol {
			return &ps[i]
		}
	}
	t.Fatalf("no %s profile on %s", protocol, node)
	return nil
}

func TestTransitProfilePlanApplyRollback(t *testing.T) {
	svc := transitTestService(t)
	now := time.Now().UTC()
	p, hash, err := svc.TransitPlanAddProfile(TransitProfileInput{
		NodeID: "foreign-a", Protocol: "trojan", Security: "tls",
		TLS:    tlsParams(),
		Secret: "trojan-secret-value",
	}, now)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	pb, _ := json.Marshal(p)
	if strings.Contains(string(pb), "trojan-secret-value") {
		t.Fatal("secret leaked into plan JSON")
	}
	if _, err := svc.TransitApply(p.ID, hash); err != nil {
		t.Fatalf("apply: %v", err)
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ps, _ := st.ListTransportProfiles("foreign-a")
	if len(ps) != 1 || ps[0].Protocol != transportprofile.ProtocolTrojan {
		t.Fatalf("profile not applied: %+v", ps)
	}
	if v, _ := st.TransitSecret(ps[0].ID); v != "trojan-secret-value" {
		t.Fatalf("secret not staged: %q", v)
	}
	// switch the link to the trojan profile
	link := mustLink(t, st, "edge-ru", "foreign-a")
	if link == nil {
		t.Fatal("fixture link missing")
	}
	p2, hash2, err := svc.TransitPlanSetLinkProfile(link.ID, ps[0].ID, now)
	if err != nil {
		t.Fatalf("link plan: %v", err)
	}
	if _, err := svc.TransitApply(p2.ID, hash2); err != nil {
		t.Fatalf("link apply: %v", err)
	}
	got, _ := st.GetLink(link.ID)
	if got.ProfileID == nil || *got.ProfileID != ps[0].ID {
		t.Fatalf("link profile not switched: %+v", got)
	}
	// transport mismatch refused at PLAN time: hysteria2 (udp) on a tcp link
	ph, hashh, err := svc.TransitPlanAddProfile(TransitProfileInput{
		NodeID: "foreign-a", Protocol: "hysteria2", Security: "tls",
		TLS: tlsParams(), Secret: "hy2",
	}, now)
	if err != nil {
		t.Fatalf("hy2 plan: %v", err)
	}
	if _, err := svc.TransitApply(ph.ID, hashh); err != nil {
		t.Fatalf("hy2 apply: %v", err)
	}
	hy := mustProfile(t, st, "foreign-a", "hysteria2")
	if _, _, err := svc.TransitPlanSetLinkProfile(link.ID, hy.ID, now); err == nil ||
		!strings.Contains(err.Error(), "VALIDATION_FAILED") {
		t.Fatalf("udp profile accepted on tcp link: %v", err)
	}
	// rollback the link switch: legacy default restored
	rb, err := svc.TransitRollback(p2.ID, now)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !rb.Applied {
		t.Fatalf("rollback not applied: %+v", rb)
	}
	after, _ := st.GetLink(link.ID)
	if after.ProfileID != nil {
		t.Fatalf("rollback did not restore legacy default: %+v", after)
	}
}

func TestTransitRenderUsesStoredCredential(t *testing.T) {
	svc := transitTestService(t)
	now := time.Now().UTC()
	p, hash, err := svc.TransitPlanAddProfile(TransitProfileInput{
		NodeID: "foreign-b", Protocol: "trojan", Security: "tls",
		TLS: tlsParams(), Secret: "render-check-password",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TransitApply(p.ID, hash); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.OpenControlStore()
	defer st.Close()
	if _, err := st.AddLink("edge-ru", "foreign-b", "tcp", 2, nil); err != nil {
		t.Fatal(err)
	}
	link := mustLink(t, st, "edge-ru", "foreign-b")
	prof := mustProfile(t, st, "foreign-b", "trojan")
	p2, hash2, err := svc.TransitPlanSetLinkProfile(link.ID, prof.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TransitApply(p2.ID, hash2); err != nil {
		t.Fatal(err)
	}
	adapter, inbound, err := svc.TransitRender(link.ID, testEndpoint(), "127.0.0.1", 1172, "/tmp/srv.crt", "/tmp/srv.key")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	ab, _ := json.Marshal(adapter)
	if !strings.Contains(string(ab), `"trojan"`) || !strings.Contains(string(ab), "render-check-password") {
		t.Fatalf("adapter must carry the resolved credential: %s", ab)
	}
	ib, _ := json.Marshal(inbound)
	if !strings.Contains(string(ib), `"/tmp/srv.crt"`) {
		t.Fatalf("inbound cert path: %s", ib)
	}
	// legacy (no profile) link refuses honestly: credentials are never guessed
	if _, err := st.AddLink("edge-ru", "foreign-a", "tcp", 1, nil); err != nil {
		t.Fatal(err)
	}
	legacy := mustLink(t, st, "edge-ru", "foreign-a")
	_, _, err = svc.TransitRender(legacy.ID, testEndpoint(), "127.0.0.1", 1173, "/tmp/s.crt", "/tmp/s.key")
	if err == nil || !strings.Contains(err.Error(), "VALIDATION_FAILED") || !strings.Contains(err.Error(), "never guessed") {
		t.Fatalf("legacy link render must refuse typed: %v", err)
	}
}

func TestTopologyDeclarativeIdempotent(t *testing.T) {
	svc := transitTestService(t)
	pwFile := filepath.Join(t.TempDir(), "trojan.pw")
	if err := os.WriteFile(pwFile, []byte("topology-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := &TopologyDoc{
		Nodes: []TopologyNodeDoc{
			{ID: "foreign-b", Country: "DE", Role: "foreign", Priority: 2},
			{ID: "foreign-c", Country: "NL", Role: "foreign", Priority: 3},
		},
		TransportProfiles: []TransportProfileDoc{
			{Ref: "foreign-b-trojan", NodeID: "foreign-b", Protocol: "trojan", Security: "tls",
				TLS: tlsParams(), PasswordFile: pwFile},
		},
		Links: []TopologyLinkDoc{
			{EdgeID: "edge-ru", ExitID: "foreign-b", Transport: "tcp", Priority: 2, ProfileRef: "foreign-b-trojan"},
		},
	}
	now := time.Now().UTC()
	p, hash, err := svc.TopologyPlan(doc, now)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	res, err := svc.TopologyApply(p.ID, hash)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var summary map[string]int
	if err := json.Unmarshal([]byte(res.Summary["changes"]), &summary); err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary["profiles_created"] != 1 || summary["links_created"] != 1 || summary["nodes_created"] != 1 {
		t.Fatalf("first apply summary: %v", summary)
	}
	// idempotent second apply: nothing new
	p2, hash2, err := svc.TopologyPlan(doc, now)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := svc.TopologyApply(p2.ID, hash2)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	var s2 map[string]int
	_ = json.Unmarshal([]byte(res2.Summary["changes"]), &s2)
	if s2["profiles_created"] != 0 || s2["links_created"] != 0 || s2["nodes_created"] != 0 {
		t.Fatalf("second apply must create nothing: %v", s2)
	}
	st, _ := svc.OpenControlStore()
	defer st.Close()
	if _, err := st.GetTransportProfile(DocProfileID("foreign-b-trojan")); err != nil {
		t.Fatalf("stable profile id: %v", err)
	}
	if v, _ := st.TransitSecret(DocProfileID("foreign-b-trojan")); v != "topology-password" {
		t.Fatalf("password file resolution: %q", v)
	}
}

func TestTopologyRefusesInlineSecrets(t *testing.T) {
	svc := transitTestService(t)
	doc := &TopologyDoc{
		TransportProfiles: []TransportProfileDoc{{
			Ref: "x", NodeID: "foreign-a", Protocol: "trojan",
			TLS: tlsParams(),
		}},
	}
	if _, _, err := svc.TopologyPlan(doc, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "password_file|password_env") {
		t.Fatalf("doc without credential source accepted: %v", err)
	}
	doc2 := &TopologyDoc{Links: []TopologyLinkDoc{{EdgeID: "edge-ru", ExitID: "foreign-a", ProfileRef: "missing"}}}
	if _, _, err := svc.TopologyPlan(doc2, time.Now()); err == nil {
		t.Fatal("unknown profile_ref accepted")
	}
}

func TestTransitCapabilitiesAdvertisement(t *testing.T) {
	caps := TransitCapabilities()
	b, _ := json.Marshal(caps)
	s := string(b)
	if !strings.Contains(s, `"trojan"`) || !strings.Contains(s, "reality") {
		t.Fatalf("capabilities: %s", s)
	}
}
