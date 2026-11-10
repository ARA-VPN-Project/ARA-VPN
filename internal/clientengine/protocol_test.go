package clientengine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Client→Edge ingress protocol selection is modeled independently of any
// Edge→Exit transit choice; this build implements vless ingress only and
// must refuse others with the stable code (docs/TRANSPORT_PROFILES.md).
func TestProfileIngressProtocolGate(t *testing.T) {
	base := Profile{
		EnginePath: "/bin/true", ServerAddr: "10.60.0.1:443", ServerName: "edge.ara.lab",
		CAPath: "/tmp/ca.crt", UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		TUNName: "ara-tun", TUNAddr4: "10.99.0.1/30",
	}
	// empty protocol defaults to vless (legacy profiles keep working)
	p := base
	if err := p.Validate(); err != nil {
		t.Fatalf("legacy profile refused: %v", err)
	}
	if p.Protocol != "vless" {
		t.Fatalf("default protocol: %q", p.Protocol)
	}
	// explicit vless accepted
	p = base
	p.Protocol = "vless"
	if err := p.Validate(); err != nil {
		t.Fatalf("vless refused: %v", err)
	}
	// Edge→Exit transit protocols are NOT ingress protocols: refuse typed
	for _, proto := range []string{"trojan", "hysteria2", "reality-vision"} {
		p = base
		p.Protocol = proto
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_CAPABILITY") {
			t.Fatalf("ingress %q accepted: %v", proto, err)
		}
		if !strings.Contains(err.Error(), "separate setting") {
			t.Fatalf("refusal must not conflate hops: %v", err)
		}
	}
}

func TestSingboxConfigIngressShapes(t *testing.T) {
	p := Profile{
		EnginePath: "/bin/true", ServerAddr: "10.60.0.1:443", ServerName: "edge.ara.lab",
		CAPath: "/tmp/ca.crt", UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		TUNName: "ara-tun", TUNAddr4: "10.99.0.1/30", DNSServer: "10.71.1.1:53",
	}
	cfg := singboxConfig(p)
	b, _ := json.Marshal(cfg)
	s := string(b)
	if !strings.Contains(s, `"type":"vless"`) || !strings.Contains(s, `"uuid"`) {
		t.Fatalf("vless ingress outbound expected: %s", s)
	}
	if !strings.Contains(s, `"tunnel-dns"`) {
		t.Fatalf("dns expected: %s", s)
	}
	if strings.Contains(s, "password") {
		t.Fatalf("vless config must not carry password fields: %s", s)
	}
	// generated config file perms stay 0600 in the real Start path
	// (covered by lifecycle tests); here assert the rendered shape only.
	_ = os.WriteFile // keep imports minimal
	_ = filepath.Join
}

func TestSupportedIngressProtocolsAdvertisement(t *testing.T) {
	l := SupportedIngressProtocols()
	if len(l) != 1 || l[0] != "vless" {
		t.Fatalf("advertised ingress protocols: %v", l)
	}
}
