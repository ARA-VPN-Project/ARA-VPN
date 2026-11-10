package transportprofile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func trojanProfile() *Profile {
	return &Profile{
		ID: "tp-1", NodeID: "foreign-a", Role: RoleTransit,
		Protocol: ProtocolTrojan, Transport: TransportTCP, Security: SecurityTLS,
		TLS:           &TLS{ServerName: "edge.ara.lab", CAPath: "/etc/ara/ca.crt"},
		CredentialRef: "arasec://transit/tp-1",
	}
}

func TestValidateTransitProtocols(t *testing.T) {
	for _, tc := range []struct {
		p *Profile
	}{
		{trojanProfile()},
		{func() *Profile { p := trojanProfile(); p.Protocol = ProtocolVLESS; p.CredentialRef = "arasec://transit/tp-vless"; return p }()},
		{func() *Profile { p := trojanProfile(); p.Protocol = ProtocolHysteria2; p.Transport = TransportUDP; p.CredentialRef = "arasec://transit/tp-hy2"; return p }()},
	} {
		if err := tc.p.Validate(); err != nil {
			t.Fatalf("profile %s refused: %v", tc.p.Protocol, err)
		}
	}
}

func TestValidateTransportMismatch(t *testing.T) {
	p := trojanProfile()
	p.Transport = TransportUDP
	err := p.Validate()
	if !isValidation(err) {
		t.Fatalf("trojan over udp must be a validation error, got %v", err)
	}
	p2 := trojanProfile()
	p2.Protocol = ProtocolHysteria2
	p2.Transport = TransportTCP
	if err := p2.Validate(); !isValidation(err) {
		t.Fatalf("hysteria2 over tcp must be a validation error, got %v", err)
	}
}

func TestValidateSecurityRequirements(t *testing.T) {
	p := trojanProfile()
	p.Security = ""
	if err := p.Validate(); !isValidation(err) {
		t.Fatalf("missing security must be rejected: %v", err)
	}
	p2 := trojanProfile()
	p2.Security = SecurityREALITY
	err := p2.Validate()
	var ue *UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("REALITY must be typed UNSUPPORTED_CAPABILITY, got %v", err)
	}
	if !strings.Contains(err.Error(), "UNSUPPORTED_CAPABILITY") {
		t.Fatalf("error must carry the stable code: %v", err)
	}
	p3 := trojanProfile()
	p3.TLS.Flow = "xtls-rprx-vision"
	if err := p3.Validate(); !errors.As(err, &ue) {
		t.Fatalf("flow without REALITY must be unsupported, got %v", err)
	}
	p4 := trojanProfile()
	p4.TLS = nil
	if err := p4.Validate(); !isValidation(err) {
		t.Fatalf("tls security without tls params must be rejected: %v", err)
	}
}

func TestValidateCredentialRef(t *testing.T) {
	p := trojanProfile()
	p.CredentialRef = "supersecret123"
	if err := p.Validate(); !isValidation(err) {
		t.Fatalf("plaintext credential must be rejected: %v", err)
	}
	if err := ValidateCredentialRef(""); !isValidation(err) {
		t.Fatalf("empty ref must be rejected")
	}
	if err := ValidateCredentialRef("arasec://transit/tp-1"); err != nil {
		t.Fatalf("valid ref refused: %v", err)
	}
}

func TestSupportedMatrix(t *testing.T) {
	if !Supported(RoleTransit, ProtocolVLESS, SecurityTLS) ||
		!Supported(RoleTransit, ProtocolTrojan, SecurityTLS) ||
		!Supported(RoleTransit, ProtocolHysteria2, SecurityTLS) {
		t.Fatal("transit profiles must be supported")
	}
	if !Supported(RoleIngress, ProtocolVLESS, SecurityTLS) {
		t.Fatal("vless ingress must be supported")
	}
	for _, proto := range []Protocol{ProtocolTrojan, ProtocolHysteria2} {
		if Supported(RoleIngress, proto, SecurityTLS) {
			t.Fatalf("%s ingress must NOT be advertised as supported", proto)
		}
		err := CheckSupported(RoleIngress, proto, SecurityTLS)
		if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_CAPABILITY") {
			t.Fatalf("ingress %s must fail typed: %v", proto, err)
		}
	}
	if Supported(RoleTransit, ProtocolTrojan, SecurityREALITY) {
		t.Fatal("reality must not be supported anywhere yet")
	}
}

func TestRenderOutboundShapes(t *testing.T) {
	// trojan
	ob, err := RenderOutbound(trojanProfile(), Endpoint{Host: "10.62.0.2", Port: 443},
		Credential{Password: "pw"}, "exit-out")
	if err != nil {
		t.Fatalf("trojan render: %v", err)
	}
	if ob["type"] != "trojan" || ob["password"] != "pw" || ob["server"] != "10.62.0.2" || ob["server_port"] != 443 {
		t.Fatalf("trojan outbound wrong: %v", ob)
	}
	tlsm := ob["tls"].(map[string]any)
	if tlsm["enabled"] != true || tlsm["server_name"] != "edge.ara.lab" || tlsm["certificate_path"] != "/etc/ara/ca.crt" {
		t.Fatalf("trojan tls wrong: %v", tlsm)
	}
	if _, has := tlsm["insecure"]; has {
		t.Fatal("insecure must never be rendered")
	}
	// vless
	vp := trojanProfile()
	vp.Protocol = ProtocolVLESS
	ob, err = RenderOutbound(vp, Endpoint{Host: "10.61.0.2", Port: 443}, Credential{UUID: "aaaa-bbbb"}, "exit-out")
	if err != nil {
		t.Fatalf("vless render: %v", err)
	}
	if ob["uuid"] != "aaaa-bbbb" || ob["type"] != "vless" {
		t.Fatalf("vless outbound wrong: %v", ob)
	}
	if _, has := ob["password"]; has {
		t.Fatal("vless must not carry a password field")
	}
	// wrong credential kind
	if _, err := RenderOutbound(trojanProfile(), Endpoint{Host: "h", Port: 1}, Credential{UUID: "x"}, "t"); !isValidation(err) {
		t.Fatalf("trojan with uuid-only credential must be rejected: %v", err)
	}
	// ingress refusal at render time
	ip := trojanProfile()
	ip.Role = RoleIngress
	_, err = RenderOutbound(ip, Endpoint{Host: "h", Port: 1}, Credential{Password: "x"}, "t")
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_CAPABILITY") {
		t.Fatalf("ingress trojan render must be refused: %v", err)
	}
}

func TestRenderInboundShape(t *testing.T) {
	in, err := RenderInbound(trojanProfile(), Endpoint{Host: "10.62.0.2", Port: 443},
		Credential{Password: "pw"}, "/ca/srv.crt", "/ca/srv.key", "ti")
	if err != nil {
		t.Fatalf("trojan inbound: %v", err)
	}
	users := in["users"].([]map[string]any)
	if users[0]["password"] != "pw" {
		t.Fatalf("inbound user wrong: %v", users)
	}
	tls := in["tls"].(map[string]any)
	if tls["certificate_path"] != "/ca/srv.crt" || tls["key_path"] != "/ca/srv.key" {
		t.Fatalf("inbound tls wrong: %v", tls)
	}
	if _, err := RenderInbound(trojanProfile(), Endpoint{Host: "h", Port: 443}, Credential{Password: "p"}, "", "k", "t"); !isValidation(err) {
		t.Fatalf("inbound without cert must be rejected: %v", err)
	}
}

func TestRenderExitAdapter(t *testing.T) {
	cfg, err := RenderExitAdapter(trojanProfile(), Endpoint{Host: "10.62.0.2", Port: 443},
		Credential{Password: "pw"}, "127.0.0.1", 1172)
	if err != nil {
		t.Fatalf("adapter render: %v", err)
	}
	b, _ := json.Marshal(cfg)
	s := string(b)
	if !strings.Contains(s, `"socks"`) || !strings.Contains(s, `"trojan"`) || !strings.Contains(s, "exit-out") {
		t.Fatalf("adapter shape wrong: %s", s)
	}
	if _, err := RenderExitAdapter(trojanProfile(), Endpoint{Host: "h", Port: 1}, Credential{Password: "p"}, "127.0.0.1", 0); !isValidation(err) {
		t.Fatalf("socks port 0 must be rejected: %v", err)
	}
}

func TestProfileJSONCarriesNoSecret(t *testing.T) {
	b, _ := json.Marshal(trojanProfile())
	s := string(b)
	if strings.Contains(s, "pw") || strings.Contains(s, "password") {
		t.Fatalf("profile JSON must not carry credential material: %s", s)
	}
	if !strings.Contains(s, "arasec://transit/tp-1") {
		t.Fatalf("credential_ref expected in profile JSON: %s", s)
	}
}

func isValidation(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(err.Error(), "VALIDATION_FAILED")
}
