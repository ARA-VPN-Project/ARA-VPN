package transportprofile

import (
	"fmt"
	"net"
	"strconv"
)

// Renderer for the pinned sing-box engine (third_party.lock.json: 1.14.4).
// Output shapes mirror the lab-validated configs of
// tests/transport/transport_matrix.sh (vless/hysteria2) extended with the
// trojan schema (https://sing-box.sagernet.org/configuration/outbound/trojan/):
// server, server_port, password, tls. Engine-schema compatibility is a lab
// gate: render + `sing-box check` + traffic test, never a doc claim. No
// custom wire/crypto code lives here — sing-box remains the only crypto
// endpoint (docs/SECURITY.md).

// Credential holds the protocol credentials in memory only. It is never
// logged, never marshalled into profile JSON and only rendered into 0600
// engine configs.
type Credential struct {
	// UUID authenticates vless.
	UUID string
	// Password authenticates trojan and hysteria2.
	Password string
}

// Endpoint is the remote (server side) address of the hop.
type Endpoint struct {
	Host string
	Port int
}

// ParseEndpoint parses host:port.
func ParseEndpoint(addr string) (Endpoint, error) {
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return Endpoint{}, invalid("endpoint %q must be host:port", addr)
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port <= 0 || port > 65535 {
		return Endpoint{}, invalid("endpoint %q: bad port", addr)
	}
	return Endpoint{Host: h, Port: port}, nil
}

func (e Endpoint) validate() error {
	if e.Host == "" {
		return invalid("endpoint host is required")
	}
	if e.Port <= 0 || e.Port > 65535 {
		return invalid("endpoint port %d out of range", e.Port)
	}
	return nil
}

func credFor(p *Profile, c Credential) (string, error) {
	switch p.Protocol {
	case ProtocolVLESS:
		if c.UUID == "" {
			return "", invalid("profile %s: vless credential uuid is required", p.ID)
		}
		return c.UUID, nil
	case ProtocolTrojan, ProtocolHysteria2:
		if c.Password == "" {
			return "", invalid("profile %s: %s credential password is required", p.ID, p.Protocol)
		}
		return c.Password, nil
	}
	return "", invalid("profile %s: unknown protocol", p.ID)
}

// tlsOutboundMap renders the client-side TLS object. Insecure is
// deliberately absent: ARA never disables verification
// (docs/TRANSPORTS.md — no weakened TLS on fallback, ever).
func (t *TLS) tlsOutboundMap() map[string]any {
	m := map[string]any{"enabled": true, "server_name": t.ServerName}
	if t.CAPath != "" {
		m["certificate_path"] = t.CAPath
	}
	if len(t.ALPN) > 0 {
		m["alpn"] = t.ALPN
	}
	return m
}

// RenderOutbound renders the sing-box outbound object for the hop
// (client side: the per-exit transit adapter or the client engine).
func RenderOutbound(p *Profile, e Endpoint, cred Credential, tag string) (map[string]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := CheckSupported(p.Role, p.Protocol, p.Security); err != nil {
		return nil, err
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	secret, err := credFor(p, cred)
	if err != nil {
		return nil, err
	}
	ob := map[string]any{
		"type": string(p.Protocol), "tag": tag,
		"server": e.Host, "server_port": e.Port,
		"tls": p.TLS.tlsOutboundMap(),
	}
	switch p.Protocol {
	case ProtocolVLESS:
		ob["uuid"] = secret
	case ProtocolTrojan, ProtocolHysteria2:
		ob["password"] = secret
	}
	return ob, nil
}

// RenderInbound renders the sing-box inbound object for the server side
// of the hop (the exit engine terminating the protocol). certPath/keyPath
// is the server certificate issued by the hop CA.
func RenderInbound(p *Profile, e Endpoint, cred Credential, certPath, keyPath, tag string) (map[string]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := CheckSupported(p.Role, p.Protocol, p.Security); err != nil {
		return nil, err
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	if certPath == "" || keyPath == "" {
		return nil, invalid("profile %s: server certificate and key paths are required", p.ID)
	}
	secret, err := credFor(p, cred)
	if err != nil {
		return nil, err
	}
	var user map[string]any
	switch p.Protocol {
	case ProtocolVLESS:
		user = map[string]any{"uuid": secret}
	case ProtocolTrojan, ProtocolHysteria2:
		user = map[string]any{"password": secret}
	}
	in := map[string]any{
		"type": string(p.Protocol), "tag": tag,
		"listen": e.Host, "listen_port": e.Port,
		"users": []map[string]any{user},
		"tls": map[string]any{
			"enabled":          true,
			"certificate_path": certPath,
			"key_path":         keyPath,
		},
	}
	if sni := p.TLS.ServerName; sni != "" {
		in["tls"].(map[string]any)["server_name"] = sni
	}
	return in, nil
}

// RenderExitServer renders the COMPLETE exit-side sing-box config for the
// hop: the protocol inbound terminating transit + a direct outbound. This
// is what `ara node transport render` writes for the exit host.
func RenderExitServer(p *Profile, e Endpoint, cred Credential, certPath, keyPath string) (map[string]any, error) {
	in, err := RenderInbound(p, e, cred, certPath, keyPath, "ti")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []map[string]any{in},
		"outbounds": []map[string]any{{"type": "direct"}},
	}, nil
}

// RenderExitAdapter renders the complete per-exit transit adapter config
// the edge host runs: SOCKS5 loopback inbound (ara-edge dials this,
// authenticated by the edge process boundary) → the profile's outbound.
// This is the ONLY supported way to add a transit protocol: ara-edge keeps
// every enforcement point (identity, policy, rate, quota, health) while
// sing-box owns the wire crypto (cmd/ara-edge main.go contract).
func RenderExitAdapter(p *Profile, e Endpoint, cred Credential, socksListen string, socksPort int) (map[string]any, error) {
	ob, err := RenderOutbound(p, e, cred, "exit-out")
	if err != nil {
		return nil, err
	}
	if socksPort <= 0 || socksPort > 65535 {
		return nil, invalid("socks port %d out of range", socksPort)
	}
	if socksListen == "" {
		return nil, invalid("socks listen host is required")
	}
	return map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []map[string]any{{"type": "socks", "tag": "exit-in", "listen": socksListen, "listen_port": socksPort}},
		"outbounds": []map[string]any{ob},
		"route":     map[string]any{"final": "exit-out"},
	}, nil
}

// Description is the stable one-line summary for status/audit (no secrets).
func (p *Profile) Description() string {
	return fmt.Sprintf("%s+%s/%s", p.Protocol, p.Security, p.Transport)
}
