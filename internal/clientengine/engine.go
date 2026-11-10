// Package clientengine owns the client data-plane engine process (the
// pinned transport engine) for the local agent: durable session record,
// strict process-ownership checks (PID + start time — a recycled PID is
// never signalled), bounded startup readiness wait and typed stop. It
// performs no shell and no arbitrary network work: one engine binary, one
// generated config, one TUN device (docs/SECURITY.md, docs/CLI_AUTOMATION.md).
package clientengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"aravpn/core/policy"
	"aravpn/core/transportprofile"
)

// Profile is one client connection profile (state/profiles/<name>.json).
// The UUID is a bearer secret: files are 0600 and it is never logged.
// Protocol is the Client→Edge ingress protocol and is configured
// INDEPENDENTLY of any Edge→Exit transit protocol (docs/TRANSPORT_PROFILES.md):
// only vless+TLS is implemented for ingress in this build — the edge
// terminates access identity itself; other values are refused with the
// stable UNSUPPORTED_CAPABILITY code instead of a silent downgrade.
type Profile struct {
	EnginePath string `json:"engine_path"` // pinned engine binary
	ServerAddr string `json:"server_addr"` // edge host:port
	ServerName string `json:"server_name"` // TLS SNI
	CAPath     string `json:"ca_path"`
	UUID       string `json:"uuid"`
	// Protocol: "" (legacy) and "vless" are equivalent; anything else is
	// rejected. Client→Edge and Edge→Exit choices never leak into each
	// other: this field describes the ingress hop only.
	Protocol  string `json:"protocol,omitempty"`
	TUNName   string `json:"tun_name"`
	TUNAddr4  string `json:"tun_addr4"`
	TUNAddr6  string `json:"tun_addr6,omitempty"`
	MTU       int    `json:"mtu"`
	DNSServer string `json:"dns_server,omitempty"` // resolved through the tunnel
	// WaitMode: "tun" polls for the TUN interface (production); "none"
	// returns after process start (tests with a stub engine).
	WaitMode string `json:"wait_mode,omitempty"`
	// Mode (B41): "tun" (default) renders the TUN inbound (needs
	// CAP_NET_ADMIN + /dev/net/tun); "proxy" renders a loopback mixed
	// HTTP/SOCKS inbound (ProxyListen) — explicitly configured applications
	// route through it, no privileged devices. An empty value means tun.
	Mode string `json:"mode,omitempty"`
	// ProxyListen is the mixed inbound address in proxy mode
	// (default 127.0.0.1:2080).
	ProxyListen string `json:"proxy_listen,omitempty"`
	// RouteRules (B39): verified client-side routing policy delivered to
	// the runtime — explicit DIRECT leaves the TUN unproxied, BLOCK is
	// refused; anything unmatched stays on the VPN outbound (final vo),
	// so an engine/Edge failure can never open a hidden DIRECT leak.
	RouteRules []ClientRouteRule `json:"route_rules,omitempty"`
}

// ClientRouteRule is one client-side route decision rendered into sing-box
// route rules IN POLICY ORDER (C03): "direct"/"block" map to their
// outbounds; "vpn" is an explicit BARRIER rule (outbound vo) — an earlier
// VPN decision must survive a later broader DIRECT, otherwise
// "secure.example→VPN; *.example→DIRECT" compiles into one wide DIRECT
// and opens a forbidden bypass. Multiple match fields in one rule are AND
// (sing-box semantics); lists inside one field are OR.
type ClientRouteRule struct {
	DomainExact  []string `json:"domain_exact,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	CIDR         []string `json:"cidr,omitempty"`
	Ports        []string `json:"ports,omitempty"` // sing-box port list, e.g. "443" or "1000-2000"
	// Proto constrains the rule ("tcp", "udp"); empty = both. A proto-only
	// match must survive compilation (C03): it never disappears and never
	// widens to cover the other transport.
	Proto  string `json:"proto,omitempty"`
	Action string `json:"action"` // direct | block | vpn
}

// RulesFromPolicy translates a verified client policy document into
// runtime route rules, preserving ORDER and every real decision: DIRECT,
// BLOCK and the explicit VPN barriers (RU_EXIT/FOREIGN_POOL). Disabled
// rules are skipped.
func RulesFromPolicy(p *policy.Policy) []ClientRouteRule {
	if p == nil {
		return nil
	}
	var out []ClientRouteRule
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}
		var action string
		switch r.Action {
		case policy.ActionDirect:
			action = "direct"
		case policy.ActionBlock:
			action = "block"
		case policy.ActionRUExit, policy.ActionForeignPool, policy.ActionForeignExit:
			action = "vpn" // explicit barrier: stop matching, stay on the tunnel
		default:
			continue // unknown action: final vo covers it; never widen
		}
		rr := ClientRouteRule{
			DomainExact:  append([]string{}, r.DomainExact...),
			DomainSuffix: append([]string{}, r.DomainSuffix...),
			CIDR:         append([]string{}, r.CIDR...),
			Proto:        string(r.Proto),
			Action:       action,
		}
		for _, pr := range r.Ports {
			if pr.To > pr.From {
				rr.Ports = append(rr.Ports, fmt.Sprintf("%d:%d", pr.From, pr.To))
			} else {
				rr.Ports = append(rr.Ports, fmt.Sprintf("%d", pr.From))
			}
		}
		if len(rr.DomainExact)+len(rr.DomainSuffix)+len(rr.CIDR)+len(rr.Ports) == 0 && rr.Proto == "" {
			continue // nothing to match on: never render a catch-all rule
		}
		out = append(out, rr)
	}
	return out
}

// SupportedIngressProtocols advertises the implemented Client→Edge
// protocols for enrollment, export and controller advertisement
// (docs/TRANSPORT_PROFILES.md). Hysteria2 appears in lab scripts as a
// transport experiment; it is deliberately NOT advertised here.
func SupportedIngressProtocols() []string { return []string{"vless"} }

func (p *Profile) Validate() error {
	// engine_path is launch-only (Start fails with a clear error when the
	// binary is missing) — subscription catalogs render configs without it
	if p.Mode == "" {
		p.Mode = "tun"
	}
	if p.Mode != "tun" && p.Mode != "proxy" {
		return errors.New("profile: mode must be tun|proxy")
	}
	if p.ServerAddr == "" || p.ServerName == "" || p.UUID == "" {
		return errors.New("profile: server_addr, server_name and uuid are required")
	}
	if p.Mode == "tun" && (p.TUNName == "" || p.TUNAddr4 == "") {
		return errors.New("profile: tun_name and tun_addr4 are required in tun mode")
	}
	if p.Mode == "proxy" {
		host, port, err := net.SplitHostPort(proxyListen(p.ProxyListen))
		num, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || num < 1 || num > 65535 || (net.ParseIP(host) == nil && host != "localhost") {
			return errors.New("profile: proxy_listen must be an IP address and a port")
		}
	}
	if p.Protocol == "" {
		p.Protocol = string(transportprofile.ProtocolVLESS)
	}
	if !transportprofile.Supported(transportprofile.RoleIngress,
		transportprofile.Protocol(p.Protocol), transportprofile.SecurityTLS) {
		return fmt.Errorf("UNSUPPORTED_CAPABILITY: client ingress protocol %q is not implemented in this build (supported: %s); the Edge→Exit transit protocol is a separate setting and does not change this value",
			p.Protocol, strings.Join(SupportedIngressProtocols(), ", "))
	}
	if p.MTU == 0 {
		p.MTU = 1400
	}
	if p.MTU < 576 || p.MTU > 65535 {
		return fmt.Errorf("profile: mtu %d out of range", p.MTU)
	}
	if p.WaitMode == "" {
		p.WaitMode = "tun"
	}
	if p.WaitMode != "tun" && p.WaitMode != "none" {
		return fmt.Errorf("profile: unknown wait_mode %q", p.WaitMode)
	}
	if _, _, err := net.SplitHostPort(p.ServerAddr); err != nil {
		return fmt.Errorf("profile: server_addr must be host:port: %w", err)
	}
	return nil
}

// session is the durable record of a running engine (session.json, 0600).
// StartTime jiffies pin the PID: a recycled PID is detected and never
// signalled (unknown-fence discipline).
type session struct {
	PID         int       `json:"pid"`
	StartTime   uint64    `json:"start_time"`
	TUNName     string    `json:"tun_name"`
	ProfileName string    `json:"profile_name"`
	Mode        string    `json:"mode,omitempty"`
	ProxyListen string    `json:"proxy_listen,omitempty"`
	StartedAt   time.Time `json:"started_at"`
}

// Engine manages the engine subprocess for one state directory.
type Engine struct {
	st Root
	mu sync.Mutex
	// policyProvider (B39) supplies the live client policy at connect time;
	// its DIRECT/BLOCK rules are merged over the profile's own rules so a
	// policy apply reaches the runtime without re-running setup. A provider
	// error aborts the connect: a silently missing routing policy is never
	// acceptable.
	policyProvider func() (*policy.Policy, error)
}

// Root is the on-disk layout the engine needs.
type Root struct {
	Dir string // state root
}

func (r Root) profilePath(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\.") {
		return "", fmt.Errorf("profile name %q is invalid", name)
	}
	return filepath.Join(r.Dir, "profiles", name+".json"), nil
}
func (r Root) profilesDir() string   { return filepath.Join(r.Dir, "profiles") }
func (r Root) sessionPath() string   { return filepath.Join(r.Dir, "engine", "session.json") }
func (r Root) configPath() string    { return filepath.Join(r.Dir, "engine", "client.json") }
func (r Root) engineLogPath() string { return filepath.Join(r.Dir, "engine", "engine.log") }

func New(root string) *Engine { return &Engine{st: Root{Dir: root}} }

// SetPolicyProvider wires the live client policy source (B39): at connect
// the provider's DIRECT/BLOCK rules are rendered into the engine config.
func (e *Engine) SetPolicyProvider(fn func() (*policy.Policy, error)) { e.policyProvider = fn }

// ErrNotConnected reports a stop/status with no live session.
var ErrNotConnected = errors.New("engine: not connected")

// ErrAlreadyConnected reports a start with a live session.
var ErrAlreadyConnected = errors.New("engine: already connected")

// StatusView is the factual engine state for status/doctor.
type StatusView struct {
	Running      bool      `json:"running"`
	PID          int       `json:"pid,omitempty"`
	ProfileName  string    `json:"profile_name,omitempty"`
	Mode         string    `json:"mode,omitempty"`
	ProxyListen  string    `json:"proxy_listen,omitempty"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	TUNPresent   bool      `json:"tun_present"`
	StaleCleaned bool      `json:"stale_cleaned,omitempty"`
}

// Start validates the profile, cleans a stale session, launches the
// engine and waits (bounded) for readiness.
func (e *Engine) Start(name string) (StatusView, error) {
	return e.StartMode(name, "")
}

// StartMode optionally overrides capture for this session only.
func (e *Engine) StartMode(name, mode string) (StatusView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	pp, err := e.st.profilePath(name)
	if err != nil {
		return StatusView{}, err
	}
	b, err := os.ReadFile(pp)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StatusView{}, fmt.Errorf("PROFILE_MISSING: profile %q is not configured", name)
		}
		return StatusView{}, fmt.Errorf("profile %s unreadable: %w", name, err)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return StatusView{}, fmt.Errorf("profile %s invalid: %w", name, err)
	}
	if mode != "" {
		p.Mode = mode
	}
	if err := p.Validate(); err != nil {
		return StatusView{}, err
	}
	// B39: merge the LIVE policy (provider wired by the agent) over the
	// profile's stored rules — a policy apply reaches the next connect
	// without re-running setup. Provider failure must not silently drop
	// the routing policy: it is a hard error.
	if e.policyProvider != nil {
		live, perr := e.policyProvider()
		if perr != nil {
			return StatusView{}, fmt.Errorf("client policy unavailable: %w", perr)
		}
		p.RouteRules = append(p.RouteRules, RulesFromPolicy(live)...)
	}
	// an existing LIVE session is a conflict; a stale one is cleaned
	cur, alive := e.currentLocked()
	if alive {
		_ = cur
		return StatusView{}, fmt.Errorf("%w (pid %d, profile %s)", ErrAlreadyConnected, cur.PID, cur.ProfileName)
	}
	if cur != nil {
		// stale session from a crashed agent: clean before start
		_ = os.Remove(e.st.sessionPath())
	}
	_ = os.MkdirAll(filepath.Dir(e.st.configPath()), 0o700)
	cfg := singboxConfig(p)
	cb, err := json.Marshal(cfg)
	if err != nil {
		return StatusView{}, err
	}
	if err := os.WriteFile(e.st.configPath(), cb, 0o600); err != nil {
		return StatusView{}, err
	}
	logF, err := os.OpenFile(e.st.engineLogPath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return StatusView{}, err
	}
	defer logF.Close()
	cmd := exec.Command(p.EnginePath, "run", "-c", e.st.configPath())
	cmd.Stdout = logF
	cmd.Stderr = logF
	if err := cmd.Start(); err != nil {
		return StatusView{}, fmt.Errorf("engine start: %w", err)
	}
	pid := cmd.Process.Pid
	startTime, _ := procStartTime(pid)
	if err := cmd.Process.Release(); err != nil {
		_ = cmd.Process.Kill()
		return StatusView{}, err
	}
	s := session{PID: pid, StartTime: startTime, TUNName: p.TUNName, ProfileName: name, Mode: p.Mode, StartedAt: time.Now().UTC()}
	if p.Mode == "proxy" {
		s.ProxyListen = proxyListen(p.ProxyListen)
	}
	// C10: production readiness differs per mode. tun → the TUN interface
	// appears; proxy → the engine's OWN listener is bound on ProxyListen
	// (a foreign process squatting the port is NOT readiness). WaitMode
	// "none" remains the explicitly test-only escape hatch; a failed or
	// exited engine NEVER reports connected.
	switch {
	case p.WaitMode == "none":
		// test-only: no readiness wait
	case p.Mode == "proxy":
		listen := s.ProxyListen
		_, lport, lerr := net.SplitHostPort(listen)
		if lerr != nil {
			killOwned(pid, startTime)
			_ = os.Remove(e.st.sessionPath())
			return StatusView{}, fmt.Errorf("profile: proxy_listen %q invalid", listen)
		}
		portN, _ := strconv.Atoi(lport)
		deadline := time.Now().Add(8 * time.Second)
		ready := false
		for {
			if !procAlive(pid, startTime) {
				_ = os.Remove(e.st.sessionPath())
				return StatusView{}, fmt.Errorf("engine: exited during startup (log: %s)", e.st.engineLogPath())
			}
			if ownedListenerReady(pid, portN) {
				ready = true
				break
			}
			if time.Now().After(deadline) {
				killOwned(pid, startTime)
				_ = os.Remove(e.st.sessionPath())
				return StatusView{}, fmt.Errorf("engine: proxy listener %s not owned by pid %d within 8s (log: %s)", listen, pid, e.st.engineLogPath())
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = ready
	default: // tun mode (production)
		deadline := time.Now().Add(8 * time.Second)
		for {
			if _, err := net.InterfaceByName(p.TUNName); err == nil {
				break
			}
			if time.Now().After(deadline) {
				killOwned(pid, startTime)
				_ = os.Remove(e.st.sessionPath())
				return StatusView{}, fmt.Errorf("engine: TUN %s did not appear within 8s (log: %s)", p.TUNName, e.st.engineLogPath())
			}
			if !procAlive(pid, startTime) {
				_ = os.Remove(e.st.sessionPath())
				return StatusView{}, fmt.Errorf("engine: exited during startup (log: %s)", e.st.engineLogPath())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err := writeSession(e.st.sessionPath(), &s); err != nil {
		killOwned(pid, startTime)
		return StatusView{}, err
	}
	return StatusView{Running: true, PID: pid, ProfileName: name, Mode: s.Mode, ProxyListen: s.ProxyListen, StartedAt: s.StartedAt, TUNPresent: tunPresent(p.TUNName)}, nil
}

// Stop signals the OWNED engine process only (PID + start time verified),
// waits bounded, escalates to SIGKILL and clears the session.
func (e *Engine) Stop() (StatusView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, alive := e.currentLocked()
	if !alive {
		if s != nil {
			_ = os.Remove(e.st.sessionPath())
			return StatusView{StaleCleaned: true}, nil
		}
		return StatusView{}, ErrNotConnected
	}
	killOwned(s.PID, s.StartTime)
	_ = os.Remove(e.st.sessionPath())
	return StatusView{Running: false, PID: s.PID, ProfileName: s.ProfileName, TUNPresent: tunPresent(s.TUNName)}, nil
}

// ListProfiles returns the stored profile names (B43: the client UI
// lists and selects among imported profiles; names are safe filenames —
// profilePath already rejects path escapes).
func (e *Engine) ListProfiles() ([]string, error) {
	entries, err := os.ReadDir(e.st.profilesDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, en := range entries {
		n := en.Name()
		if en.IsDir() || !strings.HasSuffix(n, ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(n, ".json"))
	}
	return out, nil
}

// Status reports the factual state; a stale session is reported as such.
func (e *Engine) Status() (StatusView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, alive := e.currentLocked()
	if !alive {
		v := StatusView{}
		if s != nil {
			v.StaleCleaned = true
		}
		return v, nil
	}
	return StatusView{Running: true, PID: s.PID, ProfileName: s.ProfileName, Mode: s.Mode, ProxyListen: s.ProxyListen, StartedAt: s.StartedAt, TUNPresent: tunPresent(s.TUNName)}, nil
}

// currentLocked returns the recorded session and whether its process is
// still the same live process. A dead or recycled PID makes it stale.
func (e *Engine) currentLocked() (*session, bool) {
	s, err := readSession(e.st.sessionPath())
	if err != nil {
		return nil, false
	}
	if !procAlive(s.PID, s.StartTime) {
		return s, false
	}
	return s, true
}

// ConfigFor renders the full client sing-box config for a profile — the
// exported form used by the subscription catalog and exports. Validation
// happens first; the config is a plain map the caller marshals into 0600
// files or subscription JSON.
func ConfigFor(p Profile) (map[string]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return singboxConfig(p), nil
}

func singboxConfig(p Profile) map[string]any {
	if p.Protocol == "" {
		p.Protocol = string(transportprofile.ProtocolVLESS)
	}
	// the ingress outbound goes through the shared typed renderer: one
	// code path renders both hops, so the Client→Edge profile can never
	// drift from the Edge→Exit transit profile semantics
	tp := &transportprofile.Profile{
		ID: "client-ingress", Role: transportprofile.RoleIngress,
		Protocol: transportprofile.Protocol(p.Protocol), Transport: transportprofile.TransportTCP,
		Security: transportprofile.SecurityTLS,
		TLS:      &transportprofile.TLS{ServerName: p.ServerName, CAPath: p.CAPath},
		// the client profile file (0600, same dir discipline as the
		// engine session) is itself the protected credential store for
		// the ingress hop
		CredentialRef: "arasec://client-profile/uuid",
	}
	ob, err := transportprofile.RenderOutbound(tp,
		transportprofile.Endpoint{Host: hostOf(p.ServerAddr), Port: portOf(p.ServerAddr)},
		transportprofile.Credential{UUID: p.UUID}, "vo")
	if err != nil {
		// Validate() already gated the protocol; renderer failure here is
		// an invariant violation, not a runtime condition
		panic("clientengine: ingress outbound render failed: " + err.Error())
	}
	var in map[string]any
	if p.Mode == "proxy" {
		host, port, _ := net.SplitHostPort(proxyListen(p.ProxyListen))
		if host == "localhost" {
			host = "127.0.0.1"
		}
		number, _ := strconv.Atoi(port)
		in = map[string]any{
			"type": "mixed", "tag": "ti", "listen": host, "listen_port": number,
		}
	} else {
		in = map[string]any{
			"type": "tun", "tag": "ti", "interface_name": p.TUNName,
			"address": addrList(p), "mtu": p.MTU,
			"auto_route": true, "strict_route": true, "stack": "system",
		}
	}
	outbounds := []map[string]any{ob}
	var routeRules []map[string]any
	directDomains := map[string]bool{}
	for _, rr := range p.RouteRules {
		switch rr.Action {
		case "direct", "block", "vpn":
		default:
			continue // unknown: final vo already covers them
		}
		outbound := rr.Action
		if rr.Action == "vpn" {
			outbound = "vo" // explicit barrier back onto the VPN outbound
		}
		rule := map[string]any{"outbound": outbound}
		if len(rr.DomainExact) > 0 {
			rule["domain"] = rr.DomainExact
		}
		if len(rr.DomainSuffix) > 0 {
			rule["domain_suffix"] = rr.DomainSuffix
		}
		if len(rr.CIDR) > 0 {
			rule["ip_cidr"] = rr.CIDR
		}
		if len(rr.Ports) > 0 {
			rule["port"] = rr.Ports
		}
		if rr.Proto != "" {
			rule["network"] = rr.Proto // sing-box network: tcp|udp (AND with the rest)
		}
		if len(rule) == 1 {
			continue
		}
		if rr.Action == "direct" {
			for _, d := range rr.DomainExact {
				directDomains[d] = true
			}
			for _, d := range rr.DomainSuffix {
				directDomains[d] = true
			}
		}
		routeRules = append(routeRules, rule)
	}
	if routeRules != nil {
		// the direct and block outbounds exist only when a rule uses them;
		// the VPN outbound stays the final (kill switch)
		for _, tag := range []string{"direct", "block"} {
			used := false
			for _, r := range routeRules {
				if r["outbound"] == tag {
					used = true
					break
				}
			}
			if !used {
				continue
			}
			otag := tag
			if tag == "block" {
				outbounds = append(outbounds, map[string]any{"type": "block", "tag": "block"})
				continue
			}
			outbounds = append(outbounds, map[string]any{"type": "direct", "tag": otag})
		}
	}
	routeCfg := map[string]any{"auto_detect_interface": true, "final": "vo"}
	if routeRules != nil {
		routeCfg["rules"] = routeRules
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []map[string]any{in},
		"outbounds": outbounds,
		"route":     routeCfg,
	}
	if p.DNSServer != "" || len(directDomains) > 0 {
		dnsCfg := map[string]any{}
		var servers []map[string]any
		var dnsRules []map[string]any
		if len(directDomains) > 0 {
			// DIRECT domains resolve through the LOCAL resolver — a
			// tunnel-detoured answer would make the direct connection
			// depend on the VPN it explicitly bypasses
			servers = append(servers, map[string]any{"tag": "local-dns", "type": "local"})
			dnsRules = append(dnsRules, map[string]any{
				"server": "local-dns",
				"domain": keysOf(directDomains),
			})
		}
		if p.DNSServer != "" {
			servers = append(servers, map[string]any{"tag": "tunnel-dns", "type": "tcp", "server": hostOf(p.DNSServer), "detour": "vo"})
		}
		dnsCfg["servers"] = servers
		if dnsRules != nil {
			dnsCfg["rules"] = dnsRules
		}
		dnsCfg["final"] = "tunnel-dns"
		if p.DNSServer == "" {
			dnsCfg["final"] = "local-dns"
		}
		cfg["dns"] = dnsCfg
	}
	return cfg
}

func proxyListen(address string) string {
	if address == "" {
		return "127.0.0.1:2080"
	}
	return address
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ownedListenerReady reports whether pid itself holds a LISTEN socket on
// the given local port (C10): /proc/net/tcp(6) inode → /proc/<pid>/fd.
// On non-Linux development hosts (no /proc) it degrades to "something is
// accepting connections on the port" — a weaker but honest readiness
// signal for local builds; production/lab is Linux and keeps ownership.
func ownedListenerReady(pid, port int) bool {
	if _, err := os.Stat("/proc/self"); err != nil {
		return portAccepting(port)
	}
	inode := listeningInode(port)
	if inode == "" {
		return false
	}
	return pidOwnsSocket(pid, inode)
}

// portAccepting dials the loopback port: a connect that succeeds (or is
// refused AFTER SYN-ACK — i.e. a listener exists) proves the bind.
func portAccepting(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func listeningInode(port int) string {
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			if i == 0 || !strings.Contains(line, ":") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			// local_address is fields[1] (HHHH:PORT hex); st fields[3]: 0A = LISTEN
			if len(fields[1]) < 9 || fields[3] != "0A" {
				continue
			}
			p, cerr := strconv.ParseInt(fields[1][len(fields[1])-4:], 16, 32)
			if cerr != nil || int(p) != port {
				continue
			}
			return fields[9]
		}
	}
	return ""
}

func pidOwnsSocket(pid int, inode string) bool {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	want := "socket:[" + inode + "]"
	for _, en := range entries {
		if link, err := os.Readlink(filepath.Join(fdDir, en.Name())); err == nil && link == want {
			return true
		}
	}
	return false
}

func addrList(p Profile) []string {
	l := []string{p.TUNAddr4}
	if p.TUNAddr6 != "" {
		l = append(l, p.TUNAddr6)
	}
	return l
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func portOf(addr string) int {
	_, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(ps)
	return p
}

func tunPresent(name string) bool {
	if name == "" {
		return false
	}
	_, err := net.InterfaceByName(name)
	return err == nil
}

func writeSession(path string, s *session) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readSession(path string) (*session, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// procStartTime reads the process start time in jiffies (/proc field 22);
// 0 means unknown (non-Linux), in which case PID matching alone applies.
func procStartTime(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// the comm field may contain spaces: parse after the closing paren
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 > len(b) {
		return 0, errors.New("stat: malformed")
	}
	fields := strings.Fields(string(b[i+2:]))
	// fields[0] is state (field 3); starttime is field 22 => index 19
	if len(fields) < 20 {
		return 0, errors.New("stat: short")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func procAlive(pid int, start uint64) bool {
	cur, err := procStartTime(pid)
	if err != nil {
		return false
	}
	if start != 0 && cur != 0 && cur != start {
		return false // PID recycled by another process
	}
	return true
}

// killOwned signals only a process matching BOTH the recorded PID and its
// recorded start time; anything else is treated as stale and left alone.
func killOwned(pid int, start uint64) {
	if !procAlive(pid, start) {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !procAlive(pid, start) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	if procAlive(pid, start) {
		_ = p.Signal(syscall.SIGKILL)
	}
}
