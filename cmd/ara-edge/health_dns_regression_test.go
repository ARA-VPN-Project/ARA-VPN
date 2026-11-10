package main

// Formal gate-A regressions for exit-scoped DNS (docs/ROUTING_DNS.md) and
// the probe health contract (fragmented responses, false positives,
// auth/TLS quarantine vs transport failure).

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"aravpn/core/health"
	"aravpn/core/policy"
)

// fakeDNSServer is a minimal DNS-over-TCP responder: it answers every
// query with the configured A/AAAA records (like the lab ara-dns-responder).
type fakeDNSServer struct {
	ln      net.Listener
	a       net.IP
	aaaa    net.IP
	cnameTo string // optional CNAME in the answer before the A record
}

func startFakeDNS(t *testing.T, a, aaaa net.IP, cnameTo string) *fakeDNSServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeDNSServer{ln: ln, a: a, aaaa: aaaa, cnameTo: cnameTo}
	go s.serve()
	return s
}

func (s *fakeDNSServer) addr() string { return s.ln.Addr().String() }

func (s *fakeDNSServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			for {
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				r := s.reply(msg)
				out := make([]byte, 2, 2+len(r))
				binary.BigEndian.PutUint16(out, uint16(len(r)))
				_, _ = c.Write(append(out, r...))
			}
		}(c)
	}
}

// reply echoes the question and appends the configured records.
func (s *fakeDNSServer) reply(q []byte) []byte {
	out := append([]byte{}, q...)
	out[2] |= 0x80 // QR=1
	answers := 0
	if s.cnameTo != "" {
		answers++
	}
	if s.a != nil {
		answers++
	}
	if s.aaaa != nil {
		answers++
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(answers))
	// question name echo: reuse raw question bytes
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	name := append([]byte{}, q[12:i+1]...)
	if s.cnameTo != "" {
		var cn []byte
		for _, label := range []string{"target", "example"} {
			cn = append(cn, byte(len(label)))
			cn = append(cn, label...)
		}
		cn = append(cn, 0)
		out = append(out, name...)
		out = append(out, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0, byte(len(cn))) // CNAME
		out = append(out, cn...)
	}
	if s.a != nil {
		out = append(out, name...)
		out = append(out, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4)
		out = append(out, s.a.To4()...)
	}
	if s.aaaa != nil {
		out = append(out, name...)
		out = append(out, 0x00, 0x1c, 0x00, 0x01, 0, 0, 0, 60, 0, 16)
		out = append(out, s.aaaa.To16()...)
	}
	return out
}

// fakeProxyEgress is a SOCKS5 egress that records the requested
// destination and actually proxies raw bytes to 127.0.0.1:proxyPort —
// enough to carry a DNS-over-TCP exchange in-process.
func fakeProxyEgress(t *testing.T, proxyPort int) (string, <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	seen := make(chan string, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go handleProxyConn(c, proxyPort, seen)
		}
	}()
	return l.Addr().String(), seen
}

func handleProxyConn(c net.Conn, proxyPort int, seen chan string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	h := make([]byte, 3)
	if _, err := io.ReadFull(c, h); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0})
	q := make([]byte, 4)
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	var host string
	port := 0
	switch q[3] {
	case 1:
		x := make([]byte, 6)
		_, _ = io.ReadFull(c, x)
		host = net.IP(x[0:4]).String()
		port = int(x[4])<<8 | int(x[5])
	case 3:
		x := make([]byte, 1)
		_, _ = io.ReadFull(c, x)
		v := make([]byte, int(x[0]))
		_, _ = io.ReadFull(c, v)
		host = string(v)
		px := make([]byte, 2)
		_, _ = io.ReadFull(c, px)
		port = int(px[0])<<8 | int(px[1])
	}
	select {
	case seen <- net.JoinHostPort(host, strconv.Itoa(port)):
	default:
	}
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)))
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); up.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); c.Close(); done <- struct{}{} }()
	<-done
}

func edgeDNSExitConfig(t *testing.T, socksAddr, dnsAddr string) (*edgeConfig, exitNode) {
	t.Helper()
	cfg := edgeTestConfig(t)
	e := exitNode{ID: "f", Role: "foreign", Country: "NL", Priority: 1,
		SOCKSAddr: socksAddr, DNSAddr: dnsAddr}
	cfg.Exits = []exitNode{e}
	cfg.CurrentForeign = "f"
	return cfg, e
}

func TestEdgeResolveViaExitAnswersThroughExitHop(t *testing.T) {
	dns := startFakeDNS(t, net.ParseIP("93.184.216.34"), net.ParseIP("2606:2800::68"), "")
	proxyAddr, seen := fakeProxyEgress(t, mustPort(t, dns.addr()))
	cfg, e := edgeDNSExitConfig(t, proxyAddr, "resolver.ara.lab:53")
	dp := newEdgeTestDatapath(t, cfg)
	// keep the REAL dnsOverTCPThroughExit (no override): the exchange must
	// travel through the exit hop to the resolver
	addrs, err := dp.resolveViaExit(e, "canary.ara.lab")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) == 0 || !addrs[0].Is4() || addrs[0].String() != "93.184.216.34" {
		t.Fatalf("v4-first verification failed: %v", addrs)
	}
	if !containsAddr(addrs, netip.MustParseAddr("2606:2800::68")) {
		t.Fatalf("AAAA record lost: %v", addrs)
	}
	if h := <-seen; h != "resolver.ara.lab:53" {
		t.Fatalf("DNS query did not traverse the exit hop, saw %q", h)
	}
}

func TestEdgeResolveViaExitDeniesPrivateAnswer(t *testing.T) {
	dns := startFakeDNS(t, net.ParseIP("10.9.9.9"), nil, "")
	proxyAddr, _ := fakeProxyEgress(t, mustPort(t, dns.addr()))
	cfg, e := edgeDNSExitConfig(t, proxyAddr, "resolver.ara.lab:53")
	dp := newEdgeTestDatapath(t, cfg)
	_, err := dp.resolveViaExit(e, "rebind.ara.lab")
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("denied by system ACL")) {
		t.Fatalf("private answer must deny the destination, got %v", err)
	}
}

func TestEdgeResolveViaExitFollowsBoundedCNAME(t *testing.T) {
	dns := startFakeDNS(t, net.ParseIP("93.184.216.34"), nil, "target.example")
	proxyAddr, _ := fakeProxyEgress(t, mustPort(t, dns.addr()))
	cfg, e := edgeDNSExitConfig(t, proxyAddr, "resolver.ara.lab:53")
	dp := newEdgeTestDatapath(t, cfg)
	addrs, err := dp.resolveViaExit(e, "chain.ara.lab")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAddr(addrs, netip.MustParseAddr("93.184.216.34")) {
		t.Fatalf("CNAME target address lost: %v", addrs)
	}
}

func TestEdgeResolveViaExitRefusedWithoutDNSAddr(t *testing.T) {
	proxyAddr, _ := fakeProxyEgress(t, 1)
	cfg, e := edgeDNSExitConfig(t, proxyAddr, "")
	dp := newEdgeTestDatapath(t, cfg)
	_, err := dp.resolveViaExit(e, "canary.ara.lab")
	if err == nil {
		t.Fatal("exit without dns_addr must refuse domains, not fall back to the edge resolver")
	}
}

func TestEdgeDomainFlowPinnedThroughExitScope(t *testing.T) {
	// full flow: authenticated client, domain destination, resolution and
	// dial both through the SAME exit hop
	dns := startFakeDNS(t, net.ParseIP("93.184.216.34"), nil, "")
	proxyAddr, seen := fakeProxyEgress(t, mustPort(t, dns.addr()))
	cfg, _ := edgeDNSExitConfig(t, proxyAddr, "resolver.ara.lab:53")
	cfg.Devices = []deviceAuth{{UUID: cfg.DeviceUUID, DeviceID: "dev-1", SOCKSUser: "dev-1", SOCKSPass: "pw-1"}}
	dp := newEdgeTestDatapath(t, cfg)
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	go dp.handleSOCKS(b)
	go func() {
		_, _ = a.Write([]byte{5, 1, 2})
		_, _ = a.Write(append([]byte{1, 5}, append([]byte("dev-1"), append([]byte{4}, []byte("pw-1")...)...)...))
		_, _ = a.Write([]byte{5, 1, 0, 3, 14}) // CONNECT, domain, len 14
		_, _ = a.Write([]byte("canary.ara.lab"))
		_, _ = a.Write([]byte{0, 80})
	}()
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(a, greeting); err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(a, auth); err != nil {
		t.Fatal(err)
	}
	if auth[1] != 0 {
		t.Fatalf("auth rejected: %x", auth)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(a, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("domain CONNECT refused: %x", reply)
	}
	// both the DNS query and the pinned dial must traverse the exit hop
	h1 := <-seen
	h2 := <-seen
	if h1 != "resolver.ara.lab:53" || h2 != "93.184.216.34:80" {
		t.Fatalf("exit hop saw %q then %q; want resolver query then pinned dial", h1, h2)
	}
	drainUntilClose(t, a)
}

// ---- probe health contract ----

// fakeProbeEgress answers a CONNECT and returns a canned canary response.
func fakeProbeEgress(t *testing.T, response []byte, fragment bool, rejectConnect bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		h := make([]byte, 3)
		if _, err = io.ReadFull(c, h); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		q := make([]byte, 4)
		if _, err = io.ReadFull(c, q); err != nil {
			return
		}
		switch q[3] {
		case 1:
			x := make([]byte, 6)
			_, _ = io.ReadFull(c, x)
		case 3:
			x := make([]byte, 1)
			_, _ = io.ReadFull(c, x)
			v := make([]byte, int(x[0]))
			_, _ = io.ReadFull(c, v)
			px := make([]byte, 2)
			_, _ = io.ReadFull(c, px)
		}
		if rejectConnect {
			_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		if fragment {
			for i := 0; i < len(response); i++ {
				_, _ = c.Write(response[i : i+1])
				time.Sleep(2 * time.Millisecond)
			}
			return
		}
		_, _ = c.Write(response)
	}()
	return l.Addr().String()
}

func probeExitConfig(t *testing.T, socksAddr string) (*edgeConfig, exitNode) {
	t.Helper()
	cfg := edgeTestConfig(t)
	e := exitNode{ID: "f", Role: "foreign", Country: "NL", Priority: 1,
		SOCKSAddr: socksAddr, ProbeAddr: "canary.host:8000"}
	cfg.Exits = []exitNode{e}
	cfg.CurrentForeign = "f"
	return cfg, e
}

var fullCanaryResponse = []byte("HTTP/1.0 200 OK\r\nContent-Length: 18\r\n\r\nRU-CANARY-PAYLOAD\r\n")

func TestEdgeProbeFragmentedCanarySucceeds(t *testing.T) {
	cfg, e := probeExitConfig(t, fakeProbeEgress(t, fullCanaryResponse, true, false))
	dp := newEdgeTestDatapath(t, cfg)
	if err := dp.probeExit(e, 2*time.Second); err != nil {
		t.Fatalf("fragmented full roundtrip must succeed: %v", err)
	}
}

func TestEdgeProbeFalsePositiveStatusOnlyFails(t *testing.T) {
	// 200 header without the canary body does not prove a roundtrip
	cfg, e := probeExitConfig(t, fakeProbeEgress(t, []byte("HTTP/1.0 200 OK\r\n\r\n"), false, false))
	dp := newEdgeTestDatapath(t, cfg)
	err := dp.probeExit(e, 2*time.Second)
	if err == nil || probeFailureKind(err) != health.FailServer {
		t.Fatalf("status-only response must fail with server kind, got %v", err)
	}
}

func TestEdgeProbeGarbageAnd5xxFail(t *testing.T) {
	cfg, e := probeExitConfig(t, fakeProbeEgress(t, []byte("garbage-no-http\r\n\r\nCANARY\r\n"), false, false))
	dp := newEdgeTestDatapath(t, cfg)
	if err := dp.probeExit(e, 2*time.Second); err == nil || probeFailureKind(err) != health.FailServer {
		t.Fatalf("garbage response must fail with server kind, got %v", err)
	}
	cfg2, e2 := probeExitConfig(t, fakeProbeEgress(t, []byte("HTTP/1.0 503 Service Unavailable\r\n\r\nCANARY\r\n"), false, false))
	dp2 := newEdgeTestDatapath(t, cfg2)
	if err := dp2.probeExit(e2, 2*time.Second); err == nil || probeFailureKind(err) != health.FailServer {
		t.Fatalf("5xx must fail with server kind, got %v", err)
	}
}

func TestEdgeProbeAuthRejectionQuarantinesImmediately(t *testing.T) {
	cfg, e := probeExitConfig(t, fakeProbeEgress(t, fullCanaryResponse, false, true))
	dp := newEdgeTestDatapath(t, cfg)
	now := time.Now()
	if err := dp.probeExit(e, 2*time.Second); err == nil || probeFailureKind(err) != health.FailAuth {
		t.Fatalf("CONNECT rejection must classify as auth, got %v", err)
	}
	tr := dp.health[e.ID]
	tr.RecordFailure(now, health.FailAuth, "CONNECT rejected, code 2")
	if st := tr.Effective(now).State; st != health.Quarantined {
		t.Fatalf("auth failure must quarantine immediately, got %s", st)
	}
	// quarantined nodes take no new flows: the only exit is quarantined,
	// so the domain flow must be refused, not silently served
	if _, _, err := dp.selectExit(policy.Destination{Domain: "x.example", Proto: policy.ProtoTCP, Port: 80}); err == nil {
		t.Fatal("quarantined-only topology must not grant egress")
	}
}

func TestEdgeProbeTransportFailureCountsToDown(t *testing.T) {
	cfg, e := probeExitConfig(t, fakeProbeEgress(t, fullCanaryResponse, false, true))
	dp := newEdgeTestDatapath(t, cfg)
	tr := dp.health[e.ID]
	now := time.Now()
	tr.RecordFailure(now, health.FailConnRefused, "refused")
	if st := tr.Effective(now).State; st != health.Suspect {
		t.Fatalf("one transport failure must suspect, got %s", st)
	}
	// a suspect node is not eligible for new flows
	if _, _, err := dp.selectExit(policy.Destination{Domain: "x.example", Proto: policy.ProtoTCP, Port: 80}); err == nil {
		t.Fatal("suspect-only topology must not grant egress")
	}
	for i := 1; i < 3; i++ {
		tr.RecordFailure(now.Add(time.Duration(i)*time.Second), health.FailConnRefused, "refused")
	}
	if st := tr.Effective(now.Add(3 * time.Second)).State; st != health.Down {
		t.Fatalf("three transport failures must reach down, got %s", st)
	}
}

// TestEdgeTrackerRecoveryHysteresis covers the full down→recovering→healthy
// arc with a small stability window (hysteresis: a failure inside the
// window restarts it).
func TestEdgeTrackerRecoveryHysteresis(t *testing.T) {
	tr, err := health.NewTracker(health.Config{
		FailThreshold: 2, RecoverThreshold: 2, StabilityWindow: 3 * time.Second,
		MaxObservationAge: 10 * time.Minute, InitialProbeWindow: 8 * time.Second,
	}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1700000000, 0)
	tr.RecordSuccess(t0)
	tr.RecordFailure(t0, health.FailTimeout, "x")
	tr.RecordFailure(t0.Add(time.Second), health.FailTimeout, "x")
	if st := tr.Effective(t0.Add(time.Second)).State; st != health.Down {
		t.Fatalf("two failures must reach down, got %s", st)
	}
	tr.RecordSuccess(t0.Add(2 * time.Second))
	tr.RecordSuccess(t0.Add(3 * time.Second))
	if st := tr.Effective(t0.Add(3 * time.Second)).State; st != health.Recovering {
		t.Fatalf("threshold successes must reach recovering, got %s", st)
	}
	// a failure inside the stability window restarts the whole window
	tr.RecordFailure(t0.Add(4 * time.Second), health.FailTimeout, "x")
	tr.RecordSuccess(t0.Add(5 * time.Second))
	if st := tr.Effective(t0.Add(7 * time.Second)).State; st != health.Recovering {
		t.Fatalf("failure inside window must restart hysteresis, got %s", st)
	}
	if st := tr.Effective(t0.Add(9 * time.Second)).State; st != health.Healthy {
		t.Fatalf("node must turn healthy after a clean window, got %s", st)
	}
}

func TestEdgeProbeSilentServerTimesOut(t *testing.T) {
	// an egress that accepts CONNECT and never answers the HTTP request
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		h := make([]byte, 3)
		_, _ = io.ReadFull(c, h)
		_, _ = c.Write([]byte{5, 0})
		q := make([]byte, 10)
		_, _ = io.ReadFull(c, q)
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		time.Sleep(3 * time.Second) // no HTTP response at all
	}()
	cfg, e := probeExitConfig(t, l.Addr().String())
	dp := newEdgeTestDatapath(t, cfg)
	start := time.Now()
	err = dp.probeExit(e, 400*time.Millisecond)
	if err == nil || probeFailureKind(err) != health.FailTimeout {
		t.Fatalf("silent canary must time out, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("probe must honor the deadline, took %v", time.Since(start))
	}
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func containsAddr(addrs []netip.Addr, want netip.Addr) bool {
	for _, a := range addrs {
		if a == want {
			return true
		}
	}
	return false
}

