package main

// Permanent in-repo regressions for the transport-enforcement fixes
// (review TR01–TR06, 2026-10-29). Names deliberately differ from the
// independent overlay test file so both suites can run together.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"aravpn/core/limits"
	"aravpn/core/policy"
	"aravpn/internal/transport"
)

func edgeTestConfig(t *testing.T) *edgeConfig {
	t.Helper()
	return &edgeConfig{
		DeviceUUID:     "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		StateDir:       t.TempDir(),
		QuotaBytes:     1_000_000,
		Exits:          []exitNode{{ID: "f", Role: "foreign", Country: "NL", Priority: 1, DNSAddr: "resolver.ara.lab:53"}},
		CurrentForeign: "f",
	}
}

func newEdgeTestDatapath(t *testing.T, cfg *edgeConfig) *edgeDatapath {
	t.Helper()
	dp, err := newDatapath(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dp.health[cfg.Exits[0].ID].RecordSuccess(time.Now())
	return dp
}

func TestPublishedPolicyRoutesTwoServicesOnColdStart(t *testing.T) {
	cfg := edgeTestConfig(t)
	cfg.Exits = append(cfg.Exits, exitNode{ID: "de", Role: "foreign", Country: "DE", Priority: 2})
	cfg.Policy = policy.DefaultPolicy()
	cfg.Policy.Rules = []policy.Rule{
		{ID: "video", Enabled: true, DomainSuffix: []string{"video.example"}, Action: policy.ActionForeignExit, ExitID: "f"},
		{ID: "work", Enabled: true, DomainSuffix: []string{"work.example"}, Action: policy.ActionForeignExit, ExitID: "de"},
	}
	dp := newEdgeTestDatapath(t, cfg)
	dp.health["de"].RecordSuccess(time.Now())
	for name, want := range map[string]string{"cdn.video.example": "f", "api.work.example": "de"} {
		exit, decision, err := dp.selectExit(policy.Destination{Domain: name})
		if err != nil || exit.ID != want || decision.DNSScope != "exit:"+want {
			t.Fatalf("%s selected %+v, decision %+v: %v", name, exit, decision, err)
		}
	}
}

// edgeReadUntil reads from c until substr appears or the deadline
// passes. Test pipes (net.Pipe) cannot half-close, so a client that
// finished uploading stops at the marker instead of waiting for the
// server-side EOF that real TCP/TLS conns deliver via CloseWrite.
func edgeReadUntil(t *testing.T, c net.Conn, substr string, d time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	var out bytes.Buffer
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
			if bytes.Contains(out.Bytes(), []byte(substr)) {
				return out.Bytes()
			}
		}
		if err != nil {
			return out.Bytes()
		}
	}
}

// fakeEgress is a local SOCKS5 egress stand-in that records the requested
// destination (host:port) and never connects to it; it answers CONNECT
// with success and sends CANARY as egress payload.
func fakeEgress(t *testing.T) (string, <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	seen := make(chan string, 4)
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
		var host string
		switch q[3] {
		case 1:
			x := make([]byte, 4)
			_, _ = io.ReadFull(c, x)
			host = net.IP(x).String()
		case 3:
			x := make([]byte, 1)
			_, _ = io.ReadFull(c, x)
			v := make([]byte, int(x[0]))
			_, _ = io.ReadFull(c, v)
			host = string(v)
		case 4:
			x := make([]byte, 16)
			_, _ = io.ReadFull(c, x)
			host = net.IP(x).String()
		}
		port := make([]byte, 2)
		_, _ = io.ReadFull(c, port)
		seen <- net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1])))
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		_, _ = c.Write([]byte("CANARY"))
	}()
	return l.Addr().String(), seen
}

func seenNothing(t *testing.T, seen <-chan string) {
	t.Helper()
	select {
	case h := <-seen:
		t.Fatalf("destination %q reached the egress but must not have", h)
	default:
	}
}

// TR04 mirror + both directions: rate 0 is forbidden, not unlimited.
func TestEdgeZeroRateBlocksBothDirections(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	zero := int64(0)
	regime, err := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: &zero, UploadBPS: &zero}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dp.limiter, err = regime.BindDevice(limits.RateConfig{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []limits.Direction{limits.Download, limits.Upload} {
		e := &enforcer{dp: dp, deviceID: dp.cfg.DeviceUUID, dir: dir}
		n, err := e.relay(io.Discard, bytes.NewBufferString("forbidden payload"))
		if err == nil {
			t.Fatalf("%s: rate 0 relayed payload (n=%d)", dir, n)
		}
		if n != 0 {
			t.Fatalf("%s: rate 0 relayed %d bytes", dir, n)
		}
	}
}

// Rate shaping must pace real bytes through a slow bucket, not busy-loop
// and not drop the flow.
func TestEdgeRateShapingPacesInsteadOfDropping(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	kbps := int64(8192) // 1 KiB/s
	regime, err := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: &kbps}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dp.limiter, err = regime.BindDevice(limits.RateConfig{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e := &enforcer{dp: dp, deviceID: dp.cfg.DeviceUUID, dir: limits.Download}
	start := time.Now()
	n, err := e.relay(io.Discard, bytes.NewBuffer(make([]byte, 4096)))
	d := time.Since(start)
	if err != nil {
		t.Fatalf("paced flow refused: %v", err)
	}
	if n != 4096 {
		t.Fatalf("paced flow lost bytes: %d", n)
	}
	if d < 2*time.Second {
		t.Fatalf("shaping not applied: 4 KiB at 1 KiB/s in %v", d)
	}
	if d > 10*time.Second {
		t.Fatalf("shaping stalled: %v", d)
	}
}

// Partial writes are charged as actually written, not as read.
type edgeHalfWriter struct {
	n     int
	limit int
}

func (w *edgeHalfWriter) Write(p []byte) (int, error) {
	room := w.limit - w.n
	if room < len(p) {
		w.n += room
		return room, errors.New("write failed mid-buffer")
	}
	w.n += len(p)
	return len(p), nil
}

type edgeRecJournal struct {
	mu        sync.Mutex
	recs      []limits.Rec
	failKind  limits.RecKind // Append fails for this record kind ("" = never)
	failAfter int            // Append fails after this many records (-1 = never)
}

func (j *edgeRecJournal) Append(r limits.Rec) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failKind != "" && r.Kind == j.failKind {
		return errors.New("journal append failed")
	}
	if j.failAfter >= 0 && len(j.recs) >= j.failAfter {
		return errors.New("journal append failed")
	}
	j.recs = append(j.recs, r)
	return nil
}

func (j *edgeRecJournal) Load() ([]limits.Rec, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]limits.Rec(nil), j.recs...), nil
}

func edgeLedger(t *testing.T, dp *edgeDatapath, limit int64, jr *edgeRecJournal) {
	t.Helper()
	q, err := limits.NewQuotaLedger("acc-edge-test", &limit, limits.DefaultPeriod(), jr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dp.quota = q
}

func TestEdgeRelayChargesActualWrittenBytes(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	jr := &edgeRecJournal{failAfter: -1}
	edgeLedger(t, dp, 1<<20, jr)
	e := &enforcer{dp: dp, deviceID: "dev-1", dir: limits.Download}
	out := &edgeHalfWriter{limit: 5}
	n, err := e.relay(out, bytes.NewBufferString("0123456789"))
	if err == nil {
		t.Fatal("partial write must surface as an error")
	}
	if n != 5 || out.n != 5 {
		t.Fatalf("relayed=%d written=%d, want 5/5", n, out.n)
	}
	jr.mu.Lock()
	last := jr.recs[len(jr.recs)-1]
	jr.mu.Unlock()
	if last.Kind != limits.RecCheckpoint || last.Bytes != 5 {
		t.Fatalf("checkpoint must charge the 5 actually written bytes, got %+v", last)
	}
}

func TestEdgeRelaySurfacesCheckpointFailure(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	jr := &edgeRecJournal{failKind: limits.RecCheckpoint, failAfter: -1}
	edgeLedger(t, dp, 1<<20, jr)
	e := &enforcer{dp: dp, deviceID: "dev-1", dir: limits.Upload}
	_, err := e.relay(io.Discard, bytes.NewBufferString("payload"))
	if err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("checkpoint failure must not be silent, got %v", err)
	}
}

func TestEdgeQuotaExhaustionStopsDirection(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	jr := &edgeRecJournal{failAfter: -1}
	edgeLedger(t, dp, 0, jr) // zero quota: every chargeable byte refused
	e := &enforcer{dp: dp, deviceID: "dev-1", dir: limits.Download}
	n, err := e.relay(io.Discard, bytes.NewBufferString("must not pass"))
	if err == nil || !strings.Contains(err.Error(), "admission refused") {
		t.Fatalf("exhausted quota must stop the direction, got n=%d err=%v", n, err)
	}
	if n != 0 {
		t.Fatalf("exhausted quota relayed %d bytes", n)
	}
}

// SOCKS5 with user/pass binds a device identity and grants egress — the
// positive control for TR03.
func TestEdgeSOCKSUserPassAuthGrantsEgress(t *testing.T) {
	cfg := edgeTestConfig(t)
	cfg.Devices = []deviceAuth{{UUID: cfg.DeviceUUID, DeviceID: "dev-1", SOCKSUser: "dev-1", SOCKSPass: "pw-1"}}
	dp := newEdgeTestDatapath(t, cfg)
	addr, seen := fakeEgress(t)
	dp.cfg.Exits[0].SOCKSAddr = addr
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	go dp.handleSOCKS(b)
	go func() {
		_, _ = a.Write([]byte{5, 1, 2}) // offer user/pass only
		_, _ = a.Write(append([]byte{1, 5}, append([]byte("dev-1"), append([]byte{4}, []byte("pw-1")...)...)...))
		_, _ = a.Write([]byte{5, 1, 0, 1, 93, 184, 216, 34, 0, 80}) // CONNECT
	}()
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(a, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[1] != 2 {
		t.Fatalf("server must select user/pass, got %x", greeting)
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(a, auth); err != nil {
		t.Fatal(err)
	}
	if auth[0] != 1 || auth[1] != 0 {
		t.Fatalf("valid credentials rejected: %x", auth)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(a, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("CONNECT refused after auth: %x", reply)
	}
	data := edgeReadUntil(t, a, "CANARY", 3*time.Second)
	if !bytes.Contains(data, []byte("CANARY")) {
		t.Fatalf("authenticated device got no egress payload: %x", data)
	}
	if h := <-seen; h != "93.184.216.34:80" {
		t.Fatalf("egress destination %q", h)
	}
	drainUntilClose(t, a)
}

// drainUntilClose reads the client end until the server side closed, so
// the data path (and its quota journal in t.TempDir) has finished before
// cleanup — otherwise TempDir RemoveAll races with the final journal write.
func drainUntilClose(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

func TestEdgeSOCKSWrongPasswordDeniesEgress(t *testing.T) {
	cfg := edgeTestConfig(t)
	cfg.Devices = []deviceAuth{{UUID: cfg.DeviceUUID, DeviceID: "dev-1", SOCKSUser: "dev-1", SOCKSPass: "pw-1"}}
	dp := newEdgeTestDatapath(t, cfg)
	addr, seen := fakeEgress(t)
	dp.cfg.Exits[0].SOCKSAddr = addr
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	go dp.handleSOCKS(b)
	go func() {
		_, _ = a.Write([]byte{5, 1, 2})
		_, _ = a.Write(append([]byte{1, 5}, append([]byte("dev-1"), append([]byte{6}, []byte("wrong!!")...)...)...))
	}()
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(a, greeting); err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(a, auth); err != nil {
		t.Fatal(err)
	}
	if auth[0] != 1 || auth[1] != 1 {
		t.Fatalf("wrong password must be rejected, got %x", auth)
	}
	_, _ = io.ReadAll(a) // handler closes
	seenNothing(t, seen)
}

// TR06 mirror and positive control: mixed ACL answers deny the whole
// destination; a global answer is pinned to the verified IP at the exit.
func TestEdgeDomainWithPrivateAnswerDenied(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	addr, seen := fakeEgress(t)
	dp.cfg.Exits[0].SOCKSAddr = addr
	dp.resolveExit = func(ctx context.Context, e exitNode, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.7")}, nil
	}
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	dp.bindIdentity(b, dp.cfg.Devices[0])
	fwdDone1 := make(chan struct{})
	go func() {
		defer close(fwdDone1)
		defer b.Close()
		dp.forward(b, "mixed.example", 80, "edge-test")
	}()
	_, _ = io.ReadAll(a)
	seenNothing(t, seen)
	// sync: the relay goroutine must finish before TempDir cleanup; the
	// client pipe must close first or the relay waits for EOF forever
	_ = a.Close()
	select {
	case <-fwdDone1:
	case <-time.After(6 * time.Second):
		t.Fatal("relay goroutine did not finish before cleanup")
	}
}

func TestEdgeDomainGlobalAnswerPinnedToVerifiedIP(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	addr, seen := fakeEgress(t)
	dp.cfg.Exits[0].SOCKSAddr = addr
	dp.resolveExit = func(ctx context.Context, e exitNode, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	dp.bindIdentity(b, dp.cfg.Devices[0])
	fwdDone2 := make(chan struct{})
	go func() {
		defer close(fwdDone2)
		defer b.Close()
		dp.forward(b, "example.invalid", 443, "edge-test")
	}()
	data := edgeReadUntil(t, a, "CANARY", 3*time.Second)
	if !bytes.Contains(data, []byte("CANARY")) {
		t.Fatalf("allowed domain got no egress payload: %x", data)
	}
	if h := <-seen; h != "93.184.216.34:443" {
		t.Fatalf("exit must dial the pinned verified IP, saw %q", h)
	}
	// sync: the relay goroutine must finish before TempDir cleanup; the
	// client pipe must close first or the relay waits for EOF forever
	_ = a.Close()
	select {
	case <-fwdDone2:
	case <-time.After(6 * time.Second):
		t.Fatal("relay goroutine did not finish before cleanup")
	}
}

func TestEdgeDomainUnresolvableDenied(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	addr, seen := fakeEgress(t)
	dp.cfg.Exits[0].SOCKSAddr = addr
	dp.resolveExit = func(ctx context.Context, e exitNode, host string) ([]netip.Addr, error) {
		return nil, errors.New("no such host")
	}
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	dp.bindIdentity(b, dp.cfg.Devices[0])
	fwdDone3 := make(chan struct{})
	go func() {
		defer close(fwdDone3)
		defer b.Close()
		dp.forward(b, "nx.example", 80, "edge-test")
	}()
	_, _ = io.ReadAll(a)
	seenNothing(t, seen)
	// sync: the relay goroutine must finish before TempDir cleanup; the
	// client pipe must close first or the relay waits for EOF forever
	_ = a.Close()
	select {
	case <-fwdDone3:
	case <-time.After(6 * time.Second):
		t.Fatal("relay goroutine did not finish before cleanup")
	}
}

// TR05 mirror: a supplied policy that is unreadable must fail startup,
// never become the permissive embedded default.
func TestEdgeSuppliedPolicyInvalidFailsStartup(t *testing.T) {
	cfg := edgeTestConfig(t)
	cfg.PolicyFile = filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(cfg.PolicyFile, []byte(`{"broken":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newDatapath(cfg); err == nil {
		t.Fatal("invalid supplied policy silently replaced by embedded default")
	}
}

// TR05 mirror: the committed envelope from the accepted core store is the
// enforced policy.
func TestEdgeCommittedEnvelopePolicyEnforced(t *testing.T) {
	cfg := edgeTestConfig(t)
	dir := t.TempDir()
	s, err := policy.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := policy.DefaultPolicy()
	p.Rules = []policy.Rule{{ID: "block-80", Enabled: true, Proto: policy.ProtoTCP, Ports: []policy.PortRange{{From: 80, To: 80}}, Action: policy.ActionBlock}}
	if _, err := s.ValidateAndApplyIdentity(p, 0, "plan", "key"); err != nil {
		t.Fatal(err)
	}
	cfg.PolicyFile = filepath.Join(dir, "policy.current.json")
	dp, err := newDatapath(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := dp.pol.Evaluate(policy.Destination{Domain: "example.invalid", Proto: policy.ProtoTCP, Port: 80})
	if got.Action != policy.ActionBlock {
		t.Fatalf("committed BLOCK replaced by %s", got.Action)
	}
}

// VLESS: unknown UUID gets no response and no egress; unsupported commands
// are never relayed as TCP.
func TestEdgeVLESSUnknownUUIDRejected(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	addr, seen := fakeEgress(t)
	dp.cfg.Exits[0].SOCKSAddr = addr
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	go dp.handleVLESS(b)
	go func() {
		unknown := uuidBytes("00000000-0000-0000-0000-000000000000")
		hdr := []byte{0}
		hdr = append(hdr, unknown[:]...)
		hdr = append(hdr, 0, 1, 0, 80, 1, 93, 184, 216, 34)
		_, _ = a.Write(hdr)
	}()
	data, _ := io.ReadAll(a)
	if len(data) != 0 {
		t.Fatalf("unknown uuid received a response: %x", data)
	}
	seenNothing(t, seen)
}

func TestEdgeVLESSUnsupportedCommandNotRelayed(t *testing.T) {
	dp := newEdgeTestDatapath(t, edgeTestConfig(t))
	addr, seen := fakeEgress(t)
	dp.cfg.Exits[0].SOCKSAddr = addr
	a, b := net.Pipe()
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	go dp.handleVLESS(b)
	go func() {
		id := uuidBytes(dp.cfg.DeviceUUID)
		hdr := []byte{0}
		hdr = append(hdr, id[:]...)
		hdr = append(hdr, 0, 3, 0, 53, 1, 8, 8, 8, 8) // cmd=3 (UDP)
		_, _ = a.Write(hdr)
	}()
	data, _ := io.ReadAll(a)
	if !bytes.Equal(data, []byte{0, 0}) {
		t.Fatalf("expected bare accept frame then close, got %x", data)
	}
	seenNothing(t, seen)
}

// TR01 mirrors on the wire helpers.
func TestEdgeVLESSAcceptFrameIsVersionPlusAddonLen(t *testing.T) {
	var buf bytes.Buffer
	if err := transport.WriteAccept(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0, 0}) {
		t.Fatalf("accept frame %x, want 0000", buf.Bytes())
	}
}
