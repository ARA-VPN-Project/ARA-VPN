package speedtest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func startTestpoint(t *testing.T, tokens ...string) *httptest.Server {
	t.Helper()
	s := NewServer(tokens)
	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// dialTo builds a Dialer that sends every connection to the test server:
// the same trick the edge↔exit runner uses to force the measurement
// through a specific transit path (endpoint label stays decoupled from
// the actual route).
func dialTo(tsURL string) Dialer {
	target := strings.TrimPrefix(tsURL, "http://")
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
}

func TestMeasureDownAndUpHappyPath(t *testing.T) {
	ts := startTestpoint(t, "tok-1")
	budget := Budget{BytesPerDirection: 2 << 20, Duration: 5 * time.Second, RTTProbes: 6, WarmupDuration: 100 * time.Millisecond}

	for _, dir := range []Direction{DirDown, DirUp} {
		res := Measure(context.Background(), Spec{
			Segment: SegClientEdge, Source: "client", Dest: "edge-ru",
			Endpoint: "edge.ara.lab:1", Token: "tok-1", Direction: dir,
			Budget: budget, Dialer: dialTo(ts.URL),
		}, "job-"+string(dir), time.Now())
		if !res.Metrics.OK {
			t.Fatalf("%s: not ok: %s", dir, res.Metrics.Error)
		}
		if res.Metrics.GoodputMbps <= 0 {
			t.Fatalf("%s: goodput %.2f", dir, res.Metrics.GoodputMbps)
		}
		if res.Metrics.IntegrityOK == nil || !*res.Metrics.IntegrityOK {
			t.Fatalf("%s: integrity not verified: %v", dir, res.Metrics.IntegrityOK)
		}
		if res.Metrics.ProbesIdle == 0 {
			t.Fatalf("%s: no idle RTT probes", dir)
		}
		if res.Metrics.RTTP50IdleMs <= 0 {
			t.Fatalf("%s: rtt p50 %.2f must be > 0 on loopback", dir, res.Metrics.RTTP50IdleMs)
		}
		if res.Metrics.FailedProbeRatio != 0 {
			t.Fatalf("%s: failed probe ratio %.2f on healthy endpoint", dir, res.Metrics.FailedProbeRatio)
		}
	}
}

func TestWrongTokenHonestFailure(t *testing.T) {
	ts := startTestpoint(t, "tok-1")
	res := Measure(context.Background(), Spec{
		Segment: SegEdgeExit, Source: "edge", Dest: "exit-a",
		Endpoint: "x:1", Token: "WRONG", Direction: DirDown,
		Budget: Budget{RTTProbes: 3}, Dialer: dialTo(ts.URL),
	}, "job-auth", time.Now())
	if res.Metrics.OK {
		t.Fatal("wrong token must not produce a result")
	}
	if !strings.Contains(res.Metrics.Error, "authorization") {
		t.Fatalf("error must say authorization, got: %s", res.Metrics.Error)
	}
	// honest failure: no fake zero-speed success, no fake packet loss
	if res.Metrics.Bytes != 0 && res.Metrics.IntegrityOK != nil && *res.Metrics.IntegrityOK {
		t.Fatal("unauthorized run must not verify integrity")
	}
}

func TestUnreachableEndpointNoFakeZero(t *testing.T) {
	// a dialer that always refuses: the result must say WHY, not report
	// a completed measurement of 0 Mbit/s
	res := Measure(context.Background(), Spec{
		Segment: SegEdgeExit, Source: "edge", Dest: "exit-dead",
		Endpoint: "x:1", Token: "t", Direction: DirDown,
		Budget: Budget{RTTProbes: 2, Duration: time.Second},
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("connect: connection refused")
		},
	}, "job-dead", time.Now())
	if res.Metrics.OK {
		t.Fatal("unreachable endpoint reported as ok")
	}
	if !strings.Contains(res.Metrics.Error, "unreachable") && !strings.Contains(res.Metrics.Error, "refused") {
		t.Fatalf("honest cause expected, got: %s", res.Metrics.Error)
	}
	if res.Metrics.GoodputMbps != 0 {
		t.Fatalf("unreachable run must not invent goodput: %.2f", res.Metrics.GoodputMbps)
	}
}

func TestCancelStopsGeneration(t *testing.T) {
	ts := startTestpoint(t, "tok-1")
	ctx, cancel := context.WithCancel(context.Background())
	started := time.Now()
	go func() {
		time.Sleep(400 * time.Millisecond)
		cancel()
	}()
	res := Measure(ctx, Spec{
		Segment: SegClientEdge, Source: "client", Dest: "edge-ru",
		Endpoint: "x:1", Token: "tok-1", Direction: DirUp,
		Budget: Budget{BytesPerDirection: 512 << 20, Duration: 30 * time.Second, WarmupDuration: 0},
		Dialer: dialTo(ts.URL),
	}, "job-cancel", started)
	if !res.Canceled {
		t.Fatalf("canceled flag expected: %+v", res)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("cancel did not stop generation promptly (%.1fs)", time.Since(started).Seconds())
	}
	// partial result may exist but must not pretend completeness
	if res.Metrics.IntegrityOK != nil && *res.Metrics.IntegrityOK && res.Metrics.Bytes >= 512<<20 {
		t.Fatal("canceled run reported complete integrity over the full budget")
	}
}

func TestServerCapsClampClientBudget(t *testing.T) {
	s := NewServer([]string{"tok"})
	s.MaxBytesPerStream = 1 << 20 // 1 MiB cap
	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	res := Measure(context.Background(), Spec{
		Segment: SegClientEdge, Source: "c", Dest: "e",
		Endpoint: "x:1", Token: "tok", Direction: DirDown,
		Budget: Budget{BytesPerDirection: 100 << 20, Duration: 5 * time.Second, WarmupDuration: 0},
		Dialer: dialTo(ts.URL),
	}, "job-clamp", time.Now())
	if !res.Metrics.OK {
		t.Fatalf("clamped run failed: %s", res.Metrics.Error)
	}
	if res.Metrics.Bytes > 1<<20 {
		t.Fatalf("server cap ignored: %d bytes", res.Metrics.Bytes)
	}
}

func TestEstimateBytesShownBeforeStart(t *testing.T) {
	b := Budget{BytesPerDirection: 8 << 20}
	if got := b.EstimateBytes(); got != 2*8<<20 {
		t.Fatalf("estimate %d", got)
	}
}

func TestAnalyzeBottleneckHypotheses(t *testing.T) {
	// first hop fine, chain slow → bottleneck past the first hop
	a := Analyze([]Observation{
		{Segment: SegClientEdge, Direction: DirDown, OK: true, GoodputMbps: 90},
		{Segment: SegEndToEnd, Direction: DirDown, OK: true, GoodputMbps: 20},
	})
	found := false
	for _, h := range a.Hypotheses {
		if h.Cause == "bottleneck.past_first_hop" {
			found = true
			if h.Confidence != "medium" || len(h.Evidence) < 2 {
				t.Fatalf("hypothesis quality: %+v", h)
			}
		}
	}
	if !found {
		t.Fatalf("past-first-hop hypothesis missing: %+v", a)
	}

	// reversed: first hop slow
	a2 := Analyze([]Observation{
		{Segment: SegClientEdge, Direction: DirDown, OK: true, GoodputMbps: 10},
		{Segment: SegEndToEnd, Direction: DirDown, OK: true, GoodputMbps: 80},
	})
	found2 := false
	for _, h := range a2.Hypotheses {
		if h.Cause == "bottleneck.client_edge" {
			found2 = true
		}
	}
	if !found2 {
		t.Fatalf("client-edge hypothesis missing: %+v", a2)
	}

	// failure reported as unreachable, with high confidence
	a3 := Analyze([]Observation{
		{Segment: SegEdgeExit, Direction: DirDown, OK: false, Error: "connect: connection refused", FailedProbeRatio: 1},
	})
	if len(a3.Hypotheses) == 0 || a3.Hypotheses[0].Cause != "unreachable.edge-exit" || a3.Hypotheses[0].Confidence != "high" {
		t.Fatalf("unreachable hypothesis: %+v", a3)
	}

	// rate limit note becomes the top hypothesis
	a4 := Analyze([]Observation{
		{Segment: SegClientEdge, Direction: DirDown, OK: true, GoodputMbps: 9.8, RateLimited: true, RateLimitNote: "10 mbit/s"},
	})
	if a4.Hypotheses[0].Cause != "bounded.by_limit" {
		t.Fatalf("limit hypothesis must be first: %+v", a4.Hypotheses)
	}
	// never subtract: no hypothesis computes a chain value
	for _, h := range a4.Hypotheses {
		if strings.Contains(h.DetailEN, "Mbit/s remaining") || strings.Contains(h.DetailRU, "остаток") {
			t.Fatal("analyzer must not derive chain speed by subtraction")
		}
	}
}

func TestPercentilesAndJitter(t *testing.T) {
	p50, p95 := percentiles([]float64{10, 20, 30, 40, 100})
	if p50 != 30 {
		t.Fatalf("p50 %.1f", p50)
	}
	if p95 != 100 {
		t.Fatalf("p95 %.1f", p95)
	}
	if j := jitter([]float64{10, 12, 10}); j > 2.01 || j < 1.3 {
		t.Fatalf("jitter %.2f", j)
	}
	if _, _ = percentiles(nil); false {
		t.Fatal("unreachable")
	}
	if j := jitter(nil); j != 0 {
		t.Fatal("empty jitter must be 0 (no data is not a zero measurement)")
	}
}
