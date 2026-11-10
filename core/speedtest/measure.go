package speedtest

// Measurement client: one segment, one direction at a time (sequential by
// design — tests must be comparable), explicit budgets, cancellation via
// context, honest metrics. The Dialer decides the PATH being measured:
// direct dial (client→edge over the access link), the SOCKS transit
// adapter (edge→exit, crossing the real Trojan/VLESS hop), or the local
// tunnel (client→exit end-to-end).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Segment names the measured path kind.
type Segment string

const (
	SegClientEdge Segment = "client-edge" // client ↔ ingress edge
	SegEdgeExit   Segment = "edge-exit"   // edge ↔ exit through the transit profile
	SegEndToEnd   Segment = "e2e"         // client ↔ exit through the whole chain
	SegDirect     Segment = "direct"      // explicit opt-in: client ↔ exit directly
)

// Direction of the payload flow relative to the measured hop.
type Direction string

const (
	DirDown Direction = "down"
	DirUp   Direction = "up"
)

// Budget bounds ONE measurement job. Zero values take the defaults; the
// server clamps everything to its own caps anyway.
type Budget struct {
	BytesPerDirection int64         // default 8 MiB
	Duration          time.Duration // per direction, default 10 s
	Streams           int           // default 1, max 4
	RTTProbes         int           // default 16
	WarmupDuration    time.Duration // default 1 s, excluded from goodput
}

func (b Budget) withDefaults() Budget {
	if b.BytesPerDirection <= 0 {
		b.BytesPerDirection = 8 << 20
	}
	if b.Duration <= 0 {
		b.Duration = 10 * time.Second
	}
	if b.Streams <= 0 {
		b.Streams = 1
	}
	if b.Streams > 4 {
		b.Streams = 4
	}
	if b.RTTProbes <= 0 {
		b.RTTProbes = 16
	}
	if b.WarmupDuration < 0 {
		b.WarmupDuration = 0
	}
	return b
}

// EstimateBytes is the worst-case transfer estimate shown BEFORE the job
// starts (docs/DIAGNOSTICS.md: оценка расхода до старта).
func (b Budget) EstimateBytes() int64 {
	return 2 * b.withDefaults().BytesPerDirection // down + up
}

// Dialer opens the transport connection for the measurement.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

func defaultDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Spec is one measurement job: source, destination, path, budget.
type Spec struct {
	Segment   Segment
	Source    string // factual label, e.g. "client@host"
	Dest      string // factual label, e.g. "edge-ru"
	Endpoint  string // testpoint host:port AS DIALED
	Token     string
	Direction Direction // one direction per call; callers sequence both
	Budget    Budget
	// TransitProtocol documents the hop's actual profile for the report
	// (e.g. "trojan+tls/tcp") — shown, never guessed.
	TransitProtocol string
	// RateLimitNote, when set, records the applied user/account limit the
	// path is subject to (shown; the result marks bounded runs).
	RateLimitNote string
	// Dialer overrides the path; nil = direct dial.
	Dialer Dialer
}

// DirectionResult carries the metrics of one direction.
type DirectionResult struct {
	Direction  Direction `json:"direction"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
	Bytes      int64     `json:"bytes"`
	DurationS  float64   `json:"duration_s"`
	GoodputMbps float64  `json:"goodput_mbps"`
	// IntegrityOK: hash of the received (or acknowledged) stream equals
	// the deterministic generator's digest. nil = not verifiable (e.g. a
	// canceled short transfer is still reported, honestly).
	IntegrityOK *bool `json:"integrity_ok,omitempty"`

	// RTT probes: idle (before load) and loaded (during transfer).
	ProbesIdle     int     `json:"probes_idle"`
	RTTP50IdleMs   float64 `json:"rtt_p50_idle_ms"`
	RTTP95IdleMs   float64 `json:"rtt_p95_idle_ms"`
	ProbesLoaded   int     `json:"probes_loaded"`
	RTTP50LoadedMs float64 `json:"rtt_p50_loaded_ms,omitempty"`
	RTTP95LoadedMs float64 `json:"rtt_p95_loaded_ms,omitempty"`
	JitterMs       float64 `json:"jitter_ms"`
	// FailedProbeRatio is the share of UNSUCCESSFUL application probes
	// (0..1). It is NOT IP packet loss and is labeled as failed-probe
	// ratio in every surface (docs/SPEEDTEST.md).
	FailedProbeRatio float64 `json:"failed_probe_ratio"`
	WarmupExcluded   bool    `json:"warmup_excluded"`
	WarmupBytes      int64   `json:"warmup_bytes"`
}

// Result is one job outcome (history record, UI row, CLI JSON).
type Result struct {
	Schema     string    `json:"schema"`
	JobID      string    `json:"job_id"`
	Segment    Segment   `json:"segment"`
	Source     string    `json:"source"`
	Dest       string    `json:"dest"`
	Endpoint   string    `json:"endpoint"`
	TransitProtocol string `json:"transit_protocol,omitempty"`
	Direction  Direction `json:"direction"`
	Budget     Budget    `json:"budget"`
	StartedAt  time.Time `json:"started_at"`
	DurationS  float64   `json:"duration_s"`
	Metrics    DirectionResult `json:"metrics"`
	// RateLimited marks that a configured limit (not the path) plausibly
	// bounded the result; RateLimitNote carries the applied limit text.
	RateLimited  bool   `json:"rate_limited"`
	RateLimitNote string `json:"rate_limit_note,omitempty"`
	// PathStable records whether the route/profile stayed identical for
	// the whole job; a path switch SEGMENTS or voids the result (never
	// mixes bytes of different routes into one number).
	PathStable bool   `json:"path_stable"`
	PathNote   string `json:"path_note,omitempty"`
	Canceled   bool   `json:"canceled"`
}

// Measure runs one direction of one segment against the spec. ctx
// cancellation stops generation immediately; the result reports the bytes
// actually transferred as canceled — never silently zeroed.
func Measure(ctx context.Context, spec Spec, jobID string, startedAt time.Time) Result {
	spec.Budget = spec.Budget.withDefaults()
	res := Result{
		Schema: "ara.speedtest.result/v1", JobID: jobID,
		Segment: spec.Segment, Source: spec.Source, Dest: spec.Dest,
		Endpoint: spec.Endpoint, TransitProtocol: spec.TransitProtocol,
		Direction: spec.Direction, Budget: spec.Budget, StartedAt: startedAt.UTC(),
		RateLimitNote: spec.RateLimitNote, PathStable: true,
	}
	dial := spec.Dialer
	if dial == nil {
		dial = defaultDialer
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		},
		MaxConnsPerHost: 2,
		IdleConnTimeout: 2 * time.Second,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	res.Metrics = measureDirection(ctx, client, &spec)
	res.DurationS = time.Since(startedAt).Seconds()
	res.Canceled = ctx.Err() != nil
	res.RateLimited = res.Metrics.OK && rateLimitLikely(spec, res.Metrics)
	return res
}

func measureDirection(ctx context.Context, client *http.Client, spec *Spec) DirectionResult {
	out := DirectionResult{Direction: spec.Direction, FailedProbeRatio: 0}
	// idle latency first (before any load)
	idle, failed, idleErr := probeRTT(ctx, client, spec, spec.Budget.RTTProbes, nil)
	out.ProbesIdle = len(idle) + failed
	if out.ProbesIdle > 0 {
		out.FailedProbeRatio = float64(failed) / float64(out.ProbesIdle)
	}
	// every probe unanswered means the endpoint is not reachable in this
	// direction at all: report the honest failure with the probe evidence
	if idleErr != nil {
		out.Error = idleErr.Error()
		return out
	}
	out.RTTP50IdleMs, out.RTTP95IdleMs = percentiles(idle)
	out.JitterMs = jitter(idle)

	lp := &loadedProbe{}
	switch spec.Direction {
	case DirDown:
		n, dur, warmB, warmOK, integrity, err := runDownload(ctx, client, spec, lp)
		out.Bytes, out.WarmupBytes, out.WarmupExcluded = n, warmB, warmOK
		out.IntegrityOK = integrity
		if err != nil && ctx.Err() == nil {
			out.Error = err.Error()
			return out
		}
		out.OK = n > 0
		if dur > 0 {
			out.GoodputMbps = float64(n) * 8 / dur.Seconds() / 1e6
		}
		out.DurationS = dur.Seconds()
	case DirUp:
		n, dur, warmB, warmOK, integrity, err := runUpload(ctx, client, spec, lp)
		out.Bytes, out.WarmupBytes, out.WarmupExcluded = n, warmB, warmOK
		out.IntegrityOK = integrity
		if err != nil && ctx.Err() == nil {
			out.Error = err.Error()
			return out
		}
		out.OK = n > 0
		if dur > 0 {
			out.GoodputMbps = float64(n) * 8 / dur.Seconds() / 1e6
		}
		out.DurationS = dur.Seconds()
	default:
		out.Error = fmt.Sprintf("unknown direction %q", spec.Direction)
		return out
	}
	if ctx.Err() != nil && out.Error == "" {
		out.Error = "canceled: " + ctx.Err().Error()
	}
	loadedSamples := lp.samples()
	out.ProbesLoaded = len(loadedSamples)
	out.RTTP50LoadedMs, out.RTTP95LoadedMs = percentiles(loadedSamples)
	return out
}

// loadedProbe collects latency samples DURING the transfer (loaded RTT).
type loadedProbe struct {
	mu   sync.Mutex
	rtts []float64
}

func (l *loadedProbe) add(ms float64) {
	l.mu.Lock()
	l.rtts = append(l.rtts, ms)
	l.mu.Unlock()
}

func (l *loadedProbe) samples() []float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]float64(nil), l.rtts...)
}

// probeRTT performs up to n sequential echo probes. All-probes-failed is
// returned as an error so the caller reports an unreachable endpoint
// instead of a fake 0 Mbit/s.
func probeRTT(ctx context.Context, client *http.Client, spec *Spec, n int, onProbe func(float64)) (samples []float64, failed int, err error) {
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL(spec.Endpoint, "echo"), strings.NewReader("ara-rtt-probe-ara-rtt-probe-ara-rtt-probe"))
		if rerr != nil {
			failed++
			continue
		}
		req.Header.Set("Authorization", "Bearer "+spec.Token)
		resp, derr := client.Do(req)
		if derr != nil {
			failed++
			if i == 0 && ctx.Err() == nil {
				// surface reachability problems as the failure cause
				err = fmt.Errorf("endpoint unreachable: %v", derr)
			}
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			failed++
			if i == 0 {
				if resp.StatusCode == http.StatusUnauthorized {
					err = fmt.Errorf("endpoint authorization failed (HTTP 401)")
				} else {
					err = fmt.Errorf("endpoint refused probe (HTTP %d)", resp.StatusCode)
				}
			}
			continue
		}
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		samples = append(samples, ms)
		if onProbe != nil {
			onProbe(ms)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err == nil && len(samples) == 0 && failed > 0 {
		err = fmt.Errorf("all %d probes failed", failed)
	}
	return samples, failed, err
}

func endpointURL(endpoint, path string) string {
	return "http://" + endpoint + "/v1/" + path
}

// runDownload streams the payload, excluding the warmup window from
// goodput and verifying integrity against the deterministic stream.
func runDownload(ctx context.Context, client *http.Client, spec *Spec, lp *loadedProbe) (bytes int64, dur time.Duration, warmupBytes int64, warmupExcluded bool, integrity *bool, err error) {
	// the client picks the seed: the expected digest is computable locally
	seed := uint64(time.Now().UnixNano())
	url := endpointURL(spec.Endpoint, "download") + "?bytes=" + strconv.FormatInt(spec.Budget.BytesPerDirection, 10) +
		"&max_seconds=" + strconv.Itoa(int(spec.Budget.Duration.Seconds())) + "&seed=" + strconv.FormatUint(seed, 10)
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if rerr != nil {
		return 0, 0, 0, false, nil, rerr
	}
	req.Header.Set("Authorization", "Bearer "+spec.Token)
	resp, derr := client.Do(req)
	if derr != nil {
		return 0, 0, 0, false, nil, derr
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return 0, 0, 0, false, nil, fmt.Errorf("download refused: endpoint authorization failed (HTTP 401)")
		}
		return 0, 0, 0, false, nil, fmt.Errorf("download refused: HTTP %d", resp.StatusCode)
	}
	go func() {
		probeRTT(ctx, client, spec, spec.Budget.RTTProbes, func(ms float64) { lp.add(ms) })
	}()

	start := time.Now()
	warmupEnd := start.Add(spec.Budget.WarmupDuration)
	var measured int64
	var total int64
	buf := make([]byte, 64<<10)
	h := sha256.New()      // measured-range digest (goodput sample)
	hAll := sha256.New()   // whole-transfer digest (short-transfer fallback)
	for {
		if ctx.Err() != nil {
			break
		}
		if time.Since(start) > spec.Budget.Duration+spec.Budget.WarmupDuration {
			break
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			now := time.Now()
			total += int64(n)
			hAll.Write(buf[:n])
			if now.Before(warmupEnd) {
				warmupBytes += int64(n)
				warmupExcluded = true
			} else {
				measured += int64(n)
				h.Write(buf[:n])
			}
		}
		if rerr != nil {
			if rerr != io.EOF && ctx.Err() == nil {
				return measured, measuredDur(start, spec, warmupBytes, measured), warmupBytes, warmupExcluded, nil, rerr
			}
			break
		}
	}
	// a transfer that finished entirely inside the warmup window IS a
	// complete sample (fast link): use it instead of an empty measurement
	useAll := measured == 0 && total > 0
	if useAll {
		measured = total
		warmupExcluded = false
		warmupBytes = 0
	}
	if measured > 0 {
		expected := hashOfStreamRange(seed, 0, measured)
		got := hex.EncodeToString(hAll.Sum(nil))
		if !useAll {
			expected = hashOfStreamRange(seed, warmupBytes, measured)
			got = hex.EncodeToString(h.Sum(nil))
		}
		ok := expected == got
		integrity = &ok
	}
	return measured, measuredDur(start, spec, warmupBytes, measured), warmupBytes, warmupExcluded, integrity, nil
}

func measuredDur(start time.Time, spec *Spec, warmupBytes int64, measured int64) time.Duration {
	if warmupBytes > 0 && measured > 0 {
		return time.Since(start) - spec.Budget.WarmupDuration
	}
	return time.Since(start)
}

// runUpload generates and streams the payload with the same accounting;
// the server's hash echo verifies the received stream.
func runUpload(ctx context.Context, client *http.Client, spec *Spec, lp *loadedProbe) (bytes int64, dur time.Duration, warmupBytes int64, warmupExcluded bool, integrity *bool, err error) {
	pr, pw := io.Pipe()
	gen := newPayloadGen(uint64(time.Now().UnixNano()))
	localHash := sha256.New()
	start := time.Now()
	go func() {
		defer pw.Close()
		warmupEnd := start.Add(spec.Budget.WarmupDuration)
		buf := make([]byte, 64<<10)
		var written int64
		for written < spec.Budget.BytesPerDirection {
			if ctx.Err() != nil {
				return
			}
			chunk := int64(len(buf))
			if spec.Budget.BytesPerDirection-written < chunk {
				chunk = spec.Budget.BytesPerDirection - written
			}
			gen.fill(buf[:chunk])
			// local digest covers the generated stream; the server
			// independently hashes what ARRIVED — equality proves integrity
			// of the whole path including the testpoint
			localHash.Write(buf[:chunk])
			if time.Now().Before(warmupEnd) {
				warmupBytes += chunk
				warmupExcluded = true
			}
			if _, werr := pw.Write(buf[:chunk]); werr != nil {
				return
			}
			written += chunk
		}
	}()
	url := endpointURL(spec.Endpoint, "upload") + "?bytes=" + strconv.FormatInt(spec.Budget.BytesPerDirection, 10) +
		"&max_seconds=" + strconv.Itoa(int(spec.Budget.Duration.Seconds())+1)
	req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if rerr != nil {
		return 0, 0, 0, false, nil, rerr
	}
	req.Header.Set("Authorization", "Bearer "+spec.Token)
	go func() {
		probeRTT(ctx, client, spec, spec.Budget.RTTProbes, func(ms float64) { lp.add(ms) })
	}()
	resp, derr := client.Do(req)
	if derr != nil {
		return 0, 0, warmupBytes, warmupExcluded, nil, derr
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return 0, 0, warmupBytes, warmupExcluded, nil, fmt.Errorf("upload refused: endpoint authorization failed (HTTP 401)")
		}
		return 0, 0, warmupBytes, warmupExcluded, nil, fmt.Errorf("upload refused: HTTP %d", resp.StatusCode)
	}
	var ack struct {
		Received int64  `json:"received_bytes"`
		SHA      string `json:"sha256"`
		Complete bool   `json:"complete"`
	}
	if aerr := json.NewDecoder(resp.Body).Decode(&ack); aerr != nil {
		return 0, 0, warmupBytes, warmupExcluded, nil, aerr
	}
	measured := ack.Received - warmupBytes
	durFull := time.Since(start)
	if measured <= 0 && ack.Received > 0 {
		// finished inside the warmup window: the whole acknowledged
		// transfer is the sample
		measured = ack.Received
		warmupBytes = 0
		warmupExcluded = false
	} else if warmupExcluded && durFull > spec.Budget.WarmupDuration {
		durFull -= spec.Budget.WarmupDuration
	}
	ok := ack.SHA == hex.EncodeToString(localHash.Sum(nil))
	integrity = &ok
	return measured, durFull, warmupBytes, warmupExcluded, integrity, nil
}

// rateLimitLikely: within 12% of the configured limit from the note.
func rateLimitLikely(spec Spec, m DirectionResult) bool {
	if spec.RateLimitNote == "" || !m.OK || m.DurationS <= 0 {
		return false
	}
	note := strings.ToLower(spec.RateLimitNote)
	limit := firstNumberBefore(note, "мбит")
	if limit <= 0 {
		limit = firstNumberBefore(note, "mbit")
	}
	if limit <= 0 {
		return false
	}
	return math.Abs(m.GoodputMbps-limit)/limit <= 0.12
}

func firstNumberBefore(s, marker string) float64 {
	idx := strings.Index(s, marker)
	if idx <= 0 {
		return 0
	}
	start := idx
	for start > 0 && (s[start-1] >= '0' && s[start-1] <= '9' || s[start-1] == '.' || s[start-1] == ' ') {
		start--
	}
	v, _ := strconv.ParseFloat(strings.TrimSpace(s[start:idx]), 64)
	return v
}

func percentiles(samples []float64) (p50, p95 float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	p50 = s[(len(s)-1)/2]
	i95 := int(math.Ceil(0.95*float64(len(s)))) - 1
	if i95 < 0 {
		i95 = 0
	}
	if i95 >= len(s) {
		i95 = len(s) - 1
	}
	p95 = s[i95]
	return p50, p95
}

func jitter(samples []float64) float64 {
	if len(samples) < 2 {
		return 0
	}
	var sum float64
	for i := 1; i < len(samples); i++ {
		d := samples[i] - samples[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return sum / float64(len(samples)-1)
}
