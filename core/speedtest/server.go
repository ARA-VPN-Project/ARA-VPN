// Package speedtest implements the built-in path-speed diagnostics
// (docs/SPEEDTEST.md): authenticated test endpoints on ARA nodes, a
// measurement client with explicit byte/time/stream budgets, cancellation,
// and honest metrics — goodput per direction, RTT p50/p95, jitter, and
// the FAILED-PROBE ratio (never presented as IP packet loss).
//
// Security model: the server accepts ONLY explicitly configured bearer
// tokens, only its own clamped budgets, and only the endpoints it binds;
// there is no URL fetching, no shell, no relay — a request that is not
// one of the three typed endpoints is refused. Payload is synthetic
// (seeded PRNG), streamed both ways, integrity-checked via SHA-256
// without touching disk. The default path for user-side measurements is
// the ordinary tunnel: identity, ACL, transport and rate/quota limits
// apply unchanged; the result records when a configured limit bounded it.
package speedtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Protocol version of the test endpoints.
const ProtoVersion = "ara.speedtest/v1"

// Default server caps: conservative abuse bounds; operators may tighten
// them per deployment, never widen past these without a new review.
const (
	DefaultMaxBytesPerStream  int64 = 512 << 20 // 512 MiB
	DefaultMaxStreamDuration        = 30 * time.Second
	DefaultMaxConcurrent            = 4
	MaxHeaderBytes                  = 8 << 10
)

// Server is the authenticated test endpoint run on ARA nodes
// (cmd/ara-testpoint).
type Server struct {
	// Tokens is the allowed bearer tokens; empty map refuses everything.
	Tokens map[string]bool
	// MaxBytesPerStream / MaxStreamDuration / MaxConcurrent clamp every
	// client-requested budget (client budgets are advisory).
	MaxBytesPerStream  int64
	MaxStreamDuration  time.Duration
	MaxConcurrent      int
	// Now is overridable in tests.
	Now func() time.Time
	// OnRequest, when set, observes one audit line per accepted stream
	// (never includes tokens).
	OnRequest func(direction string, requested, granted int64)

	mu    sync.Mutex
	live  int
	angle uint64 // rotating payload seed
}

// NewServer fills defaults.
func NewServer(tokens []string) *Server {
	s := &Server{
		Tokens:             map[string]bool{},
		MaxBytesPerStream:  DefaultMaxBytesPerStream,
		MaxStreamDuration:  DefaultMaxStreamDuration,
		MaxConcurrent:      DefaultMaxConcurrent,
		Now:                time.Now,
	}
	for _, t := range tokens {
		s.Tokens[t] = true
	}
	return s
}

func (s *Server) auth(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	return s.Tokens[strings.TrimPrefix(h, "Bearer ")]
}

func (s *Server) acquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live >= s.MaxConcurrent {
		return false
	}
	s.live++
	return true
}

func (s *Server) release() {
	s.mu.Lock()
	s.live--
	s.mu.Unlock()
}

// Register mounts the typed endpoints on a mux. No other path exists.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/caps", s.handleCaps)
	mux.HandleFunc("/v1/download", s.handleDownload)
	mux.HandleFunc("/v1/upload", s.handleUpload)
	mux.HandleFunc("/v1/echo", s.handleEcho)
}

func (s *Server) handleCaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":             ProtoVersion,
		"max_bytes_per_stream": s.MaxBytesPerStream,
		"max_stream_seconds":   int(s.MaxStreamDuration.Seconds()),
		"max_concurrent":       s.MaxConcurrent,
	})
}

// parseBudget clamps the client-requested byte count to the server cap.
func (s *Server) parseBudget(r *http.Request) (int64, time.Duration, error) {
	q := r.URL.Query()
	var bytes int64 = 4 << 20 // default probe: 4 MiB
	if b := q.Get("bytes"); b != "" {
		if _, err := fmt.Sscanf(b, "%d", &bytes); err != nil || bytes < 0 {
			return 0, 0, errors.New("bad bytes")
		}
	}
	if bytes > s.MaxBytesPerStream {
		bytes = s.MaxBytesPerStream
	}
	d := s.MaxStreamDuration
	if ds := q.Get("max_seconds"); ds != "" {
		var sec int
		if _, err := fmt.Sscanf(ds, "%d", &sec); err != nil || sec < 0 || sec > 3600 {
			return 0, 0, errors.New("bad max_seconds")
		}
		if d2 := time.Duration(sec) * time.Second; d2 < d {
			d = d2
		}
	}
	if s.OnRequest != nil {
		s.OnRequest(r.URL.Path, bytes, bytes)
	}
	return bytes, d, nil
}

// handleDownload streams exactly bytes of synthetic payload; the stream
// self-terminates at the budget even if the client stalls. The seed comes
// from the client (or the server when absent) so the receiving side can
// hash-verify the deterministic stream.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	if !s.auth(r) {
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}
	if !s.acquire() {
		http.Error(w, `{"error":"CONFLICT: concurrent stream cap"}`, http.StatusTooManyRequests)
		return
	}
	defer s.release()
	n, d, err := s.parseBudget(r)
	if err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	seed := s.nextSeed()
	if qs := r.URL.Query().Get("seed"); qs != "" {
		if _, err := fmt.Sscanf(qs, "%d", &seed); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Total-Bytes", fmt.Sprint(n))
	w.Header().Set("X-Payload-Seed", fmt.Sprint(seed))
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).SetWriteDeadline(s.Now().Add(d))
	writePayloadStream(w, seed, n)
}

// handleUpload counts the received synthetic stream and answers with the
// received byte count and its SHA-256 so the client can verify integrity.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	if !s.auth(r) {
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}
	if !s.acquire() {
		http.Error(w, `{"error":"CONFLICT: concurrent stream cap"}`, http.StatusTooManyRequests)
		return
	}
	defer s.release()
	n, d, err := s.parseBudget(r)
	if err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(s.Now().Add(d))
	h := sha256.New()
	received, rerr := io.CopyN(h, r.Body, n)
	// a short read is an OUTCOME (client budget/cancel, deadline), not a
	// server error: report honestly how much arrived and its digest
	if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
		var ne net.Error
		if !(errors.As(rerr, &ne) && ne.Timeout()) && !strings.Contains(rerr.Error(), "body") && !strings.Contains(rerr.Error(), "closed") {
			http.Error(w, `{"error":"INTERNAL"}`, http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"received_bytes": received,
		"sha256":         hex.EncodeToString(h.Sum(nil)),
		"complete":       received == n,
		"short_read":     rerr != nil,
	})
}

// handleEcho answers a small POST with the same body: the RTT probe.
func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	if !s.auth(r) {
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}
	body := make([]byte, 64)
	n, _ := io.ReadFull(r.Body, body)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body[:n])
}

func (s *Server) nextSeed() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.angle++
	return s.angle
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// payloadGen is the deterministic synthetic stream: same seed ⇒ same byte
// sequence, so both sides hash-verify without storing anything. A seeded
// PRNG avoids trivially compressible zeros (a compression middlebox would
// otherwise fake goodput).
type payloadGen struct{ rng interface{ Read(p []byte) (int, error) } }

func newPayloadGen(seed uint64) *payloadGen {
	return &payloadGen{rng: rand.New(rand.NewSource(int64(seed)))}
}

func (g *payloadGen) fill(b []byte) {
	if _, err := g.rng.Read(b); err != nil {
		// math/rand.Read never errors; a failure would mean broken runtime
		for i := range b {
			b[i] = 0x5e
		}
	}
}

// writePayloadStream streams n bytes of the seed's stream.
func writePayloadStream(w io.Writer, seed uint64, n int64) error {
	g := newPayloadGen(seed)
	buf := make([]byte, 64<<10)
	var written int64
	for written < n {
		chunk := int64(len(buf))
		if n-written < chunk {
			chunk = n - written
		}
		g.fill(buf[:chunk])
		if _, err := w.Write(buf[:chunk]); err != nil {
			return err
		}
		written += chunk
	}
	return nil
}

// hashOfStreamRange hashes the seed's stream over [offset, offset+n) —
// the expected digest for a measured range that skipped warmup bytes.
func hashOfStreamRange(seed uint64, offset, n int64) string {
	g := newPayloadGen(seed)
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var skipped int64
	for skipped < offset {
		chunk := int64(len(buf))
		if offset-skipped < chunk {
			chunk = offset - skipped
		}
		g.fill(buf[:chunk])
		skipped += chunk
	}
	var done int64
	for done < n {
		chunk := int64(len(buf))
		if n-done < chunk {
			chunk = n - done
		}
		g.fill(buf[:chunk])
		h.Write(buf[:chunk])
		done += chunk
	}
	return hex.EncodeToString(h.Sum(nil))
}
