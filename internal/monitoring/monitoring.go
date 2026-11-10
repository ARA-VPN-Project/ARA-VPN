// Package monitoring provides bounded availability sampling for the
// Control Center dashboard (G-wave): node/link state snapshots and
// external control-target probes, stored as a compact JSONL ring.
// No synthetic data — every record comes from a real observation.
package monitoring

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Sample is one observation of a node/path/target at a point in time.
type Sample struct {
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"` // node, target, or traffic
	Target    string    `json:"target"`
	State     string    `json:"state"` // healthy|degraded|down|unknown
	RTTMs     *float64  `json:"rtt_ms,omitempty"`
	DownMbps  *float64  `json:"down_mbps,omitempty"`
	UpMbps    *float64  `json:"up_mbps,omitempty"`
	Source    string    `json:"source,omitempty"` // probe method label
	FailCount int       `json:"fail_count,omitempty"`
}

// Store is a bounded JSONL ring of samples.
type Store struct {
	mu      sync.Mutex
	path    string
	maxRecs int
	buf     []Sample
	archive *sql.DB
}

// OpenStore opens (or creates) a monitoring ring at dir/monitoring.jsonl.
func OpenStore(dir string, maxRecords int) (*Store, error) {
	if maxRecords <= 0 {
		maxRecords = 2000
	}
	s := &Store{path: filepath.Join(dir, "monitoring.jsonl"), maxRecs: maxRecords}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const limit = 4 << 20
	bounded := &io.LimitedReader{R: f, N: limit + 1}
	decoder := json.NewDecoder(bounded)
	for {
		var sample Sample
		err := decoder.Decode(&sample)
		if bounded.N == 0 {
			return nil, fmt.Errorf("oversized monitoring history")
		}
		if errors.Is(err, io.EOF) {
			return s, nil
		}
		if err != nil {
			return nil, err
		}
		if len(s.buf) == maxRecords {
			return nil, fmt.Errorf("too many monitoring records")
		}
		s.buf = append(s.buf, sample)
	}
}

// Record appends one sample durably (0600, fsync, dir sync).
func (s *Store) Record(samples ...Sample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.buf
	if len(old)+len(samples) > s.maxRecs {
		old = old[min(len(old), len(old)+len(samples)-s.maxRecs):]
	}
	samples = samples[max(0, len(samples)-s.maxRecs):]
	next := make([]Sample, 0, len(old)+len(samples))
	next = append(next, old...)
	next = append(next, samples...)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".mon-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	enc := json.NewEncoder(f)
	for _, rec := range next {
		if err := enc.Encode(rec); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		d.Close()
		return err
	}
	defer d.Close()
	s.buf = next
	if err := d.Sync(); err != nil {
		return err
	}
	if s.archive != nil {
		return s.archiveSamples(samples)
	}
	return nil
}

// History returns the most recent n samples (all if n<=0).
func (s *Store) History(n int) []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 || n > len(s.buf) {
		n = len(s.buf)
	}
	out := make([]Sample, n)
	copy(out, s.buf[len(s.buf)-n:])
	return out
}
