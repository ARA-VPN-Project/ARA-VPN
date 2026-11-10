// Package txlog is a minimal append-only durable transaction log: JSONL
// records with fsync-per-append and flock serialization. It exists so an
// executor can durably record its intent (full effect serialization)
// BEFORE mutating state and mark the outcome after, letting a retry
// recognize its own committed effect after a crash or write failure
// between the two (review S04/S06).
package txlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Log is one append-only file.
type Log struct {
	mu   sync.Mutex
	path string
}

// Open ensures the parent directory exists and returns the log handle.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &Log{path: path}, nil
}

// Append serializes writers across processes (flock on the log file),
// writes one JSON line and fsyncs. A torn final line is refused by Read:
// a torn record must never be interpreted as intent OR outcome.
func (l *Log) Append(v any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := flockExclusive(f); err != nil {
		return err
	}
	defer funlock(f)
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Read returns every record unmarshaled into dst. A torn final line (no
// trailing newline) or an unparsable line is an error: the log is the
// truth about intents, and guessing would defeat recovery.
func (l *Log) Read(dst any) error {
	b, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		return fmt.Errorf("transaction log %s torn: last record incomplete (operator inspection required)", l.path)
	}
	var all [][]byte
	for _, line := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
		if len(line) > 0 {
			all = append(all, line)
		}
	}
	return json.Unmarshal(joinRecords(all), dst)
}

func joinRecords(lines [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, line := range lines {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(line)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

var _ = bufio.NewReader // keep imports stable if helpers evolve
