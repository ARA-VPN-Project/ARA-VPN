// Control-plane audit: append-only JSONL of admin actions with stable
// metadata (actor, action, object, revision, result, time) and no secrets
// (docs/SECURITY.md: immutable audit metadata, no secrets in audit).
package controlstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry is one admin action record.
type AuditEntry struct {
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	ObjectID string    `json:"object_id,omitempty"`
	Revision int64     `json:"revision,omitempty"`
	Result   string    `json:"result"` // ok | denied | error
	Detail   string    `json:"detail,omitempty"`
}

// Audit is the JSONL sink.
type Audit struct {
	mu   sync.Mutex
	path string
}

func OpenAudit(stateDir string) (*Audit, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	return &Audit{path: filepath.Join(stateDir, "audit.jsonl")}, nil
}

// Append writes one entry, fsynced, with server-side timestamps.
func (a *Audit) Append(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	e.At = time.Now().UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Tail returns the last n entries (oldest first) for the admin UI.
func (a *Audit) Tail(n int) ([]AuditEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := os.ReadFile(a.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var all []AuditEntry
	for _, line := range splitJSONLines(b) {
		var e AuditEntry
		if json.Unmarshal(line, &e) == nil {
			all = append(all, e)
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

func splitJSONLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	return out
}
