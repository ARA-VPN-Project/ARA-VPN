package limits

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ScopeID identifies the accounting scope. Account and device scopes are
// enforced jointly (docs/LIMITS_QUOTAS.md): the device bucket is also
// debited to its account bucket.
type ScopeID struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
}

// QuotaConfig is the volume limit for one scope. nil = unlimited;
// 0 = zero quota (all chargeable traffic refused, never treated as
// unlimited).
type QuotaConfig struct {
	TotalBytes *int64 `json:"total_bytes,omitempty"` // download+upload aggregate
	Period     Period `json:"period"`
}

func (c QuotaConfig) Validate() error {
	if c.TotalBytes != nil && *c.TotalBytes < 0 {
		return fmt.Errorf("total_bytes must be >= 0 (0 = zero quota, null = unlimited)")
	}
	if _, err := c.Period.Location(); err != nil {
		return err
	}
	if _, _, err := c.Period.Window(time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

// RecKind is the journal record kind. The journal is append-only and
// replayed on load; sequence numbers make replay idempotent.
type RecKind string

const (
	RecReserve    RecKind = "reserve"    // n bytes reserved durably before transfer
	RecCheckpoint RecKind = "checkpoint" // reconcile a reservation to actual usage
	RecAdjust     RecKind = "adjust"     // operator manual adjustment (audited)
)

// Journal format versions (review T07): v1 checkpoint records carried the
// DELTA relative to the reservation; v2 (V=2) records carry the ACTUAL
// charged bytes. The version is an explicit field — it is never guessed
// from the sign of Bytes, because v1 delta 0/positive is ambiguous with
// v2 actual. Legacy v1 journals are migrated once (with a backup copy)
// by exact v1 replay semantics before any tracker consumes them.
type Rec struct {
	Seq     uint64    `json:"seq"`
	Scope   ScopeID   `json:"scope"`
	Kind    RecKind   `json:"kind"`
	Bytes   int64     `json:"bytes"` // v2: reserve +batch, checkpoint actual, adjust ±
	V       int       `json:"v,omitempty"`
	BatchID string    `json:"batch_id,omitempty"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor,omitempty"` // operator identity for adjust
}

// JournalVersion is the record version written by this build.
const JournalVersion = 2

// Journal is the durable append-only store for quota records. Implementations
// must fsync before returning from Append (crash between transfer and
// record must lose at most the in-flight reservation batch, never the
// checkpointed history).
type Journal interface {
	Append(rec Rec) error
	Load() ([]Rec, error)
}

// FileJournal is a JSONL journal with fsync-per-append. One file per state
// dir; compaction is an operator maintenance action, not automatic, so the
// crash story stays simple.
type FileJournal struct {
	mu   sync.Mutex
	path string
	next uint64
}

func OpenFileJournal(stateDir string) (*FileJournal, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	j := &FileJournal{path: filepath.Join(stateDir, "usage.journal.jsonl")}
	// V04: the legacy migration is part of the public open path; it runs
	// under the journal's cross-process file lock, creates a fsynced
	// backup, and atomically replaces the journal (dir fsynced).
	if err := j.migrateLegacyIfNeeded(); err != nil {
		return nil, err
	}
	recs, err := j.Load()
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if r.Seq >= j.next {
			j.next = r.Seq + 1
		}
	}
	return j, nil
}

// Append writes and fsyncs one record; Seq is assigned here to keep
// monotonic order across callers. Records are stamped with the current
// journal version. The append holds the journal's STABLE lock file (the
// same one migration uses) — never the journal inode itself, because the
// journal is replaced by rename during migration (review W04).
func (j *FileJournal) Append(rec Rec) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	// acquire the stable lock BEFORE opening the mutable file
	lockf, err := os.OpenFile(j.lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("journal lock open: %w", err)
	}
	defer lockf.Close()
	if err := flockExclusive(lockf); err != nil {
		return fmt.Errorf("journal lock: %w", err)
	}
	defer funlock(lockf)
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	rec.Seq = j.next
	if rec.V == 0 {
		rec.V = JournalVersion
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	j.next++
	return nil
}

// ErrMigrationRequired is returned when a journal needs the legacy
// (version-less) migration before it can be read.
var ErrMigrationRequired = fmt.Errorf("MIGRATION_REQUIRED: legacy quota journal needs migration (run ara or the journal open path; never edit by hand)")

// scanVersions classifies the journal by RAW json content (review W05):
// the "v" field's PRESENCE is distinguished from its value — a missing
// field is the legacy writer's signature, while an explicit 0, null,
// negative, 1, a future number or a non-numeric type is an unsupported
// record that must be refused before any byte of the original is
// touched. Mixed legacy+versioned files are refused as ambiguous.
func scanVersions(b []byte) (legacy, versioned int, err error) {
	for i, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(line, &raw) != nil {
			return 0, 0, fmt.Errorf("journal line %d unreadable: operator inspection required", i+1)
		}
		vRaw, present := raw["v"]
		if !present {
			legacy++
			continue
		}
		trimmed := string(vRaw)
		switch {
		case trimmed == "null":
			return 0, 0, fmt.Errorf("journal line %d: explicit null version is unsupported", i+1)
		case len(trimmed) > 0 && trimmed[0] == '"':
			return 0, 0, fmt.Errorf("journal line %d: version must be a number, got a string", i+1)
		}
		var n int
		if _, err := fmt.Sscanf(trimmed, "%d", &n); err != nil {
			return 0, 0, fmt.Errorf("journal line %d: version %s is not an integer", i+1, trimmed)
		}
		switch {
		case n == 0:
			return 0, 0, fmt.Errorf("journal line %d: explicit v=0 is unsupported (not a legacy marker)", i+1)
		case n == 1:
			return 0, 0, fmt.Errorf("journal line %d: explicit v1 (delta checkpoint semantics) is not interpreted directly", i+1)
		case n < 0:
			return 0, 0, fmt.Errorf("journal line %d: negative version %d is invalid", i+1, n)
		case n > JournalVersion:
			return 0, 0, fmt.Errorf("journal line %d: format v%d is newer than supported v%d", i+1, n, JournalVersion)
		default:
			versioned++
		}
		if legacy > 0 && versioned > 0 {
			return 0, 0, fmt.Errorf("journal mixes legacy (version-less) and versioned records: refusing ambiguous provenance")
		}
	}
	return legacy, versioned, nil
}

// Load reads all records with the explicit supported-version table
// (review V05):
//
//	v == JournalVersion (2) — supported;
//	v == 1                  — refused: explicit v1 uses delta checkpoint
//	                          semantics; migration handles version-less
//	                          legacy files, an explicitly marked v1 file
//	                          is refused instead of reinterpreted;
//	v <= 0 with a version   — refused (invalid);
//	v > JournalVersion      — refused (newer format);
//	mixed versions          — refused (ambiguous provenance).
//
// A torn final line (crash during write) is an error: conservative
// behavior is to refuse chargeable traffic until an operator inspects,
// never a silent drop of a possibly-spent reservation.
func (j *FileJournal) Load() ([]Rec, error) {
	b, err := os.ReadFile(j.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if legacy, _, verr := scanVersions(b); verr != nil {
		return nil, verr
	} else if legacy > 0 {
		return nil, ErrMigrationRequired
	}
	var recs []Rec
	seen := map[int]bool{}
	for i, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var r Rec
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("journal line %d unreadable: %w (operator inspection required)", i+1, err)
		}
		switch {
		case r.V == JournalVersion:
			// supported
		case r.V == 1:
			return nil, fmt.Errorf("journal line %d: explicit v1 (delta checkpoint semantics) is not interpreted directly; %w", i+1, ErrMigrationRequired)
		case r.V <= 0:
			return nil, fmt.Errorf("journal line %d: missing or invalid format version v=%d; %w", i+1, r.V, ErrMigrationRequired)
		default:
			return nil, fmt.Errorf("journal line %d: format v%d is newer than supported v%d", i+1, r.V, JournalVersion)
		}
		seen[r.V] = true
		if len(seen) > 1 {
			return nil, fmt.Errorf("journal mixes format versions %v: refusing ambiguous provenance", keysOf(seen))
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func keysOf(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortIntsAsc(out)
	return out
}

func sortIntsAsc(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// migrateLegacyIfNeeded performs the LEGACY journal upgrade (review
// V04/W04/W05) as ONE transaction on the STABLE lock file:
//
//  1. acquire usage.journal.jsonl.lock (the same object Append uses) —
//     BEFORE opening/reading the mutable journal;
//  2. read the journal and classify it from THIS under-lock snapshot
//     (raw-JSON version scan: only truly version-less records migrate;
//     explicit 0/null/1/negative/future/wrong-type refuse; mixed refuses);
//  3. compute the migrated content from the same under-lock snapshot
//     with exact v1 semantics (actual = reserved of the open batch +
//     delta; checkpoint0 = full charge; open reserve stays open);
//  4. backup the original (fsynced, one-time), write a temp file
//     (fsynced), rename, fsync the directory — every error is returned.
//
// A crash before the rename leaves the original intact and the next open
// simply repeats; repeat after completion is a no-op. Writers of the OLD
// schema do not know this lock: concurrent old-writer operation during
// migration requires a controlled stop/upgrade, advisory locking cannot
// stop them (documented limitation).
func (j *FileJournal) migrateLegacyIfNeeded() error {
	// 1. the stable lock, before touching the journal
	lockf, err := os.OpenFile(j.lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("migration lock open: %w", err)
	}
	defer lockf.Close()
	if err := flockExclusive(lockf); err != nil {
		return fmt.Errorf("migration lock: %w", err)
	}
	defer funlock(lockf)

	// 2. read and classify the under-lock snapshot
	b, err := os.ReadFile(j.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	legacy, versioned, verr := scanVersions(b)
	if verr != nil {
		return verr
	}
	if legacy == 0 {
		return nil // nothing to migrate
	}
	if versioned > 0 {
		return fmt.Errorf("journal mixes legacy and versioned records: refusing ambiguous migration")
	}
	var parsed []Rec
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var r Rec
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("legacy journal line unreadable: %w (operator inspection required)", err)
		}
		parsed = append(parsed, r)
	}
	// 3. compute from the SAME under-lock snapshot (exact v1 semantics)
	type openBatch struct{ reserved int64 }
	opens := map[ScopeID]map[string]openBatch{}
	migrated := make([]Rec, 0, len(parsed))
	for _, r := range parsed {
		if _, ok := opens[r.Scope]; !ok {
			opens[r.Scope] = map[string]openBatch{}
		}
		switch r.Kind {
		case RecReserve:
			opens[r.Scope][r.BatchID] = openBatch{reserved: r.Bytes}
			r.V = JournalVersion
			migrated = append(migrated, r)
		case RecCheckpoint:
			if ob, ok := opens[r.Scope][r.BatchID]; ok {
				r.Bytes = ob.reserved + r.Bytes
				if r.Bytes < 0 {
					return fmt.Errorf("legacy journal: checkpoint for batch %q yields negative actual %d; refusing (operator inspection required)", r.BatchID, r.Bytes)
				}
				delete(opens[r.Scope], r.BatchID)
			} else if r.Bytes < 0 {
				// a negative delta with no open batch cannot represent a
				// charge; dropping it can only ever be conservative
				continue
			}
			r.V = JournalVersion
			migrated = append(migrated, r)
		default:
			r.V = JournalVersion
			migrated = append(migrated, r)
		}
	}
	// 4. backup: atomically published (review X02). The final name
	// appears only after a complete fsynced write via rename+dirsync. An
	// EXISTING backup must match the intact original byte-for-byte (it
	// can only come from an earlier interrupted attempt on the same
	// original); an invalid mismatch is regenerated from the intact
	// original; a VALID-looking but different backup refuses (origin
	// cannot be proven).
	backup := j.path + ".v1.bak"
	if existing, err := os.ReadFile(backup); err == nil {
		switch {
		case bytes.Equal(existing, b):
			// complete copy from an earlier interrupted attempt: keep it
		case len(existing) == 0 || backupInvalid(existing):
			// invalid/partial copy + intact original: safe to republish
			// the true original (the journal below is untouched legacy)
			if err := atomicPublish(backup, b); err != nil {
				return fmt.Errorf("legacy journal backup republish failed: %w", err)
			}
		default:
			return fmt.Errorf("existing backup %s differs from the intact original and is itself valid; refusing to overwrite (operator inspection required)", backup)
		}
	} else if os.IsNotExist(err) {
		if err := atomicPublish(backup, b); err != nil {
			return fmt.Errorf("legacy journal backup failed: %w", err)
		}
	} else {
		return fmt.Errorf("legacy journal backup check failed: %w", err)
	}
	// 5. temp file (fsynced), atomic rename, directory fsync
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range migrated {
		if err := enc.Encode(migrated[i]); err != nil {
			return err
		}
	}
	tmp := j.path + ".migrate.tmp"
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := tf.Write(buf.Bytes()); err != nil {
		tf.Close()
		os.Remove(tmp)
		return err
	}
	if err := tf.Sync(); err != nil {
		tf.Close()
		os.Remove(tmp)
		return fmt.Errorf("migrated journal fsync failed: %w", err)
	}
	if err := tf.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, j.path); err != nil {
		os.Remove(tmp)
		return err
	}
	d, err := os.Open(filepath.Dir(j.path))
	if err != nil {
		return fmt.Errorf("journal directory open for fsync failed: %w", err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("journal directory fsync failed: %w", err)
	}
	return d.Close()
}

// lockPath is the migration/writer lock next to the journal.
func (j *FileJournal) lockPath() string { return j.path + ".lock" }

// backupInvalid reports whether content is NOT a fully parseable journal
// (partial write, torn line, garbage). A syntactically complete copy may
// still be from another transaction — the caller must additionally match
// it against the intact original.
func backupInvalid(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var r Rec
		if json.Unmarshal(line, &r) != nil {
			return true
		}
	}
	return false
}

// atomicPublish writes data to a unique temp file in the same directory,
// fsyncs it, renames it onto path and fsyncs the directory. The final
// path never holds a partial file (review X02).
func atomicPublish(path string, data []byte) error {
	dir := filepath.Dir(path)
	tf, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	defer os.Remove(tmp)
	if _, err := tf.Write(data); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Sync(); err != nil {
		tf.Close()
		return fmt.Errorf("temp file fsync failed: %w", err)
	}
	if err := tf.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("directory open for fsync failed: %w", err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("directory fsync failed: %w", err)
	}
	return d.Close()
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:]) // torn tail without newline
	}
	return out
}
