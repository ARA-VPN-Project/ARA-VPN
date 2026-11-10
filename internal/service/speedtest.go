// Speedtest jobs (docs/SPEEDTEST.md): create → run → result/history with
// explicit budgets, cancellation, rate-limit marking and a redacted
// export. One job per host at a time (file lock). Results append to the
// history JSONL; exports never include tokens, device UUIDs, invite or
// admin keys.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aravpn/core/speedtest"
	"aravpn/internal/txlog"
)

// SpeedtestDirs returns the speedtest state layout.
func (s *StateDir) SpeedtestDir() string { return filepath.Join(s.Root, "speedtest") }

func (s *StateDir) speedtestJobsDir() string { return filepath.Join(s.SpeedtestDir(), "jobs") }

func (s *StateDir) SpeedtestHistoryPath() string {
	return filepath.Join(s.SpeedtestDir(), "history.jsonl")
}

// SpeedtestBudgets presets. Quick: a bounded smoke check; Extended: more
// bytes for a stable sample. Both are clamped by the server caps anyway
// (docs/SPEEDTEST.md: initial safe budgets, justified by lab runs).
var SpeedtestBudgetPresets = map[string]speedtest.Budget{
	"quick":    {BytesPerDirection: 8 << 20, Duration: 10 * time.Second, RTTProbes: 16, WarmupDuration: time.Second},
	"extended": {BytesPerDirection: 64 << 20, Duration: 20 * time.Second, RTTProbes: 24, WarmupDuration: 2 * time.Second},
}

// SpeedtestJob is the durable job record.
type SpeedtestJob struct {
	ID        string            `json:"id"`
	Segment   string            `json:"segment"`
	Direction string            `json:"direction"` // down|up|both
	ExitID    string            `json:"exit_id,omitempty"`
	Dest      string            `json:"dest"`
	Endpoint  string            `json:"endpoint"`
	BudgetKey string            `json:"budget"` // quick|extended|custom
	Notes     map[string]string `json:"notes,omitempty"`
	Status    string            `json:"status"` // running|done|failed|canceled
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	Results   []speedtest.Result `json:"results,omitempty"`
	Analysis  *speedtest.Analysis `json:"analysis,omitempty"`
	Error     string            `json:"error,omitempty"`
}

func (s *Service) speedtestJobPath(id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/\\.") {
		return "", fmt.Errorf("VALIDATION_FAILED: job id %q invalid", id)
	}
	return filepath.Join(s.State.speedtestJobsDir(), id+".json"), nil
}

// SpeedtestAcquire takes the one-job-per-host lock (0600 file with the
// job id). Stale locks (older than 10 min) are broken: a crashed runner
// must not block diagnostics forever.
func (s *Service) SpeedtestAcquire(jobID string) (func(), error) {
	if err := os.MkdirAll(s.State.SpeedtestDir(), 0o700); err != nil {
		return nil, err
	}
	lock := filepath.Join(s.State.SpeedtestDir(), "run.lock")
	if fi, err := os.Stat(lock); err == nil && time.Since(fi.ModTime()) < 10*time.Minute {
		b, _ := os.ReadFile(lock)
		return nil, fmt.Errorf("CONFLICT: another speedtest job is running (%s); cancel it or wait", strings.TrimSpace(string(b)))
	}
	if err := os.WriteFile(lock, []byte(jobID+"\n"), 0o600); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(lock) }, nil
}

func newJobID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sp-%d", time.Now().UnixNano())
	}
	return "sp-" + hex.EncodeToString(b[:])
}

// SpeedtestRunJob executes a single-direction spec as a typed job:
// persists the record, runs, appends history, returns the result. The
// caller sequences directions (both = two jobs joined into one record).
func (s *Service) SpeedtestRunJob(ctx context.Context, spec speedtest.Spec, budgetKey string, notes map[string]string, now time.Time) (*SpeedtestJob, error) {
	job := &SpeedtestJob{
		ID: newJobID(), Segment: string(spec.Segment), Direction: string(spec.Direction),
		Dest: spec.Dest, Endpoint: spec.Endpoint, BudgetKey: budgetKey,
		Notes: notes, Status: "running", CreatedAt: now.UTC(),
	}
	if err := s.speedtestSaveJob(job); err != nil {
		return nil, err
	}
	res := speedtest.Measure(ctx, spec, job.ID, now)
	job.UpdatedAt = time.Now().UTC()
	job.Results = []speedtest.Result{res}
	switch {
	case ctx.Err() != nil:
		job.Status = "canceled"
	case res.Metrics.OK:
		job.Status = "done"
	default:
		job.Status = "failed"
		job.Error = res.Metrics.Error
	}
	if err := s.speedtestSaveJob(job); err != nil {
		return job, err
	}
	s.speedtestAppendHistory(job)
	return job, nil
}

func (s *Service) speedtestSaveJob(j *SpeedtestJob) error {
	if err := os.MkdirAll(s.State.speedtestJobsDir(), 0o700); err != nil {
		return err
	}
	path, err := s.speedtestJobPath(j.ID)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Service) speedtestAppendHistory(j *SpeedtestJob) {
	l, err := txlog.Open(s.State.SpeedtestHistoryPath())
	if err != nil {
		return
	}
	_ = l.Append(struct {
		At      time.Time          `json:"at"`
		JobID   string             `json:"job_id"`
		Status  string             `json:"status"`
		Results []speedtest.Result `json:"results,omitempty"`
	}{time.Now().UTC(), j.ID, j.Status, j.Results})
}

// SpeedtestJobStatus returns one job record.
func (s *Service) SpeedtestJobStatus(id string) (*SpeedtestJob, error) {
	path, err := s.speedtestJobPath(id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("VALIDATION_FAILED: job %s: %w", id, err)
	}
	var j SpeedtestJob
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// SpeedtestHistory returns the last n job records (newest first).
func (s *Service) SpeedtestHistory(limit int) ([]SpeedtestJob, error) {
	if limit <= 0 {
		limit = 20
	}
	entries, err := os.ReadDir(s.State.speedtestJobsDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var jobs []SpeedtestJob
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		j, err := s.SpeedtestJobStatus(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue
		}
		jobs = append(jobs, *j)
	}
	sort.Slice(jobs, func(i, k int) bool { return jobs[i].CreatedAt.After(jobs[k].CreatedAt) })
	if len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs, nil
}

// SpeedtestCancel marks a running job canceled; the current runner checks
// the flag between directions and stops before starting the next one.
// An in-flight direction is stopped by the runner's context.
func (s *Service) SpeedtestCancel(id string) error {
	j, err := s.SpeedtestJobStatus(id)
	if err != nil {
		return err
	}
	if j.Status != "running" {
		return fmt.Errorf("VALIDATION_FAILED: job %s is %s, not running", id, j.Status)
	}
	j.Status = "canceled"
	j.UpdatedAt = time.Now().UTC()
	return s.speedtestSaveJob(j)
}

// SpeedtestExport writes the redacted support report: metrics, budget,
// path labels and analysis — no tokens, no device UUIDs, no invite or
// admin keys, no history of visited destinations. Endpoints are kept by
// default (ops data); pass redactEndpoints to mask them.
func (s *Service) SpeedtestExport(id string, redactEndpoints bool) (map[string]any, error) {
	j, err := s.SpeedtestJobStatus(id)
	if err != nil {
		return nil, err
	}
	type redactedResult struct {
		Segment         string  `json:"segment"`
		Source          string  `json:"source"`
		Dest            string  `json:"dest"`
		Direction       string  `json:"direction"`
		GoodputMbps     float64 `json:"goodput_mbps"`
		Bytes           int64   `json:"bytes"`
		DurationS       float64 `json:"duration_s"`
		RTTP50IdleMs    float64 `json:"rtt_p50_idle_ms"`
		RTTP95IdleMs    float64 `json:"rtt_p95_idle_ms"`
		RTTP50LoadedMs  float64 `json:"rtt_p50_loaded_ms,omitempty"`
		RTTP95LoadedMs  float64 `json:"rtt_p95_loaded_ms,omitempty"`
		JitterMs        float64 `json:"jitter_ms"`
		FailedProbeRatio float64 `json:"failed_probe_ratio"`
		IntegrityOK     *bool   `json:"integrity_ok,omitempty"`
		RateLimited     bool    `json:"rate_limited"`
		RateLimitNote   string  `json:"rate_limit_note,omitempty"`
		Canceled        bool    `json:"canceled"`
		Error           string  `json:"error,omitempty"`
	}
	out := map[string]any{
		"schema": "ara.speedtest.export/v1",
		"job_id": j.ID, "segment": j.Segment, "direction": j.Direction,
		"budget": j.BudgetKey, "status": j.Status, "created_at": j.CreatedAt,
	}
	if redactEndpoints {
		out["endpoint"] = "[redacted]"
	} else {
		out["endpoint"] = j.Endpoint
	}
	rs := []redactedResult{}
	for _, r := range j.Results {
		rs = append(rs, redactedResult{
			Segment: string(r.Segment), Source: r.Source, Dest: r.Dest,
			Direction: string(r.Direction), GoodputMbps: r.Metrics.GoodputMbps,
			Bytes: r.Metrics.Bytes, DurationS: r.Metrics.DurationS,
			RTTP50IdleMs: r.Metrics.RTTP50IdleMs, RTTP95IdleMs: r.Metrics.RTTP95IdleMs,
			RTTP50LoadedMs: r.Metrics.RTTP50LoadedMs, RTTP95LoadedMs: r.Metrics.RTTP95LoadedMs,
			JitterMs: r.Metrics.JitterMs, FailedProbeRatio: r.Metrics.FailedProbeRatio,
			IntegrityOK: r.Metrics.IntegrityOK, RateLimited: r.RateLimited,
			RateLimitNote: r.RateLimitNote, Canceled: r.Canceled, Error: r.Metrics.Error,
		})
	}
	out["results"] = rs
	if j.Analysis != nil {
		out["analysis"] = j.Analysis
	}
	return out, nil
}

// SpeedtestRateLimitNote renders the active limits for the current
// identity: shown with every result so a bounded number is honest.
func (s *Service) SpeedtestRateLimitNote() string {
	cfg, err := s.LoadLimitsConfig()
	if err != nil {
		return ""
	}
	parts := []string{}
	if cfg.Device.Rate.DownloadBPS != nil {
		parts = append(parts, fmt.Sprintf("down %d mbit/s", *cfg.Device.Rate.DownloadBPS*8/1_000_000))
	}
	if cfg.Device.Rate.UploadBPS != nil {
		parts = append(parts, fmt.Sprintf("up %d mbit/s", *cfg.Device.Rate.UploadBPS*8/1_000_000))
	}
	if cfg.Device.TotalBytes != nil {
		parts = append(parts, fmt.Sprintf("quota %d MiB/period", *cfg.Device.TotalBytes/(1<<20)))
	}
	return strings.Join(parts, ", ")
}
