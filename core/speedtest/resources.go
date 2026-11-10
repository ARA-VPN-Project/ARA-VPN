// CPU/RSS sampling for ARA-owned diagnostic jobs:
// bounded-window, monotonic sampling of ONE verified process (PID +
// start-time guard — a recycled PID is never read). Values are honest:
// unavailable samples are "no data", never zeros; the result states the
// CPU basis (percent of ONE core) and the window. No arbitrary PIDs are
// accepted from UI/API: the sampler only ever watches a process the
// component itself started (the speedtest job's own process or the
// engine's recorded PID+start-time).
package speedtest

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUSample is one resource observation.
type CPUSample struct {
	At         time.Time `json:"at"`
	CPUPercent float64   `json:"cpu_percent"` // percent of ONE core (0..100*k)
	RSSKiB     uint64    `json:"rss_kib"`
}

// ResourceSample is the bounded-window result. Unavailable fields are
// nil with a Reason — never zero.
type ResourceSample struct {
	Window        time.Duration `json:"window"`
	IntervalUsed  time.Duration `json:"interval"`
	Samples       int           `json:"samples"`
	// AvgCPUPercent is the CPU-time delta over the window expressed as a
	// percent of ONE core (100% = one full core).
	AvgCPUPercent *float64 `json:"avg_cpu_percent,omitempty"`
	PeakRSSKiB    *uint64  `json:"peak_rss_kib,omitempty"`
	Reason        string   `json:"no_data_reason,omitempty"`
	ProcAlive     bool     `json:"proc_alive"`
}

// ProcRef identifies the watched process: PID + start time (jiffies).
// Reading is refused when either mismatches — a recycled PID is foreign.
type ProcRef struct {
	PID       int
	StartTime uint64 // /proc/<pid>/stat field 22; 0 = unknown (non-Linux test)
}

func (p ProcRef) String() string { return fmt.Sprintf("pid=%d start=%d", p.PID, p.StartTime) }

// SelfRef is the sampler's own process (the diagnostic job's host).
func SelfRef() ProcRef {
	return ProcRef{PID: os.Getpid()}
}

// readProcCPUJiffies returns total CPU jiffies (utime+stime) and RSS
// pages→KiB. ok=false when the process is gone.
func readProcCPUAndRSS(pid int) (cpuJiffies float64, rssKiB uint64, ok bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, false
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(string(b[i+2:]))
	if len(f) < 24 {
		return 0, 0, false
	}
	utime, _ := strconv.ParseFloat(f[11], 64)
	stime, _ := strconv.ParseFloat(f[12], 64)
	rssPages, _ := strconv.ParseFloat(f[21], 64)
	_ = strings.TrimSpace("")
	const pageSizeKiB = 4 // Linux default; lab hosts are 4K
	return utime + stime, uint64(rssPages * pageSizeKiB), true
}

// readProcStartTime jiffies (field 22).
func readProcStartTime(pid int) (uint64, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+2:]))
	if len(f) < 20 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	return v, err == nil
}

// clockTicksPerSecond from the OS ( uname-independent constant on Linux).
const clockTicksPerSecond = 100.0

// SampleResources watches ref for window at interval. The FIRST read is
// the baseline (excluded); CPU is the delta over elapsed wall time — a
// short window never yields a fake 0.0%. If the process dies mid-window
// the sample stops with the data collected so far and notes it.
func SampleResources(ref ProcRef, window, interval time.Duration) *ResourceSample {
	if window <= 0 {
		window = 5 * time.Second
	}
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	out := &ResourceSample{Window: window, IntervalUsed: interval}
	// ownership guard: start-time mismatch → foreign/recycled process
	if ref.StartTime != 0 {
		if st, ok := readProcStartTime(ref.PID); !ok || st != ref.StartTime {
			out.Reason = "process identity mismatch (recycled or foreign PID): no data"
			return out
		}
	}
	cpu0, _, alive := readProcCPUAndRSS(ref.PID)
	if !alive {
		out.Reason = "process not found at sample start: no data"
		return out
	}
	t0 := time.Now()
	cpu0Jiffies := cpu0
	var peak uint64
	var samples []CPUSample
	var mu sync.Mutex
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				c, rss, ok := readProcCPUAndRSS(ref.PID)
				mu.Lock()
				if ok {
					peak = maxU64(peak, rss)
					elapsed := time.Since(t0).Seconds()
					if elapsed > 0 {
						pct := (c - cpu0Jiffies) / clockTicksPerSecond / elapsed * 100
						samples = append(samples, CPUSample{At: time.Now(), CPUPercent: pct, RSSKiB: rss})
					}
				}
				mu.Unlock()
				if !ok {
					return // process died mid-window
				}
			}
		}
	}()
	time.Sleep(window)
	close(stop)
	<-done // the sampler goroutine has fully stopped: no writes after this
	mu.Lock()
	defer mu.Unlock()
	out.Samples = len(samples)
	out.PeakRSSKiB = &peak
	out.ProcAlive = func() bool { _, _, ok := readProcCPUAndRSS(ref.PID); return ok }()
	if len(samples) == 0 {
		out.Reason = "no samples collected in the window"
		return out
	}
	// average CPU over the whole window from the LAST sample (delta-based,
	// monotonic elapsed): short windows still produce the real number
	last := samples[len(samples)-1]
	elapsed := last.At.Sub(t0).Seconds()
	if elapsed <= 0 {
		out.Reason = "window too short for a CPU delta"
		return out
	}
	avg := last.CPUPercent
	out.AvgCPUPercent = &avg
	return out
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
