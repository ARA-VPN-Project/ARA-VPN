package speedtest

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestSampleResourcesSelf: the sampler reports the real CPU delta of the
// test process under load and never a fake 0.0% for a short window.
func TestSampleResourcesSelf(t *testing.T) {
	ref := SelfRef()
	stopSpin := make(chan struct{})
	go func() { // spin to make the CPU delta unambiguous
		for {
			select {
			case <-stopSpin:
				return
			default:
			}
		}
	}()
	defer close(stopSpin)
	res := SampleResources(ref, 600*time.Millisecond, 200*time.Millisecond)
	if res.Reason != "" {
		t.Fatalf("self sample must have data: %+v", res)
	}
	if res.AvgCPUPercent == nil || *res.AvgCPUPercent <= 0 {
		t.Fatalf("spin must yield positive CPU%%: %+v", res)
	}
	if res.PeakRSSKiB == nil || *res.PeakRSSKiB == 0 {
		t.Fatalf("RSS must be observed: %+v", res)
	}
	if res.Samples < 2 {
		t.Fatalf("expected ≥2 samples in 600ms/200ms: %+v", res)
	}
}

// TestSampleResourcesGoneProcess: a PID that cannot exist is honest
// "no data" with a reason, never zeros. Deterministic: probe /proc for a
// free PID (the same read the sampler performs).
func TestSampleResourcesGoneProcess(t *testing.T) {
	dead := -1
	for cand := 4194303; cand > 300; cand-- {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d/stat", cand)); os.IsNotExist(err) {
			dead = cand
			break
		}
	}
	if dead < 0 {
		t.Skip("no free PID found on a busy host")
	}
	res := SampleResources(ProcRef{PID: dead}, 300*time.Millisecond, 100*time.Millisecond)
	if res.Samples != 0 || res.Reason == "" {
		t.Fatalf("dead process must be no-data with a reason: %+v", res)
	}
	if res.AvgCPUPercent != nil || res.PeakRSSKiB != nil {
		t.Fatalf("no data must not carry fake numbers: %+v", res)
	}
}

// TestSampleResourcesForeignStartRefused: a PID+start-time mismatch is
// refused — a recycled PID's data is never attributed to the job.
func TestSampleResourcesForeignStartRefused(t *testing.T) {
	res := SampleResources(ProcRef{PID: os.Getpid(), StartTime: 424242}, 300*time.Millisecond, 100*time.Millisecond)
	if res.Reason == "" || res.Samples != 0 {
		t.Fatalf("start-time mismatch must be refused: %+v", res)
	}
}

// helpers: minimal process start/kill via /proc-verified self fork is not
// portable here — use an existing process that we can safely watch and
// then verify the "gone" path with a PID that never existed.
func mustStartSleeper(t *testing.T) int {
	t.Helper()
	// use our own PID as the "alive" case; for the gone case the caller
	// uses a synthetic PID
	return os.Getpid()
}

func killAndWait(pid int) {}

// TestSampleResourcesBoundedWindow: the sampler respects the window even
// when the interval does not divide it evenly, and the caller never waits
// significantly beyond window+interval.
func TestSampleResourcesBoundedWindow(t *testing.T) {
	start := time.Now()
	res := SampleResources(SelfRef(), 400*time.Millisecond, 300*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("sampler overran the window: %v", elapsed)
	}
	if res.Window != 400*time.Millisecond {
		t.Fatalf("window echo: %+v", res)
	}
}
