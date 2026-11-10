package monitoring

import (
	"testing"
	"time"
)

func TestHistorySurvivesReopenAndRetainsNewest(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(Sample{Target: "a"}, Sample{Target: "b"}, Sample{Target: "c"}); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(Sample{Target: "d"}); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	history := store.History(0)
	if len(history) != 2 || history[0].Target != "c" || history[1].Target != "d" {
		t.Fatalf("unexpected retained history: %+v", history)
	}
}

func TestArchiveSurvivesRawRingRotation(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.OpenArchive(dir); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Hour).Add(-time.Minute)
	rtt := 12.0
	for _, at := range []time.Time{now.Add(-48 * time.Hour), now} {
		if err := store.Record(Sample{At: at, Kind: "target", Target: "test", RTTMs: &rtt}); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := OpenStore(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.OpenArchive(dir); err != nil {
		t.Fatal(err)
	}
	history, err := reopened.Period(now, 7*24*time.Hour, time.Hour)
	if err != nil || len(history) != 2 || history[0].RTTMs == nil || *history[0].RTTMs != 12 {
		t.Fatalf("archive did not retain observations: %+v, %v", history, err)
	}
}
