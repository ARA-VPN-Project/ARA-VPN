package main

import (
	"testing"
	"time"
)

func TestTrafficObservationsUseCounterDeltas(t *testing.T) {
	at := time.Now()
	downBefore, upBefore := uint64(100), uint64(200)
	downAfter, upAfter := uint64(30_000_100), uint64(200)
	before := edgeObservation{At: at, Instance: "edge-1", Down: &downBefore, Up: &upBefore}
	after := edgeObservation{At: at.Add(30 * time.Second), Instance: "edge-1", Down: &downAfter, Up: &upAfter}
	sample, ok := after.trafficSince(before)
	if !ok || *sample.DownMbps != 8 || *sample.UpMbps != 0 {
		t.Fatalf("expected 8 Mbit/s down, measured zero up, got %+v", sample)
	}
	for _, invalid := range []edgeObservation{
		{At: after.At, Instance: "restarted", Down: after.Down, Up: after.Up},
		{At: after.At, Instance: before.Instance, Down: after.Down},
		{At: before.At, Instance: before.Instance, Down: after.Down, Up: after.Up},
		{At: before.At.Add(3 * monitorInterval), Instance: before.Instance, Down: after.Down, Up: after.Up},
		{At: after.At, Instance: before.Instance, Down: &upBefore, Up: &downBefore},
	} {
		if _, ok := invalid.trafficSince(before); ok {
			t.Errorf("published a traffic sample for invalid comparison %+v", invalid)
		}
	}
}
