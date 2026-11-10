// Command ara-lab is the isolated-lab harness (docs/LAB_RUNBOOK.md): it
// drives the REAL health trackers and the REAL routing oracle with REAL
// TCP probes against fake exit listeners, so failover semantics are
// exercised end to end on Linux without a data plane.
//
// It changes no system network state: it only dials local endpoints given
// on the command line and prints decision transitions as JSONL.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"aravpn/core/health"
	"aravpn/core/policy"
	"aravpn/core/routing"
)

type exitSpec struct {
	ID       string `json:"id"`
	Country  string `json:"country"`
	Role     string `json:"role"` // ru | foreign
	Priority int    `json:"priority"`
	Addr     string `json:"addr"` // host:port of the lab listener
}

type config struct {
	Exits            []exitSpec `json:"exits"`
	ProbeIntervalMs  int        `json:"probe_interval_ms"`
	ProbeTimeoutMs   int        `json:"probe_timeout_ms"`
	FailThreshold    int        `json:"fail_threshold"`
	RecoverThreshold int        `json:"recover_threshold"`
	StabilityMs      int        `json:"stability_ms"`
	MaxAgeMs         int        `json:"max_age_ms"`
	DurationS        int        `json:"duration_s"`
	CurrentForeign   string     `json:"current_foreign"`
}

type transition struct {
	At     string `json:"at"`
	Event  string `json:"event"`
	ExitID string `json:"exit_id,omitempty"`
	State  string `json:"state,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func main() {
	cfgPath := flag.String("config", "", "lab config JSON")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: ara-lab failover --config lab.json")
		os.Exit(2)
	}
	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	hcfg := health.Config{
		FailThreshold:      cfg.FailThreshold,
		RecoverThreshold:   cfg.RecoverThreshold,
		StabilityWindow:    time.Duration(cfg.StabilityMs) * time.Millisecond,
		MaxObservationAge:  time.Duration(cfg.MaxAgeMs) * time.Millisecond,
		InitialProbeWindow: time.Duration(cfg.MaxAgeMs) * time.Millisecond,
	}
	now := time.Now()
	trackers := map[string]*health.Tracker{}
	for _, e := range cfg.Exits {
		tr, err := health.NewTracker(hcfg, now)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		trackers[e.ID] = tr
	}

	topo := routing.Topology{CurrentForeignID: cfg.CurrentForeign}
	for _, e := range cfg.Exits {
		role := routing.Role(e.Role)
		topo.Exits = append(topo.Exits, routing.Exit{ID: e.ID, Country: e.Country, Priority: e.Priority, Role: role})
	}
	pol := policy.DefaultPolicy()
	pol.Revision = 1

	emit := func(t transition) {
		t.At = time.Now().UTC().Format(time.RFC3339Nano)
		b, _ := json.Marshal(t)
		fmt.Println(string(b))
	}

	lastMode := routing.Mode("")
	lastStates := map[string]health.State{}
	probe := func() {
		now = time.Now()
		for _, e := range cfg.Exits {
			tr := trackers[e.ID]
			conn, err := net.DialTimeout("tcp", e.Addr, time.Duration(cfg.ProbeTimeoutMs)*time.Millisecond)
			if err == nil {
				conn.Close()
				tr.RecordSuccess(now)
			} else {
				tr.RecordFailure(now, health.FailTimeout, err.Error())
			}
			snap := tr.Effective(now)
			if prev, ok := lastStates[e.ID]; !ok || prev != snap.State {
				emit(transition{Event: "health", ExitID: e.ID, State: string(snap.State)})
				lastStates[e.ID] = snap.State
			}
		}
		snapShot := routing.Snapshot{}
		for id, tr := range trackers {
			snapShot[id] = tr.Effective(now).State
		}
		dec := routing.Decide(topo, snapShot, pol, policy.SystemACL{DenyNonGlobal: true},
			policy.Destination{Domain: "lab.example", Proto: policy.ProtoTCP, Port: 443},
			routing.QuotaState{}, 1)
		if dec.Mode != lastMode {
			emit(transition{Event: "mode", Mode: string(dec.Mode), Reason: dec.Reason, ExitID: dec.ExitID})
			lastMode = dec.Mode
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.DurationS)*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Duration(cfg.ProbeIntervalMs) * time.Millisecond)
	defer ticker.Stop()
	probe()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probe()
		}
	}
}
