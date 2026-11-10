// Speedtest runner mode for the edge host (docs/SPEEDTEST.md): the
// Edge→Exit segment is measured BY THE EDGE through the per-exit transit
// adapter (SOCKS loopback → sing-box → the exit's real protocol), so the
// result covers exactly the configured Trojan/VLESS hop. This is an
// ADMIN capability: server-side authority, its own budget, an audit
// entry, and it is never counted against a user's rate/quota — the
// client cannot invoke it.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aravpn/core/speedtest"
	"aravpn/internal/controlstore"
)

// socksDialer routes the measurement through the per-exit transit
// adapter: exactly the path user traffic takes past this point.
func socksDialer(exit exitNode, timeout time.Duration) speedtest.Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := net.LookupPort(network, port)
		if err != nil {
			return nil, err
		}
		return exit.dialSOCKS(ctx, host, p, timeout)
	}
}

// runExitSpeedtest measures both directions sequentially and prints the
// results as one JSON document. audit records the run without tokens.
func runExitSpeedtest(cfg *edgeConfig, exitID, endpoint, token, budgetKey string, budget speedtest.Budget, audit *controlstore.Audit) error {
	var exit *exitNode
	for i := range cfg.Exits {
		if cfg.Exits[i].ID == exitID {
			exit = &cfg.Exits[i]
		}
	}
	if exit == nil {
		return fmt.Errorf("VALIDATION_FAILED: exit %q is not configured", exitID)
	}
	if exit.socksEndpoint() == "" {
		return fmt.Errorf("VALIDATION_FAILED: exit %q has no transit adapter (socks_addr)", exitID)
	}
	dial := socksDialer(*exit, 10*time.Second)
	out := struct {
		Schema    string                    `json:"schema"`
		Exit      string                    `json:"exit"`
		Segment   string                    `json:"segment"`
		Budget    string                    `json:"budget"`
		Results   []speedtest.Result        `json:"results"`
		Resources *speedtest.ResourceSample `json:"resources,omitempty"`
	}{Schema: "ara.speedtest.edge-exit/v1", Exit: exitID, Segment: string(speedtest.SegEdgeExit), Budget: budgetKey}
	// resource sampling of THIS edge process (verified self identity),
	// bounded to the measurement window
	resCh := make(chan *speedtest.ResourceSample, 1)
	go func() {
		resCh <- speedtest.SampleResources(speedtest.SelfRef(), budget.Duration+speedtestBurstExtra, 500*time.Millisecond)
	}()
	dirs := []speedtest.Direction{speedtest.DirDown, speedtest.DirUp}
	for _, dir := range dirs {
		spec := speedtest.Spec{
			Segment:   speedtest.SegEdgeExit,
			Source:    "edge",
			Dest:      exitID,
			Endpoint:  endpoint,
			Token:     token,
			Direction: dir,
			Budget:    budget,
			Dialer:    dial,
		}
		res := speedtest.Measure(context.Background(), spec, "edge-exit-"+exitID, time.Now())
		out.Results = append(out.Results, res)
	}
	out.Resources = <-resCh
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	if audit != nil {
		_ = audit.Append(controlstore.AuditEntry{
			Actor: "ara-edge", Action: "speedtest.edge-exit", ObjectID: exitID, Result: "ok",
			Detail: fmt.Sprintf("budget=%s endpoint=%s directions=down,up", budgetKey, endpoint),
		})
	}
	// history for the Control Center graphs: JSONL in the edge state dir,
	// metrics only (no tokens); bounded by rotation at 1000 records
	persistEdgeSpeedHistory(cfg.StateDir, exitID, out.Results, out.Resources, budgetKey)
	return nil
}

// persistEdgeSpeedHistory appends one record to <state>/speedtest-history.jsonl.
func persistEdgeSpeedHistory(stateDir, exitID string, results []speedtest.Result, res *speedtest.ResourceSample, budgetKey string) {
	if stateDir == "" {
		return
	}
	type histRec struct {
		At        string                    `json:"at"`
		Exit      string                    `json:"exit"`
		Budget    string                    `json:"budget"`
		Results   []speedtest.Result        `json:"results"`
		Resources *speedtest.ResourceSample `json:"resources,omitempty"`
	}
	rec := histRec{At: time.Now().UTC().Format(time.RFC3339), Exit: exitID, Budget: budgetKey, Results: results, Resources: res}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	path := filepath.Join(stateDir, "speedtest-history.jsonl")
	// rotate: >1000 lines → keep the last 500
	if fi, err := os.Stat(path); err == nil && fi.Size() > 512*1024 {
		if data, rerr := os.ReadFile(path); rerr == nil {
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			if len(lines) > 1000 {
				_ = os.WriteFile(path, []byte(strings.Join(lines[len(lines)-500:], "\n")+"\n"), 0o600)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}
