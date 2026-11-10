package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"aravpn/internal/monitoring"
)

const monitorInterval = 30 * time.Second

// edgeObservation is the read-only status contract published by ara-edge.
type edgeObservation struct {
	At             time.Time      `json:"generated_at"`
	Instance       string         `json:"instance"`
	TLS            string         `json:"tls_cert_path"`
	CurrentForeign string         `json:"current_foreign_id"`
	Down           *uint64        `json:"download_bytes"`
	Up             *uint64        `json:"upload_bytes"`
	RoutePorts     map[string]int `json:"route_ports"`
	Nodes          []struct {
		ID       string    `json:"id"`
		Country  string    `json:"country"`
		Role     string    `json:"role"`
		Priority int       `json:"priority"`
		State    string    `json:"state"`
		ProbeAt  time.Time `json:"probe_at"`
		RTT      *float64  `json:"probe_ms"`
	} `json:"nodes"`
}

func (next edgeObservation) trafficSince(prev edgeObservation) (monitoring.Sample, bool) {
	elapsed := next.At.Sub(prev.At)
	if next.Instance == "" || next.Instance != prev.Instance || elapsed <= 0 || elapsed > 2*monitorInterval ||
		next.Down == nil || prev.Down == nil || next.Up == nil || prev.Up == nil ||
		*next.Down < *prev.Down || *next.Up < *prev.Up {
		return monitoring.Sample{}, false
	}
	down := float64(*next.Down-*prev.Down) * 8e-6 / elapsed.Seconds()
	up := float64(*next.Up-*prev.Up) * 8e-6 / elapsed.Seconds()
	return monitoring.Sample{At: next.At, Kind: "traffic", Target: "edge", Source: "edge_payload", DownMbps: &down, UpMbps: &up}, true
}

func readEdgeObservation(path string, now time.Time) (edgeObservation, error) {
	var observation edgeObservation
	f, err := os.Open(path)
	if err != nil {
		return observation, err
	}
	defer f.Close()
	const limit = 256 << 10
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return observation, err
	}
	if len(data) > limit {
		return observation, fmt.Errorf("oversized Edge status")
	}
	if err := json.Unmarshal(data, &observation); err != nil {
		return observation, err
	}
	if observation.At.IsZero() || now.Sub(observation.At) > 10*time.Second || observation.At.After(now.Add(time.Second)) {
		return observation, fmt.Errorf("stale Edge status")
	}
	return observation, nil
}

func collectMonitoring(ctx context.Context, store *monitoring.Store, edgeStatus string, cloudflare bool) {
	var previous edgeObservation
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()
	for {
		now := time.Now().UTC()
		var samples []monitoring.Sample
		if edgeStatus != "" {
			if next, err := readEdgeObservation(edgeStatus, now); err == nil {
				if sample, ok := next.trafficSince(previous); ok {
					samples = append(samples, sample)
				}
				previous = next
				for _, node := range next.Nodes {
					if node.ID == "" || len(node.ID) > 256 {
						continue
					}
					sample := monitoring.Sample{At: next.At, Kind: "node", Target: node.ID, State: node.State, Source: "edge_exit_probe"}
					// A probe result carries its own timestamp. Never reuse an old
					// successful duration as a fresh observation.
					if age := now.Sub(node.ProbeAt); age >= 0 && age <= monitorInterval && node.RTT != nil {
						sample.RTTMs = node.RTT
					}
					samples = append(samples, sample)
				}
			}
		}
		if cloudflare {
			targets := []struct{ name, address string }{
				{"Cloudflare", "1.1.1.1:443"},
				{"Facebook", "www.facebook.com:443"},
				{"Yandex", "ya.ru:443"},
			}
			results := make(chan monitoring.Sample, len(targets))
			for _, target := range targets {
				go func() { results <- probeMonitoringTarget(ctx, target.name, target.address) }()
			}
			for range targets {
				samples = append(samples, <-results)
			}
			if ctx.Err() != nil {
				return
			}
		}
		if len(samples) != 0 {
			if err := store.Record(samples...); err != nil {
				log.Printf("monitoring history: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func probeMonitoringTarget(ctx context.Context, name, address string) monitoring.Sample {
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", address)
	sample := monitoring.Sample{At: time.Now().UTC(), Kind: "target", Target: name, State: "down", Source: "panel_tcp"}
	if err == nil {
		conn.Close()
		ms := float64(time.Since(start)) / float64(time.Millisecond)
		sample.RTTMs, sample.State = &ms, "healthy"
	}
	return sample
}
