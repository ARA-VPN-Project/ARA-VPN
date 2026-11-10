package main

import (
	"encoding/json"
	"io"
	"os"
	"time"
)

type localUsage struct {
	Connections int   `json:"connections"`
	UsedBytes   int64 `json:"used_bytes"`
}

func (s *server) localUsageSnapshot() map[string]localUsage {
	if s.edgeStatusPath == "" || os.Getenv("ARA_LOCAL_SUB_EDGE") == "" {
		return nil
	}
	f, err := os.Open(s.edgeStatusPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var snap struct {
		GeneratedAt        time.Time             `json:"generated_at"`
		LocalSubscriptions map[string]localUsage `json:"local_subscriptions"`
	}
	if err = json.NewDecoder(io.LimitReader(f, 2<<20)).Decode(&snap); err != nil || time.Since(snap.GeneratedAt) > 10*time.Second {
		return nil
	}
	return snap.LocalSubscriptions
}
