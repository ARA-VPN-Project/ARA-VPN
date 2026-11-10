package main

import (
	"fmt"
	"net/http"
	"time"

	"aravpn/internal/service"
)

func (s *server) handleNodeCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	node, err := service.CheckableNode(s.store, r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !s.nodeCheck.TryLock() {
		writeErr(w, fmt.Errorf("CONFLICT: another node check is running"))
		return
	}
	defer s.nodeCheck.Unlock()
	out := service.CheckNodeIngress(r.Context(), node)
	step := service.NodeCheckStep{Name: "exit_canary", Status: "skipped", Reason: "no_exit_observation"}
	if s.edgeStatusPath != "" {
		now := time.Now()
		if obs, err := readEdgeObservation(s.edgeStatusPath, now); err == nil {
			for _, exit := range obs.Nodes {
				if exit.ID != node.ID || exit.ProbeAt.IsZero() || exit.ProbeAt.After(now) || now.Sub(exit.ProbeAt) > 2*monitorInterval {
					continue
				}
				step.Status = "failed"
				step.Reason = "exit_unhealthy"
				if exit.State == "healthy" {
					step.Status = "ok"
					step.Reason = ""
					if exit.RTT != nil && *exit.RTT >= 0 {
						step.DurationMS = int64(*exit.RTT)
					}
				}
				break
			}
		}
	}
	out.Steps = append(out.Steps, step)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
