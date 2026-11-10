package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"time"

	"aravpn/core/nodeaccess"
	"aravpn/internal/controlstore"
)

func (s *server) handleNodeAccessChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.nodeAccessSocket == "" {
		writeErr(w, fmt.Errorf("UNAVAILABLE: local firewall helper is not configured"))
		return
	}
	var input nodeaccess.Input
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&input); err != nil {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: invalid node access request"))
		return
	}
	plan, err := nodeaccess.Build(input)
	if err != nil {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: %w", err))
		return
	}
	action := path.Base(r.URL.Path)
	data, err := json.Marshal(plan.Input)
	if err != nil {
		writeErr(w, err)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://local/"+action, bytes.NewReader(data))
	if err != nil {
		writeErr(w, err)
		return
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", s.nodeAccessSocket)
	}, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 13 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	audit := controlstore.AuditEntry{Actor: "operator", Action: "node.access." + action, ObjectID: plan.Tag, Result: "denied"}
	resp, err := client.Do(req)
	if err != nil {
		s.audit.Append(audit)
		writeErr(w, fmt.Errorf("UNAVAILABLE: local firewall helper could not be reached"))
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		s.audit.Append(audit)
		writeErr(w, fmt.Errorf("CONFLICT: rule was not approved or could not be applied"))
		return
	}
	audit.Result = "ok"
	s.audit.Append(audit)
	writeJSON(w, http.StatusOK, map[string]any{"operation": action, "tag": plan.Tag})
}
