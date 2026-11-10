package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEdgeDeploymentRejectsMalformedRequestsBeforeService(t *testing.T) {
	s := &server{}
	for _, body := range []string{`{"root_shell":"anything"}`, `{} {}`, `[]`, `{"edge_node_id":42}`} {
		w := httptest.NewRecorder()
		s.handleEdgeDeploymentPlan(w, httptest.NewRequest("POST", "/api/v1/edge-config/plan", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("plan body %s: %d", body, w.Code)
		}
	}
	for _, body := range []string{`{}`, `{"plan_id":"p"}`, `{"plan_id":"p","plan_hash":"h"} {}`, `{"plan_id":"p","plan_hash":"h","command":"x"}`} {
		w := httptest.NewRecorder()
		s.handleEdgeDeploymentApply(w, httptest.NewRequest("POST", "/api/v1/edge-config/apply", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("apply body %s: %d", body, w.Code)
		}
	}
	for _, method := range []string{"GET", "DELETE", "PUT"} {
		w := httptest.NewRecorder()
		s.handleEdgeDeploymentPlan(w, httptest.NewRequest(method, "/api/v1/edge-config/plan", nil))
		if w.Code != 405 {
			t.Fatal(method, w.Code)
		}
	}
}
