package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aravpn/core/nodeaccess"
)

func TestNodeAccessHelperLimitsMutationToApprovedRule(t *testing.T) {
	allowed, err := nodeaccess.Build(nodeaccess.Input{Kind: "transit", Protocol: "tcp", Port: 8443, Interface: "tun0", Source: "10.1.0.2", Table: "filter"})
	if err != nil {
		t.Fatal(err)
	}
	var ops []bool
	handler := nodeAccessHandler(map[string]nodeaccess.Plan{allowed.Tag: allowed}, func(plan nodeaccess.Plan, remove bool) error {
		if plan.Rule != allowed.Rule {
			t.Fatalf("unexpected rule %s", plan.Rule)
		}
		ops = append(ops, remove)
		return nil
	})
	body := `{"kind":"transit","protocol":"tcp","port":8443,"interface":"tun0","source":"10.1.0.2/32","table":"filter"}`
	for _, tc := range []struct {
		path, body string
		status     int
	}{
		{"/apply", strings.Replace(body, "8443", "8444", 1), http.StatusForbidden},
		{"/apply", strings.Replace(body, "/32", "/24", 1), http.StatusForbidden},
		{"/apply", body, http.StatusNoContent},
		{"/remove", body, http.StatusNoContent},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
		if w.Code != tc.status {
			t.Fatalf("%s: status %d, want %d", tc.path, w.Code, tc.status)
		}
	}
	if len(ops) != 2 || ops[0] || !ops[1] {
		t.Fatalf("unexpected mutations: %v", ops)
	}
}
