package service

// FED06 invariants: transfer retry after the source flip resumes with
// exactly one activation; a retry after successful activation is a
// durable no-op; re-import never deactivates an active target copy.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTransferRetryAfterSourceFlip(t *testing.T) {
	s := newTestService(t)
	if _, err := s.PanelInit("source"); err != nil {
		t.Fatal(err)
	}
	st, err := s.OpenControlStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateAccount("a", ""); err != nil {
		t.Fatal(err)
	}
	lim := int64(1 << 20)
	sub, _, err := st.CreateSubscription("a", "test", "source", &lim, 0)
	if err != nil {
		t.Fatal(err)
	}
	var available atomic.Bool
	var activated atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/activate") {
			if !available.Load() {
				http.Error(w, `{"error":"injected outage"}`, 503)
				return
			}
			activated.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	if err := s.SubscriptionTransfer(sub.ID, "target", target.URL); err == nil {
		t.Fatal("first transfer must report activation outage")
	}
	current, err := st.GetSubscription(sub.ID)
	if err != nil || current.OwnerPanel != "target" {
		t.Fatalf("source did not reach flip: %+v %v", current, err)
	}
	available.Store(true)
	if err := s.SubscriptionTransfer(sub.ID, "target", target.URL); err != nil {
		t.Fatalf("same transfer cannot resume after source flip: %v", err)
	}
	if activated.Load() != 1 {
		t.Fatalf("target activation count=%d", activated.Load())
	}
	// further retries are durable no-ops (no extra activate calls)
	if err := s.SubscriptionTransfer(sub.ID, "target", target.URL); err != nil {
		t.Fatalf("retry after activation must be a no-op: %v", err)
	}
	if activated.Load() != 1 {
		t.Fatalf("no-op retry called activate again: %d", activated.Load())
	}
}
