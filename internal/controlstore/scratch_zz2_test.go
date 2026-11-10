package controlstore

import (
	"path/filepath"
	"testing"
)

// Debug replica: exactly what QuotaReportOp does, twice, with row dumps.
func TestZZQuotaReportOpReplayTrace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateAccount("a", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterTestDevice("a", "dev"); err != nil {
		t.Fatal(err)
	}
	lim := int64(16 << 20)
	sub, _, err := s.CreateSubscription("a", "t", "owner", &lim, 0)
	if err != nil {
		t.Fatal(err)
	}
	r1, rep1, err := s.QuotaReportOp("op:zz", sub.ID, "edge|dev", 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var stored, dg string
	_ = s.db.QueryRow(`SELECT response_json, op_digest FROM fed_ops`).Scan(&stored, &dg)
	t.Logf("after1: stored_len=%d digest=%q replayed=%v granted=%v", len(stored), dg, rep1, r1.Granted)
	r2, rep2, err := s.QuotaReportOp("op:zz", sub.ID, "edge|dev", 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRow(`SELECT response_json, op_digest FROM fed_ops`).Scan(&stored, &dg)
	t.Logf("after2: stored_len=%d digest=%q replayed=%v granted=%v", len(stored), dg, rep2, r2.Granted)
}
