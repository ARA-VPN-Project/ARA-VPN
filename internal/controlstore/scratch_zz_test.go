package controlstore

import (
	"path/filepath"
	"testing"
)

func TestZZReplayViaQuotaReportOp(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateAccount("a", ""); err != nil {
		t.Fatal(err)
	}
	lim := int64(16 << 20)
	sub, _, err := s.CreateSubscription("a", "t", "owner", &lim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterTestDevice("a", "dev"); err != nil {
		t.Fatal(err)
	}
	r1, rep1, err := s.QuotaReportOp("op:x", sub.ID, "edge|dev", 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM fed_ops`).Scan(&n)
	var stored, dg string
	_ = s.db.QueryRow(`SELECT response_json, op_digest FROM fed_ops`).Scan(&stored, &dg)
	t.Logf("after1: rows=%d stored=%q rep1=%v replayed1=%v", n, stored, r1 != nil, rep1)
	r2, rep2, err := s.QuotaReportOp("op:x", sub.ID, "edge|dev", 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM fed_ops`).Scan(&n)
	_ = s.db.QueryRow(`SELECT response_json, op_digest FROM fed_ops`).Scan(&stored, &dg)
	t.Logf("after2: rows=%d stored=%q rep2=%v replayed2=%v granted=%v", n, stored, r2 != nil, rep2, r2.Granted)
}
