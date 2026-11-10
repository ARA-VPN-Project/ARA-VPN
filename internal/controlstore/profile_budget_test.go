package controlstore

import (
	"fmt"
	"sync"
	"testing"
)

func TestProfileBudgetConcurrentReplayRefundAndReopen(t *testing.T) {
	s, id := openQuotaStore(t)
	cap := int64(1000)
	p := SubscriptionProfile{Kind: "direct", NodeID: "se", IngressAddr: "example.invalid:443", Protocol: "vless", LabelRU: "Швеция", LabelEn: "Sweden", LimitBytes: &cap}
	if err := s.SetOwnedSubscriptionProfiles(id, "owner", []SubscriptionProfile{p}); err != nil {
		t.Fatal(err)
	}
	key := ProfileKey(p)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	var firstID, firstHolder string
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g, err := s.ProfileReserve("owner", id, key, fmt.Sprintf("edge-%d", i), "dev", fmt.Sprintf("reservation-%032d", i), 100)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			total += g.Granted
			if g.Granted > 0 && firstID == "" {
				firstID = g.ID
				firstHolder = fmt.Sprintf("edge-%d", i)
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if total != 1000 {
		t.Fatalf("total %d", total)
	}
	old, err := s.ProfileReserve("owner", id, key, firstHolder, "dev", firstID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if old.Granted == 0 {
		t.Fatal("fixture reserve not granted")
	}
	if err = s.ProfileClose("owner", id, firstHolder, old.ID, 25); err != nil {
		t.Fatal(err)
	}
	if err = s.ProfileClose("owner", id, firstHolder, old.ID, 25); err != nil {
		t.Fatal(err)
	}
	g, err := s.ProfileReserve("owner", id, key, "edge2", "dev", "after-refund-0000000000000000000", 100)
	if err != nil || g.Granted != 75 {
		t.Fatalf("refund: %+v %v", g, err)
	}
	spends, err := s.ProfileSpends(id)
	if err != nil || spends[key].Committed != 1000 {
		t.Fatalf("spends: %+v %v", spends, err)
	}
	if err = s.SetOwnedSubscriptionProfiles(id, "owner", []SubscriptionProfile{p}); err != nil {
		t.Fatal(err)
	}
	g, err = s.ProfileReserve("owner", id, key, "edge", "dev", "after-readd-00000000000000000000", 1)
	if err != nil || g.Granted != 0 {
		t.Fatalf("reset by edit %+v %v", g, err)
	}
	if _, err = s.ProfileReserve("stranger", id, key, "edge", "dev", "stranger-000000000000000000000", 1); err == nil {
		t.Fatal("wrong owner admitted")
	}
}

func TestProfileCheckpointCannotBeReopenedAndTransferCarriesOutstanding(t *testing.T) {
	s, id := openQuotaStore(t)
	cap := int64(1000)
	p := SubscriptionProfile{Kind: "direct", NodeID: "se", IngressAddr: "example.invalid:443", Protocol: "vless", LabelRU: "A", LabelEn: "A", LimitBytes: &cap}
	if err := s.SetOwnedSubscriptionProfiles(id, "owner", []SubscriptionProfile{p}); err != nil {
		t.Fatal(err)
	}
	key := ProfileKey(p)
	g, err := s.ProfileReserve("owner", id, key, "edge", "dev", "reservation-00000000000000000000", 400)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProfileReserve("owner", id, key, "edge", "dev", g.ID, 401); err == nil {
		t.Fatal("changed request accepted")
	}
	if err = s.ProfileClose("owner", id, "edge", g.ID, 123); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProfileReserve("owner", id, key, "edge", "dev", g.ID, 400); err == nil {
		t.Fatal("closed reservation reopened")
	}
	if _, err = s.ProfileReserve("owner", id, key, "edge", "dev", "outstanding-00000000000000000000", 500); err != nil {
		t.Fatal(err)
	}
	spends, err := s.ProfileSpends(id)
	if err != nil {
		t.Fatal(err)
	}
	if spends[key].Committed != 623 {
		t.Fatalf("outstanding forgotten: %+v", spends)
	}
	// Simulate imported pending state and activation. The activation transaction
	// installs the FINAL profile obligations together with account usage.
	if _, err = s.db.Exec(`UPDATE subscriptions SET active=0,owner_panel='target' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateImportedSubscription(id, 50, spends); err != nil {
		t.Fatal(err)
	}
	g, err = s.ProfileReserve("target", id, key, "edge2", "dev", "after-move-00000000000000000000", 500)
	if err != nil || g.Granted != 377 {
		t.Fatalf("moved budget: %+v %v", g, err)
	}
	var filename string
	var seq int
	var alias string
	if err = s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &alias, &filename); err != nil {
		t.Fatal(err)
	}
	other, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	g, err = other.ProfileReserve("target", id, key, "edge2", "dev", "after-reopen-000000000000000000", 1)
	if err != nil || g.Granted != 0 {
		t.Fatalf("restart reset budget: %+v %v", g, err)
	}
}
