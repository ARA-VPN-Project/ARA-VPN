package controlstore

import (
	"strings"
	"testing"
	"time"
)

func openFedStore(t *testing.T) *Store {
	t.Helper()
	s := openTest(t)
	if _, err := s.CreateAccount("acc1", ""); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLinkInviteLifecycle(t *testing.T) {
	s := openFedStore(t)
	tok, err := s.CreateLinkInvite("de-1", "nodes,subscriptions,quota", time.Hour)
	if err != nil || tok == "" {
		t.Fatalf("invite: %v", err)
	}
	// the invite is stored hashed
	rows, _ := s.db.Query(`SELECT token_hash FROM link_invites`)
	if rows.Next() {
		var h string
		_ = rows.Scan(&h)
		rows.Close()
		if h == tok {
			t.Fatal("plaintext invite token stored")
		}
	} else {
		rows.Close()
	}
	scopes, err := s.RedeemLinkInvite(tok, "de-1", "pubkey-hex")
	if err != nil || scopes != "nodes,subscriptions,quota" {
		t.Fatalf("redeem: %v %q", err, scopes)
	}
	// single use
	if _, err := s.RedeemLinkInvite(tok, "de-2", "pk"); err == nil ||
		!strings.HasPrefix(err.Error(), "AUTH_FAILED") {
		t.Fatalf("replay accepted: %v", err)
	}
	pub, sc, err := s.LinkedPanelPubKey("de-1")
	if err != nil || pub != "pubkey-hex" || sc != scopes {
		t.Fatalf("pubkey lookup: %v", err)
	}
	// unknown panel has no standing
	if _, _, err := s.LinkedPanelPubKey("nope"); err == nil ||
		!strings.HasPrefix(err.Error(), "AUTH_FAILED") {
		t.Fatalf("unknown panel accepted: %v", err)
	}
	// revocation disables standing
	if err := s.RevokeLinkedPanel("de-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LinkedPanelPubKey("de-1"); err == nil {
		t.Fatal("revoked link still authorizes")
	}
}

func TestSubscriptionSharedQuotaAndTransfer(t *testing.T) {
	s := openFedStore(t)
	lim := int64(10 << 20)
	sub, token, err := s.CreateSubscription("acc1", "user1", "ru-1", &lim, 0)
	if err != nil || sub.OwnerPanel != "ru-1" || token == "" {
		t.Fatalf("create: %v", err)
	}
	profs := []SubscriptionProfile{
		{Seq: 1, LabelRU: "Германия напрямую", LabelEn: "Germany direct", Kind: "direct", NodeID: "de-1", IngressAddr: "10.62.0.2:8443", Protocol: "vless"},
		{Seq: 2, LabelRU: "Германия через Россию", LabelEn: "Germany via Russia", Kind: "transit", NodeID: "de-1", IngressAddr: "10.60.0.1:443", Protocol: "vless"},
	}
	if err := s.SetSubscriptionProfiles(sub.ID, profs); err != nil {
		t.Fatalf("profiles: %v", err)
	}
	got, _ := s.ListSubscriptionProfiles(sub.ID)
	if len(got) != 2 || got[0].Kind != "direct" || got[1].Kind != "transit" {
		t.Fatalf("catalog: %+v", got)
	}
	// incomplete profile rejected
	if err := s.SetSubscriptionProfiles(sub.ID, []SubscriptionProfile{{Kind: "direct"}}); err == nil {
		t.Fatal("incomplete profile accepted")
	}
	// shared ledger: usage from TWO serving nodes draws ONE budget
	if _, ex, err := s.QuotaReport(sub.ID, "edge-fa", 4<<20, 0); err != nil || ex {
		t.Fatalf("report1: %v", err)
	}
	rem, ex, err := s.QuotaReport(sub.ID, "edge-fb", 4<<20, 0)
	if err != nil || ex || rem == nil || *rem != 2<<20 {
		t.Fatalf("report2: rem=%v ex=%v err=%v", rem, ex, err)
	}
	used, limOut, _ := s.QuotaUsage(sub.ID)
	if used != 8<<20 || limOut == nil || *limOut != lim {
		t.Fatalf("usage: %d %v", used, limOut)
	}
	// lease reservation holds budget via Σopen (not via used): the
	// invariant Σopen+used ≤ limit is what bounds total spend
	if _, _, err := s.QuotaReport(sub.ID, "edge-fa", 1<<20, 2<<20); err != nil {
		t.Fatalf("report3: %v", err)
	}
	used2, _, _ := s.QuotaUsage(sub.ID)
	if used2 != 9<<20 {
		t.Fatalf("used after report3: %d", used2)
	}
	var open2 int64
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM sub_leases WHERE subscription_id=? AND state='issued'`, sub.ID).Scan(&open2)
	if open2 != 1<<20 { // the 10 MiB limit: only 1 MiB of headroom remains
		t.Fatalf("open lease must hold the (bounded) reservation: %d", open2)
	}
	if used2+open2 > lim {
		t.Fatalf("invariant: used=%d open=%d limit=%d", used2, open2, lim)
	}
	// revocation propagates as refusal (serving edges stop)
	if err := s.RevokeSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.QuotaReport(sub.ID, "edge-fa", 1, 0); err == nil ||
		!strings.HasPrefix(err.Error(), "AUTH_FAILED") {
		t.Fatalf("revoked subscription still accepts reports: %v", err)
	}
	if _, err := s.FindSubscriptionByToken(token); err == nil {
		t.Fatal("revoked token still resolves")
	}
}

func TestImportedSubscriptionKeepsIdentityAndSpend(t *testing.T) {
	// the TARGET side of an ownership transfer: same id, same token hash,
	// same accumulated spend — a copied user with a fresh budget cannot
	// exist because the ledger is part of the import
	s := openFedStore(t)
	lim := int64(5 << 20)
	created := time.Now().UTC().Add(-time.Hour)
	imp := &Subscription{ID: "sub-imported", AccountID: "acc1", Name: "user1",
		OwnerPanel: "de-1", LimitsBytes: &lim, CreatedAt: created, UsedBytes: 3 << 20}
	if err := s.CreateSubscriptionImported(imp, HashToken("same-token")); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := s.FindSubscriptionByToken("same-token")
	if err != nil || got.OwnerPanel != "de-1" {
		t.Fatalf("same token must resolve on the new owner: %v %+v", err, got)
	}
	used, limOut, _ := s.QuotaUsage("sub-imported")
	if used != 3<<20 || limOut == nil || *limOut != lim {
		t.Fatalf("spend not preserved: used=%d lim=%v", used, limOut)
	}
	// re-import onto the PENDING copy is an idempotent update; after
	// activation it must refuse (no divergence)
	if err := s.CreateSubscriptionImported(imp, HashToken("x")); err != nil {
		t.Fatalf("pending re-import must be idempotent: %v", err)
	}
	if err := s.ActivateImportedSubscription("sub-imported", 3<<20); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := s.CreateSubscriptionImported(imp, HashToken("x")); err == nil {
		t.Fatal("re-import onto an ACTIVE copy must refuse")
	}
}
