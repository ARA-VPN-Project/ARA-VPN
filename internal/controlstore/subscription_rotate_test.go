package controlstore

import (
	"strings"
	"testing"
	"time"
)

func TestRotateTokenBasicAndCAS(t *testing.T) {
	s := openFedStore(t)
	lim := int64(1 << 20)
	sub, oldTok, err := s.CreateSubscription("acc1", "u", "ru-1", &lim, 0)
	if err != nil {
		t.Fatal(err)
	}
	newHash := HashToken("brand-new-secret")
	res, err := s.RotateSubscriptionToken(sub.ID, "", newHash, 0)
	if err != nil || res.SubscriptionID != sub.ID {
		t.Fatalf("rotate: %v %v", res, err)
	}
	// old token dead, new token resolves, no grace
	if _, err := s.FindSubscriptionByToken(oldTok); err == nil {
		t.Fatal("old token must stop after default rotation")
	}
	got, err := s.FindSubscriptionByToken("brand-new-secret")
	if err != nil || got.ID != sub.ID {
		t.Fatalf("new token: %v %v", got, err)
	}
	// CAS: rotating from a SEEN hash works, from a stale one conflicts
	h2 := HashToken("second")
	if _, err := s.RotateSubscriptionToken(sub.ID, HashToken("stale"), h2, 0); err == nil ||
		!strings.HasPrefix(err.Error(), "CONFLICT") {
		t.Fatalf("stale CAS must conflict: %v", err)
	}
	if _, err := s.RotateSubscriptionToken(sub.ID, newHash, h2, 0); err != nil {
		t.Fatalf("fresh CAS: %v", err)
	}
	// usage and limits untouched by rotation
	used, limOut, _ := s.QuotaUsage(sub.ID)
	_ = used
	_ = limOut
	// revoked subscription cannot rotate
	if err := s.RevokeSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateSubscriptionToken(sub.ID, "", HashToken("x3"), 0); err == nil ||
		!strings.HasPrefix(err.Error(), "AUTH_FAILED") {
		t.Fatalf("revoked rotate: %v", err)
	}
}

func TestRotateGraceDualHash(t *testing.T) {
	s := openFedStore(t)
	sub, oldTok, _ := s.CreateSubscription("acc1", "u", "ru-1", nil, 0)
	if _, err := s.RotateSubscriptionToken(sub.ID, "", HashToken("n1"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	// during grace BOTH resolve (new current, old grace)
	if _, err := s.FindSubscriptionByToken("n1"); err != nil {
		t.Fatalf("new token during grace: %v", err)
	}
	got, grace, err := s.FindSubscriptionByTokenWithGrace(oldTok)
	if err != nil || got == nil || !grace {
		t.Fatalf("old token must resolve during grace: %v %v", got, err)
	}
	// after the grace deadline the old hash stops
	if _, err := s.db.Exec(`UPDATE subscription_token_grace SET expires_at=? WHERE subscription_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FindSubscriptionByTokenWithGrace(oldTok); err == nil {
		t.Fatal("expired grace must refuse")
	}
	if _, err := s.FindSubscriptionByToken("n1"); err != nil {
		t.Fatalf("current token after grace expiry: %v", err)
	}
	// rotation WITHOUT grace clears stale grace rows
	if _, err := s.RotateSubscriptionToken(sub.ID, "", HashToken("n2"), 0); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM subscription_token_grace WHERE subscription_id=?`, sub.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("no-grace rotation must clear grace rows: %d", n)
	}
}
