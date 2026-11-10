package controlstore

import "testing"

func TestRevokedSubscriptionCanBeHiddenWithoutLosingQuota(t *testing.T) {
	s := openFedStore(t)
	sub, token, err := s.CreateSubscription("acc1", "user", "ru-1", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.HideRevokedSubscription(sub.ID, "ru-1"); err == nil {
		t.Fatal("active subscription hidden")
	}
	if err := s.SetQuotaUsed(sub.ID, 100); err != nil {
		t.Fatal(err)
	}
	limit := int64(2_000_000)
	if err := s.SetSubscriptionQuota(sub.ID, "wrong", &limit); err == nil {
		t.Fatal("foreign panel changed the limit")
	}
	if err := s.SetSubscriptionQuota(sub.ID, "ru-1", &limit); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.HideRevokedSubscription(sub.ID, "ru-1"); err != nil {
		t.Fatal(err)
	}
	if subs, err := s.ListSubscriptions(); err != nil || len(subs) != 0 {
		t.Fatalf("visible subscriptions: %v (%v)", subs, err)
	}
	if _, err := s.FindSubscriptionByToken(token); err == nil {
		t.Fatal("revoked token accepted")
	}
	used, cap, err := s.QuotaUsage(sub.ID)
	if err != nil || cap == nil || *cap != limit || used != 100 {
		t.Fatalf("quota history changed: %v %v %v", used, cap, err)
	}
}
