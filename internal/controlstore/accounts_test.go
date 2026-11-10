package controlstore

import "testing"

func TestArchiveAccountRevokesDevicesAndPreventsReuse(t *testing.T) {
	s := openFedStore(t)
	sub, _, err := s.CreateSubscription("acc1", "example", "panel", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, secret, err := s.CreateDevice("acc1", "device")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ArchiveAccount("acc1"); err == nil {
		t.Fatal("archived an account with an unrevoked subscription")
	}
	if err := s.RevokeSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ArchiveAccount("acc1"); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.ListAccounts(); err != nil || len(rows) != 0 {
		t.Fatalf("visible accounts: %v (%v)", rows, err)
	}
	if _, err := s.GetSubscription(sub.ID); err != nil {
		t.Fatal("history was lost:", err)
	}
	if err := s.ConsumeEnrollment(dev.ID, secret); err == nil {
		t.Fatal("archived device enrolled")
	}
	if _, _, err := s.CreateSubscription("acc1", "new", "panel", nil, 0); err == nil {
		t.Fatal("issued to an archived account")
	}
}
