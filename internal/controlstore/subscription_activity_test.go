package controlstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestActivityRoutesAreIdempotentAndSeparateFromQuota(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateAccount("account", ""); err != nil {
		t.Fatal(err)
	}
	a, _, err := st.CreateDevice("account", "first")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := st.CreateDevice("account", "second")
	if err != nil {
		t.Fatal(err)
	}
	sub, _, err := st.CreateSubscription("account", "sub", "owner", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, _, err := st.QuotaReportRouted("normal", "digest", sub.ID, "edge|"+a.ID, 500, 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	for _, in := range []struct {
		id, key            string
		bytes, ru, foreign int64
	}{
		{a.ID, "a", 500, 350, 150}, {a.ID, "a", 500, 350, 150}, {b.ID, "b", 750, 0, 700},
	} {
		if err := st.ReportSubscriptionActivity(in.key, "digest", sub.ID, in.id, now.Unix(), in.bytes, in.ru, in.foreign); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.SubscriptionActivity(sub.ID, time.Now(), 7)
	if err != nil {
		t.Fatal(err)
	}
	var bytes, ru, foreign int64
	for _, bucket := range got.Buckets {
		bytes += bucket.Bytes
		ru += bucket.RUBytes
		foreign += bucket.ForeignBytes
	}
	if bytes != 1250 || ru != 350 || foreign != 850 || len(got.LastReported) != 2 {
		t.Fatalf("unexpected graph %+v", got)
	}
	used, _, err := st.QuotaUsage(sub.ID)
	if err != nil || used != 500 {
		t.Fatalf("telemetry changed quota: used=%d %v", used, err)
	}
}

func TestRevokedDeviceCannotUseSharedOrPrivateLink(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateAccount("account", ""); err != nil {
		t.Fatal(err)
	}
	a, _, err := st.CreateDevice("account", "first")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := st.CreateDevice("account", "second")
	if err != nil {
		t.Fatal(err)
	}
	sub, _, err := st.CreateSubscription("account", "sub", "owner", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.SubscriptionDeviceUUID(sub.ID, "", time.Now())
	if err != nil || uid != a.VlessUUID {
		t.Fatalf("invalid legacy UUID %v", err)
	}
	token, err := st.IssueSubscriptionDeviceLink(sub.ID, "owner", b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, device, err := st.FindSubscriptionDeviceLink(token); err != nil || device != b.ID {
		t.Fatalf("link binding %q %v", device, err)
	}
	if err := st.RevokeSubscriptionDevice(sub.ID, "owner", a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SubscriptionDeviceUUID(sub.ID, "", time.Now()); !errors.Is(err, ErrDeviceAccess) {
		t.Fatalf("legacy URL switched device: %v", err)
	}
	if _, _, err := st.QuotaReportOp("deny", sub.ID, "edge|"+a.ID, 0, 100); !errors.Is(err, ErrDeviceAccess) {
		t.Fatalf("revoked unlimited device got rights: %v", err)
	}
	if _, _, err := st.QuotaReportOp("allow", sub.ID, "edge|"+b.ID, 0, 100); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSubscriptionDeviceExpiry(sub.ID, "owner", b.ID, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SubscriptionDeviceUUID(sub.ID, b.ID, time.Now()); !errors.Is(err, ErrDeviceAccess) {
		t.Fatalf("expired device accepted: %v", err)
	}
}
