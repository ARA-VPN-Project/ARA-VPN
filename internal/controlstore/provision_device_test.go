package controlstore

import (
	"testing"
	"time"
)

func TestProvisionDeviceKeyAndLinkIsolation(t *testing.T) {
	st := openFedStore(t)
	slots := 2
	sub, _, err := st.ProvisionLocalSubscription("isolated", "Family", "owner", nil, 0, &slots, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := st.ListDevices()
	if _, _, err = st.ProvisionSubscriptionDevice(sub.ID, "stranger", "Phone"); err == nil {
		t.Fatal("foreign panel allocated identity")
	}
	after, _ := st.ListDevices()
	if len(after) != len(before) {
		t.Fatal("failed request leaked slot")
	}
	phone, token, err := st.ProvisionSubscriptionDevice(sub.ID, "owner", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	primary, err := st.SubscriptionDeviceUUID(sub.ID, sub.PrimaryDeviceID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if phone.VlessUUID == primary || phone.VlessUUID == "" || token == "" {
		t.Fatal("device reused primary identity")
	}
	linked, device, err := st.FindSubscriptionDeviceLink(token)
	if err != nil || linked.ID != sub.ID || device != phone.ID {
		t.Fatalf("device URL mismatch: %v", err)
	}
	if _, _, err = st.ProvisionSubscriptionDevice(sub.ID, "owner", "Third"); err == nil {
		t.Fatal("slot cap bypassed")
	}
	if err = st.RevokeSubscriptionDevice(sub.ID, "owner", phone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = st.SubscriptionDeviceUUID(sub.ID, phone.ID, time.Now()); err == nil {
		t.Fatal("revoked device still resolves a VPN identity")
	}
	if _, err = st.SubscriptionDeviceUUID(sub.ID, sub.PrimaryDeviceID, time.Now()); err != nil {
		t.Fatal("unrelated primary revoked", err)
	}
	if _, _, err = st.ProvisionSubscriptionDevice(sub.ID, "owner", "Replacement"); err != nil {
		t.Fatal("revocation did not free slot", err)
	}
}

func TestExplicitZeroSubscriptionRateIsNotUnlimited(t *testing.T) {
	st := openFedStore(t)
	sub, _, err := st.CreateSubscription("acc1", "Zero", "owner", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	if err = st.SetSubscriptionRate(sub.ID, &zero, nil); err != nil {
		t.Fatal(err)
	}
	down, up, err := st.SubscriptionRate(sub.ID)
	if err != nil || down == nil || *down != 0 || up != nil {
		t.Fatal("zero was erased", err)
	}
	if err = st.SetSubscriptionRate(sub.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	down, up, err = st.SubscriptionRate(sub.ID)
	if err != nil || down != nil || up != nil {
		t.Fatal("unlimited is distinct from zero", err)
	}
}
