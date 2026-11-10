package main

import (
	"aravpn/internal/controlstore"
	"path/filepath"
	"testing"
)

func TestLocalSubscriptionsLoadAllDevicesAndTheirLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	st, err := controlstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.AddNodeFull("ru", "RU", "ru", 1, "example.invalid:443", "example.invalid"); err != nil {
		t.Fatal(err)
	}
	profile := controlstore.SubscriptionProfile{Kind: "transit", NodeID: "exit", RoutePort: 4443, IngressAddr: "example.invalid:443", Protocol: "vless", LabelRU: "A", LabelEn: "A"}
	slots := 3
	sub, _, err := st.ProvisionLocalSubscription("user", "Sub", "owner", nil, 0, &slots, []controlstore.SubscriptionProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	phone, _, err := st.ProvisionSubscriptionDevice(sub.ID, "owner", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	tablet, _, err := st.ProvisionSubscriptionDevice(sub.ID, "owner", "Tablet")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = st.ProvisionSubscriptionDevice(sub.ID, "owner", "Over limit"); err == nil {
		t.Fatal("fourth slot admitted")
	}
	cap := int64(12345)
	if err = st.SetSubscriptionDeviceLimit(sub.ID, phone.ID, &cap); err != nil {
		t.Fatal(err)
	}
	cfg := edgeConfig{LocalPanel: &localPanelSource{Database: path, EdgeID: "ru", Owner: "owner"}, Exits: []exitNode{{ID: "exit", Role: "foreign"}}, Routes: []routeListen{{Listen: "127.0.0.1:4443", ExitID: "exit"}}}
	if err = cfg.loadLocalSubscriptions(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Subscriptions) != 1 || len(cfg.Subscriptions[0].Devices) != 3 {
		t.Fatalf("missing devices: %+v", cfg.Subscriptions)
	}
	found := false
	for _, d := range cfg.Subscriptions[0].Devices {
		if d.DeviceID == phone.ID {
			found = d.QuotaBytes != nil && *d.QuotaBytes == cap
		}
	}
	if !found {
		t.Fatal("device cap not delivered")
	}
	if err = st.RevokeSubscriptionDevice(sub.ID, "owner", phone.ID); err != nil {
		t.Fatal(err)
	}
	if err = cfg.loadLocalSubscriptions(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Subscriptions[0].Devices) != 2 {
		t.Fatal("revoked device still loaded")
	}
	found = false
	for _, d := range cfg.Subscriptions[0].Devices {
		if d.DeviceID == tablet.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("revocation disabled another device")
	}
	// Another subscription of the same account must not claim these keys.
	if _, _, err = st.ProvisionLocalSubscription("user", "Second", "owner", nil, 0, nil, []controlstore.SubscriptionProfile{profile}); err != nil {
		t.Fatal(err)
	}
	if err = cfg.loadLocalSubscriptions(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, sub := range cfg.Subscriptions {
		for _, dev := range sub.Devices {
			if previous := seen[dev.DeviceID]; previous != "" && previous != sub.SubscriptionID {
				t.Fatal("identity crossed subscription budgets")
			}
			seen[dev.DeviceID] = sub.SubscriptionID
		}
	}

}
