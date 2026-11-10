package controlstore

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSubscriptionSlotsSerializeDeviceRegistration(t *testing.T) {
	store := openFedStore(t)
	limit := 2
	sub, _, err := store.CreateSubscriptionWithProfiles("acc1", "test", "owner", nil, 0, &limit, nil)
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			_, _, err := store.CreateDevice("acc1", "fixture")
			if err == nil {
				accepted.Add(1)
			} else if !strings.Contains(err.Error(), "DEVICE_SLOTS_FULL") {
				t.Errorf("device registration: %v", err)
			}
		})
	}
	group.Wait()
	if accepted.Load() != 2 {
		t.Fatalf("accepted %d registrations", accepted.Load())
	}
	one := 1
	if err := store.SetSubscriptionMaxDevices(sub.ID, "owner", &one); err == nil {
		t.Fatal("reduced below the number of registered devices")
	}
	devices, err := store.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeDevice(devices[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateDevice("acc1", "replacement"); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedImportPreservesSlotCapAndDeviceLedger(t *testing.T) {
	store := openFedStore(t)
	capacity, bytes, rate := 3, int64(5000), int64(400)
	sub := &Subscription{ID: "migrated", AccountID: "acc1", Name: "test", OwnerPanel: "target",
		MaxDevices: &capacity, DeviceUsage: map[string]int64{"d": 1000}, DeviceLimits: map[string]*int64{"d": &bytes}, RateUpBPS: &rate}
	if err := store.PrepareSubscriptionImport(sub, "hash", nil, nil, "migration", "source", 1000); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetSubscription(sub.ID)
	if err != nil || got.MaxDevices == nil || *got.MaxDevices != capacity || *got.Active {
		t.Fatalf("pending subscription: %+v (%v)", got, err)
	}
	used, limits, down, up, err := store.LoadSubscriptionTransferState(sub.ID)
	if err != nil || used["d"] != 1000 || limits["d"] == nil || *limits["d"] != bytes || down != nil || up == nil || *up != rate {
		t.Fatalf("import lost limits or usage: %v %v %v %v %v", used, limits, down, up, err)
	}
}
