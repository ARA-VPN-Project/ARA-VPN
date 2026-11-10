package main

import (
	"aravpn/core/limits"
	"testing"
	"time"
)

func TestFlowAppliesCurrentRemoteRateWithoutBackgroundTick(t *testing.T) {
	now := time.Now()
	zero, rate := int64(0), int64(81920)
	regime, err := limits.NewAccountRegime(limits.RateConfig{DownloadBPS: &zero}, now)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := regime.BindDevice(limits.RateConfig{}, now)
	if err != nil {
		t.Fatal(err)
	}
	q := &remoteQuotaLedger{st: remoteState{RateDownBps: &rate, RateDeadlineDown: now.Add(time.Minute).Unix()}}
	dp := &edgeDatapath{remoteRates: map[string]*remoteQuotaLedger{"sub": q}, byDeviceID: map[string]deviceAuth{"dev": {SubID: "sub", AccountID: "account"}}, accountLimiters: map[string]*limits.AggregateLimiter{"account": limiter}, limiters: map[string]*limits.AggregateLimiter{"dev": limiter}, remoteApplied: map[string][2]*int64{"account": {&zero, nil}}}
	dp.syncRemoteAccountRates("dev")
	if got := dp.limiterFor("dev").TakeWithProfile(nil, limits.Download, 1, now.Add(time.Second)); !got.Granted {
		t.Fatalf("fresh right not applied: %+v", got)
	}
	// A reload replaces the ledger. Subsequent flow checks must use the new
	// zero right, never the previous goroutine's captured ledger set.
	dp.remoteRates["sub"] = &remoteQuotaLedger{st: remoteState{RateDownBps: &zero}}
	dp.syncRemoteAccountRates("dev")
	if got := dp.limiterFor("dev").TakeWithProfile(nil, limits.Download, 1, now.Add(2*time.Second)); !got.Forbidden {
		t.Fatalf("reload's zero right ignored: %+v", got)
	}
}
