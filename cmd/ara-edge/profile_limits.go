package main

import (
	"aravpn/core/limits"
	"time"
)

type localProfileKey struct {
	sub  string
	port int
}

func (dp *edgeDatapath) buildProfileLimiters(now time.Time) error {
	next := map[localProfileKey]*limits.AggregateLimiter{}
	for _, sub := range dp.cfg.Subscriptions {
		for port, rate := range sub.ProfileRates {
			key := localProfileKey{sub.SubscriptionID, port}
			lim := dp.profileLimiters[key]
			if lim == nil {
				regime, err := limits.NewAccountRegime(rate.toRateConfig(), now)
				if err != nil {
					return err
				}
				lim, err = regime.BindDevice(limits.RateConfig{}, now)
				if err != nil {
					return err
				}
			} else if err := lim.RebindAccount(rate.toRateConfig(), now); err != nil {
				return err
			}
			next[key] = lim
		}
	}
	dp.profileLimiters = next
	return nil
}

func (dp *edgeDatapath) profileLimiter(device string, port int) *limits.AggregateLimiter {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	return dp.profileLimiters[localProfileKey{dp.byDeviceID[device].SubID, port}]
}

// Owner confirmations update the live bucket without creating another burst.
func (dp *edgeDatapath) applyProfileRate(device string, port int, down, up *int64) error {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	key := localProfileKey{dp.byDeviceID[device].SubID, port}
	cfg := limits.RateConfig{DownloadBPS: down, UploadBPS: up}
	if lim := dp.profileLimiters[key]; lim != nil {
		return lim.RebindAccount(cfg, time.Now())
	}
	regime, err := limits.NewAccountRegime(cfg, time.Now())
	if err != nil {
		return err
	}
	lim, err := regime.BindDevice(limits.RateConfig{}, time.Now())
	if err != nil {
		return err
	}
	if dp.profileLimiters == nil {
		dp.profileLimiters = map[localProfileKey]*limits.AggregateLimiter{}
	}
	dp.profileLimiters[key] = lim
	return nil
}
