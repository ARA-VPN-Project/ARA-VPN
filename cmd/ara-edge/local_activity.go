package main

import (
	"context"
	"log"
	"time"

	"aravpn/internal/controlstore"
)

type localActivityKey struct{ sub, device string }
type localActivityCount struct{ ru, foreign int64 }
type localSubscriptionStatus struct {
	Connections int   `json:"connections"`
	UsedBytes   int64 `json:"used_bytes"`
}

func (dp *edgeDatapath) noteLocalTraffic(key localActivityKey, role string, bytes int64) {
	if key.sub == "" || bytes <= 0 {
		return
	}
	dp.localActivityMu.Lock()
	defer dp.localActivityMu.Unlock()
	if dp.localActivity == nil {
		dp.localActivity = map[localActivityKey]localActivityCount{}
	}
	c := dp.localActivity[key]
	if role == "ru" {
		c.ru += bytes
	} else {
		c.foreign += bytes
	}
	dp.localActivity[key] = c
}

func (dp *edgeDatapath) reportLocalTraffic(ctx context.Context) {
	p := dp.configSnapshot().LocalPanel
	if p == nil {
		return
	}
	st, err := controlstore.Open(p.Database)
	if err != nil {
		return
	}
	defer st.Close()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			dp.localActivityMu.Lock()
			pending := dp.localActivity
			dp.localActivity = nil
			dp.localActivityMu.Unlock()
			for key, v := range pending {
				if err := st.ReportLocalTraffic(key.sub, key.device, v.ru, v.foreign, now); err != nil {
					log.Print("local traffic report could not be committed")
				}
			}
		}
	}
}

func (dp *edgeDatapath) localSubscriptionStatus(now time.Time) map[string]localSubscriptionStatus {
	if dp.configSnapshot().LocalPanel == nil {
		return nil
	}
	dp.mu.Lock()
	connections := make(map[string]int, len(dp.localConnections))
	for id, n := range dp.localConnections {
		connections[id] = n
	}
	ledgers := make(map[string]quotaLedger, len(dp.ledgers))
	for id, ledger := range dp.ledgers {
		ledgers[id] = ledger
	}
	dp.mu.Unlock()
	status := make(map[string]localSubscriptionStatus, len(ledgers))
	for id, ledger := range ledgers {
		status[id] = localSubscriptionStatus{Connections: connections[id], UsedBytes: ledger.AccountState(now).Used}
	}
	return status
}
