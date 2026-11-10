package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// A shared profile credit pool serves BOTH directions and all simultaneous
// connections. Reserving a whole small budget for the HTTP request must not
// starve the response. The owner remains the cross-node authority.
type profilePool struct {
	mu       sync.Mutex
	refs     int
	helper   *enforcer
	routeKey string
}

func (dp *edgeDatapath) acquireProfilePool(device string, port int) *profilePool {
	dp.mu.Lock()
	sub := dp.byDeviceID[device].SubID
	enabled := false
	for _, ctx := range dp.configSnapshot().Subscriptions {
		if ctx.SubscriptionID == sub && ctx.ProfileBudgets[port] != "" {
			enabled = true
			break
		}
	}
	if !enabled {
		dp.mu.Unlock()
		return nil
	}
	key := localProfileKey{sub, port}
	if dp.profilePools == nil {
		dp.profilePools = map[localProfileKey]*profilePool{}
	}
	pool := dp.profilePools[key]
	if pool == nil {
		pool = &profilePool{helper: &enforcer{dp: dp, deviceID: device, profilePort: port}}
		dp.profilePools[key] = pool
	}
	dp.mu.Unlock()
	pool.mu.Lock()
	pool.refs++
	pool.mu.Unlock()
	return pool
}
func (p *profilePool) ensureLocked(e *enforcer) error {
	h := p.helper
	_, key, err := h.profileRemote()
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("profile authorization removed")
	}
	if p.routeKey != "" && p.routeKey != key && h.profileGrantID != "" {
		if err := h.closeProfileGrant(); err != nil {
			return err
		}
	}
	p.routeKey = key
	if h.profileGrantID != "" && (h.batchUsed >= h.profileGranted || h.profileExpires > 0 && time.Now().Unix() >= h.profileExpires) {
		if err := h.closeProfileGrant(); err != nil {
			return err
		}
	}
	if h.profileGrantID == "" {
		h.deviceID = e.deviceID
		h.batchUsed = 0
		if err := h.reserveProfileGrant(quotaBatchBytes); err != nil {
			return err
		}
	}
	if h.profileGrantID == "" {
		return fmt.Errorf("profile authorization removed")
	}
	return nil
}
func (p *profilePool) ensure(e *enforcer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ensureLocked(e)
}
func (p *profilePool) take(e *enforcer, n int64) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(e); err != nil {
		return 0, err
	}
	left := p.helper.profileGranted - p.helper.batchUsed
	if n > left {
		n = left
	}
	if n <= 0 {
		return 0, fmt.Errorf("profile quota exhausted")
	}
	p.helper.batchUsed += n
	return n, nil
}
func (p *profilePool) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refs--
	if p.refs == 0 && p.helper.profileGrantID != "" {
		if err := p.helper.closeProfileGrant(); err != nil {
			log.Printf("profile quota checkpoint pending: %v", err)
		}
	}
}
