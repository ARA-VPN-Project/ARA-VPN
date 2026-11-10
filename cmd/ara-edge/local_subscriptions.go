package main

import (
	"aravpn/internal/controlstore"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
)

// Local subscription provisioning is opt-in for a Control Center and Edge
// sharing one host. The database is opened read-only. The trusted Edge
// configuration continues to own all listener and exit addresses.
func (c *edgeConfig) loadLocalSubscriptions() error {
	if c.LocalPanel == nil {
		return nil
	}
	p := c.LocalPanel
	if p.EdgeID == "" || p.Owner == "" || !filepath.IsAbs(p.Database) || c.QuotaRemote != nil {
		return fmt.Errorf("local panel needs an absolute database path, edge and owner IDs, and a local quota ledger")
	}
	u := url.URL{Scheme: "file", Path: p.Database, RawQuery: "mode=ro&_pragma=busy_timeout(1500)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `SELECT s.id, s.account_id, s.limits_bytes, COALESCE(s.expires_at,''),
		d.id,d.vless_uuid,d.expires_unix,sp.kind,sp.node_id,sp.route_port,sr.download_bps,sr.upload_bps,sp.download_bps,sp.upload_bps,sp.ingress_addr,dq.limit_bytes
		FROM subscriptions s LEFT JOIN sub_rate sr ON sr.subscription_id=s.id JOIN subscription_profiles sp ON sp.subscription_id=s.id
		JOIN nodes n ON n.id=? AND n.revoked_at IS NULL AND n.ingress_addr=sp.ingress_addr
		JOIN devices d ON d.account_id=s.account_id LEFT JOIN sub_quota_device dq ON dq.subscription_id=s.id AND dq.device_id=d.id
		WHERE s.owner_panel=? AND s.active=1 AND COALESCE(s.transferred_to,'')='' AND s.revoked_at IS NULL
		AND d.revoked_at IS NULL AND COALESCE(d.vless_uuid,'')!=''
        AND (d.id=COALESCE(NULLIF(s.primary_device_id,''),
             (SELECT first.id FROM devices first WHERE first.account_id=s.account_id ORDER BY first.created_at,first.id LIMIT 1))
          OR EXISTS (SELECT 1 FROM subscription_device_links dl WHERE dl.subscription_id=s.id AND dl.device_id=d.id))
		ORDER BY s.id,sp.seq,d.id`, p.EdgeID, p.Owner)
	if err != nil {
		return err
	}
	defer rows.Close()
	ports := make(map[int]string)
	roles := make(map[string]string)
	for _, e := range c.Exits {
		roles[e.ID] = e.Role
	}
	for _, route := range c.Routes {
		_, port, _ := net.SplitHostPort(route.Listen)
		n, _ := strconv.Atoi(port)
		ports[n] = route.ExitID
	}
	legacy := make(map[string]string)
	for _, s := range c.Subscriptions {
		legacy[s.SubscriptionID] = s.AccountID
	}
	now := time.Now()
	var contexts []subContext
	quotaLimits := make(map[string]*int64)
	for rows.Next() {
		var id, account, expiry, device, uuid, kind, node, ingress string
		var max, down, up, profileDown, profileUp, deviceLimit *int64
		var deviceExpiry int64
		var port int
		if err := rows.Scan(&id, &account, &max, &expiry, &device, &uuid, &deviceExpiry, &kind, &node, &port, &down, &up, &profileDown, &profileUp, &ingress, &deviceLimit); err != nil {
			return err
		}
		if expiry != "" {
			t, err := time.Parse(time.RFC3339Nano, expiry)
			if err != nil {
				return err
			}
			if !t.After(now) {
				continue
			}
			if deviceExpiry == 0 || t.Unix() < deviceExpiry {
				deviceExpiry = t.Unix()
			}
		}
		if deviceExpiry != 0 && now.Unix() >= deviceExpiry {
			continue
		}
		var grants []string
		policy := kind == "transit" && port == 0 && node == p.EdgeID
		switch {
		case policy:
			for _, e := range c.Exits {
				if e.Role == "foreign" {
					grants = append(grants, e.ID)
				}
			}
		case port != 0 && kind == "transit" && ports[port] == node && roles[node] == "foreign":
			grants = []string{node}
		case port != 0 && kind == "direct" && node == p.EdgeID && roles[ports[port]] == "ru":
			grants = []string{ports[port]}
		default:
			continue
		}
		if len(contexts) == 0 || contexts[len(contexts)-1].SubscriptionID != id {
			quotaLimits[id] = max
			budget := id
			if legacy[id] != "" {
				budget = legacy[id]
			}
			contexts = append(contexts, subContext{SubscriptionID: id, AccountID: budget, LocalQuota: max, AccountRate: localAccountRate(down, up), ProfileRates: map[int]rateConf{}, ProfileBudgets: map[int]string{},
				Devices: []deviceAuth{{UUID: uuid, DeviceID: device, ExpiresUnix: deviceExpiry, QuotaBytes: deviceLimit}}})
		}
		sub := &contexts[len(contexts)-1]
		present := false
		for _, d := range sub.Devices {
			if d.DeviceID == device {
				present = true
				break
			}
		}
		if !present {
			sub.Devices = append(sub.Devices, deviceAuth{UUID: uuid, DeviceID: device, ExpiresUnix: deviceExpiry, QuotaBytes: deviceLimit})
		}
		sub.PolicyRouting = sub.PolicyRouting || policy
		sub.ProfileBudgets[port] = controlstore.ProfileKey(controlstore.SubscriptionProfile{Kind: kind, NodeID: node, IngressAddr: ingress, RoutePort: port})
		if profileDown != nil || profileUp != nil {
			sub.ProfileRates[port] = rateConf{DownloadBPS: profileDown, UploadBPS: profileUp}
		}
		sub.Routes = append(sub.Routes, grants...)
		if !policy {
			sub.LocalPinnedRoutes = append(sub.LocalPinnedRoutes, grants...)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if c.PolicyFile != "" && c.Policy == nil {
		c.Policy, err = loadPolicy(c.PolicyFile)
		if err != nil {
			return err
		}
	}
	encoded, err := json.Marshal([]any{contexts, c.Policy, quotaLimits})
	if err != nil {
		return err
	}
	c.localSubscriptionsHash = sha256.Sum256(encoded)
	c.DeviceUUID, c.Devices, c.Subscriptions = "", nil, contexts
	return nil
}

type localPanelSource struct {
	Database string `json:"database"`
	EdgeID   string `json:"edge_id"`
	Owner    string `json:"owner"`
}

// Older CLI clients accepted any positive value. Round up to a whole byte
// per second and permit one admission chunk without changing steady rate.
func localAccountRate(down, up *int64) *rateConf {
	normalize := func(value *int64) (*int64, *int64) {
		if value == nil || *value <= 0 {
			return value, nil
		}
		rate := *value
		if rate%8 != 0 {
			rate = (rate/8)*8 + 8
		}
		if rate >= 8192 {
			return &rate, nil
		}
		burst := int64(rateChunk)
		return &rate, &burst
	}
	d, db := normalize(down)
	u, ub := normalize(up)
	return &rateConf{DownloadBPS: d, UploadBPS: u, DownloadBurstBytes: db, UploadBurstBytes: ub}
}

// Track traffic during unlimited periods too, so adding a cap preserves usage.
func localLedgerLimit(limit *int64) *int64 {
	if limit != nil {
		return limit
	}
	unlimited := int64(math.MaxInt64)
	return &unlimited
}
