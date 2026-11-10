package main

import (
	"aravpn/internal/controlstore"
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func (e *enforcer) profileRemote() (*remoteQuotaLedger, string, error) {
	e.dp.mu.Lock()
	dev, ok := e.dp.byDeviceID[e.deviceID]
	var key string
	for _, sub := range e.dp.configSnapshot().Subscriptions {
		if sub.SubscriptionID == dev.SubID {
			key = sub.ProfileBudgets[e.profilePort]
			break
		}
	}
	e.dp.mu.Unlock()
	if !ok || key == "" {
		return nil, "", nil
	}
	remote, ok := e.dp.quotaFor(e.deviceID).(*remoteQuotaLedger)
	if !ok {
		if e.dp.configSnapshot().LocalPanel != nil {
			return nil, key, nil
		}
		return nil, "", fmt.Errorf("profile budget requires authoritative owner")
	}
	return remote, key, nil
}
func (r *remoteQuotaLedger) profileCall(payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	path := "/api/fed/v1/quota/profile"
	ts := time.Now().Unix()
	nonce := "profile-" + batchTag()
	req, err := http.NewRequest(http.MethodPost, r.cfg.OwnerURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ARA-Panel", r.ident.PanelID)
	req.Header.Set("X-ARA-Timestamp", fmt.Sprint(ts))
	req.Header.Set("X-ARA-Nonce", nonce)
	req.Header.Set("X-ARA-Signature", r.ident.Sign(http.MethodPost, path, ts, nonce, body))
	client := *r.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("profile budget owner HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(out)
}
func (e *enforcer) reserveProfileGrant(want int64) error {
	remote, key, err := e.profileRemote()
	if err != nil {
		return err
	}
	if remote == nil && key == "" {
		return nil
	}
	var entropy [16]byte
	if _, err := crand.Read(entropy[:]); err != nil {
		return err
	}
	id := fmt.Sprintf("pg-%x", entropy[:])
	var grant controlstore.ProfileGrant
	subID := e.profileSubscriptionID()
	req := map[string]any{"action": "reserve", "subscription_id": subID, "profile_key": key, "device_id": e.deviceID, "id": id, "bytes": want}
	// Retrying a lost response uses the same durable reservation identity.
	if remote == nil {
		cfg := e.dp.configSnapshot().LocalPanel
		st, openErr := controlstore.Open(cfg.Database)
		if openErr != nil {
			return openErr
		}
		defer st.Close()
		g, grantErr := st.ProfileReserve(cfg.Owner, e.profileSubscriptionID(), key, cfg.EdgeID, e.deviceID, id, want)
		err = grantErr
		if g != nil {
			grant = *g
		}
	} else {
		// Authenticate/bootstrap the serving identity and confirm the current
		// account/device authority before allocating profile credit. Profile
		// admission can run before the account's first byte reservation.
		if _, authErr := remote.reportAndRequest(e.deviceID, 0); authErr != nil {
			return authErr
		}
		err = remote.profileCall(req, &grant)
		if err != nil {
			err = remote.profileCall(req, &grant)
		}
	}
	if err != nil {
		return err
	}
	if grant.ID != id || grant.Granted <= 0 || grant.Granted > want {
		return fmt.Errorf("profile quota exhausted or invalid grant")
	}
	e.profileGrantID = id
	e.profileGranted = grant.Granted
	e.profileExpires = grant.ExpiresUnix
	if err := e.dp.applyProfileRate(e.deviceID, e.profilePort, grant.DownloadBPS, grant.UploadBPS); err != nil {
		return err
	}
	if e.batchReserved > grant.Granted {
		e.batchReserved = grant.Granted
	}
	return nil
}
func (e *enforcer) closeProfileGrant() error {
	remote, _, err := e.profileRemote()
	if err != nil {
		return err
	}
	if remote == nil {
		cfg := e.dp.configSnapshot().LocalPanel
		if cfg == nil {
			return fmt.Errorf("profile owner disappeared")
		}
		st, err := controlstore.Open(cfg.Database)
		if err != nil {
			return err
		}
		defer st.Close()
		if err = st.ProfileClose(cfg.Owner, e.profileSubscriptionID(), cfg.EdgeID, e.profileGrantID, e.batchUsed); err != nil {
			return err
		}
		e.profileGrantID = ""
		return nil
	}
	var out map[string]any
	req := map[string]any{"action": "close", "subscription_id": remote.cfg.SubscriptionID, "id": e.profileGrantID, "bytes": e.batchUsed}
	err = remote.profileCall(req, &out)
	if err != nil {
		err = remote.profileCall(req, &out)
	}
	if err != nil {
		return err
	}
	e.profileGrantID = ""
	e.profileGranted = 0
	return nil
}

func (e *enforcer) profileSubscriptionID() string {
	e.dp.mu.Lock()
	defer e.dp.mu.Unlock()
	return e.dp.byDeviceID[e.deviceID].SubID
}
