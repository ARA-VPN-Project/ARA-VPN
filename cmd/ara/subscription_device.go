package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"aravpn/core/schema"
	"aravpn/internal/controlstore"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

func cmdSubscriptionDevice(svc *service.Service, st *controlstore.Store, g *globals, tail []string, lang i18n.Lang) int {
	fs := flag.NewFlagSet("subscription "+tail[0], flag.ContinueOnError)
	id := fs.String("id", "", "subscription id")
	device := fs.String("device", "", "device id")
	name := fs.String("name", "", "new device display name")
	days := fs.Int("days", 1, "activity window (1 or 7 days)")
	until := fs.String("until", "", "RFC3339 expiry or 'none'")
	base := fs.String("base", "", "public panel HTTPS origin")
	if err := fs.Parse(tail[1:]); err != nil || *id == "" || tail[0] != "activity" && tail[0] != "device-add" && *device == "" {
		return schema.ExitUsage
	}
	out := map[string]any{"subscription_id": *id, "device_id": *device}
	var err error
	switch tail[0] {
	case "activity":
		sub, e := st.GetSubscription(*id)
		if e != nil || sub.OwnerPanel != svc.PanelID() || sub.Active != nil && !*sub.Active {
			err = fmt.Errorf("CONFLICT: activity is available from its owner")
		} else {
			var act controlstore.SubscriptionActivity
			act, err = st.SubscriptionActivity(*id, time.Now(), *days)
			out["activity"] = act
		}
	case "device-expiry":
		var timestamp int64
		if *until != "none" {
			date, e := time.Parse(time.RFC3339, *until)
			if e != nil {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, fmt.Errorf("--until must be RFC3339 or none"))
			}
			timestamp = date.Unix()
		}
		err = st.SetSubscriptionDeviceExpiry(*id, svc.PanelID(), *device, timestamp)
	case "device-revoke":
		err = st.RevokeSubscriptionDevice(*id, svc.PanelID(), *device)
	case "device-link", "device-add":
		endpoint, e := subscriptionShareEndpoint(svc, *base)
		if e == nil && endpoint.Base() == "" {
			e = fmt.Errorf("VALIDATION_FAILED: set the subscription endpoint or supply --base")
		}
		if e != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, e)
		}
		var token string
		if tail[0] == "device-add" {
			var dev *controlstore.Device
			dev, token, err = st.ProvisionSubscriptionDevice(*id, svc.PanelID(), *name)
			if err == nil {
				out["device_id"] = dev.ID
				out["device_name"] = dev.Name
			}
		} else {
			token, err = st.IssueSubscriptionDeviceLink(*id, svc.PanelID(), *device)
		}
		if err == nil {
			out["url"] = service.SubscriptionTokenURL(endpoint.Base(), token)
		}
	}
	if err != nil {
		return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
	}
	if g.json || tail[0] == "activity" {
		return okJSON(g, out)
	}
	if url, ok := out["url"]; ok {
		fmt.Fprintln(os.Stdout, url)
		return schema.ExitOK
	}
	if lang == "ru" {
		fmt.Println("Доступ устройства обновлён")
	} else {
		fmt.Println("Device access updated")
	}
	return schema.ExitOK
}
