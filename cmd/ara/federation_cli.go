// Federation and subscription CLI (docs/FEDERATION.md): headless panel
// linking, shared subscription management with the transfer of ownership,
// shared quota view — full parity with the Control Center (same service
// layer, same store), JSON envelopes and stable exit codes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"aravpn/core/qrencode"
	"aravpn/core/schema"
	"aravpn/internal/controlstore"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

// ---- ara panel init | invite | redeem | links | revoke | share ----

func cmdPanel(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara panel init --id NAME | invite --for PANEL [--scopes nodes,subscriptions,quota] | redeem --base URL --token TOK | links | revoke --id PANEL --base URL | share --to PANEL --base URL")
		return schema.ExitUsage
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer st.Close()
	switch tail[0] {
	case "init":
		fs := flag.NewFlagSet("panel init", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "unique panel id (e.g. ru-1, de-1)")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		ident, err := svc.PanelInit(*id)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"panel_id": ident.PanelID, "public_key": ident.PublicHex()})
		}
		fmt.Printf("panel %s initialized (public key %s…)\n", ident.PanelID, ident.PublicHex()[:16])
		return schema.ExitOK

	case "invite":
		fs := flag.NewFlagSet("panel invite", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		forP := fs.String("for", "", "invited panel id")
		scopes := fs.String("scopes", "nodes,subscriptions,quota", "limited powers for the link")
		ttl := fs.Int("ttl-seconds", 3600, "invite TTL")
		if err := fs.Parse(tail[1:]); err != nil || *forP == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--for required"}, nil)
		}
		tok, err := st.CreateLinkInvite(*forP, *scopes, time.Duration(*ttl)*time.Second)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"token": tok, "for": *forP, "scopes": *scopes})
		}
		fmt.Println(i18n.T(lang, "fed.invite_created", map[string]any{"for": *forP, "scopes": *scopes}))
		fmt.Println("token: " + tok)
		return schema.ExitOK

	case "redeem":
		fs := flag.NewFlagSet("panel redeem", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		base := fs.String("base", "", "inviting panel base URL (http://host:port)")
		token := fs.String("token", "", "invite token")
		if err := fs.Parse(tail[1:]); err != nil || *base == "" || *token == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--base and --token required"}, nil)
		}
		out, err := svc.PanelRedeem(*base, *token)
		if err != nil {
			return fail(g, lang, schema.CodeAuth, "error."+schema.CodeAuth, nil, err)
		}
		if g.json {
			return okJSON(g, out)
		}
		fmt.Println(i18n.T(lang, "fed.linked", map[string]any{"peer": fmt.Sprint(out["panel_id"]), "scopes": fmt.Sprint(out["scopes"])}))
		return schema.ExitOK

	case "links":
		links, err := st.ListLinkedPanels()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"links": links, "panel_id": svc.PanelID()})
		}
		fmt.Println(i18n.T(lang, "fed.links_title", map[string]any{"count": len(links)}))
		for _, l := range links {
			state := "active"
			if l.RevokedAt != nil {
				state = "revoked"
			}
			fmt.Printf("  %s  scopes=%s  %s\n", l.PanelID, l.Scopes, state)
		}
		return schema.ExitOK

	case "share":
		fs := flag.NewFlagSet("panel share", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		to := fs.String("to", "", "linked panel id")
		base := fs.String("base", "", "remote panel base URL")
		selected := multiFlag(fs, "node")
		if err := fs.Parse(tail[1:]); err != nil || *to == "" || *base == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--to and --base required"}, nil)
		}
		var out map[string]any
		var err error
		if len(*selected) > 0 {
			out, err = svc.FederationShareSelectedTopology(*to, strings.TrimRight(*base, "/"), *selected)
		} else {
			out, err = svc.FederationShareTopology(*to, strings.TrimRight(*base, "/"))
		}
		if err != nil {
			return fail(g, lang, schema.CodeAuth, "error."+schema.CodeAuth, nil, err)
		}
		if g.json {
			return okJSON(g, out)
		}
		fmt.Println(i18n.T(lang, "fed.shared", map[string]any{"count": fmt.Sprint(out["imported"]), "to": *to}))
		return schema.ExitOK

	case "revoke":
		fs := flag.NewFlagSet("panel revoke", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "linked panel id")
		base := fs.String("base", "", "remote panel base URL (best-effort notice)")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		err := svc.FederationRevokeLink(*id, strings.TrimRight(orEmptyStr(*base), "/"))
		if err != nil && !strings.Contains(err.Error(), "remote notice failed") {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"revoked": *id, "remote_notice": err == nil})
		}
		fmt.Println(i18n.T(lang, "fed.revoked", map[string]any{"id": *id}))
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "unknown panel subcommand")
	return schema.ExitUsage
}

func orEmptyStr(sv string) string { return sv }

// ---- ara subscription create|list|show|url|qr|set-profiles|revoke|transfer|quota ----

func cmdSubscription(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, `usage:
  ara subscription create --account ACC --name N [--limit-bytes N] [--ttl-seconds N] --profile direct:de-1 --profile transit:nl-1
  ara subscription list | show --id | url --id --token T [--base URL] | qr --id --token T --base URL [--png f.png]
  ara subscription endpoint [--origin https://vpn.example --name connect]
  ara subscription set-profiles --id --profile kind:node ...
  ara subscription set-rate --id --download-bps N [--upload-bps N] | set-device-limit --id --device D --limit-bytes N
  ara subscription set-device-slots --id SUB --max-devices N
  ara subscription activity --id SUB --days 1|7
  ara subscription device-expiry|device-revoke|device-link --id SUB --device D
  ara subscription device-add --id SUB --name NAME [--base URL]
  ara subscription delete --id SUB | set-quota --id SUB --limit-bytes N|unlimited
  ara subscription revoke --id | transfer --id --to-panel P --base URL | quota --id`)
		return schema.ExitUsage
	}
	if tail[0] == "endpoint" {
		return cmdSubscriptionEndpoint(svc, g, tail[1:], lang)
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer st.Close()
	switch tail[0] {
	case "activity", "device-expiry", "device-revoke", "device-link", "device-add":
		return cmdSubscriptionDevice(svc, st, g, tail, lang)
	case "create", "provision":
		fs := flag.NewFlagSet("subscription create", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		account := fs.String("account", "", "account id")
		name := fs.String("name", "", "human name")
		limit := fs.String("limit-bytes", "", "shared volume limit, bytes")
		maximum := fs.Int("max-devices", 0, "registered device slots (0 = no cap)")
		ttl := fs.Int("ttl-seconds", 0, "expiry (0 = none)")
		profiles := multiFlag(fs, "profile")
		if err := fs.Parse(tail[1:]); err != nil || *account == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--account required"}, nil)
		}
		var limPtr *int64
		if *limit != "" {
			v, err := strconv.ParseInt(*limit, 10, 64)
			if err != nil || v <= 0 {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--limit-bytes must be positive"}, nil)
			}
			limPtr = &v
		}
		inputs, err := parseSubProfiles(*profiles)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		var maxDevices *int
		if *maximum != 0 {
			maxDevices = maximum
		}
		endpoint, err := subscriptionShareEndpoint(svc, "")
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		var sub *controlstore.Subscription
		var token string
		if tail[0] == "provision" {
			sub, token, err = svc.ProvisionSubscription(*account, *name, limPtr, time.Duration(*ttl)*time.Second, inputs, maxDevices)
		} else {
			sub, token, err = svc.SubscriptionCreateWithDeviceLimit(*account, *name, limPtr, time.Duration(*ttl)*time.Second, inputs, maxDevices)
		}
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		fields := map[string]any{"subscription": sub, "token": token}
		if endpoint.Base() != "" {
			fields["url"] = service.SubscriptionTokenURL(endpoint.Base(), token)
		}
		if g.json {
			return okJSON(g, fields)
		}
		fmt.Println(i18n.T(lang, "sub.created", map[string]any{"id": sub.ID, "owner": sub.OwnerPanel}))
		if link, ok := fields["url"]; ok {
			fmt.Println(link)
		} else {
			fmt.Println("token: " + token)
		}
		return schema.ExitOK

	case "list":
		subs, err := st.ListSubscriptions()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		type row struct {
			ID, Account, Name, Owner string
			Used                     int64
			Limit                    *int64
			State                    string
		}
		out := []row{}
		for _, s := range subs {
			state := "active"
			if s.RevokedAt != nil {
				state = "revoked"
			} else if s.TransferredTo != "" {
				state = "transferred → " + s.TransferredTo
			}
			used, _, _ := st.QuotaUsage(s.ID)
			out = append(out, row{s.ID, s.AccountID, s.Name, s.OwnerPanel, used, s.LimitsBytes, state})
		}
		if g.json {
			return okJSON(g, map[string]any{"subscriptions": subs})
		}
		for _, r := range out {
			lim := "unlimited"
			if r.Limit != nil {
				lim = fmt.Sprintf("%d MiB", *r.Limit/(1<<20))
			}
			fmt.Printf("  %s  %s (%s)  owner=%s  used=%d  limit=%s  %s\n", r.ID, r.Name, r.Account, r.Owner, r.Used, lim, r.State)
		}
		return schema.ExitOK

	case "show":
		fs := flag.NewFlagSet("subscription show", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		sub, err := st.GetSubscription(*id)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		profs, _ := st.ListSubscriptionProfiles(*id)
		used, lim, _ := st.QuotaUsage(*id)
		if g.json {
			return okJSON(g, map[string]any{"subscription": sub, "profiles": profs, "used_bytes": used, "limit_bytes": lim})
		}
		fmt.Printf("%s  %s  owner=%s\n", sub.ID, sub.Name, sub.OwnerPanel)
		for _, p := range profs {
			fmt.Printf("  %d. %s / %s  (%s, node %s, ingress %s)\n", p.Seq, p.LabelRU, p.LabelEn, p.Kind, p.NodeID, p.IngressAddr)
		}
		return schema.ExitOK

	case "set-profiles":
		fs := flag.NewFlagSet("subscription set-profiles", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		profiles := multiFlag(fs, "profile")
		file := fs.String("profiles-file", "", "JSON array of profile routes and limits")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id and --profile required"}, nil)
		}
		inputs, err := parseSubProfiles(*profiles)
		if *file != "" {
			f, e := os.Open(*file)
			if e != nil {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, e)
			}
			dec := json.NewDecoder(io.LimitReader(f, 64<<10))
			dec.DisallowUnknownFields()
			err = dec.Decode(&inputs)
			f.Close()
		}
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if err := svc.SubscriptionSetProfiles(*id, inputs); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"updated": *id})
		}
		fmt.Println(i18n.T(lang, "sub.profiles_updated", map[string]any{"id": *id}))
		return schema.ExitOK

	case "url":
		fs := flag.NewFlagSet("subscription url", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		token := fs.String("token", "", "subscription token (from create)")
		base := fs.String("base", "", "public panel origin (or ARA_PUBLIC_URL)")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" || *token == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id and --token required"}, nil)
		}
		u, err := subscriptionShareLink(svc, *base, *token)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"url": u})
		}
		fmt.Println(u)
		return schema.ExitOK

	case "qr":
		fs := flag.NewFlagSet("subscription qr", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		token := fs.String("token", "", "subscription token")
		base := fs.String("base", "", "public panel origin (or ARA_PUBLIC_URL)")
		pngP := fs.String("png", "", "write PNG here")
		svgP := fs.String("svg", "", "write SVG here")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" || *token == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id and --token required"}, nil)
		}
		u, err := subscriptionShareLink(svc, *base, *token)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		png, svg := *pngP, *svgP
		if png != "" {
			if err := writeQR("png", u, png); err != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
			}
		}
		if svg != "" {
			if err := writeQR("svg", u, svg); err != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
			}
		}
		if g.json {
			return okJSON(g, map[string]any{"url": u, "png": png, "svg": svg})
		}
		fmt.Println(u)
		return schema.ExitOK

	case "delete", "set-quota":
		fs := flag.NewFlagSet("subscription "+tail[0], flag.ContinueOnError)
		id := fs.String("id", "", "subscription ID")
		var raw *string
		if tail[0] == "set-quota" {
			raw = fs.String("limit-bytes", "", "non-negative integer or unlimited")
		}
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		result := "deleted"
		if raw == nil {
			err = st.HideRevokedSubscription(*id, svc.PanelID())
		} else {
			result = "set"
			var limit *int64
			if *raw != "unlimited" {
				v, parseErr := strconv.ParseInt(*raw, 10, 64)
				if parseErr != nil || v < 0 {
					return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--limit-bytes N|unlimited required"}, nil)
				}
				limit = &v
			}
			err = st.SetSubscriptionQuota(*id, svc.PanelID(), limit)
		}
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]string{result: *id})
		}
		fmt.Println(*id)
		return schema.ExitOK

	case "revoke":
		fs := flag.NewFlagSet("subscription revoke", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		if err := st.RevokeSubscription(*id); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"revoked": *id})
		}
		fmt.Println(i18n.T(lang, "sub.revoked", map[string]any{"id": *id}))
		return schema.ExitOK

	case "transfer":
		fs := flag.NewFlagSet("subscription transfer", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		to := fs.String("to-panel", "", "target panel id")
		base := fs.String("base", "", "target panel base URL")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" || *to == "" || *base == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id, --to-panel and --base required"}, nil)
		}
		if err := svc.SubscriptionTransfer(*id, *to, strings.TrimRight(*base, "/")); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		used, _, _ := st.QuotaUsage(*id)
		if g.json {
			return okJSON(g, map[string]any{"transferred": *id, "to": *to, "used_bytes_preserved": used})
		}
		fmt.Println(i18n.T(lang, "sub.transferred", map[string]any{"id": *id, "to": *to, "used": used}))
		return schema.ExitOK

	case "set-device-slots":
		fs := flag.NewFlagSet("subscription set-device-slots", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		maximum := fs.Int("max-devices", -1, "registered device slots (0 = remove cap)")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" || *maximum < 0 {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id and --max-devices required"}, nil)
		}
		var maxDevices *int
		if *maximum != 0 {
			maxDevices = maximum
		}
		if err := st.SetSubscriptionMaxDevices(*id, svc.PanelID(), maxDevices); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"set": *id, "max_devices": maxDevices})
		}
		fmt.Printf("%s: %d\n", *id, *maximum)
		return schema.ExitOK

	case "set-rate":
		fs := flag.NewFlagSet("subscription set-rate", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		down := fs.String("download-bps", "", "shared account download, bit/s (0 = forbidden, empty = unlimited)")
		up := fs.String("upload-bps", "", "shared account upload, bit/s (0 = forbidden)")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		var dl, ul *int64
		if *down != "" {
			v, err := strconv.ParseInt(*down, 10, 64)
			if err != nil || v < 0 {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--download-bps must be non-negative"}, nil)
			}
			dl = &v
		}
		if *up != "" {
			v, err := strconv.ParseInt(*up, 10, 64)
			if err != nil || v < 0 {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--upload-bps must be non-negative"}, nil)
			}
			ul = &v
		}
		if err := st.SetSubscriptionRate(*id, dl, ul); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"set": *id})
		}
		fmt.Println(i18n.T(lang, "sub.rate_set", map[string]any{"id": *id}))
		return schema.ExitOK

	case "set-device-limit":
		fs := flag.NewFlagSet("subscription set-device-limit", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		dev := fs.String("device", "", "device id")
		limit := fs.String("limit-bytes", "", "device volume budget (empty = unlimited)")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" || *dev == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id and --device required"}, nil)
		}
		var lim *int64
		if *limit != "" {
			v, err := strconv.ParseInt(*limit, 10, 64)
			if err != nil || v < 0 {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--limit-bytes must be non-negative"}, nil)
			}
			lim = &v
		}
		if err := st.SetSubscriptionDeviceLimit(*id, *dev, lim); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"set": *id, "device": *dev})
		}
		fmt.Println(i18n.T(lang, "sub.device_limit_set", map[string]any{"id": *id, "device": *dev}))
		return schema.ExitOK

	case "rotate":
		fs := flag.NewFlagSet("subscription rotate", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		grace := fs.Int("grace-seconds", 0, "optional grace for the OLD token (0..86400)")
		out := fs.String("out", "", "write the new token to a 0600 file instead of stdout")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		endpoint, err := subscriptionShareEndpoint(svc, "")
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		token, graceUsed, rerr := svc.SubscriptionRotateToken(*id, time.Duration(*grace)*time.Second)
		if rerr != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, rerr)
		}
		if *out != "" {
			if werr := os.WriteFile(*out, []byte(token+"\n"), 0o600); werr != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, werr)
			}
			if g.json {
				return okJSON(g, map[string]any{"rotated": *id, "grace_seconds": graceUsed, "token_file": *out})
			}
			fmt.Println(i18n.T(lang, "sub.rotated_file", map[string]any{"id": *id, "file": *out, "grace": graceUsed}))
			return schema.ExitOK
		}
		fields := map[string]any{"rotated": *id, "grace_seconds": graceUsed, "token": token}
		if endpoint.Base() != "" {
			fields["url"] = service.SubscriptionTokenURL(endpoint.Base(), token)
		}
		if g.json {
			return okJSON(g, fields)
		}
		fmt.Println(i18n.T(lang, "sub.rotated", map[string]any{"id": *id, "grace": graceUsed}))
		if link, ok := fields["url"]; ok {
			fmt.Println(link)
		} else {
			fmt.Println("token: " + token)
		}
		return schema.ExitOK

	case "quota":
		fs := flag.NewFlagSet("subscription quota", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "subscription id")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		used, lim, err := st.QuotaUsage(*id)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		sub, err := st.GetSubscription(*id)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		deviceUsage, deviceLimits, down, up, err := st.LoadSubscriptionTransferState(*id)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"used_bytes": used, "limit_bytes": lim, "max_devices": sub.MaxDevices,
				"device_usage": deviceUsage, "device_limits": deviceLimits, "download_bps": down, "upload_bps": up, "owner_panel": sub.OwnerPanel})
		}
		if lim == nil {
			fmt.Printf("used=%d unlimited\n", used)
		} else {
			fmt.Printf("used=%d limit=%d remaining=%d\n", used, *lim, *lim-used)
		}
		if sub.MaxDevices != nil {
			fmt.Printf("max_devices=%d\n", *sub.MaxDevices)
		}
		if down != nil {
			fmt.Printf("download_bytes_per_second=%d\n", *down)
		}
		if up != nil {
			fmt.Printf("upload_bytes_per_second=%d\n", *up)
		}
		for _, device := range slices.Sorted(maps.Keys(deviceUsage)) {
			fmt.Printf("device=%s used_bytes=%d", device, deviceUsage[device])
			if limit := deviceLimits[device]; limit != nil {
				fmt.Printf(" limit_bytes=%d", *limit)
			}
			fmt.Println()
		}
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "unknown subscription subcommand")
	return schema.ExitUsage
}

func parseSubProfiles(items []string) ([]service.SubscriptionInput, error) {
	out := make([]service.SubscriptionInput, 0, len(items))
	for _, it := range items {
		parts := strings.Split(it, ":")
		if len(parts) < 2 || len(parts) > 3 || parts[1] == "" ||
			(parts[0] != "direct" && parts[0] != "transit" && parts[0] != "policy") ||
			(len(parts) == 3 && (parts[0] != "transit" || parts[2] == "")) {
			return nil, fmt.Errorf("--profile must be direct:<node>, policy:<edge> or transit:<exit>[:<edge>] (got %q)", it)
		}
		input := service.SubscriptionInput{Kind: parts[0], NodeID: parts[1]}
		if len(parts) == 3 {
			input.EdgeNodeID = parts[2]
		}
		out = append(out, input)
	}
	return out, nil
}

func multiFlag(fs *flag.FlagSet, name string) *[]string {
	var vals []string
	fs.Func(name, "repeatable "+name+" value", func(sv string) error {
		vals = append(vals, sv)
		return nil
	})
	return &vals
}

func orDefaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// writeQR renders the subscription URL locally (core/qrencode); the
// token never travels to third-party services (docs/CLIENT_INVITES_QR.md).
func writeQR(format, content, path string) error {
	m, err := qrencode.Encode([]byte(content))
	if err != nil {
		return err
	}
	switch format {
	case "png":
		b, err := qrencode.PNG(m, 8)
		if err != nil {
			return err
		}
		return os.WriteFile(path, b, 0o600)
	default:
		return os.WriteFile(path, []byte(qrencode.SVG(m, 8)), 0o600)
	}
}

// ara subscription follow: the INSTALLED client follows a subscription
// transfer safely — moved pointer from its own trusted panel, independent
// validation of the destination (schema + its own device identity), LKG
// preserved. Automatic continuation of an installed client (docs/FEDERATION.md).
func cmdSubscriptionFollow(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	fs := flag.NewFlagSet("subscription follow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	token := fs.String("token", "", "subscription fetch token")
	base := fs.String("base", "", "known panel base URL (the client's enrolled panel)")
	link := fs.String("link", "", "complete subscription URL instead of --base and --token")
	uuid := fs.String("device-uuid", "", "enrolled identity for the scope check")
	maxHops := fs.Int("max-hops", 4, "ownership-transfer hops (A→B→C) allowed")
	deadline := fs.Int("deadline-seconds", 20, "whole-chain deadline")
	apply := fs.Bool("apply-profile", false, "apply the validated catalog to profiles/default.json")
	var allowHTTP allowList
	fs.Var(&allowHTTP, "allow-http-base", "explicitly allow this http base (repeatable, lab scope)")
	if err := fs.Parse(skipSub(tail, "follow")); err != nil {
		return emitUsageError(g, err)
	}
	if *link != "" {
		if *base != "" || *token != "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, fmt.Errorf("--link cannot be combined with --base or --token"))
		}
		var err error
		*base, *token, err = service.ParseSubscriptionLink(*link, "")
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
	}
	if *token == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--token required"}, nil)
	}
	if *uuid == "" {
		if b, err := os.ReadFile(svc.State.Root + "/profiles/default.json"); err == nil {
			var prof struct {
				UUID string `json:"uuid"`
			}
			if json.Unmarshal(b, &prof) == nil {
				*uuid = prof.UUID
			}
		}
	}
	res, err := service.SubscriptionFollowChain(svc.State, service.FollowHTTPClient(time.Duration(*deadline)*time.Second),
		*token, orDefaultStr(*base, "http://127.0.0.1:8080"), service.FollowOptions{
			MaxHops: *maxHops, Deadline: time.Duration(*deadline) * time.Second,
			EnrolledUUID: *uuid, AllowedBases: allowHTTP, ApplyProfile: *apply,
			ProfileDir: filepath.Join(svc.State.Root, "profiles"),
		})
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	if g.json {
		return okJSON(g, res)
	}
	if res.Error != "" {
		fmt.Println(i18n.T(lang, "sub.follow_error", map[string]any{"detail": res.Error}))
		return schema.ExitUnavailable
	}
	if res.Followed {
		fmt.Println(i18n.T(lang, "sub.followed", map[string]any{"base": res.Base}))
	}
	if res.CatalogOK {
		extra := ""
		if res.ProfileApplied {
			extra = " + " + i18n.T(lang, "sub.follow_applied", nil)
		}
		fmt.Println(i18n.T(lang, "sub.follow_ok", map[string]any{"profiles": res.Profiles, "hash": res.Hash[:12]}) + extra)
	} else if res.LKGUsed {
		fmt.Println(i18n.T(lang, "sub.follow_lkg", nil))
	}
	return schema.ExitOK
}

type allowList []string

func (a *allowList) String() string { return strings.Join(*a, ",") }
func (a *allowList) Set(v string) error {
	*a = append(*a, v)
	return nil
}

func skipSub(args []string, sub string) []string {
	if len(args) > 0 && args[0] == sub {
		return args[1:]
	}
	return args
}

// ara subscription autoconfigure: store the auto-refresh credentials in
// the CLIENT state dir (0600) and start the agent loop. The token travels
// via stdin/file — never argv.
func cmdSubscriptionAutoconfigure(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	fs := flag.NewFlagSet("subscription autoconfigure", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	base := fs.String("base", "", "panel base URL the client follows")
	uuid := fs.String("device-uuid", "", "enrolled identity (scope check)")
	interval := fs.Int("interval-min", 15, "refresh interval, minutes")
	tokenFile := fs.String("token-file", "", "file with the fetch token")
	tokenStdin := fs.Bool("token-stdin", false, "read the fetch token from stdin")
	var allowHTTP allowList
	fs.Var(&allowHTTP, "allow-http-base", "explicitly allow this http base (repeatable, lab scope)")
	apply := fs.Bool("apply-profile", true, "apply the validated catalog to the client profile")
	if err := fs.Parse(skipSub(tail, "autoconfigure")); err != nil {
		return emitUsageError(g, err)
	}
	token, err := readSecret(*tokenFile, *tokenStdin)
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	if *base == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--base required"}, nil)
	}
	if *uuid == "" {
		if b, err := os.ReadFile(svc.State.Root + "/profiles/default.json"); err == nil {
			var prof struct {
				UUID string `json:"uuid"`
			}
			if json.Unmarshal(b, &prof) == nil {
				*uuid = prof.UUID
			}
		}
	}
	cfg := service.SubscriptionAutoRefreshConfig{Token: token, Base: *base,
		DeviceUUID: *uuid, IntervalMin: *interval, AllowedBases: allowHTTP, ApplyProfile: *apply}
	if err := svc.SubscriptionFollowConfigure(cfg); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	st, _ := svc.SubscriptionRefreshStatus()
	if g.json {
		return okJSON(g, map[string]any{"configured": true, "status": st})
	}
	fmt.Println(i18n.T(lang, "sub.autoconfigure_ok", map[string]any{"interval": *interval}))
	return schema.ExitOK
}
