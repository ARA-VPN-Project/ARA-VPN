package main

// invite + enroll commands (docs/CLIENT_INVITES_QR.md): the operator
// creates/reviews/revokes invites and exports QR artifacts locally; the
// client redeems a link once and stores the resulting profile. QR
// rendering is local (core/qrencode); the token never travels to third
// parties and never appears in logs or referrers (fragment-based link).

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aravpn/core/qrencode"
	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

// controlCall performs one authenticated control API request.
func controlCall(g *globals, method, path string, body any) (json.RawMessage, int, error) {
	token := os.Getenv("ARA_CONTROL_TOKEN")
	if token == "" {
		return nil, 0, fmt.Errorf("ARA_CONTROL_TOKEN is not set (operator token from the control state dir)")
	}
	base := os.Getenv("ARA_CONTROL_URL")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimSuffix(base, "/")+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := service.FollowHTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return json.RawMessage(raw), resp.StatusCode, nil
}

func cmdInvite(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara invite create --device <id> [--base https://panel.example.com] | list | revoke --id <id> | show --id <id> | qr --token <token> [--base URL] [--png f.png] [--svg f.svg]")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "create":
		fs := flag.NewFlagSet("invite create", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		device := fs.String("device", "", "device id to invite")
		baseFlag := fs.String("base", "", "public panel origin (or ARA_ENROLL_BASE)")
		ttl := fs.Int("ttl-seconds", 86400, "token lifetime in seconds (<= 7 days)")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *device == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--device required"}, nil)
		}
		base, err := shareLinkOrigin(*baseFlag, "ARA_ENROLL_BASE")
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		raw, code, err := controlCall(g, http.MethodPost, "/api/v1/invites", map[string]any{"device_id": *device, "ttl_seconds": *ttl})
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if code != http.StatusCreated {
			return fail(g, lang, schema.CodeAuth, "error."+schema.CodeAuth, map[string]any{"detail": string(raw)}, nil)
		}
		var res struct {
			Invite struct {
				ID        string `json:"id"`
				ExpiresAt string `json:"expires_at"`
			} `json:"invite"`
			Token string `json:"token"`
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		link := (&url.URL{Path: "/enroll", Fragment: res.Token}).String()
		link = base + link
		if g.json {
			return okJSON(g, map[string]any{"invite_id": res.Invite.ID, "expires_at": res.Invite.ExpiresAt, "enroll_link": link})
		}
		fmt.Println(i18n.T(lang, "invite.created", map[string]any{"id": res.Invite.ID, "expires_at": res.Invite.ExpiresAt}))
		fmt.Println(i18n.T(lang, "invite.link_once", nil))
		fmt.Println(link)
		return schema.ExitOK

	case "list":
		raw, code, err := controlCall(g, http.MethodGet, "/api/v1/invites", nil)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if code != http.StatusOK {
			return fail(g, lang, schema.CodeAuth, "error."+schema.CodeAuth, nil, nil)
		}
		if g.json {
			return okJSON(g, json.RawMessage(raw))
		}
		fmt.Println(string(raw))
		return schema.ExitOK

	case "revoke":
		fs := flag.NewFlagSet("invite revoke", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "invite id")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		raw, code, err := controlCall(g, http.MethodPost, "/api/v1/invites/revoke", map[string]any{"id": *id})
		if err != nil || code != http.StatusOK {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, json.RawMessage(raw))
		}
		fmt.Println(i18n.T(lang, "invite.revoked", map[string]any{"id": *id}))
		return schema.ExitOK

	case "show":
		fs := flag.NewFlagSet("invite show", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "invite id")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		raw, code, err := controlCall(g, http.MethodGet, "/api/v1/invites", nil)
		if err != nil || code != http.StatusOK {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		var res struct {
			Invites []map[string]any `json:"invites"`
		}
		_ = json.Unmarshal(raw, &res)
		for _, inv := range res.Invites {
			if fmt.Sprint(inv["id"]) == *id {
				if g.json {
					return okJSON(g, inv)
				}
				fmt.Println(string(mustJSON(inv)))
				return schema.ExitOK
			}
		}
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "invite not found"}, nil)

	case "qr":
		fs := flag.NewFlagSet("invite qr", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "invite id")
		token := fs.String("token", "", "plaintext token (alternative to --id; from create output)")
		baseFlag := fs.String("base", "", "public panel origin (or ARA_ENROLL_BASE)")
		pngOut := fs.String("png", "", "write PNG here")
		svgOut := fs.String("svg", "", "write SVG here")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		link := ""
		if *token != "" {
			base, err := shareLinkOrigin(*baseFlag, "ARA_ENROLL_BASE")
			if err != nil {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
			}
			link = base + (&url.URL{Path: "/enroll", Fragment: *token}).String()
		} else if *id != "" {
			raw, code, err := controlCall(g, http.MethodGet, "/api/v1/invites", nil)
			if err != nil || code != http.StatusOK {
				return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
			}
			var res struct {
				Invites []map[string]any `json:"invites"`
			}
			_ = json.Unmarshal(raw, &res)
			for _, inv := range res.Invites {
				if fmt.Sprint(inv["id"]) == *id {
					if l, ok := inv["enroll_link"].(string); ok {
						link = l
					}
					break
				}
			}
		}
		if link == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "cannot resolve link for --id (tokens are shown once at create; use --token)"}, nil)
		}
		m, err := qrencode.Encode([]byte(link))
		if err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		if *pngOut != "" {
			b, err := qrencode.PNG(m, 8)
			if err != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
			}
			if err := os.WriteFile(*pngOut, b, 0o600); err != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
			}
		}
		if *svgOut != "" {
			if err := os.WriteFile(*svgOut, []byte(qrencode.SVG(m, 8)), 0o600); err != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
			}
		}
		if g.json {
			return okJSON(g, map[string]any{"png": *pngOut, "svg": *svgOut})
		}
		// terminal preview from the matrix
		fmt.Println(i18n.T(lang, "invite.qr_exported", map[string]any{"png": *pngOut, "svg": *svgOut}))
		renderTerminalQR(m)
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "usage: ara invite create|list|revoke|show|qr")
	return schema.ExitUsage
}

func shareLinkOrigin(explicit, envKey string) (string, error) {
	for _, value := range []string{explicit, os.Getenv(envKey), os.Getenv("ARA_PUBLIC_URL")} {
		if strings.TrimSpace(value) != "" {
			return service.LinkOrigin(value)
		}
	}
	if envKey == "ARA_PUBLIC_URL" {
		return "", fmt.Errorf("VALIDATION_FAILED: set --base or ARA_PUBLIC_URL to the panel origin")
	}
	return "", fmt.Errorf("VALIDATION_FAILED: set --base, %s or ARA_PUBLIC_URL to the panel origin", envKey)
}

func renderTerminalQR(m [][]bool) {
	size := len(m)
	quiet := 2
	// 2x2 modules per terminal block keeps aspect ratio square
	for r := -quiet; r < size+quiet; r += 2 {
		line := strings.Builder{}
		for c := -quiet; c < size+quiet; c += 2 {
			dark := func(y, x int) bool {
				return y >= 0 && x >= 0 && y < size && x < size && m[y][x]
			}
			a, b, cc, d := dark(r, c), dark(r, c+1), dark(r+1, c), dark(r+1, c+1)
			switch {
			case a && b && cc && d:
				line.WriteRune('█')
			case a && b && cc:
				line.WriteRune('▀')
			case a && b && d:
				line.WriteRune('▀') // approximation is acceptable for preview
			case a && cc && d:
				line.WriteRune('█')
			case b && cc && d:
				line.WriteRune('▄')
			case a && b:
				line.WriteRune('▀')
			case cc && d:
				line.WriteRune('▄')
			case a:
				line.WriteRune('▘')
			case b:
				line.WriteRune('▝')
			case cc:
				line.WriteRune('▖')
			case d:
				line.WriteRune('▗')
			default:
				line.WriteRune(' ')
			}
		}
		fmt.Println(line.String())
	}
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// cmdEnroll redeems an invite link once and stores the client profile.
func cmdEnroll(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	link := fs.String("link", "", "enrollment link (https://…/enroll#<token>)")
	server := fs.String("server", "", "edge address host:port for the profile")
	serverName := fs.String("server-name", "edge.ara.lab", "TLS server name")
	caPath := fs.String("ca", "", "path to the edge CA certificate")
	engine := fs.String("engine", "sing-box", "pinned engine binary path")
	profile := fs.String("profile", "default", "profile name to write")
	if err := fs.Parse(tail); err != nil {
		return emitUsageError(g, err)
	}
	if *link == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--link required"}, nil)
	}
	u, err := url.Parse(*link)
	if err != nil || u.Path != "/enroll" || u.Fragment == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "link must carry the token in the fragment"}, nil)
	}
	token := u.Fragment
	// redeem target: the control origin. The link's host is the default
	// (the fragment never leaves this process); an explicit override env
	// redirects to a known control instance (lab deployments, split DNS).
	base := u.Scheme + "://" + u.Host
	if b := os.Getenv("ARA_ENROLL_BASE"); b != "" {
		base = strings.TrimSuffix(b, "/")
	} else if c := os.Getenv("ARA_CONTROL_URL"); c != "" {
		base = strings.TrimSuffix(c, "/")
	}
	base, err = service.LinkOrigin(base)
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	body, _ := json.Marshal(map[string]any{"token": token})
	resp, err := service.FollowHTTPClient(10*time.Second).Post(base+"/api/v1/invites/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fail(g, lang, schema.CodeAuth, "error."+schema.CodeAuth, map[string]any{"detail": string(raw)}, nil)
	}
	var res struct {
		Device struct {
			ID        string `json:"id"`
			AccountID string `json:"account_id"`
			Name      string `json:"name"`
			VlessUUID string `json:"vless_uuid"`
		} `json:"device"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	if *server == "" || *caPath == "" {
		// redeem-only mode: report what was received without writing a profile
		if g.json {
			return okJSON(g, map[string]any{"redeemed": true, "device_id": res.Device.ID, "vless_uuid": res.Device.VlessUUID})
		}
		fmt.Println(i18n.T(lang, "enroll.redeemed", map[string]any{"device": res.Device.ID}))
		return schema.ExitOK
	}
	prof := map[string]any{
		"engine_path": *engine,
		"server_addr": *server,
		"server_name": *serverName,
		"ca_path":     *caPath,
		"uuid":        res.Device.VlessUUID,
		"tun_name":    "ara-tun",
		"tun_addr4":   "10.99.0.1/30",
		"tun_addr6":   "fd00:99::1/126",
		"mtu":         1400,
		"wait_mode":   "tun",
	}
	dir := g.stateDir
	if dir == "" {
		def, derr := service.DefaultStateDir()
		if derr != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, derr)
		}
		dir = def.Root
	}
	pdir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	b, _ := json.MarshalIndent(prof, "", "  ")
	path := filepath.Join(pdir, *profile+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	if g.json {
		return okJSON(g, map[string]any{"redeemed": true, "device_id": res.Device.ID, "profile": path})
	}
	fmt.Println(i18n.T(lang, "enroll.profile_saved", map[string]any{"device": res.Device.ID, "profile": path}))
	return schema.ExitOK
}
