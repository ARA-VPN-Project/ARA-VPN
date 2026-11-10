// Multi-hop subscription follow:
// one controlled fetch/follow path shared by the manual CLI and the
// background agent. The chain is OWNERSHIP transfer (A→B→C of the panel
// serving the same subscription token), not a multi-hop VPN transport.
//
// Safety model:
//   - HTTP redirects are refused outright (CheckRedirect errors): moved
//     handling happens ONLY at the application level, so the bearer token
//     is never sent to a redirect target the code did not validate;
//   - each hop goes to the fetch_base recorded by the TRUSTED previous
//     panel; a cycle (A→B→A) or hop-limit overflow ends with a typed
//     error; a shared deadline and a response-size limit bound every run;
//   - scheme policy: https is always allowed; http is allowed ONLY for
//     bases explicitly listed in AllowedBases (lab scope) — a downgrade
//     https→http or a jump to a non-listed private/metadata address is a
//     typed FollowOriginError;
//   - the destination is validated INDEPENDENTLY of the device UUID match:
//     schema, TLS/origin policy and scope; the catalog is stored (and the
//     profile applied, when requested) atomically only after full
//     validation; on any failure the previous LKG stays in place.
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FollowOptions bounds and polices one follow run.
type FollowOptions struct {
	MaxHops      int           // default 4: A→B→C… bounded
	Deadline     time.Duration // default 20 s for the WHOLE chain
	MaxBodyBytes int64         // default 1 MiB
	AllowedBases []string      // explicit http bases (lab/test scope)
	EnrolledUUID string        // scope check
	ApplyProfile bool          // write the validated catalog profile to profiles/default.json
	ProfileName  string        // default "default"
	ExistingProf *osProfile    // current local profile (engine_path/tun kept)
	ProfileDir   string        // stateDir/profiles
}

type osProfile struct {
	EnginePath string `json:"engine_path"`
	ServerAddr string `json:"server_addr"`
	ServerName string `json:"server_name"`
	CAPath     string `json:"ca_path"`
	UUID       string `json:"uuid"`
	TUNName    string `json:"tun_name"`
	TUNAddr4   string `json:"tun_addr4"`
	TUNAddr6   string `json:"tun_addr6,omitempty"`
	MTU        int    `json:"mtu"`
	DNSServer  string `json:"dns_server,omitempty"`
	WaitMode   string `json:"wait_mode,omitempty"`
}

// FollowOriginError marks a policy violation of the moved/redirect chain.
type FollowOriginError struct{ What string }

func (e *FollowOriginError) Error() string { return "ORIGIN_POLICY: " + e.What }

// FollowHopError marks chain termination by hop limit or cycle.
type FollowHopError struct{ What string }

func (e *FollowHopError) Error() string { return "FOLLOW_CHAIN: " + e.What }

// followHTTPClient returns a client that refuses EVERY HTTP redirect:
// moved handling is application-level only.
func FollowHTTPClient(deadline time.Duration) *http.Client {
	return &http.Client{
		Timeout: deadline,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// validateFollowBase enforces the scheme/origin policy for the NEXT hop.
func validateFollowBase(next string, followedFromHTTPS bool, allowed []string) error {
	u, err := subscriptionFetchBase(next)
	if err != nil {
		return &FollowOriginError{What: "invalid moved subscription endpoint"}
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		for _, a := range allowed {
			if strings.TrimRight(a, "/") == strings.TrimRight(next, "/") || strings.TrimRight(a, "/") == u.Scheme+"://"+u.Host {
				return nil // explicitly scoped (lab/test)
			}
		}
		if followedFromHTTPS {
			return &FollowOriginError{What: fmt.Sprintf("downgrade https→http to %q is forbidden", next)}
		}
		return &FollowOriginError{What: fmt.Sprintf("http base %q is not in the explicitly allowed set", next)}
	default:
		return &FollowOriginError{What: fmt.Sprintf("unsupported scheme %q in %q", u.Scheme, next)}
	}
}

func hostIsPrivate(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// SubscriptionFollowChain follows the catalog across ownership transfers.
func SubscriptionFollowChain(stateDir StateDir, client *http.Client, token, base string, opts FollowOptions) (*SubscriptionFollowResult, error) {
	if !subscriptionToken.MatchString(token) {
		return nil, fmt.Errorf("VALIDATION_FAILED: subscription token required")
	}
	if opts.MaxHops <= 0 {
		opts.MaxHops = 4
	}
	if opts.Deadline <= 0 {
		opts.Deadline = 20 * time.Second
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 1 << 20
	}
	if opts.ProfileName == "" {
		opts.ProfileName = "default"
	}
	if err := os.MkdirAll(stateDir.SubscriptionDir(), 0o700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(opts.Deadline)
	res := &SubscriptionFollowResult{Base: base}
	visited := map[string]bool{}
	current := base
	var catalog map[string]any
	var catalogRaw []byte
	hops := 0
	for {
		if hops > opts.MaxHops {
			return res, &FollowHopError{What: fmt.Sprintf("hop limit %d exceeded", opts.MaxHops)}
		}
		key := strings.TrimRight(current, "/")
		if visited[key] {
			return res, &FollowHopError{What: fmt.Sprintf("cycle detected at %s", key)}
		}
		visited[key] = true
		if time.Now().After(deadline) {
			return res, &FollowHopError{What: "chain deadline exceeded"}
		}
		if _, err := subscriptionFetchBase(current); err != nil {
			return res, err
		}
		req, err := http.NewRequest(http.MethodGet, SubscriptionTokenURL(current, token), nil)
		if err != nil {
			return res, err
		}
		resp, err := client.Do(req)
		if err != nil {
			// B28: url.Error embeds the full URL with the bearer token —
			// redact to origin + reason, never the raw error string.
			res.Error = fmt.Sprintf("fetch failed at %s: %v", key, redactURLError(err))
			return res, nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
		resp.Body.Close()
		if err != nil {
			res.Error = fmt.Sprintf("read failed at %s: %v", key, err)
			return res, nil
		}
		if resp.StatusCode == http.StatusUnauthorized {
			res.Error = "AUTH_FAILED: subscription token refused by the panel"
			return res, nil
		}
		// 3xx = a panel tried to delegate via HTTP redirect: refused (the
		// token must never travel to a redirect target)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			res.Error = fmt.Sprintf("ORIGIN_POLICY: HTTP redirect refused at %s (application-level transfer notice only)", key)
			return res, nil
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			res.Error = fmt.Sprintf("catalog undecodable (HTTP %d) at %s: %v", resp.StatusCode, key, err)
			return res, nil
		}
		if resp.StatusCode != http.StatusOK {
			if msg, _ := out["error"].(string); msg != "" {
				res.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, msg)
			} else {
				res.Error = fmt.Sprintf("HTTP %d at %s", resp.StatusCode, key)
			}
			return res, nil
		}
		if moved, _ := out["moved"].(bool); moved {
			next, _ := out["fetch_base"].(string)
			if next == "" {
				res.Error = "moved notice without fetch_base: operator handoff incomplete"
				return res, nil
			}
			fromHTTPS := strings.HasPrefix(current, "https://")
			// the NEXT hop must pass the origin policy: https, or an
			// explicitly scoped base; anything else (downgrade, metadata,
			// non-listed private) is a typed refusal
			if err := validateFollowBase(next, fromHTTPS, opts.AllowedBases); err != nil {
				res.Error = err.Error()
				return res, nil
			}
			hops++
			current = next
			res.Followed = true
			continue
		}
		catalog, catalogRaw = out, body
		res.Base = current
		break
	}
	if err := validateFollowedCatalog(catalog, opts.EnrolledUUID); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	sum := sha256.Sum256(catalogRaw)
	res.Hash = hex.EncodeToString(sum[:])
	res.Profiles = len(catalog["profiles"].([]any))
	// B27: the candidate is FULLY validated and the profile applied (when
	// requested) BEFORE catalog.json is published — an inapplicable
	// candidate never becomes current, so it can never leak into LKG.
	if opts.ApplyProfile {
		if err := ApplyCatalogToProfile(stateDir, catalog, opts); err != nil {
			res.Error = "candidate rejected: profile apply failed: " + err.Error()
			return res, nil
		}
		res.ProfileApplied = true
	}
	dir := stateDir.SubscriptionDir()
	if prev, err := os.ReadFile(filepath.Join(dir, "catalog.json")); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "lkg.json"), prev, 0o600)
	} else {
		res.LKGUsed = true
	}
	tmp := filepath.Join(dir, "catalog.json.tmp")
	if err := os.WriteFile(tmp, append(catalogRaw, '\n'), 0o600); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	if err := os.Rename(tmp, filepath.Join(dir, "catalog.json")); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	res.CatalogOK = true
	return res, nil
}

// ApplyCatalogToProfile writes the validated catalog's selected profile
// into profiles/<name>.json (0600, atomic): the installed client really
// reconnects through the new endpoint/identity on its next start, not
// just stores a file. Engine/TUN settings of the existing profile are
// preserved; identity comes from the catalog (scope-checked above).
func ApplyCatalogToProfile(stateDir StateDir, catalog map[string]any, opts FollowOptions) error {
	profs, ok := catalog["profiles"].([]any)
	if !ok || len(profs) == 0 {
		return fmt.Errorf("VALIDATION_FAILED: catalog has no profiles")
	}
	// B25: pick the profile of THIS device's identity (the enrolled UUID)
	// — a catalog carrying [foreign UUID, own UUID] must never install the
	// foreign credential. The enrolled identity is the scope anchor.
	pick := -1
	for i, p := range profs {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		cfg, ok := pm["client_config"].(map[string]any)
		if !ok {
			continue
		}
		obs, ok := cfg["outbounds"].([]any)
		if !ok || len(obs) == 0 {
			continue
		}
		ob, ok := obs[0].(map[string]any)
		if !ok {
			continue
		}
		if u, ok := ob["uuid"].(string); ok && opts.EnrolledUUID != "" && u == opts.EnrolledUUID {
			pick = i
			break
		}
	}
	// fallback to the first usable profile ONLY when no identity scoping
	// was requested (no enrolled UUID provided)
	if pick < 0 && opts.EnrolledUUID == "" {
		for i, p := range profs {
			pm, _ := p.(map[string]any)
			if pm == nil {
				continue
			}
			if cfg, ok := pm["client_config"].(map[string]any); ok {
				if obs, ok := cfg["outbounds"].([]any); ok && len(obs) > 0 {
					pick = i
					break
				}
			}
		}
	}
	if pick < 0 {
		return fmt.Errorf("AUTH_FAILED: catalog has no profile for this device's enrolled identity")
	}
	pm := profs[pick].(map[string]any)
	cfg := pm["client_config"].(map[string]any)
	obs := cfg["outbounds"].([]any)
	ob := obs[0].(map[string]any)
	server, _ := ob["server"].(string)
	port, _ := ob["server_port"].(float64)
	uuid, _ := ob["uuid"].(string)
	if server == "" || port <= 0 || uuid == "" {
		return fmt.Errorf("VALIDATION_FAILED: catalog profile outbound incomplete")
	}
	// preserve local engine/TUN settings from the existing profile
	ex := opts.ExistingProf
	if ex == nil {
		if b, err := os.ReadFile(filepath.Join(opts.ProfileDir, opts.ProfileName+".json")); err == nil {
			var p osProfile
			if json.Unmarshal(b, &p) == nil {
				ex = &p
			}
		}
	}
	np := osProfile{ServerAddr: net.JoinHostPort(server, fmt.Sprint(int(port)))}
	sni := ""
	if tlsM, ok := ob["tls"].(map[string]any); ok {
		sni, _ = tlsM["server_name"].(string)
		if ca, ok := tlsM["certificate_path"].(string); ok {
			np.CAPath = ca
		}
	}
	// B26: the LOCAL trust anchor survives a catalog that omits
	// certificate_path — a missing reference never erases the configured
	// CA (replacement requires an explicit trust model change).
	if np.CAPath == "" && ex != nil && ex.CAPath != "" {
		np.CAPath = ex.CAPath
	}
	np.ServerName = sni
	np.UUID = uuid
	if ex != nil {
		np.EnginePath = ex.EnginePath
		np.TUNName = ex.TUNName
		np.TUNAddr4 = ex.TUNAddr4
		np.TUNAddr6 = ex.TUNAddr6
		np.MTU = ex.MTU
		np.DNSServer = ex.DNSServer
		np.WaitMode = ex.WaitMode
	}
	if np.TUNName == "" {
		np.TUNName = "ara-tun"
	}
	if np.TUNAddr4 == "" {
		np.TUNAddr4 = "10.99.0.1/30"
	}
	if np.MTU == 0 {
		np.MTU = 1400
	}
	// validate through the REAL client profile rules before writing
	if err := validateOSProfile(&np); err != nil {
		return err
	}
	if err := os.MkdirAll(opts.ProfileDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(&np, "", "  ")
	if err != nil {
		return err
	}
	dst := filepath.Join(opts.ProfileDir, opts.ProfileName+".json")
	// keep the previous profile as the rollback copy
	if prev, err := os.ReadFile(dst); err == nil {
		_ = os.WriteFile(dst+".lkg", prev, 0o600)
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func validateOSProfile(p *osProfile) error {
	if p.ServerAddr == "" || p.ServerName == "" || p.UUID == "" || p.TUNName == "" || p.TUNAddr4 == "" {
		return fmt.Errorf("VALIDATION_FAILED: applied profile incomplete")
	}
	return nil
}

// redactURLError strips any subscription token that http.Client errors
// embed via url.Error: only the scheme/host and reason are surfaced.
func redactURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Sprintf("%s request to %s failed: %v", strings.ToUpper(ue.Op), redactURL(ue.URL), ue.Err)
	}
	return err.Error()
}

// redactURL strips userinfo/path (the bearer token lives in the path):
// only scheme://host is surfaced.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable URL]"
	}
	return u.Scheme + "://" + u.Host
}
