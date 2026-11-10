package service

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const DefaultSubscriptionService = "sub"

var subscriptionServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var subscriptionToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type SubscriptionEndpoint struct {
	Origin string `json:"origin"`
	Name   string `json:"name"`
}

func ValidateSubscriptionServiceName(name, adminPath string) error {
	if !subscriptionServiceName.MatchString(name) || strings.EqualFold("/"+name, adminPath) {
		return fmt.Errorf("VALIDATION_FAILED: invalid subscription service name")
	}
	switch strings.ToLower(name) {
	case "api", "healthz", "enroll", "admin":
		return fmt.Errorf("VALIDATION_FAILED: subscription service name is reserved")
	}
	return nil
}

func (e SubscriptionEndpoint) Base() string {
	if e.Origin == "" {
		return ""
	}
	return e.Origin + "/" + e.Name
}

func (s *Service) SubscriptionEndpoint() (SubscriptionEndpoint, error) {
	e := SubscriptionEndpoint{Name: DefaultSubscriptionService}
	b, err := os.ReadFile(filepath.Join(s.State.Root, "subscription-endpoint.json"))
	if os.IsNotExist(err) {
		return e, nil
	}
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return e, err
	}
	if err := ValidateSubscriptionServiceName(e.Name, ""); err != nil {
		return e, err
	}
	e.Origin, err = LinkOrigin(e.Origin)
	return e, err
}

func (s *Service) SetSubscriptionEndpoint(e SubscriptionEndpoint, adminPath string) (SubscriptionEndpoint, error) {
	var err error
	e.Origin, err = LinkOrigin(e.Origin)
	if err != nil {
		return e, err
	}
	e.Name = strings.TrimSpace(e.Name)
	if err := ValidateSubscriptionServiceName(e.Name, adminPath); err != nil {
		return e, err
	}
	if adminPath == "" {
		// CLI operates on the panel's local state. The server checks its
		// effective administrative override independently.
		if b, err := os.ReadFile(filepath.Join(s.State.Root, "admin.path")); err == nil {
			if err := ValidateSubscriptionServiceName(e.Name, strings.TrimSpace(string(b))); err != nil {
				return e, err
			}
		} else if !os.IsNotExist(err) {
			return e, err
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	prepare := func(f *os.File) error {
		if os.Geteuid() != 0 {
			return nil
		}
		info, err := os.Stat(s.State.Root)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot identify the panel state owner")
		}
		return f.Chown(int(owner.Uid), int(owner.Gid))
	}
	return e, durableFileWrite(filepath.Join(s.State.Root, "subscription-endpoint.json"), append(b, '\n'), prepare)
}

// subscriptionFetchBase accepts an origin or an origin with one service
// segment, with no credentials, query, fragment, or escaped path.
func subscriptionFetchBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || strings.Contains(raw, "#") || u.RawPath != "" ||
		(u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("VALIDATION_FAILED: invalid subscription endpoint")
	}
	if u.Path != "" && u.Path != "/" {
		if err := ValidateSubscriptionServiceName(strings.TrimPrefix(u.Path, "/"), ""); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// SubscriptionTokenURL builds a fetch link. An origin-only base uses the
// default service name for explicit --base/--token and federation peers.
func SubscriptionTokenURL(baseURL, token string) string {
	base := strings.TrimRight(baseURL, "/")
	if u, err := url.Parse(base); err == nil && u.Path == "" {
		base += "/" + DefaultSubscriptionService
	}
	return base + "/" + url.PathEscape(token)
}
