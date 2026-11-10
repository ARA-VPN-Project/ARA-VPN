package service

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// LinkOrigin validates the address shared with clients. Local HTTP is
// retained for isolated fixtures. User info, paths and query strings
// cannot carry credentials or change the destination of a generated link.
func LinkOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(raw, "#") || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("VALIDATION_FAILED: specify a panel origin such as https://panel.example.com")
	}
	hostname := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if hostname == "" || hostname == "invalid" || strings.HasSuffix(hostname, ".invalid") {
		return "", fmt.Errorf("VALIDATION_FAILED: panel origin must use a real hostname")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("VALIDATION_FAILED: invalid panel origin port")
		}
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1")) {
		return "", fmt.Errorf("VALIDATION_FAILED: panel origin must use HTTPS (HTTP is limited to loopback)")
	}
	return u.Scheme + "://" + u.Host, nil
}

// ParseSubscriptionLink accepts a share URL with exactly two path segments,
// or a service base plus an explicitly supplied token.
func ParseSubscriptionLink(raw, separateToken string) (base, token string, err error) {
	raw = strings.TrimSpace(raw)
	u, parseErr := url.Parse(raw)
	if parseErr != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		strings.Contains(raw, "#") || u.RawPath != "" || strings.Contains(u.Path, "%") {
		return "", "", fmt.Errorf("VALIDATION_FAILED: invalid subscription link")
	}
	base, err = LinkOrigin(u.Scheme + "://" + u.Host)
	if err != nil {
		return "", "", err
	}
	token = strings.TrimSpace(separateToken)
	if u.Path != "" && u.Path != "/" {
		name, key, full := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
		if err := ValidateSubscriptionServiceName(name, ""); err != nil {
			return "", "", err
		}
		if full {
			if token != "" && token != key {
				return "", "", fmt.Errorf("VALIDATION_FAILED: conflicting subscription tokens")
			}
			token = key
		}
		base += "/" + name
	}
	if !subscriptionToken.MatchString(token) {
		return "", "", fmt.Errorf("VALIDATION_FAILED: invalid subscription token")
	}
	return base, token, nil
}
