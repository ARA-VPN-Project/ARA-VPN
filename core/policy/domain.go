package policy

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// LookupProfile is the IDNA profile for host names compared against rules:
// maps case, rejects disallowed characters and validates punycode labels.
var LookupProfile = idna.Lookup

// CanonicalDomain normalizes a host name to the comparison form used
// everywhere in ARA: IDNA ASCII, lowercase, no trailing dot
// (docs/ROUTING_DNS.md). Wildcards, URLs, ports and paths are rejected —
// they are silently accepting them that would create rule-bypass risk.
func CanonicalDomain(input string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("domain is empty")
	}
	if strings.ContainsAny(s, "/:?#@ ") {
		return "", fmt.Errorf("domain %q: URL/port/path characters are not a domain", input)
	}
	if strings.Contains(s, "*") {
		return "", fmt.Errorf("domain %q: wildcards are not allowed; use domain_suffix", input)
	}
	ascii, err := LookupProfile.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("domain %q: %v", input, err)
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("domain %q: exceeds 253 bytes", input)
	}
	return ascii, nil
}

// MatchesSuffix reports whether host equals suffix or is a subdomain of it,
// on label boundaries only: example.ru matches a.example.ru but not
// badexample.ru.
func MatchesSuffix(host, suffix string) bool {
	if host == suffix {
		return true
	}
	return len(host) > len(suffix) && strings.HasSuffix(host, "."+suffix)
}

// IsCanonical reports whether host is already in canonical form.
func IsCanonical(host string) bool {
	c, err := CanonicalDomain(host)
	return err == nil && c == host
}
