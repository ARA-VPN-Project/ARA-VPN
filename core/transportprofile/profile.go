// Package transportprofile is the typed model of one transport profile for
// one hop (docs/TRANSPORT_PROFILES.md): protocol (vless|trojan|hysteria2),
// network transport (tcp|udp) and TLS/security parameters are separate
// fields; protocol credentials never live in the profile — only a
// credential reference resolved from the protected secret store at render
// time. tcp/udp remain network transports; they are never a protocol
// choice (docs/TRANSPORTS.md).
//
// The capability matrix distinguishes what THIS build renders and accepts
// from what is lab-proven; docs keep that boundary honest. Unsupported
// combinations fail with a typed error mapped to UNSUPPORTED_CAPABILITY,
// never a best-effort imitation.
package transportprofile

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Protocol is the wire protocol of the hop.
type Protocol string

const (
	ProtocolVLESS     Protocol = "vless"
	ProtocolTrojan    Protocol = "trojan"
	ProtocolHysteria2 Protocol = "hysteria2"
)

// Transport is the network transport the protocol runs over.
type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// Security is the channel security binding. Plaintext profiles do not
// exist (docs/TRANSPORTS.md); REALITY is a separate capability that this
// build does not render yet (UNSUPPORTED_CAPABILITY until a proven engine
// configuration lands in the lab).
type Security string

const (
	SecurityTLS     Security = "tls"
	SecurityREALITY Security = "reality"
)

// Role is which hop the profile serves; the same protocol can be
// implemented for one role and not the other (Client→Edge and Edge→Exit
// are configured and validated independently).
type Role string

const (
	RoleIngress Role = "ingress" // client → edge
	RoleTransit Role = "transit" // edge → exit
)

// Profile is one typed transport profile (control store: transport_profiles).
type Profile struct {
	ID       string    `json:"id"`
	NodeID   string    `json:"node_id"` // owning exit node
	Role     Role      `json:"role"`
	Protocol Protocol  `json:"protocol"`
	Transport Transport `json:"transport"`
	Security Security  `json:"security"`
	TLS      *TLS      `json:"tls,omitempty"`
	// CredentialRef points into the protected secret store
	// ("arasec://transit/<profile-id>"); the profile JSON itself never
	// carries credentials (docs/SECURITY.md).
	CredentialRef string `json:"credential_ref"`

	// Lifecycle timestamps (control plane bookkeeping).
	CreatedAt time.Time  `json:"created_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// TLS carries the TLS/security parameters of the profile.
type TLS struct {
	ServerName string `json:"server_name"`
	// CAPath pins the verification root; empty means the platform store,
	// which lab profiles must never rely on (pin the test CA explicitly).
	CAPath string   `json:"ca_path,omitempty"`
	ALPN   []string `json:"alpn,omitempty"`

	// REALITY-only parameters: rejected for this build's capability set;
	// kept as explicit fields so a future validated engine configuration
	// does not need a schema change.
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	RealityShortID   string `json:"reality_short_id,omitempty"`
	// Flow is the protocol flow (e.g. xtls-rprx-vision); meaningful only
	// with REALITY in the pinned engine.
	Flow string `json:"flow,omitempty"`
}

// ValidationError is the typed rejection with the stable code prefix so
// callers surface VALIDATION_FAILED with a machine-stable message.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return "VALIDATION_FAILED: " + e.msg }

func invalid(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// UnsupportedError marks a well-formed combination this build refuses; it
// maps to UNSUPPORTED_CAPABILITY (stable code, never a silent downgrade).
type UnsupportedError struct {
	What string
}

func (e *UnsupportedError) Error() string { return "UNSUPPORTED_CAPABILITY: " + e.What }

// Validate checks the profile as a whole. Role must be set explicitly:
// the same protocol can be accepted for transit and refused for ingress.
func (p *Profile) Validate() error {
	if p.ID == "" || strings.ContainsAny(p.ID, " \t/\\") {
		return invalid("transport profile: id is required and must not contain whitespace or path separators")
	}
	// NodeID is control-plane bookkeeping: the store validates node
	// existence on insert; the client ingress profile (engine-side
	// rendering) is not store-backed and legitimately has none.
	switch p.Role {
	case RoleIngress, RoleTransit:
	default:
		return invalid("transport profile %s: role must be ingress|transit", p.ID)
	}
	switch p.Protocol {
	case ProtocolVLESS, ProtocolTrojan:
		if p.Transport == "" {
			p.Transport = TransportTCP
		}
		if p.Transport != TransportTCP {
			return invalid("transport profile %s: %s runs over tcp (got %q)", p.ID, p.Protocol, p.Transport)
		}
	case ProtocolHysteria2:
		if p.Transport == "" {
			p.Transport = TransportUDP
		}
		if p.Transport != TransportUDP {
			return invalid("transport profile %s: hysteria2 runs over udp (got %q)", p.ID, p.Transport)
		}
	case "":
		return invalid("transport profile %s: protocol is required", p.ID)
	default:
		return invalid("transport profile %s: unknown protocol %q", p.ID, p.Protocol)
	}
	switch p.Security {
	case SecurityTLS:
		if p.TLS == nil {
			return invalid("transport profile %s: security tls requires tls parameters", p.ID)
		}
		if err := p.TLS.Validate(); err != nil {
			return err
		}
	case SecurityREALITY:
		return &UnsupportedError{What: fmt.Sprintf("REALITY (requested on profile %s): a separate capability pending a lab-proven engine configuration; tls is the supported security", p.ID)}
	case "":
		return invalid("transport profile %s: security is required (tls; no plaintext profiles)", p.ID)
	default:
		return invalid("transport profile %s: unknown security %q", p.ID, p.Security)
	}
	if err := ValidateCredentialRef(p.CredentialRef); err != nil {
		return err
	}
	return nil
}

// ValidateCredentialRef checks the reference shape only; resolution
// happens in the secret store.
func ValidateCredentialRef(ref string) error {
	if ref == "" {
		return invalid("credential_ref is required")
	}
	if !strings.HasPrefix(ref, "arasec://") || len(ref) <= len("arasec://") {
		return invalid("credential_ref must be arasec://<scope>/<name>")
	}
	if strings.ContainsAny(ref, " \t\r\n") {
		return invalid("credential_ref must not contain whitespace")
	}
	return nil
}

// Validate checks TLS parameters. The server name is what the client
// verifies against the presented certificate; pinning the CA file is
// required for ARA profiles so verification never silently degrades.
func (t *TLS) Validate() error {
	if t == nil {
		return invalid("tls: parameters required")
	}
	if t.ServerName == "" {
		return invalid("tls: server_name is required")
	}
	if _, _, err := net.SplitHostPort(t.ServerName); err == nil {
		return invalid("tls: server_name must be a hostname, not host:port")
	}
	if strings.ContainsAny(t.ServerName, "/\\ \t") {
		return invalid("tls: server_name contains invalid characters")
	}
	if t.Flow != "" && t.RealityPublicKey == "" {
		return &UnsupportedError{What: "flow without REALITY is not a supported combination (vision requires reality; refused instead of a silent plaintext flow)"}
	}
	return nil
}

// Supported reports whether this build renders and accepts the
// combination for the given role. The matrix is the single authority both
// for product validation and for the UI/CLI advertisement
// (docs/TRANSPORT_PROFILES.md):
//
//	transit: vless+tls, trojan+tls, hysteria2+tls (udp alternative)
//	ingress: vless+tls only — the edge terminates access identity itself;
//	         trojan/hysteria2 ingress require a separate engine listener
//	         with per-device identity binding and are not implemented.
func Supported(r Role, proto Protocol, sec Security) bool {
	if sec != SecurityTLS {
		return false
	}
	switch r {
	case RoleTransit:
		switch proto {
		case ProtocolVLESS, ProtocolTrojan, ProtocolHysteria2:
			return true
		}
	case RoleIngress:
		return proto == ProtocolVLESS
	}
	return false
}

// CheckSupported validates and returns the typed UNSUPPORTED_CAPABILITY
// error when the role/protocol/security combination is not implemented.
func CheckSupported(r Role, proto Protocol, sec Security) error {
	if !Supported(r, proto, sec) {
		return &UnsupportedError{What: fmt.Sprintf("%s profile %s+%s for role %s", string(r), proto, sec, r)}
	}
	return nil
}
