// Package schema defines versioned envelopes, stable error codes and the
// product-wide identifier types shared by ara-core consumers (CLI, agent,
// control). JSON keys here are part of the automation contract and must not
// be renamed without a schema_version bump (see docs/CLI_AUTOMATION.md).
package schema

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SchemaVersion is the version of the config/policy JSON contract produced
// and consumed by this build. Config schema, policy_revision and core API
// version are versioned independently (docs/ARCHITECTURE.md).
const SchemaVersion = 1

// APIVersion is the versioned envelope value used by CLI --json output.
const APIVersion = "ara.api/v1"

// Envelope is the single versioned object every CLI --json invocation prints
// to stdout. Exactly one of data / error is set.
type Envelope struct {
	APIVersion string `json:"api_version"`
	OK         bool   `json:"ok"`
	RequestID  string `json:"request_id"`
	Data       any    `json:"data,omitempty"`
	Error      *Error `json:"error,omitempty"`
}

// Error is the typed machine-readable error. Code and MessageKey are stable
// identifiers and are never localized; human text is resolved from the
// message catalog via MessageKey and Params.
type Error struct {
	Code       string         `json:"code"`
	MessageKey string         `json:"message_key"`
	Params     map[string]any `json:"params,omitempty"`
	Retryable  bool           `json:"retryable"`
}

// Stable error codes (docs/DIAGNOSTICS.md, docs/CLI_AUTOMATION.md).
const (
	CodeValidation         = "VALIDATION_FAILED"
	CodeAuth               = "AUTH_FAILED"
	CodePermission         = "PERMISSION_DENIED"
	CodeConflict           = "CONFLICT"
	CodePlanStale          = "PLAN_STALE"
	CodePlanExpired        = "PLAN_EXPIRED"
	CodeUnavailable        = "UNAVAILABLE"
	CodeAgentUnavailable   = "AGENT_UNAVAILABLE"
	CodeUnsupported        = "UNSUPPORTED_CAPABILITY"
	CodeVerification       = "VERIFICATION_FAILED"
	CodePolicyInvalid      = "POLICY_INVALID"
	CodeCertInvalid        = "CERT_INVALID"
	CodeAccessUnreachable  = "ACCESS_UNREACHABLE"
	CodeDNSScopeFailed     = "DNS_SCOPE_FAILED"
	CodeMTUSuspected       = "MTU_SUSPECTED"
	CodePortConflict       = "PORT_CONFLICT"
	CodeQuotaExceeded      = "QUOTA_EXCEEDED"
	CodeNoEgress           = "NO_EGRESS_AVAILABLE"
	CodeAllForeignDown     = "ALL_FOREIGN_DOWN_RU_FALLBACK"
	CodeUpdateSignInvalid  = "UPDATE_SIGNATURE_INVALID"
	CodeUpdateExpired      = "UPDATE_EXPIRED"
	CodeUpdateChanMismatch = "UPDATE_CHANNEL_MISMATCH"
	CodePartial            = "PARTIAL_ROLLBACK_NEEDED"
	CodeInternal           = "INTERNAL"
)

// Exit codes documented and tested (docs/CLI_AUTOMATION.md).
const (
	ExitOK          = 0
	ExitUsage       = 2 // validation / usage error
	ExitAuth        = 3 // auth / permission
	ExitConflict    = 4 // conflict / stale revision or plan
	ExitUnavailable = 5 // service unavailable
	ExitUnsupported = 6 // capability not supported by this build/target
	ExitSecurity    = 7 // verification / security failure
	ExitPartial     = 8 // partial success / rollback needed
)

// ExitCodeFor maps a stable error code to the documented CLI exit code.
func ExitCodeFor(code string) int {
	switch code {
	case CodeValidation, CodePolicyInvalid:
		return ExitUsage
	case CodeAuth, CodePermission, CodeCertInvalid:
		return ExitAuth
	case CodeConflict, CodePlanStale, CodePlanExpired:
		return ExitConflict
	case CodeUnavailable, CodeAgentUnavailable, CodeAccessUnreachable,
		CodeDNSScopeFailed, CodePortConflict, CodeMTUSuspected:
		return ExitUnavailable
	case CodeUnsupported:
		return ExitUnsupported
	case CodeVerification, CodeUpdateSignInvalid, CodeUpdateExpired, CodeUpdateChanMismatch:
		return ExitSecurity
	case CodeQuotaExceeded, CodeNoEgress, CodeAllForeignDown:
		// Quota exhaustion and egress loss are state, not command failure:
		// the command itself succeeded and reported actual state.
		return ExitOK
	case CodePartial:
		return ExitPartial
	default:
		return ExitUsage
	}
}

// NewRequestID returns a random 128-bit hex identifier for correlation.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure means the OS entropy source is broken; there is
		// no safe fallback value, so surface an internal error code.
		return "req-entropy-unavailable"
	}
	return hex.EncodeToString(b[:])
}

// NewEnvelope builds a success envelope with a fresh request ID.
func NewEnvelope(data any) Envelope {
	return Envelope{APIVersion: APIVersion, OK: true, RequestID: NewRequestID(), Data: data}
}

// NewErrorEnvelope builds an error envelope with a fresh request ID.
func NewErrorEnvelope(code, messageKey string, retryable bool, params map[string]any) Envelope {
	return Envelope{
		APIVersion: APIVersion,
		OK:         false,
		RequestID:  NewRequestID(),
		Error:      &Error{Code: code, MessageKey: messageKey, Params: params, Retryable: retryable},
	}
}

// NewID returns a short random identifier for objects (rules, plans, nodes).
func NewID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s-%s", prefix, NewRequestID()[:12])
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

// APIVersionInt returns the numeric core API version for selector checks.
func APIVersionInt() int {
	var v int
	fmt.Sscanf(APIVersion, "ara.api/v%d", &v)
	return v
}

// SchemaVersionNum returns the numeric policy schema version.
func SchemaVersionNum() int { return SchemaVersion }
