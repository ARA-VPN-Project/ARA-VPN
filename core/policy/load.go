package policy

import (
	"encoding/json"
	"fmt"
)

// ParseState decodes a policy state document: either the current envelope
// format ({state_version, policy, identity}) written by Store, or the
// legacy bare-policy document. It performs no I/O and no validation beyond
// decoding — callers must apply Policy.Validate before enforcement.
// Shared by Store.LoadState and the edge data path so every consumer reads
// committed policy through one parser (review TR05: a committed envelope
// must never be misread as an invalid bare document and silently replaced
// by a permissive default).
func ParseState(b []byte) (*Policy, *ApplyIdentity, error) {
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err == nil && sf.StateVersion == stateFileVersion && sf.Policy != nil {
		return sf.Policy, sf.Identity, nil
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, nil, fmt.Errorf("policy document unreadable: %w", err)
	}
	return &p, nil, nil
}
