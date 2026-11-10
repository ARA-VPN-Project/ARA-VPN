package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"aravpn/core/policy"
)

//go:embed route_presets.json
var routePresetJSON []byte

type routePreset struct {
	StrictForeign bool          `json:"strict_foreign,omitempty"`
	ID            string        `json:"id"`
	Title         string        `json:"title"`
	Pack          string        `json:"pack"`
	Action        policy.Action `json:"action"`
	Suffix        []string      `json:"suffix"`
	Exact         []string      `json:"exact"`
	CIDR          []string      `json:"cidr,omitempty"`
	ExtraSuffix   []string      `json:"extra_suffix,omitempty"`
	ExtraExact    []string      `json:"extra_exact,omitempty"`
	Examples      []string      `json:"examples"`
	Optional      bool          `json:"optional"`
}

var routePresets = func() []routePreset {
	var catalog []routePreset
	if err := json.Unmarshal(routePresetJSON, &catalog); err != nil {
		panic(err)
	}
	return catalog
}()

type presetDraft struct {
	Candidate policy.Policy `json:"candidate"`
	Added     []string      `json:"added"`
	Existing  []string      `json:"existing"`
}

// Merge only adds rules to the draft. Earlier rules keep precedence and
// repeated additions preserve any operator edits to existing preset IDs.
func addRoutePresets(candidate policy.Policy, selected []string) (presetDraft, error) {
	result := presetDraft{Candidate: candidate, Added: []string{}, Existing: []string{}}
	result.Candidate.Rules = append([]policy.Rule(nil), candidate.Rules...)
	wanted := make(map[string]bool, len(selected))
	for _, id := range selected {
		wanted[id] = true
	}
	known := make(map[string]bool, len(candidate.Rules))
	for _, rule := range candidate.Rules {
		known[rule.ID] = true
	}
	for _, preset := range routePresets {
		if !wanted[preset.ID] {
			continue
		}
		delete(wanted, preset.ID)
		added, existing := false, false
		for _, match := range []struct {
			kind   string
			update bool
			values []string
		}{
			{"suffix", false, preset.Suffix}, {"host", false, preset.Exact}, {"cidr", false, preset.CIDR},
			{"suffix", true, preset.ExtraSuffix}, {"host", true, preset.ExtraExact},
		} {
			if len(match.values) == 0 {
				continue
			}
			id := "preset-" + preset.ID + "-" + match.kind
			if match.update {
				// An existing preset ID may have been edited by the operator.
				// Add catalog extensions as separate rules without rewriting it.
				id += "-extra"
			}
			if known[id] {
				existing = true
				continue
			}
			rule := policy.Rule{ID: id, Enabled: true, Action: preset.Action, Comment: preset.Title}
			if preset.StrictForeign {
				noFallback := false
				rule.AllowRUFallback = &noFallback
			}
			// The policy combines different match types with AND.
			// Separate rules make exact hosts, suffixes and CIDRs alternatives.
			switch match.kind {
			case "suffix":
				rule.DomainSuffix = match.values
			case "host":
				rule.DomainExact = match.values
			case "cidr":
				rule.CIDR = match.values
			}
			result.Candidate.Rules = append(result.Candidate.Rules, rule)
			added = true
		}
		if added {
			result.Added = append(result.Added, preset.Title)
		}
		if existing {
			result.Existing = append(result.Existing, preset.Title)
		}
	}
	if len(wanted) != 0 {
		return presetDraft{}, fmt.Errorf("unknown route preset")
	}
	if err := result.Candidate.Validate(); err != nil {
		return presetDraft{}, err
	}
	return result, nil
}

func (s *server) handleRoutePresets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"presets": routePresets})
	case http.MethodPost:
		var request struct {
			Candidate policy.Policy `json:"candidate"`
			Selected  []string      `json:"selected"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&request); err != nil ||
			len(request.Selected) == 0 || len(request.Selected) > len(routePresets) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "VALIDATION_FAILED"})
			return
		}
		result, err := addRoutePresets(request.Candidate, request.Selected)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
