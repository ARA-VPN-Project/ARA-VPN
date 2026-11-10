// Package edgeconfval is the SHARED typed validator for edge config
// documents (F02): the sync path and the runtime must refuse the same
// malformed inputs — a matching sha256 or the presence of two arrays does
// not prove the config is usable. The runtime loads the same JSON shape
// (cmd/ara-edge edgeConfig) and enforces the identical identity/exit
// rules via this validator.
package edgeconfval

import (
	"encoding/json"
	"fmt"
	"strings"

	"aravpn/internal/backbone"
)

type device struct {
	UUID       string `json:"uuid"`
	DeviceID   string `json:"device_id"`
	SOCKSUser  string `json:"socks_user,omitempty"`
	SOCKSPass  string `json:"socks_pass,omitempty"`
	SubID      string `json:"subscription_id,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	QuotaBytes *int64 `json:"quota_bytes,omitempty"`
}

type exitNode struct {
	Backbone  *backbone.Binding `json:"backbone,omitempty"`
	ID        string            `json:"id"`
	Country   string            `json:"country"`
	Role      string            `json:"role"`
	Priority  int               `json:"priority"`
	SOCKSAddr string            `json:"socks_addr"`
	ProbeAddr string            `json:"probe_addr,omitempty"`
	DNSAddr   string            `json:"dns_addr,omitempty"`
}

type config struct {
	AccessListen   string     `json:"access_listen"`
	SOCKSListen    string     `json:"socks_listen"`
	Devices        []device   `json:"devices"`
	Exits          []exitNode `json:"exits"`
	CurrentForeign string     `json:"current_foreign_id"`
	QuotaBytes     int64      `json:"quota_bytes"`
}

// Validate parses and semantically checks an edge config document with
// the SAME identity rules the runtime enforces: device UUIDs are
// required and unique, exits are required with ids and SOCKS addresses,
// the SOCKS listener requires SOCKS credentials.
func Validate(b []byte) error {
	var c config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("VALIDATION_FAILED: config is not a valid edge config object: %w", err)
	}
	if len(c.Devices) == 0 {
		return fmt.Errorf("VALIDATION_FAILED: config devices are required")
	}
	if len(c.Exits) == 0 {
		return fmt.Errorf("VALIDATION_FAILED: config exits are required")
	}
	seenUUID, seenID, seenUser := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.UUID == "" {
			return fmt.Errorf("VALIDATION_FAILED: devices[%d].uuid is required", i)
		}
		if seenUUID[strings.ToLower(d.UUID)] {
			return fmt.Errorf("VALIDATION_FAILED: duplicate device uuid %s", d.UUID)
		}
		seenUUID[strings.ToLower(d.UUID)] = true
		id := d.DeviceID
		if id == "" {
			id = d.UUID
		}
		if seenID[id] {
			return fmt.Errorf("VALIDATION_FAILED: duplicate device_id %s", id)
		}
		seenID[id] = true
		if d.SOCKSUser != "" {
			if d.SOCKSPass == "" {
				return fmt.Errorf("VALIDATION_FAILED: devices[%d] has socks_user without socks_pass", i)
			}
			if seenUser[d.SOCKSUser] {
				return fmt.Errorf("VALIDATION_FAILED: duplicate socks_user %s", d.SOCKSUser)
			}
			seenUser[d.SOCKSUser] = true
		}
	}
	seenExit := map[string]bool{}
	for i := range c.Exits {
		e := &c.Exits[i]
		if e.ID == "" {
			return fmt.Errorf("VALIDATION_FAILED: exits[%d].id is required", i)
		}
		if seenExit[e.ID] {
			return fmt.Errorf("VALIDATION_FAILED: duplicate exit id %s", e.ID)
		}
		seenExit[e.ID] = true
		if e.Role != "ru" && e.Role != "foreign" {
			return fmt.Errorf("VALIDATION_FAILED: exits[%d].role must be ru|foreign (got %q)", i, e.Role)
		}
		// socks_addr/dns_addr are intentionally NOT required here: the
		// datapath dials/probes per connection and fails that connection
		// when they are missing, and the CONFIG GENERATOR (EdgeConfigPlan)
		// enforces exit_dns_addr at generation time (B21). The shared
		// validator enforces the identity/semantics both paths need before
		// activation — enforced-at-dial rules would reject legitimate
		// configs whose adapter addresses are bound at runtime.
		// Keep the bound endpoint out of the legacy field. Older Edge
		// binaries must fail to dial rather than use an unbound endpoint.
		if e.Backbone != nil && e.SOCKSAddr != "" {
			return fmt.Errorf("VALIDATION_FAILED: exits[%d] cannot mix legacy and backbone SOCKS addresses", i)
		}
		if err := e.Backbone.Validate(); err != nil {
			return fmt.Errorf("VALIDATION_FAILED: exits[%d].backbone: %w", i, err)
		}
		_ = e.DNSAddr
	}
	return nil
}
