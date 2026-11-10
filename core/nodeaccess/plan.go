// Package nodeaccess renders scoped nftables rules for the ARA service ports.
package nodeaccess

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
)

const Chain = "ara_node_access"

type Input struct {
	Kind      string `json:"kind"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Interface string `json:"interface"`
	Source    string `json:"source"`
	Table     string `json:"table"`
}

type Plan struct {
	Input
	Rule string `json:"rule"`
	Tag  string `json:"tag"`
}

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)
var tableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)

func Build(in Input) (Plan, error) {
	if in.Kind != "ingress" && in.Kind != "transit" {
		return Plan{}, fmt.Errorf("unknown access kind")
	}
	if in.Protocol != "tcp" && in.Protocol != "udp" {
		return Plan{}, fmt.Errorf("expected TCP or UDP")
	}
	if in.Port < 1 || in.Port > 65535 || in.Port == 22 {
		return Plan{}, fmt.Errorf("invalid or reserved port")
	}
	if !interfaceName.MatchString(in.Interface) || in.Interface == "lo" || !tableName.MatchString(in.Table) {
		return Plan{}, fmt.Errorf("invalid interface or nftables table")
	}
	match := "iifname " + strconv.Quote(in.Interface)
	if in.Source != "" {
		source, err := netip.ParsePrefix(in.Source)
		if err != nil {
			addr, aerr := netip.ParseAddr(in.Source)
			if aerr != nil || addr.Zone() != "" {
				return Plan{}, fmt.Errorf("source must be an IP address or CIDR")
			}
			source = netip.PrefixFrom(addr, addr.BitLen())
		}
		if source.Bits() == 0 || source.Addr().Is4In6() || source.Addr().IsMulticast() ||
			(in.Kind == "transit" && (source.Bits() != source.Addr().BitLen() || !source.Addr().IsGlobalUnicast())) {
			return Plan{}, fmt.Errorf("transit requires the single unicast address of its peer")
		}
		source = source.Masked()
		in.Source = source.String()
		family := "ip6"
		if source.Addr().Is4() {
			family = "ip"
		}
		match += " " + family + " saddr " + in.Source
	} else if in.Kind == "transit" {
		return Plan{}, fmt.Errorf("transit requires the tunnel peer address")
	}
	rule := fmt.Sprintf("add rule inet %s %s %s %s dport %d counter accept", in.Table, Chain, match, in.Protocol, in.Port)
	digest := sha256.Sum256([]byte(rule))
	tag := fmt.Sprintf("ara-node-%x", digest[:12])
	return Plan{Input: in, Rule: rule + " comment " + strconv.Quote(tag), Tag: tag}, nil
}
