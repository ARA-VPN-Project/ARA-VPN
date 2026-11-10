// Package backbone describes a SOCKS exit reachable through an operator-managed
// OpenVPN TUN or WireGuard interface. It never changes Linux network state.
package backbone

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
)

type Binding struct {
	Protocol  string `json:"protocol"`
	Interface string `json:"interface"`
	SOCKSAddr string `json:"socks_addr"`
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func (b *Binding) Validate() error {
	if b == nil {
		return nil
	}
	if b.Protocol != "openvpn" && b.Protocol != "wireguard" {
		return fmt.Errorf("unknown backbone protocol %q", b.Protocol)
	}
	if !interfaceName.MatchString(b.Interface) {
		return fmt.Errorf("invalid tunnel interface name")
	}
	host, port, err := net.SplitHostPort(b.SOCKSAddr)
	if err != nil {
		return fmt.Errorf("backbone SOCKS endpoint must be a numeric private IP and port")
	}
	addr, addrErr := netip.ParseAddr(host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if addrErr != nil || !addr.IsPrivate() || addr.Zone() != "" || portErr != nil || portNumber == 0 {
		return fmt.Errorf("backbone SOCKS endpoint must be a numeric private IP and port")
	}
	return nil
}
