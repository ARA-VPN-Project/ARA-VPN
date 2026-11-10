// Network-path checks for `ara doctor` (docs/DIAGNOSTICS.md, requirement 8:
// Wi-Fi/mobile diagnostics): route-to-ingress interface selection, DNS and
// IPv6 resolution of the ingress name, MTU comparison. Strictly read-only:
// no route, DNS, firewall or interface changes — a home router is never
// touched. A lab netns proves none of this for the user's own network;
// these checks report the FACTS on this machine, not a verdict.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"aravpn/internal/service"
)

type doctorCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// networkChecks reads the client profile and reports the factual network
// situation toward the ingress.
func networkChecks(svc *service.Service) []doctorCheck {
	var out []doctorCheck
	prof := readClientProfile(svc)
	if prof == nil {
		out = append(out, doctorCheck{Name: "net_ingress_profile", OK: true, Detail: "no client profile configured (skipped)"})
		return out
	}
	host, port, err := net.SplitHostPort(prof.ServerAddr)
	if err != nil {
		out = append(out, doctorCheck{Name: "net_ingress_addr", OK: false, Detail: err.Error()})
		return out
	}
	// DNS: resolve the ingress NAME (not the addr) the way the engine will
	if net.ParseIP(host) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var r net.Resolver
		addrs, err := r.LookupHost(ctx, host)
		if err != nil {
			out = append(out, doctorCheck{Name: "net_ingress_dns", OK: false, Detail: fmt.Sprintf("%s: %v", host, err)})
		} else {
			v4, v6 := 0, 0
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil {
					if ip.To4() != nil {
						v4++
					} else {
						v6++
					}
				}
			}
			detail := fmt.Sprintf("%s → %d IPv4, %d IPv6", host, v4, v6)
			if v4 == 0 && v6 == 0 {
				out = append(out, doctorCheck{Name: "net_ingress_dns", OK: false, Detail: detail + " (no usable addresses)"})
			} else {
				out = append(out, doctorCheck{Name: "net_ingress_dns", OK: true, Detail: detail})
			}
		}
	}
	// Route/interface: a connected UDP socket picks the route the engine
	// would use WITHOUT sending any packet (connect on UDP is local).
	d := net.Dialer{Timeout: 3 * time.Second}
	if c, err := d.Dial("udp", net.JoinHostPort(host, orDefault(port, "443"))); err == nil {
		local := c.LocalAddr().(*net.UDPAddr)
		iface, mtu := ifaceByAddr(local.IP)
		detail := fmt.Sprintf("ingress %s via %s (%s)", local.IP, ifaceName(iface), orEmpty(mtu))
		out = append(out, doctorCheck{Name: "net_ingress_route", OK: true, Detail: detail})
		// MTU: the tunnel adds overhead; a low access MTU with a high
		// profile MTU is a blackhole SUSPICION, never a diagnosis
		if iface != nil && prof.MTU > 0 {
			if *mtu < 1280 && prof.MTU > *mtu {
				out = append(out, doctorCheck{Name: "net_mtu_suspect", OK: false,
					Detail: fmt.Sprintf("interface MTU %d < 1280 with profile MTU %d: run the MTU probe before blaming the tunnel", *mtu, prof.MTU)})
			} else {
				out = append(out, doctorCheck{Name: "net_mtu", OK: true,
					Detail: fmt.Sprintf("interface MTU %d, profile MTU %d", *mtu, prof.MTU)})
			}
		}
		c.Close()
	} else {
		out = append(out, doctorCheck{Name: "net_ingress_route", OK: false, Detail: err.Error()})
	}
	return out
}

type clientProfileLite struct {
	ServerAddr string `json:"server_addr"`
	MTU        int    `json:"mtu"`
}

func readClientProfile(svc *service.Service) *clientProfileLite {
	b, err := os.ReadFile(filepath.Join(svc.State.Root, "profiles", "default.json"))
	if err != nil {
		return nil
	}
	var p clientProfileLite
	if json.Unmarshal(b, &p) != nil {
		return nil
	}
	return &p
}

func ifaceByAddr(ip net.IP) (*net.Interface, *int) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.Contains(ip) {
				mtu := ifaces[i].MTU
				return &ifaces[i], &mtu
			}
		}
	}
	return nil, nil
}

func ifaceName(i *net.Interface) string {
	if i == nil {
		return "unknown"
	}
	return i.Name
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orEmpty(v *int) string {
	if v == nil {
		return "MTU unknown"
	}
	return fmt.Sprintf("MTU %d", *v)
}
