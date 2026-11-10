package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"aravpn/core/policy"
	"aravpn/core/schema"
	"aravpn/internal/i18n"
)

const backboneDir = "/etc/ara-edge/backbones"

var backboneName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$`)

type backbonePrevious struct {
	Config  []byte
	Active  bool
	Enabled bool
}

func cmdBackbone(g *globals, tail []string, lang i18n.Lang) int {
	if len(tail) == 0 || (tail[0] != "apply" && tail[0] != "status") {
		return fail(g, lang, schema.CodeValidation, "error.VALIDATION_FAILED", nil,
			fmt.Errorf("ara node backbone apply|status --protocol openvpn|wireguard --name IFACE [--config FILE --peer PRIVATE_IP]"))
	}
	if runtime.GOOS != "linux" {
		return unsupportedCmd(g, "backbone", lang)
	}
	fs := flag.NewFlagSet("node backbone "+tail[0], flag.ContinueOnError)
	protocol := fs.String("protocol", "", "openvpn or wireguard")
	name := fs.String("name", "", "ARA tunnel interface name")
	source := fs.String("config", "", "local reviewed configuration file")
	peer := fs.String("peer", "", "private tunnel peer IPv4 for readiness verification")
	if err := fs.Parse(tail[1:]); err != nil {
		return emitUsageError(g, err)
	}
	if (*protocol != "openvpn" && *protocol != "wireguard") || !backboneName.MatchString(*name) ||
		(*protocol == "wireguard" && !strings.HasPrefix(*name, "ara-wg-")) {
		return fail(g, lang, schema.CodeValidation, "error.VALIDATION_FAILED", nil, fmt.Errorf("invalid backbone protocol or interface"))
	}
	unit := fmt.Sprintf("ara-%s@%s.service", *protocol, *name)
	dst := filepath.Join(backboneDir, *protocol, *name+".conf")
	pending := dst + ".pending"
	if tail[0] == "apply" {
		addr, err := netip.ParseAddr(*peer)
		if *source == "" || err != nil || !addr.Is4() || !addr.IsPrivate() {
			return fail(g, lang, schema.CodeValidation, "error.VALIDATION_FAILED", nil, fmt.Errorf("config and private IPv4 peer required"))
		}
		if err := applyBackbone(*protocol, *name, *source, addr.String(), unit, dst, pending); err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error.UNAVAILABLE", nil, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	active := systemdBackbone(ctx, "is-active", unit) == nil
	enabled := systemdBackbone(ctx, "is-enabled", unit) == nil
	_, pendingErr := os.Stat(pending)
	if g.json {
		return okJSON(g, map[string]any{"unit": unit, "active": active, "enabled": enabled, "pending": pendingErr == nil})
	}
	fmt.Printf("%s active=%t enabled=%t pending=%t\n", unit, active, enabled, pendingErr == nil)
	return schema.ExitOK
}

func systemdBackbone(ctx context.Context, action, unit string) error {
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "--quiet", action, unit).Run()
}

func applyBackbone(protocol, name, source, peer, unit, dst, pending string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("applying a backbone requires root")
	}
	dir := filepath.Dir(dst)
	unlock, err := policy.LockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	restore := func(previous backbonePrevious) error {
		restoreCtx, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := systemdBackbone(restoreCtx, "stop", unit); err != nil {
			return err
		}
		if previous.Config != nil {
			if err := atomicWriteFile(dst, previous.Config, 0o600); err != nil {
				return err
			}
		} else if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if previous.Enabled {
			if err := systemdBackbone(restoreCtx, "enable", unit); err != nil {
				return err
			}
		} else if err := systemdBackbone(restoreCtx, "disable", unit); err != nil {
			return err
		}
		if previous.Active {
			if err := systemdBackbone(restoreCtx, "start", unit); err != nil {
				return err
			}
		}
		return clearBackbonePending(pending)
	}
	if b, err := os.ReadFile(pending); err == nil {
		var previous backbonePrevious
		if err := json.Unmarshal(b, &previous); err != nil {
			return fmt.Errorf("backbone recovery journal invalid: %w", err)
		}
		if err := restore(previous); err != nil {
			return fmt.Errorf("backbone recovery incomplete: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	config, err := readBackboneConfig(source)
	if err != nil {
		return err
	}
	if protocol == "openvpn" {
		if err := validateOpenVPNBackbone(config); err != nil {
			return err
		}
	} else {
		stage, err := os.MkdirTemp(dir, ".validate-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		candidate := filepath.Join(stage, "config")
		if err := os.WriteFile(candidate, config, 0o600); err != nil {
			return err
		}
		if err := exec.CommandContext(ctx, "/usr/lib/ara/wireguard-backbone", "check", name, candidate).Run(); err != nil {
			return fmt.Errorf("WireGuard configuration rejected: %w", err)
		}
	}
	old, err := readBackboneConfig(dst)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	previous := backbonePrevious{old, systemdBackbone(ctx, "is-active", unit) == nil, systemdBackbone(ctx, "is-enabled", unit) == nil}
	journal, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(pending, journal, 0o600); err != nil {
		return err
	}
	activate := func() error {
		if err := atomicWriteFile(dst, config, 0o600); err != nil {
			return err
		}
		if err := systemdBackbone(ctx, "restart", unit); err != nil {
			return fmt.Errorf("start %s: %w", unit, err)
		}
		for {
			if exec.CommandContext(ctx, "/usr/bin/ping", "-n", "-I", name, "-c", "1", "-W", "2", peer).Run() == nil {
				return systemdBackbone(ctx, "enable", unit)
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("peer %s did not respond through %s: %w", peer, name, ctx.Err())
			case <-time.After(time.Second):
			}
		}
	}
	if err := activate(); err != nil {
		if rollbackErr := restore(previous); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("backbone rollback incomplete: %w", rollbackErr))
		}
		return err
	}
	return clearBackbonePending(pending)
}

func clearBackbonePending(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readBackboneConfig(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<10 {
		return nil, fmt.Errorf("expected a non-empty regular backbone configuration of at most 64 KiB")
	}
	return io.ReadAll(io.LimitReader(f, (64<<10)+1))
}

func validateOpenVPNBackbone(config []byte) error {
	seen := make(map[string]bool)
	for n, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		args := strings.Fields(line)
		option := args[0]
		switch option {
		case "dev", "dev-type", "ca", "cert", "key", "tls-crypt", "data-ciphers", "disable-dco",
			"persist-key", "persist-tun", "keepalive", "verb", "proto", "local", "port", "tls-server", "dh",
			"remote-cert-tls", "ifconfig", "remote", "nobind", "tls-client", "verify-x509-name", "tun-mtu", "mssfix":
		default:
			return fmt.Errorf("unsupported OpenVPN directive on line %d", n+1)
		}
		if seen[option] || strings.ContainsAny(line, "\\\"'\x00") {
			return fmt.Errorf("ambiguous OpenVPN directive on line %d", n+1)
		}
		seen[option] = true
		if option == "ifconfig" {
			if len(args) != 3 {
				return fmt.Errorf("OpenVPN ifconfig requires two private IPv4 addresses")
			}
			for _, ip := range args[1:] {
				addr, err := netip.ParseAddr(ip)
				if err != nil || !addr.Is4() || !addr.IsPrivate() {
					return fmt.Errorf("OpenVPN ifconfig requires two private IPv4 addresses")
				}
			}
		}
	}
	for _, option := range []string{"ca", "cert", "key", "tls-crypt", "remote-cert-tls", "ifconfig"} {
		if !seen[option] {
			return fmt.Errorf("OpenVPN %s required", option)
		}
	}
	if seen["tls-client"] == seen["tls-server"] || (seen["tls-client"] && !seen["verify-x509-name"]) {
		return fmt.Errorf("OpenVPN requires one TLS role and explicit server identity on the client")
	}
	return nil
}
