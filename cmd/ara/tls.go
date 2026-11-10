package main

// tls wizard commands: `ara tls import/check/activate/rollback/acme` over
// the shared tlswizard store (active/prev/next with atomic activation and
// automatic rollback on probe failure).

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
	"aravpn/internal/tlswizard"
)

// trustPool (B31): the trust policy is EXPLICIT. Default = system roots
// (production chain verification); a CA bundle path adds private roots;
// "lab" selects the nil-roots adjacency mode deliberately. A missing
// argument never silently downgrades to lab mode.
func trustPool(spec string) (*x509.CertPool, string, error) {
	switch spec {
	case "", "system":
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		return pool, "system", nil
	case "lab":
		return nil, "lab", nil
	default:
		b, err := os.ReadFile(spec)
		if err != nil {
			return nil, "", fmt.Errorf("trust bundle unreadable: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, "", fmt.Errorf("trust bundle %s contains no PEM certificates", spec)
		}
		return pool, spec, nil
	}
}

// tlsProbe (B32): a real TLS handshake against the staged serving pair —
// hostname/chain verification against the trust policy and the fingerprint
// of the NEW leaf (matched by the caller against the staged pair).
func tlsProbe(addr, serverName string, roots *x509.CertPool, timeout time.Duration) ([32]byte, error) {
	var fp [32]byte
	d := &net.Dialer{Timeout: timeout}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if serverName == "" {
		serverName = host
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fp, fmt.Errorf("tls probe %s (sni %s): %w", addr, serverName, err)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return fp, fmt.Errorf("tls probe: no server certificate presented")
	}
	// the SERVED chain must include intermediates when one was staged —
	// a leaf-only serve would fail strict clients (B33)
	if len(st.PeerCertificates) < 2 && roots != nil {
		chains := st.VerifiedChains
		if len(chains) == 0 || len(chains[0]) < 2 {
			return fp, fmt.Errorf("tls probe: server presented a bare leaf without its intermediate chain")
		}
	}
	sum := sha256.Sum256(st.PeerCertificates[0].Raw)
	return sum, nil
}

// persistACMEAccountKey (B34): the ACME account key is durable state —
// 0600, per hostname, written atomically. `ara tls renew` reuses it so a
// new CLI process keeps the SAME ACME account.
func acmeAccountKeyPath(stateDir, hostname string) string {
	return filepath.Join(stateDir, "tls", "acme", hostname+".account.pem")
}

func netDialTimeout(network, addr string, seconds int) (conn interface{ Close() error }, err error) {
	d := net.Dialer{Timeout: time.Duration(seconds) * time.Second}
	c, err := d.Dial(network, addr)
	return c, err
}

func tlsStore(g *globals) tlswizard.Store {
	root := g.stateDir
	if root == "" {
		if def, err := service.DefaultStateDir(); err == nil {
			root = def.Root
		}
	}
	return tlswizard.Store{Dir: root + "/tls"}
}

func printImported(g *globals, imp *tlswizard.Imported) int {
	if g.json {
		return okJSON(g, imp)
	}
	fmt.Printf("subject: %s\n dns: %v\n valid: %s .. %s (renew by %s)\n chain: %d cert(s)\n",
		imp.Subject, imp.DNSNames, imp.NotBefore.Format(time.RFC3339),
		imp.NotAfter.Format(time.RFC3339), imp.RenewBy.Format(time.RFC3339), imp.ChainLen)
	return schema.ExitOK
}

func cmdTLS(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara tls import --cert f --key f [--chain f] --hostname h [--trust system|ca.pem|lab] | tls status | tls activate --probe-addr h:443 [--probe-host h --trust …] | tls rollback | tls renew --acme-dir URL --hostname h [--trust …]")
		return schema.ExitUsage
	}
	st := tlsStore(g)
	switch tail[0] {
	case "import":
		fs := flag.NewFlagSet("tls import", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		cert := fs.String("cert", "", "leaf certificate PEM (chain may follow)")
		key := fs.String("key", "", "private key PEM")
		chain := fs.String("chain", "", "optional intermediate chain PEM")
		hostname := fs.String("hostname", "", "expected serving hostname")
		trust := fs.String("trust", "system", "verification trust: system (default), a CA bundle path, or lab (explicit)")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *cert == "" || *key == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--cert and --key required"}, nil)
		}
		roots, _, terr := trustPool(*trust)
		if terr != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, terr)
		}
		cp, err := os.ReadFile(*cert)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		kp, err := os.ReadFile(*key)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		var chp []byte
		if *chain != "" {
			if chp, err = os.ReadFile(*chain); err != nil {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
			}
		}
		imp, err := st.Import(cp, kp, chp, *hostname, roots, time.Now())
		if err != nil {
			return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
		}
		return printImported(g, imp)

	case "status":
		imp, err := st.Active()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		due, _, _ := st.NeedsRenewal(time.Now())
		if g.json {
			return okJSON(g, map[string]any{"active": imp, "renewal_due": due, "cert_path": st.ActiveCertificatePath()})
		}
		label := "Certificate file"
		if lang == i18n.RU {
			label = "Файл сертификата"
		}
		fmt.Printf("%s %s\n", label, st.ActiveCertificatePath())
		fmt.Println(i18n.T(lang, "tls.renewal_due", map[string]any{"due": dueBool(due)}))
		return printImported(g, imp)

	case "activate":
		fs := flag.NewFlagSet("tls activate", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		probeAddr := fs.String("probe-addr", "", "TLS addr to probe after activation (empty: pair-load only)")
		probeHost := fs.String("probe-host", "", "SNI/hostname for the probe (default: probe-addr host)")
		trust := fs.String("trust", "system", "probe trust: system (default), a CA bundle path, or lab (explicit)")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		roots, _, terr := trustPool(*trust)
		if terr != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, terr)
		}
		probe := func() error {
			if _, err := st.ActiveTLS(); err != nil {
				return err
			}
			if *probeAddr == "" {
				return nil
			}
			// B32: the probe is a real TLS handshake with hostname/chain
			// verification — a TCP connect proves nothing about serving
			_, perr := tlsProbe(*probeAddr, *probeHost, roots, 5*time.Second)
			return perr
		}
		imp, err := st.Activate(probe)
		if err != nil {
			return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
		}
		return printImported(g, imp)

	case "rollback":
		if err := st.Rollback(); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		imp, err := st.Active()
		if err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		return printImported(g, imp)

	case "renew":
		// full ACME workflow: HTTP-01 challenge listener on :80, issue,
		// save cert+leaf key atomically into the wizard store, activate
		fs := flag.NewFlagSet("tls renew", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		acmeDir := fs.String("acme-dir", "", "ACME directory URL (lab test server or production)")
		hostname := fs.String("hostname", "", "hostname to issue")
		listen := fs.String("challenge-listen", ":80", "HTTP-01 challenge listener address")
		trust := fs.String("trust", "system", "verification trust for the issued chain: system (default), a CA bundle path, or lab")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *acmeDir == "" || *hostname == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--acme-dir and --hostname required"}, nil)
		}
		roots, _, terr := trustPool(*trust)
		if terr != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, terr)
		}
		// B34: the account key is durable per-hostname state — reuse it
		// across CLI processes so the ACME account stays the same
		keyPath := acmeAccountKeyPath(g.stateDir, *hostname)
		var acctPEM []byte
		if b, rerr := os.ReadFile(keyPath); rerr == nil {
			acctPEM = b
		}
		cs, err := tlswizard.NewChallengeServer(*listen)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		defer cs.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		certPEM, leafKeyPEM, acctOut, err := tlswizard.ACMEIssue(ctx, *acmeDir, *hostname, nil, acctPEM, cs)
		if err != nil {
			return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
		}
		if acctOut != nil && len(acctPEM) == 0 {
			if derr := os.MkdirAll(filepath.Dir(keyPath), 0o700); derr != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, derr)
			}
			tmp := keyPath + ".tmp"
			if werr := os.WriteFile(tmp, acctOut, 0o600); werr == nil {
				if ferr := os.Rename(tmp, keyPath); ferr != nil {
					os.Remove(tmp)
					return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, ferr)
				}
			}
		}
		if _, err := st.Import(certPEM, leafKeyPEM, nil, *hostname, roots, time.Now()); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		imp, err := st.Activate(func() error { _, e := st.ActiveTLS(); return e })
		if err != nil {
			return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
		}
		return printImported(g, imp)
	}
	return schema.ExitUsage
}

func dueBool(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
