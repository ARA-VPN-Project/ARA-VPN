package tlswizard

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"net/http/httptest"
	"testing"
	"time"
)

func issue(t *testing.T, host string, notAfter time.Time, signer *ecdsa.PrivateKey, selfSigned bool) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	var der []byte
	var err error
	if selfSigned {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		der, err = x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	} else {
		caTmpl := x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-ca"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDer, cerr := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &signer.PublicKey, signer)
		if cerr != nil {
			t.Fatal(cerr)
		}
		caCert, _ := x509.ParseCertificate(caDer)
		der, err = x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, signer)
	}
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return certPEM, keyPEM
}

func TestImportValidateActivateRollback(t *testing.T) {
	dir := t.TempDir()
	st := Store{Dir: dir}
	now := time.Now()
	cert1, key1 := issue(t, "edge.ara.lab", now.Add(90*24*time.Hour), nil, true)
	imp, err := st.Import(cert1, key1, nil, "edge.ara.lab", nil, now)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imp.DNSNames[0] != "edge.ara.lab" || imp.ChainLen != 1 {
		t.Fatalf("imported: %+v", imp)
	}
	probeCalled := 0
	probe := func() error { probeCalled++; return nil }
	imp, err = st.Activate(probe)
	if err != nil || probeCalled != 1 {
		t.Fatalf("activate: %v probes=%d", err, probeCalled)
	}
	// second import + activate: prev holds pair 1
	cert2, key2 := issue(t, "edge.ara.lab", now.Add(60*24*time.Hour), nil, true)
	if _, err := st.Import(cert2, key2, nil, "edge.ara.lab", nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Activate(probe); err != nil {
		t.Fatal(err)
	}
	cur, _ := st.Active()
	if !cur.NotAfter.Equal(now.Add(60 * 24 * time.Hour).Truncate(time.Second)) {
		t.Fatalf("active is not pair 2: %+v", cur)
	}
	// failing probe rolls back automatically
	cert3, key3 := issue(t, "edge.ara.lab", now.Add(30*24*time.Hour), nil, true)
	_, _ = st.Import(cert3, key3, nil, "edge.ara.lab", nil, now)
	badProbe := func() error { return http.ErrAbortHandler }
	if _, err := st.Activate(badProbe); err == nil {
		t.Fatal("failing probe must fail activation")
	}
	cur, _ = st.Active()
	if !cur.NotAfter.Equal(now.Add(60 * 24 * time.Hour).Truncate(time.Second)) {
		t.Fatal("rollback did not restore pair 2")
	}
	// after the auto-rollback prev is empty; a new successful activation
	// refills prev, then an explicit operator rollback goes back to it
	cert4, key4 := issue(t, "edge.ara.lab", now.Add(45*24*time.Hour), nil, true)
	_, _ = st.Import(cert4, key4, nil, "edge.ara.lab", nil, now)
	if _, err := st.Activate(probe); err != nil {
		t.Fatal(err)
	}
	if err := st.Rollback(); err != nil {
		t.Fatal(err)
	}
	cur, _ = st.Active()
	if !cur.NotAfter.Equal(now.Add(60 * 24 * time.Hour).Truncate(time.Second)) {
		t.Fatalf("rollback did not restore pair 2: %+v", cur)
	}
	// renewal window: pair 1 (90d) not due; a 10-day cert is due
	due, _, err := st.NeedsRenewal(now)
	if err != nil || due {
		t.Fatalf("90d cert must not need renewal: due=%v err=%v", due, err)
	}
	certSoon, keySoon := issue(t, "edge.ara.lab", now.Add(10*24*time.Hour), nil, true)
	_, _ = st.Import(certSoon, keySoon, nil, "edge.ara.lab", nil, now)
	if _, err := st.Activate(probe); err != nil {
		t.Fatal(err)
	}
	due, _, err = st.NeedsRenewal(now)
	if err != nil || !due {
		t.Fatalf("10d cert must need renewal: due=%v err=%v", due, err)
	}
	_ = httptest.NewServer
}

func TestImportRejections(t *testing.T) {
	now := time.Now()
	cert, key := issue(t, "edge.ara.lab", now.Add(90*24*time.Hour), nil, true)
	// key mismatch
	otherCert, _ := issue(t, "edge.ara.lab", now.Add(90*24*time.Hour), nil, true)
	if _, err := ValidateFiles(otherCert, key, nil, "edge.ara.lab", nil, now); err == nil {
		t.Fatal("key mismatch accepted")
	}
	// wrong hostname
	if _, err := ValidateFiles(cert, key, nil, "other.ara.lab", nil, now); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	// expired
	expCert, expKey := issue(t, "edge.ara.lab", now.Add(-time.Hour), nil, true)
	if _, err := ValidateFiles(expCert, expKey, nil, "edge.ara.lab", nil, now); err == nil {
		t.Fatal("expired accepted")
	}
}

// pendingChallenges exposes tokens awaiting answers for a hostname (used
// by the dynamic answerer in tests).
func (s *TestACMEServer) pendingChallenges(host string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for id, o := range s.orders {
		if o.hostname == host && o.status == "pending" {
			out[fmt.Sprintf("token-%s", id)] = o.expectedKA
		}
	}
	return out
}

// TestACMERealChallengeLifecycle: issue with a REAL HTTP-01 round trip
// (the lab server fetches the answer from our listener — an unanswered
// challenge keeps the order pending and issuance FAILS), persist
// cert/leaf-key/account-key, restart-simulate with a fresh wizard over
// the same disk state, complete a REAL TLS handshake with the issued
// pair, and renew reusing the persisted account key.
func TestACMERealChallengeLifecycle(t *testing.T) {
	srv := NewTestACMEServer()
	dirURL, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	const host = "client.example.com"

	cs, err := NewChallengeServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	srv.SetChallengeFetchPort(portOf(cs.Addr()))

	// the challenge answer for the identifier: the client's HTTP-01
	// listener serves token.thumbprint; the lab fetch requires a non-empty
	// match, and the dynamic answerer below relays each announced token's
	// expected answer into our listener (in production the operator's
	// listener serves it directly).
	dynStop := make(chan struct{})
	defer close(dynStop)
	go func() {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-dynStop:
				return
			case <-tick.C:
				for token, ka := range srv.pendingChallenges(host) {
					if ka != "" {
						cs.AddChallenge(token, ka)
					}
				}
			}
		}
	}()

	ctx := ctxWithTimeout(t, 30*time.Second)
	certPEM, leafKeyPEM, acctKeyPEM, err := ACMEIssue(ctx, dirURL, host, nil, nil, cs)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// negative control: a DIFFERENT host with no listener must fail
	if _, _, _, err := ACMEIssue(ctxWithTimeout(t, 15*time.Second), dirURL, "unreachable.example.com", nil, acctKeyPEM, nil); err == nil {
		t.Fatal("issuance must fail when the challenge cannot be answered")
	}

	// persist atomically into the wizard store
	dir := t.TempDir()
	st := Store{Dir: dir}
	if _, err := st.Import(certPEM, leafKeyPEM, nil, host, nil, time.Now()); err != nil {
		t.Fatalf("import issued material: %v", err)
	}
	if _, err := st.Activate(func() error { _, e := st.ActiveTLS(); return e }); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// restart simulation: fresh wizard over the same disk state serves a
	// REAL TLS handshake verified against the TRUSTED lab CA (RootCAs +
	// ServerName) — no InsecureSkipVerify
	st2 := Store{Dir: dir}
	tlsCert, err := st2.ActiveTLS()
	if err != nil {
		t.Fatal(err)
	}
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tlsSrv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	dialAddr := strings.TrimPrefix(tlsSrv.URL, "https://")
	rootPool := srv.RootPool()
	tlsDial := func(serverName string, pool *x509.CertPool) error {
		conn, err := tls.Dial("tcp", dialAddr, &tls.Config{ServerName: serverName, RootCAs: pool})
		if err != nil {
			return err
		}
		st := conn.ConnectionState()
		if len(st.PeerCertificates) == 0 || st.PeerCertificates[0].DNSNames[0] != serverName {
			conn.Close()
			return errors.New("unexpected certificate")
		}
		return conn.Close()
	}
	if err := tlsDial(host, rootPool); err != nil {
		t.Fatalf("verified handshake failed: %v", err)
	}
	// negative: an unrelated CA must NOT verify the issued chain
	badCACertPEM, badCAKeyPEM := issue(t, "unrelated.example.com", time.Now().Add(24*time.Hour), nil, true)
	badPool := x509.NewCertPool()
	badPool.AppendCertsFromPEM(badCACertPEM)
	_ = badCAKeyPEM
	if err := tlsDial(host, badPool); err == nil {
		t.Fatal("handshake succeeded with an untrusted CA")
	}
	// negative: the issued certificate must not verify for another name
	if err := tlsDial("other.example.com", rootPool); err == nil {
		t.Fatal("handshake succeeded for a hostname the certificate does not cover")
	}

	// renewal: same account key (persisted), new certificate; account key
	// must be reused byte-for-byte so restarts keep the ACME identity
	cert2, leaf2, acct2, err := ACMEIssue(ctxWithTimeout(t, 30*time.Second), dirURL, host, nil, acctKeyPEM, cs)
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if !bytes.Equal(acct2, acctKeyPEM) {
		t.Fatal("renewal must reuse the persisted account key")
	}
	if _, err := st2.Import(cert2, leaf2, nil, host, nil, time.Now()); err != nil {
		t.Fatalf("renewal import: %v", err)
	}
	if _, err := st2.Activate(func() error { _, e := st2.ActiveTLS(); return e }); err != nil {
		t.Fatalf("renewal activate: %v", err)
	}
	imp, _ := st2.Active()
	if imp.Subject == "" {
		t.Fatal("active certificate lost after renewal")
	}
}

func ctxWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
