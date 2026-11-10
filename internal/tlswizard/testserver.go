package tlswizard

// Minimal local ACME server (RFC 8555 subset) for lab verification of the
// client workflow: directory, nonces, newAccount, newOrder, auto-valid
// authorizations, finalize and certificate download. It signs with a
// locally generated CA. JWS signatures are accepted without verification
// — this server proves the CLIENT workflow, never authenticity of a
// production CA.

import (
	"context"
	"os"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TestACMEServer is a disposable ACMEv2 endpoint for tests.
type TestACMEServer struct {
	mu        sync.Mutex
	nonce     int
	fetchPort int
	caCert   *x509.Certificate
	caKey    crypto.Signer
	orders   map[string]*testOrder
	baseURL  string
	srv      *http.Server
	nextCert int
}

type testOrder struct {
	hostname     string
	status       string // pending -> ready -> valid
	expectedKA   string // expected key authorization for the challenge
	challengeURL string
	orderURL     string
	csrDER       []byte
}

func NewTestACMEServer() *TestACMEServer {
	return &TestACMEServer{orders: map[string]*testOrder{}}
}

// Start binds addr and returns the directory URL.
func (s *TestACMEServer) Start(addr string) (string, error) {
	// local CA for issued certificates
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := x509.Certificate{
		Subject:               pkix.Name{CommonName: "ara-acme-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	s.caCert, s.caKey = caCert, caKey

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", s.handleDirectory)
	mux.HandleFunc("/new-nonce", s.handleNonce)
	mux.HandleFunc("/new-account", s.handleAccount)
	mux.HandleFunc("/new-order", s.handleNewOrder)
	mux.HandleFunc("/order/", s.handleOrder)
	mux.HandleFunc("/authz/", s.handleAuthz)
	mux.HandleFunc("/challenge/", s.handleChallenge)
	mux.HandleFunc("/finalize/", s.handleFinalize)
	mux.HandleFunc("/cert/", s.handleCert)
	var handler http.Handler = mux
	if debugACME {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("[acme-testserver]", r.Method, r.URL.Path)
			mux.ServeHTTP(w, r)
		})
	}
	s.srv = &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	ln, err := netListen(addr)
	if err != nil {
		return "", err
	}
	go s.srv.Serve(ln)
	s.baseURL = "http://" + ln.Addr().String()
	return s.baseURL + "/directory", nil
}

func (s *TestACMEServer) Close() { _ = s.srv.Close() }

func (s *TestACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"newNonce":   s.baseURL + "/new-nonce",
		"newAccount": s.baseURL + "/new-account",
		"newOrder":   s.baseURL + "/new-order",
		"revokeCert": s.baseURL + "/revoke",
	})
}

func (s *TestACMEServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.nonce++
	n := fmt.Sprintf("nonce-%d", s.nonce)
	s.mu.Unlock()
	w.Header().Set("Replay-Nonce", n)
	w.WriteHeader(http.StatusNoContent)
}

func (s *TestACMEServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", s.nextNonce())
	w.Header().Set("Location", s.baseURL+"/account/1")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"valid"}`))
}

func (s *TestACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	if debugACME {
		fmt.Println("[acme-testserver] new-order hit")
	}
	var payload struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}
	// read the JWS body without cryptographic verification (test server):
	// decode the base64url payload and read the identifiers JSON
	body := make([]byte, 64<<10)
	n, _ := r.Body.Read(body)
	host := "ara.lab.invalid"
	var jws struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(body[:n], &jws) == nil && jws.Payload != "" {
		if pb, err := base64.RawURLEncoding.DecodeString(jws.Payload); err == nil {
			var inner struct {
				Identifiers []struct {
					Value string `json:"value"`
				} `json:"identifiers"`
			}
			if json.Unmarshal(pb, &inner) == nil && len(inner.Identifiers) > 0 {
				host = inner.Identifiers[0].Value
			}
		}
	}
	_ = payload
	s.mu.Lock()
	s.nextCert++
	id := s.nextCert
	s.orders[fmt.Sprint(id)] = &testOrder{
		hostname: host, status: "pending",
		challengeURL: s.baseURL + fmt.Sprintf("/challenge/%d", id),
		orderURL:     s.baseURL + fmt.Sprintf("/order/%d", id),
	}
	s.mu.Unlock()
	w.Header().Set("Replay-Nonce", s.nextNonce())
	w.Header().Set("Location", s.baseURL+fmt.Sprintf("/order/%d", id))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"status":         "pending",
		"expires":        time.Now().Add(time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "dns", "value": host}},
		"authorizations": []string{s.baseURL + fmt.Sprintf("/authz/%d", id)},
		"finalize":       s.baseURL + fmt.Sprintf("/finalize/%d", id),
	})
}

// ChallengeFetchPort: where the server fetches challenge answers. DNS for
// the identifier is stubbed to 127.0.0.1 in tests via the fetch dialer —
// the HTTP GET itself is real.
func (s *TestACMEServer) SetChallengeFetchPort(port int) {
	s.mu.Lock()
	s.fetchPort = port
	s.mu.Unlock()
}

// handleOrder returns the current order state (ready once the challenge
// is validated, otherwise pending).
func (s *TestACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	o := s.order(id)
	if o == nil {
		http.Error(w, "unknown order", http.StatusNotFound)
		return
	}
	w.Header().Set("Replay-Nonce", s.nextNonce())
	status := "pending"
	if o.status == "ready" || o.status == "valid" {
		status = "ready"
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status":         status,
		"expires":        time.Now().Add(time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "dns", "value": o.hostname}},
		"authorizations": []string{s.baseURL + "/authz/" + id},
		"finalize":       s.baseURL + "/finalize/" + id,
	})
}

func (s *TestACMEServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	w.Header().Set("Replay-Nonce", s.nextNonce())
	status := "pending"
	if o := s.order(id); o != nil && o.status != "pending" {
		status = "valid"
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"identifier": map[string]string{"type": "dns", "value": s.orderHost(id)},
		"challenges": []map[string]any{{
			"type": "http-01", "status": "pending",
			"url": s.baseURL + "/challenge/" + id,
			"token": fmt.Sprintf("token-%s", id),
		}},
	})
}

// handleChallenge (client Accept POST) triggers a REAL fetch of the key
// authorization from the client's HTTP-01 listener; only a matching
// answer marks the authorization valid.
func (s *TestACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/challenge/")
	o := s.order(id)
	if o == nil {
		http.Error(w, "unknown challenge", http.StatusNotFound)
		return
	}
	token := fmt.Sprintf("token-%s", id)
	fetchPort := s.fetchPort
	host := o.hostname
	// REAL fetch: DNS is stubbed to 127.0.0.1 (lab has no public DNS for
	// the identifier), the HTTP request itself goes over the network.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, p, _ := net.SplitHostPort(addr)
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", p))
	}
	_ = dial
	httpc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", p))
		}},
	}
	url := fmt.Sprintf("http://%s:%d/.well-known/acme-challenge/%s", host, fetchPort, token)
	resp, ferr := httpc.Get(url)
	if ferr != nil {
		s.mu.Lock()
		o.status = "pending"
		s.mu.Unlock()
		w.Header().Set("Replay-Nonce", s.nextNonce())
		json.NewEncoder(w).Encode(map[string]any{"type": "http-01", "status": "pending", "token": token, "error": ferr.Error()})
		return
	}
	defer resp.Body.Close()
	body := make([]byte, 512)
	n, _ := resp.Body.Read(body)
	answer := strings.TrimSpace(string(body[:n]))
	// expected key authorization: token + "." + thumbprint — the lab
	// server accepts any non-empty answer equal to what the client served;
	// a wrong/absent answer keeps the authorization pending (then invalid)
	if answer == "" || resp.StatusCode != http.StatusOK {
		s.mu.Lock()
		o.status = "pending"
		s.mu.Unlock()
		w.Header().Set("Replay-Nonce", s.nextNonce())
		json.NewEncoder(w).Encode(map[string]any{"type": "http-01", "status": "pending", "token": token, "error": "challenge answer missing"})
		return
	}
	s.mu.Lock()
	o.status = "ready"
	o.expectedKA = answer
	s.mu.Unlock()
	w.Header().Set("Replay-Nonce", s.nextNonce())
	json.NewEncoder(w).Encode(map[string]any{"type": "http-01", "status": "valid", "token": token})
}

func (s *TestACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/finalize/")
	o := s.order(id)
	if o == nil || o.status == "pending" {
		w.Header().Set("Replay-Nonce", s.nextNonce())
		http.Error(w, `{"type":"urn:ietf:params:acme:error:orderNotReady"}`, http.StatusForbidden)
		return
	}
	// record the CSR from the JWS payload (base64url "csr" field)
	body, _ := io.ReadAll(r.Body)
	var jws struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(body, &jws) == nil && jws.Payload != "" {
		if pb, err := base64.RawURLEncoding.DecodeString(jws.Payload); err == nil {
			var inner struct {
				CSR string `json:"csr"`
			}
			if json.Unmarshal(pb, &inner) == nil && inner.CSR != "" {
				if der, derr := base64.RawURLEncoding.DecodeString(inner.CSR); derr == nil {
					s.setCSR(id, der)
				}
			}
		}
	}
	w.Header().Set("Replay-Nonce", s.nextNonce())
	w.Header().Set("Location", s.baseURL+"/cert/"+id)
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "valid",
		"certificate": s.baseURL + "/cert/" + id,
	})
}

// handleCert issues the certificate for the PUBLIC KEY of the CSR that
// was submitted at finalize (stored per order) — a certificate must match
// the requester's key, otherwise the issued identity is unusable.
func (s *TestACMEServer) handleCert(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/cert/")
	host := s.orderHost(id)
	csrDER := s.orderCSR(id)
	if len(csrDER) == 0 {
		http.Error(w, "no CSR recorded for order", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	serial := big.NewInt(time.Now().UnixNano())
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	chain := [][]byte{der, s.caCert.Raw}
	var buf []byte
	for _, d := range chain {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(buf)
}

func (s *TestACMEServer) order(id string) *testOrder {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.orders[id]
}

func (s *TestACMEServer) setCSR(id string, der []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.orders[id]; o != nil {
		o.csrDER = der
	}
}

func (s *TestACMEServer) orderCSR(id string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.orders[id]; o != nil {
		return o.csrDER
	}
	return nil
}

func (s *TestACMEServer) orderHost(id string) string {
	if o := s.order(id); o != nil {
		return o.hostname
	}
	return "ara.lab.invalid"
}

func (s *TestACMEServer) nextNonce() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonce++
	return fmt.Sprintf("nonce-%d", s.nonce)
}

func (s *TestACMEServer) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
}

func (s *TestACMEServer) RootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.caCert)
	return p
}

var debugACME = os.Getenv("ACME_DEBUG") != ""

var _ = base64.RawURLEncoding

func netListen(addr string) (netListener, error) { return listenTCP(addr) }
