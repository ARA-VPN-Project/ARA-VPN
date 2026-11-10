package tlswizard

// Real ACME HTTP-01 challenge workflow: the client must ANSWER the
// challenge — serve the key authorization over HTTP — before the server
// marks it valid. The lab server (testserver.go) VALIDATES challenges by
// fetching http://<host>/.well-known/acme-challenge/<token>; without a
// live answer the order never reaches valid. The issued leaf key and the
// account key are returned to the caller for 0600 persistence (cert+leaf
// key → active store, account key → renewals). All network work honors
// ctx deadlines/cancellation.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	acmeclient "golang.org/x/crypto/acme"
)

// ChallengeServer answers ACME HTTP-01 challenges on an HTTP listener.
type ChallengeServer struct {
	srv    *http.Server
	ln     net.Listener
	mu     sync.Mutex
	tokens map[string]string // token -> keyAuth
}

// NewChallengeServer binds the given address (":80" in production; a lab
// port otherwise). The ACME server must be able to reach it.
func NewChallengeServer(addr string) (*ChallengeServer, error) {
	cs := &ChallengeServer{tokens: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)
		cs.mu.Lock()
		keyAuth, ok := cs.tokens[token]
		cs.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(keyAuth))
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cs.ln = ln
	cs.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = cs.srv.Serve(ln) }()
	return cs, nil
}

// AddChallenge registers a token→keyAuth answer.
func (cs *ChallengeServer) AddChallenge(token, keyAuth string) {
	cs.mu.Lock()
	cs.tokens[token] = keyAuth
	cs.mu.Unlock()
}

// Addr returns the bound address.
func (cs *ChallengeServer) Addr() string { return cs.ln.Addr().String() }

// Close stops the listener.
func (cs *ChallengeServer) Close() { _ = cs.srv.Close() }

// ACMEIssue performs a complete order: account (reusing accountKeyPEM
// when given), authorization with a REAL HTTP-01 round trip bound to
// challenge (an already-running HTTP-01 listener owned by the caller;
// nil is allowed — authorization will then stay pending and issuance
// fails), finalize, certificate fetch. ctx carries deadlines and
// cancellation. Returns the issued chain, the leaf key and the account
// key — cert+leaf key belong in the wizard store, the account key is kept
// for renewals.
func ACMEIssue(ctx context.Context, directoryURL string, hostname string, contacts []string, accountKeyPEM []byte, challenge *ChallengeServer) (certPEM, leafKeyPEM, acctKeyPEM []byte, err error) {
	acctKey, err := loadOrCreateAccountKey(accountKeyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	client := &acmeclient.Client{Key: acctKey, DirectoryURL: directoryURL}
	if _, err := client.Discover(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("acme: discover: %w", err)
	}
	acct := &acmeclient.Account{Contact: contacts}
	// Register is idempotent for an existing account key: the server
	// answers 200 with the account URL and the client treats it as done.
	if _, err := client.Register(ctx, acct, func(string) bool { return true }); err != nil {
		return nil, nil, nil, fmt.Errorf("acme: register: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, []acmeclient.AuthzID{{Type: "dns", Value: hostname}})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("acme: new-order: %w", err)
	}
	var cs *ChallengeServer
	defer func() {
		if cs != nil {
			cs.Close()
		}
	}()
	for _, u := range order.AuthzURLs {
		az, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("acme: authz: %w", err)
		}
		if az.Status != "pending" && az.Status != "ready" {
			continue
		}
		var chosen *acmeclient.Challenge
		for _, ch := range az.Challenges {
			if ch.Type == "http-01" {
				chosen = ch
				break
			}
		}
		if chosen == nil {
			return nil, nil, nil, errors.New("acme: no http-01 challenge offered")
		}
		keyAuth, err := client.HTTP01ChallengeResponse(chosen.Token)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("acme: keyauth: %w", err)
		}
		if challenge == nil {
			return nil, nil, nil, errors.New("acme: no challenge listener: authorization cannot be answered")
		}
		challenge.AddChallenge(chosen.Token, keyAuth)
		if _, err := client.Accept(ctx, chosen); err != nil {
			return nil, nil, nil, fmt.Errorf("acme: accept: %w", err)
		}
		if err := waitAuthorizationValid(ctx, client, u); err != nil {
			return nil, nil, nil, err
		}
	}
	// wait for order "ready", then finalize with a fresh leaf CSR
	order, err = waitOrderReady(ctx, client, order.URI)
	if err != nil {
		return nil, nil, nil, err
	}
	csrDER, csrKey, err := newCSR(hostname)
	if err != nil {
		return nil, nil, nil, err
	}
	derChain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("acme: finalize: %w", err)
	}
	certPEM = pemChain(derChain)
	if leafKeyPEM, err = marshalECKey(csrKey); err != nil {
		return nil, nil, nil, err
	}
	if acctKeyPEM, err = marshalECKey(acctKey); err != nil {
		return nil, nil, nil, err
	}
	leaf, _ := parseFirstCert(certPEM)
	if leaf == nil {
		return nil, nil, nil, errors.New("acme: issued certificate unreadable")
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return nil, nil, nil, fmt.Errorf("acme: issued cert does not cover %q: %w", hostname, err)
	}
	return certPEM, leafKeyPEM, acctKeyPEM, nil
}

func waitOrderReady(ctx context.Context, client *acmeclient.Client, orderURI string) (*acmeclient.Order, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		o, err := client.GetOrder(ctx, orderURI)
		if err != nil {
			return nil, err
		}
		switch o.Status {
		case "ready", "valid":
			return o, nil
		case "invalid":
			return nil, errors.New("acme: order invalid")
		}
		if time.Now().After(deadline) {
			return nil, errors.New("acme: order not ready in time")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func waitAuthorizationValid(ctx context.Context, client *acmeclient.Client, authzURL string) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		az, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return err
		}
		switch az.Status {
		case "valid":
			return nil
		case "invalid":
			return errors.New("acme: authorization invalid (challenge fetch failed?)")
		}
		if time.Now().After(deadline) {
			return errors.New("acme: authorization timeout")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func loadOrCreateAccountKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(pemBytes) > 0 {
		k, err := parseKey(pemBytes)
		if err != nil {
			return nil, err
		}
		if ek, ok := k.(*ecdsa.PrivateKey); ok {
			return ek, nil
		}
		return nil, errors.New("acme: account key must be ECDSA")
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func marshalECKey(k crypto.PrivateKey) ([]byte, error) {
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("acme: not an ECDSA key")
	}
	der, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
