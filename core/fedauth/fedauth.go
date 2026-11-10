// Package fedauth provides mutual panel authentication for the federation
// API (docs/FEDERATION.md): each panel owns an Ed25519 identity (0600 key
// file in its state dir); every federation request carries panel id,
// timestamp, nonce and a signature over method+path+timestamp+nonce+body
// hash. The receiving panel verifies against the LINKED panel's public
// key — a panel not in the link table has no standing, and admin keys are
// never shared across panels.
package fedauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Identity is one panel's long-term key pair.
type Identity struct {
	PanelID   string `json:"panel_id"`
	PrivHex   string `json:"private_key"`
	CreatedAt string `json:"created_at"`
}

func (i *Identity) Public() ed25519.PublicKey {
	priv := i.priv()
	if priv == nil {
		return nil
	}
	return priv.Public().(ed25519.PublicKey)
}

func (i *Identity) priv() ed25519.PrivateKey {
	b, _ := hex.DecodeString(i.PrivHex)
	if len(b) != ed25519.SeedSize {
		return nil
	}
	return ed25519.NewKeyFromSeed(b)
}

// LoadOrCreate reads or generates the panel identity (0600).
func LoadOrCreate(stateDir, panelID string) (*Identity, error) {
	path := filepath.Join(stateDir, "panel_identity.json")
	if b, err := os.ReadFile(path); err == nil {
		var id Identity
		if err := json.Unmarshal(b, &id); err != nil {
			return nil, fmt.Errorf("panel identity unreadable: %w", err)
		}
		if panelID != "" && id.PanelID != panelID {
			return nil, fmt.Errorf("panel identity id %q != requested %q", id.PanelID, panelID)
		}
		return &id, nil
	}
	if panelID == "" {
		return nil, errors.New("panel id required to create an identity")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	id := &Identity{PanelID: panelID, PrivHex: hex.EncodeToString(seed),
		CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(id, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return nil, err
	}
	return id, os.Rename(tmp, path)
}

// Skew is the accepted clock difference for signed requests.
const Skew = 2 * time.Minute

// CanonicalString is the signed material: method, path, timestamp, nonce,
// SHA-256 of the body. Both sides compute it identically.
func CanonicalString(method, path string, ts int64, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return method + "\n" + path + "\n" + fmt.Sprint(ts) + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
}

// Sign produces the signature header value for a request.
func (i *Identity) Sign(method, path string, ts int64, nonce string, body []byte) string {
	return hex.EncodeToString(ed25519.Sign(i.priv(), []byte(CanonicalString(method, path, ts, nonce, body))))
}

// Verify checks a signed request from a linked panel (its stored public
// key), including the freshness window and a NON-EMPTY nonce.
func Verify(pubB64 string, method, path string, ts int64, nonce, sig string, body []byte, now time.Time) error {
	if nonce == "" || sig == "" {
		return errors.New("missing nonce or signature")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > Skew || d < -Skew {
		return fmt.Errorf("timestamp outside ±%s window", Skew)
	}
	pub, err := hex.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad linked panel public key")
	}
	sb, err := hex.DecodeString(sig)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(CanonicalString(method, path, ts, nonce, body)), sb) {
		return errors.New("signature verification failed")
	}
	return nil
}

// PublicHex renders the identity's public key for the invite/link exchange.
func (i *Identity) PublicHex() string {
	return hex.EncodeToString(i.Public())
}
