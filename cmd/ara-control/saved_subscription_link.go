package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"aravpn/internal/service"
)

var savedSubscriptionID = regexp.MustCompile(`^sub-[a-f0-9]+$`)

func (s *server) subscriptionLinkVault() (cipher.AEAD, error) {
	key, err := privateValue(s.stateDir, "subscription-links.key", "", 32)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func (s *server) saveSubscriptionLink(id, token string) error {
	if !savedSubscriptionID.MatchString(id) {
		return errors.New("invalid subscription ID")
	}
	vault, err := s.subscriptionLinkVault()
	if err != nil {
		return err
	}
	sealed := vault.Seal(nil, nil, []byte(token), []byte(id))
	return writePrivateAtomic(filepath.Join(s.stateDir, "saved-"+id+".link"), sealed)
}

func (s *server) handleSavedSubscriptionLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if !savedSubscriptionID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	sub, err := s.store.GetSubscription(id)
	if err != nil || sub.OwnerPanel != s.panelIdentity().PanelID || sub.RevokedAt != nil || sub.TransferredTo != "" ||
		(sub.Active != nil && !*sub.Active) || (sub.ExpiresAt != nil && !time.Now().Before(*sub.ExpiresAt)) {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.stateDir, "saved-"+id+".link"))
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, 200, map[string]bool{"saved": false})
		return
	}
	if err != nil {
		http.Error(w, "Link unavailable", 500)
		return
	}
	vault, err := s.subscriptionLinkVault()
	if err != nil {
		http.Error(w, "Link unavailable", 500)
		return
	}
	plain, err := vault.Open(nil, nil, b, []byte(id))
	if err != nil {
		http.Error(w, "Link unavailable", 500)
		return
	}
	token := string(plain)
	current, err := s.store.FindSubscriptionByToken(token)
	if err != nil || current.ID != id {
		writeJSON(w, 200, map[string]bool{"saved": false})
		return
	}
	e, err := s.subscriptionEndpoint()
	if err != nil || e.Base() == "" {
		http.Error(w, "Link unavailable", 409)
		return
	}
	writeJSON(w, 200, map[string]any{"saved": true, "url": service.SubscriptionTokenURL(e.Base(), token)})
}
