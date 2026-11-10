package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aravpn/core/policy"
)

type routeList struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	TitleEN  string        `json:"title_en"`
	URLs     []string      `json:"sources"`
	Action   policy.Action `json:"action"`
	Networks bool          `json:"-"`
}

var availableRouteLists = []routeList{
	{"geoip-ru", "GeoIP RU · IP-сети", "GeoIP RU · IP networks", []string{
		"https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/ru/ipv4-aggregated.txt",
		"https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/ru/ipv6-aggregated.txt",
	}, policy.ActionRUExit, true},
	{"blocked-ru", "Блокировки RU · список сообщества", "RU blocks · community list", []string{
		"https://github.com/runetfreedom/russia-blocked-geosite/releases/latest/download/antifilter-download-community.txt",
	}, policy.ActionForeignPool, false},
}

type routeListSnapshot struct {
	Updated time.Time           `json:"updated_at"`
	Entries map[string][]string `json:"entries"`
}

var routeListUpdateLock sync.Mutex

func (s *server) readRouteLists() (routeListSnapshot, error) {
	var snapshot routeListSnapshot
	b, err := os.ReadFile(filepath.Join(s.stateDir, "route-lists.json"))
	if err != nil {
		return snapshot, err
	}
	err = json.Unmarshal(b, &snapshot)
	return snapshot, err
}

func (s *server) refreshRouteLists(ctx context.Context) error {
	if !routeListUpdateLock.TryLock() {
		return errors.New("route list refresh already running")
	}
	defer routeListUpdateLock.Unlock()
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		switch req.URL.Hostname() {
		case "github.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
			if req.URL.Scheme == "https" && len(via) < 4 {
				return nil
			}
		}
		return errors.New("unexpected GitHub redirect")
	}}
	snapshot := routeListSnapshot{Updated: time.Now().UTC(), Entries: map[string][]string{}}
	for _, list := range availableRouteLists {
		seen := map[string]bool{}
		for _, address := range list.URLs {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
			if err != nil {
				return err
			}
			res, err := client.Do(req)
			if err != nil {
				return err
			}
			body, err := io.ReadAll(io.LimitReader(res.Body, 300001))
			res.Body.Close()
			if err != nil || len(body) > 300000 || res.StatusCode != http.StatusOK {
				return fmt.Errorf("GitHub source unavailable or oversized (%s)", list.ID)
			}
			for _, line := range strings.Split(string(body), "\n") {
				v := strings.TrimSpace(line)
				if v == "" || strings.HasPrefix(v, "#") {
					continue
				}
				if list.Networks {
					p, err := netip.ParsePrefix(v)
					if err != nil || p != p.Masked() || !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() || p.Bits() < 8 {
						return fmt.Errorf("invalid network in %s", list.ID)
					}
				} else {
					v = strings.TrimPrefix(v, "domain:")
					if !strings.Contains(v, ".") {
						return fmt.Errorf("invalid domain in %s", list.ID)
					}
				}
				if !seen[v] {
					seen[v] = true
					snapshot.Entries[list.ID] = append(snapshot.Entries[list.ID], v)
				}
			}
		}
		values := snapshot.Entries[list.ID]
		if len(values) == 0 || len(values) > 14000 {
			return fmt.Errorf("unexpected list size (%s)", list.ID)
		}
		rule := routeListRule(list, values)
		if err := rule.Validate(); err != nil {
			return err
		}
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.stateDir, ".route-lists-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(s.stateDir, "route-lists.json"))
}

func routeListRule(list routeList, values []string) policy.Rule {
	r := policy.Rule{ID: "list-" + list.ID, Action: list.Action, Comment: list.Title}
	if list.Networks {
		r.CIDR = values
	} else {
		r.DomainSuffix = values
	}
	return r
}

func (s *server) routeListBackground(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		cached, _ := s.readRouteLists()
		if time.Since(cached.Updated) >= 24*time.Hour {
			refreshCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = s.refreshRouteLists(refreshCtx)
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *server) handleRouteLists(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/policy/lists/refresh" {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		if err := s.refreshRouteLists(ctx); err != nil {
			http.Error(w, "GitHub refresh failed; previous lists retained", http.StatusBadGateway)
			return
		}
	}
	snapshot, _ := s.readRouteLists()
	if r.Method == http.MethodGet || r.URL.Path == "/api/v1/policy/lists/refresh" && r.Method == http.MethodPost {
		type item struct {
			routeList
			Count int `json:"count"`
		}
		items := make([]item, 0, len(availableRouteLists))
		for _, list := range availableRouteLists {
			items = append(items, item{list, len(snapshot.Entries[list.ID])})
		}
		writeJSON(w, http.StatusOK, map[string]any{"lists": items, "updated_at": snapshot.Updated})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		ID        string        `json:"id"`
		Candidate policy.Policy `json:"candidate"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&request); err != nil {
		http.Error(w, "Invalid policy draft", 400)
		return
	}
	for _, list := range availableRouteLists {
		if list.ID != request.ID {
			continue
		}
		values := snapshot.Entries[list.ID]
		if len(values) == 0 {
			http.Error(w, "Update the catalog first", 409)
			return
		}
		rule := routeListRule(list, values)
		found := false
		for i, old := range request.Candidate.Rules {
			if old.ID != rule.ID {
				continue
			}
			old.CIDR, old.DomainSuffix = rule.CIDR, rule.DomainSuffix
			request.Candidate.Rules[i] = old
			found = true
			break
		}
		if !found {
			request.Candidate.Rules = append(request.Candidate.Rules, rule)
		}
		if b, _ := json.Marshal(request.Candidate); len(b) > 240<<10 {
			http.Error(w, "Policy draft exceeds size limit", 400)
			return
		}
		if err := request.Candidate.Validate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, 200, map[string]any{"candidate": request.Candidate})
		return
	}
	http.NotFound(w, r)
}
