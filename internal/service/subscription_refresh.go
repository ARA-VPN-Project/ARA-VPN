// Client subscription auto-refresh:
// the installed agent periodically follows the subscription (moved-aware,
// scope-checked, LKG-backed — the same safety model as `ara follow`) with
// a bounded interval + backoff, records an honest status, and exposes it
// over IPC (`subscription.status`, `subscription.refresh`) and the client
// UI. A bad catalog never breaks an existing connection: the follow only
// writes state/subscription/catalog.json after full validation.
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SubscriptionAutoRefreshConfig bounds the background follow loop.
type SubscriptionAutoRefreshConfig struct {
	Token       string   // subscription fetch token (0600 state file)
	Base        string   // the client's enrolled panel base
	DeviceUUID  string   // enrolled identity for the scope check
	IntervalMin int      // base interval, minutes (default 15, max 240)
	AllowedBases []string // explicit http bases (lab/test scope)
	ApplyProfile bool    // apply the validated catalog to the client profile
}

type subscriptionAutoRefreshState struct {
	mu            sync.Mutex
	stop          chan struct{}
	stopped       chan struct{}
	cfg           SubscriptionAutoRefreshConfig
	lastAttempt   time.Time
	lastSuccess   time.Time
	lastError     string
	followedCount int
	failStreak    int
	backoffMin    int
}

const (
	subRefreshDefaultInterval = 15
	subRefreshMaxInterval     = 240
	subRefreshMaxBackoff      = 120 // minutes
	subRefreshTokenFile       = "refresh.json"
)

// SubscriptionRefreshState is the honest status for UI/IPC.
type SubscriptionRefreshState struct {
	Enabled       bool      `json:"enabled"`
	IntervalMin   int       `json:"interval_min"`
	LastAttempt   time.Time `json:"last_attempt,omitempty"`
	LastSuccess   time.Time `json:"last_success,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	FollowedCount int       `json:"followed_count"`
	FailStreak    int       `json:"fail_streak"`
	BackoffMin    int       `json:"backoff_min,omitempty"`
	LKGAvailable  bool      `json:"lkg_available"`
}

// SaveSubscriptionRefreshConfig stores the auto-refresh credentials (0600).
func (s *StateDir) SaveSubscriptionRefreshConfig(cfg SubscriptionAutoRefreshConfig) error {
	if err := os.MkdirAll(s.SubscriptionDir(), 0o700); err != nil {
		return err
	}
	b, err := jsonMarshalIndent(cfg)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.SubscriptionDir(), "refresh.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.SubscriptionDir(), subRefreshTokenFile))
}

// LoadSubscriptionRefreshConfig reads the auto-refresh config.
func (s *StateDir) LoadSubscriptionRefreshConfig() (SubscriptionAutoRefreshConfig, bool, error) {
	var cfg SubscriptionAutoRefreshConfig
	b, err := os.ReadFile(filepath.Join(s.SubscriptionDir(), subRefreshTokenFile))
	if err != nil {
		return cfg, false, nil // not configured
	}
	if err := jsonUnmarshal(b, &cfg); err != nil {
		return cfg, false, err
	}
	return cfg, cfg.Token != "", nil
}

// SubscriptionAutoRefresh runs the follow loop until ctx is done. Each
// cycle: follow → honest status; failures back off exponentially (2× up
// to the max), successes restore the base interval. The loop NEVER
// touches a running tunnel: it only writes the validated catalog.
func (s *Service) SubscriptionAutoRefresh(cfg SubscriptionAutoRefreshConfig, stop <-chan struct{}) *subscriptionAutoRefreshState {
	st := &subscriptionAutoRefreshState{stop: make(chan struct{}), stopped: make(chan struct{}), cfg: cfg}
	if cfg.IntervalMin <= 0 {
		cfg.IntervalMin = subRefreshDefaultInterval
	}
	if cfg.IntervalMin > subRefreshMaxInterval {
		cfg.IntervalMin = subRefreshMaxInterval
	}
	st.backoffMin = cfg.IntervalMin
	go func() {
		defer close(st.stopped)
		interval := time.Duration(cfg.IntervalMin) * time.Minute
		// refresh once shortly after start so an offline-issued catalog
		// converges quickly, then keep the interval
		timer := time.NewTimer(5 * time.Second)
		for {
			select {
			case <-stop:
				return
			case <-st.stop:
				return
			case <-timer.C:
			}
			res, err := SubscriptionFollowChain(s.State, FollowHTTPClient(20*time.Second), cfg.Token, cfg.Base, FollowOptions{
				MaxHops: 4, Deadline: 20 * time.Second, EnrolledUUID: cfg.DeviceUUID,
				AllowedBases: cfg.AllowedBases, ApplyProfile: cfg.ApplyProfile,
				ProfileDir: filepath.Join(s.State.Root, "profiles"),
			})
			st.mu.Lock()
			st.lastAttempt = time.Now()
			if err != nil {
				st.lastError = err.Error()
				st.failStreak++
			} else if res.Error != "" {
				st.lastError = res.Error
				st.failStreak++
				if res.Followed {
					st.followedCount++
				}
			} else {
				st.lastError = ""
				st.lastSuccess = time.Now()
				if res.Followed {
					st.followedCount++
				}
				st.failStreak = 0
			}
			if st.failStreak > 0 {
				st.backoffMin = cfg.IntervalMin << min(st.failStreak, 4) // ×2 per fail, capped
				if st.backoffMin > subRefreshMaxBackoff {
					st.backoffMin = subRefreshMaxBackoff
				}
			} else {
				st.backoffMin = cfg.IntervalMin
			}
			st.mu.Unlock()
			interval = time.Duration(st.backoffMin) * time.Minute
			timer.Reset(interval)
		}
	}()
	return st
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SubscriptionRefreshStatus returns the current auto-refresh state.
func (s *Service) SubscriptionRefreshStatus() (*SubscriptionRefreshState, error) {
	cfg, ok, err := s.State.LoadSubscriptionRefreshConfig()
	if err != nil {
		return nil, err
	}
	out := &SubscriptionRefreshState{Enabled: ok, IntervalMin: cfg.IntervalMin}
	if !ok {
		return out, nil
	}
	out.LKGAvailable = fileExists(s.State.SubscriptionLKGPath())
	if s.subRefresh != nil {
		s.subRefresh.mu.Lock()
		defer s.subRefresh.mu.Unlock()
		out.LastAttempt = s.subRefresh.lastAttempt
		out.LastSuccess = s.subRefresh.lastSuccess
		out.LastError = s.subRefresh.lastError
		out.FollowedCount = s.subRefresh.followedCount
		out.FailStreak = s.subRefresh.failStreak
		out.BackoffMin = s.subRefresh.backoffMin
	}
	return out, nil
}

// SubscriptionRefreshOnce runs one manual follow (UI/IPC `subscription.refresh`).
func (s *Service) SubscriptionRefreshOnce() (*SubscriptionFollowResult, error) {
	cfg, ok, err := s.State.LoadSubscriptionRefreshConfig()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("VALIDATION_FAILED: subscription auto-refresh is not configured")
	}
	return SubscriptionFollowChain(s.State, FollowHTTPClient(15*time.Second), cfg.Token, cfg.Base, FollowOptions{
		EnrolledUUID: cfg.DeviceUUID, AllowedBases: cfg.AllowedBases,
		ApplyProfile: cfg.ApplyProfile, ProfileDir: filepath.Join(s.State.Root, "profiles"),
	})
}

// SubscriptionFollowConfigure stores the auto-refresh credentials and
// (re)starts the background loop on this service instance.
func (s *Service) SubscriptionFollowConfigure(cfg SubscriptionAutoRefreshConfig) error {
	if err := s.State.SaveSubscriptionRefreshConfig(cfg); err != nil {
		return err
	}
	s.startSubscriptionAutoRefresh(cfg)
	return nil
}

func (s *Service) startSubscriptionAutoRefresh(cfg SubscriptionAutoRefreshConfig) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	if s.subRefresh != nil {
		select {
		case <-s.subRefresh.stop:
		default:
			close(s.subRefresh.stop) // replace the previous loop
		}
	}
	s.subRefresh = s.SubscriptionAutoRefresh(cfg, s.stopCh)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
