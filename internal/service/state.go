// Package service is the typed service layer shared by the CLI, the agent
// daemon and the control API (docs/CLI_AUTOMATION.md): one implementation
// of validation, plan/apply and status so UI and CLI cannot drift apart.
//
// It owns no network I/O beyond local state files; the data plane is not
// part of this layer (connect/disconnect are agent-mediated and return
// UNSUPPORTED_CAPABILITY in this build until the transport engine lands).
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// StateDir bundles all on-disk state locations for one ARA instance.
type StateDir struct {
	Root string
}

// DefaultStateDir is ~/.ara (client); server roles use their own via flag.
func DefaultStateDir() (StateDir, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return StateDir{}, err
	}
	return StateDir{Root: filepath.Join(home, ".ara")}, nil
}

func (s StateDir) PolicyDir() string  { return filepath.Join(s.Root, "policy") }
func (s StateDir) LimitsDir() string  { return filepath.Join(s.Root, "limits") }
func (s StateDir) PlansDir() string   { return filepath.Join(s.Root, "plans") }
func (s StateDir) TopoPath() string   { return filepath.Join(s.Root, "topology.json") }
func (s StateDir) HealthPath() string { return filepath.Join(s.Root, "health.json") }
func (s StateDir) LimitsPath() string { return filepath.Join(s.Root, "limits.json") }
func (s StateDir) AgentSock() string  { return filepath.Join(s.Root, "agent.sock") }
func (s StateDir) ControlDB() string  { return filepath.Join(s.Root, "control.db") }
func (s StateDir) AuditPath() string  { return filepath.Join(s.Root, "audit.jsonl") }
func (s StateDir) TokenPath() string  { return filepath.Join(s.Root, "control.token") }

// Ensure creates the directory layout with private permissions.
func (s StateDir) Ensure() error {
	for _, d := range []string{s.Root, s.PolicyDir(), s.LimitsDir(), s.PlansDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// Service is the façade over one StateDir plus background client loops.
type Service struct {
	State      StateDir
	stopCh     chan struct{}
	subMu      sync.Mutex
	subRefresh *subscriptionAutoRefreshState
}

// New validates the state dir is usable.
func New(st StateDir) (*Service, error) {
	if err := st.Ensure(); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	return &Service{State: st, stopCh: make(chan struct{})}, nil
}

// Stop terminates background loops (auto-refresh).
func (s *Service) Stop() {
	if s.stopCh != nil {
		close(s.stopCh)
	}
}
