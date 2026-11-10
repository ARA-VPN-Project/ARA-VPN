package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"aravpn/core/plan"
)

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// planRegistry wires the kind executors for this state dir.
func (s *Service) planRegistry() (*plan.Registry, error) {
	reg, err := plan.NewRegistry(s.State.Root)
	if err != nil {
		return nil, err
	}
	reg.Register(&policyExecutor{svc: s})
	reg.Register(&limitsExecutor{svc: s})
	reg.Register(&setupExecutor{svc: s})
	reg.Register(&transitExecutor{svc: s})
	reg.Register(&topologyExecutor{svc: s})
	reg.Register(&edgeConfigExecutor{svc: s})
	return reg, nil
}

// NewPlanID returns a random plan/idempotency identifier.
func NewPlanID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b)
}
