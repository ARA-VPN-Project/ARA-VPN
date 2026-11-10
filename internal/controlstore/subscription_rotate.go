// Subscription token rotation:
// the operator (or an authorized agent panel) re-issues the client's fetch
// token. Properties:
//   - the new secret is crypto-random, shown ONCE at issuance; only its
//     SHA-256 is stored (same trust level as CreateSubscription);
//   - rotation is CAS-guarded on the CURRENT token hash — two concurrent
//     rotations cannot both succeed from the same起点, and a rotate that
//     raced a transfer/revocation is refused by the same WHERE;
//   - identity, profiles, expiry, limits, usage, leases are untouched:
//     only the token_hash column changes (nothing else can change in the
//     same statement);
//   - the old token stops working immediately after the atomic swap
//     (default). An explicit grace keeps BOTH hashes valid until the
//     deadline — implemented as a bounded dual-hash table, honored by
//     FindSubscriptionByToken on every panel through replication;
//   - the operation is audited WITHOUT secrets; a lost issuance response
//     is handled by a plain re-rotation (the old token is already dead,
//     the operator rotates again — hashes never reconstruct secrets);
//   - rotation is distinct from revocation: revoking VPN credentials is a
//     separate operation.
package controlstore

import (
	"fmt"
	"time"
)

// rotateGraceTable keeps the superseded hash during an EXPLICIT grace
// window (bounded); default rotation leaves no grace.
func (s *Store) migrateRotateGrace() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS subscription_token_grace (
		subscription_id TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		PRIMARY KEY (subscription_id, token_hash))`)
	return err
}

// RotateTokenResult carries the IssuedOnce secret metadata (the secret
// itself is returned by the caller-level API, never stored).
type RotateTokenResult struct {
	SubscriptionID string     `json:"subscription_id"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	GraceSeconds   int        `json:"grace_seconds,omitempty"`
}

// RotateSubscriptionToken atomically replaces the fetch token hash. The
// caller generates the random secret, passes only its HASH here. CAS on
// expectCurrentHash: nil means "rotate unconditionally from the current
// row" (operator authority), non-nil means "from the token I saw" (client
// of a concurrent-safe agent flow). Refuses revoked subscriptions.
func (s *Store) RotateSubscriptionToken(subID, expectCurrentHash, newHash string, grace time.Duration) (*RotateTokenResult, error) {
	if newHash == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: new token hash required")
	}
	if grace < 0 || grace > 24*time.Hour {
		return nil, fmt.Errorf("VALIDATION_FAILED: grace must be 0..24h")
	}
	sub, err := s.GetSubscription(subID)
	if err != nil {
		return nil, err
	}
	if sub.RevokedAt != nil {
		return nil, fmt.Errorf("AUTH_FAILED: subscription revoked")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if expectCurrentHash != "" {
		var cur string
		if err := tx.QueryRow(`SELECT token_hash FROM subscriptions WHERE id=?`, subID).Scan(&cur); err != nil {
			return nil, err
		}
		if cur != expectCurrentHash {
			return nil, fmt.Errorf("CONFLICT: token already rotated from the seen value")
		}
	}
	// grace: keep the CURRENT hash valid until the deadline (dual-hash),
	// then it dies with the swap
	if grace > 0 {
		var old string
		if err := tx.QueryRow(`SELECT token_hash FROM subscriptions WHERE id=?`, subID).Scan(&old); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO subscription_token_grace(subscription_id, token_hash, expires_at) VALUES (?,?,?)
			ON CONFLICT(subscription_id, token_hash) DO UPDATE SET expires_at=excluded.expires_at`,
			subID, old, time.Now().UTC().Add(grace).Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	} else {
		// default: no grace — drop any stale grace rows for this sub
		if _, err := tx.Exec(`DELETE FROM subscription_token_grace WHERE subscription_id=?`, subID); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`UPDATE subscriptions SET token_hash=? WHERE id=?`, newHash, subID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &RotateTokenResult{SubscriptionID: subID, ExpiresAt: sub.ExpiresAt, GraceSeconds: int(grace.Seconds())}, nil
}

// FindSubscriptionByTokenWithGrace resolves a token against the CURRENT
// hash OR a still-valid grace hash. Revoked subscriptions never resolve.
func (s *Store) FindSubscriptionByTokenWithGrace(token string) (*Subscription, bool /*grace*/, error) {
	h := HashToken(token)
	sub, err := s.FindSubscriptionByToken(token)
	if err == nil {
		return sub, false, nil
	}
	var subID string
	err = s.db.QueryRow(`SELECT subscription_id FROM subscription_token_grace
		WHERE token_hash=? AND expires_at > ?`, h, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&subID)
	if err != nil {
		return nil, false, fmt.Errorf("AUTH_FAILED: subscription token is invalid, expired or revoked")
	}
	sub2, err := s.GetSubscription(subID)
	if err != nil || sub2.RevokedAt != nil {
		return nil, false, fmt.Errorf("AUTH_FAILED: subscription token is invalid, expired or revoked")
	}
	return sub2, true, nil
}
