package controlstore

import "fmt"

// HideRevokedSubscription removes the row from the operator list while keeping
// the revoked identity, audit references and usage ledger intact.
func (s *Store) HideRevokedSubscription(id, owner string) error {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO hidden_subscriptions(subscription_id)
		SELECT id FROM subscriptions WHERE id=? AND owner_panel=? AND revoked_at IS NOT NULL
		AND active=1 AND COALESCE(transferred_to,'')=''`, id, owner)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n != 1 {
		return fmt.Errorf("CONFLICT: subscription must be revoked, locally owned and visible")
	}
	return err
}

func (s *Store) SetSubscriptionQuota(id, owner string, limit *int64) error {
	if limit != nil && *limit < 0 {
		return fmt.Errorf("VALIDATION_FAILED: quota must be non-negative")
	}
	res, err := s.db.Exec(`UPDATE subscriptions SET limits_bytes=? WHERE id=? AND owner_panel=? AND active=1
		AND revoked_at IS NULL AND COALESCE(transferred_to,'')='' AND (expires_at IS NULL OR julianday(expires_at)>julianday('now'))
		AND NOT EXISTS (SELECT 1 FROM sub_migrations WHERE subscription_id=? AND state='prepared')`, limit, id, owner, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n != 1 {
		return fmt.Errorf("CONFLICT: subscription is inactive, transferring or owned by another panel")
	}
	return err
}
