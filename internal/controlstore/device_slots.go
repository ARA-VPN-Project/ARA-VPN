package controlstore

import (
	"fmt"
	"strings"
)

func (s *Store) migrateDeviceSlots() error {
	if _, err := s.db.Exec("ALTER TABLE subscriptions ADD COLUMN max_devices INTEGER CHECK (max_devices > 0)"); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name: max_devices") {
		return err
	}
	// Registered devices belong to an account and are shared by its
	// subscriptions. The tightest active subscription cap applies.
	for _, statement := range []string{
		`CREATE TRIGGER IF NOT EXISTS subscription_device_slots_insert
		BEFORE INSERT ON devices
		WHEN NEW.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM devices WHERE id=NEW.id)
		AND EXISTS (SELECT 1 FROM subscriptions
			WHERE account_id=NEW.account_id AND active=1 AND revoked_at IS NULL
			AND COALESCE(transferred_to,'')='' AND (expires_at IS NULL OR julianday(expires_at)>julianday('now'))
			AND max_devices <= (SELECT COUNT(*) FROM devices WHERE account_id=NEW.account_id AND revoked_at IS NULL))
		BEGIN SELECT RAISE(ABORT,'CONFLICT: DEVICE_SLOTS_FULL'); END`,
		`CREATE TRIGGER IF NOT EXISTS subscription_device_slots_create
		BEFORE INSERT ON subscriptions
		WHEN NEW.active=1 AND NEW.max_devices < (SELECT COUNT(*) FROM devices WHERE account_id=NEW.account_id AND revoked_at IS NULL)
		BEGIN SELECT RAISE(ABORT,'CONFLICT: DEVICE_SLOTS_FULL'); END`,
		`CREATE TRIGGER IF NOT EXISTS subscription_device_slots_update
		BEFORE UPDATE OF max_devices, active ON subscriptions
		WHEN NEW.active=1 AND NEW.max_devices < (SELECT COUNT(*) FROM devices WHERE account_id=NEW.account_id AND revoked_at IS NULL)
		BEGIN SELECT RAISE(ABORT,'CONFLICT: DEVICE_SLOTS_FULL'); END`,
	} {
		if _, err := s.db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

// SetSubscriptionMaxDevices changes the cap on the authoritative panel only.
func (s *Store) SetSubscriptionMaxDevices(id, owner string, maximum *int) error {
	if maximum != nil && *maximum <= 0 {
		return fmt.Errorf("VALIDATION_FAILED: max_devices must be positive")
	}
	res, err := s.db.Exec(`UPDATE subscriptions SET max_devices=? WHERE id=? AND owner_panel=? AND active=1
		AND revoked_at IS NULL AND COALESCE(transferred_to,'')='' AND (expires_at IS NULL OR julianday(expires_at)>julianday('now'))`, maximum, id, owner)
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("CONFLICT: subscription is inactive or owned by another panel")
	}
	return nil
}
