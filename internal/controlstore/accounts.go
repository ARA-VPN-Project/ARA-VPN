package controlstore

import (
	"fmt"
	"time"
)

func (s *Store) migrateAccountArchive() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS archived_accounts (id TEXT PRIMARY KEY REFERENCES accounts(id), archived_at TEXT NOT NULL)`); err != nil {
		return err
	}
	for _, table := range []string{"devices", "subscriptions"} {
		for _, event := range []struct{ name, sql string }{{"insert", "INSERT"}, {"move", "UPDATE OF account_id"}} {
			stmt := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS archived_%s_%s BEFORE %s ON %s
				WHEN EXISTS(SELECT 1 FROM archived_accounts WHERE id=NEW.account_id)
				BEGIN SELECT RAISE(ABORT,'CONFLICT: account is archived'); END`, table, event.name, event.sql, table)
			if _, err := s.db.Exec(stmt); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) ListAccounts() ([]Account, error) {
	rows, err := s.db.Query(`SELECT id,created_at,notes FROM accounts WHERE id NOT IN (SELECT id FROM archived_accounts) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []Account
	for rows.Next() {
		var a Account
		var created string
		if err := rows.Scan(&a.ID, &created, &a.Notes); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

func (s *Store) ArchiveAccount(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.Exec(`INSERT INTO archived_accounts(id,archived_at)
		SELECT id,? FROM accounts WHERE id=? AND NOT EXISTS(SELECT 1 FROM archived_accounts WHERE id=accounts.id)
		AND NOT EXISTS(SELECT 1 FROM subscriptions WHERE account_id=accounts.id AND revoked_at IS NULL AND COALESCE(transferred_to,'')='')`, now, id)
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("CONFLICT: account is missing, archived, or still has an unrevoked subscription")
	}
	if _, err := tx.Exec(`UPDATE devices SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL`, now, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO hidden_subscriptions(subscription_id)
		SELECT id FROM subscriptions WHERE account_id=? AND revoked_at IS NOT NULL`, id); err != nil {
		return err
	}
	return tx.Commit()
}
