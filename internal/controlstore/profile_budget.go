package controlstore

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ProfileKey binds a budget to a concrete route, independently of list order.
func ProfileKey(p SubscriptionProfile) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", p.Kind, p.NodeID, p.IngressAddr, p.RoutePort)))
	return hex.EncodeToString(h[:])
}

type ProfileSpend struct {
	Epoch     string `json:"epoch"`
	Committed int64  `json:"committed_bytes"`
}
type ProfileGrant struct {
	DownloadBPS *int64 `json:"download_bps"`
	UploadBPS   *int64 `json:"upload_bps"`
	ExpiresUnix int64  `json:"expires_unix"`
	ID          string `json:"id"`
	Granted     int64  `json:"granted"`
	Remaining   *int64 `json:"remaining_bytes"`
}

func (s *Store) migrateProfileBudgets() error {
	// Explicitly check migrations: duplicate-column errors alone are tolerated.
	rows, err := s.db.Query(`PRAGMA table_info(subscription_profiles)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "limit_bytes" {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		if _, err = s.db.Exec(`ALTER TABLE subscription_profiles ADD COLUMN limit_bytes INTEGER`); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS profile_budget(subscription_id TEXT NOT NULL, profile_key TEXT NOT NULL, epoch TEXT NOT NULL, committed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(subscription_id,profile_key))`,
		`CREATE TABLE IF NOT EXISTS profile_grants(id TEXT PRIMARY KEY,subscription_id TEXT NOT NULL,profile_key TEXT NOT NULL,holder TEXT NOT NULL,device_id TEXT NOT NULL,epoch TEXT NOT NULL,amount INTEGER NOT NULL,actual INTEGER)`,
	} {
		if _, err = s.db.Exec(q); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`ALTER TABLE profile_grants ADD COLUMN requested INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	return nil
}

// ProfileReserve commits a bounded right BEFORE payload. An unclosed grant
// stays charged after a crash. Normal close refunds only its unused tail.
// Account/device admission is independent and still mandatory on the Edge.
func (s *Store) ProfileReserve(owner, subID, key, holder, device, id string, want int64) (*ProfileGrant, error) {
	if want <= 0 || want > 512*1024 || len(id) < 16 || len(id) > 128 {
		return nil, fmt.Errorf("VALIDATION_FAILED: invalid profile reservation")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Take the writer lock before reading admission state.
	if _, err = tx.Exec(`UPDATE subscriptions SET name=name WHERE id=?`, subID); err != nil {
		return nil, err
	}
	var old ProfileGrant
	var oldSub, oldKey, oldHolder, oldDev, oldEpoch string
	var closed *int64
	var requested int64
	err = tx.QueryRow(`SELECT subscription_id,profile_key,holder,device_id,epoch,amount,actual,requested FROM profile_grants WHERE id=?`, id).Scan(&oldSub, &oldKey, &oldHolder, &oldDev, &oldEpoch, &old.Granted, &closed, &requested)
	if err == nil {
		if oldSub != subID || oldKey != key || oldHolder != holder || oldDev != device || requested != 0 && requested != want {
			return nil, fmt.Errorf("CONFLICT: reservation identity reused")
		}
		if closed != nil {
			return nil, fmt.Errorf("CONFLICT: profile reservation already closed")
		}
		if oldEpoch != subQuotaMonth(time.Now().UTC()) {
			return nil, fmt.Errorf("CONFLICT: expired profile reservation")
		}
		old.ID = id
		epochTime, _ := time.Parse("2006-01", oldEpoch)
		old.ExpiresUnix = epochTime.AddDate(0, 1, 0).Unix()
		var err error
		old.DownloadBPS, old.UploadBPS, err = profileRateTx(tx, subID, key)
		if err != nil {
			return nil, err
		}
		return &old, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	var allowed int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM subscriptions WHERE id=? AND owner_panel=? AND active=1 AND revoked_at IS NULL AND COALESCE(transferred_to,'')='' AND (expires_at IS NULL OR expires_at>?)`, subID, owner, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&allowed); err != nil {
		return nil, err
	}
	if allowed != 1 {
		return nil, fmt.Errorf("AUTH_FAILED: subscription unavailable on this owner")
	}
	if err = guardDeviceLive(tx, device, subID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT kind,node_id,ingress_addr,route_port,limit_bytes FROM subscription_profiles WHERE subscription_id=?`, subID)
	if err != nil {
		return nil, err
	}
	var cap *int64
	matched := false
	for rows.Next() {
		var p SubscriptionProfile
		if err = rows.Scan(&p.Kind, &p.NodeID, &p.IngressAddr, &p.RoutePort, &p.LimitBytes); err != nil {
			rows.Close()
			return nil, err
		}
		if ProfileKey(p) == key {
			cap = p.LimitBytes
			matched = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("PERMISSION_DENIED: profile not granted")
	}
	epoch := subQuotaMonth(time.Now().UTC())
	_, err = tx.Exec(`INSERT INTO profile_budget(subscription_id,profile_key,epoch,committed) VALUES(?,?,?,0) ON CONFLICT(subscription_id,profile_key) DO UPDATE SET committed=CASE WHEN epoch=excluded.epoch THEN committed ELSE 0 END,epoch=excluded.epoch`, subID, key, epoch)
	if err != nil {
		return nil, err
	}
	var spent int64
	if err = tx.QueryRow(`SELECT committed FROM profile_budget WHERE subscription_id=? AND profile_key=?`, subID, key).Scan(&spent); err != nil {
		return nil, err
	}
	grant := want
	var remaining *int64
	if cap != nil {
		avail := *cap - spent
		if avail < 0 {
			avail = 0
		}
		if grant > avail {
			grant = avail
		}
		r := avail - grant
		remaining = &r
	}
	if grant > 0 {
		if _, err = tx.Exec(`INSERT INTO profile_grants(id,subscription_id,profile_key,holder,device_id,epoch,amount,requested) VALUES(?,?,?,?,?,?,?,?)`, id, subID, key, holder, device, epoch, grant, want); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE profile_budget SET committed=committed+? WHERE subscription_id=? AND profile_key=?`, grant, subID, key); err != nil {
			return nil, err
		}
	}
	down, up, err := profileRateTx(tx, subID, key)
	if err != nil {
		return nil, err
	}
	epochTime, _ := time.Parse("2006-01", epoch)
	return &ProfileGrant{ID: id, Granted: grant, Remaining: remaining, DownloadBPS: down, UploadBPS: up, ExpiresUnix: epochTime.AddDate(0, 1, 0).Unix()}, tx.Commit()
}
func (s *Store) ProfileClose(owner, subID, holder, id string, actual int64) error {
	if actual < 0 {
		return fmt.Errorf("VALIDATION_FAILED: negative actual")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE subscriptions SET name=name WHERE id=?`, subID); err != nil {
		return err
	}
	var key, epoch string
	var amount int64
	var previous *int64
	if err = tx.QueryRow(`SELECT profile_key,epoch,amount,actual FROM profile_grants WHERE id=? AND subscription_id=? AND holder=?`, id, subID, holder).Scan(&key, &epoch, &amount, &previous); err != nil {
		return err
	}
	if previous != nil {
		if *previous != actual {
			return fmt.Errorf("CONFLICT: profile checkpoint changed")
		}
		return tx.Commit()
	}
	if actual > amount {
		return fmt.Errorf("VALIDATION_FAILED: actual exceeds grant")
	}
	var owned int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM subscriptions WHERE id=? AND owner_panel=? AND COALESCE(transferred_to,'')=''`, subID, owner).Scan(&owned); err != nil {
		return err
	}
	if owned != 1 {
		return fmt.Errorf("NOT_OWNER")
	}
	if _, err = tx.Exec(`UPDATE profile_grants SET actual=? WHERE id=?`, actual, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE profile_budget SET committed=committed-? WHERE subscription_id=? AND profile_key=? AND epoch=?`, amount-actual, subID, key, epoch); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ProfileSpends(subID string) (map[string]ProfileSpend, error) {
	rows, err := s.db.Query(`SELECT profile_key,epoch,committed FROM profile_budget WHERE subscription_id=?`, subID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ProfileSpend{}
	for rows.Next() {
		var key string
		var p ProfileSpend
		if err = rows.Scan(&key, &p.Epoch, &p.Committed); err != nil {
			return nil, err
		}
		out[key] = p
	}
	return out, rows.Err()
}

func profileRateTx(tx *sql.Tx, subID, key string) (*int64, *int64, error) {
	rows, err := tx.Query(`SELECT kind,node_id,ingress_addr,route_port,download_bps,upload_bps FROM subscription_profiles WHERE subscription_id=?`, subID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p SubscriptionProfile
		if err = rows.Scan(&p.Kind, &p.NodeID, &p.IngressAddr, &p.RoutePort, &p.DownloadBPS, &p.UploadBPS); err != nil {
			return nil, nil, err
		}
		if ProfileKey(p) == key {
			return p.DownloadBPS, p.UploadBPS, nil
		}
	}
	if err = rows.Err(); err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("PERMISSION_DENIED: profile removed")
}
