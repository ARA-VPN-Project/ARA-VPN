package controlstore

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const activityBucketSeconds = 300
const activityRetention = 7 * 24 * time.Hour

var ErrDeviceAccess = errors.New("DEVICE_ACCESS_DENIED")

func (s *Store) migrateSubscriptionActivity() error {
	for _, col := range []struct{ table, name, decl string }{
		{"subscription_profiles", "download_bps", "INTEGER"},
		{"subscription_profiles", "upload_bps", "INTEGER"},
		{"devices", "expires_unix", "INTEGER NOT NULL DEFAULT 0"},
		{"subscriptions", "primary_device_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		if _, err := s.db.Exec("ALTER TABLE " + col.table + " ADD COLUMN " + col.name + " " + col.decl); err != nil &&
			!strings.Contains(err.Error(), "duplicate column name: "+col.name) {
			return err
		}
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS subscription_activity (
			subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
			bucket INTEGER NOT NULL, device_id TEXT NOT NULL, bytes INTEGER NOT NULL, ru_bytes INTEGER NOT NULL, foreign_bytes INTEGER NOT NULL,
			PRIMARY KEY (subscription_id,bucket,device_id))`,
		`CREATE TABLE IF NOT EXISTS subscription_local_usage (
			subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
			month TEXT NOT NULL, device_id TEXT NOT NULL, bytes INTEGER NOT NULL,
			PRIMARY KEY (subscription_id,month,device_id))`,
		`CREATE INDEX IF NOT EXISTS subscription_activity_retention ON subscription_activity(bucket)`,
		`CREATE TABLE IF NOT EXISTS subscription_last_activity (
			subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
			device_id TEXT NOT NULL, reported_at INTEGER NOT NULL, PRIMARY KEY(subscription_id,device_id))`,
		`CREATE TABLE IF NOT EXISTS subscription_device_links (
			token_hash TEXT PRIMARY KEY, subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
			device_id TEXT NOT NULL REFERENCES devices(id))`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func recordSubscriptionActivity(tx *sql.Tx, subID, deviceID string, bytes, ru, foreign int64, now time.Time) error {
	// Legacy unregistered holders participate in quota, but cannot be
	// counted as client devices in the subscription UI.
	if _, err := tx.Exec(`INSERT INTO subscription_activity(subscription_id,bucket,device_id,bytes,ru_bytes,foreign_bytes)
		SELECT ?,?,d.id,?,?,? FROM devices d JOIN subscriptions s ON s.account_id=d.account_id WHERE s.id=? AND d.id=?
		ON CONFLICT(subscription_id,bucket,device_id) DO UPDATE SET bytes=bytes+excluded.bytes,ru_bytes=ru_bytes+excluded.ru_bytes,foreign_bytes=foreign_bytes+excluded.foreign_bytes`,
		subID, now.Unix()/activityBucketSeconds*activityBucketSeconds, bytes, ru, foreign, subID, deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO subscription_last_activity(subscription_id,device_id,reported_at)
		SELECT ?,d.id,? FROM devices d JOIN subscriptions s ON s.account_id=d.account_id WHERE s.id=? AND d.id=?
		ON CONFLICT(subscription_id,device_id) DO UPDATE SET reported_at=MAX(reported_at,excluded.reported_at)`,
		subID, now.Unix(), subID, deviceID); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM subscription_activity WHERE bucket < ?`, now.Add(-activityRetention).Unix()/activityBucketSeconds*activityBucketSeconds)
	return err
}

type ActivityBucket struct {
	At           int64 `json:"at_unix"`
	Bytes        int64 `json:"bytes"`
	Devices      int   `json:"devices"`
	RUBytes      int64 `json:"ru_bytes"`
	ForeignBytes int64 `json:"foreign_bytes"`
}

type SubscriptionActivity struct {
	From          int64            `json:"from_unix"`
	Until         int64            `json:"until_unix"`
	BucketSeconds int64            `json:"bucket_seconds"`
	Buckets       []ActivityBucket `json:"buckets"`
	LastReported  map[string]int64 `json:"last_reported_unix"`
}

func (s *Store) SubscriptionActivity(id string, now time.Time, days int) (SubscriptionActivity, error) {
	width := int64(activityBucketSeconds)
	if days == 7 {
		width = 3600
	} else if days != 1 {
		return SubscriptionActivity{}, fmt.Errorf("VALIDATION_FAILED: days must be 1 or 7")
	}
	end := (now.Unix()/width + 1) * width
	out := SubscriptionActivity{From: end - int64(days)*86400, Until: end, BucketSeconds: width,
		Buckets: []ActivityBucket{}, LastReported: map[string]int64{}}
	rows, err := s.db.Query(`SELECT bucket/?*?,SUM(bytes),COUNT(DISTINCT device_id),SUM(ru_bytes),SUM(foreign_bytes)
		FROM subscription_activity WHERE subscription_id=? AND bucket>=? AND bucket<? GROUP BY 1 ORDER BY 1`,
		width, width, id, out.From, out.Until)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var bucket ActivityBucket
		if err := rows.Scan(&bucket.At, &bucket.Bytes, &bucket.Devices, &bucket.RUBytes, &bucket.ForeignBytes); err != nil {
			rows.Close()
			return out, err
		}
		out.Buckets = append(out.Buckets, bucket)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT device_id,reported_at FROM subscription_last_activity WHERE subscription_id=?`, id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var device string
		var at int64
		if err := rows.Scan(&device, &at); err != nil {
			return out, err
		}
		out.LastReported[device] = at
	}
	return out, rows.Err()
}

func (s *Store) SetSubscriptionDeviceExpiry(subID, owner, deviceID string, expires int64) error {
	if expires < 0 || expires > 253402300799 {
		return fmt.Errorf("VALIDATION_FAILED: invalid expiry")
	}
	res, err := s.db.Exec(`UPDATE devices SET expires_unix=? WHERE id=? AND revoked_at IS NULL AND account_id=(
		SELECT account_id FROM subscriptions WHERE id=? AND owner_panel=? AND active=1 AND revoked_at IS NULL AND COALESCE(transferred_to,'')='')`,
		expires, deviceID, subID, owner)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("CONFLICT: device or owned subscription is unavailable")
	}
	return nil
}

func (s *Store) RevokeSubscriptionDevice(subID, owner, deviceID string) error {
	res, err := s.db.Exec(`UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL AND account_id=(
		SELECT account_id FROM subscriptions WHERE id=? AND owner_panel=? AND active=1 AND revoked_at IS NULL AND COALESCE(transferred_to,'')='')`,
		time.Now().UTC().Format(time.RFC3339Nano), deviceID, subID, owner)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("CONFLICT: device or owned subscription is unavailable")
	}
	return nil
}

// Bind the shared legacy link once, including when the original device has
// since been revoked. Fetching an old URL can never switch to another UUID.
func (s *Store) SubscriptionDeviceUUID(subID, deviceID string, now time.Time) (string, error) {
	if deviceID == "" {
		_, err := s.db.Exec(`UPDATE subscriptions SET primary_device_id=COALESCE(
			(SELECT id FROM devices WHERE account_id=subscriptions.account_id AND COALESCE(vless_uuid,'')<>''
			 ORDER BY created_at,id LIMIT 1),'') WHERE id=? AND primary_device_id=''`, subID)
		if err != nil {
			return "", err
		}
		if err := s.db.QueryRow(`SELECT primary_device_id FROM subscriptions WHERE id=?`, subID).Scan(&deviceID); err != nil {
			return "", err
		}
		if deviceID == "" {
			return "", nil // existing catalogs without an enrolled identity
		}
	}
	var uuid string
	err := s.db.QueryRow(`SELECT d.vless_uuid FROM devices d JOIN subscriptions s ON s.account_id=d.account_id
		WHERE s.id=? AND d.id=? AND d.revoked_at IS NULL AND (d.expires_unix=0 OR d.expires_unix>?)`,
		subID, deviceID, now.Unix()).Scan(&uuid)
	if errors.Is(err, sql.ErrNoRows) || err == nil && uuid == "" {
		return "", ErrDeviceAccess
	}
	return uuid, err
}

func (s *Store) IssueSubscriptionDeviceLink(subID, owner, deviceID string) (string, error) {
	token, err := randomSecret(24)
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(`INSERT INTO subscription_device_links(token_hash,subscription_id,device_id)
		SELECT ?,s.id,d.id FROM subscriptions s JOIN devices d ON s.account_id=d.account_id
		WHERE s.id=? AND s.owner_panel=? AND s.active=1 AND s.revoked_at IS NULL
		AND COALESCE(s.transferred_to,'')='' AND (s.expires_at IS NULL OR julianday(s.expires_at)>julianday('now'))
		AND d.id=? AND d.revoked_at IS NULL AND (d.expires_unix=0 OR d.expires_unix>?) AND COALESCE(d.vless_uuid,'')<>''
		ON CONFLICT DO NOTHING`, HashToken(token), subID, owner, deviceID, time.Now().Unix())
	if err != nil {
		return "", err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return "", fmt.Errorf("CONFLICT: device or owned subscription is unavailable")
	}
	return token, nil
}

func (s *Store) FindSubscriptionDeviceLink(token string) (*Subscription, string, error) {
	var subID, deviceID string
	if err := s.db.QueryRow(`SELECT subscription_id,device_id FROM subscription_device_links WHERE token_hash=?`,
		HashToken(token)).Scan(&subID, &deviceID); err != nil {
		return nil, "", err
	}
	sub, err := s.GetSubscription(subID)
	return sub, deviceID, err
}

var ErrActivityExpired = errors.New("ACTIVITY_EXPIRED")

func (s *Store) ReportSubscriptionActivity(opKey, digest, subID, deviceID string, at, bytes, ru, foreign int64) error {
	now := time.Now()
	if at < now.Add(-activityRetention).Unix() {
		return ErrActivityExpired
	}
	if at > now.Add(5*time.Minute).Unix() || bytes <= 0 || ru < 0 || foreign < 0 || ru > bytes || foreign > bytes-ru {
		return fmt.Errorf("VALIDATION_FAILED: invalid activity report")
	}
	_, _, err := s.WithFedOpTxDigest("activity:"+opKey, digest, func(tx *sql.Tx) (any, error) {
		if err := guardDeviceLive(tx, deviceID, subID); err != nil {
			return nil, err
		}
		if err := recordSubscriptionActivity(tx, subID, deviceID, bytes, ru, foreign, now); err != nil {
			return nil, err
		}
		return true, nil
	})
	return err
}

func (s *Store) SubscriptionDeviceAccess(subID, deviceID string) (int64, error) {
	var total, allowed int
	var expires int64
	err := s.db.QueryRow(`SELECT COUNT(*),COUNT(CASE WHEN d.id=? AND d.revoked_at IS NULL
		AND (d.expires_unix=0 OR d.expires_unix>unixepoch()) THEN 1 END),
		COALESCE(MAX(CASE WHEN d.id=? THEN d.expires_unix END),0)
		FROM devices d JOIN subscriptions s ON s.account_id=d.account_id WHERE s.id=?`, deviceID, deviceID, subID).Scan(&total, &allowed, &expires)
	if err != nil {
		return 0, err
	}
	if total > 0 && allowed != 1 {
		return 0, ErrDeviceAccess
	}
	return expires, nil
}

// ReportLocalTraffic adds the graph and monthly usage in a single transaction.
// Local traffic is already admitted by the Edge quota journal.
func (s *Store) ReportLocalTraffic(sub, device string, ru, foreign int64, now time.Time) error {
	if ru < 0 || foreign < 0 || ru+foreign <= 0 {
		return fmt.Errorf("invalid local traffic")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = guardDeviceLive(tx, device, sub); err != nil {
		return err
	}
	if err = recordSubscriptionActivity(tx, sub, device, ru+foreign, ru, foreign, now); err != nil {
		return err
	}
	month := now.UTC().Format("2006-01")
	if _, err = tx.Exec(`INSERT INTO subscription_local_usage(subscription_id,month,device_id,bytes) VALUES (?,?,?,?)
		ON CONFLICT(subscription_id,month,device_id) DO UPDATE SET bytes=bytes+excluded.bytes`, sub, month, device, ru+foreign); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LocalTrafficUsage(now time.Time) (map[string]map[string]int64, error) {
	out := map[string]map[string]int64{}
	rows, err := s.db.Query(`SELECT subscription_id,device_id,bytes FROM subscription_local_usage WHERE month=?`, now.UTC().Format("2006-01"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sub, device string
		var bytes int64
		if err := rows.Scan(&sub, &device, &bytes); err != nil {
			return nil, err
		}
		if out[sub] == nil {
			out[sub] = map[string]int64{}
		}
		out[sub][device] = bytes
	}
	return out, rows.Err()
}

// ProvisionSubscriptionDevice atomically allocates a slot, a separate VPN
// identity and a device-bound subscription URL. Failure leaves no orphan slot.
func (s *Store) ProvisionSubscriptionDevice(subID, owner, name string) (*Device, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 120 {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: device name required (max 120 characters)")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE subscriptions SET name=name WHERE id=? AND owner_panel=? AND active=1 AND revoked_at IS NULL AND COALESCE(transferred_to,'')='' AND (expires_at IS NULL OR julianday(expires_at)>julianday('now'))`, subID, owner)
	if err != nil {
		return nil, "", err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return nil, "", fmt.Errorf("CONFLICT: owned subscription unavailable")
	}
	var account string
	if err = tx.QueryRow(`SELECT account_id FROM subscriptions WHERE id=?`, subID).Scan(&account); err != nil {
		return nil, "", err
	}
	id, err := randomID("dev")
	if err != nil {
		return nil, "", err
	}
	uuid, err := randomSecret(16)
	if err != nil {
		return nil, "", err
	}
	token, err := randomSecret(24)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	identity := formatUUID(uuid)
	if _, err = tx.Exec(`INSERT INTO devices(id,account_id,name,created_at,vless_uuid,enrollment_used_at,identity_pubkey) VALUES(?,?,?,?,?,?,'provisioned')`, id, account, name, now.Format(time.RFC3339Nano), identity, now.Format(time.RFC3339Nano)); err != nil {
		return nil, "", err
	}
	if _, err = tx.Exec(`INSERT INTO subscription_device_links(token_hash,subscription_id,device_id) VALUES(?,?,?)`, HashToken(token), subID, id); err != nil {
		return nil, "", err
	}
	return &Device{ID: id, AccountID: account, Name: name, CreatedAt: now, VlessUUID: identity}, token, tx.Commit()
}
