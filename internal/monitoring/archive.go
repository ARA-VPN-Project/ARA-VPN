package monitoring

import (
	"database/sql"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const archiveStep = 300

func (s *Store) OpenArchive(dir string) error {
	db, err := sql.Open("sqlite", filepath.Join(dir, "monitoring-archive.db"))
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS observations (
		at INTEGER, kind TEXT, target TEXT, source TEXT, rtt REAL, down REAL, up REAL,
		nr INTEGER, nd INTEGER, nu INTEGER, PRIMARY KEY(at,kind,target,source)) WITHOUT ROWID`); err != nil {
		db.Close()
		return err
	}
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM observations)`).Scan(&exists); err != nil {
		db.Close()
		return err
	}
	s.archive = db
	if !exists {
		if err := s.archiveSamples(s.buf); err != nil {
			s.archive = nil
			db.Close()
			return err
		}
	}
	return nil
}

func (s *Store) archiveSamples(samples []Sample) error {
	tx, err := s.archive.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, v := range samples {
		if v.At.IsZero() {
			continue
		}
		_, err := tx.Exec(`INSERT INTO observations VALUES(?,?,?,?,coalesce(?,0),coalesce(?,0),coalesce(?,0),? IS NOT NULL,? IS NOT NULL,? IS NOT NULL)
			ON CONFLICT DO UPDATE SET rtt=rtt+excluded.rtt,down=down+excluded.down,up=up+excluded.up,
			nr=nr+excluded.nr,nd=nd+excluded.nd,nu=nu+excluded.nu`,
			v.At.Unix()/archiveStep*archiveStep, v.Kind, v.Target, v.Source, v.RTTMs, v.DownMbps, v.UpMbps, v.RTTMs, v.DownMbps, v.UpMbps)
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM observations WHERE at < ?`, time.Now().AddDate(-1, 0, -2).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Period(now time.Time, duration, step time.Duration) ([]Sample, error) {
	if s.archive == nil {
		return nil, nil
	}
	seconds := int64(step.Seconds())
	rows, err := s.archive.Query(`SELECT at/?*?,kind,target,source,
		sum(rtt)/nullif(sum(nr),0),sum(down)/nullif(sum(nd),0),sum(up)/nullif(sum(nu),0)
		FROM observations WHERE at>=? AND at<=? GROUP BY 1,2,3,4 ORDER BY 1`, seconds, seconds, now.Add(-duration).Truncate(step).Unix(), now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var at int64
		var p Sample
		if err := rows.Scan(&at, &p.Kind, &p.Target, &p.Source, &p.RTTMs, &p.DownMbps, &p.UpMbps); err != nil {
			return nil, err
		}
		p.At = time.Unix(at, 0).Add(step / 2)
		if p.At.After(now) {
			p.At = now
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
