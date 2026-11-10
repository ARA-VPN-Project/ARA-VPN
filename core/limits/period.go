package limits

import "time"

// PeriodKind names the quota window. Only monthly exists in the MVP; day
// and fixed windows may be added as a versioned API extension
// (docs/LIMITS_QUOTAS.md).
type PeriodKind string

const PeriodMonthly PeriodKind = "monthly"

// Period is a quota window with an IANA timezone (default UTC). reset_at is
// exposed to UI in both local and UTC form; all server timestamps are UTC.
type Period struct {
	Kind PeriodKind `json:"kind"`
	TZ   string     `json:"tz"` // IANA name, "" => UTC
}

// DefaultPeriod is monthly UTC.
func DefaultPeriod() Period { return Period{Kind: PeriodMonthly, TZ: "UTC"} }

// Location resolves the configured timezone, embedding tzdata so servers
// without a full zoneinfo database still compute correct boundaries.
func (p Period) Location() (*time.Location, error) {
	name := p.TZ
	if name == "" {
		name = "UTC"
	}
	return time.LoadLocation(name)
}

// Window returns [start, end) of the quota period containing now.
// Monthly windows are calendar months in the configured location: the
// boundary lands on local midnight, and DST transitions are handled by
// location arithmetic, not by fixed offsets.
func (p Period) Window(now time.Time) (start, end time.Time, err error) {
	loc, err := p.Location()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	local := now.In(loc)
	switch p.Kind {
	case PeriodMonthly:
		start = time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc)
		end = time.Date(local.Year(), local.Month()+1, 1, 0, 0, 0, 0, loc)
		return start, end, nil
	default:
		return time.Time{}, time.Time{}, errUnknownPeriod
	}
}

// ResetAt returns the exact end of the current window (the next reset).
func (p Period) ResetAt(now time.Time) (time.Time, error) {
	_, end, err := p.Window(now)
	return end, err
}

type limitsError2 string

func (e limitsError2) Error() string { return string(e) }

const errUnknownPeriod = limitsError2("unknown period kind")
