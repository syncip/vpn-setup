package engine

import (
	"fmt"
	"time"

	"vpnpanel/internal/store"
)

const GB = 1 << 30

// EffectiveLimits: individuelle Limits vor Tarif, nil = keine Limits.
func EffectiveLimits(u *store.User, plans map[int64]*store.Plan) *store.Limits {
	if u.Limits != nil {
		return u.Limits
	}
	if u.PlanID != nil {
		if p, ok := plans[*u.PlanID]; ok {
			return &p.Limits
		}
	}
	return nil
}

// PeriodStart liefert den Beginn des aktuellen Abrechnungszeitraums.
func PeriodStart(l *store.Limits, now time.Time) int64 {
	if l == nil {
		return 0
	}
	loc := now.Location()
	switch l.Period {
	case "daily":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).Unix()
	case "weekly":
		wd := l.ResetDay // 1 = Montag … 7 = Sonntag
		if wd < 1 || wd > 7 {
			wd = 1
		}
		target := time.Weekday(wd % 7)
		d := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		for d.Weekday() != target {
			d = d.AddDate(0, 0, -1)
		}
		return d.Unix()
	case "monthly":
		day := l.ResetDay
		if day < 1 || day > 28 {
			day = 1
		}
		d := time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, loc)
		if d.After(now) {
			d = d.AddDate(0, -1, 0)
		}
		return d.Unix()
	}
	return 0
}

// NextReset: Zeitpunkt der nächsten Zurücksetzung (0 = nie).
func NextReset(l *store.Limits, now time.Time) int64 {
	if l == nil {
		return 0
	}
	s := time.Unix(PeriodStart(l, now), 0).In(now.Location())
	switch l.Period {
	case "daily":
		return s.AddDate(0, 0, 1).Unix()
	case "weekly":
		return s.AddDate(0, 0, 7).Unix()
	case "monthly":
		return s.AddDate(0, 1, 0).Unix()
	}
	return 0
}

func minRate(a, b float64) float64 {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}

type Verdict struct {
	Status   string
	Reason   string
	RateDown float64
	RateUp   float64
}

func (v Verdict) Active() bool { return v.Status == "ok" || v.Status == "throttled" }

// Evaluate bestimmt Status und Geschwindigkeit eines Nutzers.
func Evaluate(u *store.User, l *store.Limits, now time.Time) Verdict {
	if !u.Enabled {
		return Verdict{Status: "disabled", Reason: "Deaktiviert"}
	}
	if u.ExpiresAt > 0 && now.Unix() >= u.ExpiresAt {
		return Verdict{Status: "expired", Reason: "Abgelaufen am " + time.Unix(u.ExpiresAt, 0).Format("02.01.2006")}
	}
	if l == nil {
		return Verdict{Status: "ok"}
	}
	used := float64(u.PeriodUp + u.PeriodDown)
	v := Verdict{Status: "ok", RateDown: l.SpeedDownMbit, RateUp: l.SpeedUpMbit}
	if l.TrafficGB > 0 && used >= l.TrafficGB*GB {
		if l.OnLimit == "throttle" {
			return Verdict{Status: "throttled", Reason: fmt.Sprintf("Datenlimit %.0f GB erreicht – gedrosselt", l.TrafficGB),
				RateDown: minRate(l.LimitDownMbit, l.SpeedDownMbit), RateUp: minRate(l.LimitUpMbit, l.SpeedUpMbit)}
		}
		return Verdict{Status: "blocked", Reason: fmt.Sprintf("Datenlimit %.0f GB erreicht", l.TrafficGB)}
	}
	// höchste erreichte Drosselstufe
	var best *store.Tier
	for i := range l.Tiers {
		t := &l.Tiers[i]
		if t.AfterGB > 0 && used >= t.AfterGB*GB && (best == nil || t.AfterGB > best.AfterGB) {
			best = t
		}
	}
	if best != nil {
		v.Status = "throttled"
		v.Reason = fmt.Sprintf("Ab %.0f GB gedrosselt", best.AfterGB)
		v.RateDown = minRate(best.DownMbit, v.RateDown)
		v.RateUp = minRate(best.UpMbit, v.RateUp)
	}
	return v
}

// ValidateLimits prüft Eingaben aus der Oberfläche.
func ValidateLimits(l *store.Limits) error {
	if l == nil {
		return nil
	}
	switch l.Period {
	case "", "none":
		l.Period = "none"
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("unbekannter Zeitraum %q", l.Period)
	}
	if l.OnLimit != "throttle" {
		l.OnLimit = "block"
	}
	for _, v := range []float64{l.TrafficGB, l.SpeedDownMbit, l.SpeedUpMbit, l.LimitDownMbit, l.LimitUpMbit} {
		if v < 0 {
			return fmt.Errorf("negative Werte sind nicht erlaubt")
		}
	}
	if l.OnLimit == "throttle" && l.TrafficGB > 0 && l.LimitDownMbit <= 0 && l.LimitUpMbit <= 0 {
		return fmt.Errorf("für „Drosseln nach Limit“ bitte eine Geschwindigkeit angeben")
	}
	var tiers []store.Tier
	for _, t := range l.Tiers {
		if t.AfterGB <= 0 {
			continue
		}
		if t.DownMbit < 0 || t.UpMbit < 0 {
			return fmt.Errorf("negative Werte sind nicht erlaubt")
		}
		tiers = append(tiers, t)
	}
	l.Tiers = tiers
	if l.MaxDevices < 0 {
		l.MaxDevices = 0
	}
	return nil
}
