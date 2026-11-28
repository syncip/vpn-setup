package api

// Zeitraum und Gliederung für alle Verlaufs-Abfragen (Verkehr gesamt, je Nutzer/Server/Zugang, Ausgänge):
//   ?from=&to=   Unix-Sekunden (frei), sonst ?range=24h|7d|30d|90d|365d
//   ?grain=      hour | day | week | month (leer/auto = passend zur Länge)
//   ?tz=         Zeitzone des Browsers (z. B. Europe/Berlin) – Tage, Wochen (ab Montag) und Monate
//                beginnen dort um Mitternacht. Gespeichert wird stündlich; gröbere Stufen werden hier gebildet.

import (
	"net/http"
	"strconv"
	"time"
)

type period struct {
	since, until int64 // Unix-Sekunden, until exklusiv
	grain        string
	loc          *time.Location
}

const maxHourSpan = 93 * 86400 // feiner als Tage höchstens ~3 Monate (≈ 2200 Balken)

var grainSecs = map[string]int64{"hour": 3600, "day": 86400, "week": 7 * 86400, "month": 30 * 86400}

func parsePeriod(r *http.Request) period {
	now := time.Now()
	q := r.URL.Query()
	p := period{loc: time.Local}
	if tz := q.Get("tz"); tz != "" && len(tz) < 64 {
		if l, err := time.LoadLocation(tz); err == nil {
			p.loc = l
		}
	}
	oldest := now.AddDate(-10, 0, 0).Unix()
	if f, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil && f > 0 {
		t, err := strconv.ParseInt(q.Get("to"), 10, 64)
		if err != nil || t <= f || t > now.Unix()+86400*400 {
			t = now.Unix() + 3600
		}
		p.since, p.until = max(f, oldest), t
	} else {
		p.until = now.Unix() + 3600
		switch q.Get("range") {
		case "7d":
			p.since = now.AddDate(0, 0, -7).Unix()
		case "30d":
			p.since = now.AddDate(0, 0, -30).Unix()
		case "90d":
			p.since = now.AddDate(0, 0, -90).Unix()
		case "365d":
			p.since = now.AddDate(-1, 0, 0).Unix()
		default:
			p.since = now.Add(-24 * time.Hour).Unix()
		}
	}
	if p.until <= p.since {
		p.until = p.since + 3600
	}
	span := p.until - p.since
	p.grain = q.Get("grain")
	if _, ok := grainSecs[p.grain]; !ok {
		switch {
		case span <= 3*86400:
			p.grain = "hour"
		case span <= 92*86400:
			p.grain = "day"
		default:
			p.grain = "month"
		}
	}
	if p.grain == "hour" && span > maxHourSpan {
		p.grain = "day"
	}
	// Anfang auf den Beginn des ersten Abschnitts legen (ganze Tage/Wochen/Monate)
	p.since = p.key(p.since)
	return p
}

// key: Beginn des Abschnitts, in dem ts liegt (Unix-Sekunden).
func (p period) key(ts int64) int64 {
	if p.grain == "hour" {
		return ts - ts%3600
	}
	t := time.Unix(ts, 0).In(p.loc)
	y, m, d := t.Date()
	switch p.grain {
	case "week":
		wd := (int(t.Weekday()) + 6) % 7 // Montag = 0
		return time.Date(y, m, d-wd, 0, 0, 0, 0, p.loc).Unix()
	case "month":
		return time.Date(y, m, 1, 0, 0, 0, 0, p.loc).Unix()
	}
	return time.Date(y, m, d, 0, 0, 0, 0, p.loc).Unix()
}

// bucket: ungefähre Länge eines Abschnitts in Sekunden (für ältere Oberflächen und Achsen).
func (p period) bucket() int64 { return grainSecs[p.grain] }

func (p period) meta() map[string]any {
	return map[string]any{"bucket": p.bucket(), "grain": p.grain, "since": p.since, "until": p.until, "tz": p.loc.String()}
}

// calStarts: Beginn von heute, dieser Woche (Montag), diesem Monat, diesem Jahr in ?tz= und vor 30 Tagen.
func calStarts(r *http.Request) map[string]int64 {
	loc := time.Local
	if tz := r.URL.Query().Get("tz"); tz != "" && len(tz) < 64 {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}
	now := time.Now().In(loc)
	y, mo, d := now.Date()
	wd := (int(now.Weekday()) + 6) % 7
	return map[string]int64{
		"day":   time.Date(y, mo, d, 0, 0, 0, 0, loc).Unix(),
		"week":  time.Date(y, mo, d-wd, 0, 0, 0, 0, loc).Unix(),
		"month": time.Date(y, mo, 1, 0, 0, 0, 0, loc).Unix(),
		"year":  time.Date(y, 1, 1, 0, 0, 0, 0, loc).Unix(),
		"30d":   now.AddDate(0, 0, -30).Unix(),
	}
}
