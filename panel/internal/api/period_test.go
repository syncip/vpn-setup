package api

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestPeriodKeys(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("keine Zeitzonen-Daten")
	}
	at := func(s string) int64 {
		x, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
		if err != nil {
			t.Fatal(err)
		}
		return x.Unix()
	}
	cases := []struct{ grain, ts, want string }{
		{"day", "2026-03-29 23:30", "2026-03-29 00:00"},   // Tag der Zeitumstellung (23 Std.)
		{"week", "2026-11-28 12:00", "2026-11-23 00:00"},  // Samstag → Montag
		{"week", "2026-11-23 00:00", "2026-11-23 00:00"},  // Montag bleibt
		{"month", "2026-11-28 12:00", "2026-11-01 00:00"}, // Monatsanfang
		{"month", "2026-01-01 00:30", "2026-01-01 00:00"},
		{"hour", "2026-11-28 12:59", "2026-11-28 12:00"},
	}
	for _, c := range cases {
		p := period{grain: c.grain, loc: loc}
		if got := p.key(at(c.ts)); got != at(c.want) {
			t.Errorf("%s %s: %s, erwartet %s", c.grain, c.ts, time.Unix(got, 0).In(loc), c.want)
		}
	}
}

func TestParsePeriod(t *testing.T) {
	now := time.Now().Unix()
	get := func(q string) period { return parsePeriod(httptest.NewRequest("GET", "/x?"+q, nil)) }
	if p := get("range=24h"); p.grain != "hour" {
		t.Errorf("24h: %s", p.grain)
	}
	if p := get("range=30d"); p.grain != "day" {
		t.Errorf("30d: %s", p.grain)
	}
	if p := get("range=365d"); p.grain != "month" {
		t.Errorf("365d: %s", p.grain)
	}
	// Stunden für ein Jahr wären zu viele Balken → Tage
	if p := get("range=365d&grain=hour"); p.grain != "day" {
		t.Errorf("365d/hour: %s", p.grain)
	}
	p := get("from=" + itoa(now-10*86400) + "&to=" + itoa(now) + "&grain=week&tz=Europe/Berlin")
	if p.grain != "week" || p.loc.String() != "Europe/Berlin" || p.since > now-10*86400 {
		t.Errorf("frei: %+v", p)
	}
	if p := get("tz=../../etc/passwd"); p.loc != time.Local {
		t.Errorf("ungültige Zeitzone übernommen: %v", p.loc)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
