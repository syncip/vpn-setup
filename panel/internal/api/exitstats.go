package api

// Statistik der Ausgänge: Live-Durchsatz (mit Verlauf der letzten 30 Minuten), Verkehr als Zeitreihe mit
// Zeitraum und Gliederung (period.go) und Summen heute/Woche/Monat/Jahr.

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"vpnpanel/internal/store"
)

// exitLive: aktueller Durchsatz je Ausgang und Gruppe (Byte/s), für die Live-Anzeige.
func (a *API) exitLive(w http.ResponseWriter, r *http.Request) {
	ex, gr, act := a.E.ExitLive()
	out := map[string]any{"ts": time.Now().UnixMilli(), "exits": ex, "groups": gr, "active": act}
	if r.URL.Query().Get("hist") == "1" { // einmal beim Öffnen: Verlauf der letzten 30 Minuten
		out["history"] = a.E.ExitLiveHistory()
	}
	writeJSON(w, out)
}

// exitTraffic: Verkehr je Ausgang als Zeitreihe [Abschnitt, Ausgang, hoch, runter] mit Zeitraum und
// Gliederung wie beim Gesamtverlauf (period.go), dazu die Summen je Ausgang im Zeitraum.
// Ältere Oberflächen schicken ?days=N.
func (a *API) exitTraffic(w http.ResponseWriter, r *http.Request) {
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && r.URL.Query().Get("from") == "" {
		d = min(max(d, 1), 3650)
		q := r.URL.Query()
		q.Set("from", strconv.FormatInt(time.Now().AddDate(0, 0, -d).Unix(), 10))
		r.URL.RawQuery = q.Encode()
	}
	p := parsePeriod(r)
	rows, err := a.St.ExitTrafficRange(p.since, p.until)
	if err != nil {
		fail(w, err)
		return
	}
	type k2 struct{ b, id int64 }
	by := map[k2]*[4]int64{}
	totals := map[int64]store.ExitTotals{}
	for _, x := range rows {
		k := k2{p.key(x[0]), x[1]}
		g := by[k]
		if g == nil {
			g = &[4]int64{k.b, k.id}
			by[k] = g
		}
		g[2] += x[2]
		g[3] += x[3]
		t := totals[x[1]]
		t.Up, t.Down = t.Up+x[2], t.Down+x[3]
		totals[x[1]] = t
	}
	series := make([][4]int64, 0, len(by))
	for _, g := range by {
		series = append(series, *g)
	}
	sort.Slice(series, func(i, j int) bool {
		if series[i][0] != series[j][0] {
			return series[i][0] < series[j][0]
		}
		return series[i][1] < series[j][1]
	})
	m := p.meta()
	m["series"], m["totals"] = series, totals
	m["days"] = (p.until - p.since + 86399) / 86400
	writeJSON(w, m)
}

// exitTotals: Verkehr je Ausgang heute, diese Woche, diesen Monat, dieses Jahr (Kalender in ?tz=) und 30 Tage.
func (a *API) exitTotals(w http.ResponseWriter, r *http.Request) {
	starts := calStarts(r)
	out := map[string]map[int64]store.ExitTotals{}
	for k, since := range starts {
		t, err := a.St.ExitTraffic(since)
		if err != nil {
			fail(w, err)
			return
		}
		out[k] = t
	}
	writeJSON(w, map[string]any{"totals": out, "starts": starts})
}
