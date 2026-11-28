package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
)

// Anordnung der Fenster (Karten) je Seite, pro Administrator gespeichert: Reihenfolge, Breite
// (1–12 Spalten), ausgeblendete und hinzugefügte Fenster. Unter „chart:<id>“ liegen die Einstellungen
// einer Grafik (Darstellung je Einheit, Einheit, Höhe, Zeitraum, ausgeblendete Reihen in Hidden), unter
// „period:<id>“ die Zeitraum-Wahl eines Verlaufs (web/src/lib/period.js). Liegt in der Tabelle settings unter
// „state:layout:<AdminID>“ (state:-Schlüssel tauchen in den Einstellungen nicht auf).

type boardLayout struct {
	Order  []string       `json:"order,omitempty"`
	Hidden []string       `json:"hidden,omitempty"`
	Shown  []string       `json:"shown,omitempty"` // anfangs ausgeblendete Fenster, die hinzugefügt wurden
	W      map[string]int `json:"w,omitempty"`
	// Grafik („chart:<id>“)
	KindRate  string `json:"kind_rate,omitempty"`
	KindBytes string `json:"kind_bytes,omitempty"`
	KindCount string `json:"kind_count,omitempty"`
	Unit      string `json:"unit,omitempty"`  // bits | bytes
	Size      string `json:"size,omitempty"`  // s | m | l
	Range     string `json:"range,omitempty"` // z. B. 10m, 24h, 7
	// Zeitraum-Wahl („period:<id>“)
	Mode   string `json:"mode,omitempty"`  // 24h | 7d | … | day | week | month | year | custom
	Grain  string `json:"grain,omitempty"` // auto | hour | day | week | month
	From   string `json:"from,omitempty"`  // JJJJ-MM-TT (custom)
	To     string `json:"to,omitempty"`
	Offset int    `json:"offset,omitempty"` // 0 = aktueller Zeitraum, -1 = davor …
}

var (
	layoutID   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,47}$`)
	layoutPage = regexp.MustCompile(`^(chart:|period:)?[a-z0-9][a-z0-9_.-]{0,47}$`)
	layoutDay  = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2})?$`)
	layoutOpt  = regexp.MustCompile(`^[a-z0-9]{0,8}$`)
)

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func layoutKey(id int64) string { return "state:layout:" + strconv.FormatInt(id, 10) }

func validLayout(m map[string]boardLayout) error {
	if len(m) > 256 {
		return errors.New("zu viele Seiten")
	}
	for page, b := range m {
		if !layoutPage.MatchString(page) {
			return errors.New("ungültiger Seitenname")
		}
		if len(b.Order) > 64 || len(b.Hidden) > 64 || len(b.Shown) > 64 || len(b.W) > 64 {
			return errors.New("zu viele Fenster")
		}
		for _, k := range []string{b.KindRate, b.KindBytes, b.KindCount} {
			if !oneOf(k, "", "line", "area", "bars") {
				return errors.New("ungültige Darstellung")
			}
		}
		if !oneOf(b.Unit, "", "bits", "bytes") || !oneOf(b.Size, "", "s", "m", "l") || !layoutOpt.MatchString(b.Range) {
			return errors.New("ungültige Einstellung der Grafik")
		}
		if !oneOf(b.Mode, "", "24h", "7d", "30d", "90d", "365d", "day", "week", "month", "year", "custom") ||
			!oneOf(b.Grain, "", "auto", "hour", "day", "week", "month") ||
			!layoutDay.MatchString(b.From) || !layoutDay.MatchString(b.To) || b.Offset > 0 || b.Offset < -5000 {
			return errors.New("ungültiger Zeitraum")
		}
		for _, id := range append(append(append([]string{}, b.Order...), b.Hidden...), b.Shown...) {
			if !layoutID.MatchString(id) {
				return errors.New("ungültiger Fenstername")
			}
		}
		for id, w := range b.W {
			if !layoutID.MatchString(id) || w < 1 || w > 12 {
				return errors.New("ungültige Breite")
			}
		}
	}
	return nil
}

// GET /api/layout
func (a *API) getLayout(w http.ResponseWriter, r *http.Request) {
	m := map[string]boardLayout{}
	if raw := a.St.GetSetting(layoutKey(adminOf(r).ID), ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	writeJSON(w, m)
}

// PUT /api/layout – ganze Anordnung ersetzen
func (a *API) putLayout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	m := map[string]boardLayout{}
	if err := readJSON(r, &m); err != nil {
		fail(w, err)
		return
	}
	if err := validLayout(m); err != nil {
		fail(w, err)
		return
	}
	raw, _ := json.Marshal(m)
	if err := a.St.SetSetting(layoutKey(adminOf(r).ID), string(raw)); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, m)
}
