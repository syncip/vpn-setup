package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
)

// Anordnung der Fenster (Karten) je Seite, pro Administrator gespeichert: Reihenfolge, Breite
// (1–12 Spalten) und ausgeblendete Fenster. Liegt in der Tabelle settings unter
// „state:layout:<AdminID>“ (state:-Schlüssel tauchen in den Einstellungen nicht auf).

type boardLayout struct {
	Order  []string       `json:"order"`
	Hidden []string       `json:"hidden"`
	W      map[string]int `json:"w"`
}

var layoutID = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,47}$`)

func layoutKey(id int64) string { return "state:layout:" + strconv.FormatInt(id, 10) }

func validLayout(m map[string]boardLayout) error {
	if len(m) > 64 {
		return errors.New("zu viele Seiten")
	}
	for page, b := range m {
		if !layoutID.MatchString(page) {
			return errors.New("ungültiger Seitenname")
		}
		if len(b.Order) > 64 || len(b.Hidden) > 64 || len(b.W) > 64 {
			return errors.New("zu viele Fenster")
		}
		for _, id := range append(append([]string{}, b.Order...), b.Hidden...) {
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
