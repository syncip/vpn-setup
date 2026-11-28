package engine

// Live-Verlauf der Ausgänge und Gruppen (letzte 30 Minuten) im Panel statt im Browser: bleibt beim
// Neuladen und Seitenwechsel erhalten. Gemessen wird, solange jemand die Live-Anzeige abfragt
// (ExitLive alle 2 s), höchstens alle 1,5 s ein Punkt.

import (
	"strconv"
	"sync"
	"time"
)

const exitHistKeep = 30 * time.Minute

type exitHistState struct {
	mu   sync.Mutex
	at   time.Time
	hist map[string][]LivePoint // "all", "e<ID>", "g<ID>"
}

var exitHist = &exitHistState{hist: map[string][]LivePoint{}}

func (h *exitHistState) record(now time.Time, exits, groups map[int64]ExitRate) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if now.Sub(h.at) < 1500*time.Millisecond {
		return
	}
	h.at = now
	ms, cut := now.UnixMilli(), now.Add(-exitHistKeep).UnixMilli()
	var all LivePoint
	seen := map[string]bool{"all": true}
	for id, r := range exits {
		k := "e" + strconv.FormatInt(id, 10)
		h.hist[k] = appendPoint(h.hist[k], LivePoint{TS: ms, Up: r.Up, Down: r.Down}, cut)
		seen[k] = true
		all.Up += r.Up
		all.Down += r.Down
	}
	for id, r := range groups {
		k := "g" + strconv.FormatInt(id, 10)
		h.hist[k] = appendPoint(h.hist[k], LivePoint{TS: ms, Up: r.Up, Down: r.Down}, cut)
		seen[k] = true
	}
	all.TS = ms
	h.hist["all"] = appendPoint(h.hist["all"], all, cut)
	for k, l := range h.hist { // gelöschte Ausgänge/Gruppen auslaufen lassen
		if !seen[k] && (len(l) == 0 || l[len(l)-1].TS < cut) {
			delete(h.hist, k)
		}
	}
}

// ExitLiveHistory: Kopie des Verlaufs (Schlüssel "all", "e<ID>", "g<ID>").
func (e *Engine) ExitLiveHistory() map[string][]LivePoint {
	exitHist.mu.Lock()
	defer exitHist.mu.Unlock()
	out := make(map[string][]LivePoint, len(exitHist.hist))
	for k, l := range exitHist.hist {
		out[k] = append([]LivePoint(nil), l...)
	}
	return out
}

// MigrateRetention: Verkehr wird seit v0.38.0 400 statt 180 Tage aufbewahrt (Jahresansicht). Wer die alte
// Vorgabe gespeichert hat, bekommt einmalig die neue; ein selbst gewählter anderer Wert bleibt.
func (e *Engine) MigrateRetention() {
	const flag = "state:retention_400"
	if e.St.GetSetting(flag, "") == "1" {
		return
	}
	if e.St.GetSetting("traffic_retention", "") == "180" {
		_ = e.St.SetSetting("traffic_retention", "400")
	}
	_ = e.St.SetSetting(flag, "1")
}
