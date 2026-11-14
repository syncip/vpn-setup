package api

import (
	"net/http"

	"vpnpanel/internal/engine"
)

// GET /api/status – kompakter Zustand für Seitenleiste und Übersicht (wird alle paar Sekunden
// abgefragt): Kennzahlen des Servers, Geräte online und „Braucht Aufmerksamkeit“.
func (a *API) status(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"host": a.E.HostStats()}
	online, total := 0, 0
	if snap, err := a.E.Snapshot(); err == nil {
		for _, pb := range snap.Peers {
			total++
			if peerOn(pb.Peer) {
				online++
			}
		}
	}
	out["peers_online"], out["peers"] = online, total
	att := a.E.Attention(a.Version)
	if att == nil {
		att = []engine.AttentionItem{}
	}
	out["attention"] = att
	writeJSON(w, out)
}
