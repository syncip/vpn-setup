package api

import "net/http"

// GET /api/search – kompakter Index für die Schnellsuche (Strg+K): Nutzer, Geräte/Zugänge,
// Server, Tarife. Ausgänge und Gruppen holt die Oberfläche aus /api/exits.
func (a *API) searchIndex(w http.ResponseWriter, r *http.Request) {
	type ent struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Sub    string `json:"sub,omitempty"`
		UserID int64  `json:"user_id,omitempty"`
		Proto  string `json:"proto,omitempty"`
		Off    bool   `json:"off,omitempty"`
	}
	out := map[string][]ent{"users": {}, "peers": {}, "servers": {}, "plans": {}}
	users, _ := a.St.Users()
	uname := map[int64]string{}
	for _, u := range users {
		uname[u.ID] = u.Name
		out["users"] = append(out["users"], ent{ID: u.ID, Name: u.Name, Sub: u.Note, Off: !u.Enabled})
	}
	servers, _ := a.St.Servers()
	sinfo := map[int64]*ent{}
	for _, s := range servers {
		e := ent{ID: s.ID, Name: s.Name, Proto: s.Protocol, Off: !s.Enabled}
		out["servers"] = append(out["servers"], e)
		sinfo[s.ID] = &e
	}
	peers, _ := a.St.Peers()
	for _, p := range peers {
		sub := ""
		proto := ""
		if s := sinfo[p.ServerID]; s != nil {
			sub, proto = s.Name, s.Proto
		}
		if v, ok := p.Settings["address4"].(string); ok && v != "" {
			sub += " · " + v
		}
		out["peers"] = append(out["peers"], ent{ID: p.ID, Name: p.Name, Sub: uname[p.UserID] + " · " + sub, UserID: p.UserID, Proto: proto, Off: !p.Enabled})
	}
	plans, _ := a.St.Plans()
	for _, p := range plans {
		out["plans"] = append(out["plans"], ent{ID: p.ID, Name: p.Name, Sub: p.Description})
	}
	writeJSON(w, out)
}
