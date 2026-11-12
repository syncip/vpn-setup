package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// ---------- Zugriff auf Netze (Netzwerk → Zugriff) ----------

type netGrantRow struct {
	*engine.NetGrant
	Reach engine.GrantReach `json:"reach"`
}

func (a *API) listNetAccess(w http.ResponseWriter, r *http.Request) {
	objs, err := a.St.Objects("netaccess")
	if err != nil {
		fail(w, err)
		return
	}
	var gs []*engine.NetGrant
	for _, o := range objs {
		g := engine.NetGrantFrom(o)
		g.Servers, g.Users, g.Plans, g.Peers = orInts(g.Servers), orInts(g.Users), orInts(g.Plans), orInts(g.Peers)
		gs = append(gs, g)
	}
	reach := a.E.GrantReach(gs)
	rows := []netGrantRow{}
	for _, g := range gs {
		rows = append(rows, netGrantRow{NetGrant: g, Reach: reach[g.ID]})
	}
	// Auswahl für das Formular (nur Geräte, deren Verkehr weitergeleitet wird)
	type opt struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol,omitempty"`
		UserID   int64  `json:"user_id,omitempty"`
		ServerID int64  `json:"server_id,omitempty"`
		Enabled  bool   `json:"enabled"`
	}
	servers, _ := a.St.Servers()
	users, _ := a.St.Users()
	peers, _ := a.St.Peers()
	plans, _ := a.St.Plans()
	sOpts, uOpts, pOpts, plOpts := []opt{}, []opt{}, []opt{}, []opt{}
	protoOf := map[int64]string{}
	for _, s := range servers {
		protoOf[s.ID] = s.Protocol
		sOpts = append(sOpts, opt{ID: s.ID, Name: s.Name, Protocol: s.Protocol, Enabled: s.Enabled})
	}
	for _, u := range users {
		uOpts = append(uOpts, opt{ID: u.ID, Name: u.Name, Enabled: u.Enabled})
	}
	for _, p := range peers {
		if pr := protoOf[p.ServerID]; pr == "wireguard" || pr == "openvpn" || pr == "vless" {
			pOpts = append(pOpts, opt{ID: p.ID, Name: p.Name, Protocol: pr, UserID: p.UserID, ServerID: p.ServerID, Enabled: p.Enabled})
		}
	}
	for _, p := range plans {
		plOpts = append(plOpts, opt{ID: p.ID, Name: p.Name, Enabled: true})
	}
	writeJSON(w, map[string]any{"grants": rows, "networks": a.E.Networks(), "servers": sOpts, "users": uOpts, "peers": pOpts, "plans": plOpts})
}

func (a *API) saveNetAccess(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
		Servers []int64 `json:"servers"`
		All     *bool   `json:"all"`
		Users   []int64 `json:"users"`
		Plans   []int64 `json:"plans"`
		Peers   []int64 `json:"peers"`
		Note    *string `json:"note"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if badLabel(n) {
			errJSON(w, http.StatusBadRequest, "Name fehlt oder ist zu lang")
			return
		}
		o.Name = n
	}
	if o.Name == "" {
		errJSON(w, http.StatusBadRequest, "Name fehlt")
		return
	}
	if in.Enabled != nil {
		o.Enabled = *in.Enabled
	}
	if in.Note != nil {
		n := strings.TrimSpace(*in.Note)
		if len(n) > 300 {
			errJSON(w, http.StatusBadRequest, "Notiz zu lang")
			return
		}
		o.Data["note"] = n
	}
	if in.All != nil {
		o.Data["all"] = *in.All
	}
	// IDs prüfen und doppelte entfernen
	check := func(key string, list []int64, exists func(int64) error, what string) bool {
		if list == nil {
			return true
		}
		if len(list) > 5000 {
			errJSON(w, http.StatusBadRequest, "zu viele Einträge: "+what)
			return false
		}
		seen := map[int64]bool{}
		out := []int64{}
		for _, id := range list {
			if seen[id] {
				continue
			}
			if exists(id) != nil {
				errJSON(w, http.StatusBadRequest, fmt.Sprintf("%s %d gibt es nicht", what, id))
				return false
			}
			seen[id] = true
			out = append(out, id)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		o.Data[key] = out
		return true
	}
	for _, id := range in.Servers {
		if s, err := a.St.Server(id); err == nil && s.Protocol != "wireguard" {
			errJSON(w, http.StatusBadRequest, "„"+s.Name+"“ ist kein WireGuard-Server – Netze sind WireGuard-Server")
			return
		}
	}
	if !check("servers", in.Servers, func(id int64) error { _, err := a.St.Server(id); return err }, "Server") {
		return
	}
	if !check("users", in.Users, func(id int64) error { _, err := a.St.User(id); return err }, "Nutzer") ||
		!check("plans", in.Plans, func(id int64) error { _, err := a.St.Plan(id); return err }, "Tarif") ||
		!check("peers", in.Peers, func(id int64) error { _, err := a.St.Peer(id); return err }, "Gerät") {
		return
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Netz-Freigabe „"+o.Name+"“ gespeichert")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

func (a *API) createNetAccess(w http.ResponseWriter, r *http.Request) {
	a.saveNetAccess(w, r, &store.Object{Kind: "netaccess", Enabled: true, Data: store.M{}, Secrets: store.M{}})
}

func (a *API) updateNetAccess(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("netaccess", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveNetAccess(w, r, o)
}

func (a *API) deleteNetAccess(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("netaccess", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteObject("netaccess", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("warn", "Netz-Freigabe „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}
