package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// Ziel-Regeln: Verkehr über Ausgangsgruppen leiten (global, je Server, Nutzer oder Gerät).

type routeRow struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Scope   string   `json:"scope"`
	ScopeID int64    `json:"scope_id"`
	Match   string   `json:"match"` // all | targets
	Nets    []string `json:"nets"`
	Domains []string `json:"domains"`
	Lists   []int64  `json:"lists"`
	Group   int64    `json:"group"`
	Note    string   `json:"note,omitempty"` // warum die Regel gerade nicht wirkt
}

func routeRowOf(r *engine.Route, note string) *routeRow {
	m := "targets"
	if r.All {
		m = "all"
	}
	return &routeRow{ID: r.ID, Name: r.Name, Enabled: r.Enabled, Scope: r.Scope, ScopeID: r.ScopeID, Match: m,
		Nets: orStrings(r.Nets), Domains: orStrings(r.Domains), Lists: orInts(r.Lists), Group: r.Group, Note: note}
}

func (a *API) listRoutes(w http.ResponseWriter, r *http.Request) {
	objs, err := a.St.Objects("route")
	if err != nil {
		fail(w, err)
		return
	}
	notes := a.E.RouteNotes()
	rows := []*routeRow{}
	for _, o := range objs {
		rt := engine.RouteFrom(o)
		rows = append(rows, routeRowOf(rt, notes[rt.ID]))
	}
	// Auswahl für das Formular
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
	sOpts, uOpts, pOpts, gOpts, lOpts := []opt{}, []opt{}, []opt{}, []opt{}, []opt{}
	proto := map[int64]string{}
	for _, s := range servers {
		proto[s.ID] = s.Protocol
		sOpts = append(sOpts, opt{ID: s.ID, Name: s.Name, Protocol: s.Protocol, Enabled: s.Enabled})
	}
	for _, u := range users {
		uOpts = append(uOpts, opt{ID: u.ID, Name: u.Name, Enabled: u.Enabled})
	}
	for _, p := range peers {
		pOpts = append(pOpts, opt{ID: p.ID, Name: p.Name, Protocol: proto[p.ServerID], UserID: p.UserID, ServerID: p.ServerID, Enabled: p.Enabled})
	}
	if gs, err := a.St.Objects("group"); err == nil {
		for _, o := range gs {
			gOpts = append(gOpts, opt{ID: o.ID, Name: o.Name, Enabled: o.Enabled})
		}
	}
	if ls, err := a.St.Objects("iplist"); err == nil {
		for _, o := range ls {
			if engine.IPListFrom(o).Mode == "targets" {
				lOpts = append(lOpts, opt{ID: o.ID, Name: o.Name, Enabled: o.Enabled})
			}
		}
	}
	errs := a.E.Errors()
	writeJSON(w, map[string]any{"routes": rows, "servers": sOpts, "users": uOpts, "peers": pOpts, "groups": gOpts, "lists": lOpts,
		"error": strings.TrimSpace(errs["acl"] + " " + errs["dns"])})
}

func (a *API) saveRoute(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
		Scope   *string `json:"scope"`
		ScopeID *int64  `json:"scope_id"`
		Match   *string `json:"match"`
		Nets    *string `json:"nets"`    // ein Netz pro Zeile
		Domains *string `json:"domains"` // eine Domain pro Zeile
		Lists   []int64 `json:"lists"`
		Group   *int64  `json:"group"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if len([]rune(n)) > 60 {
			errJSON(w, http.StatusBadRequest, "Name ist zu lang")
			return
		}
		o.Name = n
	}
	if in.Enabled != nil {
		o.Enabled = *in.Enabled
	}
	if in.Scope != nil {
		o.Data["scope"] = *in.Scope
	}
	if in.ScopeID != nil {
		o.Data["scope_id"] = *in.ScopeID
	}
	scope, _ := o.Data["scope"].(string)
	var sid int64
	switch v := o.Data["scope_id"].(type) {
	case int64:
		sid = v
	case float64:
		sid = int64(v)
	}
	switch scope {
	case "global":
		o.Data["scope_id"] = int64(0)
	case "server":
		if _, err := a.St.Server(sid); err != nil {
			errJSON(w, http.StatusBadRequest, "Bitte einen Server wählen")
			return
		}
	case "user":
		if _, err := a.St.User(sid); err != nil {
			errJSON(w, http.StatusBadRequest, "Bitte einen Nutzer wählen")
			return
		}
	case "peer":
		if _, err := a.St.Peer(sid); err != nil {
			errJSON(w, http.StatusBadRequest, "Bitte ein Gerät wählen")
			return
		}
	default:
		errJSON(w, http.StatusBadRequest, "Gilt für: global, Server, Nutzer oder Gerät")
		return
	}
	if in.Match != nil {
		if *in.Match != "all" && *in.Match != "targets" {
			errJSON(w, http.StatusBadRequest, "Ziele: alles oder bestimmte Ziele")
			return
		}
		o.Data["match"] = *in.Match
	}
	if in.Nets != nil {
		list, err := engine.ParseRouteNets(*in.Nets)
		if err != nil {
			fail(w, err)
			return
		}
		o.Data["nets"] = orStrings(list)
	}
	if in.Domains != nil {
		list, err := engine.ParseRouteDomains(*in.Domains)
		if err != nil {
			fail(w, err)
			return
		}
		o.Data["domains"] = orStrings(list)
	}
	if in.Lists != nil {
		ids := []int64{}
		for _, id := range in.Lists {
			lo, err := a.St.Object("iplist", id)
			if err != nil || engine.IPListFrom(lo).Mode != "targets" {
				errJSON(w, http.StatusBadRequest, fmt.Sprintf("Zielliste %d gibt es nicht", id))
				return
			}
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		o.Data["lists"] = ids
	}
	if in.Group != nil {
		if *in.Group != 0 {
			if _, err := a.St.Object("group", *in.Group); err != nil {
				errJSON(w, http.StatusBadRequest, "Ausgangsgruppe gibt es nicht")
				return
			}
		}
		o.Data["group"] = *in.Group
	}
	if o.Data["match"] == nil {
		o.Data["match"] = "all"
	}
	if o.Data["group"] == nil {
		errJSON(w, http.StatusBadRequest, "Bitte wählen, worüber der Verkehr laufen soll")
		return
	}
	if o.Data["match"] == "targets" {
		n := 0
		for _, k := range []string{"nets", "domains", "lists"} {
			switch v := o.Data[k].(type) {
			case []string:
				n += len(v)
			case []int64:
				n += len(v)
			case []any:
				n += len(v)
			}
		}
		if n == 0 {
			errJSON(w, http.StatusBadRequest, "Bitte mindestens ein Ziel angeben (Netz, Domain oder Zielliste)")
			return
		}
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Ziel-Regel gespeichert")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

func (a *API) createRoute(w http.ResponseWriter, r *http.Request) {
	a.saveRoute(w, r, &store.Object{Kind: "route", Enabled: true, Data: store.M{}, Secrets: store.M{}})
}

func (a *API) updateRoute(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("route", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveRoute(w, r, o)
}

func (a *API) deleteRoute(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("route", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteObject("route", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Ziel-Regel gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// usedByRoutes: Text für den Löschschutz von Gruppen und Ziellisten.
func (a *API) usedByRoutes(kind string, id int64) string {
	rs := a.E.RoutesUsing(kind, id)
	if len(rs) == 0 {
		return ""
	}
	return fmt.Sprintf("wird noch von %d Ziel-Regel(n) verwendet", len(rs))
}
