package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/exits"
	"vpnpanel/internal/store"
)

// ---------- Ausgänge und Gruppen (Menü „Proxy“) ----------

type exitRow struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Enabled  bool              `json:"enabled"`
	Type     string            `json:"type"`
	Server   string            `json:"server"` // Gegenstelle (Anzeige)
	Address  string            `json:"address,omitempty"`
	NeedAuth bool              `json:"need_auth"`
	HasAuth  bool              `json:"has_auth"`
	Username string            `json:"username,omitempty"`
	Removed  []string          `json:"removed"`
	Groups   []int64           `json:"groups"`
	Status   *exits.ExitStatus `json:"status"`
	Error    string            `json:"error,omitempty"`
}

type groupRow struct {
	ID      int64              `json:"id"`
	Name    string             `json:"name"`
	Enabled bool               `json:"enabled"`
	Exits   []int64            `json:"exits"`
	OnFail  string             `json:"on_fail"`
	MaxLoss float64            `json:"max_loss"`
	MaxRTT  float64            `json:"max_rtt"`
	MinMbit float64            `json:"min_mbit"`
	DNS     string             `json:"dns"`
	Status  *exits.GroupStatus `json:"status"`
	Users   []map[string]any   `json:"users"`
}

func (a *API) listExits(w http.ResponseWriter, r *http.Request) {
	eo, err := a.St.Objects("exit")
	if err != nil {
		fail(w, err)
		return
	}
	gro, _ := a.St.Objects("group")
	es, gs := a.E.Exits.Status()
	errs := a.E.Errors()
	inGroups := map[int64][]int64{}
	groups := []*groupRow{}
	for _, o := range gro {
		g := exits.GroupFrom(o)
		row := &groupRow{ID: g.ID, Name: g.Name, Enabled: g.Enabled, Exits: g.Exits, OnFail: g.OnFail, MaxLoss: g.MaxLoss,
			MaxRTT: g.MaxRTT, MinMbit: g.MinMbit, DNS: strings.Join(g.DNS, ", "), Users: []map[string]any{}}
		if row.Exits == nil {
			row.Exits = []int64{}
		}
		if s, ok := gs[g.ID]; ok {
			row.Status = &s
		}
		for _, id := range g.Exits {
			inGroups[id] = append(inGroups[id], g.ID)
		}
		for _, s := range a.E.GroupUsers(g.ID) {
			row.Users = append(row.Users, map[string]any{"id": s.ID, "name": s.Name, "protocol": s.Protocol})
		}
		groups = append(groups, row)
	}
	rows := []*exitRow{}
	for _, o := range eo {
		row := &exitRow{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Removed: []string{}, Groups: inGroups[o.ID]}
		row.Type, _ = o.Data["type"].(string)
		if l, ok := o.Data["removed"].([]any); ok {
			for _, v := range l {
				if s, ok := v.(string); ok {
					row.Removed = append(row.Removed, s)
				}
			}
		}
		if row.Groups == nil {
			row.Groups = []int64{}
		}
		if x, err := exits.ExitFrom(o); err == nil {
			if x.WG != nil {
				row.Server, row.Address = x.WG.Endpoint, x.WG.Address.String()
			} else if x.OVPN != nil {
				row.Server, row.NeedAuth = x.OVPN.Remote, x.OVPN.NeedAuth
				row.HasAuth, row.Username = x.User != "" && x.Pass != "", x.User
			}
		} else {
			row.Error = err.Error()
		}
		if s, ok := es[o.ID]; ok {
			row.Status = &s
		}
		if msg := errs[fmt.Sprintf("exit:%d", o.ID)]; msg != "" && row.Error == "" {
			row.Error = msg
		}
		rows = append(rows, row)
	}
	writeJSON(w, map[string]any{"exits": rows, "groups": groups, "error": errs["exits"],
		"speedtest": a.E.Setting("exit_speedtest")})
}

type exitInput struct {
	Name     *string `json:"name"`
	Enabled  *bool   `json:"enabled"`
	Config   string  `json:"config"`
	Username *string `json:"username"`
	Password *string `json:"password"` // leer = unverändert
}

// parseExitConfig erkennt die Art und bereinigt die Konfiguration.
func parseExitConfig(text string) (typ string, removed []string, err error) {
	text = strings.TrimPrefix(text, "\uFEFF")
	if strings.Contains(strings.ToLower(text), "[interface]") {
		w, err := exits.ParseWG(text)
		if err != nil {
			return "", nil, err
		}
		return "wireguard", w.Removed, nil
	}
	o, err := exits.ParseOVPN(text)
	if err != nil {
		return "", nil, err
	}
	return "openvpn", o.Removed, nil
}

func (a *API) saveExit(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in exitInput
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
	var removed []string
	if strings.TrimSpace(in.Config) != "" {
		if len(in.Config) > 256*1024 {
			errJSON(w, http.StatusBadRequest, "Konfiguration zu groß")
			return
		}
		typ, rm, err := parseExitConfig(in.Config)
		if err != nil {
			errJSON(w, http.StatusBadRequest, "Konfiguration: "+err.Error())
			return
		}
		if old, _ := o.Data["type"].(string); old != "" && old != typ {
			errJSON(w, http.StatusBadRequest, "Art des Ausgangs kann nicht geändert werden – bitte neu anlegen")
			return
		}
		o.Data["type"] = typ
		o.Secrets["config"] = strings.TrimPrefix(in.Config, "\uFEFF")
		removed = rm
		if removed == nil {
			removed = []string{}
		}
		o.Data["removed"] = removed
	} else if o.ID == 0 {
		errJSON(w, http.StatusBadRequest, "Konfiguration fehlt")
		return
	}
	if in.Username != nil {
		u := strings.TrimSpace(*in.Username)
		if len(u) > 200 || strings.ContainsAny(u, "\r\n") {
			errJSON(w, http.StatusBadRequest, "Benutzername ungültig")
			return
		}
		o.Secrets["username"] = u
	}
	if in.Password != nil && *in.Password != "" {
		if len(*in.Password) > 500 || strings.ContainsAny(*in.Password, "\r\n") {
			errJSON(w, http.StatusBadRequest, "Passwort ungültig")
			return
		}
		o.Secrets["password"] = *in.Password
	}
	if o.ID == 0 {
		slot, err := a.E.NewSlot("exit")
		if err != nil {
			fail(w, err)
			return
		}
		o.Data["slot"] = slot
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Ausgang „"+o.Name+"“ gespeichert")
	a.E.RequestApply()
	if removed == nil {
		removed = []string{}
	}
	writeJSON(w, map[string]any{"id": o.ID, "type": o.Data["type"], "removed": removed})
}

func (a *API) createExit(w http.ResponseWriter, r *http.Request) {
	a.saveExit(w, r, &store.Object{Kind: "exit", Enabled: true, Data: store.M{}, Secrets: store.M{}})
}

func (a *API) updateExit(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("exit", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveExit(w, r, o)
}

func (a *API) deleteExit(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("exit", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	// aus allen Gruppen entfernen
	gro, _ := a.St.Objects("group")
	for _, g := range gro {
		gr := exits.GroupFrom(g)
		var keep []int64
		for _, id := range gr.Exits {
			if id != o.ID {
				keep = append(keep, id)
			}
		}
		if len(keep) != len(gr.Exits) {
			g.Data["exits"] = orEmptyT(keep)
			_ = a.St.SaveObject(g)
		}
	}
	if err := a.St.DeleteObject("exit", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("warn", "Ausgang „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) checkExits(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Speed bool `json:"speed"`
	}
	_ = readJSON(r, &in)
	go a.E.CheckExits(in.Speed) // kann bei Geschwindigkeitstests eine Minute dauern
	writeJSON(w, map[string]bool{"ok": true})
}

type groupInput struct {
	Name    *string  `json:"name"`
	Enabled *bool    `json:"enabled"`
	Exits   []int64  `json:"exits"`
	OnFail  string   `json:"on_fail"`
	MaxLoss *float64 `json:"max_loss"`
	MaxRTT  *float64 `json:"max_rtt"`
	MinMbit *float64 `json:"min_mbit"`
	DNS     *string  `json:"dns"`
}

func (a *API) saveGroup(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in groupInput
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
	if in.Exits != nil {
		seen := map[int64]bool{}
		list := []int64{}
		for _, id := range in.Exits {
			if seen[id] {
				continue
			}
			if _, err := a.St.Object("exit", id); err != nil {
				errJSON(w, http.StatusBadRequest, fmt.Sprintf("Ausgang %d gibt es nicht", id))
				return
			}
			seen[id] = true
			list = append(list, id)
		}
		o.Data["exits"] = list
	}
	switch in.OnFail {
	case "":
	case "block", "direct":
		o.Data["on_fail"] = in.OnFail
	default:
		errJSON(w, http.StatusBadRequest, "Verhalten bei Ausfall: block oder direct")
		return
	}
	for k, v := range map[string]*float64{"max_loss": in.MaxLoss, "max_rtt": in.MaxRTT, "min_mbit": in.MinMbit} {
		if v == nil {
			continue
		}
		if *v < 0 || (k == "max_loss" && *v > 100) || *v > 100000 {
			errJSON(w, http.StatusBadRequest, "Grenzwert ungültig: "+k)
			return
		}
		o.Data[k] = *v
	}
	if in.DNS != nil {
		var ok []string
		for _, d := range strings.FieldsFunc(*in.DNS, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
			ad, err := netip.ParseAddr(d)
			if err != nil || !ad.Is4() {
				errJSON(w, http.StatusBadRequest, "DNS-Server: nur IPv4-Adressen ("+d+")")
				return
			}
			ok = append(ok, ad.String())
		}
		if len(ok) > 4 {
			errJSON(w, http.StatusBadRequest, "höchstens 4 DNS-Server")
			return
		}
		o.Data["dns"] = strings.Join(ok, ",")
	}
	if o.ID == 0 {
		slot, err := a.E.NewSlot("group")
		if err != nil {
			fail(w, err)
			return
		}
		o.Data["slot"] = slot
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Ausgangsgruppe „"+o.Name+"“ gespeichert")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	a.saveGroup(w, r, &store.Object{Kind: "group", Enabled: true, Data: store.M{"exits": []int64{}}, Secrets: store.M{}})
}

func (a *API) updateGroup(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("group", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveGroup(w, r, o)
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("group", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if users := a.E.GroupUsers(o.ID); len(users) > 0 {
		var names []string
		for _, s := range users {
			names = append(names, s.Name)
		}
		errJSON(w, http.StatusBadRequest, "Gruppe wird noch verwendet von: "+strings.Join(names, ", "))
		return
	}
	if err := a.St.DeleteObject("group", o.ID); err != nil {
		fail(w, err)
		return
	}
	_ = a.St.SetSetting(fmt.Sprintf("state:exits:active:%d", o.ID), "")
	_ = a.St.SetSetting(fmt.Sprintf("state:exits:pin:%d", o.ID), "")
	a.E.Log("warn", "Ausgangsgruppe „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) switchGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Exit int64 `json:"exit"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := a.E.SwitchExit(pathID(r), in.Exit); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- IP-Listen ----------

type ipListRow struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Mode    string   `json:"mode"`
	Entries []string `json:"entries"`
	All     bool     `json:"all"`
	Servers []int64  `json:"servers"`
}

func (a *API) listIPLists(w http.ResponseWriter, r *http.Request) {
	objs, err := a.St.Objects("iplist")
	if err != nil {
		fail(w, err)
		return
	}
	rows := []*ipListRow{}
	for _, o := range objs {
		l := engine.IPListFrom(o)
		rows = append(rows, &ipListRow{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Mode: l.Mode, Entries: orStrings(l.Entries),
			All: l.All, Servers: orInts(l.Servers)})
	}
	writeJSON(w, map[string]any{"lists": rows, "error": a.E.Errors()["acl"]})
}

func orStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func orInts(v []int64) []int64 {
	if v == nil {
		return []int64{}
	}
	return v
}

func (a *API) saveIPList(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
		Mode    string  `json:"mode"`
		Entries *string `json:"entries"` // eine Adresse/ein Netz pro Zeile, # = Kommentar
		All     *bool   `json:"all"`
		Servers []int64 `json:"servers"`
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
	switch in.Mode {
	case "":
		if o.Data["mode"] == nil {
			o.Data["mode"] = "block"
		}
	case "block", "allow":
		o.Data["mode"] = in.Mode
	default:
		errJSON(w, http.StatusBadRequest, "Art: block oder allow")
		return
	}
	if in.Entries != nil {
		list, err := engine.ParseIPEntries(*in.Entries)
		if err != nil {
			fail(w, err)
			return
		}
		o.Data["entries"] = orStrings(list)
	}
	if in.All != nil {
		o.Data["all"] = *in.All
	}
	if in.Servers != nil {
		ids := []int64{}
		for _, id := range in.Servers {
			if _, err := a.St.Server(id); err != nil {
				errJSON(w, http.StatusBadRequest, fmt.Sprintf("Server %d gibt es nicht", id))
				return
			}
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		o.Data["servers"] = ids
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "IP-Liste „"+o.Name+"“ gespeichert")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

func (a *API) createIPList(w http.ResponseWriter, r *http.Request) {
	a.saveIPList(w, r, &store.Object{Kind: "iplist", Enabled: true, Data: store.M{"mode": "block"}, Secrets: store.M{}})
}

func (a *API) updateIPList(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("iplist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveIPList(w, r, o)
}

func (a *API) deleteIPList(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("iplist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteObject("iplist", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("warn", "IP-Liste „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}
