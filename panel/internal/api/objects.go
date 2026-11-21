package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/exits"
	"vpnpanel/internal/store"
)

// ---------- Ausgänge und Gruppen (Menü „Proxy“) ----------

type exitRow struct {
	ID       int64                       `json:"id"`
	Name     string                      `json:"name"`
	Enabled  bool                        `json:"enabled"`
	Type     string                      `json:"type"`
	Server   string                      `json:"server"` // Gegenstelle (Anzeige)
	Address  string                      `json:"address,omitempty"`
	NeedAuth bool                        `json:"need_auth"`
	HasAuth  bool                        `json:"has_auth"`
	Username string                      `json:"username,omitempty"`
	Removed  []string                    `json:"removed"`
	Groups   []int64                     `json:"groups"`
	Status   *exits.ExitStatus           `json:"status"`
	Error    string                      `json:"error,omitempty"`
	Mode     string                      `json:"mode"`               // always | standby
	CheckMin int                         `json:"check_min"`          // Prüfabstand in Bereitschaft
	Traffic  map[string]store.ExitTotals `json:"traffic"`            // day | week | month | all
	Limits   *store.Limits               `json:"limits"`             // nil = keine
	Limit    *engine.ExitLimitState      `json:"limit"`              // Verbrauch und Status im Zeitraum
	Via      int64                       `json:"via"`                // Kaskade: verbunden über diesen Ausgang (0 = direkt)
	ViaRule  string                      `json:"via_rule,omitempty"` // Weg bestimmt von dieser Ziel-Regel
	Tor      *exits.TorCfg               `json:"tor,omitempty"`
	Bridges  int                         `json:"bridges,omitempty"` // Tor: Zahl der Brücken (Inhalt bleibt geheim)
}

type groupRow struct {
	ID      int64                       `json:"id"`
	Name    string                      `json:"name"`
	Enabled bool                        `json:"enabled"`
	Exits   []int64                     `json:"exits"`
	OnFail  string                      `json:"on_fail"`
	MaxLoss float64                     `json:"max_loss"`
	MaxRTT  float64                     `json:"max_rtt"`
	MinMbit float64                     `json:"min_mbit"`
	DNS     string                      `json:"dns"`
	Status  *exits.GroupStatus          `json:"status"`
	Users   []map[string]any            `json:"users"`
	Limits  *store.Limits               `json:"limits"`         // nil = keine
	Limit   *engine.ExitLimitState      `json:"limit"`          // Verbrauch und Status im Zeitraum
	Traffic map[string]store.ExitTotals `json:"traffic"`        // day | month (über die Gruppe gelaufen)
	Auto    int64                       `json:"auto,omitempty"` // automatisch für diesen Ausgang (Ende einer Kette in einer Ziel-Regel)
	Rotate  exits.Rotation              `json:"rotate"`         // Wechsel innerhalb der Gruppe
	Block   exits.BlockCheck            `json:"block"`          // Block-Prüfung
	Avoid   int                         `json:"avoid"`          // Ziele mit Ausnahme (laufen über einen anderen Ausgang)
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
	glim := a.E.GroupLimitStates()
	now0 := time.Now()
	gtDay, _ := a.St.GroupTraffic(now0.Add(-24 * time.Hour).Unix())
	gtMonth, _ := a.St.GroupTraffic(now0.AddDate(0, 0, -30).Unix())
	ov := a.E.Exits.Overrides()
	for _, o := range gro {
		g := exits.GroupFrom(o)
		row := &groupRow{ID: g.ID, Name: g.Name, Enabled: g.Enabled, Exits: g.Exits, OnFail: g.OnFail, MaxLoss: g.MaxLoss,
			MaxRTT: g.MaxRTT, MinMbit: g.MinMbit, DNS: strings.Join(g.DNS, ", "), Users: []map[string]any{},
			Limits: engine.ExitLimits(o), Traffic: map[string]store.ExitTotals{"day": gtDay[g.ID], "month": gtMonth[g.ID]}, Rotate: g.Rotate,
			Block: g.Block, Avoid: len(ov[g.ID]), Auto: numOf(o.Data["auto"])}
		if st, ok := glim[g.ID]; ok {
			row.Limit = &st
		}
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
	now := time.Now()
	tr := map[string]map[int64]store.ExitTotals{}
	for k, since := range map[string]int64{"day": now.Add(-24 * time.Hour).Unix(), "week": now.AddDate(0, 0, -7).Unix(),
		"month": now.AddDate(0, 0, -30).Unix(), "all": 0} {
		tr[k], _ = a.St.ExitTraffic(since)
	}
	lim := a.E.ExitLimitStates()
	var chainOwner map[int64]string
	if cw, err := a.loadChainWorld(); err == nil {
		_, chainOwner, _ = cw.plan()
	}
	rows := []*exitRow{}
	for _, o := range eo {
		row := &exitRow{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Removed: []string{}, Groups: inGroups[o.ID], Traffic: map[string]store.ExitTotals{}}
		for k, m := range tr {
			row.Traffic[k] = m[o.ID]
		}
		row.Type, _ = o.Data["type"].(string)
		row.Limits = engine.ExitLimits(o)
		if st, ok := lim[o.ID]; ok {
			row.Limit = &st
		}
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
			row.Mode, row.CheckMin, row.Via = x.Mode, x.CheckMin, x.Via
			row.ViaRule = chainOwner[o.ID]
			if x.Tor != nil {
				row.Tor, row.Bridges = x.Tor, len(x.Tor.Bridges)
				row.Server = "Tor"
				if len(x.Tor.ExitCountries) > 0 {
					row.Server += " · Ausgang " + strings.ToUpper(strings.Join(x.Tor.ExitCountries, ", "))
				}
				if row.Bridges > 0 {
					row.Server += " · Brücken"
				}
			} else if x.WG != nil {
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
	Name     *string         `json:"name"`
	Enabled  *bool           `json:"enabled"`
	Config   string          `json:"config"`
	Username *string         `json:"username"`
	Password *string         `json:"password"`  // leer = unverändert
	Mode     *string         `json:"mode"`      // always | standby
	CheckMin *int            `json:"check_min"` // Minuten (Bereitschaft)
	Limits   json.RawMessage `json:"limits"`    // fehlt = unverändert, null = keine Limits
	Via      *int64          `json:"via"`       // Kaskade: über diesen Ausgang verbinden (0 = direkt)
	Type     string          `json:"type"`      // nur beim Anlegen: "tor" (ohne Konfigurationsdatei)
	Tor      *exits.TorCfg   `json:"tor"`       // Tor-Einstellungen (fehlt = unverändert)
	Bridges  *string         `json:"bridges"`   // Tor-Brücken, je Zeile eine (fehlt = unverändert)
}

// exitVias: Ausgang → Vorgänger (Kaskade) aller gespeicherten Ausgänge.
func exitVias(objs []*store.Object) map[int64]int64 {
	out := map[int64]int64{}
	for _, o := range objs {
		if v, ok := o.Data["via"].(float64); ok && v > 0 {
			out[o.ID] = int64(v)
		}
	}
	return out
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
	if in.Type == "tor" && o.ID == 0 {
		o.Data["type"] = "tor"
	}
	isTor := o.Data["type"] == "tor"
	if isTor {
		if strings.TrimSpace(in.Config) != "" {
			errJSON(w, http.StatusBadRequest, "Ein Tor-Ausgang hat keine Konfigurationsdatei")
			return
		}
		cur := exits.TorFrom(o.Data["tor"], strOf(o.Secrets["bridges"]))
		if in.Tor != nil {
			br := cur.Bridges
			cur = in.Tor
			cur.ExitCountries, cur.EntryCountries, cur.ExcludeCountries = exits.NormCountries(cur.ExitCountries),
				exits.NormCountries(cur.EntryCountries), exits.NormCountries(cur.ExcludeCountries)
			cur.Bridges = br
		}
		if in.Bridges != nil {
			if len(*in.Bridges) > 64*1024 {
				errJSON(w, http.StatusBadRequest, "Brücken: zu lang")
				return
			}
			cur.Bridges = exits.TorFrom(nil, *in.Bridges).Bridges
		}
		if msg := cur.Check(); msg != "" {
			errJSON(w, http.StatusBadRequest, "Tor: "+msg)
			return
		}
		o.Data["tor"] = cur
		if len(cur.Bridges) > 0 {
			o.Secrets["bridges"] = strings.Join(cur.Bridges, "\n")
		} else {
			delete(o.Secrets, "bridges")
		}
		o.Data["removed"] = []string{}
	} else if strings.TrimSpace(in.Config) != "" {
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
	if in.Mode != nil {
		if *in.Mode != "always" && *in.Mode != "standby" {
			errJSON(w, http.StatusBadRequest, "Verbindung: always oder standby")
			return
		}
		o.Data["mode"] = *in.Mode
	}
	if in.CheckMin != nil {
		if *in.CheckMin < 5 || *in.CheckMin > 7*24*60 {
			errJSON(w, http.StatusBadRequest, "Prüfabstand: 5 Minuten bis 7 Tage")
			return
		}
		o.Data["check_min"] = *in.CheckMin
	}
	if in.Via != nil && *in.Via != numOf(o.Data["via"]) && o.ID != 0 {
		if rule := a.chainRuleFor(o.ID); rule != "" {
			errJSON(w, http.StatusBadRequest, "Der Weg von „"+o.Name+"“ wird von der Ziel-Regel „"+rule+"“ bestimmt – dort die Stufen ändern")
			return
		}
	}
	if in.Via != nil {
		eo, err := a.St.Objects("exit")
		if err != nil {
			fail(w, err)
			return
		}
		ids := map[int64]bool{}
		for _, x := range eo {
			ids[x.ID] = true
		}
		if msg := exits.CheckVia(o.ID, *in.Via, exitVias(eo), func(id int64) bool { return ids[id] }); msg != "" {
			errJSON(w, http.StatusBadRequest, msg)
			return
		}
		// Über Tor geht nur TCP: kein WireGuard, OpenVPN nur mit „proto tcp“
		for _, x := range eo {
			if x.ID != *in.Via || x.Data["type"] != "tor" {
				continue
			}
			switch o.Data["type"] {
			case "wireguard":
				errJSON(w, http.StatusBadRequest, "WireGuard kann nicht über Tor laufen (Tor überträgt nur TCP)")
				return
			case "openvpn":
				cfg := strings.ToLower(strOf(o.Secrets["config"]))
				if !strings.Contains(cfg, "proto tcp") {
					errJSON(w, http.StatusBadRequest, "OpenVPN über Tor nur mit „proto tcp“ (Tor überträgt nur TCP)")
					return
				}
			}
		}
		if *in.Via == 0 {
			delete(o.Data, "via")
		} else {
			o.Data["via"] = *in.Via
		}
	}
	if msg := setObjLimits(o, in.Limits); msg != "" {
		errJSON(w, http.StatusBadRequest, msg)
		return
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
	// Kaskade: Läuft ein anderer Ausgang über diesen, erst dort umstellen
	if eo, err := a.St.Objects("exit"); err == nil {
		for _, x := range eo {
			if v, _ := x.Data["via"].(float64); int64(v) == o.ID && x.ID != o.ID {
				errJSON(w, http.StatusConflict, "Ausgang „"+x.Name+"“ läuft über diesen Ausgang – dort zuerst „Verbunden über“ ändern")
				return
			}
		}
	}
	// Stufe einer Ziel-Regel (Kaskade) bzw. Ende einer Kette (automatische Gruppe)
	if cw, err := a.loadChainWorld(); err == nil {
		auto := cw.autoGroup(o.ID)
		for _, r := range cw.routes {
			inChain := false
			for _, id := range idsOf(r.Data["chain"]) {
				inChain = inChain || id == o.ID
			}
			if inChain || (auto != nil && numOf(r.Data["group"]) == auto.ID) {
				errJSON(w, http.StatusConflict, "Ausgang ist Stufe der Ziel-Regel „"+a.routeLabel(r)+"“ – dort zuerst die Stufen ändern")
				return
			}
		}
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
	_ = a.St.DeleteExitTraffic(o.ID)
	a.E.Log("warn", "Ausgang „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// setObjLimits übernimmt Limits aus der Eingabe (fehlt = unverändert, null = keine). Fehlertext oder "".
func setObjLimits(o *store.Object, raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if string(raw) == "null" {
		delete(o.Data, "limits")
		return ""
	}
	var l store.Limits
	if err := json.Unmarshal(raw, &l); err != nil {
		return "Limits: " + err.Error()
	}
	if err := engine.ValidateLimits(&l); err != nil {
		return err.Error()
	}
	l.MaxDevices = 0 // gibt es bei Ausgängen und Gruppen nicht
	if l.HasAny() {
		o.Data["limits"] = l
	} else {
		delete(o.Data, "limits")
	}
	return ""
}

// resetExitUsage / resetGroupUsage: Verbrauch im laufenden Zeitraum auf 0 setzen.
func (a *API) resetExitUsage(w http.ResponseWriter, r *http.Request) {
	if err := a.E.ResetUsage("exit", pathID(r)); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) resetGroupUsage(w http.ResponseWriter, r *http.Request) {
	if err := a.E.ResetUsage("group", pathID(r)); err != nil {
		fail(w, err)
		return
	}
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

// exitNewIdentity: Tor-Ausgang – neue Identität (neue Kreise für neue Verbindungen).
func (a *API) exitNewIdentity(w http.ResponseWriter, r *http.Request) {
	if err := a.E.ExitNewIdentity(pathID(r)); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// checkExit: einen Ausgang sofort prüfen (Ping bzw. mit Speedtest) und das Ergebnis liefern.
func (a *API) checkExit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Speed bool `json:"speed"`
	}
	_ = readJSON(r, &in)
	o, err := a.St.Object("exit", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	// Verbinden (Bereitschaft) + Speedtest kann länger dauern als die übliche Schreibfrist
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(150 * time.Second))
	st, err := a.E.CheckExit(o.ID, in.Speed)
	res := map[string]any{"status": st, "ok": err == nil}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, res)
}

type groupInput struct {
	Name    *string           `json:"name"`
	Enabled *bool             `json:"enabled"`
	Exits   []int64           `json:"exits"`
	OnFail  string            `json:"on_fail"`
	MaxLoss *float64          `json:"max_loss"`
	MaxRTT  *float64          `json:"max_rtt"`
	MinMbit *float64          `json:"min_mbit"`
	DNS     *string           `json:"dns"`
	Limits  json.RawMessage   `json:"limits"` // fehlt = unverändert, null = keine Limits
	Rotate  *exits.Rotation   `json:"rotate"` // fehlt = unverändert
	Block   *exits.BlockCheck `json:"block"`  // fehlt = unverändert
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
	if msg := setObjLimits(o, in.Limits); msg != "" {
		errJSON(w, http.StatusBadRequest, msg)
		return
	}
	if in.Rotate != nil {
		r := *in.Rotate
		if r.Mode == "" {
			r = exits.RotationFrom(nil) // aus – Vorgaben behalten
			r.Mode = ""
			if old := exits.RotationFrom(o.Data["rotate"]); old.MinMin > 0 || old.MinGB > 0 {
				r = old // Werte für später behalten
				r.Mode = ""
			}
		}
		if msg := r.Check(); msg != "" {
			errJSON(w, http.StatusBadRequest, msg)
			return
		}
		b, _ := json.Marshal(r)
		var mm map[string]any
		_ = json.Unmarshal(b, &mm)
		o.Data["rotate"] = mm
	}
	if in.Block != nil {
		b := *in.Block
		var ds []string
		seen := map[string]bool{}
		for _, d := range b.Domains {
			n := exits.NormDomain(d)
			if n == "" {
				if strings.TrimSpace(d) != "" {
					errJSON(w, http.StatusBadRequest, "Block-Prüfung: ungültiges Ziel „"+strings.TrimSpace(d)+"“")
					return
				}
				continue
			}
			if !seen[n] {
				seen[n] = true
				ds = append(ds, n)
			}
		}
		b.Domains = ds
		if msg := b.Check(); msg != "" {
			errJSON(w, http.StatusBadRequest, msg)
			return
		}
		o.Data["block"] = b.Map()
		defer a.E.BlockKick()
	}
	if o.ID != 0 {
		if msg := a.checkChains(func(cw *chainWorld) { cw.groups[o.ID] = o }); msg != "" {
			errJSON(w, http.StatusBadRequest, msg)
			return
		}
		defer a.syncChains()
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
	if msg := a.usedByRoutes("group", o.ID); msg != "" {
		errJSON(w, http.StatusBadRequest, "Die Gruppe "+msg)
		return
	}
	if names := a.E.SmartUsing(o.ID); len(names) > 0 {
		errJSON(w, http.StatusBadRequest, "Die Gruppe wird noch von SmartDNS verwendet: "+strings.Join(names, ", "))
		return
	}
	_ = a.St.DeleteGroupTraffic(o.ID)
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

// groupBlock: Ziele und Ergebnisse der Block-Prüfung einer Gruppe.
func (a *API) groupBlock(w http.ResponseWriter, r *http.Request) {
	rows, last, err := a.E.BlockReport(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	var ts int64
	if !last.IsZero() {
		ts = last.Unix()
	}
	writeJSON(w, map[string]any{"rows": rows, "last": ts})
}

// checkGroupBlock: Ziele der Gruppe (bzw. ein Ziel) sofort über alle Ausgänge prüfen.
func (a *API) checkGroupBlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
	}
	_ = readJSON(r, &in)
	a.E.BlockCheckNow(pathID(r), in.Domain)
	writeJSON(w, map[string]bool{"ok": true})
}

// resetGroupBlock: gespeicherte Ergebnisse eines Ziels verwerfen (wird neu geprüft).
func (a *API) resetGroupBlock(w http.ResponseWriter, r *http.Request) {
	d := exits.NormDomain(r.URL.Query().Get("domain"))
	if d == "" {
		errJSON(w, http.StatusBadRequest, "Ziel fehlt")
		return
	}
	if err := a.St.DeleteBlockResults(d, 0); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Block-Prüfung: Ergebnisse für "+d+" zurückgesetzt")
	a.E.BlockCheckNow(pathID(r), d)
	writeJSON(w, map[string]bool{"ok": true})
}

// rotateGroup: Wechsel sofort auslösen (ganze Gruppe: nächster Ausgang, je Ziel: neu mischen).
func (a *API) rotateGroup(w http.ResponseWriter, r *http.Request) {
	if err := a.E.RotateGroup(pathID(r)); err != nil {
		fail(w, err)
		return
	}
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
	ID      int64              `json:"id"`
	Name    string             `json:"name"`
	Enabled bool               `json:"enabled"`
	Mode    string             `json:"mode"`
	Entries []string           `json:"entries"`
	All     bool               `json:"all"`
	Servers []int64            `json:"servers"`
	URL     string             `json:"url"`
	Refresh int                `json:"refresh"` // Stunden, 0 = nur von Hand
	Total   int                `json:"total"`   // Einträge insgesamt (eigene + geladene)
	Status  *engine.ListStatus `json:"status,omitempty"`
	UsedBy  int                `json:"used_by"` // Ziel-Regeln, die die Liste verwenden
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
		row := &ipListRow{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Mode: l.Mode, Entries: orStrings(l.Entries),
			All: l.All, Servers: orInts(l.Servers), URL: l.URL, Refresh: l.Refresh, UsedBy: len(a.E.RoutesUsing("iplist", o.ID))}
		st, total := a.E.ListInfo(o)
		row.Total = total
		if l.URL != "" {
			row.Status = &st
		}
		rows = append(rows, row)
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
		URL     *string `json:"url"`     // Online-Liste: Adresse (leer = keine)
		Refresh *int    `json:"refresh"` // Stunden zwischen den Abrufen, 0 = nur von Hand
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
	oldMode, _ := o.Data["mode"].(string)
	switch in.Mode {
	case "":
		if o.Data["mode"] == nil {
			o.Data["mode"] = "block"
		}
	case "block", "allow", "targets":
		if oldMode == "targets" && in.Mode != "targets" && o.ID != 0 {
			if msg := a.usedByRoutes("iplist", o.ID); msg != "" {
				errJSON(w, http.StatusBadRequest, "Die Zielliste "+msg)
				return
			}
		}
		o.Data["mode"] = in.Mode
	default:
		errJSON(w, http.StatusBadRequest, "Art: Sperrliste, Freigabeliste oder Zielliste")
		return
	}
	oldURL, _ := o.Data["url"].(string)
	if in.URL != nil {
		u := strings.TrimSpace(*in.URL)
		if u != "" {
			if err := engine.CheckListURL(u); err != nil {
				fail(w, err)
				return
			}
		}
		o.Data["url"] = u
	}
	if in.Refresh != nil {
		if *in.Refresh < 0 || *in.Refresh > 24*90 {
			errJSON(w, http.StatusBadRequest, "Aktualisierung: 0 (nur von Hand) bis 2160 Stunden")
			return
		}
		o.Data["refresh"] = *in.Refresh
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
	if newURL, _ := o.Data["url"].(string); newURL != oldURL {
		a.E.DeleteListData(o.ID) // alter Inhalt gehört zur alten Adresse
		if newURL != "" {
			go func(id int64) { // erster Abruf im Hintergrund – die Liste kann groß sein
				_, _ = a.E.FetchList(id)
				a.E.RequestApply()
			}(o.ID)
		}
	}
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

// refreshIPList lädt eine Online-Liste sofort neu.
func (a *API) refreshIPList(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if _, err := a.E.FetchList(id); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	st := a.E.ListStatus(id)
	writeJSON(w, map[string]any{"ok": true, "count": st.Count, "skipped": st.Skipped})
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
	if msg := a.usedByRoutes("iplist", o.ID); msg != "" {
		errJSON(w, http.StatusBadRequest, "Die Liste "+msg)
		return
	}
	if err := a.St.DeleteObject("iplist", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.DeleteListData(o.ID)
	a.E.Log("warn", "IP-Liste „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// exitLive: aktueller Durchsatz je Ausgang und Gruppe (Byte/s), für die Live-Anzeige.
func (a *API) exitLive(w http.ResponseWriter, r *http.Request) {
	ex, gr, act := a.E.ExitLive()
	writeJSON(w, map[string]any{"ts": time.Now().UnixMilli(), "exits": ex, "groups": gr, "active": act})
}

// exitTraffic: Verkehr je Ausgang als Zeitreihe (?days=1|7|30|90).
func (a *API) exitTraffic(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days < 1 || days > 365 {
		days = 7
	}
	bucket := int64(3600)
	switch {
	case days > 30:
		bucket = 86400
	case days > 2:
		bucket = 6 * 3600
	}
	series, err := a.St.ExitTrafficSeries(time.Now().AddDate(0, 0, -days).Unix(), bucket)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"bucket": bucket, "series": series, "days": days})
}

func strOf(v any) string { s, _ := v.(string); return s }
