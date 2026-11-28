package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// System → „Was gilt?“: Für ein Gerät, einen Nutzer, einen Server, eine Gruppe oder ein Gerät ohne VPN
// alles zeigen, was wirkt – Routing, DNS, SmartDNS, Limits, Zugriff, Einstellungen – jeweils mit Herkunft.
// Die Werte kommen aus denselben Daten wie beim Anwenden (kompilierte Ziel-Regeln, Profile, Limits).

type effRow struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Sub    string `json:"sub,omitempty"`
	From   string `json:"from,omitempty"`   // Herkunft (z. B. „Nutzer“, „Tarif „Basis““, „Vorgabe“)
	Link   string `json:"link,omitempty"`   // Seite zum Ändern
	Target string `json:"target,omitempty"` // anderes Objekt in dieser Übersicht (peer:3, group:2 …)
	Tone   string `json:"tone,omitempty"`   // ok | warn | bad | muted
}

type effSection struct {
	Key   string   `json:"key"`
	Title string   `json:"title"`
	Icon  string   `json:"icon"`
	Rows  []effRow `json:"rows"`
	Empty string   `json:"empty,omitempty"` // Text, wenn nichts gesetzt ist
	Note  string   `json:"note,omitempty"`
}

type effOut struct {
	Kind     string       `json:"kind"`
	ID       int64        `json:"id"`
	Name     string       `json:"name"`
	Sub      string       `json:"sub"`
	Proto    string       `json:"proto,omitempty"`
	Sections []effSection `json:"sections"`
}

type effTarget struct {
	Kind  string `json:"kind"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Sub   string `json:"sub,omitempty"`
	Proto string `json:"proto,omitempty"`
	Off   bool   `json:"off,omitempty"`
}

// effCtx: einmal geladene Daten für eine Auswertung.
type effCtx struct {
	a        *API
	snap     *engine.Snapshot
	g        proto.Global
	groups   map[int64]*exits.Group
	gstat    map[int64]exits.GroupStatus
	exitName map[int64]string
	routes   map[int64]*engine.Route
	smart    map[int64]string // SmartDNS-Profil → Name
	servers  map[int64]*store.Server
}

func (a *API) effCtx() (*effCtx, error) {
	snap, err := a.E.Snapshot()
	if err != nil {
		return nil, err
	}
	c := &effCtx{a: a, snap: snap, g: a.E.Global(), groups: map[int64]*exits.Group{}, exitName: map[int64]string{},
		routes: map[int64]*engine.Route{}, smart: map[int64]string{}, servers: map[int64]*store.Server{}}
	xs, gs := a.E.LoadExits()
	for _, x := range xs {
		c.exitName[x.ID] = x.Name
	}
	for _, g := range gs {
		c.groups[g.ID] = g
	}
	if a.E.Exits != nil {
		_, c.gstat = a.E.Exits.Status()
	}
	if objs, err := a.St.Objects("route"); err == nil {
		for _, o := range objs {
			c.routes[o.ID] = engine.RouteFrom(o)
		}
	}
	if objs, err := a.St.Objects("smartdns"); err == nil {
		for _, o := range objs {
			c.smart[o.ID] = o.Name
		}
	}
	for _, sb := range snap.Servers {
		c.servers[sb.Server.ID] = sb.Server
	}
	return c, nil
}

// ---------- Texte ----------

func q(s string) string { return "„" + s + "“" }

func (c *effCtx) userName(id int64) string {
	if u := c.snap.Users[id]; u != nil {
		return u.Name
	}
	return fmt.Sprintf("Nutzer %d", id)
}

func (c *effCtx) serverName(id int64) string {
	if s := c.servers[id]; s != nil {
		return s.Name
	}
	return fmt.Sprintf("Server %d", id)
}

func (c *effCtx) peerName(id int64) string {
	if pb := c.snap.Peers[id]; pb != nil {
		return pb.Peer.Name
	}
	return fmt.Sprintf("Gerät %d", id)
}

// scopeText: Zuordnung als Herkunft („Gerät“, „Nutzer „Max““ …).
func (c *effCtx) scopeText(sc string) string {
	kind, idS, _ := strings.Cut(sc, ":")
	id, _ := strconv.ParseInt(idS, 10, 64)
	switch kind {
	case "peer":
		return "Gerät " + q(c.peerName(id))
	case "user":
		return "Nutzer " + q(c.userName(id))
	case "server":
		return "Server " + q(c.serverName(id))
	case "client":
		if o, err := c.a.St.Object("dnsclient", id); err == nil {
			return "Gerät ohne VPN " + q(o.Name)
		}
		return "Gerät ohne VPN"
	case "id":
		return "beim Gerät gewählt"
	case "vpn":
		return "alle VPN-Geräte"
	case "ext":
		return "alle Geräte ohne VPN"
	case "global":
		return "alle Geräte"
	}
	return sc
}

func (c *effCtx) groupName(id int64) string {
	if g := c.groups[id]; g != nil {
		return g.Name
	}
	return fmt.Sprintf("Gruppe %d", id)
}

// groupWay: „Gruppe „USA“ (aktiv: Mullvad NY)“ bzw. Zustand.
func (c *effCtx) groupWay(id int64) (string, string, string) {
	if id == 0 {
		return "direkt über den Server", "", ""
	}
	name := "Gruppe " + q(c.groupName(id))
	st, ok := c.gstat[id]
	switch {
	case !ok:
		return name, "", ""
	case st.Active != 0:
		tone := "ok"
		if st.State == "failover" {
			tone = "warn"
		}
		return name, "aktiver Ausgang: " + c.exitName[st.Active], tone
	case st.State == "direct":
		return name, "kein Ausgang erreichbar – läuft direkt über den Server", "warn"
	case st.State == "blocked":
		r := "kein Ausgang erreichbar – Verkehr gesperrt"
		if st.Reason != "" {
			r += " (" + st.Reason + ")"
		}
		return name, r, "bad"
	}
	return name, "", ""
}

func ruleName(r *engine.Route) string {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Sprintf("Regel Nr. %d", r.ID)
	}
	return "Regel " + q(r.Name)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func listText(a []string, max int) string {
	if len(a) <= max {
		return strings.Join(a, ", ")
	}
	return strings.Join(a[:max], ", ") + fmt.Sprintf(" … (+%d)", len(a)-max)
}

func ruleTargets(r proto.RouteRule, lists map[int64]string) string {
	if r.All {
		return "alles"
	}
	var parts []string
	if len(r.Domains) > 0 {
		parts = append(parts, listText(r.Domains, 4))
	}
	if len(r.Nets) > 0 {
		var ns []string
		for _, n := range r.Nets {
			ns = append(ns, n.String())
		}
		parts = append(parts, listText(ns, 3))
	}
	for _, id := range r.Lists {
		parts = append(parts, "Liste "+q(lists[id]))
	}
	return strings.Join(parts, "; ")
}

func mbit(v float64) string {
	if v <= 0 {
		return "unbegrenzt"
	}
	return strconv.FormatFloat(v, 'f', -1, 64) + " Mbit/s"
}

func fmtBytes(b int64) string {
	f := float64(b)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%d B", b)
			}
			return strings.Replace(fmt.Sprintf("%.1f %s", f, u), ".", ",", 1)
		}
		f /= 1024
	}
	return ""
}

func dateText(ts int64) string { return time.Unix(ts, 0).Format("02.01.2006") }

var statusText = map[string]string{"ok": "Aktiv", "throttled": "Gedrosselt", "blocked": "Gesperrt", "disabled": "Deaktiviert", "expired": "Abgelaufen"}

func statusTone(s string) string {
	switch s {
	case "ok":
		return "ok"
	case "throttled":
		return "warn"
	}
	return "bad"
}

// ---------- Abschnitte ----------

func (c *effCtx) targetLists() map[int64]string {
	out := map[int64]string{}
	if objs, err := c.a.St.Objects("iplist"); err == nil {
		for _, o := range objs {
			out[o.ID] = o.Name
		}
	}
	return out
}

// routingRows: wirksame Ziel-Regeln in ihrer Reihenfolge (die erste passende gilt).
func (c *effCtx) routingRows(p *proto.Policy) []effRow {
	lists := c.targetLists()
	var rows []effRow
	hasAll := false
	if p != nil {
		for _, r := range p.Rules {
			way, sub, tone := c.groupWay(r.Group)
			row := effRow{Label: ruleTargets(r, lists), Value: way, Sub: sub, Tone: tone}
			if r.Group != 0 {
				row.Target = fmt.Sprintf("group:%d", r.Group)
			}
			switch {
			case r.ID >= 1_000_000_000: // SmartDNS
				pid := (r.ID - 1_000_000_000) / 100
				row.From = "SmartDNS " + q(c.smart[pid])
				row.Link = "#/dns/smart"
			case r.ID == 0:
				row.From = "Proxy-Server: Einstellung „Ausgang“"
				row.Link = "#/routing/proxy"
			default:
				if rt := c.routes[r.ID]; rt != nil {
					sc := rt.Scope
					if sc != "global" {
						sc = fmt.Sprintf("%s:%d", rt.Scope, rt.ScopeID)
					}
					row.From = ruleName(rt) + " · " + c.scopeText(sc)
				}
				row.Link = "#/routing/rules"
			}
			if r.All {
				hasAll = true
				row.Label = "alles andere"
				if len(rows) == 0 {
					row.Label = "alles"
				}
			}
			rows = append(rows, row)
			if r.All {
				break
			}
		}
	}
	if !hasAll {
		label := "alles andere"
		if len(rows) == 0 {
			label = "alles"
		}
		rows = append(rows, effRow{Label: label, Value: "direkt über den Server", From: "keine Regel", Tone: "muted"})
	}
	return rows
}

func (c *effCtx) dnsRows(prof *engine.EffProfile, smart []engine.EffSmart, defaultScope string) []effRow {
	var rows []effRow
	if !c.g.PanelDNS {
		rows = append(rows, effRow{Label: "Panel-DNS", Value: "aus", Sub: "Geräte nutzen ihren eigenen DNS – Filter und SmartDNS wirken nicht", Tone: "warn", Link: "#/dns/settings"})
	}
	if prof == nil {
		rows = append(rows, effRow{Label: "Filterprofil", Value: "keins", Sub: "nichts wird gesperrt", Tone: "muted", Link: "#/dns/profiles"})
	} else {
		sub := "Blocklisten: keine"
		if len(prof.Lists) > 0 {
			sub = "Blocklisten: " + listText(prof.Lists, 5)
		}
		if prof.Rules > 0 {
			sub += " · " + plural(prof.Rules, "eigene Regel", "eigene Regeln")
		}
		rows = append(rows, effRow{Label: "Filterprofil", Value: q(prof.Name), Sub: sub, From: c.scopeText(prof.Scope), Link: "#/dns/profiles"})
		doh := "erlaubt"
		if prof.BlockDoH {
			doh = "gesperrt (Geräte müssen den Panel-DNS nutzen)"
		}
		rows = append(rows, effRow{Label: "Verschlüsseltes DNS fremder Anbieter", Value: doh, From: "Filterprofil " + q(prof.Name)})
		ans := "0.0.0.0 (Seite lädt nicht)"
		if prof.NXDomain {
			ans = "„gibt es nicht“ (NXDOMAIN)"
		}
		rows = append(rows, effRow{Label: "Antwort bei Sperre", Value: ans, From: "Filterprofil " + q(prof.Name)})
	}
	if len(smart) == 0 {
		rows = append(rows, effRow{Label: "SmartDNS", Value: "keine Weiterleitung", Tone: "muted", Link: "#/dns/smart"})
	}
	for _, s := range smart {
		way, sub, tone := c.groupWay(s.Group)
		if sub != "" {
			sub = " · " + sub
		}
		rows = append(rows, effRow{Label: "SmartDNS: " + listText(s.Domains, 4), Value: way, Sub: plural(len(s.Domains), "Domain", "Domains") + sub, Tone: tone,
			From: "Profil " + q(s.ProfileName) + " · " + c.scopeText(s.Scope), Link: "#/dns/smart", Target: fmt.Sprintf("group:%d", s.Group)})
	}
	_ = defaultScope
	return rows
}

func (c *effCtx) limitRows(u *store.User) []effRow {
	var rows []effRow
	v := c.snap.Verdict[u.ID]
	st := effRow{Label: "Status", Value: statusText[v.Status], Sub: v.Reason, Tone: statusTone(v.Status), Link: fmt.Sprintf("#/users/%d", u.ID)}
	rows = append(rows, st)
	exp := effRow{Label: "Ablauf", Value: "nie", Tone: "muted"}
	if u.ExpiresAt > 0 {
		exp = effRow{Label: "Ablauf", Value: dateText(u.ExpiresAt)}
		if time.Now().Unix() >= u.ExpiresAt {
			exp.Tone = "bad"
		}
	}
	rows = append(rows, exp)
	l := engine.EffectiveLimits(u, c.snap.Plans)
	from := "keine Limits"
	link := fmt.Sprintf("#/users/%d", u.ID)
	switch {
	case u.Limits != nil:
		from = "eigene Limits des Nutzers"
	case l != nil && u.PlanID != nil:
		from = "Tarif " + q(c.snap.Plans[*u.PlanID].Name)
		link = "#/users/plans"
	}
	if l == nil {
		rows = append(rows, effRow{Label: "Limits", Value: "keine", Sub: "Datenvolumen und Geschwindigkeit unbegrenzt", Tone: "muted", Link: link})
		return rows
	}
	vol := "unbegrenzt"
	if l.TrafficGB > 0 {
		per := map[string]string{"daily": "je Tag", "weekly": "je Woche", "monthly": "je Monat", "none": "insgesamt", "": "insgesamt"}[l.Period]
		vol = fmt.Sprintf("%s GB %s", strconv.FormatFloat(l.TrafficGB, 'f', -1, 64), per)
		used := fmtBytes(u.PeriodUp+u.PeriodDown) + " verbraucht"
		after := "danach gesperrt"
		if l.OnLimit == "throttle" {
			after = "danach " + mbit(l.LimitDownMbit) + " ↓ / " + mbit(l.LimitUpMbit) + " ↑"
		}
		rows = append(rows, effRow{Label: "Datenvolumen", Value: vol, Sub: used + " · " + after, From: from, Link: link})
	} else {
		rows = append(rows, effRow{Label: "Datenvolumen", Value: vol, From: from, Link: link, Tone: "muted"})
	}
	rows = append(rows, effRow{Label: "Geschwindigkeit", Value: mbit(l.SpeedDownMbit) + " ↓ / " + mbit(l.SpeedUpMbit) + " ↑", From: from, Link: link})
	if len(l.Tiers) > 0 {
		rows = append(rows, effRow{Label: "Drosselstufen", Value: plural(len(l.Tiers), "Stufe", "Stufen"), From: from, Link: link})
	}
	if v.RateDown > 0 || v.RateUp > 0 {
		rows = append(rows, effRow{Label: "Gerade wirksam", Value: mbit(v.RateDown) + " ↓ / " + mbit(v.RateUp) + " ↑", Tone: "warn"})
	}
	md := "unbegrenzt"
	if l.MaxDevices > 0 {
		md = strconv.Itoa(l.MaxDevices)
	}
	rows = append(rows, effRow{Label: "Höchstens Geräte", Value: md, From: from, Link: link})
	return rows
}

// grantsFor: Netzfreigaben, die für einen Zugang gelten (WireGuard → andere Netze).
func (c *effCtx) accessRows(pb *proto.PeerBundle) []effRow {
	var rows []effRow
	if on, allow := c.a.E.PrivateBlock(); on {
		sub := "lokale und private Adressen sind nicht erreichbar"
		if allow > 0 {
			sub += fmt.Sprintf(" (außer %s)", plural(allow, "Ausnahme", "Ausnahmen"))
		}
		rows = append(rows, effRow{Label: "Private Netze", Value: "gesperrt", Sub: sub, From: "Einstellungen", Link: "#/system/settings"})
	} else {
		rows = append(rows, effRow{Label: "Private Netze", Value: "erreichbar", Sub: "Sperre privater Netze ist aus", From: "Einstellungen", Link: "#/system/settings", Tone: "muted"})
	}
	if c.g.Net != nil {
		for _, t := range c.g.Net.For(pb.Peer.ID) {
			var ns []string
			for _, n := range t.Nets {
				ns = append(ns, n.String())
			}
			rows = append(rows, effRow{Label: "Netz " + q(t.Name), Value: "erreichbar", Sub: listText(ns, 4), Link: "#/servers/access", Target: fmt.Sprintf("server:%d", t.Server), Tone: "ok"})
		}
	}
	if objs, err := c.a.St.Objects("netaccess"); err == nil {
		for _, o := range objs {
			gr := engine.NetGrantFrom(o)
			if gr.Enabled && gr.Matches(pb) {
				var ns []string
				for _, id := range gr.Servers {
					ns = append(ns, c.serverName(id))
				}
				rows = append(rows, effRow{Label: "Freigabe " + q(gr.Name), Value: "zu " + listText(ns, 4), Link: "#/servers/access"})
			}
		}
	}
	return rows
}

func (c *effCtx) aclRows(server int64) []effRow {
	acl := c.a.E.ACLFor(server)
	var rows []effRow
	if len(acl.Allow) > 0 {
		rows = append(rows, effRow{Label: "Nur erlaubt aus", Value: listText(acl.Allow, 5), Sub: "andere Adressen können sich nicht verbinden", Link: "#/routing/iplists", Tone: "warn"})
	}
	if len(acl.Deny) > 0 {
		rows = append(rows, effRow{Label: "Gesperrt aus", Value: listText(acl.Deny, 5), Link: "#/routing/iplists"})
	}
	if len(rows) == 0 {
		rows = append(rows, effRow{Label: "Verbindungen", Value: "von überall", Sub: "keine Sperr- oder Freigabeliste", Link: "#/routing/iplists", Tone: "muted"})
	}
	return rows
}

// settingRows: Einstellungen laut Treiber (nur gesetzte, keine Schlüssel).
func settingRows(fields []proto.Field, m store.M, kind string, link string) []effRow {
	var rows []effRow
	for _, f := range fields {
		if f.Type == "secret" || f.ReadOnly || f.Type == "peers" {
			continue
		}
		if len(f.Kinds) > 0 && kind != "" {
			ok := false
			for _, k := range f.Kinds {
				if k == kind {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		v, set := m[f.Key]
		from := ""
		if !set || v == nil || v == "" {
			if f.Default == nil {
				continue
			}
			v, from = f.Default, "Vorgabe"
		}
		val := fieldValue(f, v)
		if val == "" {
			continue
		}
		row := effRow{Label: f.Label, Value: val, From: from, Link: link}
		if from != "" {
			row.Tone = "muted"
		}
		rows = append(rows, row)
	}
	return rows
}

func fieldValue(f proto.Field, v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "ja"
		}
		return "nein"
	case []any:
		var s []string
		for _, e := range x {
			s = append(s, fmt.Sprint(e))
		}
		return listText(s, 5)
	case []string:
		return listText(x, 5)
	case float64:
		v = strconv.FormatFloat(x, 'f', -1, 64)
	}
	s := fmt.Sprint(v)
	for _, o := range f.Options {
		if fmt.Sprint(o.Value) == s {
			return o.Label
		}
	}
	if len(s) > 120 {
		s = s[:120] + " …"
	}
	return s
}
