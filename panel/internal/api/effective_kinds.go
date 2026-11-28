package api

// „Was gilt?“: Auswertung je Art (Nutzer, Gerät, Server, Gruppe …) und Handler.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// ---------- je Art ----------

func (c *effCtx) peer(id int64) (*effOut, error) {
	pb := c.snap.Peers[id]
	if pb == nil {
		return nil, store.ErrNotFound
	}
	srv := c.servers[pb.Peer.ServerID]
	if srv == nil {
		return nil, store.ErrNotFound
	}
	out := &effOut{Kind: "peer", ID: id, Name: pb.Peer.Name, Sub: "Gerät von " + pb.User.Name + " · " + srv.Name, Proto: srv.Protocol}
	ov := []effRow{
		{Label: "Nutzer", Value: pb.User.Name, Target: fmt.Sprintf("user:%d", pb.User.ID), Link: fmt.Sprintf("#/users/%d", pb.User.ID)},
		{Label: "Server", Value: srv.Name + " (" + srv.Protocol + ")", Target: fmt.Sprintf("server:%d", srv.ID), Link: "#/servers"},
	}
	switch {
	case !pb.Peer.Enabled:
		ov = append(ov, effRow{Label: "Zustand", Value: "deaktiviert", Sub: "kein Verkehr", Tone: "bad"})
	case !pb.Active:
		v := c.snap.Verdict[pb.User.ID]
		ov = append(ov, effRow{Label: "Zustand", Value: "gesperrt", Sub: v.Reason, Tone: "bad", From: "Nutzer"})
	default:
		ov = append(ov, effRow{Label: "Zustand", Value: "aktiv", Tone: "ok"})
	}
	if a := proto.Str(pb.Peer.Settings, "address4"); a != "" {
		ov = append(ov, effRow{Label: "Adresse im Tunnel", Value: a})
	}
	if pb.Peer.LastSeen > 0 {
		ov = append(ov, effRow{Label: "Zuletzt da", Value: time.Unix(pb.Peer.LastSeen, 0).Format("02.01.2006 15:04")})
	}
	out.Sections = append(out.Sections, effSection{Key: "overview", Title: "Überblick", Icon: "info", Rows: ov})

	pol := c.g.Policies[id]
	note := "Von oben nach unten: Die erste passende Zeile bestimmt den Weg. Gerät vor Nutzer vor Server vor „alle“; Domains und Netze vor „alles“."
	if srv.Protocol == "hysteria2" {
		pol = c.g.ServerPolicies[srv.ID]
		note = "Hysteria2 kann Geräte nicht einzeln leiten – es gelten nur Regeln für den Server und für alle."
	}
	rrows := c.routingRows(pol)
	if !pb.Active || !pb.Peer.Enabled {
		rrows = []effRow{{Label: "alles", Value: "kein Verkehr", Sub: "Zugang ist gesperrt bzw. deaktiviert", Tone: "bad"}}
	}
	out.Sections = append(out.Sections, effSection{Key: "routing", Title: "Routing – welche IP sehen Webseiten?", Icon: "route", Rows: rrows, Note: note})

	scopes := engine.PeerScopes(id, pb.User.ID, srv.ID)
	prof := c.a.E.DNSProfileFor(append(scopes, "global")...)
	smart := c.a.E.SmartFor(append(scopes, "vpn", "global")...)
	if srv.Protocol == "hysteria2" {
		var keep []engine.EffSmart
		for _, s := range smart {
			if !strings.HasPrefix(s.Scope, "peer:") && !strings.HasPrefix(s.Scope, "user:") {
				keep = append(keep, s)
			}
		}
		smart = keep
	}
	out.Sections = append(out.Sections, effSection{Key: "dns", Title: "DNS", Icon: "globe", Rows: c.dnsRows(prof, smart, "")})
	out.Sections = append(out.Sections, effSection{Key: "limits", Title: "Limits (vom Nutzer)", Icon: "gauge", Rows: c.limitRows(pb.User)})
	out.Sections = append(out.Sections, effSection{Key: "access", Title: "Zugriff", Icon: "shield", Rows: append(c.accessRows(pb), c.aclRows(srv.ID)...)})
	if d, ok := proto.Get(srv.Protocol); ok {
		if rows := settingRows(d.Info().PeerFields, pb.Peer.Settings, pb.Peer.Kind, fmt.Sprintf("#/users/%d", pb.User.ID)); len(rows) > 0 {
			out.Sections = append(out.Sections, effSection{Key: "settings", Title: "Einstellungen des Geräts", Icon: "settings", Rows: rows})
		}
	}
	return out, nil
}

// peerWay: kurzer Weg eines Geräts („alles über Gruppe „USA““).
func (c *effCtx) peerWay(pb *proto.PeerBundle) (string, string) {
	if !pb.Peer.Enabled {
		return "deaktiviert", "bad"
	}
	if !pb.Active {
		return "gesperrt", "bad"
	}
	pol := c.g.Policies[pb.Peer.ID]
	if s := c.servers[pb.Peer.ServerID]; s != nil && s.Protocol == "hysteria2" {
		pol = c.g.ServerPolicies[s.ID]
	}
	all, parts := int64(0), 0
	if pol != nil {
		for _, r := range pol.Rules {
			if r.All {
				all = r.Group
				break
			}
			parts++
		}
	}
	w, _, _ := c.groupWay(all)
	if all == 0 {
		w = "direkt"
	}
	if parts > 0 {
		w += fmt.Sprintf(" (+%s)", plural(parts, "Ausnahme", "Ausnahmen"))
	}
	return w, ""
}

func (c *effCtx) user(id int64) (*effOut, error) {
	u := c.snap.Users[id]
	if u == nil {
		return nil, store.ErrNotFound
	}
	out := &effOut{Kind: "user", ID: id, Name: u.Name, Sub: "Nutzer"}
	if u.Note != "" {
		out.Sub += " · " + u.Note
	}
	out.Sections = append(out.Sections, effSection{Key: "limits", Title: "Status und Limits", Icon: "gauge", Rows: c.limitRows(u)})
	var devs []effRow
	var pbs []*proto.PeerBundle
	for _, pb := range c.snap.Peers {
		if pb.User.ID == id {
			pbs = append(pbs, pb)
		}
	}
	sort.Slice(pbs, func(i, j int) bool { return pbs[i].Peer.ID < pbs[j].Peer.ID })
	for _, pb := range pbs {
		w, tone := c.peerWay(pb)
		devs = append(devs, effRow{Label: pb.Peer.Name, Value: w, Sub: c.serverName(pb.Peer.ServerID), Tone: tone, Target: fmt.Sprintf("peer:%d", pb.Peer.ID)})
	}
	out.Sections = append(out.Sections, effSection{Key: "devices", Title: "Geräte und ihr Weg", Icon: "phone", Rows: devs, Empty: "Keine Geräte.",
		Note: "Ein Klick zeigt alles, was für das Gerät gilt."})
	var rr []effRow
	lists := c.targetLists()
	for _, r := range c.routes {
		if r.Scope == "user" && r.ScopeID == id {
			way, _, _ := c.groupWay(r.Group)
			t := "alles"
			if !r.All {
				t = ruleTargets(proto.RouteRule{Domains: r.Domains, Lists: r.Lists}, lists)
				if len(r.Nets) > 0 {
					t = strings.TrimPrefix(t+"; "+listText(r.Nets, 3), "; ")
				}
			}
			row := effRow{Label: t, Value: way, From: ruleName(r), Link: "#/routing/rules"}
			if !r.Enabled {
				row.Tone, row.Sub = "muted", "Regel ist deaktiviert"
			}
			rr = append(rr, row)
		}
	}
	sort.Slice(rr, func(i, j int) bool { return rr[i].From < rr[j].From })
	out.Sections = append(out.Sections, effSection{Key: "routing", Title: "Ziel-Regeln für diesen Nutzer", Icon: "route", Rows: rr,
		Empty: "Keine eigenen Regeln – es gelten die des Servers bzw. für alle.", Note: "Regeln einzelner Geräte haben Vorrang."})
	prof := c.a.E.DNSProfileFor(fmt.Sprintf("user:%d", id), "global")
	smart := c.a.E.SmartFor(fmt.Sprintf("user:%d", id), "vpn", "global")
	out.Sections = append(out.Sections, effSection{Key: "dns", Title: "DNS", Icon: "globe", Rows: c.dnsRows(prof, smart, ""),
		Note: "Gilt für Geräte dieses Nutzers ohne eigene Zuordnung. Zuordnungen am Server stehen eine Ebene darunter; was für ein einzelnes Gerät wirklich gilt, zeigt das Gerät."})
	return out, nil
}

func (c *effCtx) server(id int64) (*effOut, error) {
	srv := c.servers[id]
	if srv == nil {
		return nil, store.ErrNotFound
	}
	out := &effOut{Kind: "server", ID: id, Name: srv.Name, Sub: "Server · " + srv.Protocol, Proto: srv.Protocol}
	n, act := 0, 0
	for _, pb := range c.snap.Peers {
		if pb.Peer.ServerID == id {
			n++
			if pb.Active {
				act++
			}
		}
	}
	ov := []effRow{{Label: "Zustand", Value: map[bool]string{true: "aktiv", false: "deaktiviert"}[srv.Enabled], Tone: map[bool]string{true: "ok", false: "bad"}[srv.Enabled], Link: "#/servers"},
		{Label: "Geräte", Value: fmt.Sprintf("%d (%d aktiv)", n, act)}}
	if d, ok := proto.Get(srv.Protocol); ok {
		if st := d.Status(c.a.E.Env(), srv); srv.Enabled && !st.Running {
			ov = append(ov, effRow{Label: "Dienst", Value: "läuft nicht", Sub: st.Detail, Tone: "bad"})
		}
	}
	out.Sections = append(out.Sections, effSection{Key: "overview", Title: "Überblick", Icon: "info", Rows: ov})
	note := "Gilt für Geräte ohne eigene Regel bzw. ohne Regel ihres Nutzers. Was für ein einzelnes Gerät wirklich gilt, zeigt das Gerät."
	if srv.Protocol == "hysteria2" {
		note = "Hysteria2 leitet alle Geräte gleich – genau so."
	}
	out.Sections = append(out.Sections, effSection{Key: "routing", Title: "Routing (Server und alle)", Icon: "route", Rows: c.routingRows(c.g.ServerPolicies[id]), Note: note})
	prof := c.a.E.DNSProfileFor(fmt.Sprintf("server:%d", id), "global")
	smart := c.a.E.SmartFor(fmt.Sprintf("server:%d", id), "vpn", "global")
	out.Sections = append(out.Sections, effSection{Key: "dns", Title: "DNS", Icon: "globe", Rows: c.dnsRows(prof, smart, ""),
		Note: "Gilt für Geräte dieses Servers ohne eigene Zuordnung bzw. ohne Zuordnung ihres Nutzers."})
	out.Sections = append(out.Sections, effSection{Key: "acl", Title: "Wer darf sich verbinden?", Icon: "shield", Rows: c.aclRows(id)})
	if objs, err := c.a.St.Objects("netaccess"); err == nil {
		var rows []effRow
		for _, o := range objs {
			gr := engine.NetGrantFrom(o)
			for _, s := range gr.Servers {
				if s == id {
					who := "alle Nutzer"
					if !gr.All {
						who = fmt.Sprintf("%s, %s, %s", plural(len(gr.Users), "Nutzer", "Nutzer"), plural(len(gr.Plans), "Tarif", "Tarife"), plural(len(gr.Peers), "Gerät", "Geräte"))
					}
					row := effRow{Label: q(gr.Name), Value: who, Link: "#/servers/access"}
					if !gr.Enabled {
						row.Tone, row.Sub = "muted", "deaktiviert"
					}
					rows = append(rows, row)
				}
			}
		}
		if srv.Protocol == "wireguard" {
			out.Sections = append(out.Sections, effSection{Key: "net", Title: "Wer darf in dieses Netz?", Icon: "network", Rows: rows, Empty: "Keine Freigaben – nur Geräte dieses Servers."})
		}
	}
	if d, ok := proto.Get(srv.Protocol); ok {
		if rows := settingRows(d.Info().ServerFields, srv.Settings, "", "#/servers"); len(rows) > 0 {
			out.Sections = append(out.Sections, effSection{Key: "settings", Title: "Einstellungen des Servers", Icon: "settings", Rows: rows})
		}
	}
	return out, nil
}

func (c *effCtx) group(id int64) (*effOut, error) {
	g := c.groups[id]
	if g == nil {
		return nil, store.ErrNotFound
	}
	out := &effOut{Kind: "group", ID: id, Name: g.Name, Sub: "Ausgangsgruppe"}
	way, sub, tone := c.groupWay(id)
	_ = way
	ov := []effRow{{Label: "Zustand", Value: map[bool]string{true: "aktiv", false: "deaktiviert"}[g.Enabled], Sub: sub, Tone: tone, Link: "#/routing/groups"}}
	if !g.Enabled {
		ov[0].Tone = "bad"
	}
	onFail := "Verkehr sperren"
	if g.OnFail == "direct" {
		onFail = "direkt über den Server (eigene IP sichtbar!)"
	}
	ov = append(ov, effRow{Label: "Wenn kein Ausgang geht", Value: onFail, Link: "#/routing/groups"})
	check := fmt.Sprintf("höchstens %s %% Verlust, %s ms", strconv.FormatFloat(g.MaxLoss, 'f', -1, 64), strconv.FormatFloat(g.MaxRTT, 'f', -1, 64))
	if g.MinMbit > 0 {
		check += ", mindestens " + mbit(g.MinMbit)
	}
	ov = append(ov, effRow{Label: "Prüfung", Value: check, Link: "#/routing/groups"})
	if g.Rotate.Mode != "" {
		ov = append(ov, effRow{Label: "Wechsel", Value: map[string]string{"group": "ganze Gruppe wechselt", "dest": "je Ziel verteilt"}[g.Rotate.Mode], Link: "#/routing/groups"})
	}
	ov = append(ov, effRow{Label: "DNS über die Gruppe", Value: strings.Join(g.DNS, ", ")})
	if ls, ok := c.a.E.GroupLimitStates()[id]; ok && ls.Limits != nil {
		v := "unbegrenzt"
		if ls.Limits.TrafficGB > 0 {
			v = fmt.Sprintf("%s von %s GB", fmtBytes(ls.Used), strconv.FormatFloat(ls.Limits.TrafficGB, 'f', -1, 64))
		}
		ov = append(ov, effRow{Label: "Datenlimit", Value: v, Sub: ls.Reason, Tone: statusTone(ls.Status), Link: "#/routing/groups"})
	}
	out.Sections = append(out.Sections, effSection{Key: "overview", Title: "Überblick", Icon: "info", Rows: ov})
	var xr []effRow
	st := c.gstat[id]
	for i, x := range g.Exits {
		row := effRow{Label: fmt.Sprintf("%d.", i+1), Value: c.exitName[x], Link: "#/routing/exits"}
		if st.Active == x {
			row.Sub, row.Tone = "gerade aktiv", "ok"
		}
		xr = append(xr, row)
	}
	out.Sections = append(out.Sections, effSection{Key: "exits", Title: "Ausgänge (Reihenfolge)", Icon: "layers", Rows: xr, Empty: "Keine Ausgänge."})
	var used []effRow
	for _, r := range c.routes {
		if r.Group != id {
			continue
		}
		sc := r.Scope
		if sc != "global" {
			sc = fmt.Sprintf("%s:%d", r.Scope, r.ScopeID)
		}
		t := "alles"
		if !r.All {
			t = plural(len(r.Domains)+len(r.Nets)+len(r.Lists), "Ziel", "Ziele")
		}
		row := effRow{Label: ruleName(r), Value: c.scopeText(sc), Sub: t, Link: "#/routing/rules", Target: strings.Replace(sc, "global", "", 1)}
		if !r.Enabled {
			row.Tone, row.Sub = "muted", "deaktiviert"
		}
		used = append(used, row)
	}
	if objs, err := c.a.St.Objects("smartdns"); err == nil {
		for _, o := range objs {
			p := engine.SmartProfileFrom(o)
			for _, r := range p.Routes {
				if r.Group == id {
					var who []string
					for _, a := range p.Assign {
						who = append(who, c.scopeText(a))
					}
					row := effRow{Label: "SmartDNS " + q(p.Name), Value: listText(who, 3), Sub: listText(r.Domains, 4), Link: "#/dns/smart"}
					if !p.Enabled {
						row.Tone = "muted"
					}
					used = append(used, row)
				}
			}
		}
	}
	for _, s := range c.servers {
		if s.Protocol == "proxy" && engine.ToInt64(s.Settings["group"]) == id {
			used = append(used, effRow{Label: "Proxy-Server " + q(s.Name), Value: "alles", Link: "#/routing/proxy", Target: fmt.Sprintf("server:%d", s.ID)})
		}
	}
	for i := range used {
		if used[i].Target != "" && !strings.Contains(used[i].Target, ":") {
			used[i].Target = ""
		}
	}
	sort.SliceStable(used, func(i, j int) bool { return used[i].Label < used[j].Label })
	out.Sections = append(out.Sections, effSection{Key: "used", Title: "Wer nutzt die Gruppe?", Icon: "route", Rows: used, Empty: "Niemand – keine Regel und kein SmartDNS verweist auf die Gruppe."})
	return out, nil
}

func (c *effCtx) client(id int64) (*effOut, error) {
	o, err := c.a.St.Object("dnsclient", id)
	if err != nil {
		return nil, err
	}
	cl := engine.DNSClientFrom(o)
	out := &effOut{Kind: "client", ID: id, Name: cl.Name, Sub: "Gerät ohne VPN (DNS von außen)"}
	ov := []effRow{{Label: "Zustand", Value: map[bool]string{true: "aktiv", false: "deaktiviert"}[cl.Enabled], Tone: map[bool]string{true: "ok", false: "bad"}[cl.Enabled], Link: "#/dns/external"}}
	if len(cl.Addrs) > 0 {
		ov = append(ov, effRow{Label: "Adressen", Value: listText(cl.Addrs, 5), Link: "#/dns/external"})
	}
	if cl.Token != "" {
		ov = append(ov, effRow{Label: "DoH/DoT", Value: "eigene Adresse vorhanden", Link: "#/dns/external"})
	}
	if cl.Learn {
		ov = append(ov, effRow{Label: "Adresse merken", Value: "ja", Sub: "wer per DoH/DoT fragt, darf 24 h auch normales DNS"})
	}
	if !c.a.E.DNSPublic() {
		ov = append(ov, effRow{Label: "DNS von außen", Value: "aus", Sub: "Port 53 ist von außen nicht erreichbar", Tone: "warn", Link: "#/dns/external"})
	}
	out.Sections = append(out.Sections, effSection{Key: "overview", Title: "Überblick", Icon: "info", Rows: ov})
	var prof *engine.EffProfile
	switch {
	case cl.Profile > 0:
		prof = c.a.E.DNSProfileFor(fmt.Sprintf("id:%d", cl.Profile))
	case cl.Profile == 0:
		prof = c.a.E.DNSProfileFor("global")
	}
	smart := c.a.E.SmartFor(fmt.Sprintf("client:%d", id), "ext", "global")
	rows := c.dnsRows(prof, smart, "")
	if cl.Profile < 0 {
		rows[0] = effRow{Label: "Filterprofil", Value: "ohne Filter", From: "beim Gerät gewählt", Link: "#/dns/external", Tone: "muted"}
	}
	out.Sections = append(out.Sections, effSection{Key: "dns", Title: "DNS", Icon: "globe", Rows: rows,
		Note: "SmartDNS für Geräte ohne VPN: Der DNS antwortet mit der Adresse des Servers, der HTTPS-Verbindungen über die Gruppe weiterreicht."})
	rate, burst := c.a.E.ExtRateOf(cl)
	rr := effRow{Label: "Anfragen über UDP", Link: "#/dns/external"}
	switch {
	case cl.Rate < 0:
		rr.Value, rr.From, rr.Tone = "unbegrenzt", "beim Gerät gesetzt", "warn"
	case rate <= 0:
		rr.Value, rr.From, rr.Tone = "unbegrenzt", "Vorgabe (aus)", "warn"
	default:
		rr.Value = fmt.Sprintf("%s je Sekunde, kurzzeitig %s", strconv.FormatFloat(rate, 'f', -1, 64), strconv.FormatFloat(burst, 'f', -1, 64))
		rr.From = "Vorgabe"
		if cl.Rate > 0 {
			rr.From = "beim Gerät gesetzt"
		}
	}
	out.Sections = append(out.Sections, effSection{Key: "rate", Title: "Schutz vor Missbrauch", Icon: "shield", Rows: []effRow{rr}})
	return out, nil
}

// ---------- Handler ----------

// GET /api/effective → Liste zum Suchen; ?kind=peer|user|server|group|client&id=… → Auswertung.
func (a *API) effective(w http.ResponseWriter, r *http.Request) {
	c, err := a.effCtx()
	if err != nil {
		fail(w, err)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		writeJSON(w, c.targets())
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	var out *effOut
	switch kind {
	case "peer":
		out, err = c.peer(id)
	case "user":
		out, err = c.user(id)
	case "server":
		out, err = c.server(id)
	case "group":
		out, err = c.group(id)
	case "client":
		out, err = c.client(id)
	default:
		errJSON(w, http.StatusBadRequest, "unbekannte Art")
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	for i := range out.Sections {
		if out.Sections[i].Rows == nil {
			out.Sections[i].Rows = []effRow{}
		}
	}
	writeJSON(w, out)
}

func (c *effCtx) targets() []effTarget {
	out := []effTarget{}
	for _, u := range c.snap.Users {
		out = append(out, effTarget{Kind: "user", ID: u.ID, Name: u.Name, Sub: statusText[u.Status], Off: !u.Enabled})
	}
	for _, pb := range c.snap.Peers {
		s := c.servers[pb.Peer.ServerID]
		p := ""
		if s != nil {
			p = s.Protocol
		}
		out = append(out, effTarget{Kind: "peer", ID: pb.Peer.ID, Name: pb.Peer.Name, Sub: pb.User.Name + " · " + c.serverName(pb.Peer.ServerID), Proto: p, Off: !pb.Active || !pb.Peer.Enabled})
	}
	for _, s := range c.servers {
		out = append(out, effTarget{Kind: "server", ID: s.ID, Name: s.Name, Sub: s.Protocol, Proto: s.Protocol, Off: !s.Enabled})
	}
	for _, g := range c.groups {
		out = append(out, effTarget{Kind: "group", ID: g.ID, Name: g.Name, Sub: plural(len(g.Exits), "Ausgang", "Ausgänge"), Off: !g.Enabled})
	}
	if objs, err := c.a.St.Objects("dnsclient"); err == nil {
		for _, o := range objs {
			cl := engine.DNSClientFrom(o)
			out = append(out, effTarget{Kind: "client", ID: cl.ID, Name: cl.Name, Sub: listText(cl.Addrs, 2), Off: !cl.Enabled})
		}
	}
	order := map[string]int{"user": 0, "peer": 1, "server": 2, "group": 3, "client": 4}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return order[out[i].Kind] < order[out[j].Kind]
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}
