package api

import (
	"fmt"
	"net/http"
	"sort"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/wireguard"
	"vpnpanel/internal/store"
)

// Netzwerk-Übersicht: wer hängt an welchem Server, worüber geht der Verkehr hinaus und wo hakt es.

// viaOut: Weg eines Zugangs nach außen laut Ziel-Regeln.
type viaOut struct {
	All     int64   `json:"all"`     // Gruppe für „alles“; 0 = direkt über den Server
	Partial []int64 `json:"partial"` // Gruppen, über die nur bestimmte Ziele laufen
	Rules   []int64 `json:"rules"`   // wirksame Regeln in ihrer Reihenfolge
	// Scope: Ebene der Regel, die „alles“ bestimmt (peer | user | server | global), "" = keine
	Scope string `json:"scope"`
}

type issue struct {
	Level string `json:"level"` // bad | warn
	Kind  string `json:"kind"`  // server | group | exit | route | user | list | system
	ID    int64  `json:"id,omitempty"`
	Text  string `json:"text"`
	Link  string `json:"link,omitempty"`
}

func viaOf(p *proto.Policy, scopes map[int64]string) viaOut {
	v := viaOut{Partial: []int64{}, Rules: []int64{}}
	if p == nil {
		return v
	}
	seen := map[int64]bool{}
	for _, r := range p.Rules {
		v.Rules = append(v.Rules, r.ID)
		if r.All {
			v.All, v.Scope = r.Group, scopes[r.ID]
			if r.ID == 0 {
				v.Scope = "server" // Einstellung „Ausgang“ des Proxy-Servers
			}
			break
		}
		if r.Group != 0 && !seen[r.Group] {
			seen[r.Group] = true
			v.Partial = append(v.Partial, r.Group)
		}
	}
	return v
}

func (a *API) topology(w http.ResponseWriter, r *http.Request) {
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	g := a.E.Global()
	scopes := map[int64]string{}
	routeName := map[int64]string{}
	if objs, err := a.St.Objects("route"); err == nil {
		for _, o := range objs {
			rt := engine.RouteFrom(o)
			scopes[rt.ID] = rt.Scope
			routeName[rt.ID] = rt.Name
		}
	}
	type peerOut struct {
		ID       int64   `json:"id"`
		Name     string  `json:"name"`
		Kind     string  `json:"kind"`
		UserID   int64   `json:"user_id"`
		ServerID int64   `json:"server_id"`
		Protocol string  `json:"protocol"`
		Enabled  bool    `json:"enabled"`
		Active   bool    `json:"active"`
		Online   bool    `json:"online"`
		LastSeen int64   `json:"last_seen"`
		Address  string  `json:"address,omitempty"`
		Via      viaOut  `json:"via"`
		Reach    []int64 `json:"reach,omitempty"` // WireGuard: Geräte, die dieses Gerät erreichen darf
	}
	type userOut struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Reason string `json:"reason,omitempty"`
	}
	peers := []peerOut{}
	serverVia := map[int64]viaOut{}
	for _, sb := range snap.Servers {
		serverVia[sb.Server.ID] = viaOf(g.ServerPolicies[sb.Server.ID], scopes)
		var reach map[int64][]int64
		if sb.Server.Protocol == "wireguard" {
			reach = wireguard.Reachable(sb)
		}
		for _, pb := range sb.Peers {
			pol := g.Policies[pb.Peer.ID]
			if sb.Server.Protocol == "hysteria2" { // kann Nutzer nicht einzeln leiten
				pol = g.ServerPolicies[sb.Server.ID]
			}
			peers = append(peers, peerOut{ID: pb.Peer.ID, Name: pb.Peer.Name, Kind: pb.Peer.Kind, UserID: pb.Peer.UserID, ServerID: sb.Server.ID,
				Protocol: sb.Server.Protocol, Enabled: pb.Peer.Enabled, Active: pb.Active, Online: peerOn(pb.Peer), LastSeen: pb.Peer.LastSeen,
				Address: proto.Str(pb.Peer.Settings, "address4"), Via: viaOf(pol, scopes), Reach: reach[pb.Peer.ID]})
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	users := []userOut{}
	var issues []issue
	for _, u := range snap.Users {
		users = append(users, userOut{ID: u.ID, Name: u.Name, Status: u.Status, Reason: u.StatusReason})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })

	// ---------- Wo hakt es? ----------
	errs := a.E.Errors()
	label := map[string]string{"exits": "Ausgänge", "acl": "Firewall (IP-Listen, Ziel-Regeln)", "dns": "DNS-Umleiter", "shaping": "Geschwindigkeitsbegrenzung", "nginx": "nginx"}
	var keys []string
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := a.E.Env()
	for _, sb := range snap.Servers {
		sv := sb.Server
		if !sv.Enabled {
			continue
		}
		d, ok := proto.Get(sv.Protocol)
		if !ok {
			continue
		}
		if st := d.Status(env, sv); !st.Running {
			issues = append(issues, issue{"bad", "server", sv.ID, fmt.Sprintf("Server „%s“ läuft nicht: %s", sv.Name, st.Detail), "#/servers"})
		}
	}
	for _, k := range keys {
		name := label[k]
		if d, ok := proto.Get(k); ok {
			name = d.Info().Label
		}
		if name == "" {
			name = k
		}
		issues = append(issues, issue{Level: "bad", Kind: "system", Text: name + ": " + errs[k]})
	}
	es, gs := a.E.Exits.Status()
	exitName := map[int64]string{}
	if eo, err := a.St.Objects("exit"); err == nil {
		for _, o := range eo {
			exitName[o.ID] = o.Name
			st, ok := es[o.ID]
			if !o.Enabled || !ok || st.Checked == 0 {
				continue
			}
			switch {
			case !st.Up || st.Error != "":
				msg := st.Error
				if msg == "" {
					msg = "nicht verbunden"
				}
				issues = append(issues, issue{"bad", "exit", o.ID, fmt.Sprintf("Ausgang „%s“: %s", o.Name, msg), "#/proxy"})
			case st.Loss > 20:
				issues = append(issues, issue{"warn", "exit", o.ID, fmt.Sprintf("Ausgang „%s“: %.0f %% Paketverlust", o.Name, st.Loss), "#/proxy"})
			}
		}
	}
	if gro, err := a.St.Objects("group"); err == nil {
		for _, o := range gro {
			st, ok := gs[o.ID]
			if !o.Enabled || !ok {
				continue
			}
			switch st.State {
			case "blocked":
				issues = append(issues, issue{"bad", "group", o.ID, fmt.Sprintf("Gruppe „%s“: alle Ausgänge gestört – Verkehr ist gesperrt", o.Name), "#/proxy"})
			case "direct":
				issues = append(issues, issue{"warn", "group", o.ID, fmt.Sprintf("Gruppe „%s“: alle Ausgänge gestört – Verkehr geht direkt über den Server", o.Name), "#/proxy"})
			case "failover":
				issues = append(issues, issue{"warn", "group", o.ID, fmt.Sprintf("Gruppe „%s“ nutzt den Ausweich-Ausgang „%s“ (%s)", o.Name, exitName[st.Active], st.Reason), "#/proxy"})
			}
		}
	}
	notes := a.E.RouteNotes()
	var nids []int64
	for id := range notes {
		nids = append(nids, id)
	}
	sort.Slice(nids, func(i, j int) bool { return nids[i] < nids[j] })
	for _, id := range nids {
		n := routeName[id]
		if n == "" {
			n = fmt.Sprintf("#%d", id)
		}
		issues = append(issues, issue{"warn", "route", id, fmt.Sprintf("Ziel-Regel „%s“ wirkt nicht: %s", n, notes[id]), "#/proxy"})
	}
	if lo, err := a.St.Objects("iplist"); err == nil {
		for _, o := range lo {
			if l := engine.IPListFrom(o); l.Enabled && l.URL != "" {
				if st := a.E.ListStatus(o.ID); st.Error != "" {
					issues = append(issues, issue{"warn", "list", o.ID, fmt.Sprintf("IP-Liste „%s“: Abruf fehlgeschlagen – %s", o.Name, st.Error), "#/iplists"})
				}
			}
		}
	}
	for _, u := range users {
		switch u.Status {
		case "blocked", "expired":
			issues = append(issues, issue{"warn", "user", u.ID, fmt.Sprintf("Nutzer „%s“ ist %s%s", u.Name, map[string]string{"blocked": "gesperrt", "expired": "abgelaufen"}[u.Status], because(u.Reason)), fmt.Sprintf("#/users/%d", u.ID)})
		case "throttled":
			issues = append(issues, issue{"warn", "user", u.ID, fmt.Sprintf("Nutzer „%s“ ist gedrosselt%s", u.Name, because(u.Reason)), fmt.Sprintf("#/users/%d", u.ID)})
		}
	}
	if issues == nil {
		issues = []issue{}
	}
	writeJSON(w, map[string]any{"peers": peers, "users": users, "server_via": serverVia, "issues": issues})
}

func because(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

// assignRoute: Ausgang per Drag & Drop zuweisen – der ganze Verkehr eines Geräts, Nutzers oder
// Servers (bzw. aller) läuft über die Gruppe; group 0 = direkt über den Server. Ersetzt die
// bisherige „alles“-Regel dieser Ebene; Ziel-Regeln bleiben unberührt.
func (a *API) assignRoute(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scope   string `json:"scope"`
		ScopeID int64  `json:"scope_id"`
		Group   int64  `json:"group"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	var name string
	servers := map[int64]bool{} // Server, auf denen die Ebene Zugänge hat (für geerbte Regeln)
	switch in.Scope {
	case "global":
		in.ScopeID, name = 0, "alle"
	case "server":
		sv, err := a.St.Server(in.ScopeID)
		if err != nil {
			errJSON(w, http.StatusBadRequest, "Server gibt es nicht")
			return
		}
		name = "Server " + sv.Name
	case "user":
		u := snap.Users[in.ScopeID]
		if u == nil {
			errJSON(w, http.StatusBadRequest, "Nutzer gibt es nicht")
			return
		}
		name = "Nutzer " + u.Name
		for _, pb := range snap.Peers {
			if pb.Peer.UserID == u.ID {
				servers[pb.Peer.ServerID] = true
			}
		}
	case "peer":
		pb := snap.Peers[in.ScopeID]
		if pb == nil {
			errJSON(w, http.StatusBadRequest, "Gerät gibt es nicht")
			return
		}
		name = "Gerät " + pb.Peer.Name
		servers[pb.Peer.ServerID] = true
		if sv, err := a.St.Server(pb.Peer.ServerID); err == nil && sv.Protocol == "hysteria2" {
			errJSON(w, http.StatusBadRequest, "Hysteria2 kann Geräte nicht einzeln leiten – bitte den Server auf die Gruppe ziehen")
			return
		}
	default:
		errJSON(w, http.StatusBadRequest, "Gilt für: global, Server, Nutzer oder Gerät")
		return
	}
	target := "direkt über den Server"
	if in.Group != 0 {
		o, err := a.St.Object("group", in.Group)
		if err != nil {
			errJSON(w, http.StatusBadRequest, "Ausgangsgruppe gibt es nicht")
			return
		}
		target = "Gruppe " + o.Name
	}
	objs, err := a.St.Objects("route")
	if err != nil {
		fail(w, err)
		return
	}
	// Bisherige „alles“-Regel(n) dieser Ebene entfernen; prüfen, ob eine weiter gefasste Regel erbt
	inherited := false
	userOf := int64(0)
	if in.Scope == "peer" {
		userOf = snap.Peers[in.ScopeID].Peer.UserID
	}
	for _, o := range objs {
		rt := engine.RouteFrom(o)
		if !rt.All {
			continue
		}
		if rt.Scope == in.Scope && rt.ScopeID == in.ScopeID {
			if err := a.St.DeleteObject("route", o.ID); err != nil {
				fail(w, err)
				return
			}
			continue
		}
		if !rt.Enabled || rt.Group == 0 {
			continue
		}
		switch {
		case rt.Scope == "global" && in.Scope != "global",
			rt.Scope == "server" && servers[rt.ScopeID],
			rt.Scope == "user" && rt.ScopeID == userOf && userOf != 0:
			inherited = true
		}
	}
	// Proxy-Server: die Einstellung „Ausgang“ wirkt wie eine „alles“-Regel am Server
	for id := range servers {
		if sv, err := a.St.Server(id); err == nil && sv.Protocol == "proxy" {
			if f, ok := sv.Settings["group"].(float64); ok && f != 0 {
				inherited = true
			}
		}
	}
	if in.Group != 0 || inherited {
		o := &store.Object{Kind: "route", Enabled: true, Secrets: store.M{},
			Data: store.M{"scope": in.Scope, "scope_id": in.ScopeID, "match": "all", "group": in.Group}}
		if err := a.St.SaveObject(o); err != nil {
			fail(w, err)
			return
		}
	}
	a.E.Log("info", fmt.Sprintf("Ausgang zugewiesen: %s → %s", name, target))
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// setReach: Zugriff zwischen zwei WireGuard-Geräten per Drag & Drop – Gerät {id} darf target
// erreichen (allow) oder nicht mehr. Der bisherige Zugriff wird als feste Auswahl übernommen.
func (a *API) setReach(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target int64 `json:"target"`
		Allow  bool  `json:"allow"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	id := pathID(r)
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	from, to := snap.Peers[id], snap.Peers[in.Target]
	if from == nil || to == nil || id == in.Target {
		errJSON(w, http.StatusBadRequest, "Gerät gibt es nicht")
		return
	}
	if from.Peer.ServerID != to.Peer.ServerID {
		errJSON(w, http.StatusBadRequest, "Zugriff untereinander geht nur zwischen Geräten desselben WireGuard-Servers")
		return
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID != from.Peer.ServerID {
			continue
		}
		if sb.Server.Protocol != "wireguard" {
			errJSON(w, http.StatusBadRequest, "Zugriff untereinander gibt es nur bei WireGuard")
			return
		}
		list := []int64{}
		for _, x := range wireguard.Reachable(sb)[id] {
			if x != in.Target {
				list = append(list, x)
			}
		}
		if in.Allow {
			list = append(list, in.Target)
		}
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		p := from.Peer
		p.Settings["access"], p.Settings["access_peers"] = "custom", list
		if err := a.E.InitPeer(sb.Server, p); err != nil {
			fail(w, err)
			return
		}
		if err := a.St.SavePeer(p); err != nil {
			fail(w, err)
			return
		}
		verb := "darf jetzt"
		if !in.Allow {
			verb = "darf nicht mehr"
		}
		a.E.Log("info", fmt.Sprintf("Zugriff: %s %s auf %s zugreifen", p.Name, verb, to.Peer.Name))
		a.E.RequestApply()
		writeJSON(w, map[string]any{"ok": true, "reach": list})
		return
	}
	fail(w, store.ErrNotFound)
}
