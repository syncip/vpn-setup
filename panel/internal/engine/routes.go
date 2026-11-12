package engine

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// Ziel-Regeln (Objekte der Art „route“): Verkehr über eine Ausgangsgruppe leiten – alles oder nur
// bestimmte Ziele (Netze, Ziellisten, Domains), global, je Server, je Nutzer oder je Gerät.
//
// Rangfolge: Regeln am Gerät vor denen des Nutzers, vor denen des Servers, vor globalen. Innerhalb
// einer Ebene stehen Ziel-Regeln vor „alles“. Die erste passende Regel gilt; nach einer
// „alles“-Regel wird nicht weiter gesucht.

const (
	maxRouteNets    = 2000
	maxRouteDomains = 1000
)

type Route struct {
	ID      int64
	Name    string
	Enabled bool
	Scope   string // global | server | user | peer
	ScopeID int64
	All     bool
	Nets    []string
	Domains []string
	Lists   []int64
	Group   int64 // 0 = direkt über den Server
}

func ids(v any) []int64 {
	var out []int64
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if f, ok := x.(float64); ok {
				out = append(out, int64(f))
			}
		}
	}
	return out
}

func strs(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func RouteFrom(o *store.Object) *Route {
	r := &Route{ID: o.ID, Name: o.Name, Enabled: o.Enabled}
	r.Scope, _ = o.Data["scope"].(string)
	switch r.Scope {
	case "server", "user", "peer":
	default:
		r.Scope = "global"
	}
	if f, ok := o.Data["scope_id"].(float64); ok {
		r.ScopeID = int64(f)
	}
	if m, _ := o.Data["match"].(string); m != "targets" {
		r.All = true
	}
	r.Nets, r.Domains, r.Lists = strs(o.Data["nets"]), strs(o.Data["domains"]), ids(o.Data["lists"])
	if f, ok := o.Data["group"].(float64); ok {
		r.Group = int64(f)
	}
	return r
}

// ParseRouteNets: IPv4-Adressen und -Netze (eine pro Zeile bzw. durch Komma getrennt).
func ParseRouteNets(text string) ([]string, error) {
	list, err := ParseIPEntries(text)
	if err != nil {
		return nil, err
	}
	for _, s := range list {
		if !netip.MustParsePrefix(s).Addr().Is4() {
			return nil, fmt.Errorf("„%s“: Ausgänge können nur IPv4 – bitte nur IPv4-Netze eintragen", s)
		}
	}
	if len(list) > maxRouteNets {
		return nil, fmt.Errorf("höchstens %d Netze pro Regel (für mehr eine Zielliste anlegen)", maxRouteNets)
	}
	return list, nil
}

var domainRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$`)

// ParseRouteDomains: Domains (eine pro Zeile bzw. durch Komma/Leerzeichen getrennt). „*.“ und
// führende Punkte fallen weg – Unterdomains sind immer eingeschlossen. Auch ganze Adressen
// (https://www.beispiel.de/seite) werden auf den Namen gekürzt.
func ParseRouteDomains(text string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' || r == '\r' }) {
			d := strings.ToLower(f)
			if i := strings.Index(d, "://"); i >= 0 {
				d = d[i+3:]
			}
			if i := strings.IndexAny(d, "/?"); i >= 0 {
				d = d[:i]
			}
			d = strings.TrimPrefix(d, "*.")
			d = strings.Trim(d, ".")
			if i := strings.LastIndexByte(d, ':'); i >= 0 {
				d = d[:i]
			}
			if !domainRe.MatchString(d) || len(d) > 253 {
				return nil, fmt.Errorf("„%s“ ist kein gültiger Domainname (Beispiel: netflix.com)", f)
			}
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	if len(out) > maxRouteDomains {
		return nil, fmt.Errorf("höchstens %d Domains pro Regel", maxRouteDomains)
	}
	sort.Strings(out)
	return out, nil
}

// routing: Ergebnis der Auswertung aller Regeln für den aktuellen Stand.
type routing struct {
	Policies       map[int64]*proto.Policy // je Zugang
	ServerPolicies map[int64]*proto.Policy // je Server (nur Server- und globale Regeln)
	TargetLists    map[int64][]netip.Prefix
	ByKey          map[string]*proto.Policy
	Groups         map[int64]proto.GroupRoute
	Skipped        map[int64]string // Regel-ID → warum sie nicht wirkt
	Net            *proto.NetAccess // Zugriff auf andere Netze (Netzwerk → Zugriff)
	Private        *proto.PrivateGuard
}

type routeState struct {
	mu  sync.Mutex
	cur *routing
}

func (e *Engine) routing() *routing {
	e.rt.mu.Lock()
	defer e.rt.mu.Unlock()
	if e.rt.cur == nil {
		return &routing{}
	}
	return e.rt.cur
}

// RouteNotes: Hinweise zu Regeln, die gerade nicht wirken (für die Oberfläche).
func (e *Engine) RouteNotes() map[int64]string { return e.routing().Skipped }

// compileRoutes stellt die Regelfolgen aller Zugänge zusammen.
func (e *Engine) compileRoutes(snap *Snapshot) *routing {
	rt := &routing{Policies: map[int64]*proto.Policy{}, ServerPolicies: map[int64]*proto.Policy{}, TargetLists: map[int64][]netip.Prefix{},
		ByKey: map[string]*proto.Policy{}, Skipped: map[int64]string{}}
	objs, _ := e.St.Objects("route")
	groups := e.groupRoutes()
	rt.Groups = groups
	lists := map[int64]*IPList{}
	if lo, err := e.St.Objects("iplist"); err == nil {
		for _, o := range lo {
			if l := IPListFrom(o); l.Enabled && l.Mode == "targets" {
				lists[l.ID] = l
			}
		}
	}
	type entry struct {
		key  string
		rule proto.RouteRule
	}
	byScope := map[string][]entry{} // "global", "server:3", "user:5", "peer:9"
	add := func(scope string, en entry) { byScope[scope] = append(byScope[scope], en) }
	for _, o := range objs {
		r := RouteFrom(o)
		if !r.Enabled {
			continue
		}
		if r.Group != 0 {
			if g, ok := groups[r.Group]; !ok {
				rt.Skipped[r.ID] = "Ausgangsgruppe gibt es nicht mehr"
				continue
			} else if !g.Enabled {
				rt.Skipped[r.ID] = "Ausgangsgruppe „" + g.Name + "“ ist deaktiviert"
				continue
			}
		}
		rule := proto.RouteRule{ID: r.ID, All: r.All, Group: r.Group}
		if !r.All {
			for _, s := range r.Nets {
				if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
					rule.Nets = append(rule.Nets, p)
				}
			}
			rule.Domains = r.Domains
			for _, id := range r.Lists {
				if l := lists[id]; l != nil {
					rule.Lists = append(rule.Lists, id)
					if _, ok := rt.TargetLists[id]; !ok {
						v4, _ := e.listPrefixes(l)
						rt.TargetLists[id] = v4
					}
				}
			}
			if len(rule.Nets) == 0 && len(rule.Domains) == 0 && len(rule.Lists) == 0 {
				rt.Skipped[r.ID] = "keine Ziele (Liste leer oder deaktiviert)"
				continue
			}
		}
		scope := r.Scope
		if scope != "global" {
			scope = fmt.Sprintf("%s:%d", r.Scope, r.ScopeID)
		}
		add(scope, entry{fmt.Sprintf("r%d", r.ID), rule})
	}
	// Proxy-Server haben die Gruppe als Server-Einstellung („Ausgang“) – wirkt wie eine „alles“-Regel am Server.
	for _, sb := range snap.Servers {
		if sb.Server.Protocol != "proxy" {
			continue
		}
		gid := int64(0)
		switch v := sb.Server.Settings["group"].(type) {
		case float64:
			gid = int64(v)
		case string:
			fmt.Sscan(v, &gid)
		}
		if g, ok := groups[gid]; gid != 0 && ok && g.Enabled {
			add(fmt.Sprintf("server:%d", sb.Server.ID), entry{fmt.Sprintf("sg%d-%d", sb.Server.ID, gid), proto.RouteRule{All: true, Group: gid}})
		}
	}
	for k := range byScope { // Ziel-Regeln vor „alles“, sonst nach ID
		es := byScope[k]
		sort.SliceStable(es, func(i, j int) bool {
			if es[i].rule.All != es[j].rule.All {
				return !es[i].rule.All
			}
			return es[i].rule.ID < es[j].rule.ID
		})
	}
	build := func(scopes ...string) *proto.Policy {
		var keys []string
		var rules []proto.RouteRule
	outer:
		for _, s := range scopes {
			for _, en := range byScope[s] {
				keys = append(keys, en.key)
				rules = append(rules, en.rule)
				if en.rule.All {
					break outer
				}
			}
		}
		// Am Ende stehende „direkt“-Regeln ändern nichts
		for len(rules) > 0 && rules[len(rules)-1].Group == 0 {
			rules, keys = rules[:len(rules)-1], keys[:len(keys)-1]
		}
		if len(rules) == 0 {
			return nil
		}
		key := hashStr(strings.Join(keys, ","))
		if p := rt.ByKey[key]; p != nil {
			return p
		}
		p := &proto.Policy{Key: key, Rules: rules}
		rt.ByKey[key] = p
		return p
	}
	for _, sb := range snap.Servers {
		if !sb.Server.Enabled {
			continue
		}
		srv := fmt.Sprintf("server:%d", sb.Server.ID)
		if p := build(srv, "global"); p != nil {
			rt.ServerPolicies[sb.Server.ID] = p
		}
		for _, pb := range sb.Peers {
			if !pb.Active {
				continue
			}
			if p := build(fmt.Sprintf("peer:%d", pb.Peer.ID), fmt.Sprintf("user:%d", pb.User.ID), srv, "global"); p != nil {
				rt.Policies[pb.Peer.ID] = p
			}
		}
	}
	rt.Net = e.compileNetAccess(snap)
	rt.Private = e.privateGuard()
	e.rt.mu.Lock()
	e.rt.cur = rt
	e.rt.mu.Unlock()
	return rt
}

// pruneRoutes löscht Regeln, deren Server, Nutzer oder Gerät es nicht mehr gibt.
func (e *Engine) pruneRoutes(snap *Snapshot) {
	objs, _ := e.St.Objects("route")
	if len(objs) == 0 {
		return
	}
	servers, _ := e.St.Servers()
	hasServer := map[int64]bool{}
	for _, s := range servers {
		hasServer[s.ID] = true
	}
	for _, o := range objs {
		r := RouteFrom(o)
		gone := (r.Scope == "server" && !hasServer[r.ScopeID]) || (r.Scope == "user" && snap.Users[r.ScopeID] == nil) || (r.Scope == "peer" && snap.Peers[r.ScopeID] == nil)
		if gone {
			_ = e.St.DeleteObject("route", o.ID)
			e.Log("info", fmt.Sprintf("Ziel-Regel „%s“ entfernt (Server, Nutzer oder Gerät gibt es nicht mehr)", routeLabel(r)))
		}
	}
}

func routeLabel(r *Route) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("#%d", r.ID)
}

// RoutesUsing: Regeln, die eine Gruppe (kind "group") oder Zielliste (kind "iplist") verwenden.
func (e *Engine) RoutesUsing(kind string, id int64) []*Route {
	objs, _ := e.St.Objects("route")
	var out []*Route
	for _, o := range objs {
		r := RouteFrom(o)
		if kind == "group" && r.Group == id {
			out = append(out, r)
		}
		if kind == "iplist" {
			for _, l := range r.Lists {
				if l == id {
					out = append(out, r)
					break
				}
			}
		}
	}
	return out
}
