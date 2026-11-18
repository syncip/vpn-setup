package exits

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Ausnahmen je Ziel (Block-Prüfung): Sperrt ein Ziel einen Ausgang der Gruppe (Captcha, Sperrseite,
// wiederholte Fehler), läuft dieses Ziel über einen anderen Ausgang der Gruppe. Die Zuordnung Ziel →
// Ausgang legt die Engine fest (SetOverrides); die Adressen der Ziele lernt der Manager aus den
// DNS-Antworten (LearnOverride) und trägt sie in Sets der Tabelle inet vpnexits ein:
//
//	set ov<Gruppe>_<Ausgang> { type ipv4_addr; flags timeout; … }
//	chain g<Gruppe> { ct mark & 0x40000000 == 0 ip daddr @ov1_2 ct mark set … Ausgang 2 … }
//
// Der Proxy wählt den Ausgang selbst (Route) und weicht bei einem Fehlschlag sofort aus.

const ovKeep = time.Hour // so lange bleibt eine gelernte Adresse im Set (wird bei jeder Antwort verlängert)

type ovKey struct{ group, exit int64 }

// SetOverrides ersetzt die Ausnahmen: Gruppe → Domain → Ausgang.
func (m *Manager) SetOverrides(env *Env, ov map[int64]map[string]int64) {
	m.mu.Lock()
	same := fmt.Sprint(sortedOv(ov)) == fmt.Sprint(sortedOv(m.ov))
	m.ov = ov
	for k := range m.ovIPs {
		keep := false
		for _, x := range ov[k.group] {
			keep = keep || x == k.exit
		}
		if !keep {
			delete(m.ovIPs, k)
		}
	}
	m.mu.Unlock()
	if !same {
		m.syncPins(env)
	}
}

func sortedOv(ov map[int64]map[string]int64) []string {
	var out []string
	for g, m := range ov {
		for d, x := range m {
			out = append(out, fmt.Sprintf("%d/%s/%d", g, d, x))
		}
	}
	sort.Strings(out)
	return out
}

// Overrides: aktuelle Ausnahmen (Kopie).
func (m *Manager) Overrides() map[int64]map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]map[string]int64{}
	for g, d := range m.ov {
		out[g] = map[string]int64{}
		for k, v := range d {
			out[g][k] = v
		}
	}
	return out
}

// domainMatch: name gleich domain oder Unterdomain davon.
func domainMatch(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// overrideLocked: Ausgang für ein Ziel einer Gruppe (0 = keine Ausnahme). m.mu gesperrt.
func (m *Manager) overrideLocked(gid int64, name string) (int64, string) {
	best, bestD := int64(0), ""
	for d, x := range m.ov[gid] {
		if domainMatch(name, d) && len(d) > len(bestD) {
			best, bestD = x, d
		}
	}
	return best, bestD
}

// LearnOverride: Adressen einer DNS-Antwort (Verkehr über die Gruppe gid) – gehört der Name zu
// einer Ausnahme, kommen die Adressen in deren Set.
func (m *Manager) LearnOverride(env *Env, gid int64, name string, addrs []netip.Addr) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	m.mu.Lock()
	x, _ := m.overrideLocked(gid, name)
	if x == 0 {
		m.mu.Unlock()
		return
	}
	k := ovKey{gid, x}
	if m.ovIPs[k] == nil {
		m.ovIPs[k] = map[netip.Addr]time.Time{}
	}
	now := m.clock()
	var add []string
	for _, a := range addrs {
		a = a.Unmap()
		if !a.Is4() {
			continue
		}
		if exp, ok := m.ovIPs[k][a]; ok && exp.Sub(now) > ovKeep/2 {
			continue // frisch genug
		}
		m.ovIPs[k][a] = now.Add(ovKeep)
		add = append(add, a.String())
	}
	gs, xs := m.slotOfGroupLocked(gid), m.slotOfExitLocked(x)
	m.mu.Unlock()
	if len(add) == 0 || gs == 0 || xs == 0 {
		return
	}
	// Eintragen (ein bestehender Eintrag wird ersetzt = verlängert). Fehlt das Set (Tabelle wird gerade
	// neu geladen), trägt das Neuladen die Adressen aus ovIPs ein.
	set := fmt.Sprintf("ov%d_%d", gs, xs)
	var b strings.Builder
	fmt.Fprintf(&b, "add element inet %s %s { %s }\n", pinTable, set, strings.Join(withTimeout(add, ovKeep), ", "))
	if _, err := env.Sys.RunInput(b.String(), "nft", "-f", "-"); err != nil {
		var d strings.Builder
		fmt.Fprintf(&d, "delete element inet %s %s { %s }\n", pinTable, set, strings.Join(add, ", "))
		_, _ = env.Sys.RunInput(d.String()+b.String(), "nft", "-f", "-")
	}
}

func withTimeout(addrs []string, d time.Duration) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = fmt.Sprintf("%s timeout %ds", a, int(d.Seconds()))
	}
	return out
}

func (m *Manager) slotOfGroupLocked(gid int64) int {
	for _, g := range m.lastGroups {
		if g.ID == gid {
			return g.Slot
		}
	}
	return 0
}

func (m *Manager) slotOfExitLocked(id int64) int {
	for _, e := range m.lastExits {
		if e.ID == id && e.Enabled {
			return e.Slot
		}
	}
	return 0
}

// ovElementsLocked: gelernte Adressen einer Ausnahme mit Restlaufzeit (für das Neuladen). m.mu gesperrt.
func (m *Manager) ovElementsLocked(k ovKey) []string {
	now := m.clock()
	var out []string
	for a, exp := range m.ovIPs[k] {
		if left := exp.Sub(now); left > 10*time.Second {
			out = append(out, fmt.Sprintf("%s timeout %ds", a, int(left.Seconds())))
		} else {
			delete(m.ovIPs[k], a)
		}
	}
	sort.Strings(out)
	return out
}

// RouteChoice: Ausgang für eine Verbindung (Markierung = Prüf-Markierung des Ausgangs).
type RouteChoice struct {
	Exit int64
	Mark uint32
	Over bool // Ausnahme aus der Block-Prüfung
}

// Route: Ausgänge für eine Verbindung des Proxys zu host über die Gruppe – zuerst der gewählte
// (Ausnahme, sonst aktiver bzw. je Ziel verteilter), dahinter die übrigen gesunden Ausgänge zum
// sofortigen Ausweichen. Leer = die Gruppe hat keinen Ausgang (gesperrt bzw. direkt): dann mit der
// Gruppen-Markierung verbinden.
func (m *Manager) Route(gid int64, host string) []RouteChoice {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routeLocked(gid, host, true)
}

// Natural: Ausgang, über den host ohne Ausnahme liefe (0 = keiner).
func (m *Manager) Natural(gid int64, host string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.routeLocked(gid, host, false); len(r) > 0 {
		return r[0].Exit
	}
	return 0
}

// Usable: nutzbare Ausgänge der Gruppe (verbunden, gesund bzw. aktiv) in ihrer Reihenfolge.
func (m *Manager) Usable(gid int64) []RouteChoice {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routeLocked(gid, "", false)
}

func (m *Manager) routeLocked(gid int64, host string, useOv bool) []RouteChoice {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var g *Group
	for _, x := range m.lastGroups {
		if x.ID == gid {
			g = x
		}
	}
	gs := m.groups[gid]
	if g == nil || gs == nil || !g.Enabled || g.Blocked != "" || gs.Active == 0 {
		return nil
	}
	byID := map[int64]*Exit{}
	for _, e := range m.lastExits {
		byID[e.ID] = e
	}
	usable := func(id int64) bool {
		x := byID[id]
		if x == nil || !x.Enabled || x.Slot < 1 || (x.Standby() && !m.conn[id]) {
			return false
		}
		ok, _ := m.isHealthy(g, x)
		return ok || id == gs.Active
	}
	var out []RouteChoice
	seen := map[int64]bool{}
	add := func(id int64, over bool) {
		if id != 0 && !seen[id] && usable(id) {
			seen[id] = true
			out = append(out, RouteChoice{Exit: id, Mark: probeMark(byID[id].Slot), Over: over})
		}
	}
	if host != "" && useOv {
		if x, _ := m.overrideLocked(gid, host); x != 0 {
			add(x, true)
		}
	}
	if rs := m.rot[gid]; rs != nil && g.Rotate.Mode == "dest" && len(rs.pool) > 0 && host != "" {
		h := fnv.New32a()
		fmt.Fprintf(h, "%d|%s", rs.seed, host)
		add(rs.pool[int(h.Sum32())%len(rs.pool)], false)
	}
	add(gs.Active, false)
	for _, id := range m.order(g) {
		add(id, false)
	}
	return out
}

// ExitName: Name eines Ausgangs (für Meldungen).
func (m *Manager) ExitName(id int64) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.lastExits {
		if e.ID == id {
			return e.Name
		}
	}
	return fmt.Sprintf("Ausgang %d", id)
}

// HasOverrides: hat die Gruppe Ausnahmen? (schnelle Vorprüfung für jede DNS-Antwort)
func (m *Manager) HasOverrides(gid int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ov[gid]) > 0
}
