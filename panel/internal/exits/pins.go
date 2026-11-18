package exits

import (
	"fmt"
	"sort"
	"strings"
)

// Weicher Wechsel: Jede Verbindung über eine Gruppe merkt sich bei ihrem Aufbau den Ausgang
// (conntrack-Markierung, Bits 0x7f000000 = Prüf-Markierung des Ausgangs). Alle weiteren Pakete der
// Verbindung laufen über genau diesen Ausgang (seine Prüf-Tabelle), auch wenn die Gruppe inzwischen
// umgeschaltet hat – laufende Downloads, Anrufe und Anmeldungen bleiben bestehen. Neue Verbindungen
// nehmen den aktuellen Ausgang der Gruppe bzw. bei „je Ziel“ einen nach der Zieladresse gewählten.
//
// Eigene Tabelle inet vpnexits (getrennt von inet vpnpanel, damit ein Wechsel nur sie neu lädt):
//   - prerouting, Priorität -140: nach vp_pre (mangle, -150), das weitergeleitete Pakete der Geräte
//     mit der Gruppen-Markierung versieht
//   - output (route), Priorität -160: Dienste auf dem Server (Proxy, Xray, DNS) – vor der Kette VPNVL
//     (iptables mangle/OUTPUT, -150), die die Paket-Markierung in die Verbindung schreibt
//
// Gruppen ohne Ausgang (gesperrt oder „direkt“) stehen nicht in der Verteilung: Ihre Pakete behalten
// die Gruppen-Markierung und folgen der Gruppen-Tabelle (Sperre bzw. direkter Weg).

const (
	pinTable = "vpnexits"
	pinBit   = 0x40000000 // gesetzt = Verbindung hat ihren Ausgang (Prüf-Markierungen haben dieses Bit)
	keepMask = 0x80ffffff // alles außer den Bits für Gruppe/Ausgang bleibt erhalten (z. B. Drosselung)
)

// pinGroup: wohin neue Verbindungen einer Gruppe gehen.
type pinGroup struct {
	Slot  int
	Exits []int // Plätze der Ausgänge: einer = ganze Gruppe, mehrere = je Ziel verteilt
	Seed  uint32
}

// pinScript erzeugt die Tabelle. exits = Plätze aller eingeschalteten Ausgänge (für bestehende
// Verbindungen), groups = Verteilung je Gruppe. Leer, wenn es keine Ausgänge gibt.
func pinScript(exits []int, groups []pinGroup) string {
	if len(exits) == 0 {
		return ""
	}
	exits = append([]int(nil), exits...)
	sort.Ints(exits)
	sort.Slice(groups, func(i, j int) bool { return groups[i].Slot < groups[j].Slot })
	has := map[int]bool{}
	for _, s := range exits {
		has[s] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", pinTable, pinTable, pinTable)
	var entries []string
	for _, g := range groups {
		ok := false
		for _, s := range g.Exits {
			ok = ok || has[s]
		}
		if ok {
			entries = append(entries, fmt.Sprintf("0x%08x : jump g%d", GroupMark(g.Slot), g.Slot))
		}
	}
	b.WriteString("\tchain pin {\n")
	fmt.Fprintf(&b, "\t\tmeta mark & 0x%08x == 0x0 return\n", MarkMask)
	fmt.Fprintf(&b, "\t\tmeta mark & 0x%08x != 0x0 return\n", pinBit)
	if len(entries) > 0 {
		fmt.Fprintf(&b, "\t\tmeta mark & 0x%08x vmap { %s }\n", MarkMask, strings.Join(entries, ", "))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain pre {\n\t\ttype filter hook prerouting priority -140; policy accept;\n\t\tjump pin\n\t}\n")
	b.WriteString("\tchain out {\n\t\ttype route hook output priority -160; policy accept;\n\t\tjump pin\n\t}\n")
	var restore []string
	for _, s := range exits {
		restore = append(restore, fmt.Sprintf("0x%08x : jump x%d", probeMark(s), s))
	}
	usedSet := map[int]bool{}
	for _, g := range groups {
		var ex []int
		for _, s := range g.Exits {
			if has[s] {
				ex = append(ex, s)
			}
		}
		if len(ex) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\tchain g%d {\n", g.Slot)
		if len(ex) == 1 {
			fmt.Fprintf(&b, "\t\tct mark & 0x%08x == 0x0 ct mark set ct mark & 0x%08x | 0x%08x\n", pinBit, keepMask, probeMark(ex[0]))
		} else {
			var m []string
			for i, s := range ex {
				m = append(m, fmt.Sprintf("%d : jump s%d", i, s))
				usedSet[s] = true
			}
			fmt.Fprintf(&b, "\t\tct mark & 0x%08x == 0x0 jhash ip daddr mod %d seed 0x%08x vmap { %s }\n", pinBit, len(ex), g.Seed, strings.Join(m, ", "))
		}
		fmt.Fprintf(&b, "\t\tct mark & 0x%08x vmap { %s }\n", MarkMask, strings.Join(restore, ", "))
		b.WriteString("\t}\n")
	}
	for _, s := range exits {
		if usedSet[s] {
			fmt.Fprintf(&b, "\tchain s%d {\n\t\tct mark set ct mark & 0x%08x | 0x%08x\n\t}\n", s, keepMask, probeMark(s))
		}
		fmt.Fprintf(&b, "\tchain x%d {\n\t\tmeta mark set meta mark & 0x%08x | 0x%08x\n\t}\n", s, keepMask, probeMark(s))
	}
	b.WriteString("}\n")
	return b.String()
}

// syncPins lädt die Tabelle neu, wenn sich die Verteilung geändert hat (oder die Tabelle fehlt).
// Wird bei jedem Umschalten VOR dem Ersetzen der Gruppen-Route aufgerufen.
func (m *Manager) syncPins(env *Env) {
	m.mu.Lock()
	exits, groups := m.lastExits, m.lastGroups
	var slots []int
	byID := map[int64]*Exit{}
	for _, e := range exits {
		byID[e.ID] = e
		if e.Enabled && e.Slot > 0 {
			slots = append(slots, e.Slot)
		}
	}
	var pg []pinGroup
	for _, g := range groups {
		if !g.Enabled || g.Slot < 1 || g.Blocked != "" {
			continue
		}
		gs := m.groups[g.ID]
		if gs == nil {
			continue
		}
		p := pinGroup{Slot: g.Slot}
		if rs := m.rot[g.ID]; rs != nil && g.Rotate.Mode == "dest" && len(rs.pool) > 0 {
			for _, id := range rs.pool {
				if x := byID[id]; x != nil && x.Enabled && x.Slot > 0 {
					p.Exits = append(p.Exits, x.Slot)
				}
			}
			p.Seed = rs.seed
		}
		if len(p.Exits) == 0 && gs.Active != 0 {
			if x := byID[gs.Active]; x != nil && x.Slot > 0 {
				p.Exits = []int{x.Slot}
			}
		}
		if len(p.Exits) > 0 {
			pg = append(pg, p)
		}
	}
	m.mu.Unlock()
	script := pinScript(slots, pg)
	sys := env.Sys
	const key = "exits:pins"
	if script == "" {
		if env.Get(key) != "" {
			_, _ = sys.Run("nft", "delete", "table", "inet", pinTable)
			env.Set(key, "")
		}
		return
	}
	sig := hash(script)
	if env.Get(key) == sig {
		if _, err := sys.Run("nft", "-t", "list", "table", "inet", pinTable); err == nil {
			return
		}
	}
	if out, err := sys.RunInput(script, "nft", "-f", "-"); err != nil {
		msg := strings.TrimSpace(out)
		if len(msg) > 300 {
			msg = msg[:300] + " …"
		}
		env.Log("error", "Ausgänge: Verbindungs-Zuordnung (nftables) fehlgeschlagen: "+err.Error()+" "+msg)
		return
	}
	env.Set(key, sig)
}
