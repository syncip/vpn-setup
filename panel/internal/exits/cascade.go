package exits

import (
	"fmt"
	"strconv"
	"strings"
)

// Kaskade: Ein Ausgang kann über einen anderen Ausgang verbunden sein (z. B. Server → WARP →
// Windscribe). Dazu bekommen die verschlüsselten Tunnelpakete des Ausgangs die Prüf-Markierung
// seines Vorgängers (WireGuard: FwMark, OpenVPN: mark) – sie laufen damit über dessen Tabelle
// 2000+Platz hinaus, mit dessen Kill-Switch (Sperr-Route), nie direkt. Der Anbieter am Ende sieht
// nur die Adresse des Vorgängers, der Vorgänger nur verschlüsselten Verkehr zum nächsten Anbieter.

const (
	maxCascade  = 3  // höchstens so viele Ausgänge hintereinander
	cascadeLoss = 80 // MTU-Abzug je Stufe (WireGuard über WireGuard bzw. OpenVPN)
	ovpnMTU     = 1500
)

// CheckVia prüft die Kette eines Ausgangs (id) über via. vias: Ausgang → Vorgänger aller Ausgänge.
// Fehlertext oder "".
func CheckVia(id, via int64, vias map[int64]int64, exists func(int64) bool) string {
	if via == 0 {
		return ""
	}
	if via == id {
		return "Ein Ausgang kann nicht über sich selbst laufen"
	}
	if !exists(via) {
		return "Vorgänger-Ausgang gibt es nicht"
	}
	seen := map[int64]bool{id: true}
	depth := 1
	for cur := via; cur != 0; cur = vias[cur] {
		if seen[cur] {
			return "Die Kette der Ausgänge darf keinen Kreis bilden"
		}
		seen[cur] = true
		depth++
		if depth > maxCascade {
			return fmt.Sprintf("Höchstens %d Ausgänge hintereinander", maxCascade)
		}
	}
	// auch Ausgänge, die über diesen laufen, zählen zur Länge
	var below func(x int64) int
	below = func(x int64) int {
		n := 0
		for k, v := range vias {
			if v == x && k != id {
				if d := 1 + below(k); d > n {
					n = d
				}
			}
		}
		return n
	}
	if depth+below(id) > maxCascade {
		return fmt.Sprintf("Höchstens %d Ausgänge hintereinander", maxCascade)
	}
	return ""
}

// chainLocked: Vorgänger eines Ausgangs der Reihe nach (nächster zuerst). m.mu gesperrt.
func (m *Manager) chainLocked(e *Exit) []*Exit {
	byID := map[int64]*Exit{}
	for _, x := range m.lastExits {
		byID[x.ID] = x
	}
	var out []*Exit
	seen := map[int64]bool{e.ID: true}
	for cur := byID[e.ID]; cur != nil && cur.Via != 0 && len(out) < maxCascade; {
		v := byID[cur.Via]
		if v == nil || seen[v.ID] {
			break
		}
		seen[v.ID] = true
		out = append(out, v)
		cur = v
	}
	return out
}

// viaMark: Markierung für die Tunnelpakete eines Ausgangs (0 = direkt über den Server). Fehlt der
// Vorgänger oder ist er abgeschaltet, gibt es einen Fehler – der Ausgang wird dann nicht verbunden,
// denn ohne Regel für die Markierung ginge sein Tunnel direkt hinaus.
func (m *Manager) viaMark(e *Exit) (uint32, error) {
	if e.Via == 0 {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.lastExits {
		if x.ID == e.Via {
			if !x.Enabled || x.Slot < 1 || x.Blocked != "" {
				return 0, fmt.Errorf("Vorgänger „%s“ ist abgeschaltet", x.Name)
			}
			return probeMark(x.Slot), nil
		}
	}
	return 0, fmt.Errorf("Vorgänger-Ausgang fehlt")
}

// ensureViaPath: Regel und Sperr-Route für die Markierung des Vorgängers sicherstellen, bevor der
// Tunnel hochfährt. Beim ersten Einrichten legt Apply die Regeln erst nach den Schnittstellen an –
// WireGuard handelt aber sofort aus (Keepalive); ohne Regel ginge der Handshake direkt hinaus.
func (m *Manager) ensureViaPath(env *Env, e *Exit) {
	m.mu.Lock()
	var slot int
	for _, x := range m.lastExits {
		if x.ID == e.Via {
			slot = x.Slot
		}
	}
	m.mu.Unlock()
	if slot < 1 {
		return
	}
	sys := env.Sys
	t := strconv.Itoa(probeTable + slot)
	_, _ = sys.Run("ip", "-4", "route", "replace", "blackhole", "default", "metric", safetyMetric, "table", t)
	prio := strconv.Itoa(probePrio + slot)
	if !sys.DryRun() {
		if out, err := sys.Run("ip", "-4", "rule", "show", "priority", prio); err == nil && strings.Contains(out, "lookup") {
			return
		}
	}
	_, _ = sys.Run("ip", "-4", "rule", "add", "priority", prio, "fwmark", fmt.Sprintf("0x%x/0x%x", probeMark(slot), MarkMask), "lookup", t)
}

// tunnelMTU: MTU der Schnittstelle eines Ausgangs – je Stufe der Kaskade kleiner.
func (m *Manager) tunnelMTU(e *Exit) int {
	mtu := 1420
	if e.WG != nil && e.WG.MTU > 0 {
		mtu = e.WG.MTU
	}
	m.mu.Lock()
	chain := m.chainLocked(e)
	m.mu.Unlock()
	if len(chain) == 0 {
		return mtu
	}
	// MTU des direkten Vorgängers, abzüglich der Kapselung
	v := chain[0]
	vm := ovpnMTU - cascadeLoss
	if v.WG != nil && v.WG.MTU > 0 {
		vm = v.WG.MTU
	}
	vm -= cascadeLoss * (len(chain) - 1)
	if lim := vm - cascadeLoss; lim < mtu {
		mtu = lim
	}
	if mtu < 1200 {
		mtu = 1200
	}
	return mtu
}

// withFwMark: FwMark in die Einstellungen für „wg setconf“ einfügen. Ohne Kaskade bleibt die
// Konfiguration unverändert (gleiche Kennung wie bisher → kein Neuaufbau nach dem Update); die
// Markierung setzt applyExit zusätzlich ausdrücklich („wg set … fwmark“).
func withFwMark(conf string, mark uint32) string {
	if mark == 0 {
		return conf
	}
	return strings.Replace(conf, "[Interface]\n", fmt.Sprintf("[Interface]\nFwMark = 0x%08x\n", mark), 1)
}

// ViaChain: Vorgänger eines Ausgangs (nächster zuerst) für Anzeige und Meldungen.
func (m *Manager) ViaChain(id int64) []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.lastExits {
		if e.ID == id {
			var out []int64
			for _, x := range m.chainLocked(e) {
				out = append(out, x.ID)
			}
			return out
		}
	}
	return nil
}
