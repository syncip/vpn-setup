package exits

import (
	"fmt"
	"strconv"
	"time"
)

// Ausgänge in Bereitschaft: Manche Anbieter sehen es ungern (oder es fällt auf), wenn ein Server
// rund um die Uhr mit vielen ihrer Standorte verbunden ist. Ein Ausgang in Bereitschaft ist nur
// verbunden, solange eine Gruppe ihn als aktiven Ausgang nutzt. Sonst verbindet der Server ihn alle
// CheckMin Minuten kurz, prüft ihn und trennt wieder. Fällt der aktive Ausgang einer Gruppe aus,
// werden die Ausgänge in Bereitschaft der Reihe nach verbunden und geprüft, bevor umgeschaltet wird.

const connectWait = 20 * time.Second // so lange auf die Schnittstelle warten (OpenVPN)

func (m *Manager) isConn(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conn[id]
}

func (m *Manager) setConn(id int64, on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if on {
		m.conn[id] = true
	} else {
		delete(m.conn, id)
	}
	if st := m.status[id]; st != nil {
		st.Connected = on
	}
}

// neededSet: Ausgänge, die gerade eine Gruppe nutzt.
func (m *Manager) neededSet() map[int64]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]bool{}
	for _, g := range m.groups {
		if g.Active != 0 {
			out[g.Active] = true
		}
	}
	return out
}

// connect verbindet einen Ausgang (Bereitschaft) und wartet, bis die Schnittstelle da ist.
func (m *Manager) connect(env *Env, e *Exit) error {
	if err := m.applyExit(env, e); err != nil {
		return err
	}
	sys := env.Sys
	n := IfName(e.ID)
	if !sys.DryRun() {
		deadline := time.Now().Add(connectWait)
		for {
			if _, err := sys.Run("ip", "link", "show", "dev", n); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("Tunnel kam nicht zustande (%s)", connectWait)
			}
			time.Sleep(500 * time.Millisecond)
		}
		// Prüf-Route setzen und den Tunnel anstoßen (WireGuard handelt erst beim ersten Paket aus)
		_, _ = sys.Run("ip", "-4", "route", "replace", "default", "dev", n, "table", strconv.Itoa(probeTable+e.Slot))
		mark := strconv.FormatUint(uint64(probeMark(e.Slot)), 10)
		_, _ = sys.Run("ping", "-n", "-q", "-c", "2", "-i", "0.5", "-W", "2", "-m", mark, "-I", n, pingTarget)
	}
	m.setConn(e.ID, true)
	return nil
}

// disconnect trennt einen Ausgang (Konfiguration bleibt erhalten).
func (m *Manager) disconnect(env *Env, e *Exit) {
	sys := env.Sys
	n := IfName(e.ID)
	wasConn := m.isConn(e.ID)
	m.setConn(e.ID, false)
	switch e.Type {
	case "openvpn":
		if _, err := sys.Run("systemctl", "is-active", "--quiet", "vpn-exit@"+n); err == nil || wasConn {
			_, _ = sys.Run("systemctl", "disable", "--now", "vpn-exit@"+n)
		}
	default:
		if _, err := sys.Run("ip", "link", "show", "dev", n); err == nil || (wasConn && !sys.DryRun()) {
			_, _ = sys.Run("ip", "link", "del", "dev", n)
		}
	}
	env.Set("exits:cfg:"+n, "") // beim nächsten Verbinden neu einrichten
}

// CheckAll: wie Check, prüft aber auch die Ausgänge in Bereitschaft sofort (Knopf in der Oberfläche).
func (m *Manager) CheckAll(env *Env, exits []*Exit, groups []*Group, speedEvery time.Duration) {
	m.mu.Lock()
	m.force = true
	m.mu.Unlock()
	m.Check(env, exits, groups, speedEvery)
}

// failoverCandidates: Fällt der aktive Ausgang einer Gruppe aus, werden Ausgänge in Bereitschaft
// (in der Reihenfolge der Gruppe) verbunden und geprüft, bis einer gesund ist.
func (m *Manager) failoverCandidates(env *Env, groups []*Group, byID map[int64]*Exit, probe func(*Exit)) {
	tried := map[int64]bool{}
	for _, g := range groups {
		if !g.Enabled || g.Slot < 1 {
			continue
		}
		cur := m.active(env, g, byID)
		m.mu.Lock()
		curOK := false
		if cur != 0 {
			curOK, _ = m.isHealthy(g, byID[cur])
		}
		order := m.order(g)
		m.mu.Unlock()
		if curOK {
			continue
		}
		for _, id := range order {
			x := byID[id]
			if x == nil || !x.Enabled || id == cur {
				continue
			}
			if x.Standby() && !m.isConn(id) && !tried[id] {
				tried[id] = true
				if err := m.connect(env, x); err != nil {
					env.Log("warn", fmt.Sprintf("Ausgang „%s“ (Bereitschaft): %v", x.Name, err))
					m.disconnect(env, x)
					continue
				}
				probe(x)
			}
			m.mu.Lock()
			ok, _ := m.isHealthy(g, x)
			m.mu.Unlock()
			if ok {
				break
			}
		}
	}
}

// CheckOne prüft einen einzelnen Ausgang sofort (Knöpfe „Ping“ und „Speedtest“). Ein Ausgang in
// Bereitschaft wird dafür kurz verbunden und danach wieder getrennt, wenn ihn keine Gruppe nutzt.
func (m *Manager) CheckOne(env *Env, e *Exit, speed bool) (ExitStatus, error) {
	m.probeMu.Lock()
	defer m.probeMu.Unlock()
	if e == nil || !e.Enabled || e.Slot < 1 {
		return ExitStatus{}, fmt.Errorf("Ausgang ist deaktiviert")
	}
	m.mu.Lock()
	if m.status[e.ID] == nil {
		m.status[e.ID] = &ExitStatus{ID: e.ID, Standby: e.Standby()}
	}
	m.mu.Unlock()
	tmp := false
	if e.Standby() && !m.isConn(e.ID) {
		if err := m.connect(env, e); err != nil {
			m.disconnect(env, e)
			m.record(e, Sample{TS: time.Now().Unix(), Loss: 100}, "", "", 0, false, fmt.Errorf("%w: %v", errNoTunnel, err))
			return m.statusOf(e.ID), err
		}
		tmp = true
	}
	s, ip, loc, mb, err := m.probe(env, e, speed)
	m.record(e, s, ip, loc, mb, speed, err)
	if tmp && !m.neededSet()[e.ID] {
		m.disconnect(env, e)
	}
	if speed && mb == 0 && err == nil {
		err = fmt.Errorf("Geschwindigkeit konnte nicht gemessen werden")
	}
	return m.statusOf(e.ID), err
}

func (m *Manager) statusOf(id int64) ExitStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st := m.status[id]; st != nil {
		c := *st
		c.Samples = append([]Sample(nil), st.Samples...)
		return c
	}
	return ExitStatus{ID: id}
}
