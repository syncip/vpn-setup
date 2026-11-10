package engine

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// Ausgänge (externe VPNs) und Ausgangsgruppen – Anbindung an Datenbank und Treiber.

func (e *Engine) exitEnv() *exits.Env {
	return &exits.Env{
		Sys: e.Sys,
		Get: func(k string) string { return e.St.GetSetting("state:"+k, "") },
		Set: func(k, v string) { _ = e.St.SetSetting("state:"+k, v) },
		Log: e.Log,
		Out: e.Setting("out_interface"),
	}
}

// LoadExits liest Ausgänge und Gruppen. Fehlerhafte Ausgänge (sollte nach der Prüfung beim
// Hochladen nicht vorkommen) werden als deaktiviert behandelt und gemeldet.
func (e *Engine) LoadExits() ([]*exits.Exit, []*exits.Group) {
	eo, _ := e.St.Objects("exit")
	gro, _ := e.St.Objects("group")
	var xs []*exits.Exit
	for _, o := range eo {
		x, err := exits.ExitFrom(o)
		if err != nil {
			e.setErr(fmt.Sprintf("exit:%d", o.ID), err.Error())
			x.Enabled = false
		}
		xs = append(xs, x)
	}
	var gs []*exits.Group
	for _, o := range gro {
		gs = append(gs, exits.GroupFrom(o))
	}
	return xs, gs
}

func exitMap(xs []*exits.Exit) map[int64]*exits.Exit {
	m := map[int64]*exits.Exit{}
	for _, x := range xs {
		m[x.ID] = x
	}
	return m
}

func (e *Engine) applyExits() error {
	xs, gs := e.LoadExits()
	if len(xs) == 0 && len(gs) == 0 && e.St.GetSetting("state:exits:ifaces", "") == "" && e.St.GetSetting("state:exits:rules", "") == "" {
		return nil // nie benutzt
	}
	err := e.Exits.Apply(e.exitEnv(), xs, gs)
	if err != nil {
		e.setErr("exits", err.Error())
	} else {
		e.setErr("exits", "")
	}
	return err
}

// groupRoutes: Gruppen für die Treiber (Markierung und DNS).
func (e *Engine) groupRoutes() map[int64]proto.GroupRoute {
	objs, err := e.St.Objects("group")
	if err != nil || len(objs) == 0 {
		return nil
	}
	m := map[int64]proto.GroupRoute{}
	_, gst := e.Exits.Status()
	for _, o := range objs {
		g := exits.GroupFrom(o)
		r := proto.GroupRoute{ID: g.ID, Name: g.Name, Enabled: g.Enabled && g.Slot > 0, Mark: exits.GroupMark(g.Slot), DNS: g.DNS}
		if st, ok := gst[g.ID]; ok {
			r.State = st.State
			if st.Active != 0 {
				r.Dev = exits.IfName(st.Active)
			}
		}
		m[g.ID] = r
	}
	return m
}

func (e *Engine) speedEvery() time.Duration {
	return time.Duration(atoi(e.Setting("exit_speedtest"), 360)) * time.Minute
}

// RunExits: Prüfschleife der Ausgänge (alle 30 Sekunden).
func (e *Engine) RunExits(stop <-chan struct{}) {
	e.Exits.OnSwitch(func(gid int64) {
		for _, d := range proto.All() {
			if s, ok := d.(proto.GroupSwitcher); ok {
				s.GroupSwitched(gid)
			}
		}
		e.RequestApply() // Dienste, die sich an den aktiven Ausgang binden (Hysteria2), neu einrichten
	})
	e.Exits.Run(stop, e.exitEnv, e.LoadExits, e.speedEvery)
}

// CheckExits: sofort prüfen (Knopf in der Oberfläche); speed = auch Geschwindigkeit messen.
func (e *Engine) CheckExits(speed bool) {
	xs, gs := e.LoadExits()
	every := e.speedEvery()
	if speed {
		every = time.Nanosecond
	}
	e.Exits.Check(e.exitEnv(), xs, gs, every)
}

// SwitchExit: Gruppe von Hand auf einen Ausgang umschalten.
func (e *Engine) SwitchExit(groupID, exitID int64) error {
	o, err := e.St.Object("group", groupID)
	if err != nil {
		return err
	}
	g := exits.GroupFrom(o)
	if !g.Enabled || g.Slot < 1 {
		return fmt.Errorf("Gruppe ist deaktiviert")
	}
	xs, _ := e.LoadExits()
	return e.Exits.Switch(e.exitEnv(), g, exitID, exitMap(xs))
}

// NewSlot: freien Platz (Markierung/Tabelle) für einen neuen Ausgang bzw. eine neue Gruppe.
func (e *Engine) NewSlot(kind string) (int, error) {
	objs, err := e.St.Objects(kind)
	if err != nil {
		return 0, err
	}
	return exits.FreeSlot(objs)
}

// ExitUsers: Wer nutzt eine Gruppe? (Server-IDs, für Löschschutz und Anzeige)
func (e *Engine) GroupUsers(groupID int64) []*store.Server {
	servers, _ := e.St.Servers()
	var out []*store.Server
	for _, s := range servers {
		if v, ok := s.Settings["group"]; ok {
			if f, ok := v.(float64); ok && int64(f) == groupID {
				out = append(out, s)
			} else if str, ok := v.(string); ok && str == strconv.FormatInt(groupID, 10) {
				out = append(out, s)
			}
		}
	}
	return out
}

// ExitRate: aktueller Durchsatz eines Ausgangs (Bytes pro Sekunde), aus Sicht der Nutzer:
// Down = vom Anbieter empfangen, Up = zum Anbieter gesendet.
type ExitRate struct {
	Up   float64 `json:"up"`
	Down float64 `json:"down"`
}

type exitRateState struct {
	mu   sync.Mutex
	at   time.Time
	prev map[int64][2]uint64 // rx, tx
	last map[int64]ExitRate
}

// ExitRates liest die Zähler der Ausgangs-Schnittstellen und bildet die Rate seit dem letzten Aufruf
// (frühestens nach einer Sekunde neu). Im Testmodus leer – die Oberfläche schätzt dann aus den Geräten.
func (e *Engine) ExitRates() map[int64]ExitRate {
	if e.Sys.DryRun() {
		return map[int64]ExitRate{}
	}
	st := &e.exitRates
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	dt := now.Sub(st.at).Seconds()
	if st.last != nil && dt < 1 {
		return st.last
	}
	objs, _ := e.St.Objects("exit")
	cur := map[int64][2]uint64{}
	out := map[int64]ExitRate{}
	read := func(dev, name string) (uint64, bool) {
		b, err := e.Sys.ReadFile("/sys/class/net/" + dev + "/statistics/" + name)
		if err != nil {
			return 0, false
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return n, err == nil
	}
	for _, o := range objs {
		if !o.Enabled {
			continue
		}
		dev := exits.IfName(o.ID)
		rx, ok1 := read(dev, "rx_bytes")
		tx, ok2 := read(dev, "tx_bytes")
		if !ok1 || !ok2 {
			continue
		}
		cur[o.ID] = [2]uint64{rx, tx}
		if p, ok := st.prev[o.ID]; ok && dt > 0 && dt < 120 && rx >= p[0] && tx >= p[1] {
			out[o.ID] = ExitRate{Down: float64(rx-p[0]) / dt, Up: float64(tx-p[1]) / dt}
		} else {
			out[o.ID] = ExitRate{}
		}
	}
	st.at, st.prev, st.last = now, cur, out
	return out
}
