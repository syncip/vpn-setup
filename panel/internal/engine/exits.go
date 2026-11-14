package engine

import (
	"encoding/json"
	"fmt"
	"math"
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
	lim := e.savedExitLimits()
	for _, o := range eo {
		x, err := exits.ExitFrom(o)
		if err != nil {
			e.setErr(fmt.Sprintf("exit:%d", o.ID), err.Error())
			x.Enabled = false
		}
		if l := lim[o.ID]; l.Status == "blocked" {
			x.Enabled = false // Datenlimit erreicht – bis zum nächsten Zeitraum abgeschaltet
			x.Blocked = l.Reason
		}
		xs = append(xs, x)
	}
	var gs []*exits.Group
	glim := e.savedGroupLimits()
	for _, o := range gro {
		g := exits.GroupFrom(o)
		if l := glim[o.ID]; l.Status == "blocked" {
			g.Blocked = l.Reason // Datenlimit der Gruppe erreicht – gesperrt
		}
		gs = append(gs, g)
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
	e.checkExitLimits()
	xs, gs := e.LoadExits()
	if len(xs) == 0 && len(gs) == 0 && e.St.GetSetting("state:exits:ifaces", "") == "" && e.St.GetSetting("state:exits:rules", "") == "" {
		return nil // nie benutzt
	}
	err := e.Exits.Apply(e.exitEnv(), xs, gs)
	e.shapeExits()
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
	e.Exits.CheckAll(e.exitEnv(), xs, gs, every)
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
	if l := e.savedGroupLimits()[g.ID]; l.Status == "blocked" {
		return fmt.Errorf("Gruppe ist durch ihr Datenlimit gesperrt (%s)", l.Reason)
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

// ifaceCounter liest einen Zähler einer Schnittstelle (rx_bytes, tx_bytes).
func (e *Engine) ifaceCounter(dev, name string) (uint64, bool) {
	b, err := e.Sys.ReadFile("/sys/class/net/" + dev + "/statistics/" + name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

// collectExitTraffic zählt den Verkehr der Ausgänge seit dem letzten Lauf (Statistik je Stunde).
// Die Zähler der Schnittstellen beginnen nach jedem Neuverbinden bei 0 – ist ein Wert kleiner als
// zuvor, zählt er ganz. Die letzten Werte stehen in der Datenbank, damit ein Neustart nichts verliert.
func (e *Engine) collectExitTraffic(ts int64) {
	if e.Sys.DryRun() {
		return
	}
	objs, _ := e.St.Objects("exit")
	if len(objs) == 0 {
		return
	}
	prev := map[int64][2]uint64{}
	_ = json.Unmarshal([]byte(e.St.GetSetting("state:exits:counters", "")), &prev)
	// Gruppen, die einen Ausgang gerade nutzen: ihr Verkehr zählt für deren Limits
	usedBy := map[int64][]int64{}
	if e.Exits != nil {
		_, gst := e.Exits.Status()
		for gid, st := range gst {
			if st.Active != 0 {
				usedBy[st.Active] = append(usedBy[st.Active], gid)
			}
		}
	}
	cur := map[int64][2]uint64{}
	for _, o := range objs {
		dev := exits.IfName(o.ID)
		rx, ok1 := e.ifaceCounter(dev, "rx_bytes")
		tx, ok2 := e.ifaceCounter(dev, "tx_bytes")
		if !ok1 || !ok2 {
			cur[o.ID] = [2]uint64{} // nicht verbunden – nach dem Verbinden zählt alles ab 0
			continue
		}
		cur[o.ID] = [2]uint64{rx, tx}
		p, had := prev[o.ID]
		if !had {
			continue // erster Wert – ab jetzt zählen
		}
		down, up := rx, tx
		if rx >= p[0] {
			down = rx - p[0]
		}
		if tx >= p[1] {
			up = tx - p[1]
		}
		if up+down > 0 {
			_ = e.St.AddExitTraffic(o.ID, ts, int64(up), int64(down))
			for _, gid := range usedBy[o.ID] {
				_ = e.St.AddGroupTraffic(gid, ts, int64(up), int64(down))
			}
		}
	}
	b, _ := json.Marshal(cur)
	_ = e.St.SetSetting("state:exits:counters", string(b))
}

// CheckExit prüft einen Ausgang sofort (speed = auch Geschwindigkeit messen).
func (e *Engine) CheckExit(id int64, speed bool) (exits.ExitStatus, error) {
	xs, _ := e.LoadExits()
	return e.Exits.CheckOne(e.exitEnv(), exitMap(xs)[id], speed)
}

// ExitLive: aktueller Durchsatz je Ausgang und je Gruppe (Byte/s) für die Live-Anzeige. Eine Gruppe
// zeigt den Durchsatz ihres aktiven Ausgangs. Im Testmodus Beispielwerte.
func (e *Engine) ExitLive() (map[int64]ExitRate, map[int64]ExitRate, map[int64]int64) {
	var rates map[int64]ExitRate
	active := map[int64]int64{}
	if e.Exits != nil {
		_, gs := e.Exits.Status()
		for gid, st := range gs {
			active[gid] = st.Active
		}
	}
	if e.Sys.DryRun() {
		rates = map[int64]ExitRate{}
		t := float64(time.Now().UnixMilli()) / 1000
		xs, _ := e.LoadExits()
		for _, x := range xs {
			if !x.Enabled {
				continue
			}
			used := 0.0
			for _, a := range active {
				if a == x.ID {
					used++
				}
			}
			f := float64(x.ID)
			down := 2_000 + used*(2_500_000+1_800_000*math.Sin(t/(7+f)+f))
			rates[x.ID] = ExitRate{Down: down, Up: down/9 + 500}
		}
	} else {
		rates = e.ExitRates()
	}
	groups := map[int64]ExitRate{}
	for gid, a := range active {
		groups[gid] = rates[a]
	}
	return rates, groups, active
}
