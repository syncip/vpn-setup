package engine

// Datenlimits für Ausgänge: Volumen je Zeitraum (wie bei Nutzern), beim Erreichen abschalten oder
// drosseln, dazu Grundgeschwindigkeit und Drosselstufen. Gezählt wird der Verkehr der Schnittstelle
// ex<ID> (hoch + runter, wie ihn auch der Anbieter zählt).
//
//   - „Abschalten“: der Ausgang gilt als deaktiviert (LoadExits) – der Tunnel wird getrennt, Gruppen
//     schalten auf den nächsten Ausgang bzw. sperren/gehen direkt, wie bei einem Ausfall.
//   - „Drosseln“: tc auf ex<ID> – ausgehend HTB (Upload zum Anbieter), eingehend Policer (Download).
//
// Der Zustand steht unter state:exits:limits und wird bei jeder Statistik-Runde neu bestimmt.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
)

// ExitLimitState: Verbrauch und Status eines Ausgangs mit Limits.
type ExitLimitState struct {
	Status      string        `json:"status"` // ok | throttled | blocked
	Reason      string        `json:"reason,omitempty"`
	Up          int64         `json:"up"`   // Byte im Zeitraum (zum Anbieter)
	Down        int64         `json:"down"` // Byte im Zeitraum (vom Anbieter)
	Used        int64         `json:"used"`
	Percent     float64       `json:"percent"` // vom Datenlimit, 0 ohne Datenlimit
	RateDown    float64       `json:"rate_down,omitempty"`
	RateUp      float64       `json:"rate_up,omitempty"`
	PeriodStart int64         `json:"period_start"`
	NextReset   int64         `json:"next_reset"`
	Limits      *store.Limits `json:"limits"`
}

// ExitLimits liest die Limits eines Ausgangs (nil = keine).
func ExitLimits(o *store.Object) *store.Limits {
	v, ok := o.Data["limits"]
	if !ok || v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var l store.Limits
	if json.Unmarshal(b, &l) != nil {
		return nil
	}
	if !l.HasAny() {
		return nil
	}
	return &l
}

// EvaluateExit: Status eines Ausgangs bei used Byte Verbrauch (dieselben Regeln wie bei Nutzern).
func EvaluateExit(l *store.Limits, used int64, now time.Time) Verdict {
	if l == nil {
		return Verdict{Status: "ok"}
	}
	return Evaluate(&store.User{Enabled: true, PeriodDown: used}, l, now)
}

// exitBase: beim Zurücksetzen gemerkter Verbrauch (zählt im selben Zeitraum nicht mit).
type exitBase struct {
	PS   int64 `json:"ps"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func exitBaseKey(id int64) string { return "state:exits:limitbase:" + strconv.FormatInt(id, 10) }

// ExitLimitStates bestimmt Verbrauch und Status aller Ausgänge mit Limits (aus der Datenbank).
func (e *Engine) ExitLimitStates() map[int64]ExitLimitState {
	objs, _ := e.St.Objects("exit")
	now := time.Now()
	out := map[int64]ExitLimitState{}
	cache := map[int64]map[int64]store.ExitTotals{}
	for _, o := range objs {
		l := ExitLimits(o)
		if l == nil {
			continue
		}
		ps := PeriodStart(l, now)
		t, ok := cache[ps]
		if !ok {
			t, _ = e.St.ExitTraffic(ps)
			cache[ps] = t
		}
		tot := t[o.ID]
		var b exitBase
		if json.Unmarshal([]byte(e.St.GetSetting(exitBaseKey(o.ID), "")), &b) == nil && b.PS == ps {
			tot.Up, tot.Down = max(0, tot.Up-b.Up), max(0, tot.Down-b.Down)
		}
		used := tot.Up + tot.Down
		v := EvaluateExit(l, used, now)
		st := ExitLimitState{Status: v.Status, Reason: v.Reason, Up: tot.Up, Down: tot.Down, Used: used,
			RateDown: v.RateDown, RateUp: v.RateUp, PeriodStart: ps, NextReset: NextReset(l, now), Limits: l}
		if l.TrafficGB > 0 {
			st.Percent = round1(100 * float64(used) / (l.TrafficGB * GB))
		}
		out[o.ID] = st
	}
	return out
}

// ResetExitUsage: Verbrauch des Ausgangs im laufenden Zeitraum auf 0 setzen (der Verlauf bleibt).
func (e *Engine) ResetExitUsage(id int64) error {
	o, err := e.St.Object("exit", id)
	if err != nil {
		return err
	}
	l := ExitLimits(o)
	ps := PeriodStart(l, time.Now())
	t, _ := e.St.ExitTraffic(ps)
	b, _ := json.Marshal(exitBase{PS: ps, Up: t[id].Up, Down: t[id].Down})
	if err := e.St.SetSetting(exitBaseKey(id), string(b)); err != nil {
		return err
	}
	e.Log("info", "Ausgang „"+o.Name+"“: Verbrauch im laufenden Zeitraum zurückgesetzt")
	e.RequestApply()
	return nil
}

// savedExitLimits: zuletzt bestimmter Status (für LoadExits, ohne Datenbankabfrage des Verkehrs).
type savedExitLimit struct {
	Status   string  `json:"s"`
	Reason   string  `json:"r,omitempty"`
	RateDown float64 `json:"d,omitempty"`
	RateUp   float64 `json:"u,omitempty"`
}

func (e *Engine) savedExitLimits() map[int64]savedExitLimit {
	m := map[int64]savedExitLimit{}
	_ = json.Unmarshal([]byte(e.St.GetSetting("state:exits:limits", "")), &m)
	return m
}

// checkExitLimits bestimmt den Status neu und meldet Änderungen. true = anwenden nötig.
func (e *Engine) checkExitLimits() bool {
	cur := e.ExitLimitStates()
	prev := e.savedExitLimits()
	next := map[int64]savedExitLimit{}
	changed := false
	names := map[int64]string{}
	if objs, err := e.St.Objects("exit"); err == nil {
		for _, o := range objs {
			names[o.ID] = o.Name
		}
	}
	ids := make([]int64, 0, len(cur))
	for id := range cur {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		st := cur[id]
		if st.Status == "ok" && st.RateDown == 0 && st.RateUp == 0 {
			continue
		}
		next[id] = savedExitLimit{Status: st.Status, Reason: st.Reason, RateDown: st.RateDown, RateUp: st.RateUp}
	}
	for id, n := range next {
		p, had := prev[id]
		if had && p == n {
			continue
		}
		changed = true
		if p.Status == n.Status {
			continue // nur die Geschwindigkeit hat sich geändert
		}
		name := names[id]
		switch n.Status {
		case "blocked":
			e.Log("warn", "Ausgang „"+name+"“: "+n.Reason+" – abgeschaltet bis zum nächsten Zeitraum")
		case "throttled":
			e.Log("info", "Ausgang „"+name+"“: "+n.Reason)
		}
	}
	for id, p := range prev {
		if _, ok := next[id]; ok {
			continue
		}
		changed = true
		if p.Status == "blocked" || p.Status == "throttled" {
			e.Log("info", "Ausgang „"+names[id]+"“: Limit wieder frei (neuer Zeitraum bzw. Limit geändert)")
		}
	}
	if changed {
		b, _ := json.Marshal(next)
		_ = e.St.SetSetting("state:exits:limits", string(b))
	}
	return changed
}

// shapeExits: Drosselung der Ausgänge per tc (bei jeder Statistik-Runde und nach dem Anwenden –
// verbindet sich ein Ausgang neu, ist die Schnittstelle neu und braucht die Regeln wieder).
func (e *Engine) shapeExits() {
	objs, _ := e.St.Objects("exit")
	saved := e.savedExitLimits()
	get := func(k string) string { return e.St.GetSetting("state:"+k, "") }
	set := func(k, v string) { _ = e.St.SetSetting("state:"+k, v) }
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	for _, o := range objs {
		dev := exits.IfName(o.ID)
		s := saved[o.ID]
		var rules []shaping.IfaceRule
		if o.Enabled && s.Status != "blocked" && (s.RateDown > 0 || s.RateUp > 0) {
			// ausgehend auf ex<ID> = Upload zum Anbieter, eingehend = Download
			rules = []shaping.IfaceRule{{ID: 1, Down: s.RateUp, Up: s.RateDown, Prefixes: all}}
		}
		if !e.Sys.DryRun() {
			if _, ok := e.ifaceCounter(dev, "rx_bytes"); !ok {
				set("tc:"+dev, "") // nicht verbunden – beim nächsten Verbinden neu einrichten
				continue
			}
		}
		if len(rules) == 0 && get("tc:"+dev) == "" {
			continue
		}
		if err := shaping.ApplyIface(e.Sys, dev, rules, get, set); err != nil {
			e.setErr(fmt.Sprintf("exitshape:%d", o.ID), "Drosselung des Ausgangs „"+o.Name+"“: "+err.Error())
		} else {
			e.setErr(fmt.Sprintf("exitshape:%d", o.ID), "")
		}
	}
}
