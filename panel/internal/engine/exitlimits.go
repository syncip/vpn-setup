package engine

// Datenlimits für Ausgänge und Ausgangsgruppen: Volumen je Zeitraum (wie bei Nutzern), beim Erreichen
// abschalten oder drosseln, dazu Grundgeschwindigkeit und Drosselstufen.
//
//   - Ausgang: gezählt wird der Verkehr der Schnittstelle ex<ID> (hoch + runter, wie beim Anbieter).
//     „Abschalten“ = der Ausgang gilt als deaktiviert (LoadExits) – Gruppen schalten sofort um.
//   - Gruppe: gezählt wird der Verkehr des jeweils aktiven Ausgangs der Gruppe (Tabelle group_traffic).
//     „Abschalten“ = die Gruppe sperrt (kein Ausgang, auch bei „direkt“).
//   - „Drosseln“: tc auf ex<ID> – ausgehend HTB (Upload zum Anbieter), eingehend Policer (Download).
//     Eine gedrosselte Gruppe drosselt ihren aktiven Ausgang (es gilt die kleinste Geschwindigkeit).
//
// Der Zustand steht unter state:exits:limits bzw. state:groups:limits und wird bei jeder
// Statistik-Runde neu bestimmt.

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

// ExitLimitState: Verbrauch und Status eines Ausgangs bzw. einer Gruppe mit Limits.
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

// ExitLimits liest die Limits eines Ausgangs bzw. einer Gruppe (nil = keine).
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

// EvaluateExit: Status bei used Byte Verbrauch (dieselben Regeln wie bei Nutzern).
func EvaluateExit(l *store.Limits, used int64, now time.Time) Verdict {
	if l == nil {
		return Verdict{Status: "ok"}
	}
	return Evaluate(&store.User{Enabled: true, PeriodDown: used}, l, now)
}

// limitTraffic: Verkehr je Ausgang („exit“) bzw. Gruppe („group“) ab since.
func (e *Engine) limitTraffic(kind string, since int64) map[int64]store.ExitTotals {
	var t map[int64]store.ExitTotals
	if kind == "group" {
		t, _ = e.St.GroupTraffic(since)
	} else {
		t, _ = e.St.ExitTraffic(since)
	}
	if t == nil {
		t = map[int64]store.ExitTotals{}
	}
	return t
}

func limitLabel(kind, name string) string {
	if kind == "group" {
		return "Gruppe „" + name + "“"
	}
	return "Ausgang „" + name + "“"
}

// exitBase: beim Zurücksetzen gemerkter Verbrauch (zählt im selben Zeitraum nicht mit).
type exitBase struct {
	PS   int64 `json:"ps"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func limitBaseKey(kind string, id int64) string {
	if kind == "group" {
		return "state:groups:limitbase:" + strconv.FormatInt(id, 10)
	}
	return "state:exits:limitbase:" + strconv.FormatInt(id, 10)
}

func limitStateKey(kind string) string {
	if kind == "group" {
		return "state:groups:limits"
	}
	return "state:exits:limits"
}

// limitStates bestimmt Verbrauch und Status aller Ausgänge bzw. Gruppen mit Limits.
func (e *Engine) limitStates(kind string) map[int64]ExitLimitState {
	objs, _ := e.St.Objects(kind)
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
			t = e.limitTraffic(kind, ps)
			cache[ps] = t
		}
		tot := t[o.ID]
		var b exitBase
		if json.Unmarshal([]byte(e.St.GetSetting(limitBaseKey(kind, o.ID), "")), &b) == nil && b.PS == ps {
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

// ExitLimitStates / GroupLimitStates: Verbrauch und Status (aus der Datenbank).
func (e *Engine) ExitLimitStates() map[int64]ExitLimitState  { return e.limitStates("exit") }
func (e *Engine) GroupLimitStates() map[int64]ExitLimitState { return e.limitStates("group") }

// ResetUsage: Verbrauch im laufenden Zeitraum auf 0 setzen (der Verlauf bleibt). kind = exit | group
func (e *Engine) ResetUsage(kind string, id int64) error {
	o, err := e.St.Object(kind, id)
	if err != nil {
		return err
	}
	l := ExitLimits(o)
	ps := PeriodStart(l, time.Now())
	t := e.limitTraffic(kind, ps)
	b, _ := json.Marshal(exitBase{PS: ps, Up: t[id].Up, Down: t[id].Down})
	if err := e.St.SetSetting(limitBaseKey(kind, id), string(b)); err != nil {
		return err
	}
	e.Log("info", limitLabel(kind, o.Name)+": Verbrauch im laufenden Zeitraum zurückgesetzt")
	e.RequestApply()
	return nil
}

// ResetExitUsage: für einen Ausgang.
func (e *Engine) ResetExitUsage(id int64) error { return e.ResetUsage("exit", id) }

// savedExitLimit: zuletzt bestimmter Status (für LoadExits, ohne Datenbankabfrage des Verkehrs).
type savedExitLimit struct {
	Status   string  `json:"s"`
	Reason   string  `json:"r,omitempty"`
	RateDown float64 `json:"d,omitempty"`
	RateUp   float64 `json:"u,omitempty"`
}

func (e *Engine) savedLimits(kind string) map[int64]savedExitLimit {
	m := map[int64]savedExitLimit{}
	_ = json.Unmarshal([]byte(e.St.GetSetting(limitStateKey(kind), "")), &m)
	return m
}

func (e *Engine) savedExitLimits() map[int64]savedExitLimit  { return e.savedLimits("exit") }
func (e *Engine) savedGroupLimits() map[int64]savedExitLimit { return e.savedLimits("group") }

// checkExitLimits bestimmt den Status von Ausgängen und Gruppen neu. true = anwenden nötig.
func (e *Engine) checkExitLimits() bool {
	a := e.checkLimits("exit")
	b := e.checkLimits("group")
	return a || b
}

func (e *Engine) checkLimits(kind string) bool {
	cur := e.limitStates(kind)
	prev := e.savedLimits(kind)
	next := map[int64]savedExitLimit{}
	changed := false
	names := map[int64]string{}
	if objs, err := e.St.Objects(kind); err == nil {
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
		switch n.Status {
		case "blocked":
			what := "abgeschaltet bis zum nächsten Zeitraum"
			if kind == "group" {
				what = "Verkehr gesperrt bis zum nächsten Zeitraum"
			}
			e.Log("warn", limitLabel(kind, names[id])+": "+n.Reason+" – "+what)
		case "throttled":
			e.Log("info", limitLabel(kind, names[id])+": "+n.Reason)
		}
	}
	for id, p := range prev {
		if _, ok := next[id]; ok {
			continue
		}
		changed = true
		if p.Status == "blocked" || p.Status == "throttled" {
			e.Log("info", limitLabel(kind, names[id])+": Limit wieder frei (neuer Zeitraum bzw. Limit geändert)")
		}
	}
	if changed {
		b, _ := json.Marshal(next)
		_ = e.St.SetSetting(limitStateKey(kind), string(b))
	}
	return changed
}

// limitRates: wirksame Drosselung je Ausgang – eigenes Limit und das gedrosselter Gruppen, die den
// Ausgang gerade nutzen (je Richtung die kleinste Geschwindigkeit).
func (e *Engine) limitRates() map[int64]savedExitLimit {
	out := map[int64]savedExitLimit{}
	for id, s := range e.savedExitLimits() {
		if s.Status != "blocked" {
			out[id] = savedExitLimit{RateDown: s.RateDown, RateUp: s.RateUp}
		}
	}
	gl := e.savedGroupLimits()
	if len(gl) > 0 && e.Exits != nil {
		_, gs := e.Exits.Status()
		for gid, s := range gl {
			st, ok := gs[gid]
			if !ok || st.Active == 0 || s.Status == "blocked" || (s.RateDown == 0 && s.RateUp == 0) {
				continue
			}
			r := out[st.Active]
			r.RateDown, r.RateUp = minRate(r.RateDown, s.RateDown), minRate(r.RateUp, s.RateUp)
			out[st.Active] = r
		}
	}
	return out
}

// shapeExits: Drosselung der Ausgänge per tc (bei jeder Statistik-Runde und nach dem Anwenden –
// verbindet sich ein Ausgang neu, ist die Schnittstelle neu und braucht die Regeln wieder).
func (e *Engine) shapeExits() {
	objs, _ := e.St.Objects("exit")
	rates := e.limitRates()
	get := func(k string) string { return e.St.GetSetting("state:"+k, "") }
	set := func(k, v string) { _ = e.St.SetSetting("state:"+k, v) }
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	for _, o := range objs {
		dev := exits.IfName(o.ID)
		s := rates[o.ID]
		var rules []shaping.IfaceRule
		if o.Enabled && (s.RateDown > 0 || s.RateUp > 0) {
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
