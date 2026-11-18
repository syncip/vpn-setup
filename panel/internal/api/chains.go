package api

import (
	"fmt"
	"strings"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/store"
)

// Kaskade über Ziel-Regeln: Eine Regel nennt bis zu drei Stufen (Ausgang, Ausgang, … Ausgang oder
// Gruppe). Daraus ergibt sich „Verbunden über“ der beteiligten Ausgänge: Stufe 1 verbindet sich
// direkt, jede weitere über die vorige, die Ausgänge der letzten Stufe über die vorletzte.
//
// Ein Ausgang ist ein Tunnel und hat deshalb nur einen Weg: Verlangen zwei Regeln für denselben
// Ausgang verschiedene Vorgänger, wird die zweite nicht gespeichert. Von Regeln bestimmte Ausgänge
// tragen „via_rule“; gilt keine Regel mehr für sie, verbinden sie sich wieder direkt. Endet eine
// Kette mit einem einzelnen Ausgang, legt das Panel dafür eine Gruppe an („auto“ = Ausgang) und
// entfernt sie wieder, wenn keine Regel sie mehr braucht.
//
// Regeln ohne „chain“ (ältere bzw. per Karte angelegte) bestimmen keinen Weg.

type stageIn struct {
	Kind string `json:"kind"` // exit | group
	ID   int64  `json:"id"`
}

func numOf(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	}
	return 0
}

func idsOf(v any) []int64 {
	switch x := v.(type) {
	case []int64:
		return x
	case []any:
		out := make([]int64, 0, len(x))
		for _, e := range x {
			out = append(out, numOf(e))
		}
		return out
	}
	return nil
}

// chainWorld: Stand aller Objekte, die für die Kaskade zählen.
type chainWorld struct {
	exits  map[int64]*store.Object
	groups map[int64]*store.Object
	routes []*store.Object
	label  map[int64]string // Regel → Bezeichnung für Meldungen (Notiz bzw. „für …“)
}

func (a *API) loadChainWorld() (*chainWorld, error) {
	w := &chainWorld{exits: map[int64]*store.Object{}, groups: map[int64]*store.Object{}, label: map[int64]string{}}
	eo, err := a.St.Objects("exit")
	if err != nil {
		return nil, err
	}
	for _, o := range eo {
		w.exits[o.ID] = o
	}
	gro, err := a.St.Objects("group")
	if err != nil {
		return nil, err
	}
	for _, o := range gro {
		w.groups[o.ID] = o
	}
	if w.routes, err = a.St.Objects("route"); err != nil {
		return nil, err
	}
	for _, r := range w.routes {
		w.label[r.ID] = a.routeLabel(r)
	}
	return w, nil
}

// withRoute ersetzt (bzw. ergänzt) eine Regel; del = Regel entfernen.
func (w *chainWorld) withRoute(o *store.Object, del bool) {
	var out []*store.Object
	for _, r := range w.routes {
		if r.ID != o.ID || o.ID == 0 {
			out = append(out, r)
		}
	}
	if !del {
		out = append(out, o)
	}
	w.routes = out
}

// routeLabel: Notiz der Regel, sonst wofür sie gilt („für alle“, „für Nutzer anna“ …).
func (a *API) routeLabel(r *store.Object) string {
	if r.Name != "" {
		return r.Name
	}
	id := numOf(r.Data["scope_id"])
	switch r.Data["scope"] {
	case "server":
		if s, err := a.St.Server(id); err == nil {
			return "für Server " + s.Name
		}
	case "user":
		if u, err := a.St.User(id); err == nil {
			return "für Nutzer " + u.Name
		}
	case "peer":
		if p, err := a.St.Peer(id); err == nil {
			return "für Gerät " + p.Name
		}
	}
	return "für alle"
}

func (w *chainWorld) exitName(id int64) string {
	if o := w.exits[id]; o != nil {
		return "„" + o.Name + "“"
	}
	return fmt.Sprintf("Ausgang %d", id)
}

// finalExits: Ausgänge der letzten Stufe einer Regel (die der Zielgruppe).
func (w *chainWorld) finalExits(r *store.Object) []int64 {
	if g := w.groups[numOf(r.Data["group"])]; g != nil {
		return idsOf(g.Data["exits"])
	}
	return nil
}

// plan: gewünschter Vorgänger je Ausgang (0 = direkt) aus allen aktiven Regeln mit Kette.
// Fehlertext bei Widerspruch oder ungültiger Kette, sonst "".
func (w *chainWorld) plan() (map[int64]int64, map[int64]string, string) {
	want := map[int64]int64{}
	owner := map[int64]string{}
	set := func(id, via int64, rule string) string {
		if old, ok := want[id]; ok && old != via {
			was, now := "direkt", "direkt"
			if old != 0 {
				was = "über " + w.exitName(old)
			}
			if via != 0 {
				now = "über " + w.exitName(via)
			}
			return fmt.Sprintf("%s verbindet sich in der Ziel-Regel „%s“ %s, hier wäre es %s. Ein Ausgang ist ein Tunnel und hat nur einen Weg – für beides einen zweiten Ausgang anlegen.",
				w.exitName(id), owner[id], was, now)
		}
		want[id], owner[id] = via, rule
		return ""
	}
	for _, r := range w.routes {
		if !r.Enabled || r.Data["chain"] == nil {
			continue
		}
		name := w.label[r.ID]
		if name == "" {
			name = r.Name
		}
		chain := idsOf(r.Data["chain"])
		prev := int64(0)
		for _, id := range chain {
			if msg := set(id, prev, name); msg != "" {
				return nil, nil, msg
			}
			prev = id
		}
		if numOf(r.Data["group"]) == 0 {
			continue
		}
		for _, id := range w.finalExits(r) {
			if msg := set(id, prev, name); msg != "" {
				return nil, nil, msg
			}
		}
	}
	// Ergebnis prüfen: keine Kreise, höchstens drei Stufen, über Tor nur TCP
	vias := map[int64]int64{}
	for id, o := range w.exits {
		v := numOf(o.Data["via"])
		if o.Data["via_rule"] == true {
			v = 0 // gilt nur, solange eine Regel es verlangt
		}
		if x, ok := want[id]; ok {
			v = x
		}
		if v != 0 {
			vias[id] = v
		}
	}
	for id, v := range want {
		if v == 0 {
			continue
		}
		rest := map[int64]int64{}
		for k, x := range vias {
			if k != id {
				rest[k] = x
			}
		}
		if msg := exits.CheckVia(id, v, rest, func(x int64) bool { return w.exits[x] != nil }); msg != "" {
			return nil, nil, w.exitName(id) + ": " + msg
		}
		if msg := viaTypeError(w.exits[id], w.exits[v]); msg != "" {
			return nil, nil, msg
		}
	}
	return want, owner, ""
}

// viaTypeError: Über Tor geht nur TCP – kein WireGuard, OpenVPN nur mit „proto tcp“.
func viaTypeError(o, via *store.Object) string {
	if o == nil || via == nil || via.Data["type"] != "tor" {
		return ""
	}
	switch o.Data["type"] {
	case "wireguard":
		return "WireGuard kann nicht über Tor laufen (Tor überträgt nur TCP) – „" + o.Name + "“"
	case "openvpn":
		if !strings.Contains(strings.ToLower(strOf(o.Secrets["config"])), "proto tcp") {
			return "OpenVPN über Tor nur mit „proto tcp“ (Tor überträgt nur TCP) – „" + o.Name + "“"
		}
	}
	return ""
}

// routeStages übernimmt die Stufen in die Regel (chain, group). Endet die Kette mit einem Ausgang,
// wird dessen Gruppe gesucht bzw. vorgemerkt (newAuto ≠ 0: Gruppe für diesen Ausgang anlegen).
func (w *chainWorld) routeStages(o *store.Object, st []stageIn) (newAuto int64, msg string) {
	if len(st) > 3 {
		return 0, "Höchstens 3 Stufen"
	}
	seen := map[int64]bool{}
	var chain []int64
	for i, s := range st {
		last := i == len(st)-1
		switch s.Kind {
		case "exit":
			if w.exits[s.ID] == nil {
				return 0, fmt.Sprintf("Ausgang %d gibt es nicht", s.ID)
			}
			if seen[s.ID] {
				return 0, w.exitName(s.ID) + " steht zweimal in der Kette"
			}
			seen[s.ID] = true
			if !last {
				chain = append(chain, s.ID)
			}
		case "group":
			if w.groups[s.ID] == nil {
				return 0, "Ausgangsgruppe gibt es nicht"
			}
			if !last {
				return 0, "Eine Gruppe kann nur die letzte Stufe sein (davor einzelne Ausgänge)"
			}
		default:
			return 0, "Stufe: Ausgang oder Gruppe"
		}
	}
	o.Data["chain"] = orEmptyT(chain)
	if len(st) == 0 {
		o.Data["group"] = int64(0)
		return 0, ""
	}
	end := st[len(st)-1]
	if end.Kind == "group" {
		for _, id := range idsOf(w.groups[end.ID].Data["exits"]) {
			if seen[id] {
				return 0, w.exitName(id) + " ist Teil der Gruppe und kann nicht davor stehen"
			}
		}
		o.Data["group"] = end.ID
		return 0, ""
	}
	if g := w.autoGroup(end.ID); g != nil {
		o.Data["group"] = g.ID
		return 0, ""
	}
	// vorläufig (für die Prüfung); die echte Gruppe entsteht erst beim Speichern
	w.groups[-1] = &store.Object{ID: -1, Kind: "group", Data: store.M{"exits": []int64{end.ID}}}
	o.Data["group"] = int64(-1)
	return end.ID, ""
}

func (w *chainWorld) autoGroup(exitID int64) *store.Object {
	for _, g := range w.groups {
		if numOf(g.Data["auto"]) == exitID {
			return g
		}
	}
	return nil
}

// newAutoGroup: Gruppe für einen einzelnen Ausgang am Ende einer Kette.
func (a *API) newAutoGroup(w *chainWorld, exitID int64) (*store.Object, error) {
	slot, err := a.E.NewSlot("group")
	if err != nil {
		return nil, err
	}
	g := &store.Object{Kind: "group", Name: w.exits[exitID].Name, Enabled: true, Secrets: store.M{},
		Data: store.M{"exits": []int64{exitID}, "on_fail": "block", "auto": exitID, "slot": slot}}
	if err := a.St.SaveObject(g); err != nil {
		return nil, err
	}
	w.groups[g.ID] = g
	return g, nil
}

// applyChains schreibt die geplanten Wege in die Ausgänge und entfernt nicht mehr gebrauchte
// automatische Gruppen.
func (a *API) applyChains(w *chainWorld, want map[int64]int64) {
	changed := false
	defer func() {
		if changed {
			a.E.RequestApply()
		}
	}()
	for id, o := range w.exits {
		v, ruled := want[id]
		cur := numOf(o.Data["via"])
		switch {
		case ruled && (cur != v || o.Data["via_rule"] != true):
			if v == 0 {
				delete(o.Data, "via")
			} else {
				o.Data["via"] = v
			}
			o.Data["via_rule"] = true
		case !ruled && o.Data["via_rule"] == true:
			delete(o.Data, "via")
			delete(o.Data, "via_rule")
		default:
			continue
		}
		if err := a.St.SaveObject(o); err != nil {
			a.E.Log("warn", "Kaskade: „"+o.Name+"“: "+err.Error())
			continue
		}
		changed = true
		if v != 0 && ruled {
			a.E.Log("info", "Ausgang „"+o.Name+"“ verbindet sich über "+w.exitName(v)+" (Ziel-Regel)")
		}
	}
	used := map[int64]bool{}
	for _, r := range w.routes {
		used[numOf(r.Data["group"])] = true
	}
	for id, g := range w.groups {
		if g.Data["auto"] == nil || used[id] || len(a.E.GroupUsers(id)) > 0 {
			continue
		}
		_ = a.St.DeleteGroupTraffic(id)
		if err := a.St.DeleteObject("group", id); err == nil {
			_ = a.St.SetSetting(fmt.Sprintf("state:exits:active:%d", id), "")
			_ = a.St.SetSetting(fmt.Sprintf("state:exits:pin:%d", id), "")
			delete(w.groups, id)
			changed = true
		}
	}
}

// rulesFor: Name der Regel, die den Weg eines Ausgangs bestimmt ("" = keine).
func (a *API) chainRuleFor(exitID int64) string {
	w, err := a.loadChainWorld()
	if err != nil {
		return ""
	}
	_, owner, _ := w.plan()
	return owner[exitID]
}

// syncChains: nach Änderungen an Gruppen oder Ausgängen die Wege neu ableiten. Fehlertext, wenn
// der neue Stand einen Widerspruch ergäbe (dann wird nichts geändert).
func (a *API) checkChains(edit func(w *chainWorld)) string {
	w, err := a.loadChainWorld()
	if err != nil {
		return err.Error()
	}
	edit(w)
	_, _, msg := w.plan()
	return msg
}

func (a *API) syncChains() {
	w, err := a.loadChainWorld()
	if err != nil {
		return
	}
	want, _, msg := w.plan()
	if msg != "" {
		a.E.Log("warn", "Kaskade: "+msg)
		return
	}
	a.applyChains(w, want)
}
