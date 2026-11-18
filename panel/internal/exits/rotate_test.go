package exits

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestPinScript(t *testing.T) {
	s := pinScript([]int{3, 1, 2}, []pinGroup{{Slot: 2, Exits: []int{1, 3}, Seed: 5}, {Slot: 1, Exits: []int{2}}, {Slot: 4, Exits: []int{9}}})
	if p := os.Getenv("PIN_SCRIPT_OUT"); p != "" { // Syntaxprüfung mit nft -c (Labor)
		_ = os.WriteFile(p, []byte(s), 0o644)
	}
	for _, want := range []string{
		"type filter hook prerouting priority -140",
		"type route hook output priority -160",
		"meta mark & 0x7f000000 vmap { 0x01000000 : jump g1, 0x02000000 : jump g2 }",
		"ct mark & 0x40000000 == 0x0 ct mark set ct mark & 0x80ffffff | 0x42000000", // Gruppe 1 → Ausgang Platz 2
		"jhash ip daddr mod 2 seed 0x00000005 vmap { 0 : jump s1, 1 : jump s3 }",    // Gruppe 2 je Ziel
		"vmap { 0x41000000 : jump x1, 0x42000000 : jump x2, 0x43000000 : jump x3 }",
		"meta mark set meta mark & 0x80ffffff | 0x43000000",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("fehlt: %s\n%s", want, s)
		}
	}
	if strings.Contains(s, "g4") {
		t.Fatal("Gruppe ohne vorhandenen Ausgang darf nicht verteilt werden")
	}
	if pinScript(nil, nil) != "" {
		t.Fatal("ohne Ausgänge keine Tabelle")
	}
}

func TestRotationSettings(t *testing.T) {
	r := RotationFrom(map[string]any{"mode": "group", "min_min": 30.0, "max_min": 10.0})
	if r.MaxMin != 30 || r.DrainMin != defDrainMin || !r.FlushDNS || r.Check() != "" {
		t.Fatalf("%+v %s", r, r.Check())
	}
	if (Rotation{Mode: "group", DrainMin: 30}).Check() == "" {
		t.Fatal("ganze Gruppe ohne Zeit/Datenmenge muss abgelehnt werden")
	}
	if (Rotation{Mode: "dest", DrainMin: 30}).Check() != "" {
		t.Fatal("je Ziel ohne Wechsel ist erlaubt (feste Verteilung)")
	}
	if (Rotation{Mode: "x"}).Check() == "" || (Rotation{Mode: "group", MinMin: 5, MaxMin: 1, DrainMin: 30}).Check() == "" {
		t.Fatal("ungültige Werte durchgelassen")
	}
}

type rotFixture struct {
	m      *Manager
	env    *Env
	now    time.Time
	g      *Group
	byID   map[int64]*Exit
	events []SwitchEvent
	logs   *[]string
}

func newRotFixture(t *testing.T, mode string, standby2 bool) *rotFixture {
	env, _, logs := testEnv(t)
	f := &rotFixture{m: New(), env: env, now: time.Unix(1_800_000_000, 0), logs: logs}
	f.m.now = func() time.Time { return f.now }
	f.byID = map[int64]*Exit{1: {ID: 1, Name: "A", Enabled: true, Slot: 1, Mode: "always"}, 2: {ID: 2, Name: "B", Enabled: true, Slot: 2, Mode: "always"},
		3: {ID: 3, Name: "C", Enabled: true, Slot: 3, Mode: "always"}}
	if standby2 {
		f.byID[2].Mode = "standby"
	}
	f.g = &Group{ID: 7, Name: "G", Enabled: true, Slot: 1, Exits: []int64{1, 2, 3}, OnFail: "block", MaxLoss: 20, MaxRTT: 400,
		Rotate: Rotation{Mode: mode, MinMin: 10, MaxMin: 10, DrainMin: 5, WarmSec: 90, FlushDNS: true}}
	f.m.OnSwitch(func(ev SwitchEvent) { f.events = append(f.events, ev) })
	f.m.remember([]*Exit{f.byID[1], f.byID[2], f.byID[3]}, []*Group{f.g})
	for id := range f.byID {
		if !(standby2 && id == 2) {
			setHealth(f.m, id, true)
		}
	}
	f.m.active(env, f.g, f.byID)
	f.m.evaluate(env, f.g, f.byID)
	return f
}

func (f *rotFixture) tick(d time.Duration) {
	f.now = f.now.Add(d)
	f.m.rotate(f.env, []*Group{f.g}, f.byID, func(x *Exit) { setHealth(f.m, x.ID, true) })
	f.m.evaluate(f.env, f.g, f.byID)
}

func (f *rotFixture) status() GroupStatus { _, gs := f.m.Status(); return gs[7] }

func TestRotationGroup(t *testing.T) {
	f := newRotFixture(t, "group", true)
	if st := f.status(); st.Active != 1 {
		t.Fatalf("Start: %+v", st)
	}
	f.tick(0) // plant den Wechsel in 10 Minuten
	if st := f.status(); st.NextRotate != f.now.Add(10*time.Minute).Unix() || st.Rotate != "group" {
		t.Fatalf("Plan: %+v", st)
	}
	f.tick(8 * time.Minute) // noch kein Vorlauf (90 s vorher)
	if st := f.status(); st.Next != 0 || st.Active != 1 {
		t.Fatalf("zu früh vorbereitet: %+v", st)
	}
	f.tick(time.Minute) // 9 min: Vorlauf – Kandidat wird vorbereitet (Bereitschaft: verbunden)
	st := f.status()
	if st.Next == 0 || st.Next == 1 || st.Active != 1 {
		t.Fatalf("kein Kandidat: %+v", st)
	}
	if st.Next == 2 && !f.m.isConn(2) {
		t.Fatal("Ausgang in Bereitschaft nicht vorher verbunden")
	}
	if !f.m.neededSet()[st.Next] {
		t.Fatal("Kandidat muss verbunden bleiben")
	}
	cand := st.Next
	f.tick(time.Minute) // 10 min: Wechsel
	st = f.status()
	if st.Active != cand || st.State != "ok" {
		t.Fatalf("nicht gewechselt: %+v", st)
	}
	if len(f.events) != 1 || f.events[0].Hard || !f.events[0].Rotation {
		t.Fatalf("Ereignis: %+v", f.events)
	}
	// alter Ausgang läuft aus: bleibt genutzt (Verkehr zählt, verbunden), neue Verbindungen über den neuen
	if !containsID(st.Uses, 1) || !containsID(st.Uses, cand) {
		t.Fatalf("Uses: %v", st.Uses)
	}
	es, _ := f.m.Status()
	if es[1].Draining == 0 {
		t.Fatal("A läuft nicht aus")
	}
	if !strings.Contains(strings.Join(*f.logs, "\n"), "laufende Verbindungen bleiben") {
		t.Fatalf("Protokoll: %v", *f.logs)
	}
	// kein Zurück zum „bevorzugten“ A, obwohl A gesund ist
	f.m.mu.Lock()
	f.m.healthy["7/1"] = time.Now().Add(-time.Hour)
	f.m.mu.Unlock()
	f.tick(30 * time.Second)
	if f.status().Active != cand {
		t.Fatal("nach dem Wechsel zurück zum ersten Ausgang geschaltet")
	}
	// nach DrainMin (5 min) ist A fertig ausgelaufen
	f.tick(5 * time.Minute)
	if containsID(f.status().Uses, 1) {
		t.Fatalf("A läuft noch aus: %v", f.status().Uses)
	}
	// Jetzt wechseln
	if err := f.m.RotateNow(f.g); err != nil {
		t.Fatal(err)
	}
	f.tick(0)
	if a := f.status().Active; a == cand {
		t.Fatal("„Jetzt wechseln“ ohne Wirkung")
	}
}

func TestRotationGroupFailoverRandomAndHard(t *testing.T) {
	f := newRotFixture(t, "group", false)
	f.tick(0)
	setHealth(f.m, 1, false)
	f.m.evaluate(f.env, f.g, f.byID)
	st := f.status()
	if st.Active == 1 || st.Active == 0 || st.State != "ok" {
		t.Fatalf("Ausfall: %+v", st)
	}
	if len(f.events) != 1 || !f.events[0].Hard {
		t.Fatalf("Ausfall muss hart sein: %+v", f.events)
	}
	es, _ := f.m.Status()
	if es[1].Draining != 0 {
		t.Fatal("gestörter Ausgang darf nicht auslaufen")
	}
}

func TestRotationDest(t *testing.T) {
	f := newRotFixture(t, "dest", false)
	f.tick(0)
	st := f.status()
	if len(st.Pool) != 3 {
		t.Fatalf("Verteilung: %+v", st)
	}
	if f.env.Get("exits:pins") == "" {
		t.Fatal("Verteilung nicht geladen")
	}
	seed := f.m.rot[7].seed
	// B gestört → fällt aus der Verteilung, läuft aus
	setHealth(f.m, 2, false)
	f.tick(30 * time.Second)
	st = f.status()
	if len(st.Pool) != 2 || containsID(st.Pool, 2) {
		t.Fatalf("Verteilung ohne B: %v", st.Pool)
	}
	if f.m.rot[7].seed != seed {
		t.Fatal("Verteilung ohne Grund neu gemischt")
	}
	// nach 10 Minuten neu mischen
	f.tick(10 * time.Minute)
	if f.m.rot[7].seed == seed || len(f.events) == 0 || !f.events[len(f.events)-1].Rotation {
		t.Fatalf("nicht neu gemischt: %+v", f.events)
	}
	// alle Ausgänge der Gruppe bleiben verbunden (Bereitschaft wird geprüft und kehrt zurück)
	n := f.m.neededSet()
	if !n[1] || !n[2] || !n[3] {
		t.Fatalf("needed: %v", n)
	}
}

func containsID(l []int64, id int64) bool {
	for _, x := range l {
		if x == id {
			return true
		}
	}
	return false
}
