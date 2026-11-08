package exits

import (
	"strings"
	"testing"
	"time"

	"vpnpanel/internal/system"
)

func testEnv(t *testing.T) (*Env, map[string]string, *[]string) {
	state := map[string]string{}
	var logs []string
	return &Env{Sys: &system.Dry{Root: t.TempDir()}, Get: func(k string) string { return state[k] }, Set: func(k, v string) { state[k] = v },
		Log: func(_, msg string) { logs = append(logs, msg) }}, state, &logs
}

// setHealth trägt eine Messung ein (gut = 0 % Verlust, 30 ms, HTTPS ok).
func setHealth(m *Manager, id int64, good bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Sample{TS: time.Now().Unix(), Loss: 0, RTT: 30, OK: true}
	if !good {
		s = Sample{TS: time.Now().Unix(), Loss: 100}
	}
	st := m.status[id]
	if st == nil {
		st = &ExitStatus{ID: id}
		m.status[id] = st
	}
	st.Up = true
	st.Samples = []Sample{s, s, s, s}
	st.Loss, st.RTT = avg(st.Samples)
}

func TestFailover(t *testing.T) {
	env, state, logs := testEnv(t)
	m := New()
	switched := 0
	m.OnSwitch(func(int64) { switched++ })
	exits := map[int64]*Exit{1: {ID: 1, Name: "A", Enabled: true, Slot: 1}, 2: {ID: 2, Name: "B", Enabled: true, Slot: 2}}
	g := &Group{ID: 9, Name: "G", Enabled: true, Slot: 1, Exits: []int64{1, 2}, OnFail: "block", MaxLoss: 20, MaxRTT: 400}
	active := func() (int64, string) { _, gs := m.Status(); return gs[9].Active, gs[9].State }

	setHealth(m, 1, true)
	setHealth(m, 2, true)
	m.evaluate(env, g, exits)
	if a, s := active(); a != 1 || s != "ok" {
		t.Fatalf("Start: %d %s", a, s)
	}
	// A fällt aus → B
	setHealth(m, 1, false)
	m.evaluate(env, g, exits)
	if a, s := active(); a != 2 || s != "failover" || state["exits:active:9"] != "2" || switched != 1 {
		t.Fatalf("Ausfall: %d %s %v", a, s, state)
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "„A“ gestört") {
		t.Fatalf("Grund fehlt: %v", *logs)
	}
	// A wieder gut, aber noch nicht 10 Minuten → bleibt B
	setHealth(m, 1, true)
	m.evaluate(env, g, exits)
	if a, _ := active(); a != 2 {
		t.Fatal("zu früh zurückgeschaltet")
	}
	// 10 Minuten später → zurück zu A
	m.mu.Lock()
	m.healthy["9/1"] = time.Now().Add(-11 * time.Minute)
	m.mu.Unlock()
	m.evaluate(env, g, exits)
	if a, s := active(); a != 1 || s != "ok" {
		t.Fatalf("nicht zurück: %d %s", a, s)
	}
	// alle gestört → gesperrt (blackhole)
	setHealth(m, 1, false)
	setHealth(m, 2, false)
	m.evaluate(env, g, exits)
	if a, s := active(); a != 0 || s != "blocked" {
		t.Fatalf("alle gestört: %d %s", a, s)
	}
	log := strings.Join(env.Sys.Log(), "\n")
	if !strings.Contains(log, "ip -4 route replace blackhole default table 3001") {
		t.Fatalf("keine Sperre:\n%s", log)
	}
	// „direkt“: Tabelle leeren
	g.OnFail = "direct"
	setHealth(m, 1, true)
	m.evaluate(env, g, exits)
	setHealth(m, 1, false)
	m.evaluate(env, g, exits)
	if _, s := active(); s != "direct" || !strings.Contains(strings.Join(env.Sys.Log(), "\n"), "ip -4 route flush table 3001") {
		t.Fatalf("direkt: %s", s)
	}
}

func TestManualSwitchSticks(t *testing.T) {
	env, state, _ := testEnv(t)
	m := New()
	exits := map[int64]*Exit{1: {ID: 1, Name: "A", Enabled: true, Slot: 1}, 2: {ID: 2, Name: "B", Enabled: true, Slot: 2}}
	g := &Group{ID: 3, Name: "G", Enabled: true, Slot: 1, Exits: []int64{1, 2}, MaxLoss: 20}
	setHealth(m, 1, true)
	setHealth(m, 2, true)
	m.evaluate(env, g, exits)
	if err := m.Switch(env, g, 2, exits); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.healthy["3/1"] = time.Now().Add(-time.Hour)
	m.mu.Unlock()
	m.evaluate(env, g, exits)
	_, gs := m.Status()
	if gs[3].Active != 2 || state["exits:pin:3"] != "2" {
		t.Fatalf("Handwahl nicht behalten: %+v", gs[3])
	}
	// gewählter Ausgang fällt aus → A übernimmt, danach zurück zu B
	setHealth(m, 2, false)
	m.evaluate(env, g, exits)
	if _, gs = m.Status(); gs[3].Active != 1 {
		t.Fatal("kein Ausweichen")
	}
	setHealth(m, 2, true)
	m.mu.Lock()
	m.healthy["3/2"] = time.Now().Add(-11 * time.Minute)
	m.mu.Unlock()
	m.evaluate(env, g, exits)
	if _, gs = m.Status(); gs[3].Active != 2 {
		t.Fatal("nicht zurück zum gewählten Ausgang")
	}
	// Wahl des ersten Ausgangs hebt die Handwahl auf
	if err := m.Switch(env, g, 1, exits); err != nil || state["exits:pin:3"] != "" {
		t.Fatalf("Handwahl nicht aufgehoben: %v %q", err, state["exits:pin:3"])
	}
	if err := m.Switch(env, g, 99, exits); err == nil {
		t.Fatal("fremder Ausgang angenommen")
	}
}

// addSample hängt eine Messung an (wie Check).
func addSample(m *Manager, id int64, s Sample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.status[id]
	st.Up = true
	st.Samples = append(st.Samples, s)
	st.Loss, st.RTT = avg(st.Samples)
}

func TestSingleHiccupNoFailover(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	exits := map[int64]*Exit{1: {ID: 1, Name: "A", Enabled: true, Slot: 1}, 2: {ID: 2, Name: "B", Enabled: true, Slot: 2}}
	g := &Group{ID: 4, Name: "G", Enabled: true, Slot: 1, Exits: []int64{1, 2}, OnFail: "block", MaxLoss: 20, MaxRTT: 400}
	setHealth(m, 1, true)
	setHealth(m, 2, true)
	m.evaluate(env, g, exits)
	active := func() int64 { _, gs := m.Status(); return gs[4].Active }
	good := Sample{TS: time.Now().Unix(), Loss: 0, RTT: 30, OK: true}
	// eine Prüfung ohne HTTPS-Antwort, eine verlorene Ping-Runde → bleibt bei A
	addSample(m, 1, Sample{TS: time.Now().Unix(), Loss: 0, RTT: 30, OK: false})
	m.evaluate(env, g, exits)
	if active() != 1 {
		t.Fatal("einzelner HTTPS-Aussetzer hat umgeschaltet")
	}
	addSample(m, 1, good)
	addSample(m, 1, Sample{TS: time.Now().Unix(), Loss: 100, OK: true, RTT: 0})
	m.evaluate(env, g, exits)
	if active() != 1 {
		t.Fatal("blockierter Ping (HTTPS geht) hat umgeschaltet")
	}
	addSample(m, 1, good)
	addSample(m, 1, Sample{TS: time.Now().Unix(), Loss: 60, RTT: 30, OK: true})
	m.evaluate(env, g, exits)
	if active() != 1 {
		t.Fatal("eine verlustreiche Ping-Runde hat umgeschaltet")
	}
	// zweimal hintereinander schlecht → B
	addSample(m, 1, Sample{TS: time.Now().Unix(), Loss: 100, OK: false})
	m.evaluate(env, g, exits)
	if active() != 2 {
		t.Fatal("zwei schlechte Prüfungen hintereinander: kein Umschalten")
	}
}

func TestSafetyRoute(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	g := &Group{ID: 4, Name: "G", Enabled: true, Slot: 3, OnFail: "block"}
	m.routeGroup(env, g, 1)
	log := strings.Join(env.Sys.Log(), "\n")
	if !strings.Contains(log, "ip -4 route replace blackhole default metric 10000 table 3003") ||
		!strings.Contains(log, "ip -4 route replace default dev ex1 table 3003") {
		t.Fatalf("Sicherung fehlt:\n%s", log)
	}
	g.OnFail = "direct"
	m.routeGroup(env, g, 1)
	if log = strings.Join(env.Sys.Log(), "\n"); !strings.Contains(log, "ip -4 route del blackhole default metric 10000 table 3003") {
		t.Fatalf("Sicherung bei „direkt“ nicht entfernt:\n%s", log)
	}
}
