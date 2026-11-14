package exits

import (
	"strings"
	"testing"
)

func wgExit(t *testing.T, id int64, slot int) *Exit {
	t.Helper()
	w, err := ParseWG("[Interface]\nPrivateKey = " + key('a') + "\nAddress = 100.64.1.2/32\n[Peer]\nPublicKey = " + key('b') +
		"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n")
	if err != nil {
		t.Fatal(err)
	}
	return &Exit{ID: id, Name: string(rune('A' + id - 1)), Enabled: true, Type: "wireguard", Slot: slot, WG: w, Mode: "always"}
}

// Wird der aktive Ausgang abgeschaltet (z. B. Datenlimit), schaltet Apply sofort um – nicht erst
// bei der nächsten Prüfung.
func TestApplySwitchesAwayFromDisabledExit(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	a, b := wgExit(t, 1, 1), wgExit(t, 2, 2)
	g := &Group{ID: 9, Name: "G", Enabled: true, Slot: 1, Exits: []int64{1, 2}, OnFail: "block", MaxLoss: 20, MaxRTT: 400}
	setHealth(m, 1, true)
	setHealth(m, 2, true)
	if err := m.Apply(env, []*Exit{a, b}, []*Group{g}); err != nil {
		t.Fatal(err)
	}
	m.evaluate(env, g, map[int64]*Exit{1: a, 2: b})
	if _, gs := m.Status(); gs[9].Active != 1 {
		t.Fatalf("Start: %+v", gs[9])
	}
	a.Enabled = false
	if err := m.Apply(env, []*Exit{a, b}, []*Group{g}); err != nil {
		t.Fatal(err)
	}
	if _, gs := m.Status(); gs[9].Active != 2 || gs[9].State != "failover" {
		t.Fatalf("nicht sofort umgeschaltet: %+v", gs[9])
	}
	if !strings.Contains(strings.Join(env.Sys.Log(), "\n"), "ip -4 route replace default dev ex2 table 3001") {
		t.Fatal("Route nicht umgestellt")
	}
}

// Datenlimit der Gruppe: gesperrt, auch wenn die Gruppe bei Ausfall „direkt“ ginge; danach wieder frei.
func TestGroupLimitBlocks(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	a := wgExit(t, 1, 1)
	g := &Group{ID: 9, Name: "G", Enabled: true, Slot: 1, Exits: []int64{1}, OnFail: "direct", MaxLoss: 20, MaxRTT: 400}
	setHealth(m, 1, true)
	_ = m.Apply(env, []*Exit{a}, []*Group{g})
	m.evaluate(env, g, map[int64]*Exit{1: a})
	g.Blocked = "Datenlimit 10 GB erreicht"
	_ = m.Apply(env, []*Exit{a}, []*Group{g})
	_, gs := m.Status()
	if gs[9].Active != 0 || gs[9].State != "blocked" || !gs[9].Limit || gs[9].Reason != g.Blocked {
		t.Fatalf("nicht gesperrt: %+v", gs[9])
	}
	log := strings.Join(env.Sys.Log(), "\n")
	if !strings.Contains(log, "ip -4 route replace blackhole default table 3001") {
		t.Fatalf("keine Sperr-Route:\n%s", log)
	}
	if err := m.Switch(env, g, 1, map[int64]*Exit{1: a}); err == nil {
		// Switch selbst prüft das Limit nicht – das macht die Engine; die nächste Bewertung sperrt wieder
		m.evaluate(env, g, map[int64]*Exit{1: a})
	}
	g.Blocked = ""
	_ = m.Apply(env, []*Exit{a}, []*Group{g})
	if _, gs := m.Status(); gs[9].Active != 1 || gs[9].Limit {
		t.Fatalf("nicht wieder frei: %+v", gs[9])
	}
}
