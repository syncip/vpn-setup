package exits

import (
	"strings"
	"testing"

	"vpnpanel/internal/system"
)

// TestStandby: Ausgänge in Bereitschaft sind nur verbunden, solange eine Gruppe sie nutzt; sonst
// werden sie zur fälligen Prüfung kurz verbunden und wieder getrennt. Beim Umschalten wird zuerst verbunden.
func TestStandby(t *testing.T) {
	env, _, _ := testEnv(t)
	dry := env.Sys.(*system.Dry)
	m := New()
	a := &Exit{ID: 1, Name: "A", Enabled: true, Slot: 1, Mode: "standby", CheckMin: 30}
	b := &Exit{ID: 2, Name: "B", Enabled: true, Slot: 2, Mode: "standby", CheckMin: 30}
	c := &Exit{ID: 3, Name: "C", Enabled: true, Slot: 3, Mode: "always", CheckMin: 30}
	g := &Group{ID: 9, Name: "G", Enabled: true, Slot: 1, Exits: []int64{1, 2}, OnFail: "block", MaxLoss: 20, MaxRTT: 400}
	list := []*Exit{a, b, c}

	m.Check(env, list, []*Group{g}, 0)
	es, gs := m.Status()
	if gs[9].Active != 1 || !m.isConn(1) || m.isConn(2) {
		t.Fatalf("Start: aktiv %d, A %v, B %v", gs[9].Active, m.isConn(1), m.isConn(2))
	}
	if es[2].Checked == 0 || es[2].Connected || es[2].NextCheck == 0 || !es[2].Standby {
		t.Errorf("B nicht geprüft bzw. nicht getrennt: %+v", es[2])
	}
	if !strings.Contains(strings.Join(dry.Log(), "\n"), "ip link del dev ex2") {
		t.Error("B nach der Prüfung nicht getrennt")
	}
	// gleich nochmal: B ist nicht fällig → keine neue Messung
	before := len(es[2].Samples)
	m.Check(env, list, []*Group{g}, 0)
	if es, _ := m.Status(); len(es[2].Samples) != before {
		t.Error("B geprüft, obwohl nicht fällig")
	}
	// „Jetzt prüfen“ prüft auch B
	m.CheckAll(env, list, []*Group{g}, 0)
	if es, _ := m.Status(); len(es[2].Samples) != before+1 || m.isConn(2) {
		t.Error("Jetzt prüfen: B nicht geprüft bzw. verbunden geblieben")
	}
	// A fällt aus → B wird verbunden und übernimmt
	setHealth(m, 1, false)
	setHealth(m, 2, true)
	m.evaluate(env, g, map[int64]*Exit{1: a, 2: b})
	if _, gs := m.Status(); gs[9].Active != 2 || !m.isConn(2) {
		t.Fatalf("Umschalten: aktiv %d, B verbunden %v", gs[9].Active, m.isConn(2))
	}
	// von Hand zurück auf A: A wird verbunden
	m.setConn(1, false)
	if err := m.Switch(env, g, 1, map[int64]*Exit{1: a, 2: b}); err != nil || !m.isConn(1) {
		t.Fatalf("Switch: %v %v", err, m.isConn(1))
	}
}
