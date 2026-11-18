package exits

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"vpnpanel/internal/system"
)

func TestPinScriptOverrides(t *testing.T) {
	g := []pinGroup{{Slot: 1, Exits: []int{1}, Ov: []pinOv{{Exit: 2, Elems: []string{"192.0.2.10 timeout 3600s"}}}}}
	s := pinScript([]int{1, 2}, g)
	if p := os.Getenv("PIN_SCRIPT_OUT"); p != "" {
		_ = os.WriteFile(p+".ov", []byte(s), 0o644)
	}
	for _, want := range []string{
		"set ov1_2 {", "type ipv4_addr; flags timeout;", "elements = { 192.0.2.10 timeout 3600s }",
		"ct mark & 0x40000000 == 0x0 ip daddr @ov1_2 ct mark set ct mark & 0x80ffffff | 0x42000000",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("fehlt: %s\n%s", want, s)
		}
	}
	// die Ausnahme steht vor der normalen Zuordnung
	if strings.Index(s, "@ov1_2") > strings.Index(s, "| 0x41000000\n") {
		t.Fatalf("Reihenfolge:\n%s", s)
	}
	// Kennung ohne Inhalte: neue Adressen laden die Tabelle nicht neu
	g2 := []pinGroup{{Slot: 1, Exits: []int{1}, Ov: []pinOv{{Exit: 2, Elems: []string{"192.0.2.99 timeout 10s"}}}}}
	if pinScriptX([]int{1, 2}, g, false) != pinScriptX([]int{1, 2}, g2, false) {
		t.Fatal("Inhalte der Sets dürfen die Kennung nicht ändern")
	}
}

func TestOverrideRouteAndLearn(t *testing.T) {
	f := newRotFixture(t, "", false)
	if r := f.m.Route(7, "www.example.org"); len(r) != 3 || r[0].Exit != 1 || r[0].Over {
		t.Fatalf("ohne Ausnahme: %+v", r)
	}
	f.m.SetOverrides(f.env, map[int64]map[string]int64{7: {"example.org": 2}})
	r := f.m.Route(7, "www.Example.org.")
	if len(r) != 3 || r[0].Exit != 2 || !r[0].Over || r[0].Mark != probeMark(2) || r[1].Exit != 1 {
		t.Fatalf("mit Ausnahme: %+v", r)
	}
	if n := f.m.Natural(7, "www.example.org"); n != 1 {
		t.Fatalf("Natural: %d", n)
	}
	if r := f.m.Route(7, "example.com"); r[0].Exit != 1 {
		t.Fatal("Ausnahme gilt für fremdes Ziel")
	}
	if !strings.Contains(f.env.Get("exits:pins"), "") || !f.m.HasOverrides(7) || f.m.HasOverrides(8) {
		t.Fatal("HasOverrides")
	}
	dry := f.env.Sys.(*system.Dry)
	f.m.LearnOverride(f.env, 7, "cdn.example.org.", []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::1")})
	f.m.LearnOverride(f.env, 7, "other.net", []netip.Addr{netip.MustParseAddr("192.0.2.8")})
	in := strings.Join(dry.Stdin, "\n")
	if !strings.Contains(in, "add element inet vpnexits ov1_2 { 192.0.2.7 timeout 3600s }") || strings.Contains(in, "2001:db8") || strings.Contains(in, "192.0.2.8") {
		t.Fatalf("gelernt:\n%s", in)
	}
	// beim Neuladen der Tabelle kommen die gelernten Adressen mit
	f.m.mu.Lock()
	el := f.m.ovElementsLocked(ovKey{7, 2})
	f.m.mu.Unlock()
	if len(el) != 1 || !strings.HasPrefix(el[0], "192.0.2.7 timeout ") {
		t.Fatalf("Elemente: %v", el)
	}
	// Ausnahme aufheben → Adressen vergessen
	f.m.SetOverrides(f.env, map[int64]map[string]int64{})
	if len(f.m.ovIPs) != 0 || f.m.HasOverrides(7) {
		t.Fatal("nicht aufgehoben")
	}
}

func TestBlockCheckSettings(t *testing.T) {
	b := BlockCheckFrom(map[string]any{"on": true, "domains": []any{"https://Shop.example.net/", "bad domain"}, "top": 50.0})
	if !b.On || len(b.Domains) != 1 || b.Domains[0] != "shop.example.net" || b.Top != 50 || b.Fails != 4 || !b.Auto || !b.Realtime {
		t.Fatalf("%+v", b)
	}
	if b.Check() != "" {
		t.Fatal(b.Check())
	}
	if (BlockCheck{On: true, Fails: 4, Top: 5, OkHours: 1, BadHours: 1}).Check() == "" {
		t.Fatal("ohne Ziele und ohne automatische Ziele muss abgelehnt werden")
	}
	if got := BlockCheckFrom(b.Map()); got.Top != 50 || got.Domains[0] != "shop.example.net" {
		t.Fatalf("Rundreise: %+v", got)
	}
}

func TestBlockNeedConnectsStandby(t *testing.T) {
	f := newRotFixture(t, "", true) // B (2) in Bereitschaft
	if f.m.neededSet()[2] {
		t.Fatal("B ohne Bedarf verbunden")
	}
	f.m.SetBlockNeed(map[int64]bool{2: true})
	if !f.m.neededSet()[2] {
		t.Fatal("Block-Prüfung braucht B – muss verbunden werden")
	}
	f.m.SetBlockNeed(nil)
	if f.m.neededSet()[2] {
		t.Fatal("Bedarf nicht aufgehoben")
	}
}
