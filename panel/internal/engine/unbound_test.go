package engine

import (
	"strings"
	"testing"
)

// TestUnboundSkip: nach zwei Fehlschlägen in Folge wird Unbound übersprungen (solange Ersatz da
// ist), ein Erfolg dazwischen setzt die Zählung zurück.
func TestUnboundSkip(t *testing.T) {
	var g dnsGate
	list := []string{unboundAddr, "1.1.1.1:53"}
	if got := g.skipDown(list); len(got) != 2 {
		t.Fatalf("ohne Ausfall: %v", got)
	}
	g.ub.note(false)
	g.ub.note(true)
	g.ub.note(false)
	if g.ub.down.Load() {
		t.Fatal("Erfolg dazwischen muss die Zählung zurücksetzen")
	}
	g.ub.note(false)
	if !g.ub.down.Load() {
		t.Fatal("zwei Fehlschläge in Folge: nicht übersprungen")
	}
	if got := g.skipDown(list); strings.Join(got, ",") != "1.1.1.1:53" {
		t.Errorf("übersprungen: %v", got)
	}
	if got := g.skipDown([]string{unboundAddr}); len(got) != 1 {
		t.Errorf("ohne Ersatz bleibt Unbound: %v", got)
	}
	if q := probeRoot(); len(q) != 17 || q[2] != 1 || q[14] != 2 {
		t.Errorf("Prüfanfrage: %x", q)
	}
}
