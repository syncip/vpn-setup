package store

import (
	"path/filepath"
	"testing"
)

func TestSmartTraffic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const h = int64(1_800_000_000) - int64(1_800_000_000)%86400 // Tagesbeginn (UTC)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.AddSmartTraffic(SmartVPN, h+10, 100, 1000))
	must(s.AddSmartTraffic(SmartVPN, h+3000, 1, 2)) // selbe Stunde → aufaddiert
	must(s.AddSmartTraffic(SmartProxy, h+3700, 5, 50))
	must(s.AddSmartTraffic(SmartProxy, h+3800, 0, 0)) // nichts → kein Eintrag

	ser, err := s.SmartTrafficSeries(h, h+86400, 3600)
	must(err)
	if len(ser) != 2 {
		t.Fatalf("Fenster: %d", len(ser))
	}
	if p := ser[h]; p == nil || p.VUp != 101 || p.VDown != 1002 || p.PUp != 0 {
		t.Fatalf("Stunde 1: %+v", p)
	}
	if p := ser[h+3600]; p == nil || p.PUp != 5 || p.PDown != 50 || p.VDown != 0 {
		t.Fatalf("Stunde 2: %+v", p)
	}
	// Tagesfenster: alles in einem Punkt, Schlüssel wie bei TrafficSeries
	day, err := s.SmartTrafficSeries(h, h+86400, 86400)
	must(err)
	if p := day[h]; len(day) != 1 || p.VUp != 101 || p.PDown != 50 {
		t.Fatalf("Tag: %+v", day)
	}
	up, down, err := s.SmartTrafficSum(SmartProxy, h+1800) // ab Stundenbeginn gerechnet
	must(err)
	if up != 5 || down != 50 {
		t.Fatalf("Summe Proxy: %d/%d", up, down)
	}
	must(s.PruneTraffic(h + 3600))
	if ser, _ := s.SmartTrafficSeries(h, h+86400, 3600); len(ser) != 1 || ser[h] != nil {
		t.Fatalf("nach Aufräumen: %+v", ser)
	}
}
