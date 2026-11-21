package api

import "testing"

func TestValidLayout(t *testing.T) {
	ok := map[string]boardLayout{"overview": {Order: []string{"attention", "live"}, Hidden: []string{"version"}, Shown: []string{"dns"}, W: map[string]int{"quick": 6}},
		"chart:stats-live": {KindRate: "line", KindBytes: "bars", Unit: "bytes", Size: "l", Range: "10m", Hidden: []string{"up"}}}
	if err := validLayout(ok); err != nil {
		t.Fatalf("gültige Anordnung abgelehnt: %v", err)
	}
	bad := []map[string]boardLayout{
		{"Overview": {}}, // Großbuchstaben
		{"overview": {Order: []string{"<script>"}}},    // Sonderzeichen
		{"overview": {W: map[string]int{"quick": 13}}}, // zu breit
		{"overview": {W: map[string]int{"quick": 0}}},  // zu schmal
		{"overview": {Hidden: []string{""}}},           // leer
		{"overview": {Order: make([]string, 65)}},      // zu viele
		{"chart:x": {KindRate: "pie"}},                 // unbekannte Darstellung
		{"chart:x": {Unit: "kb"}},                      // unbekannte Einheit
		{"chart:x": {Range: "<b>"}},                    // Zeitraum
		{"graph:x": {}},                                // unbekannter Präfix
	}
	for i, m := range bad {
		if validLayout(m) == nil {
			t.Errorf("Fall %d: ungültige Anordnung angenommen", i)
		}
	}
}
