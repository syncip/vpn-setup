package api

import "testing"

func TestValidLayout(t *testing.T) {
	ok := map[string]boardLayout{"overview": {Order: []string{"attention", "live"}, Hidden: []string{"version"}, W: map[string]int{"quick": 6}}}
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
	}
	for i, m := range bad {
		if validLayout(m) == nil {
			t.Errorf("Fall %d: ungültige Anordnung angenommen", i)
		}
	}
}
