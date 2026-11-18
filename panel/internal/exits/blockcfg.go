package exits

import (
	"fmt"
	"strings"
)

// BlockCheck: Block-Prüfung einer Gruppe. Ziele (Domains) werden über jeden Ausgang der Gruppe
// geprüft; sperrt ein Ziel einen Ausgang (Captcha, Sperrseite, Fehlversuche in Folge), läuft es über
// einen anderen Ausgang der Gruppe. Ergebnisse stehen in der Datenbank und werden nur in großen
// Abständen erneuert (OkHours bzw. BadHours) – nicht alle paar Minuten.
type BlockCheck struct {
	On       bool     `json:"on"`
	Domains  []string `json:"domains"`   // fest eingetragene Ziele
	Auto     bool     `json:"auto"`      // dazu die meistbesuchten Ziele der Gruppe (DNS-Protokoll)
	Top      int      `json:"top"`       // wie viele davon
	OkHours  int      `json:"ok_hours"`  // „erreichbar“ erneut prüfen nach … Stunden
	BadHours int      `json:"bad_hours"` // „gesperrt“ erneut prüfen nach … Stunden
	Fails    int      `json:"fails"`     // Fehlversuche in Folge, ab denen ein Ausgang als gesperrt gilt
	Realtime bool     `json:"realtime"`  // Proxy weicht beim Verbindungsfehler sofort auf einen anderen Ausgang aus
}

const (
	defBlockTop   = 20
	defBlockOk    = 24
	defBlockBad   = 6
	defBlockFails = 4
)

// BlockCheckFrom liest die Einstellung (Data["block"]) und setzt Vorgaben.
func BlockCheckFrom(v any) BlockCheck {
	b := BlockCheck{Top: defBlockTop, OkHours: defBlockOk, BadHours: defBlockBad, Fails: defBlockFails, Auto: true, Realtime: true}
	m, ok := v.(map[string]any)
	if !ok {
		return b
	}
	b.On, _ = m["on"].(bool)
	if x, ok := m["auto"].(bool); ok {
		b.Auto = x
	}
	if x, ok := m["realtime"].(bool); ok {
		b.Realtime = x
	}
	num := func(k string, def int) int {
		switch f := m[k].(type) {
		case float64:
			if f > 0 {
				return int(f)
			}
		case int:
			if f > 0 {
				return f
			}
		}
		return def
	}
	b.Top, b.OkHours, b.BadHours, b.Fails = num("top", defBlockTop), num("ok_hours", defBlockOk), num("bad_hours", defBlockBad), num("fails", defBlockFails)
	if l, ok := m["domains"].([]any); ok {
		for _, d := range l {
			if s, ok := d.(string); ok {
				if s = NormDomain(s); s != "" {
					b.Domains = append(b.Domains, s)
				}
			}
		}
	}
	return b
}

// NormDomain: „https://www.Example.org/x“ → „www.example.org“; leer bei Unsinn.
func NormDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#:"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "*."), ".")
	if s == "" || !strings.Contains(s, ".") || len(s) > 253 {
		return ""
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return ""
		}
	}
	return s
}

// Map: zum Speichern in Data["block"].
func (b BlockCheck) Map() map[string]any {
	d := make([]any, 0, len(b.Domains))
	for _, s := range b.Domains {
		d = append(d, s)
	}
	return map[string]any{"on": b.On, "domains": d, "auto": b.Auto, "top": b.Top, "ok_hours": b.OkHours,
		"bad_hours": b.BadHours, "fails": b.Fails, "realtime": b.Realtime}
}

// Check: Fehlertext oder "".
func (b BlockCheck) Check() string {
	switch {
	case !b.On:
		return ""
	case len(b.Domains) == 0 && !b.Auto:
		return "Block-Prüfung: Ziele eintragen oder „meistbesuchte Ziele“ einschalten"
	case b.Top < 1 || b.Top > 200:
		return "Block-Prüfung: 1 bis 200 meistbesuchte Ziele"
	case b.OkHours < 1 || b.OkHours > 24*30 || b.BadHours < 1 || b.BadHours > 24*30:
		return "Block-Prüfung: Abstand der Prüfungen 1 Stunde bis 30 Tage"
	case b.Fails < 1 || b.Fails > 20:
		return "Block-Prüfung: 1 bis 20 Fehlversuche"
	case len(b.Domains) > 500:
		return fmt.Sprintf("Block-Prüfung: höchstens 500 Ziele (%d)", len(b.Domains))
	}
	return ""
}
