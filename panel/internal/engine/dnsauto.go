package engine

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Auflösung über Unbound und automatische Wahl der schnellsten DNS-Server.

const (
	unboundAddr = "127.0.0.1:5335"
	unboundConf = "/etc/unbound/unbound.conf.d/vpnpanel.conf"
	unboundBin  = "/usr/sbin/unbound"
)

// ---------- Unbound ----------

// unboundInstalled: Paket vorhanden (Trockenlauf: immer).
func (e *Engine) unboundInstalled() bool {
	return e.Sys.DryRun() || e.Sys.Exists(unboundBin)
}

// UnboundInstalled: für die Oberfläche.
func (e *Engine) UnboundInstalled() bool { return e.unboundInstalled() }

// useUnbound: Namen selbst auflösen (rekursiv über Unbound) statt öffentliche DNS-Server zu fragen.
func (e *Engine) useUnbound() bool {
	return e.Setting("dns_resolver") == "unbound" && e.unboundInstalled()
}

func (e *Engine) unboundConfig() string {
	cache := atoi(e.Setting("dns_cache_size"), dnsCacheMax)
	msgMB := min(256, max(8, cache/2000)) // ~2 KB je Antwort
	return fmt.Sprintf(`# Vom VPN-Panel geschrieben – Änderungen gehen beim nächsten Anwenden verloren.
server:
    interface: 127.0.0.1@5335
    port: 5335
    do-ip6: yes
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 3600
    msg-cache-size: %dm
    rrset-cache-size: %dm
    cache-min-ttl: 0
    cache-max-ttl: 86400
    so-reuseport: yes
    num-threads: 2
    verbosity: 0
`, msgMB, msgMB*2)
}

// applyUnbound schreibt die Konfiguration und startet den Dienst (bzw. hält ihn an, wenn er nicht
// gebraucht wird – das Paket bleibt installiert).
func (e *Engine) applyUnbound() {
	want := e.Setting("dns_enabled") == "1" && e.Setting("dns_resolver") == "unbound"
	if !want {
		if e.Sys.Exists(unboundConf) {
			_ = e.Sys.Remove(unboundConf)
			_, _ = e.Sys.Run("systemctl", "disable", "--now", "unbound")
		}
		e.setErr("unbound", "")
		return
	}
	if !e.unboundInstalled() {
		e.setErr("unbound", "Unbound ist nicht installiert – Setup-Script erneut ausführen (installiert das Paket „unbound“). Bis dahin fragt der Panel-DNS die eingestellten DNS-Server.")
		return
	}
	changed, err := e.Sys.WriteFile(unboundConf, []byte(e.unboundConfig()), 0o644)
	if err != nil {
		e.setErr("unbound", "Unbound: "+err.Error())
		return
	}
	if msg := e.ensureRootKey(); msg != "" {
		e.setErr("unbound", msg)
		return
	}
	if out, err := e.Sys.Run("unbound-checkconf"); err != nil {
		e.setErr("unbound", "Unbound-Konfiguration fehlerhaft: "+strings.TrimSpace(out))
		return
	}
	act := "start"
	if changed {
		act = "restart"
	}
	_, _ = e.Sys.Run("systemctl", "enable", "unbound")
	if out, err := e.Sys.Run("systemctl", act, "unbound"); err != nil {
		e.setErr("unbound", "Unbound startet nicht: "+strings.TrimSpace(out))
		return
	}
	e.setErr("unbound", "")
}

// ---------- Liste für den Speedtest ----------

// DNSCandidateList: Server für Speedtest und automatische Wahl (Einstellung dns_candidates,
// eine Zeile je Server: „Adresse Name“; leer = die eingebaute Liste).
func (e *Engine) DNSCandidateList() []DNSCandidate {
	v := strings.TrimSpace(e.Setting("dns_candidates"))
	if v == "" {
		return append([]DNSCandidate(nil), DNSCandidates...)
	}
	list, _ := ParseCandidates(v)
	return list
}

// ParseCandidates liest die Liste („Adresse Name“ je Zeile).
func ParseCandidates(v string) ([]DNSCandidate, error) {
	var out []DNSCandidate
	seen := map[string]bool{}
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		addr, name, _ := strings.Cut(line, " ")
		list, err := ParseUpstream(addr)
		if err != nil || len(list) != 1 {
			return nil, fmt.Errorf("DNS-Server „%s“: bitte eine IP-Adresse (optional mit Port)", addr)
		}
		addr = list[0]
		if ap, err := netip.ParseAddrPort(addr); err == nil && ap.Addr().IsLoopback() {
			return nil, fmt.Errorf("„%s“: lokale Adressen gehören nicht in die Liste (Unbound wird von selbst gemessen)", addr)
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		name = strings.TrimSpace(name)
		if len(name) > 40 {
			name = name[:40]
		}
		if name == "" {
			name = addr
		}
		out = append(out, DNSCandidate{Addr: addr, Name: name})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("mindestens einen DNS-Server in der Liste lassen")
	}
	if len(out) > 30 {
		return nil, fmt.Errorf("höchstens 30 DNS-Server in der Liste")
	}
	return out, nil
}

// CandidatesText: Liste als Text für die Einstellung.
func CandidatesText(l []DNSCandidate) string {
	var b strings.Builder
	for _, c := range l {
		fmt.Fprintf(&b, "%s %s\n", c.Addr, c.Name)
	}
	return strings.TrimSpace(b.String())
}

// ---------- automatische Wahl ----------

// DNSAutoResult: letzter automatischer Test.
type DNSAutoResult struct {
	At      int64    `json:"at"`
	Chosen  []string `json:"chosen"`  // gewählte Server
	Before  []string `json:"before"`  // vorher eingestellt
	Changed bool     `json:"changed"` // Einstellung geändert
	Reason  string   `json:"reason"`
	BestMS  float64  `json:"best_ms"`
	OldMS   float64  `json:"old_ms"`
}

func (e *Engine) DNSAutoLast() *DNSAutoResult {
	var r DNSAutoResult
	if json.Unmarshal([]byte(e.St.GetSetting("state:dns_auto", "")), &r) != nil || r.At == 0 {
		return nil
	}
	return &r
}

// speedScore: Bewertung aus bekannten und zufälligen Namen (kleiner = besser).
func speedScore(s DNSSpeed) float64 { return s.Median + s.Uncached/4 }

// pickFastest wählt aus dem Speedtest die n schnellsten Server und entscheidet, ob gewechselt wird:
// nur wenn die neue Auswahl mindestens 15 % schneller ist (oder ein bisheriger Server nicht antwortet),
// damit kleine Messschwankungen nicht ständig umschalten.
func pickFastest(res []DNSSpeed, current []string, n int) (chosen []string, change bool, reason string, best, old float64) {
	byAddr := map[string]DNSSpeed{}
	for _, s := range res {
		byAddr[hostPort53(s.Addr)] = s
	}
	for _, s := range res {
		if ap, err := netip.ParseAddrPort(hostPort53(s.Addr)); err == nil && ap.Addr().IsLoopback() {
			continue // Unbound ist kein Upstream
		}
		if s.OK == 0 || s.OK*2 < s.Total || len(chosen) >= n {
			continue
		}
		chosen = append(chosen, s.Addr)
		best += speedScore(s)
	}
	if len(chosen) == 0 {
		return nil, false, "kein DNS-Server hat zuverlässig geantwortet – Einstellung bleibt", 0, 0
	}
	best /= float64(len(chosen))
	dead := false
	for _, c := range current {
		s, ok := byAddr[hostPort53(c)]
		if !ok {
			continue
		}
		if s.OK == 0 || s.OK*2 < s.Total {
			dead = true
			continue
		}
		old += speedScore(s)
	}
	if len(current) > 0 && !dead {
		old /= float64(len(current))
	}
	same := len(chosen) == len(current)
	for i := range chosen {
		if same && hostPort53(chosen[i]) != hostPort53(current[i]) {
			same = false
		}
	}
	switch {
	case same:
		return chosen, false, "die eingestellten Server sind bereits die schnellsten", best, old
	case dead:
		return chosen, true, "ein eingestellter Server antwortet nicht zuverlässig", best, old
	case old > 0 && best > old*0.85:
		return chosen, false, fmt.Sprintf("schnellere Auswahl wäre nur %.0f %% besser – Einstellung bleibt", (1-best/old)*100), best, old
	}
	return chosen, true, "schnellere DNS-Server gefunden", best, old
}

// RunDNSAuto prüft, ob ein automatischer Test fällig ist (jede Minute aufgerufen), bzw. führt ihn aus.
func (e *Engine) RunDNSAuto(force bool) *DNSAutoResult {
	if !force && (e.Setting("dns_auto") != "1" || e.Setting("dns_enabled") != "1" || e.Sys.DryRun()) {
		return nil
	}
	hours := max(1, atoi(e.Setting("dns_auto_hours"), 24))
	if last := e.DNSAutoLast(); !force && last != nil && time.Since(time.Unix(last.At, 0)) < time.Duration(hours)*time.Hour {
		return nil
	}
	n := min(4, max(1, atoi(e.Setting("dns_auto_count"), 2)))
	current, _ := ParseUpstream(e.Setting("dns_upstream"))
	res := e.DNSSpeedTest(nil)
	chosen, change, reason, best, old := pickFastest(res, current, n)
	r := &DNSAutoResult{At: time.Now().Unix(), Chosen: chosen, Before: current, Reason: reason, BestMS: round1(best), OldMS: round1(old)}
	if change {
		v, err := ValidateSetting("dns_upstream", strings.Join(chosen, ", "))
		if err == nil && e.St.SetSetting("dns_upstream", v) == nil {
			r.Changed = true
			e.Log("info", fmt.Sprintf("DNS-Server automatisch gewechselt: %s → %s (%s; Ø %.0f → %.0f ms)",
				strings.Join(current, ", "), v, reason, old, best))
			e.RequestApply()
		}
	}
	if r.Chosen == nil {
		r.Chosen = []string{}
	}
	b, _ := json.Marshal(r)
	_ = e.St.SetSetting("state:dns_auto", string(b))
	return r
}

func round1(f float64) float64 { return float64(int(f*10)) / 10 }
