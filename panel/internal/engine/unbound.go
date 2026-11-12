package engine

import (
	"crypto/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Selbstprüfung von Unbound: Fällt er aus, fragt der Panel-DNS gleich die Ersatz-Server (statt bei
// jeder Anfrage erst 3 Sekunden auf Unbound zu warten), zeigt den Grund an und versucht alle
// 5 Minuten, ihn wieder zu starten.

const (
	unboundKey    = "/var/lib/unbound/root.key" // DNSSEC-Vertrauensanker (auto-trust-anchor-file von Debian)
	dnsRootKey    = "/usr/share/dns/root.key"   // aus dem Paket dns-root-data
	unboundAnchor = "/usr/sbin/unbound-anchor"
	unboundEvery  = 20 * time.Second
	unboundFixGap = 5 * time.Minute
)

// UnboundHealth: Zustand für die Oberfläche.
type UnboundHealth struct {
	On      bool   `json:"on"` // als Resolver gewählt und DNS an
	OK      bool   `json:"ok"`
	Why     string `json:"why,omitempty"`
	Detail  string `json:"detail,omitempty"` // letzte Zeilen aus dem Journal
	Checked int64  `json:"checked"`
	MS      int    `json:"ms,omitempty"`
}

type unboundState struct {
	down    atomic.Bool  // übersprungen, bis die Prüfung wieder eine Antwort bekommt
	fails   atomic.Int32 // Fehlschläge in Folge bei echten Anfragen
	mu      sync.Mutex
	h       UnboundHealth
	lastFix time.Time
}

// note: Ergebnis einer echten Anfrage an Unbound; nach zwei Fehlschlägen in Folge überspringen.
func (u *unboundState) note(ok bool) {
	if ok {
		u.fails.Store(0)
		return
	}
	if u.fails.Add(1) >= 2 {
		u.down.Store(true)
	}
}

// skipDown: Unbound aus der Liste nehmen, solange er ausgefallen ist (nur wenn Ersatz da ist).
func (g *dnsGate) skipDown(servers []string) []string {
	if !g.ub.down.Load() || len(servers) < 2 {
		return servers
	}
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if s != unboundAddr {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return servers
	}
	return out
}

// UnboundHealth: letzter Prüfstand.
func (e *Engine) UnboundHealth() UnboundHealth {
	u := &e.dns.ub
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.h
}

// RunUnbound prüft Unbound regelmäßig.
func (e *Engine) RunUnbound(stop <-chan struct{}) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		e.checkUnbound()
		t.Reset(unboundEvery)
	}
}

// probeRoot: Anfrage „. NS“ – beantwortet Unbound nach dem Start sofort aus dem Speicher.
func probeRoot() []byte {
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	_, _ = rand.Read(q[:2])
	return q
}

func (e *Engine) checkUnbound() {
	u := &e.dns.ub
	h := UnboundHealth{On: e.Setting("dns_enabled") == "1" && e.useUnbound(), Checked: time.Now().Unix()}
	switch {
	case !h.On:
		u.down.Store(false)
		u.fails.Store(0)
	case e.Sys.DryRun():
		h.OK, h.Why = true, "Testmodus – Unbound wird nicht gefragt"
	default:
		t := time.Now()
		resp := exchangeOne(probeRoot(), unboundAddr, 0, false, 2*time.Second)
		if resp != nil && resp[3]&0x0f != 2 { // nicht SERVFAIL
			h.OK, h.MS = true, int(time.Since(t).Milliseconds())
			u.fails.Store(0)
			u.down.Store(false)
			break
		}
		u.down.Store(true)
		switch {
		case resp != nil:
			h.Why = "Unbound antwortet mit SERVFAIL – meist DNSSEC (Uhrzeit, Vertrauensanker) oder keine Verbindung ins Internet."
		case !e.unboundActive():
			h.Why = "Der Dienst „unbound“ läuft nicht."
		default:
			h.Why = "Unbound antwortet nicht (Zeitüberschreitung) – erreicht er die DNS-Server im Internet (UDP/TCP 53 nach außen)?"
		}
		// selbst reparieren: Vertrauensanker anlegen, Konfiguration prüfen, Dienst starten
		u.mu.Lock()
		fix := time.Since(u.lastFix) > unboundFixGap
		if fix {
			u.lastFix = time.Now()
		}
		u.mu.Unlock()
		if fix {
			e.applyUnbound()
			if msg := e.Errors()["unbound"]; msg != "" {
				h.Why = msg
			}
		}
		h.Detail = e.unboundJournal()
		if !e.unboundActive() {
			h.Why += " Anfragen gehen solange an die Ersatz-DNS-Server."
		}
	}
	u.mu.Lock()
	u.h = h
	u.mu.Unlock()
}

func (e *Engine) unboundActive() bool {
	out, _ := e.Sys.Run("systemctl", "is-active", "unbound")
	return strings.TrimSpace(out) == "active"
}

// unboundJournal: die letzten Meldungen des Dienstes (Fehler zuerst interessant).
func (e *Engine) unboundJournal() string {
	out, _ := e.Sys.Run("journalctl", "-u", "unbound", "-n", "8", "--no-pager", "-o", "cat")
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// ensureRootKey: DNSSEC-Vertrauensanker anlegen, falls er fehlt (Debian installiert die Pakete dafür
// nur als Empfehlung). Liefert eine Fehlermeldung, wenn das nicht geht.
func (e *Engine) ensureRootKey() string {
	if e.Sys.DryRun() || e.Sys.Exists(unboundKey) {
		return ""
	}
	if e.Sys.Exists(dnsRootKey) {
		_, _ = e.Sys.Run("install", "-o", "unbound", "-g", "unbound", "-m", "644", dnsRootKey, unboundKey)
	} else if e.Sys.Exists(unboundAnchor) {
		_, _ = e.Sys.Run(unboundAnchor, "-a", unboundKey) // Exit 1 heißt „neu geschrieben“
		_, _ = e.Sys.Run("chown", "unbound:unbound", unboundKey)
	}
	if e.Sys.Exists(unboundKey) {
		e.Log("info", "Unbound: DNSSEC-Vertrauensanker angelegt ("+unboundKey+")")
		return ""
	}
	return "Unbound: DNSSEC-Vertrauensanker " + unboundKey + " fehlt. Im Container „apt install dns-root-data“ ausführen (oder das Setup-Script erneut) – bis dahin fragt der Panel-DNS die Ersatz-DNS-Server."
}
