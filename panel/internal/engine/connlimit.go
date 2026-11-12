package engine

import (
	"fmt"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// connLimit begrenzt gleichzeitige Verbindungen eines Dienstes – insgesamt und je Absenderadresse.
// Ohne Grenze könnte jemand von außen mit vielen offenen (und stillen) Verbindungen Dateideskriptoren
// und Speicher des Panels aufbrauchen (DNS über TCP, DoT).
type connLimit struct {
	mu       sync.Mutex
	total    int
	perIP    map[netip.Addr]int
	maxTotal int
	maxPerIP int
}

func newConnLimit(maxTotal, maxPerIP int) *connLimit {
	return &connLimit{perIP: map[netip.Addr]int{}, maxTotal: maxTotal, maxPerIP: maxPerIP}
}

// acquire: Platz für eine Verbindung von ip? Bei true gehört ein release dazu.
func (l *connLimit) acquire(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.perIP[ip] >= l.maxPerIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

func (l *connLimit) release(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}

// DNS über TCP (Port 53) und DoT (Port 853): Grenzen für gleichzeitige Verbindungen.
var (
	dnsTCPLimit = newConnLimit(512, 32)
	dotLimit    = newConnLimit(512, 64)
)

// guard fängt einen Absturz in der Bearbeitung einer einzelnen Anfrage von außen ab (defer): Ein
// unerwarteter Fehler bei einem Paket darf nicht das ganze Panel beenden. Gemeldet wird gedrosselt.
func (e *Engine) guard(where string) {
	if r := recover(); r != nil {
		guardMu.Lock()
		quiet := time.Since(guardLast) < time.Minute
		if !quiet {
			guardLast = time.Now()
		}
		guardMu.Unlock()
		if !quiet {
			e.Log("error", fmt.Sprintf("Interner Fehler in %s abgefangen: %v\n%s", where, r, firstLines(string(debug.Stack()), 12)))
		}
	}
}

var (
	guardMu   sync.Mutex
	guardLast time.Time
)

func firstLines(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, "\n")
}
