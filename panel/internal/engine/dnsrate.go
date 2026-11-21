package engine

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Schutz für DNS von außen (Port 53, UDP): Absender lassen sich bei UDP fälschen. Wer große Netze
// (bis 0.0.0.0/0) freigibt, betreibt einen offenen DNS-Server – der ließe sich sonst für
// Verstärkungsangriffe auf fremde Adressen missbrauchen. Deshalb je Absender (IPv4-Adresse bzw.
// IPv6-/64) höchstens extRate Anfragen je Sekunde (kurz bis extBurst), und ANY-Anfragen über UDP
// werden abgewiesen. TCP, DoH und DoT sind nicht betroffen (dort ist der Absender echt).

const (
	extRate  = 20.0 // Anfragen je Sekunde und Absender (Dauer)
	extBurst = 60.0 // kurzzeitig
	extKeys  = 20000
)

type rateBucket struct {
	tokens float64
	at     time.Time
}

type extLimiter struct {
	mu      sync.Mutex
	m       map[netip.Addr]*rateBucket
	dropped int64
}

func rateKey(a netip.Addr) netip.Addr {
	if a.Is6() && !a.Is4In6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a.Unmap()
}

// allow: darf der Absender jetzt noch eine Anfrage stellen?
func (l *extLimiter) allow(a netip.Addr, now time.Time) bool {
	k := rateKey(a)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil || len(l.m) > extKeys {
		l.m = map[netip.Addr]*rateBucket{}
	}
	b := l.m[k]
	if b == nil {
		b = &rateBucket{tokens: extBurst, at: now}
		l.m[k] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * extRate
	if b.tokens > extBurst {
		b.tokens = extBurst
	}
	b.at = now
	if b.tokens < 1 {
		l.dropped++
		return false
	}
	b.tokens--
	return true
}

// Dropped: wegen der Begrenzung verworfene Anfragen (seit dem Start).
func (l *extLimiter) Dropped() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// LargeNets: freigegebene Netze, die größer als /24 bzw. /56 sind (Warnhinweis in der Oberfläche).
func LargeNets(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a); err == nil {
			if (p.Addr().Is4() && p.Bits() < 24) || (!p.Addr().Is4() && p.Bits() < 56) {
				out = append(out, a)
			}
		}
	}
	return out
}

// queryType: Typ der ersten Frage (0 = nicht lesbar).
func queryType(query []byte) dnsmessage.Type {
	var p dnsmessage.Parser
	if _, err := p.Start(query); err == nil {
		if q, err := p.Question(); err == nil {
			return q.Type
		}
	}
	return 0
}

// refusedReply: Antwort „abgelehnt“ ohne Inhalt (kleiner als die Anfrage).
func refusedReply(query []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	return dnsReply(hdr, q, dnsmessage.RCodeRefused, nil, 0)
}
