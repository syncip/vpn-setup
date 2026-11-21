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
// IPv6-/64) höchstens dns_ext_rate Anfragen je Sekunde (kurz bis dns_ext_burst), je freigegebenem
// Gerät einstellbar, und ANY-Anfragen über UDP werden abgewiesen (dns_ext_any). TCP, DoH und DoT
// sind nicht betroffen (dort ist der Absender echt).

const (
	defExtRate  = 20
	defExtBurst = 60
	extKeys     = 20000
	maxExtRate  = 100000
)

// extRateOf: wirksame Grenze eines Geräts (rate 0 = keine Begrenzung).
// own: 0 = Vorgabe, -1 = unbegrenzt, >0 = eigener Wert; ownBurst: 0 = 3 × Anfragen je Sekunde.
func extRateOf(globalRate, globalBurst, own, ownBurst int) (rate, burst float64) {
	switch {
	case own < 0:
		return 0, 0
	case own > 0:
		rate = float64(own)
		burst = float64(ownBurst)
		if burst <= 0 {
			burst = rate * 3
		}
	default:
		rate, burst = float64(globalRate), float64(globalBurst)
	}
	if rate > 0 && burst < rate {
		burst = rate
	}
	return rate, burst
}

type rateBucket struct {
	tokens float64
	at     time.Time
}

type extLimiter struct {
	mu      sync.Mutex
	m       map[netip.Addr]*rateBucket
	dropped int64
	byID    map[int64]*RateDrops // je freigegebenem Gerät
}

// RateDrops: wegen der Begrenzung verworfene Anfragen (seit dem Start des Panels).
type RateDrops struct {
	Count int64 `json:"count"`
	Last  int64 `json:"last"`
}

func rateKey(a netip.Addr) netip.Addr {
	if a.Is6() && !a.Is4In6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a.Unmap()
}

// allow: darf der Absender jetzt noch eine Anfrage stellen? (rate <= 0: immer)
func (l *extLimiter) allow(a netip.Addr, now time.Time, rate, burst float64, client int64) bool {
	if rate <= 0 {
		return true
	}
	k := rateKey(a)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil || len(l.m) > extKeys {
		l.m = map[netip.Addr]*rateBucket{}
	}
	b := l.m[k]
	if b == nil {
		b = &rateBucket{tokens: burst, at: now}
		l.m[k] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.at = now
	if b.tokens < 1 {
		l.dropped++
		if l.byID == nil {
			l.byID = map[int64]*RateDrops{}
		}
		d := l.byID[client]
		if d == nil {
			d = &RateDrops{}
			l.byID[client] = d
		}
		d.Count++
		d.Last = now.Unix()
		return false
	}
	b.tokens--
	return true
}

// Dropped: verworfene Anfragen insgesamt und je Gerät.
func (l *extLimiter) Dropped() (int64, map[int64]RateDrops) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[int64]RateDrops, len(l.byID))
	for k, v := range l.byID {
		out[k] = *v
	}
	return l.dropped, out
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

// numData: Zahl aus gespeicherten Daten (JSON liefert float64).
func numData(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}
