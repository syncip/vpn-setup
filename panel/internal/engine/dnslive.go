package engine

import (
	"sort"
	"strings"
	"time"
)

// Live-Ansicht des Panel-DNS: Anfragen je Sekunde der letzten Minuten (nur im Speicher).

const liveSecs = 600 // 10 Minuten

type liveSlot struct {
	ts                     int64
	n, bl, cached, err, ok int
	ms                     int // Summe der Antwortzeiten aufgelöster Anfragen
}

type dnsLive struct {
	slots [liveSecs]liveSlot
}

// add zählt eine Anfrage (Aufrufer hält g.mu).
func (l *dnsLive) add(ts int64, action string, ms int) {
	s := &l.slots[ts%liveSecs]
	if s.ts != ts {
		*s = liveSlot{ts: ts}
	}
	s.n++
	switch action {
	case "blocked":
		s.bl++
	case "cached":
		s.cached++
	case "error":
		s.err++
	case "ok":
		s.ok++
		s.ms += ms
	}
}

// DNSLivePoint: eine Sekunde.
type DNSLivePoint struct {
	TS     int64 `json:"ts"`
	N      int   `json:"n"`
	Bl     int   `json:"bl"`
	Cached int   `json:"cached"`
	Err    int   `json:"err"`
	MS     int   `json:"ms"` // Ø Antwortzeit aufgelöster Anfragen, 0 = keine
}

// DNSLive: Daten für die Live-Ansicht.
type DNSLive struct {
	Now       int64           `json:"now"`
	Points    []DNSLivePoint  `json:"points"`    // letzte Sekunden, ältere zuerst (auch leere)
	QPS       float64         `json:"qps"`       // Mittel der letzten 10 Sekunden
	Peak      int             `json:"peak"`      // höchster Wert im Fenster
	Clients   int             `json:"clients"`   // Geräte mit Anfragen in der letzten Minute
	Upstreams []DNSServerLive `json:"upstreams"` // DNS-Server seit dem Start
	Unbound   UnboundHealth   `json:"unbound"`
}

// DNSServerLive: ein DNS-Server mit Anteil (seit dem Start des Dienstes).
type DNSServerLive struct {
	DNSServerStat
	Name  string  `json:"name"`
	Share float64 `json:"share"` // Anteil an allen beantworteten Anfragen (%)
}

// DNSLiveData liefert die letzten secs Sekunden (höchstens 10 Minuten).
func (e *Engine) DNSLiveData(secs int) DNSLive {
	if secs <= 0 || secs > liveSecs {
		secs = 300
	}
	g := &e.dns
	now := time.Now().Unix()
	out := DNSLive{Now: now, Points: make([]DNSLivePoint, 0, secs)}
	g.mu.Lock()
	for t := now - int64(secs) + 1; t <= now; t++ {
		s := g.live.slots[t%liveSecs]
		p := DNSLivePoint{TS: t}
		if s.ts == t {
			p.N, p.Bl, p.Cached, p.Err = s.n, s.bl, s.cached, s.err
			if s.ok > 0 {
				p.MS = s.ms / s.ok
			}
		}
		out.Points = append(out.Points, p)
		if p.N > out.Peak {
			out.Peak = p.N
		}
	}
	clients := 0
	for _, last := range g.clients {
		if now-last < 60 {
			clients++
		}
	}
	g.mu.Unlock()
	out.Clients = clients
	// laufende Sekunde ist unvollständig → die 10 davor
	sum := 0
	for _, p := range out.Points[max(0, len(out.Points)-11) : len(out.Points)-1] {
		sum += p.N
	}
	out.QPS = float64(sum) / 10
	total := 0
	stats := e.DNSServerStats()
	for _, s := range stats {
		total += s.OK
	}
	out.Unbound = e.UnboundHealth()
	out.Upstreams = []DNSServerLive{}
	for _, s := range stats {
		u := DNSServerLive{DNSServerStat: s, Name: DNSServerName(s.Server)}
		if total > 0 {
			u.Share = float64(int(float64(s.OK)*1000/float64(total))) / 10
		}
		out.Upstreams = append(out.Upstreams, u)
	}
	sort.Slice(out.Upstreams, func(i, j int) bool { return out.Upstreams[i].OK > out.Upstreams[j].OK })
	return out
}

// DNSServerName: lesbarer Name eines DNS-Servers („Unbound“, „Cloudflare“, sonst die Adresse).
func DNSServerName(srv string) string {
	if srv == unboundAddr {
		return "Unbound"
	}
	host := strings.TrimSuffix(srv, ":53")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	for _, c := range DNSCandidates {
		if c.Addr == host {
			return c.Name
		}
	}
	return host
}

// RunDemoDNSLive erzeugt im Testmodus (-demo) ausgedachte Anfragen für die Live-Ansicht.
func (e *Engine) RunDemoDNSLive(stop <-chan struct{}) {
	g := &e.dns
	servers := []string{unboundAddr, "1.1.1.1:53", "9.9.9.9:53"}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	i := 0
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			i++
			n := 4 + (i*7)%9 + int(now.Unix()%5)
			if i%37 < 3 {
				n += 25 // kurze Spitze
			}
			g.mu.Lock()
			if g.srv == nil {
				g.srv = map[string]*srvStat{}
			}
			for k := 0; k < n; k++ {
				switch {
				case k%5 == 0:
					g.live.add(now.Unix(), "blocked", 0)
				case k%3 == 0:
					g.live.add(now.Unix(), "cached", 0)
				default:
					srv := servers[(k+i)%len(servers)]
					if k%4 == 0 {
						srv = servers[0]
					}
					ms := 6 + (k*13+i)%40
					g.live.add(now.Unix(), "ok", ms)
					s := g.srv[srv]
					if s == nil {
						s = &srvStat{ms: float64(ms)}
						g.srv[srv] = s
					}
					s.ok++
					s.ms = s.ms*0.9 + float64(ms)*0.1
					s.last = now
				}
			}
			g.queries += n
			g.last = now.Unix()
			g.mu.Unlock()
		}
	}
}
