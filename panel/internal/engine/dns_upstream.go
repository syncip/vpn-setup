package engine

// Panel-DNS: Weiterreichen an Upstream-Server, Server-Statistik und DNS-Speedtest.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
)

// ---------- Weiterreichen ----------

// dnsExchange schickt die Anfrage unverändert an den ersten Server, der antwortet.
func dnsExchange(query []byte, servers []string, mark uint32, tcp bool) []byte {
	for _, srv := range servers {
		if resp := exchangeOne(query, srv, mark, tcp, dnsTimeout); resp != nil {
			return resp
		}
	}
	return nil
}

// exchangeOne: eine Anfrage an einen Server (nil = keine passende Antwort).
func exchangeOne(query []byte, srv string, mark uint32, tcp bool, timeout time.Duration) []byte {
	// Lokale Ziele (Unbound der Gruppe auf 127.0.0.1) brauchen keine Markierung: die Tabelle „local“
	// greift ohnehin zuerst, und ohne CAP_NET_ADMIN schlüge SO_MARK fehl.
	if ap, err := netip.ParseAddrPort(srv); err == nil && ap.Addr().IsLoopback() {
		mark = 0
	}
	d := exits.Dialer(mark)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	network := "udp"
	if tcp {
		network = "tcp"
	}
	if mark != 0 { // Ausgänge können nur IPv4
		network += "4"
	}
	c, err := d.DialContext(ctx, network, srv)
	cancel()
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	var resp []byte
	if tcp {
		if writeFrame(c, query) == nil {
			resp, _ = readFrame(c)
		}
	} else if _, err := c.Write(query); err == nil {
		buf := make([]byte, 4096)
		if n, err := c.Read(buf); err == nil && n >= 12 {
			resp = buf[:n]
		}
	}
	if len(resp) >= 12 && resp[0] == query[0] && resp[1] == query[1] {
		return resp
	}
	return nil
}

// exchange verteilt die Anfrage nach der eingestellten Strategie:
//   - order: der Reihe nach (zweiter Server nur, wenn der erste nicht antwortet)
//   - fastest: zuerst der Server mit der besten gemessenen Antwortzeit; jede 20. Anfrage geht an
//     die anderen, damit deren Messung aktuell bleibt
//   - roundrobin: reihum
//   - parallel: an bis zu drei Server gleichzeitig, die erste Antwort gilt (am schnellsten, mehr Last)
func (g *dnsGate) exchange(query []byte, servers []string, mark uint32, tcp bool) ([]byte, string) {
	servers = g.skipDown(servers)
	if len(servers) <= 1 {
		return g.measure(query, servers, mark, tcp)
	}
	g.mu.Lock()
	strategy := g.strategy
	g.rr++
	n := g.rr
	order := append([]string(nil), servers...)
	switch strategy {
	case "roundrobin":
		k := int(n) % len(order)
		order = append(order[k:], order[:k]...)
	case "fastest":
		if n%20 == 0 {
			k := int(n/20) % len(order)
			order = append(order[k:], order[:k]...)
		} else {
			sort.SliceStable(order, func(i, j int) bool { return g.score(order[i]) < g.score(order[j]) })
		}
	}
	g.mu.Unlock()
	if strategy != "parallel" {
		return g.measure(query, order, mark, tcp)
	}
	if len(order) > 3 {
		order = order[:3]
	}
	type res struct {
		b   []byte
		srv string
	}
	ch := make(chan res, len(order))
	for _, srv := range order {
		go func(srv string) {
			b, s := g.measure(query, []string{srv}, mark, tcp)
			ch <- res{b, s}
		}(srv)
	}
	last := ""
	for range order {
		if r := <-ch; r.b != nil {
			return r.b, r.srv
		} else {
			last = r.srv
		}
	}
	return nil, last
}

// score: erwartete Antwortzeit (unbekannte Server zuerst ausprobieren, Ausfälle bestrafen).
func (g *dnsGate) score(srv string) float64 {
	s := g.srv[srv]
	if s == nil {
		return 0
	}
	return s.ms
}

// measure fragt der Reihe nach und merkt sich Antwortzeiten bzw. Ausfälle je Server.
func (g *dnsGate) measure(query []byte, servers []string, mark uint32, tcp bool) ([]byte, string) {
	last := ""
	for _, srv := range servers {
		last = srv
		t := time.Now()
		resp := exchangeOne(query, srv, mark, tcp, dnsTimeout)
		ms := float64(time.Since(t).Microseconds()) / 1000
		if st := g.ubStateOf(srv); st != nil {
			st.note(resp != nil)
		}
		g.mu.Lock()
		if g.srv == nil {
			g.srv = map[string]*srvStat{}
		}
		s := g.srv[srv]
		if s == nil {
			s = &srvStat{ms: ms}
			g.srv[srv] = s
		}
		s.last = time.Now()
		if resp != nil {
			s.ok++
			s.ms = s.ms*0.8 + ms*0.2
		} else {
			s.fail++
			s.ms = s.ms*0.5 + float64(dnsTimeout.Milliseconds())*0.5
		}
		g.mu.Unlock()
		if resp != nil {
			return resp, srv
		}
	}
	return nil, last
}

// DNSServerStat: gemessene Werte eines DNS-Servers im laufenden Betrieb (für die Oberfläche).
type DNSServerStat struct {
	Server string  `json:"server"`
	MS     float64 `json:"ms"`
	OK     int     `json:"ok"`
	Fail   int     `json:"fail"`
	Last   int64   `json:"last"`
}

// DNSServerStats: Antwortzeiten der benutzten DNS-Server seit dem Start.
func (e *Engine) DNSServerStats() []DNSServerStat {
	g := &e.dns
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []DNSServerStat{}
	for k, s := range g.srv {
		out = append(out, DNSServerStat{Server: k, MS: float64(int(s.ms*10)) / 10, OK: s.ok, Fail: s.fail, Last: s.last.Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MS < out[j].MS })
	return out
}

// ---------- DNS-Speedtest ----------

// DNSCandidate: öffentlicher DNS-Server für den Speedtest.
type DNSCandidate struct {
	Addr string `json:"addr"`
	Name string `json:"name"`
	Note string `json:"note"`
}

// DNSCandidates: bekannte DNS-Server mit normalem DNS (Port 53).
var DNSCandidates = []DNSCandidate{
	{"1.1.1.1", "Cloudflare", "schnell, protokolliert kaum"},
	{"1.0.0.1", "Cloudflare (2)", ""},
	{"8.8.8.8", "Google", ""},
	{"8.8.4.4", "Google (2)", ""},
	{"9.9.9.9", "Quad9", "sperrt bekannte Schadseiten"},
	{"149.112.112.112", "Quad9 (2)", ""},
	{"94.140.14.140", "AdGuard ungefiltert", ""},
	{"208.67.222.222", "OpenDNS", ""},
	{"76.76.2.0", "Control D ungefiltert", ""},
	{"185.222.222.222", "DNS.SB", ""},
}

// DNSSpeed: Ergebnis eines Servers.
type DNSSpeed struct {
	Addr     string  `json:"addr"`
	Name     string  `json:"name"`
	Note     string  `json:"note,omitempty"`
	Current  bool    `json:"current"`  // steht in den Einstellungen
	Median   float64 `json:"median"`   // ms, bekannte Namen (beim Server meist im Speicher)
	Uncached float64 `json:"uncached"` // ms, zufällige Namen (Server muss selbst nachfragen)
	OK       int     `json:"ok"`
	Total    int     `json:"total"`
}

var speedNames = []string{"google.com", "youtube.com", "facebook.com", "amazon.de", "wikipedia.org", "netflix.com", "apple.com", "microsoft.com",
	"whatsapp.net", "instagram.com", "cloudflare.com", "github.com"}

// DNSSpeedTest misst die eingestellten und die bekannten öffentlichen DNS-Server direkt vom Server aus
// (nicht über Ausgangsgruppen): Median über bekannte Namen und über zufällige Unterdomains.
func (e *Engine) DNSSpeedTest(extra []string) []DNSSpeed {
	current := map[string]bool{}
	cands := e.DNSCandidateList()
	list, _ := ParseUpstream(e.Setting("dns_upstream"))
	var targets []DNSSpeed
	seen := map[string]bool{}
	add := func(addr, name, note string) {
		hp := hostPort53(addr)
		if seen[hp] {
			return
		}
		seen[hp] = true
		targets = append(targets, DNSSpeed{Addr: addr, Name: name, Note: note, Current: current[hp]})
	}
	for _, s := range list {
		current[hostPort53(s)] = true
	}
	for _, s := range list {
		name := "eingestellt"
		for _, c := range cands {
			if c.Addr == s {
				name = c.Name
			}
		}
		add(s, name, "")
	}
	for _, s := range extra {
		add(s, "eigener", "")
	}
	for _, c := range cands {
		add(c.Addr, c.Name, c.Note)
	}
	if e.unboundInstalled() && (e.Setting("dns_resolver") == "unbound" || e.Sys.Exists(unboundBin)) && !e.Sys.DryRun() {
		add(unboundAddr, "Unbound (lokal)", "löst selbst auf, ohne fremden DNS-Anbieter")
	}
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(t *DNSSpeed) {
			defer wg.Done()
			srv := hostPort53(t.Addr)
			var known, fresh []float64
			for round := 0; round < 2; round++ {
				for _, n := range speedNames {
					if t.Total >= 3 && t.OK == 0 {
						return // antwortet nicht – nicht weiter warten
					}
					if ms, ok := speedQuery(srv, n); ok {
						known = append(known, ms)
						t.OK++
					}
					t.Total++
				}
			}
			for i := 0; i < 6; i++ {
				n := fmt.Sprintf("x%s.%s", proto.RandHex(5), speedNames[i])
				if ms, ok := speedQuery(srv, n); ok {
					fresh = append(fresh, ms)
					t.OK++
				}
				t.Total++
			}
			t.Median, t.Uncached = median(known), median(fresh)
		}(&targets[i])
	}
	wg.Wait()
	sort.SliceStable(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		if (a.OK == 0) != (b.OK == 0) {
			return b.OK == 0
		}
		return a.Median+a.Uncached/4 < b.Median+b.Uncached/4
	})
	return targets
}

func speedQuery(srv, name string) (float64, bool) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true})
	_ = b.StartQuestions()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return 0, false
	}
	_ = b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		return 0, false
	}
	t := time.Now()
	resp := exchangeOne(q, srv, 0, false, 2*time.Second)
	if resp == nil {
		return 0, false
	}
	return float64(time.Since(t).Microseconds()) / 1000, true
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	m := v[len(v)/2]
	if len(v)%2 == 0 {
		m = (v[len(v)/2-1] + v[len(v)/2]) / 2
	}
	return float64(int(m*10)) / 10
}

// answerAddrs: alle öffentlichen IPv4-Adressen (A-Einträge) aus einer Antwort.
func answerAddrs(resp []byte) []netip.Addr {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil
	}
	if p.SkipAllQuestions() != nil {
		return nil
	}
	var out []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeA && h.Class == dnsmessage.ClassINET {
			r, err := p.AResource()
			if err != nil {
				break
			}
			a := netip.AddrFrom4(r.A)
			if !a.IsUnspecified() && !a.IsLoopback() && !a.IsPrivate() {
				out = append(out, a)
			}
			continue
		}
		if p.SkipAnswer() != nil {
			break
		}
	}
	return out
}

// DNSCheck: Was passiert mit einem Namen für ein Gerät? (Prüfen-Feld in der Oberfläche)
type DNSCheck struct {
	Action string `json:"action"` // blocked | rewritten | ok
	Detail string `json:"detail"`
	Via    int64  `json:"via"`
	Doh    bool   `json:"doh"`
	Dev    bool   `json:"device"` // Gerät nutzt den Panel-DNS
	Prof   string `json:"profile"`
}

// CheckDNS wertet einen Namen für ein Gerät aus, ohne ihn aufzulösen.
func (e *Engine) CheckDNS(peerID int64, name string) DNSCheck {
	name = cleanDomain(name)
	g := &e.dns
	g.mu.Lock()
	var s *srcPolicy
	for i := range g.srcs {
		if g.srcs[i].peer == peerID {
			x := g.srcs[i]
			s = &x
			break
		}
	}
	g.mu.Unlock()
	out := DNSCheck{Action: "ok"}
	if s == nil {
		out.Detail = "Gerät nutzt den Panel-DNS nicht (aus, nicht verbunden oder kein WireGuard/OpenVPN)"
		return out
	}
	out.Dev, out.Doh = true, s.doh
	if s.filt != nil {
		out.Prof = s.filt.Name
	}
	if act, detail, addrs := s.filt.verdict(name); act != "" {
		out.Action, out.Detail = act, detail
		if act == "rewritten" {
			var a []string
			for _, x := range addrs {
				a = append(a, x.String())
			}
			out.Detail += " → " + strings.Join(a, ", ")
		}
		return out
	} else if detail != "" {
		out.Detail = detail
	}
	if s.doh && proto.DomainSuffixMatch(dohHosts, name) {
		out.Action, out.Detail = "blocked", "verschlüsseltes DNS (DoH) – würde am Panel vorbeigehen"
		return out
	}
	if r, ok := s.pol.MatchDomain(name); ok {
		out.Via = r.Group
		out.Detail = strings.TrimSpace(out.Detail + " Ziel-Regel")
	} else if ag, ok := s.pol.AllGroup(); ok {
		out.Via = ag
	}
	return out
}
