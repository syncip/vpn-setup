package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
)

// DNS-Umleiter für Domain-Regeln bei weitergeleitetem Verkehr (WireGuard, OpenVPN).
//
// Der Kernel sieht nur Adressen, keine Namen. Für Geräte mit Domain-Regeln leitet die Firewall
// deshalb deren DNS-Anfragen (Port 53) an diesen Umleiter. Er reicht jede Anfrage weiter – passt
// der Name auf eine Regel, über deren Ausgangsgruppe (und deren DNS-Server), sonst über den Weg
// der „alles“-Regel bzw. direkt. Die Adressen aus der Antwort trägt er in das Set der Regel ein
// (d<Regel-ID>), bevor das Gerät die Antwort bekommt; ab dann leitet der Kernel Verbindungen zu
// diesen Adressen über die Gruppe. Für passende Namen gibt es keine IPv6-Adressen (Ausgänge
// können nur IPv4). Geräte mit verschlüsseltem DNS (DoH) umgehen das – siehe README.

const (
	dnsKeep    = 24 * time.Hour // so lange gilt eine gelernte Adresse
	dnsTimeout = 3 * time.Second
)

type dnsGate struct {
	mu     sync.Mutex
	srcs   []srcPolicy
	groups map[int64]proto.GroupRoute
	cache  map[int64]map[netip.Addr]int64 // Regel → Adresse → Ablauf (Unix)
	loaded bool
	saved  time.Time
	udp    net.PacketConn
	tcp    net.Listener
	sem    chan struct{}
	warned bool
}

// dnsListen: Adresse des Umleiters (Tests setzen 127.0.0.1:0).
var dnsListen = fmt.Sprintf(":%d", dnsPort)

func (g *dnsGate) cachePath(e *Engine) string { return filepath.Join(e.Cfg.DataDir, "dnscache.json") }

func (g *dnsGate) load(e *Engine) {
	if g.loaded {
		return
	}
	g.loaded = true
	g.cache = map[int64]map[netip.Addr]int64{}
	b, err := os.ReadFile(g.cachePath(e))
	if err != nil {
		return
	}
	var raw map[int64]map[string]int64
	if json.Unmarshal(b, &raw) != nil {
		return
	}
	now := time.Now().Unix()
	for id, m := range raw {
		for s, exp := range m {
			if a, err := netip.ParseAddr(s); err == nil && exp > now {
				if g.cache[id] == nil {
					g.cache[id] = map[netip.Addr]int64{}
				}
				g.cache[id][a] = exp
			}
		}
	}
}

func (g *dnsGate) save(e *Engine) {
	now := time.Now()
	raw := map[int64]map[string]int64{}
	for id, m := range g.cache {
		for a, exp := range m {
			if exp <= now.Unix() {
				delete(m, a)
				continue
			}
			if raw[id] == nil {
				raw[id] = map[string]int64{}
			}
			raw[id][a.String()] = exp
		}
	}
	b, _ := json.Marshal(raw)
	_ = os.WriteFile(g.cachePath(e), b, 0o600)
	g.saved = now
}

// configure übernimmt den neuen Stand und startet bzw. stoppt den Umleiter nach Bedarf.
func (g *dnsGate) configure(e *Engine, srcs []srcPolicy, rt *routing) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.load(e)
	g.srcs = nil
	rules := map[int64]bool{}
	for _, s := range srcs {
		if s.pol.HasDomains() { // IPv4- und IPv6-Adressen der Geräte
			g.srcs = append(g.srcs, s)
			for _, r := range s.pol.Rules {
				if len(r.Domains) > 0 {
					rules[r.ID] = true
				}
			}
		}
	}
	g.groups = rt.Groups
	for id := range g.cache {
		if !rules[id] {
			delete(g.cache, id)
		}
	}
	need := len(g.srcs) > 0 && (!e.Sys.DryRun() || dnsListen != fmt.Sprintf(":%d", dnsPort))
	if need && g.udp == nil {
		pc, err := net.ListenPacket("udp", dnsListen) // IPv4 und IPv6
		if err != nil {
			e.setErr("dns", "DNS-Umleiter für Domain-Regeln: "+err.Error())
			return
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			e.setErr("dns", "DNS-Umleiter für Domain-Regeln: "+err.Error())
			return
		}
		e.setErr("dns", "")
		g.udp, g.tcp, g.sem = pc, ln, make(chan struct{}, 256)
		go g.serveUDP(e, pc)
		go g.serveTCP(e, ln)
	} else if !need && g.udp != nil {
		g.udp.Close()
		g.tcp.Close()
		g.udp, g.tcp = nil, nil
		e.setErr("dns", "")
	}
}

// elements: gelernte Adressen einer Regel für das Neuladen der Firewall.
func (g *dnsGate) elements(ruleID int64) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now().Unix()
	var out []string
	for a, exp := range g.cache[ruleID] {
		if left := exp - now; left > 10 {
			out = append(out, fmt.Sprintf("%s timeout %ds", a, left))
		}
	}
	sort.Strings(out)
	return out
}

// learn trägt Adressen in das Set der Regel ein (bzw. verlängert sie).
func (g *dnsGate) learn(e *Engine, ruleID int64, addrs []netip.Addr) {
	if len(addrs) == 0 {
		return
	}
	g.mu.Lock()
	now := time.Now()
	m := g.cache[ruleID]
	if m == nil {
		m = map[netip.Addr]int64{}
		g.cache[ruleID] = m
	}
	keep := int64(dnsKeep.Seconds())
	var add, renew []string
	for _, a := range addrs {
		left := m[a] - now.Unix()
		switch {
		case left > keep/2: // frisch genug
			continue
		case left > 60: // noch im Set → entfernen und neu eintragen (verlängern)
			renew = append(renew, a.String())
		case left > 0: // läuft gleich ab – beim nächsten Mal
			continue
		}
		if len(m) >= 60000 {
			break
		}
		m[a] = now.Unix() + keep
		add = append(add, a.String())
	}
	if now.Sub(g.saved) > 30*time.Second && len(add) > 0 {
		g.save(e)
	}
	g.mu.Unlock()
	if len(add) == 0 {
		return
	}
	var b strings.Builder
	if len(renew) > 0 {
		fmt.Fprintf(&b, "delete element inet %s d%d { %s }\n", nftTable, ruleID, strings.Join(renew, ", "))
	}
	fmt.Fprintf(&b, "add element inet %s d%d { %s }\n", nftTable, ruleID, strings.Join(add, ", "))
	if out, err := e.Sys.RunInput(b.String(), "nft", "-f", "-"); err != nil {
		g.mu.Lock()
		first := !g.warned
		g.warned = true
		for _, s := range add { // nicht eingetragen → beim nächsten Mal erneut versuchen
			if a, perr := netip.ParseAddr(s); perr == nil {
				delete(m, a)
			}
		}
		g.mu.Unlock()
		if first {
			e.Log("warn", fmt.Sprintf("Domain-Regeln: Adressen konnten nicht eingetragen werden: %v %s", err, strings.TrimSpace(out)))
		}
	}
}

func (g *dnsGate) policyOf(a netip.Addr) *proto.Policy {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.srcs {
		if s.pfx.Contains(a) {
			return s.pol
		}
	}
	return nil
}

func (g *dnsGate) serveUDP(e *Engine, pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || n < 12 {
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case g.sem <- struct{}{}:
		default:
			continue // überlastet → Gerät fragt erneut
		}
		go func() {
			defer func() { <-g.sem }()
			src, _ := netip.AddrFromSlice(ua.IP)
			if resp := g.handle(e, src.Unmap(), q, false); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}()
	}
}

func (g *dnsGate) serveTCP(e *Engine, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			ta, ok := c.RemoteAddr().(*net.TCPAddr)
			if !ok {
				return
			}
			src, _ := netip.AddrFromSlice(ta.IP)
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readFrame(c)
				if err != nil {
					return
				}
				resp := g.handle(e, src.Unmap(), q, true)
				if resp == nil || writeFrame(c, resp) != nil {
					return
				}
			}
		}()
	}
}

func readFrame(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 12 {
		return nil, fmt.Errorf("zu kurz")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeFrame(w io.Writer, b []byte) error {
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	_, err := w.Write(out)
	return err
}

// dohHosts: Namen bekannter DoH-Server (und die Prüf-Domain, mit der Firefox DoH abschaltet).
var dohHosts = []string{
	"use-application-dns.net",
	"cloudflare-dns.com", "one.one.one.one", "dns.google", "dns.google.com", "dns64.dns.google",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "dns12.quad9.net",
	"doh.opendns.com", "doh.familyshield.opendns.com", "doh.umbrella.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
	"dns.adguard-dns.com", "dns.adguard.com", "dns-unfiltered.adguard.com", "doh.dns.sb", "dns.mullvad.net", "doh.mullvad.net",
	"private.canadianshield.cira.ca", "doh.xfinity.com", "odvr.nic.cz", "doh.libredns.gr", "dns.switch.ch", "doh.ffmuc.net",
	"dns.digitale-gesellschaft.ch", "freedns.controld.com", "dns.controld.com", "doh.quickline.ch", "dnsforge.de",
}

// dnsUpstream: DNS-Server für Anfragen, die nicht über eine Gruppe laufen (Tests ersetzen sie).
var dnsUpstream = []string{"1.1.1.1:53", "9.9.9.9:53"}

// handle beantwortet eine Anfrage (nil = verwerfen).
func (g *dnsGate) handle(e *Engine, src netip.Addr, query []byte, tcp bool) []byte {
	pol := g.policyOf(src)
	if pol == nil {
		return nil // fremde Absender bekommen keine Antwort
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil || hdr.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	// empty: Antwort ohne Einträge
	empty := func(code dnsmessage.RCode) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionDesired: hdr.RecursionDesired,
			RecursionAvailable: true, RCode: code})
		b.EnableCompression()
		if b.StartQuestions() != nil || b.Question(q) != nil {
			return nil
		}
		out, err := b.Finish()
		if err != nil {
			return nil
		}
		return out
	}
	// Verschlüsseltes DNS (DoH) ginge am Umleiter vorbei. Browser schalten es von selbst ein, wenn der
	// eingetragene DNS-Server es anbietet (z. B. 1.1.1.1) – finden sie den DoH-Server nicht, nehmen sie
	// normales DNS. Deshalb gibt es für diese Geräte die Namen bekannter DoH-Server nicht.
	if proto.DomainMatch(dohHosts, name) {
		return empty(dnsmessage.RCodeNameError)
	}
	rule, matched := pol.MatchDomain(name)
	if matched && q.Type == dnsmessage.TypeAAAA {
		// keine IPv6-Adressen für Ziele einer Regel – Ausgänge können nur IPv4
		return empty(dnsmessage.RCodeSuccess)
	}
	group := int64(0)
	if matched {
		group = rule.Group
	} else if ag, ok := pol.AllGroup(); ok {
		group = ag
	}
	servers, mark := dnsUpstream, uint32(0)
	g.mu.Lock()
	if gr, ok := g.groups[group]; group != 0 && ok && gr.Enabled && len(gr.DNS) > 0 {
		mark = gr.Mark
		servers = nil
		for _, s := range gr.DNS {
			servers = append(servers, net.JoinHostPort(s, "53"))
		}
	}
	g.mu.Unlock()
	resp := dnsExchange(query, servers, mark, tcp)
	if resp == nil {
		return nil
	}
	if matched {
		if addrs := answerAddrs(resp); len(addrs) > 0 {
			g.learn(e, rule.ID, addrs)
		}
	}
	return resp
}

// dnsExchange schickt die Anfrage unverändert an den ersten Server, der antwortet.
func dnsExchange(query []byte, servers []string, mark uint32, tcp bool) []byte {
	d := exits.Dialer(mark)
	for _, srv := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
		network := "udp4"
		if tcp {
			network = "tcp4"
		}
		c, err := d.DialContext(ctx, network, srv)
		cancel()
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(dnsTimeout))
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
		c.Close()
		if len(resp) >= 12 && resp[0] == query[0] && resp[1] == query[1] {
			return resp
		}
	}
	return nil
}

// answerAddrs: alle IPv4-Adressen (A-Einträge) aus einer Antwort.
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
