package engine

import (
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

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// Panel-DNS für Geräte, deren Verkehr weitergeleitet wird (WireGuard, OpenVPN).
//
// Die Firewall leitet DNS-Anfragen (Port 53) dieser Geräte an diesen Dienst – egal welchen
// DNS-Server das Gerät eingetragen hat; neue Configs nennen gleich die Tunneladresse des Servers.
// Für jede Anfrage gilt:
//
//  1. Filterprofil des Geräts: Freigaben, eigene Antworten, Sperren (Blocklisten, eigene Regeln).
//  2. Verschlüsseltes DNS (DoH/DoT) wird für Geräte mit Domain-Regeln bzw. mit Profil „sperren“
//     abgewiesen – sonst ginge es am Panel vorbei.
//  3. Domain-Regeln: Passt der Name, fragt der Dienst über die Ausgangsgruppe (und deren DNS-Server)
//     und trägt die Adressen der Antwort in das Set der Regel ein (d<Regel-ID>), bevor das Gerät die
//     Antwort bekommt; ab dann leitet der Kernel Verbindungen dorthin über die Gruppe. Für solche
//     Namen gibt es keine IPv6-Adressen (Ausgänge können nur IPv4).
//  4. Sonst über den Weg der „alles“-Regel bzw. direkt an die eingestellten DNS-Server.
//
// Antworten werden zwischengespeichert, jede Anfrage (je nach Einstellung) protokolliert.

const (
	dnsKeep     = 24 * time.Hour // so lange gilt eine gelernte Adresse
	dnsTimeout  = 3 * time.Second
	dnsCacheMax = 50000
)

type dnsGate struct {
	mu       sync.Mutex
	srcs     []srcPolicy
	groups   map[int64]proto.GroupRoute
	upstream []string
	cache    map[int64]map[netip.Addr]int64 // Regel → Adresse → Ablauf (Unix)
	loaded   bool
	saved    time.Time
	udp      net.PacketConn
	tcp      net.Listener
	sem      chan struct{}
	warned   bool
	// Antworten
	answers map[string]*dnsAnswer
	// Protokoll
	logOn  bool
	logCh  chan store.DNSEntry
	logRun bool
	// Diagnose: was der Dienst gesehen hat (seit Programmstart)
	stat    map[int64]*RuleDNS // je Domain-Regel
	clients map[netip.Addr]int64
	queries int
	blocked int
	last    int64
	// Zwischenspeicher und Verteilung (Einstellungen)
	cacheMax int
	ttlMin   uint32
	ttlMax   uint32
	nocache  []string
	strategy string // order | fastest | roundrobin | parallel
	ub       unboundState
	ubg      map[int64]string // Unbound-Instanz je Ausgangsgruppe (Gruppe → Adresse)
	ubgState sync.Map         // Adresse der Instanz → *unboundState
	rr       uint32
	srv      map[string]*srvStat // Antwortzeiten je DNS-Server
	live     dnsLive             // Anfragen je Sekunde (Live-Ansicht)
}

// srvStat: gemessene Antwortzeiten eines DNS-Servers (gleitender Mittelwert).
type srvStat struct {
	ms   float64
	ok   int
	fail int
	last time.Time
}

type dnsAnswer struct {
	msg []byte
	at  time.Time
	exp time.Time
}

// RuleDNS: Stand einer Domain-Regel im DNS-Dienst (für die Oberfläche).
type RuleDNS struct {
	Used    bool   `json:"used"`            // Regel gilt für mindestens ein WireGuard-/OpenVPN-Gerät
	Addrs   int    `json:"addrs"`           // gelernte Adressen
	Queries int    `json:"queries"`         // passende DNS-Anfragen
	Last    int64  `json:"last"`            // letzte passende Anfrage
	Error   string `json:"error,omitempty"` // letzter Fehler
}

// DNSInfo: Stand des Dienstes insgesamt.
type DNSInfo struct {
	Running bool               `json:"running"`
	Queries int                `json:"queries"` // alle Anfragen seit dem Start
	Blocked int                `json:"blocked"`
	Last    int64              `json:"last"`
	Clients int                `json:"clients"` // Geräte, von denen Anfragen kamen
	Devices int                `json:"devices"` // Geräte, deren DNS über das Panel läuft
	Cached  int                `json:"cached"`  // Antworten im Zwischenspeicher
	Rules   map[int64]*RuleDNS `json:"rules"`
}

// DNSInfo liefert den Stand für die Oberfläche.
func (e *Engine) DNSInfo() DNSInfo {
	g := &e.dns
	g.mu.Lock()
	defer g.mu.Unlock()
	out := DNSInfo{Running: g.udp != nil, Queries: g.queries, Blocked: g.blocked, Last: g.last, Clients: len(g.clients),
		Cached: len(g.answers), Rules: map[int64]*RuleDNS{}}
	devs := map[int64]bool{}
	for _, s := range g.srcs {
		devs[s.peer] = true
	}
	out.Devices = len(devs)
	now := time.Now().Unix()
	rule := func(id int64) *RuleDNS {
		if out.Rules[id] == nil {
			out.Rules[id] = &RuleDNS{}
			if s := g.stat[id]; s != nil {
				*out.Rules[id] = *s
			}
		}
		return out.Rules[id]
	}
	for _, s := range g.srcs {
		if s.pol == nil {
			continue
		}
		for _, r := range s.pol.Rules {
			if len(r.Domains) > 0 {
				rule(r.ID).Used = true
			}
		}
	}
	for id, m := range g.cache {
		n := 0
		for _, exp := range m {
			if exp > now {
				n++
			}
		}
		if n > 0 || out.Rules[id] != nil {
			rule(id).Addrs = n
		}
	}
	return out
}

// note hält eine passende Anfrage bzw. einen Fehler für die Diagnose fest.
func (g *dnsGate) note(ruleID int64, errText string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stat == nil {
		g.stat = map[int64]*RuleDNS{}
	}
	s := g.stat[ruleID]
	if s == nil {
		s = &RuleDNS{}
		g.stat[ruleID] = s
	}
	s.Queries++
	s.Last = time.Now().Unix()
	s.Error = errText
}

// dnsListen: Adresse des Dienstes (Tests setzen 127.0.0.1:0).
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

// ParseUpstream: DNS-Server (IP-Adressen, optional mit Port), mit Komma oder Leerzeichen getrennt.
func ParseUpstream(v string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if ap, err := netip.ParseAddrPort(f); err == nil {
			out = append(out, ap.String())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("DNS-Server „%s“: bitte IP-Adressen angeben (z. B. 1.1.1.1 oder 9.9.9.9:53)", f)
		}
		out = append(out, a.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("mindestens einen DNS-Server angeben")
	}
	if len(out) > 6 {
		return nil, fmt.Errorf("höchstens 6 DNS-Server")
	}
	return out, nil
}

func hostPort53(s string) string {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String()
	}
	return net.JoinHostPort(s, "53")
}

// dnsUpstream: ersetzt die Einstellung (nur Tests).
var dnsUpstream []string

// configure übernimmt den neuen Stand und startet bzw. stoppt den Dienst nach Bedarf.
func (g *dnsGate) configure(e *Engine, srcs []srcPolicy, rt *routing) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.load(e)
	g.srcs = nil
	rules := map[int64]bool{}
	for _, s := range srcs {
		if !s.dns {
			continue
		}
		g.srcs = append(g.srcs, s)
		if s.pol != nil {
			for _, r := range s.pol.Rules {
				if len(r.Domains) > 0 {
					rules[r.ID] = true
				}
			}
		}
	}
	g.groups = rt.Groups
	g.upstream = nil
	if dnsUpstream != nil {
		g.upstream = dnsUpstream
	} else {
		list, err := ParseUpstream(e.Setting("dns_upstream"))
		if err != nil {
			list = []string{"1.1.1.1", "9.9.9.9"}
		}
		for _, s := range list {
			g.upstream = append(g.upstream, hostPort53(s))
		}
	}
	g.cacheMax = atoi(e.Setting("dns_cache_size"), dnsCacheMax)
	if g.cacheMax < 0 {
		g.cacheMax = 0
	}
	g.ttlMin = uint32(max(0, atoi(e.Setting("dns_ttl_min"), 0)))
	g.ttlMax = uint32(max(0, atoi(e.Setting("dns_ttl_max"), 86400)))
	if g.ttlMax == 0 {
		g.ttlMax = 86400
	}
	g.nocache = strings.Fields(e.Setting("dns_nocache"))
	g.strategy = e.Setting("dns_strategy")
	if dnsUpstream == nil && e.useUnbound() {
		// Unbound löst selbst auf; die eingestellten Server springen nur ein, wenn er nicht antwortet
		g.upstream = append([]string{unboundAddr}, g.upstream...)
		g.strategy = "order"
	}
	g.logOn = atoi(e.Setting("dns_log_days"), 7) > 0
	if g.logOn && !g.logRun {
		g.logRun = true
		g.logCh = make(chan store.DNSEntry, 20000)
		go g.writeLog(e, g.logCh)
	}
	for id := range g.cache {
		if !rules[id] {
			delete(g.cache, id)
		}
	}
	// Antworten können vom Weg (Gruppe) abhängen – nach Änderungen neu fragen
	g.answers = nil
	need := (len(g.srcs) > 0 || e.dnsPublic()) && (!e.Sys.DryRun() || dnsListen != fmt.Sprintf(":%d", dnsPort))
	if need && g.udp == nil {
		pc, err := net.ListenPacket("udp", dnsListen) // IPv4 und IPv6
		if err != nil {
			e.setErr("dns", "Panel-DNS: "+err.Error())
			return
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			e.setErr("dns", "Panel-DNS: "+err.Error())
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

func (g *dnsGate) sourceOf(a netip.Addr) *srcPolicy {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.srcs {
		if g.srcs[i].pfx.Contains(a) {
			s := g.srcs[i]
			return &s
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
			defer e.guard("DNS (UDP)")
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
		ta, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = c.Close()
			continue
		}
		src, _ := netip.AddrFromSlice(ta.IP)
		src = src.Unmap()
		if !dnsTCPLimit.acquire(src) { // zu viele offene Verbindungen (insgesamt oder von dieser Adresse)
			_ = c.Close()
			continue
		}
		go func() {
			defer dnsTCPLimit.release(src)
			defer c.Close()
			defer e.guard("DNS (TCP)")
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readFrame(c)
				if err != nil {
					return
				}
				resp := g.handle(e, src, q, true)
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
	"mask.icloud.com", "mask-h2.icloud.com",
}

// dnsReply baut eine Antwort auf die Frage q (Adressen nur, wenn sie zum Typ passen).
func dnsReply(hdr dnsmessage.Header, q dnsmessage.Question, code dnsmessage.RCode, addrs []netip.Addr, ttl uint32) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionDesired: hdr.RecursionDesired,
		RecursionAvailable: true, RCode: code})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil {
		return nil
	}
	if b.StartAnswers() != nil {
		return nil
	}
	for _, a := range addrs {
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}
		switch {
		case q.Type == dnsmessage.TypeA && a.Is4():
			rh.Type = dnsmessage.TypeA
			_ = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		case q.Type == dnsmessage.TypeAAAA && a.Is6():
			rh.Type = dnsmessage.TypeAAAA
			_ = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

var (
	null4 = netip.MustParseAddr("0.0.0.0")
	null6 = netip.MustParseAddr("::")
)

// handle beantwortet eine Anfrage (nil = verwerfen).
func (g *dnsGate) handle(e *Engine, src netip.Addr, query []byte, tcp bool) []byte {
	s := g.sourceOf(src)
	if s == nil {
		if es := e.extSourceOf(src); es != nil {
			es.via = "dns"
			s = es
			if !tcp {
				// Schutz vor Missbrauch für Verstärkungsangriffe (gefälschte Absender, dnsrate.go)
				if !e.dnsRate.allow(src, time.Now(), es.rate, es.burst, -es.peer) {
					return nil
				}
				if queryType(query) == dnsmessage.TypeALL && e.dnsx.anyBlock() {
					return refusedReply(query)
				}
			}
		}
	}
	if s == nil {
		// nicht freigegebene Absender bekommen keine Antwort – von außen werden sie aber mitgezählt
		if e.dnsx.isPublic() {
			e.noteExt(src, 0, queryName(query), true, false, "dns")
		}
		return nil
	}
	return g.handleWith(e, src, s, query, tcp)
}

// queryName: gefragter Name einer Anfrage ("" = nicht lesbar).
func queryName(query []byte) string {
	var p dnsmessage.Parser
	if _, err := p.Start(query); err == nil {
		if q, err := p.Question(); err == nil {
			return strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
		}
	}
	return ""
}

// handleWith beantwortet eine Anfrage mit bekannter Richtlinie (auch DoH/DoT).
func (g *dnsGate) handleWith(e *Engine, src netip.Addr, s *srcPolicy, query []byte, tcp bool) []byte {
	start := time.Now()
	g.mu.Lock()
	g.queries++
	g.last = start.Unix()
	if g.clients == nil {
		g.clients = map[netip.Addr]int64{}
	}
	if len(g.clients) < 2000 {
		g.clients[src] = g.last
	}
	g.mu.Unlock()
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
	entry := store.DNSEntry{TS: start.Unix(), PeerID: s.peer, UserID: s.user, Client: src.String(), Name: name, QType: int(q.Type), Transport: s.via}
	done := func(resp []byte, action, detail string, via int64) []byte {
		entry.Action, entry.Detail, entry.Via = action, detail, via
		entry.MS = int(time.Since(start).Milliseconds())
		if resp != nil {
			var rp dnsmessage.Parser
			if h, err := rp.Start(resp); err == nil {
				entry.RCode = int(h.RCode)
			}
		} else {
			entry.RCode = int(dnsmessage.RCodeServerFailure)
		}
		g.mu.Lock()
		if action == "blocked" {
			g.blocked++
		}
		g.live.add(start.Unix(), action, entry.MS)
		g.mu.Unlock()
		if s.peer < 0 {
			e.noteExt(src, -s.peer, name, false, action == "blocked", s.via)
		}
		g.logEntry(entry)
		return resp
	}

	// 1. Filterprofil
	if act, detail, addrs := s.filt.verdict(name); act == "blocked" {
		if s.filt.NXDomain {
			return done(dnsReply(hdr, q, dnsmessage.RCodeNameError, nil, 60), "blocked", detail, 0)
		}
		return done(dnsReply(hdr, q, dnsmessage.RCodeSuccess, []netip.Addr{null4, null6}, 60), "blocked", detail, 0)
	} else if act == "rewritten" {
		return done(dnsReply(hdr, q, dnsmessage.RCodeSuccess, addrs, 300), "rewritten", detail, 0)
	}

	// 2. Verschlüsseltes DNS ginge am Panel vorbei. Browser schalten es von selbst ein, wenn der
	// eingetragene DNS-Server es anbietet (z. B. 1.1.1.1) – finden sie den DoH-Server nicht, nehmen
	// sie normales DNS.
	if s.doh && proto.DomainSuffixMatch(dohHosts, name) {
		return done(dnsReply(hdr, q, dnsmessage.RCodeNameError, nil, 60), "blocked", "verschlüsseltes DNS (DoH) – würde am Panel vorbeigehen", 0)
	}

	// SmartDNS für Geräte ohne VPN: Name zeigt auf den Server, der die HTTPS-Verbindung über die
	// Gruppe weiterreicht (VPN-Geräte leitet stattdessen die Ziel-Regel aus dem SmartDNS-Profil).
	if s.peer < 0 {
		if rid, gid, dom, ok := s.smart.matchRuleLabel(name); ok {
			g.mu.Lock()
			gr, gok := g.groups[gid]
			g.mu.Unlock()
			if gok && gr.Enabled {
				if q.Type == dnsmessage.TypeA {
					e.smartQuery(rid, dom, name, s.peer)
				}
				// Wer die Serveradresse bekommt, darf damit auch den Proxy nutzen – wichtig bei DoH/DoT
				// über die Kennung, wenn die Adresse des Geräts nicht freigegeben ist.
				// Nur für diesen Namen und 30 Minuten (jede Antwort verlängert).
				e.smartGrant(src, -s.peer, name)
				v4, v6 := e.PublicAddrs()
				detail := "SmartDNS: " + dom + " über „" + gr.Name + "“"
				switch q.Type {
				case dnsmessage.TypeA:
					if v4.IsValid() {
						return done(dnsReply(hdr, q, dnsmessage.RCodeSuccess, []netip.Addr{v4}, 60), "rewritten", detail, gid)
					}
				case dnsmessage.TypeAAAA:
					// IPv6 nur, wenn auch die Anfrage über IPv6 kam: Sonst verbindet sich das Gerät über
					// seine (unbekannte) IPv6-Adresse, und der Proxy kann es nicht zuordnen.
					var a []netip.Addr
					if v6.IsValid() && src.Is6() && !src.Is4In6() {
						a = []netip.Addr{v6}
					}
					if v4.IsValid() {
						return done(dnsReply(hdr, q, dnsmessage.RCodeSuccess, a, 60), "rewritten", detail, gid)
					}
				case 64, 65: // HTTPS/SVCB: keine Hinweise auf echte Adressen
					if v4.IsValid() {
						return done(dnsReply(hdr, q, dnsmessage.RCodeSuccess, nil, 60), "rewritten", detail, gid)
					}
				}
			}
		}
	}

	// 3./4. Weg bestimmen
	rule, matched := s.pol.MatchDomain(name)
	if matched && rule.ID >= smartRuleBase && q.Type == dnsmessage.TypeA {
		if rid, _, dom, ok := s.smart.matchRule(name); ok && rid == rule.ID {
			e.smartQuery(rid, dom, name, s.peer)
		}
	}
	if matched && (q.Type == dnsmessage.TypeAAAA || q.Type == 64 || q.Type == 65) {
		// Keine IPv6-Adressen für Ziele einer Regel – Ausgänge können nur IPv4. Das gilt auch für
		// HTTPS-/SVCB-Einträge (Typ 65/64): Browser entnehmen ihnen sonst IPv6-Adressen (ipv6hint).
		return done(dnsReply(hdr, q, dnsmessage.RCodeSuccess, nil, 60), "ok", "Ziel-Regel: nur IPv4", rule.Group)
	}
	group := int64(0)
	if matched {
		group = rule.Group
	} else if ag, ok := s.pol.AllGroup(); ok {
		group = ag
	}
	g.mu.Lock()
	servers, mark := g.upstream, uint32(0)
	if gr, ok := g.groups[group]; group != 0 && ok && gr.Enabled && len(gr.DNS) > 0 {
		mark = gr.Mark
		servers = nil
		// Unbound der Gruppe zuerst (löst selbst auf, über den Ausgang), dann die DNS-Server der Gruppe
		if a := g.ubg[group]; a != "" {
			servers = append(servers, a)
		}
		for _, sv := range gr.DNS {
			servers = append(servers, hostPort53(sv))
		}
	}
	upstream := g.upstream
	g.mu.Unlock()

	key := fmt.Sprintf("%d|%d|%d|%s", group, q.Type, q.Class, name)
	g.mu.Lock()
	noCache := proto.DomainSuffixMatch(g.nocache, name)
	g.mu.Unlock()
	var resp []byte
	cached := false
	if !noCache {
		resp, cached = g.cached(key, hdr.ID)
	}
	errText := ""
	if resp == nil {
		resp, entry.Upstream = g.exchange(query, servers, mark, tcp)
		if resp == nil && mark != 0 {
			// DNS über die Gruppe antwortet nicht (manche Anbieter sperren fremde DNS-Server): direkt
			// auflösen – wichtiger ist, dass das Ziel erkannt wird und über die Gruppe läuft.
			errText = "DNS-Server der Gruppe antworten über den Ausgang nicht – Namen werden direkt aufgelöst (in der Gruppe einen DNS-Server des Anbieters eintragen)"
			resp, entry.Upstream = g.exchange(query, upstream, 0, tcp)
		}
		if resp != nil && !noCache {
			g.store(key, resp)
		}
	}
	if resp == nil {
		if matched {
			g.note(rule.ID, "keine Antwort vom DNS-Server")
		}
		return done(nil, "error", "keine Antwort vom DNS-Server", group)
	}
	if group != 0 && q.Type == dnsmessage.TypeA && e.Exits != nil {
		if e.Exits.HasOverrides(group) {
			// Block-Prüfung: Adressen von Zielen mit Ausnahme in deren Set eintragen
			e.Exits.LearnOverride(e.exitEnv(), group, name, answerAddrs(resp))
		}
		e.noteNames(group, name, answerAddrs(resp)) // passive Erkennung: Adresse → Name
	}
	detail := ""
	if matched {
		if q.Type == dnsmessage.TypeA {
			g.note(rule.ID, errText)
		}
		if addrs := answerAddrs(resp); len(addrs) > 0 {
			g.learn(e, rule.ID, addrs)
		}
		detail = "Ziel-Regel"
		if errText != "" {
			detail = "Ziel-Regel – " + errText
		}
	}
	action := "ok"
	if cached {
		action = "cached"
	}
	return done(resp, action, detail, group)
}
