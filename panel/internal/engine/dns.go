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
	need := len(g.srcs) > 0 && (!e.Sys.DryRun() || dnsListen != fmt.Sprintf(":%d", dnsPort))
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
		return nil // fremde Absender bekommen keine Antwort
	}
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
	entry := store.DNSEntry{TS: start.Unix(), PeerID: s.peer, UserID: s.user, Client: src.String(), Name: name, QType: int(q.Type)}
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
		if action == "blocked" {
			g.mu.Lock()
			g.blocked++
			g.mu.Unlock()
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
	if s.doh && proto.DomainMatch(dohHosts, name) {
		return done(dnsReply(hdr, q, dnsmessage.RCodeNameError, nil, 60), "blocked", "verschlüsseltes DNS (DoH) – würde am Panel vorbeigehen", 0)
	}

	// 3./4. Weg bestimmen
	rule, matched := s.pol.MatchDomain(name)
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
		for _, sv := range gr.DNS {
			servers = append(servers, hostPort53(sv))
		}
	}
	upstream := g.upstream
	g.mu.Unlock()

	key := fmt.Sprintf("%d|%d|%d|%s", group, q.Type, q.Class, name)
	resp, cached := g.cached(key, hdr.ID)
	errText := ""
	if resp == nil {
		resp = dnsExchange(query, servers, mark, tcp)
		if resp == nil && mark != 0 {
			// DNS über die Gruppe antwortet nicht (manche Anbieter sperren fremde DNS-Server): direkt
			// auflösen – wichtiger ist, dass das Ziel erkannt wird und über die Gruppe läuft.
			errText = "DNS-Server der Gruppe antworten über den Ausgang nicht – Namen werden direkt aufgelöst (in der Gruppe einen DNS-Server des Anbieters eintragen)"
			resp = dnsExchange(query, upstream, 0, tcp)
		}
		if resp != nil {
			g.store(key, resp)
		}
	}
	if resp == nil {
		if matched {
			g.note(rule.ID, "keine Antwort vom DNS-Server")
		}
		return done(nil, "error", "keine Antwort vom DNS-Server", group)
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

// ---------- Zwischenspeicher ----------

// cached liefert eine gespeicherte Antwort mit der ID der Anfrage und heruntergezählten TTLs.
func (g *dnsGate) cached(key string, id uint16) ([]byte, bool) {
	g.mu.Lock()
	a := g.answers[key]
	g.mu.Unlock()
	if a == nil {
		return nil, false
	}
	now := time.Now()
	if now.After(a.exp) {
		return nil, false
	}
	out := append([]byte(nil), a.msg...)
	binary.BigEndian.PutUint16(out, id)
	adjustTTL(out, uint32(now.Sub(a.at).Seconds()))
	return out, true
}

// store merkt sich eine Antwort (nicht abgeschnittene, ohne Serverfehler) für ihre kleinste TTL.
func (g *dnsGate) store(key string, msg []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Truncated || (h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError) {
		return
	}
	ttl := uint32(3600)
	if p.SkipAllQuestions() != nil {
		return
	}
	n := 0
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		n++
		if rh.TTL < ttl {
			ttl = rh.TTL
		}
		if p.SkipAnswer() != nil {
			break
		}
	}
	if n == 0 { // leere Antworten / „gibt es nicht“: kurz merken
		ttl = 60
	}
	if ttl < 5 {
		return
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.answers == nil {
		g.answers = map[string]*dnsAnswer{}
	}
	if len(g.answers) >= dnsCacheMax {
		i := 0
		for k, v := range g.answers { // abgelaufene und ein Zehntel zufällig entfernen
			if now.After(v.exp) || i%10 == 0 {
				delete(g.answers, k)
			}
			i++
		}
	}
	g.answers[key] = &dnsAnswer{msg: append([]byte(nil), msg...), at: now, exp: now.Add(time.Duration(ttl) * time.Second)}
}

// adjustTTL zieht von allen TTLs (außer OPT) die vergangene Zeit ab.
func adjustTTL(m []byte, sub uint32) {
	if sub == 0 || len(m) < 12 {
		return
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	rr := int(binary.BigEndian.Uint16(m[6:])) + int(binary.BigEndian.Uint16(m[8:])) + int(binary.BigEndian.Uint16(m[10:]))
	off := 12
	skipName := func() bool {
		for off < len(m) {
			l := int(m[off])
			switch {
			case l == 0:
				off++
				return true
			case l&0xC0 == 0xC0:
				off += 2
				return off <= len(m)
			default:
				off += l + 1
			}
		}
		return false
	}
	for i := 0; i < qd; i++ {
		if !skipName() {
			return
		}
		off += 4
	}
	for i := 0; i < rr; i++ {
		if !skipName() || off+10 > len(m) {
			return
		}
		typ := binary.BigEndian.Uint16(m[off:])
		if typ != 41 {
			ttl := binary.BigEndian.Uint32(m[off+4:])
			if ttl > sub {
				ttl -= sub
			} else {
				ttl = 1
			}
			binary.BigEndian.PutUint32(m[off+4:], ttl)
		}
		off += 10 + int(binary.BigEndian.Uint16(m[off+8:]))
	}
}

// ---------- Protokoll ----------

func (g *dnsGate) logEntry(en store.DNSEntry) {
	g.mu.Lock()
	on, ch := g.logOn, g.logCh
	g.mu.Unlock()
	if !on || ch == nil {
		return
	}
	select {
	case ch <- en:
	default: // Datenbank kommt nicht hinterher → Eintrag fällt weg
	}
}

// writeLog schreibt das Protokoll gesammelt (alle 2 Sekunden) und räumt stündlich auf.
func (g *dnsGate) writeLog(e *Engine, ch chan store.DNSEntry) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var buf []store.DNSEntry
	var pruned time.Time
	for {
		select {
		case en := <-ch:
			buf = append(buf, en)
			if len(buf) < 2000 {
				continue
			}
		case <-t.C:
		}
		if len(buf) > 0 {
			if err := e.St.AddDNSLog(buf); err != nil {
				e.setErr("dnslog", "DNS-Protokoll: "+err.Error())
			}
			buf = buf[:0]
		}
		if time.Since(pruned) > time.Hour {
			pruned = time.Now()
			days := atoi(e.Setting("dns_log_days"), 7)
			if days <= 0 {
				days = 0
			}
			_, _ = e.St.PruneDNSLog(time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix())
		}
	}
}

// ---------- Weiterreichen ----------

// dnsExchange schickt die Anfrage unverändert an den ersten Server, der antwortet.
func dnsExchange(query []byte, servers []string, mark uint32, tcp bool) []byte {
	d := exits.Dialer(mark)
	for _, srv := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
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
	if s.doh && proto.DomainMatch(dohHosts, name) {
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
