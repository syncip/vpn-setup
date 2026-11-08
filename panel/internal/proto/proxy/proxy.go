// Package proxy: SOCKS5- und HTTP-Proxy mit Anmeldung (Benutzername/Passwort oder Client-IP),
// direkt im Panel-Prozess. Verbindungen laufen auf Wunsch über eine Ausgangsgruppe (externe VPNs,
// Paket exits): Sockets bekommen die Markierung der Gruppe, DNS wird ebenfalls über die Gruppe
// abgefragt. Nur IPv4 nach draußen.
//
// Weil alles im Prozess läuft, kennt das Panel jeden Zugang sofort: gesperrte Nutzer werden beim
// nächsten Anwenden getrennt, die Drosselung pro Nutzer ist ein Token-Bucket, Statistik und
// Online-Status kommen ohne Umweg.
package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

const (
	handshakeTimeout = 15 * time.Second
	idleTimeout      = 10 * time.Minute
	maxPerIP         = 512
	maxTotal         = 8192
)

type serverCfg struct {
	Socks     bool   `json:"socks"`
	SocksPort int    `json:"socks_port"`
	HTTP      bool   `json:"http"`
	HTTPPort  int    `json:"http_port"`
	Group     any    `json:"group"` // ID der Ausgangsgruppe, 0/leer = direkt über den Server
	Host      string `json:"host"`
	MaxConns  int    `json:"max_conns"`
	BlockSMTP bool   `json:"block_smtp"`
}

func load(srv *store.Server) serverCfg {
	c := serverCfg{Socks: true, SocksPort: 1080, HTTP: true, HTTPPort: 8080, MaxConns: 256, BlockSMTP: true}
	_ = proto.Decode(srv.Settings, &c)
	return c
}

func groupOf(c serverCfg) int64 {
	switch v := c.Group.(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

type Driver struct{}

func init() { proto.Register(Driver{}) }

func (Driver) Info() proto.Info {
	return proto.Info{
		ID:          "proxy",
		Label:       "Proxy",
		Description: "SOCKS5- und HTTP-Proxy mit Benutzername und Passwort – für Fernseher und Apps. Auf Wunsch über eine Ausgangsgruppe (externes VPN, anderer Standort). Unverschlüsselt.",
		ServerFields: []proto.Field{
			{Key: "group", Label: "Ausgang", Type: "exitgroup", Default: 0,
				Help: "Ausgangsgruppe (Menü „Proxy“ → Ausgänge), über die der Verkehr läuft. „Direkt“ = über die Adresse dieses Servers."},
			{Key: "socks", Label: "SOCKS5 aktiv", Type: "bool", Default: true},
			{Key: "socks_port", Label: "SOCKS5-Port (TCP)", Type: "number", Default: 1080,
				Help: "Muss auf dem Proxmox-Host per TCP an den Container weitergeleitet werden."},
			{Key: "http", Label: "HTTP-Proxy aktiv", Type: "bool", Default: true},
			{Key: "http_port", Label: "HTTP-Proxy-Port (TCP)", Type: "number", Default: 8080,
				Help: "Muss auf dem Proxmox-Host per TCP an den Container weitergeleitet werden."},
			{Key: "max_conns", Label: "Max. gleichzeitige Verbindungen pro Zugang", Type: "number", Default: 256, Advanced: true},
			{Key: "block_smtp", Label: "Mailversand (Port 25) sperren", Type: "bool", Default: true, Advanced: true,
				Help: "Verhindert, dass über den Proxy Spam verschickt wird."},
			{Key: "host", Label: "Adresse in den Zugangsdaten", Type: "text", Advanced: true, Placeholder: "Server-Domain aus den Einstellungen"},
		},
		PeerFields: []proto.Field{
			{Key: "source_ips", Label: "Anmeldung per IP (ohne Passwort)", Type: "cidrlist", Advanced: true, Placeholder: "z. B. 203.0.113.7",
				Help: "Für Geräte, die keinen Proxy mit Passwort können (z. B. viele Fernseher): Verbindungen von diesen Adressen gelten ohne Anmeldung als dieser Zugang. Nur feste Adressen eintragen!"},
		},
		Kinds: []proto.Kind{{ID: "access", Label: "Zugang", Icon: "key", Description: "Benutzername und Passwort für SOCKS5/HTTP.", Defaults: store.M{}}},
	}
}

var hostRe = netHostRe()

func netHostRe() func(string) bool {
	return func(h string) bool {
		if h == "" || len(h) > 253 {
			return false
		}
		for _, r := range h {
			if !(r == '.' || r == '-' || r == ':' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return false
			}
		}
		return true
	}
}

func (Driver) InitServer(env *proto.Env, srv *store.Server, all []*store.Server) error {
	c := load(srv)
	for _, p := range []struct {
		on   bool
		port int
		name string
	}{{c.Socks, c.SocksPort, "SOCKS5"}, {c.HTTP, c.HTTPPort, "HTTP"}} {
		if p.port < 1 || p.port > 65535 {
			return fmt.Errorf("%s-Port %d ungültig", p.name, p.port)
		}
		if !p.on {
			continue
		}
		if msg := proto.PortConflict(env.Global, all, srv.ID, "tcp", p.port, 0); msg != "" {
			return fmt.Errorf("%s", msg)
		}
	}
	if c.Socks && c.HTTP && c.SocksPort == c.HTTPPort {
		return fmt.Errorf("SOCKS5 und HTTP brauchen verschiedene Ports")
	}
	if g := groupOf(c); g != 0 {
		if _, ok := env.Global.Groups[g]; !ok {
			return fmt.Errorf("Ausgangsgruppe %d gibt es nicht", g)
		}
	}
	if c.MaxConns < 1 || c.MaxConns > 4096 {
		return fmt.Errorf("max. Verbindungen: 1–4096")
	}
	c.Host = strings.TrimSpace(c.Host)
	if c.Host != "" && !hostRe(c.Host) {
		return fmt.Errorf("Adresse %q ungültig", c.Host)
	}
	srv.Settings["group"] = groupOf(c)
	srv.Settings["host"] = c.Host
	return nil
}

const pwChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randStr(n int) string {
	b := proto.RandBytes(n)
	for i := range b {
		b[i] = pwChars[int(b[i])%len(pwChars)]
	}
	return string(b)
}

func (Driver) InitPeer(env *proto.Env, srv *store.Server, p *store.Peer, others []*store.Peer) error {
	p.Kind = "access"
	if proto.Str(p.Secrets, "username") == "" {
		used := map[string]bool{}
		for _, o := range others {
			used[proto.Str(o.Secrets, "username")] = true
		}
		for {
			u := "u" + strings.ToLower(randStr(7))
			if !used[u] {
				p.Secrets["username"] = u
				break
			}
		}
	}
	if proto.Str(p.Secrets, "password") == "" {
		p.Secrets["password"] = randStr(24)
	}
	// Anmeldung per IP: normalisieren, keine Netze größer als /24 bzw. /56
	ips := strList(p.Settings["source_ips"])
	if v, ok := p.Settings["source_ips"].(string); ok {
		ips = strings.Fields(strings.ReplaceAll(v, ",", " "))
	}
	var out []string
	for _, s := range ips {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		pf, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("Anmeldung per IP: %q ungültig", s)
		}
		if (pf.Addr().Is4() && pf.Bits() < 24) || (!pf.Addr().Is4() && pf.Bits() < 56) {
			return fmt.Errorf("Anmeldung per IP: %s ist zu groß (höchstens /24 bzw. /56)", pf)
		}
		out = append(out, pf.String())
	}
	if len(out) > 32 {
		return fmt.Errorf("Anmeldung per IP: höchstens 32 Einträge")
	}
	p.Settings["source_ips"] = out
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("ungültig")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("ungültig")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ---------- Laufzeit ----------

type peerRT struct {
	id         int64
	user, pass string
	active     bool
	srv        int64
	sources    []netip.Prefix
	up, down   atomic.Int64 // seit Programmstart
	lastUp     int64        // Stand beim letzten Collect
	lastDown   int64
	conns      int
	since      int64
	lastIP     string
	bUp, bDown bucket
}

type tracked struct {
	client, upstream net.Conn
	peer             *peerRT
	ip               netip.Addr
	inst             *instance
}

func (t *tracked) close() {
	_ = t.client.Close()
	if t.upstream != nil {
		_ = t.upstream.Close()
	}
}

type instance struct {
	id        int64
	name      string
	cfg       serverCfg
	group     int64
	route     proto.GroupRoute
	acl       *proto.ACL
	users     map[string]*peerRT
	sources   []*peerRT
	socks     net.Listener
	http      net.Listener
	transport *http.Transport
	err       string
	resolver  *net.Resolver
}

var mgr = struct {
	sync.Mutex
	inst  map[int64]*instance
	peers map[int64]*peerRT
	conns map[*tracked]struct{}
	perIP map[netip.Addr]int
	total int
	self  []netip.Prefix // öffentliche Adressen des Servers (nie als Ziel)
}{inst: map[int64]*instance{}, peers: map[int64]*peerRT{}, conns: map[*tracked]struct{}{}, perIP: map[netip.Addr]int{}}

func listenAddr(env *proto.Env, port int) string {
	if env.Sys.DryRun() {
		return fmt.Sprintf("127.0.0.1:%d", port) // Testmodus: nur lokal
	}
	return fmt.Sprintf(":%d", port)
}

func (d Driver) Apply(env *proto.Env, servers []*proto.ServerBundle) error {
	setLog(env.Log)
	self, selfOK := selfPrefixes(env, servers)
	mgr.Lock()
	defer mgr.Unlock()
	if selfOK || len(self) > len(mgr.self) {
		mgr.self = self
	}
	var errs []string
	want := map[int64]bool{}
	seenPeers := map[int64]bool{}
	for _, sb := range servers {
		sv := sb.Server
		if !sv.Enabled {
			continue
		}
		want[sv.ID] = true
		c := load(sv)
		in := mgr.inst[sv.ID]
		if in == nil {
			in = &instance{id: sv.ID}
			mgr.inst[sv.ID] = in
		}
		old := in.cfg
		in.name, in.cfg = sv.Name, c
		// Ausgang (Gruppe) geändert → alle Verbindungen neu aufbauen lassen
		g := groupOf(c)
		route := env.Global.Groups[g]
		rerouted := in.group != g || in.route.Mark != route.Mark || in.route.Enabled != route.Enabled
		in.group, in.route = g, route
		dns := route.DNS
		if g != 0 && len(dns) > 0 {
			in.resolver = exits.Resolver(route.Mark, dns)
		} else {
			in.resolver = net.DefaultResolver
		}
		in.acl = env.Global.ACLs[sv.ID]
		if in.transport == nil || rerouted {
			if in.transport != nil {
				in.transport.CloseIdleConnections()
			}
			inst := in
			in.transport = &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 64, IdleConnTimeout: 60 * time.Second,
				ResponseHeaderTimeout: 60 * time.Second, TLSHandshakeTimeout: 15 * time.Second,
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return inst.dial(ctx, addr) }}
		}
		// Zugänge
		in.users = map[string]*peerRT{}
		in.sources = nil
		for _, pb := range sb.Peers {
			p := pb.Peer
			rt := mgr.peers[p.ID]
			if rt == nil {
				rt = &peerRT{id: p.ID}
				mgr.peers[p.ID] = rt
			}
			seenPeers[p.ID] = true
			rt.srv = sv.ID
			rt.user, rt.pass = proto.Str(p.Secrets, "username"), proto.Str(p.Secrets, "password")
			rt.active = pb.Active
			rt.bDown.setRate(pb.RateDown)
			rt.bUp.setRate(pb.RateUp)
			rt.sources = nil
			for _, s := range strList(p.Settings["source_ips"]) {
				if pf, err := parsePrefix(s); err == nil {
					rt.sources = append(rt.sources, pf)
				}
			}
			if rt.active && rt.user != "" {
				in.users[rt.user] = rt
				if len(rt.sources) > 0 {
					in.sources = append(in.sources, rt)
				}
			}
		}
		// Listener (neu) öffnen, wenn sich Port oder Schalter geändert haben
		in.err = ""
		var lerr []string
		if in.socks != nil && (!c.Socks || c.SocksPort != old.SocksPort) {
			_ = in.socks.Close()
			in.socks = nil
		}
		if in.http != nil && (!c.HTTP || c.HTTPPort != old.HTTPPort) {
			_ = in.http.Close()
			in.http = nil
		}
		if c.Socks && in.socks == nil {
			if ln, err := net.Listen("tcp", listenAddr(env, c.SocksPort)); err != nil {
				lerr = append(lerr, fmt.Sprintf("SOCKS5-Port %d: %v", c.SocksPort, err))
			} else {
				in.socks = ln
				go acceptLoop(in, ln, false)
			}
		}
		if c.HTTP && in.http == nil {
			if ln, err := net.Listen("tcp", listenAddr(env, c.HTTPPort)); err != nil {
				lerr = append(lerr, fmt.Sprintf("HTTP-Port %d: %v", c.HTTPPort, err))
			} else {
				in.http = ln
				go acceptLoop(in, ln, true)
			}
		}
		if len(lerr) > 0 {
			in.err = strings.Join(lerr, "; ")
			errs = append(errs, sv.Name+": "+in.err)
		}
		// bestehende Verbindungen prüfen
		for t := range mgr.conns {
			if t.inst != in {
				continue
			}
			if rerouted || !t.peer.active || mgr.peers[t.peer.id] != t.peer || t.peer.srv != in.id || !in.acl.Allowed(t.ip) ||
				(t.client.LocalAddr() != nil && !listenerOwns(in, t.client.LocalAddr())) {
				t.close()
			}
		}
	}
	for id, in := range mgr.inst {
		if want[id] {
			continue
		}
		in.shutdown()
		delete(mgr.inst, id)
	}
	for id := range mgr.peers {
		if !seenPeers[id] {
			delete(mgr.peers, id)
		}
	}
	for t := range mgr.conns {
		if mgr.inst[t.inst.id] != t.inst || mgr.peers[t.peer.id] == nil {
			t.close()
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// listenerOwns: gehört die lokale Adresse einer Verbindung noch zu einem offenen Listener?
func listenerOwns(in *instance, la net.Addr) bool {
	ta, ok := la.(*net.TCPAddr)
	if !ok {
		return true
	}
	return (in.socks != nil && in.cfg.SocksPort == ta.Port) || (in.http != nil && in.cfg.HTTPPort == ta.Port)
}

func (in *instance) shutdown() {
	if in.socks != nil {
		_ = in.socks.Close()
	}
	if in.http != nil {
		_ = in.http.Close()
	}
	if in.transport != nil {
		in.transport.CloseIdleConnections()
	}
	for t := range mgr.conns {
		if t.inst == in {
			t.close()
		}
	}
}

// GroupSwitched: Ausgang einer Gruppe gewechselt → Verbindungen trennen, damit Apps sie über den
// neuen Ausgang neu aufbauen (sonst hingen sie am alten, evtl. toten Tunnel).
func (Driver) GroupSwitched(groupID int64) {
	mgr.Lock()
	defer mgr.Unlock()
	for _, in := range mgr.inst {
		if in.group == groupID && in.transport != nil {
			in.transport.CloseIdleConnections()
		}
	}
	for t := range mgr.conns {
		if t.inst.group == groupID {
			t.close()
		}
	}
}

// ---------- Annehmen ----------

func addrOf(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		a, _ := netip.AddrFromSlice(ta.IP)
		return a.Unmap()
	}
	return netip.Addr{}
}

func acceptLoop(in *instance, ln net.Listener, isHTTP bool) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ip := addrOf(c)
		mgr.Lock()
		kind, why := "", ""
		switch {
		case mgr.inst[in.id] != in:
			kind = "stop" // Server wird gerade abgebaut – nicht melden
		case !in.acl.Allowed(ip):
			kind, why = "acl", "durch eine IP-Liste gesperrt"
		case mgr.perIP[ip] >= maxPerIP:
			kind, why = "perip", fmt.Sprintf("zu viele gleichzeitige Verbindungen von dieser Adresse (max. %d)", maxPerIP)
		case mgr.total >= maxTotal:
			kind, why = "total", fmt.Sprintf("Verbindungsgrenze des Proxys erreicht (max. %d)", maxTotal)
		default:
			mgr.total++
			mgr.perIP[ip]++
		}
		name := in.name
		mgr.Unlock()
		if kind != "" {
			_ = c.Close()
			if why != "" {
				note("warn", ip.String()+"|"+kind, fmt.Sprintf("Proxy „%s“: Verbindung von %s abgelehnt – %s", name, ip, why))
			}
			continue
		}
		go func() {
			defer func() {
				mgr.Lock()
				mgr.total--
				if mgr.perIP[ip]--; mgr.perIP[ip] <= 0 {
					delete(mgr.perIP, ip)
				}
				mgr.Unlock()
				_ = c.Close()
			}()
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(60 * time.Second)
			}
			_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
			if isHTTP {
				in.serveHTTP(c, ip)
			} else {
				in.serveSOCKS(c, ip)
			}
		}()
	}
}

// loginFailed: fehlgeschlagene Anmeldung melden (gedrosselt). Eine Sperre nach Fehlversuchen gibt
// es bewusst nicht: Sie traf vor allem die eigenen Geräte (Apps, die es mit alten Daten weiter
// versuchen), und die zufälligen 24-stelligen Passwörter lassen sich ohnehin nicht erraten.
func (in *instance) loginFailed(ip netip.Addr, user, pass, via string) {
	mgr.Lock()
	name := in.name
	var off *peerRT
	for _, rt := range mgr.peers {
		if rt.srv == in.id && !rt.active && rt.user == user && subtle.ConstantTimeCompare([]byte(rt.pass), []byte(pass)) == 1 {
			off = rt
			break
		}
	}
	mgr.Unlock()
	if off != nil {
		note("warn", ip.String()+"|off|"+user, fmt.Sprintf("Proxy „%s“: Anmeldung von %s (%s) mit Zugang „%s“ abgewiesen – Zugang gesperrt, abgelaufen oder über dem Limit", name, ip, via, user))
		return
	}
	note("info", ip.String()+"|auth", fmt.Sprintf("Proxy „%s“: Anmeldung von %s (%s) fehlgeschlagen – falscher Benutzername oder falsches Passwort", name, ip, via))
}

// login prüft Benutzername/Passwort (Zeit-konstant).
func (in *instance) login(user, pass string) *peerRT {
	mgr.Lock()
	rt := in.users[user]
	mgr.Unlock()
	want := "x"
	if rt != nil {
		want = rt.pass
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(pass)) != 1 || rt == nil {
		return nil
	}
	return rt
}

// bySource: Zugang mit „Anmeldung per IP“ für diese Client-Adresse.
func (in *instance) bySource(ip netip.Addr) *peerRT {
	mgr.Lock()
	defer mgr.Unlock()
	for _, rt := range in.sources {
		for _, p := range rt.sources {
			if p.Contains(ip) {
				return rt
			}
		}
	}
	return nil
}

// track meldet eine Verbindung an (Limit pro Zugang); nil = Limit erreicht.
func (in *instance) track(c net.Conn, rt *peerRT, ip netip.Addr) *tracked {
	mgr.Lock()
	defer mgr.Unlock()
	if !rt.active || mgr.peers[rt.id] != rt || rt.conns >= in.cfg.MaxConns {
		return nil
	}
	t := &tracked{client: c, peer: rt, ip: ip, inst: in}
	mgr.conns[t] = struct{}{}
	if rt.conns == 0 {
		rt.since = time.Now().Unix()
	}
	rt.conns++
	rt.lastIP = ip.String()
	return t
}

func (t *tracked) done() {
	mgr.Lock()
	defer mgr.Unlock()
	if _, ok := mgr.conns[t]; !ok {
		return
	}
	delete(mgr.conns, t)
	t.peer.conns--
}

func (t *tracked) setUpstream(u net.Conn) bool {
	mgr.Lock()
	defer mgr.Unlock()
	if _, ok := mgr.conns[t]; !ok { // inzwischen getrennt
		return false
	}
	t.upstream = u
	return true
}

// ---------- Ziel prüfen und verbinden ----------

var errNotAllowed = errors.New("Ziel nicht erlaubt")
var errNoRoute = errors.New("Ausgang nicht verfügbar")
var errV6 = errors.New("IPv6-Ziel über eine Ausgangsgruppe")

// allowLocal: nur für Tests (Ziel auf 127.0.0.1)
var allowLocal = false

// blockedNets: zusätzlich zu Loopback/privat/Link-local/Multicast nie erreichbar – CGNAT/Tailscale,
// Sonderbereiche und IPv6-Übergänge, über die sich IPv4-Ziele (auch private) verstecken ließen.
var blockedNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4",
		"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32", "2002::/16", "fec0::/10"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// blocked: Ziele, die über den Proxy nie erreichbar sein dürfen (lokale Netze, Proxmox-Host,
// Tailscale, Multicast …). Die öffentlichen Adressen des Servers selbst prüft dial über mgr.self.
func blocked(a netip.Addr) bool {
	a = a.Unmap()
	if allowLocal && a.IsLoopback() {
		return false
	}
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// selfPrefixes: öffentliche Adressen des Servers (Domain aus den Einstellungen und den Proxy-Servern) –
// IPv4 genau, IPv6 als /64. Darüber wären sonst Dienste des Proxmox-Hosts erreichbar.
func selfPrefixes(env *proto.Env, servers []*proto.ServerBundle) ([]netip.Prefix, bool) {
	if env.Sys == nil || env.Sys.DryRun() {
		return nil, true
	}
	hosts := map[string]bool{}
	if env.Global.ServerHost != "" {
		hosts[env.Global.ServerHost] = true
	}
	for _, sb := range servers {
		if h := load(sb.Server).Host; h != "" {
			hosts[h] = true
		}
	}
	var out []netip.Prefix
	ok := true
	for h := range hosts {
		if a, err := netip.ParseAddr(h); err == nil {
			out = append(out, hostPrefix(a))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		cancel()
		if err != nil {
			ok = false
			continue
		}
		for _, a := range ips {
			out = append(out, hostPrefix(a))
		}
	}
	return out, ok
}

func hostPrefix(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

func (in *instance) dial(ctx context.Context, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return nil, errNotAllowed
	}
	mgr.Lock()
	cfg, route, group, res, self := in.cfg, in.route, in.group, in.resolver, mgr.self
	mgr.Unlock()
	if port == 25 && cfg.BlockSMTP {
		return nil, errNotAllowed
	}
	var mark uint32
	if group != 0 {
		if !route.Enabled {
			return nil, errNoRoute
		}
		mark = route.Mark
	}
	// Direkt über den Server gehen IPv4 und IPv6 (IPv4 bevorzugt); Ausgänge können nur IPv4.
	var ips []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.Is6() && group != 0 {
			return nil, errV6
		}
		ips = []netip.Addr{a}
	} else {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ips, err = res.LookupNetIP(rctx, "ip4", host)
		if group == 0 {
			if v6, err6 := res.LookupNetIP(rctx, "ip6", host); err6 == nil && len(v6) > 0 {
				ips = append(ips, v6...)
				err = nil
			}
		}
		cancel()
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = &net.DNSError{Err: "keine Adresse", Name: host, IsNotFound: true}
			}
			return nil, err
		}
	}
	d := exits.Dialer(mark)
	var lastErr error = errNotAllowed
	for _, a := range ips {
		a = a.Unmap()
		if blocked(a) || inPrefixes(self, a) {
			continue
		}
		nw := "tcp4"
		if a.Is6() {
			nw = "tcp6"
		}
		c, err := d.DialContext(ctx, nw, netip.AddrPortFrom(a, uint16(port)).String())
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// dialReason: verständlicher Grund für ein fehlgeschlagenes Verbinden (Antwort an den Client und Ereignis).
func (in *instance) dialReason(target string, err error) (kind, msg string) {
	mgr.Lock()
	via := "direkt über den Server"
	if in.group != 0 {
		via = "über die Ausgangsgruppe „" + in.route.Name + "“"
	}
	mgr.Unlock()
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, errNotAllowed):
		return "notallowed", "Ziel " + target + " ist über den Proxy nicht erlaubt (lokales Netz, Server selbst oder Port 25)"
	case errors.Is(err, errNoRoute):
		return "noroute", "die Ausgangsgruppe ist deaktiviert oder gelöscht"
	case errors.Is(err, errV6):
		return "v6", "Ziel " + target + " ist eine IPv6-Adresse – Ausgangsgruppen können nur IPv4; im Client die Namensauflösung über den Proxy einschalten (bei curl socks5h://)"
	case errors.As(err, &dnsErr):
		return "dns", "Name " + target + " ließ sich nicht auflösen (" + via + "): " + dnsErr.Err
	}
	return "dial", "Verbindung zu " + target + " fehlgeschlagen (" + via + "): " + err.Error()
}

// ---------- Weiterleiten mit Zählung und Drosselung ----------

// metered: Verbindung zum Client – Read = Upload des Nutzers, Write = Download. Gezählt und
// gedrosselt wird erst nach der Anmeldung (rt gesetzt); idle = Leerlauf-Timeout aktiv.
type metered struct {
	net.Conn
	rt   *peerRT
	idle bool
}

func (m *metered) Read(b []byte) (int, error) {
	if m.rt == nil {
		return m.Conn.Read(b)
	}
	if m.rt.bUp.limited() && len(b) > 16384 {
		b = b[:16384]
	}
	if m.idle {
		_ = m.Conn.SetReadDeadline(time.Now().Add(idleTimeout))
	}
	n, err := m.Conn.Read(b)
	if n > 0 {
		m.rt.up.Add(int64(n))
		m.rt.bUp.take(n)
	}
	return n, err
}

func (m *metered) Write(b []byte) (int, error) {
	if m.rt == nil {
		return m.Conn.Write(b)
	}
	total := 0
	for len(b) > 0 {
		chunk := b
		if m.rt.bDown.limited() && len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		m.rt.bDown.take(len(chunk))
		if m.idle {
			_ = m.Conn.SetWriteDeadline(time.Now().Add(idleTimeout))
		}
		n, err := m.Conn.Write(chunk)
		total += n
		m.rt.down.Add(int64(n))
		if err != nil {
			return total, err
		}
		b = b[n:]
	}
	return total, nil
}

// rw: gepufferter Leser + Schreiber (bereits gelesene Daten gehen nicht verloren).
type rw struct {
	io.Reader
	io.Writer
}

type deadlineConn struct{ net.Conn }

func (d deadlineConn) Read(b []byte) (int, error) {
	_ = d.Conn.SetReadDeadline(time.Now().Add(idleTimeout))
	return d.Conn.Read(b)
}

// relay kopiert in beide Richtungen, bis eine Seite schließt.
func relay(client io.ReadWriter, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, client)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, deadlineConn{up})
		done <- struct{}{}
	}()
	<-done
	_ = up.SetDeadline(time.Now().Add(5 * time.Second))
	<-done
}

// bucket: einfacher Token-Bucket (Bytes pro Sekunde), gemeinsam für alle Verbindungen eines Zugangs.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

func (b *bucket) setRate(mbit float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := mbit * 1e6 / 8
	if r != b.rate {
		b.rate, b.tokens, b.last = r, 0, time.Now()
	}
}

func (b *bucket) limited() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate > 0
}

func (b *bucket) take(n int) {
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return
	}
	now := time.Now()
	burst := max(b.rate/4, 64*1024)
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	b.tokens -= float64(n)
	wait := time.Duration(0)
	if b.tokens < 0 {
		wait = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// ---------- SOCKS5 ----------

func (in *instance) serveSOCKS(c net.Conn, ip netip.Addr) {
	m := &metered{Conn: c}
	br := bufio.NewReader(m)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 || hdr[1] == 0 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	var rt *peerRT
	hasPW, hasNone := false, false
	for _, m := range methods {
		hasPW = hasPW || m == 2
		hasNone = hasNone || m == 0
	}
	switch {
	case hasPW:
		_, _ = c.Write([]byte{5, 2})
		// RFC 1929
		h := make([]byte, 2)
		if _, err := io.ReadFull(br, h); err != nil || h[0] != 1 {
			return
		}
		u := make([]byte, h[1])
		if _, err := io.ReadFull(br, u); err != nil {
			return
		}
		pl, err := br.ReadByte()
		if err != nil {
			return
		}
		p := make([]byte, pl)
		if _, err := io.ReadFull(br, p); err != nil {
			return
		}
		if rt = in.login(string(u), string(p)); rt == nil {
			_, _ = c.Write([]byte{1, 1})
			in.loginFailed(ip, string(u), string(p), "SOCKS5")
			return
		}
		_, _ = c.Write([]byte{1, 0})
	case hasNone:
		if rt = in.bySource(ip); rt == nil {
			_, _ = c.Write([]byte{5, 0xff})
			in.notice(ip, "noauth", "SOCKS5 ohne Benutzername/Passwort, und die Adresse gehört zu keinem Zugang mit „Anmeldung per IP“")
			return
		}
		_, _ = c.Write([]byte{5, 0})
	default:
		_, _ = c.Write([]byte{5, 0xff})
		in.notice(ip, "method", "der SOCKS5-Client bietet keine unterstützte Anmeldeart an")
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 5 {
		return
	}
	reply := func(code byte) { _, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if req[1] != 1 { // nur CONNECT
		reply(7)
		if req[1] == 3 {
			in.notice(ip, "udp", "der Client verlangt UDP (UDP ASSOCIATE) – der Proxy leitet nur TCP weiter")
		}
		return
	}
	var host string
	switch req[3] {
	case 1:
		a := make([]byte, 4)
		if _, err := io.ReadFull(br, a); err != nil {
			return
		}
		host = netip.AddrFrom4([4]byte(a)).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil || l == 0 {
			return
		}
		a := make([]byte, l)
		if _, err := io.ReadFull(br, a); err != nil {
			return
		}
		host = string(a)
	case 4:
		a := make([]byte, 16)
		if _, err := io.ReadFull(br, a); err != nil {
			return
		}
		host = netip.AddrFrom16([16]byte(a)).Unmap().String()
	default:
		reply(8)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	t := in.track(c, rt, ip)
	if t == nil {
		reply(2)
		in.limitHit(ip, rt)
		return
	}
	m.rt = rt
	defer t.done()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	up, err := in.dial(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	cancel()
	if err != nil {
		kind, msg := in.dialReason(net.JoinHostPort(host, strconv.Itoa(port)), err)
		switch kind {
		case "notallowed":
			reply(2)
		case "noroute":
			reply(3)
		case "v6":
			reply(8)
		case "dns":
			reply(4)
		default:
			reply(5)
		}
		in.notice(ip, "dial-"+kind, msg)
		return
	}
	if !t.setUpstream(up) {
		_ = up.Close()
		return
	}
	reply(0)
	_ = c.SetDeadline(time.Time{})
	m.idle = true
	relay(rw{br, m}, up)
}

// ---------- HTTP ----------

func (in *instance) serveHTTP(c net.Conn, ip netip.Addr) {
	m := &metered{Conn: c}
	br := bufio.NewReader(m)
	var rt *peerRT
	var t *tracked
	defer func() {
		if t != nil {
			t.done()
		}
	}()
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		// Anmeldung (bei jeder Anfrage dieselbe)
		who, u, p := in.authHTTP(req, ip)
		if who == nil {
			// ohne Zugangsdaten ist 407 der normale erste Schritt (Browser fragen dann nach) → nicht melden
			writeStatus(c, http.StatusProxyAuthRequired, "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n")
			if req.Header.Get("Proxy-Authorization") != "" {
				in.loginFailed(ip, u, p, "HTTP")
			}
			return
		}
		if rt != nil && who != rt {
			return
		}
		if rt == nil {
			rt = who
			if t = in.track(c, rt, ip); t == nil {
				writeStatus(c, http.StatusTooManyRequests, "")
				in.limitHit(ip, rt)
				return
			}
			m.rt = rt
		}
		_ = c.SetDeadline(time.Time{})
		m.idle = true
		client := m
		if req.Method == http.MethodConnect {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			up, err := in.dial(ctx, req.Host)
			cancel()
			if err != nil {
				_, msg := in.dialReason(req.Host, err)
				writeStatusMsg(client, dialStatus(err), "", msg)
				in.notice(ip, "dial", msg)
				return
			}
			if !t.setUpstream(up) {
				_ = up.Close()
				return
			}
			_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
			relay(rw{br, m}, up)
			return
		}
		if req.URL.Scheme != "http" || req.URL.Host == "" {
			writeStatus(client, http.StatusBadRequest, "")
			return
		}
		req.RequestURI = ""
		for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
			req.Header.Del(h)
		}
		resp, err := in.transport.RoundTrip(req) // Körper kommt über br (gezählt)
		if err != nil {
			_, msg := in.dialReason(req.URL.Host, err)
			writeStatusMsg(client, dialStatus(err), "", msg)
			in.notice(ip, "dial", msg)
			return
		}
		resp.Header.Del("Connection")
		resp.Header.Del("Keep-Alive")
		last := req.Close || resp.Close || (resp.ContentLength < 0 && len(resp.TransferEncoding) == 0)
		err = resp.Write(client)
		resp.Body.Close()
		if err != nil || last {
			return
		}
		_ = c.SetDeadline(time.Now().Add(idleTimeout))
	}
}

// authHTTP liefert den Zugang (nil = abgelehnt) und die gesendeten Zugangsdaten (für die Meldung).
func (in *instance) authHTTP(req *http.Request, ip netip.Addr) (*peerRT, string, string) {
	h := req.Header.Get("Proxy-Authorization")
	if h == "" {
		return in.bySource(ip), "", ""
	}
	scheme, val, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return nil, "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(val))
	if err != nil {
		return nil, "", ""
	}
	u, p, ok := strings.Cut(string(raw), ":")
	if !ok {
		return nil, "", ""
	}
	return in.login(u, p), u, p
}

// notice: abgelehnte Verbindung melden (gedrosselt, siehe notes.go).
func (in *instance) notice(ip netip.Addr, kind, why string) {
	mgr.Lock()
	name := in.name
	mgr.Unlock()
	note("info", ip.String()+"|"+kind, fmt.Sprintf("Proxy „%s“: Verbindung von %s abgelehnt – %s", name, ip, why))
}

// limitHit: Zugang hat seine Höchstzahl gleichzeitiger Verbindungen erreicht.
func (in *instance) limitHit(ip netip.Addr, rt *peerRT) {
	mgr.Lock()
	name, user, max := in.name, rt.user, in.cfg.MaxConns
	mgr.Unlock()
	note("warn", ip.String()+"|limit|"+user, fmt.Sprintf("Proxy „%s“: Zugang „%s“ hat die Höchstzahl gleichzeitiger Verbindungen erreicht (%d) – weitere von %s abgelehnt", name, user, max, ip))
}

func dialStatus(err error) int {
	switch {
	case errors.Is(err, errNotAllowed):
		return http.StatusForbidden
	case errors.Is(err, errNoRoute):
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

func writeStatus(w io.Writer, code int, extra string) { writeStatusMsg(w, code, extra, "") }

// writeStatusMsg: Fehlerantwort mit Grund im Text (curl -v / Browser zeigen ihn an).
func writeStatusMsg(w io.Writer, code int, extra, msg string) {
	body := http.StatusText(code) + "\n"
	if msg != "" {
		body += msg + "\n"
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n%sContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), extra, len(body), body)
}

// ---------- Statistik ----------

func (Driver) Collect(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.Usage, error) {
	mgr.Lock()
	defer mgr.Unlock()
	res := map[int64]proto.Usage{}
	now := time.Now().Unix()
	for _, sb := range servers {
		for _, pb := range sb.Peers {
			rt := mgr.peers[pb.Peer.ID]
			if rt == nil {
				continue
			}
			up, down := rt.up.Load(), rt.down.Load()
			u := proto.Usage{Up: up - rt.lastUp, Down: down - rt.lastDown}
			rt.lastUp, rt.lastDown = up, down
			if rt.conns > 0 || u.Up+u.Down > 0 {
				u.Seen = now
				u.Endpoint = rt.lastIP
			}
			if u.Up+u.Down > 0 || u.Seen > 0 {
				res[pb.Peer.ID] = u
			}
		}
	}
	return res, nil
}

func (Driver) Live(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.LiveSample, error) {
	mgr.Lock()
	defer mgr.Unlock()
	res := map[int64]proto.LiveSample{}
	for _, sb := range servers {
		for _, pb := range sb.Peers {
			rt := mgr.peers[pb.Peer.ID]
			if rt == nil {
				continue
			}
			s := proto.LiveSample{Up: rt.up.Load(), Down: rt.down.Load(), Online: rt.conns > 0}
			if s.Online {
				s.Endpoint, s.Since = rt.lastIP, rt.since
			}
			res[pb.Peer.ID] = s
		}
	}
	return res, nil
}

// ---------- Anzeige ----------

func linkHost(env *proto.Env, c serverCfg) string {
	if c.Host != "" {
		return c.Host
	}
	if env.Global.ServerHost != "" {
		return env.Global.ServerHost
	}
	return "SERVER"
}

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
	c := load(sb.Server)
	host := linkHost(env, c)
	user, pass := proto.Str(pb.Peer.Secrets, "username"), proto.Str(pb.Peer.Secrets, "password")
	ui := url.UserPassword(user, pass)
	info := [][2]string{{"Server", host}}
	var links []proto.Link
	if c.Socks {
		info = append(info, [2]string{"SOCKS5-Port", strconv.Itoa(c.SocksPort)})
		// socks5h: Namen löst der Proxy auf (DNS über den Ausgang, keine IPv6-Ziele vom Client)
		links = append(links, proto.Link{Label: "SOCKS5", URL: (&url.URL{Scheme: "socks5h", User: ui, Host: net.JoinHostPort(host, strconv.Itoa(c.SocksPort))}).String()})
	}
	if c.HTTP {
		info = append(info, [2]string{"HTTP-Proxy-Port", strconv.Itoa(c.HTTPPort)})
		links = append(links, proto.Link{Label: "HTTP-Proxy", URL: (&url.URL{Scheme: "http", User: ui, Host: net.JoinHostPort(host, strconv.Itoa(c.HTTPPort))}).String()})
	}
	info = append(info, [2]string{"Benutzername", user}, [2]string{"Passwort", pass})
	exit := "direkt über den Server"
	if g, ok := env.Global.Groups[groupOf(c)]; ok {
		exit = "Ausgangsgruppe „" + g.Name + "“"
	}
	info = append(info, [2]string{"Ausgang", exit})
	if s := strList(pb.Peer.Settings["source_ips"]); len(s) > 0 {
		info = append(info, [2]string{"Anmeldung per IP", strings.Join(s, ", ")})
	}
	return &proto.ClientConfig{
		Title: "Proxy – " + sb.Server.Name,
		Links: links,
		Info:  info,
		Instructions: []string{
			"In der App bzw. in den Netzwerkeinstellungen des Geräts einen Proxy eintragen: Server, Port, Benutzername und Passwort.",
			"SOCKS5 ist für Apps meist die bessere Wahl; Fernseher und Browser kennen oft nur „HTTP-Proxy“.",
			"Kann ein Gerät kein Passwort (häufig bei Fernsehern), beim Zugang unter „Erweitert“ die feste öffentliche IP des Anschlusses für die Anmeldung per IP eintragen.",
			"Achtung: Die Verbindung zum Proxy ist unverschlüsselt – Benutzername und Passwort können unterwegs mitgelesen werden. Inhalte von HTTPS-Seiten bleiben verschlüsselt.",
		},
	}, nil
}

func (Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	return nil
}

func (Driver) Ports(srv *store.Server) []proto.Port {
	c := load(srv)
	var out []proto.Port
	if c.Socks {
		out = append(out, proto.Port{Port: c.SocksPort, Proto: "tcp", Note: "SOCKS5-Proxy " + srv.Name})
	}
	if c.HTTP {
		out = append(out, proto.Port{Port: c.HTTPPort, Proto: "tcp", Note: "HTTP-Proxy " + srv.Name})
	}
	return out
}

func (Driver) Status(env *proto.Env, srv *store.Server) proto.Status {
	if !srv.Enabled {
		return proto.Status{Detail: "deaktiviert"}
	}
	mgr.Lock()
	defer mgr.Unlock()
	in := mgr.inst[srv.ID]
	if in == nil {
		return proto.Status{Detail: "noch nicht gestartet"}
	}
	if in.err != "" {
		return proto.Status{Detail: in.err}
	}
	var parts []string
	if in.socks != nil {
		parts = append(parts, fmt.Sprintf("SOCKS5 %d", in.cfg.SocksPort))
	}
	if in.http != nil {
		parts = append(parts, fmt.Sprintf("HTTP %d", in.cfg.HTTPPort))
	}
	if len(parts) == 0 {
		return proto.Status{Detail: "SOCKS5 und HTTP ausgeschaltet"}
	}
	n := 0
	for t := range mgr.conns {
		if t.inst == in {
			n++
		}
	}
	detail := strings.Join(parts, ", ") + fmt.Sprintf(" – %d Verbindungen", n)
	if in.group != 0 {
		if !in.route.Enabled {
			return proto.Status{Detail: "Ausgangsgruppe deaktiviert – Verbindungen werden abgewiesen"}
		}
		detail += " – über „" + in.route.Name + "“"
	}
	return proto.Status{Running: true, Detail: detail}
}

// strList: Liste aus den Einstellungen ([]any aus der Datenbank oder []string).
func strList(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		var out []string
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
