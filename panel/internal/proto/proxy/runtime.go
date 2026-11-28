package proxy

// Laufzeit des Proxys: Instanzen, Zuhörer und Annehmen von Verbindungen.

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
)

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
	pol        *proto.Policy   // Ziel-Regeln dieses Zugangs (nil = direkt über den Server)
	transport  *http.Transport // für einfache HTTP-Anfragen (hält Verbindungen zu Zielen offen)
}

type tracked struct {
	client, upstream net.Conn
	peer             *peerRT
	ip               netip.Addr
	inst             *instance
	group            int64 // Ausgangsgruppe der Verbindung (0 = direkt, -1 = einfache HTTP-Anfragen, je Ziel verschieden)
}

func (t *tracked) setGroup(g int64) {
	mgr.Lock()
	t.group = g
	mgr.Unlock()
}

func (t *tracked) close() {
	_ = t.client.Close()
	if t.upstream != nil {
		_ = t.upstream.Close()
	}
}

type instance struct {
	id      int64
	name    string
	cfg     serverCfg
	acl     *proto.ACL
	users   map[string]*peerRT
	sources []*peerRT
	socks   net.Listener
	http    net.Listener
	err     string
}

var mgr = struct {
	sync.Mutex
	inst  map[int64]*instance
	peers map[int64]*peerRT
	conns map[*tracked]struct{}
	perIP map[netip.Addr]int
	total int
	self  []netip.Prefix // öffentliche Adressen des Servers (nie als Ziel)
	// Ausgangsgruppen, Ziellisten und DNS je Gruppe (Stand des letzten Apply)
	groups    map[int64]proto.GroupRoute
	lists     map[int64][]netip.Prefix
	resolvers map[int64]*net.Resolver
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
	// Gruppen: geänderte Markierung/DNS → Verbindungen über diese Gruppe neu aufbauen lassen
	regroup := map[int64]bool{}
	for id, g := range env.Global.Groups {
		if old, ok := mgr.groups[id]; ok && (old.Mark != g.Mark || old.Enabled != g.Enabled || strings.Join(old.DNS, ",") != strings.Join(g.DNS, ",")) {
			regroup[id] = true
		}
	}
	for id := range mgr.groups {
		if _, ok := env.Global.Groups[id]; !ok {
			regroup[id] = true
		}
	}
	mgr.groups, mgr.lists = env.Global.Groups, env.Global.TargetLists
	res := map[int64]*net.Resolver{}
	for id, g := range mgr.groups {
		if r := mgr.resolvers[id]; r != nil && !regroup[id] {
			res[id] = r
		} else if len(g.DNS) > 0 {
			res[id] = exits.Resolver(g.Mark, g.DNS)
		}
	}
	mgr.resolvers = res
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
		in.acl = env.Global.ACLs[sv.ID]
		rerouted := map[*peerRT]bool{} // Ziel-Regeln geändert → Verbindungen des Zugangs neu aufbauen lassen
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
			pol := env.Global.Policies[p.ID]
			oldKey, newKey := "", ""
			if rt.pol != nil {
				oldKey = rt.pol.Key
			}
			if pol != nil {
				newKey = pol.Key
			}
			if oldKey != newKey {
				rerouted[rt] = true
				if rt.transport != nil {
					rt.transport.CloseIdleConnections()
				}
			}
			rt.pol = pol
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
			if rerouted[t.peer] || regroup[t.group] || !t.peer.active || mgr.peers[t.peer.id] != t.peer || t.peer.srv != in.id || !in.acl.Allowed(t.ip) ||
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
	for id, rt := range mgr.peers {
		if !seenPeers[id] {
			if rt.transport != nil {
				rt.transport.CloseIdleConnections()
			}
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
	for _, rt := range mgr.peers {
		if rt.transport != nil {
			rt.transport.CloseIdleConnections()
		}
	}
	for t := range mgr.conns {
		if t.group == groupID {
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
				// Ein unerwarteter Fehler in einer Verbindung darf nicht das ganze Panel beenden
				if r := recover(); r != nil {
					note("error", "panic", fmt.Sprintf("Proxy „%s“: interner Fehler abgefangen: %v", name, r))
				}
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
