package proxy

// Ziel prüfen, über Ausgänge verbinden, Weiterleiten mit Zählung und Drosselung.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
)

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

// dialErr: Fehler beim Verbinden samt Gruppe, über die es gehen sollte (für die Meldung).
type dialErr struct {
	group int64
	err   error
}

func (e *dialErr) Error() string { return e.err.Error() }
func (e *dialErr) Unwrap() error { return e.err }

// dial verbindet zum Ziel – je nach Ziel-Regeln des Zugangs direkt oder über eine Ausgangsgruppe.
// group = gewählte Gruppe (0 = direkt).
func (in *instance) dial(ctx context.Context, addr string, rt *peerRT) (c net.Conn, group int64, err error) {
	c, group, err = in.dial0(ctx, addr, rt)
	if err != nil {
		err = &dialErr{group, err}
	}
	return
}

func (in *instance) dial0(ctx context.Context, addr string, rt *peerRT) (net.Conn, int64, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, errNotAllowed
	}
	mgr.Lock()
	cfg, self, pol, lists := in.cfg, mgr.self, rt.pol, mgr.lists
	groups, resolvers := mgr.groups, mgr.resolvers
	mgr.Unlock()
	if port == 25 && cfg.BlockSMTP {
		return nil, 0, errNotAllowed
	}
	resolver := func(g int64) *net.Resolver {
		if r := resolvers[g]; g != 0 && r != nil {
			return r
		}
		return net.DefaultResolver
	}
	// lookup: direkt über den Server IPv4 und IPv6 (IPv4 bevorzugt); Ausgänge können nur IPv4.
	lookup := func(g int64) ([]netip.Addr, error) {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		ips, err := resolver(g).LookupNetIP(rctx, "ip4", host)
		if g == 0 {
			if v6, err6 := resolver(g).LookupNetIP(rctx, "ip6", host); err6 == nil && len(v6) > 0 {
				ips, err = append(ips, v6...), nil
			}
		}
		if err == nil && len(ips) == 0 {
			err = &net.DNSError{Err: "keine Adresse", Name: host, IsNotFound: true}
		}
		return ips, err
	}
	var group int64
	var ips []netip.Addr
	if a, perr := netip.ParseAddr(host); perr == nil {
		a = a.Unmap()
		group, _ = pol.Match("", a, lists)
		if a.Is6() && group != 0 {
			return nil, group, errV6
		}
		ips = []netip.Addr{a}
	} else {
		// Erst nach dem Namen entscheiden; gibt es Regeln nach Adresse, den Namen auflösen und
		// mit der Adresse neu entscheiden (bei anderem Ergebnis über die richtige Gruppe erneut auflösen).
		group, _ = pol.Match(host, netip.Addr{}, lists)
		if ips, err = lookup(group); err != nil {
			return nil, group, err
		}
		if g2, _ := pol.Match(host, ips[0], lists); g2 != group {
			group = g2
			if ips, err = lookup(group); err != nil {
				return nil, group, err
			}
		}
	}
	var mark uint32
	if group != 0 {
		g, ok := groups[group]
		if !ok || !g.Enabled {
			return nil, group, errNoRoute
		}
		mark = g.Mark
		// Block-Prüfung: Ausgang je Ziel (Ausnahme) und sofortiges Ausweichen bei einem Fehlschlag
		if ExitRoute != nil {
			name := host
			if _, perr := netip.ParseAddr(host); perr == nil {
				name = ""
			}
			if choices := ExitRoute(group, name); len(choices) > 0 {
				c, err := dialChoices(ctx, group, name, choices, ips, port, self)
				return c, group, err
			}
		}
	}
	d := exits.Dialer(mark)
	var lastErr error = errNotAllowed
	for _, a := range ips {
		a = a.Unmap()
		if blocked(a) || inPrefixes(self, a) || (a.Is6() && group != 0) {
			continue
		}
		nw := "tcp4"
		if a.Is6() {
			nw = "tcp6"
		}
		c, err := d.DialContext(ctx, nw, netip.AddrPortFrom(a, uint16(port)).String())
		if err == nil {
			return c, group, nil
		}
		lastErr = err
	}
	return nil, group, lastErr
}

// Block-Prüfung (von der Engine gesetzt): Ausgänge für ein Ziel in der Reihenfolge, in der sie
// versucht werden (leer = wie bisher über die Gruppen-Markierung), und Meldung von Fehlschlägen.
var (
	ExitRoute func(group int64, host string) []exits.RouteChoice
	ExitFail  func(group int64, host string, exit int64, detail string)
)

// dialChoices verbindet über den ersten Ausgang; schlägt das fehl (Zeitüberschreitung, abgelehnt,
// zurückgesetzt), sofort über den nächsten – der Fehlschlag wird der Block-Prüfung gemeldet.
func dialChoices(ctx context.Context, group int64, name string, choices []exits.RouteChoice, ips []netip.Addr, port int, self []netip.Prefix) (net.Conn, error) {
	var lastErr error = errNotAllowed
	for i, ch := range choices {
		d := exits.Dialer(ch.Mark)
		if i < len(choices)-1 {
			d.Timeout = 6 * time.Second // beim Ausweichen nicht lange warten
		}
		tried := false
		for _, a := range ips {
			a = a.Unmap()
			if blocked(a) || inPrefixes(self, a) || a.Is6() {
				continue
			}
			tried = true
			c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(a, uint16(port)).String())
			if err == nil {
				return c, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				return nil, err
			}
		}
		if !tried {
			return nil, lastErr
		}
		if ExitFail != nil && name != "" {
			ExitFail(group, name, ch.Exit, "Proxy: "+shortErr(lastErr))
		}
	}
	return nil, lastErr
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded"):
		return "Zeitüberschreitung beim Verbinden"
	case strings.Contains(s, "refused"):
		return "Verbindung abgelehnt"
	case strings.Contains(s, "reset"):
		return "Verbindung zurückgesetzt"
	case strings.Contains(s, "unreachable"):
		return "Ziel nicht erreichbar"
	}
	if len(s) > 120 {
		s = s[:120] + " …"
	}
	return s
}

// httpTransport: Transport eines Zugangs für einfache HTTP-Anfragen (jede Verbindung wird nach
// den Ziel-Regeln des Zugangs aufgebaut).
func (in *instance) httpTransport(rt *peerRT) *http.Transport {
	mgr.Lock()
	defer mgr.Unlock()
	if rt.transport == nil {
		rt.transport = &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 32, IdleConnTimeout: 60 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second, TLSHandshakeTimeout: 15 * time.Second,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				c, _, err := in.dial(ctx, addr, rt)
				return c, err
			}}
	}
	return rt.transport
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
	via := "direkt über den Server"
	var de *dialErr
	if errors.As(err, &de) && de.group != 0 {
		mgr.Lock()
		via = "über die Ausgangsgruppe „" + mgr.groups[de.group].Name + "“"
		mgr.Unlock()
	}
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
