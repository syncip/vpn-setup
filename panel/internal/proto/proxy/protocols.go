package proxy

// Protokolle: SOCKS5 und HTTP-Proxy (CONNECT und einfache Anfragen).

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

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
	up, group, err := in.dial(ctx, net.JoinHostPort(host, strconv.Itoa(port)), rt)
	t.setGroup(group)
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
			// erst melden, dann antworten: sonst kann ein nächster Versuch die Meldung überholen
			if req.Header.Get("Proxy-Authorization") != "" {
				in.loginFailed(ip, u, p, "HTTP")
			}
			writeStatus(c, http.StatusProxyAuthRequired, "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n")
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
			up, group, err := in.dial(ctx, req.Host, rt)
			t.setGroup(group)
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
		t.setGroup(-1)
		resp, err := in.httpTransport(rt).RoundTrip(req) // Körper kommt über br (gezählt)
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
