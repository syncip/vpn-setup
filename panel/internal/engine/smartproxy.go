package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"vpnpanel/internal/exits"
)

// SmartDNS-Proxy: Für Geräte ohne VPN antwortet der Panel-DNS bei SmartDNS-Domains mit der Adresse
// des Servers. nginx reicht HTTPS-Verbindungen mit diesen Namen (SNI) hierher weiter (mit PROXY-Protocol,
// damit die echte Absenderadresse bekannt ist). Der Proxy prüft, ob der Absender freigegeben ist und
// der Name in seinem Profil über eine Gruppe läuft, löst ihn über die Gruppe auf und verbindet sich
// über deren Ausgang – die Verschlüsselung bleibt Ende-zu-Ende, der Server sieht nur den Namen.

const smartAddr = "127.0.0.1:8477"

type smartProxy struct {
	mu      sync.Mutex
	ln      net.Listener
	domains []string
	active  atomic.Int64
	total   atomic.Int64
	denied  atomic.Int64
	bytes   atomic.Int64
	lastErr string
	recent  map[string]*SmartHit // Domain → Zähler
}

// SmartHit: Nutzung einer SmartDNS-Domain über den Proxy (seit dem Start).
type SmartHit struct {
	Domain string `json:"domain"`
	Group  int64  `json:"group"`
	Conns  int64  `json:"conns"`
	Bytes  int64  `json:"bytes"`
	Last   int64  `json:"last"`
	Err    string `json:"err,omitempty"`
}

// SmartDomains: alle SmartDNS-Domains aktiver Profile (für nginx).
func (e *Engine) SmartDomains() []string {
	_, byID := e.dnsProfileFilters()
	seen := map[string]bool{}
	var out []string
	for _, f := range byID {
		for d := range f.smart {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

// applySmart startet bzw. beendet den Proxy (nur nötig, wenn Geräte ohne VPN den Panel-DNS nutzen).
func (e *Engine) applySmart(domains []string) {
	p := &e.smart
	p.mu.Lock()
	defer p.mu.Unlock()
	p.domains = domains
	need := len(domains) > 0 && e.Setting("dns_enabled") == "1" && (e.dnsPublic() || e.encDNSOn())
	if !need || e.Sys.DryRun() {
		if p.ln != nil {
			_ = p.ln.Close()
			p.ln = nil
		}
		return
	}
	if p.ln != nil {
		return
	}
	ln, err := net.Listen("tcp", smartAddr)
	if err != nil {
		p.lastErr = err.Error()
		e.Log("warn", "SmartDNS-Proxy: "+err.Error())
		return
	}
	p.ln = &proxyproto.Listener{Listener: ln, ReadHeaderTimeout: 5 * time.Second}
	go p.serve(e, p.ln)
}

// smartNeedsNginx: Diese Namen leitet nginx an den Proxy (leer = keine).
func (e *Engine) smartNginxNames() []string {
	if e.Setting("dns_enabled") != "1" || !(e.dnsPublic() || e.encDNSOn()) {
		return nil
	}
	return e.SmartDomains()
}

func (p *smartProxy) serve(e *Engine, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handle(e, c)
	}
}

func (p *smartProxy) note(dom string, gid int64, n int64, errText string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recent == nil {
		p.recent = map[string]*SmartHit{}
	}
	h := p.recent[dom]
	if h == nil {
		if len(p.recent) > 500 {
			return
		}
		h = &SmartHit{Domain: dom, Group: gid}
		p.recent[dom] = h
	}
	h.Group = gid
	if n < 0 {
		h.Conns++
	} else {
		h.Bytes += n
	}
	h.Last = time.Now().Unix()
	if errText != "" {
		h.Err = errText
	}
}

func (p *smartProxy) handle(e *Engine, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	src, _ := netip.AddrFromSlice(ta.IP)
	src = src.Unmap()
	br := bufio.NewReaderSize(c, 16*1024)
	hello, sni, err := readClientHello(br)
	if err != nil || sni == "" {
		p.denied.Add(1)
		return
	}
	// Wer darf? Freigegebene Geräte ohne VPN (bzw. VPN-Geräte) mit SmartDNS für diesen Namen.
	s := e.dns.sourceOf(src)
	if s == nil {
		s = e.extSourceOf(src)
	}
	if s == nil {
		p.denied.Add(1)
		return
	}
	gid, dom, ok := s.filt.smartMatch(sni)
	if !ok {
		p.denied.Add(1)
		return
	}
	e.dns.mu.Lock()
	gr, gok := e.dns.groups[gid]
	e.dns.mu.Unlock()
	if !gok || !gr.Enabled {
		p.note(dom, gid, -1, "Gruppe deaktiviert")
		return
	}
	p.total.Add(1)
	p.note(dom, gid, -1, "")
	servers := gr.DNS
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "9.9.9.9"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	ips, err := exits.Resolver(gr.Mark, servers).LookupNetIP(ctx, "ip4", sni)
	cancel()
	if err != nil {
		p.note(dom, gid, 0, "Auflösung über die Gruppe: "+shortErr(err))
		return
	}
	pub4, pub6 := e.PublicAddrs()
	var up net.Conn
	for _, a := range ips {
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.IsPrivate() || a == pub4 || a == pub6 {
			continue
		}
		up, err = exits.Dialer(gr.Mark).DialContext(context.Background(), "tcp4", netip.AddrPortFrom(a, 443).String())
		if err == nil {
			break
		}
	}
	if up == nil {
		if err == nil {
			err = errors.New("keine öffentliche Adresse")
		}
		p.note(dom, gid, 0, "Verbinden über die Gruppe: "+shortErr(err))
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	if _, err := up.Write(hello); err != nil {
		return
	}
	p.active.Add(1)
	defer p.active.Add(-1)
	done := make(chan int64, 2)
	go func() { n, _ := io.Copy(up, br); _ = closeWrite(up); done <- n }()
	go func() { n, _ := io.Copy(c, up); _ = closeWrite(c); done <- n }()
	n := <-done + <-done
	p.bytes.Add(n)
	p.note(dom, gid, n, "")
}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120] + " …"
	}
	return s
}

// readClientHello liest den ersten TLS-Datensatz (ClientHello) und liefert ihn samt Servernamen.
func readClientHello(r *bufio.Reader) ([]byte, string, error) {
	hdr, err := r.Peek(5)
	if err != nil {
		return nil, "", err
	}
	if hdr[0] != 0x16 { // Handshake
		return nil, "", errors.New("kein TLS")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > 16*1024-5 {
		return nil, "", errors.New("ClientHello zu groß")
	}
	rec := make([]byte, 5+n)
	if _, err := io.ReadFull(r, rec); err != nil {
		return nil, "", err
	}
	return rec, parseSNI(rec[5:]), nil
}

// parseSNI sucht die Erweiterung server_name im ClientHello ("" = keine).
func parseSNI(b []byte) string {
	if len(b) < 4 || b[0] != 1 { // client_hello
		return ""
	}
	b = b[4:]
	if len(b) < 34 {
		return ""
	}
	b = b[34:] // Version + Zufall
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(b[i])
		}
		if len(b) < lenBytes+l {
			return false
		}
		b = b[lenBytes+l:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // Sitzung, Cipher-Suites, Kompression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	ext := b[2:]
	if l := int(binary.BigEndian.Uint16(b)); l < len(ext) {
		ext = ext[:l]
	}
	for len(ext) >= 4 {
		typ, l := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+l {
			return ""
		}
		data := ext[4 : 4+l]
		ext = ext[4+l:]
		if typ != 0 || len(data) < 2 {
			continue
		}
		list := data[2:]
		for len(list) >= 3 {
			nt, nl := list[0], int(binary.BigEndian.Uint16(list[1:]))
			if len(list) < 3+nl {
				return ""
			}
			if nt == 0 {
				return strings.ToLower(strings.TrimSuffix(string(list[3:3+nl]), "."))
			}
			list = list[3+nl:]
		}
	}
	return ""
}

// SmartStatus: Zustand des SmartDNS-Proxys (Oberfläche).
type SmartStatus struct {
	Running bool       `json:"running"`
	Needed  bool       `json:"needed"` // Geräte ohne VPN nutzen SmartDNS-Profile
	Domains int        `json:"domains"`
	Active  int64      `json:"active"`
	Total   int64      `json:"total"`
	Denied  int64      `json:"denied"`
	Bytes   int64      `json:"bytes"`
	Hits    []SmartHit `json:"hits"`
	Error   string     `json:"error,omitempty"`
	Target4 string     `json:"target4"` // Adresse, mit der der DNS antwortet
	Target6 string     `json:"target6"`
}

func (e *Engine) SmartState() SmartStatus {
	p := &e.smart
	v4, v6 := e.PublicAddrs()
	p.mu.Lock()
	st := SmartStatus{Running: p.ln != nil, Domains: len(p.domains), Error: p.lastErr, Hits: []SmartHit{}}
	for _, h := range p.recent {
		st.Hits = append(st.Hits, *h)
	}
	p.mu.Unlock()
	st.Needed = len(st.Hits) > 0 || (st.Domains > 0 && (e.dnsPublic() || e.encDNSOn()))
	st.Active, st.Total, st.Denied, st.Bytes = p.active.Load(), p.total.Load(), p.denied.Load(), p.bytes.Load()
	sort.Slice(st.Hits, func(i, j int) bool { return st.Hits[i].Last > st.Hits[j].Last })
	if len(st.Hits) > 30 {
		st.Hits = st.Hits[:30]
	}
	if v4.IsValid() {
		st.Target4 = v4.String()
	}
	if v6.IsValid() {
		st.Target6 = v6.String()
	}
	return st
}
