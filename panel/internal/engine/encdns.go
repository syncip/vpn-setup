package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Verschlüsseltes DNS für Geräte ohne VPN:
//
//   - DoH: https://<kennung>.<dns-host>/dns-query (bzw. https://<dns-host>/dns-query/<kennung>) – über
//     nginx auf Port 443 (SNI), mit PROXY-Protocol zum Panel.
//   - DoT: <kennung>.<dns-host> auf Port 853 (z. B. Android „Privates DNS“), direkt am Panel.
//
// Die Kennung gehört zu einer Freigabe („Ohne VPN“) und bestimmt das Filterprofil – so funktioniert
// es von jedem Netz aus, ohne feste IP. Das Zertifikat (<dns-host> und *.<dns-host>) holt das Panel
// bei Let's Encrypt über die DNS-Prüfung mit der Cloudflare-API; das API-Token steht nur in
// /etc/vpn/secrets.env (CF_API_TOKEN=…), nie in der Datenbank.

const dohAddr = "127.0.0.1:8476"

type encDNS struct {
	mu      sync.Mutex
	cert    *tls.Certificate
	info    CertInfo
	doh     net.Listener
	dot     net.Listener
	dotPort int
	issuing bool
	lastTry time.Time
	lastErr string
	step    string // laufender Schritt beim Ausstellen
	nDoH    atomic.Int64
	nDoT    atomic.Int64
	denied  atomic.Int64
}

// CertInfo: Angaben zum Zertifikat.
type CertInfo struct {
	Names      []string `json:"names"`
	NotAfter   int64    `json:"not_after"`
	NotBefore  int64    `json:"not_before"`
	Issuer     string   `json:"issuer"`
	SelfSigned bool     `json:"self_signed"`
}

func (e *Engine) encDNSHost() string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(e.Setting("dns_tls_host")), "."))
}

// encDNSOn: DoH/DoT eingeschaltet (und Panel-DNS an).
func (e *Engine) encDNSOn() bool {
	return e.Setting("dns_enabled") == "1" && e.Setting("dns_tls") == "1" && e.encDNSHost() != ""
}

func (e *Engine) tlsDir() string { return filepath.Join(e.Cfg.DataDir, "dns-tls") }

// cfToken: Cloudflare-API-Token aus <data>/secrets.env (oder der Umgebung).
func (e *Engine) cfToken() string { return e.secret("CF_API_TOKEN") }

// applyEncDNS startet bzw. beendet DoH/DoT und stößt bei Bedarf das Zertifikat an.
func (e *Engine) applyEncDNS() {
	x := &e.enc
	host := e.encDNSHost()
	on := e.encDNSOn()
	x.mu.Lock()
	defer x.mu.Unlock()
	if !on {
		x.stopLocked()
		return
	}
	if x.cert == nil || !certCovers(x.info, host) {
		x.loadLocked(e, host)
	}
	if x.cert == nil && e.Sys.DryRun() {
		if c, info, err := selfSigned(host); err == nil {
			x.cert, x.info = c, info
		}
	}
	if x.cert == nil {
		x.stopLocked()
		if !x.issuing && x.lastTry.IsZero() && !e.Sys.DryRun() { // danach: RenewEncCert (alle 6 h)
			x.issuing = true
			go e.issueCert(host)
		}
		return
	}
	if e.Sys.DryRun() {
		return
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: x.getCert}
	if x.doh == nil {
		if ln, err := net.Listen("tcp", dohAddr); err != nil {
			e.Log("warn", "DoH: "+err.Error())
		} else {
			pl := &proxyproto.Listener{Listener: ln, ReadHeaderTimeout: 5 * time.Second}
			x.doh = pl
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.serveDoH(w, r) }),
				TLSConfig: cfg.Clone(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second,
				IdleTimeout: 120 * time.Second, ErrorLog: nil}
			srv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
			go func() { _ = srv.ServeTLS(pl, "", "") }()
		}
	}
	port := atoi(e.Setting("dns_dot_port"), 853)
	if x.dot != nil && x.dotPort != port {
		_ = x.dot.Close()
		x.dot = nil
	}
	if x.dot == nil && port > 0 {
		if ln, err := net.Listen("tcp", ":"+strconv.Itoa(port)); err != nil {
			e.Log("warn", fmt.Sprintf("DoT (Port %d): %v", port, err))
		} else {
			x.dot, x.dotPort = ln, port
			go e.serveDoT(tls.NewListener(ln, cfg.Clone()))
		}
	}
}

func (x *encDNS) stopLocked() {
	if x.doh != nil {
		_ = x.doh.Close()
		x.doh = nil
	}
	if x.dot != nil {
		_ = x.dot.Close()
		x.dot = nil
	}
}

func (x *encDNS) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.cert == nil {
		return nil, errors.New("kein Zertifikat")
	}
	return x.cert, nil
}

func certCovers(info CertInfo, host string) bool {
	has, wild := false, false
	for _, n := range info.Names {
		has = has || n == host
		wild = wild || n == "*."+host
	}
	return has && wild
}

func (x *encDNS) loadLocked(e *Engine, host string) {
	c, err := tls.LoadX509KeyPair(filepath.Join(e.tlsDir(), "cert.pem"), filepath.Join(e.tlsDir(), "key.pem"))
	if err != nil {
		return
	}
	info := certInfoOf(&c)
	if !certCovers(info, host) || time.Unix(info.NotAfter, 0).Before(time.Now()) {
		return
	}
	x.cert, x.info = &c, info
}

func certInfoOf(c *tls.Certificate) CertInfo {
	if len(c.Certificate) == 0 {
		return CertInfo{}
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return CertInfo{}
	}
	return CertInfo{Names: leaf.DNSNames, NotAfter: leaf.NotAfter.Unix(), NotBefore: leaf.NotBefore.Unix(), Issuer: leaf.Issuer.CommonName,
		SelfSigned: leaf.Issuer.String() == leaf.Subject.String()}
}

// selfSigned: Ersatz im Testmodus.
func selfSigned(host string) (*tls.Certificate, CertInfo, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, CertInfo{}, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host, "*." + host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, CertInfo{}, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return c, certInfoOf(c), nil
}

// ---------- Anfragen ----------

// clientFor: Richtlinie für DoH/DoT – erst die Kennung, sonst die Absenderadresse (feste Freigabe).
func (e *Engine) clientFor(token string, src netip.Addr) *srcPolicy {
	if token != "" {
		if s := e.extByToken(token, src); s != nil {
			return s
		}
		return nil
	}
	return e.extSource(src, false) // feste Freigaben gelten für DoH/DoT auch ohne „DNS von außen“
}

// tokenOf: Kennung aus dem Namen (<kennung>.<dns-host>).
func (e *Engine) tokenOf(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if h, _, err := net.SplitHostPort(name); err == nil {
		name = h
	}
	base := e.encDNSHost()
	if t, ok := strings.CutSuffix(name, "."+base); ok && t != "" && !strings.Contains(t, ".") {
		return t
	}
	return ""
}

func (e *Engine) serveDoH(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	token := e.tokenOf(r.Host)
	if t, ok := strings.CutPrefix(path, "/dns-query/"); ok && t != "" && !strings.Contains(t, "/") {
		token, path = strings.ToLower(t), "/dns-query"
	}
	if path != "/dns-query" {
		http.Error(w, "DNS-over-HTTPS: /dns-query", http.StatusNotFound)
		return
	}
	var q []byte
	switch r.Method {
	case http.MethodGet:
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.URL.Query().Get("dns"), "="))
		if err != nil {
			http.Error(w, "dns fehlt", http.StatusBadRequest)
			return
		}
		q = b
	case http.MethodPost:
		b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			return
		}
		q = b
	default:
		http.Error(w, "nur GET/POST", http.StatusMethodNotAllowed)
		return
	}
	if len(q) < 12 {
		http.Error(w, "zu kurz", http.StatusBadRequest)
		return
	}
	src := netip.Addr{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		src = ap.Addr().Unmap()
	}
	via := "doh"
	if token == "" {
		via = "doh-addr"
	}
	s := e.clientFor(token, src)
	if s == nil {
		e.enc.denied.Add(1)
		if src.IsValid() {
			e.noteExt(src, 0, queryName(q), true, false, via)
		}
		http.Error(w, "unbekannte Kennung", http.StatusForbidden)
		return
	}
	sc := *s
	sc.via = via
	s = &sc
	e.enc.nDoH.Add(1)
	id := binary.BigEndian.Uint16(q)
	binary.BigEndian.PutUint16(q, 0) // RFC 8484: ID 0 zwischenspeichern
	resp := e.encAnswer(src, s, q)
	if resp == nil {
		http.Error(w, "keine Antwort", http.StatusBadGateway)
		return
	}
	binary.BigEndian.PutUint16(resp, id)
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=0")
	_, _ = w.Write(resp)
}

// encAnswer: wie normales DNS, abgeschnittene Antworten werden per TCP neu geholt.
func (e *Engine) encAnswer(src netip.Addr, s *srcPolicy, q []byte) []byte {
	resp := e.dns.handleWith(e, src, s, q, false)
	if len(resp) > 3 && resp[2]&0x02 != 0 { // TC
		if r2 := e.dns.handleWith(e, src, s, q, true); r2 != nil {
			return r2
		}
	}
	return resp
}

func (e *Engine) serveDoT(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ta, _ := c.RemoteAddr().(*net.TCPAddr)
		var src netip.Addr
		if ta != nil {
			src, _ = netip.AddrFromSlice(ta.IP)
			src = src.Unmap()
		}
		if !dotLimit.acquire(src) { // zu viele offene Verbindungen – noch vor dem (teuren) TLS-Handshake
			_ = c.Close()
			continue
		}
		go func() {
			defer dotLimit.release(src)
			defer c.Close()
			defer e.guard("DoT")
			tc, ok := c.(*tls.Conn)
			if !ok {
				return
			}
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				return
			}
			token := e.tokenOf(tc.ConnectionState().ServerName)
			via := "dot"
			if token == "" {
				via = "dot-addr"
			}
			s := e.clientFor(token, src)
			if s == nil {
				e.enc.denied.Add(1)
				if src.IsValid() {
					e.noteExt(src, 0, "", true, false, via)
				}
				return
			}
			sc := *s
			sc.via = via
			s = &sc
			for {
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				q, err := readFrame(c)
				if err != nil {
					return
				}
				e.enc.nDoT.Add(1)
				resp := e.encAnswer(src, s, q)
				if resp == nil || writeFrame(c, resp) != nil {
					return
				}
			}
		}()
	}
}

// ---------- Anzeige ----------

// EncDNSStatus: Zustand von DoH/DoT für die Oberfläche.
type EncDNSStatus struct {
	On        bool     `json:"on"`
	Host      string   `json:"host"`
	Cert      CertInfo `json:"cert"`
	HasCert   bool     `json:"has_cert"`
	Issuing   bool     `json:"issuing"`
	Step      string   `json:"step,omitempty"`
	Error     string   `json:"error,omitempty"`
	LastTry   int64    `json:"last_try"`
	TokenSet  bool     `json:"token_set"`
	TokenFile string   `json:"token_file"`
	DoTPort   int      `json:"dot_port"`
	DoH       bool     `json:"doh"` // lauscht
	DoT       bool     `json:"dot"`
	QDoH      int64    `json:"q_doh"`
	QDoT      int64    `json:"q_dot"`
	Denied    int64    `json:"denied"`
}

func (e *Engine) EncDNSState() EncDNSStatus {
	x := &e.enc
	st := EncDNSStatus{On: e.encDNSOn(), Host: e.encDNSHost(), TokenSet: e.cfToken() != "", TokenFile: filepath.Join(e.Cfg.DataDir, "secrets.env"),
		DoTPort: atoi(e.Setting("dns_dot_port"), 853)}
	if e.Cfg.DataDir == "" || strings.Contains(e.Cfg.DataDir, "devdata") {
		st.TokenFile = "/etc/vpn/secrets.env"
	}
	x.mu.Lock()
	st.Cert, st.HasCert, st.Issuing, st.Step, st.Error = x.info, x.cert != nil, x.issuing, x.step, x.lastErr
	if !x.lastTry.IsZero() {
		st.LastTry = x.lastTry.Unix()
	}
	st.DoH, st.DoT = x.doh != nil || (e.Sys.DryRun() && x.cert != nil), x.dot != nil || (e.Sys.DryRun() && x.cert != nil)
	x.mu.Unlock()
	st.QDoH, st.QDoT, st.Denied = x.nDoH.Load(), x.nDoT.Load(), x.denied.Load()
	return st
}
