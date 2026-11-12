package engine

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/dns/dnsmessage"
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
func (e *Engine) cfToken() string {
	if b, err := os.ReadFile(filepath.Join(e.Cfg.DataDir, "secrets.env")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "export "))
			if v, ok := strings.CutPrefix(l, "CF_API_TOKEN="); ok {
				return strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	return os.Getenv("CF_API_TOKEN")
}

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

// ---------- Zertifikat (Let's Encrypt, DNS-Prüfung über Cloudflare) ----------

// RenewEncCert prüft täglich, ob das Zertifikat bald abläuft (30 Tage vorher erneuern).
func (e *Engine) RenewEncCert(force bool) error {
	if !e.encDNSOn() {
		return errors.New("DoH/DoT ist ausgeschaltet oder ohne Namen")
	}
	host := e.encDNSHost()
	x := &e.enc
	x.mu.Lock()
	if x.issuing {
		x.mu.Unlock()
		return errors.New("Zertifikat wird gerade geholt")
	}
	due := x.cert == nil || x.info.SelfSigned || !certCovers(x.info, host) || time.Until(time.Unix(x.info.NotAfter, 0)) < 30*24*time.Hour
	if !force && (!due || time.Since(x.lastTry) < 6*time.Hour) {
		x.mu.Unlock()
		return nil
	}
	if e.Sys.DryRun() {
		x.lastErr = "Testmodus: kein echtes Zertifikat (selbstsigniert)"
		x.lastTry = time.Now()
		x.mu.Unlock()
		return errors.New(x.lastErr)
	}
	x.issuing = true
	x.mu.Unlock()
	go e.issueCert(host)
	return nil
}

func (e *Engine) issueCert(host string) {
	x := &e.enc
	err := e.obtainCert(host)
	x.mu.Lock()
	x.issuing, x.lastTry, x.step = false, time.Now(), ""
	if err != nil {
		x.lastErr = err.Error()
	} else {
		x.lastErr = ""
		x.loadLocked(e, host)
	}
	x.mu.Unlock()
	if err != nil {
		e.Log("error", "Zertifikat für "+host+": "+err.Error())
		return
	}
	e.Log("info", "Zertifikat für "+host+" und *."+host+" von Let's Encrypt geholt")
	e.RequestApply()
}

func (x *encDNS) setStep(s string) {
	x.mu.Lock()
	x.step = s
	x.mu.Unlock()
}

func (e *Engine) obtainCert(host string) error {
	x := &e.enc
	token := e.cfToken()
	if token == "" {
		return fmt.Errorf("Cloudflare-API-Token fehlt: in %s die Zeile CF_API_TOKEN=… eintragen", filepath.Join(e.Cfg.DataDir, "secrets.env"))
	}
	if err := os.MkdirAll(e.tlsDir(), 0o700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cf := &cfAPI{token: token}
	x.setStep("Cloudflare-Zone suchen")
	zone, err := cf.zoneFor(ctx, host)
	if err != nil {
		return err
	}
	// DNS-Einträge für den Namen und alle Kennungen (*.name) anlegen, falls sie fehlen (ohne Cloudflare-Proxy)
	x.setStep("DNS-Einträge prüfen")
	v4, v6 := e.PublicAddrs()
	for _, n := range []string{host, "*." + host} {
		if v4.IsValid() {
			if err := cf.ensureRecord(ctx, zone, "A", n, v4.String()); err != nil {
				return err
			}
		}
		if v6.IsValid() {
			if err := cf.ensureRecord(ctx, zone, "AAAA", n, v6.String()); err != nil {
				return err
			}
		}
	}

	x.setStep("Let's-Encrypt-Konto")
	akey, err := loadOrCreateKey(filepath.Join(e.tlsDir(), "account.key"))
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: akey, DirectoryURL: acme.LetsEncryptURL, UserAgent: "vpnpanel"}
	acct := &acme.Account{}
	if mail := strings.TrimSpace(e.Setting("dns_acme_email")); mail != "" {
		acct.Contact = []string{"mailto:" + mail}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("Let's-Encrypt-Konto: %w", err)
	}
	x.setStep("Auftrag anlegen")
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(host, "*."+host))
	if err != nil {
		return fmt.Errorf("Auftrag: %w", err)
	}
	type pending struct {
		zURL string
		chal *acme.Challenge
	}
	var todo []pending
	var recs []string
	defer func() {
		cctx, c2 := context.WithTimeout(context.Background(), 30*time.Second)
		defer c2()
		for _, id := range recs {
			_ = cf.deleteRecord(cctx, zone, id)
		}
	}()
	var values []string
	for _, zu := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, zu)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				ch = c
			}
		}
		if ch == nil {
			return errors.New("Let's Encrypt bietet keine DNS-Prüfung an")
		}
		val, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return err
		}
		x.setStep("Prüfeintrag bei Cloudflare anlegen")
		id, err := cf.createRecord(ctx, zone, "TXT", "_acme-challenge."+z.Identifier.Value, val)
		if err != nil {
			return err
		}
		recs = append(recs, id)
		values = append(values, val)
		todo = append(todo, pending{zu, ch})
	}
	if len(todo) > 0 {
		x.setStep("warten, bis der Prüfeintrag sichtbar ist")
		if err := waitTXT(ctx, "_acme-challenge."+host, values); err != nil {
			return err
		}
		time.Sleep(10 * time.Second)
	}
	for _, p := range todo {
		x.setStep("Let's Encrypt prüft")
		if _, err := cl.Accept(ctx, p.chal); err != nil {
			return fmt.Errorf("Prüfung: %w", err)
		}
		if _, err := cl.WaitAuthorization(ctx, p.zURL); err != nil {
			return fmt.Errorf("Prüfung fehlgeschlagen: %w", err)
		}
	}
	x.setStep("Zertifikat ausstellen")
	ckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}, DNSNames: []string{host, "*." + host}}, ckey)
	if err != nil {
		return err
	}
	order, err = cl.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("Auftrag: %w", err)
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("Ausstellen: %w", err)
	}
	var certPEM bytes.Buffer
	for _, d := range ders {
		_ = pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	kb, err := x509.MarshalECPrivateKey(ckey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(filepath.Join(e.tlsDir(), "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.tlsDir(), "cert.pem"), certPEM.Bytes(), 0o600)
}

func loadOrCreateKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			return x509.ParseECPrivateKey(blk.Bytes)
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600)
}

// waitTXT wartet, bis öffentliche Resolver alle Werte sehen (höchstens 3 Minuten).
func waitTXT(ctx context.Context, name string, want []string) error {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		ok := true
		for _, srv := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
			got := lookupTXT(srv, name)
			for _, w := range want {
				found := false
				for _, g := range got {
					found = found || g == w
				}
				ok = ok && found
			}
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("der Prüfeintrag ist nach 3 Minuten noch nicht sichtbar")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func lookupTXT(srv, name string) []string {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		return nil
	}
	resp := exchangeOne(q, srv, 0, true, 4*time.Second)
	if resp == nil {
		return nil
	}
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil
	}
	_ = p.SkipAllQuestions()
	var out []string
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type != dnsmessage.TypeTXT {
			_ = p.SkipAnswer()
			continue
		}
		r, err := p.TXTResource()
		if err != nil {
			break
		}
		out = append(out, strings.Join(r.TXT, ""))
	}
	return out
}

// ---------- Cloudflare-API ----------

type cfAPI struct{ token string }

type cfResp struct {
	Success bool                       `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage            `json:"result"`
}

func (c *cfAPI) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare: %w", err)
	}
	defer res.Body.Close()
	var r cfResp
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("Cloudflare: HTTP %d", res.StatusCode)
	}
	if !r.Success {
		msg := fmt.Sprintf("HTTP %d", res.StatusCode)
		if len(r.Errors) > 0 {
			msg = r.Errors[0].Message
		}
		if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized {
			msg += " – Token braucht das Recht „Zone → DNS → Bearbeiten“"
		}
		return fmt.Errorf("Cloudflare: %s", msg)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (c *cfAPI) zoneFor(ctx context.Context, host string) (string, error) {
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var zones []struct {
			ID string `json:"id"`
		}
		if err := c.call(ctx, "GET", "/zones?name="+name, nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("keine Cloudflare-Zone für %s gefunden (Token für die richtige Zone?)", host)
}

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
}

func (c *cfAPI) createRecord(ctx context.Context, zone, typ, name, content string) (string, error) {
	var r cfRecord
	err := c.call(ctx, "POST", "/zones/"+zone+"/dns_records", cfRecord{Type: typ, Name: name, Content: content, TTL: 60}, &r)
	return r.ID, err
}

func (c *cfAPI) deleteRecord(ctx context.Context, zone, id string) error {
	return c.call(ctx, "DELETE", "/zones/"+zone+"/dns_records/"+id, nil, nil)
}

// ensureRecord legt einen A-/AAAA-Eintrag ohne Proxy an, wenn es für den Namen noch keinen gibt.
// Vorhandene Einträge bleiben unangetastet.
func (c *cfAPI) ensureRecord(ctx context.Context, zone, typ, name, content string) error {
	var have []cfRecord
	if err := c.call(ctx, "GET", "/zones/"+zone+"/dns_records?type="+typ+"&name="+name, nil, &have); err != nil {
		return err
	}
	if len(have) > 0 {
		for _, h := range have {
			if h.Proxied != nil && *h.Proxied {
				return fmt.Errorf("%s ist bei Cloudflare „proxied“ (orange Wolke) – für DoT muss es „Nur DNS“ sein", name)
			}
		}
		return nil
	}
	off := false
	return c.call(ctx, "POST", "/zones/"+zone+"/dns_records", cfRecord{Type: typ, Name: name, Content: content, TTL: 300, Proxied: &off}, nil)
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

// ---------- Cloudflare-Token über die Oberfläche ----------

var cfTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{20,200}$`)

// SetCFToken schreibt das Token in <data>/secrets.env (Rechte 600) – nie in die Datenbank.
// Leer = Zeile entfernen. Andere Zeilen der Datei bleiben unverändert.
func (e *Engine) SetCFToken(tok string) error {
	tok = strings.TrimSpace(tok)
	if tok != "" && !cfTokenRe.MatchString(tok) {
		return errors.New("das sieht nicht wie ein Cloudflare-API-Token aus (nur Buchstaben, Ziffern, - und _)")
	}
	path := filepath.Join(e.Cfg.DataDir, "secrets.env")
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var lines []string
	done := false
	for _, l := range strings.Split(strings.TrimRight(string(old), "\n"), "\n") {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "export "))
		if strings.HasPrefix(t, "CF_API_TOKEN=") {
			if tok != "" && !done {
				lines = append(lines, "CF_API_TOKEN="+tok)
				done = true
			}
			continue
		}
		if l != "" || len(lines) > 0 {
			lines = append(lines, l)
		}
	}
	if tok != "" && !done {
		if len(lines) == 0 {
			lines = append(lines, "# Cloudflare-API-Token (Recht „Zone → DNS → Bearbeiten“) für das Let's-Encrypt-Zertifikat von DoH/DoT")
		}
		lines = append(lines, "CF_API_TOKEN="+tok)
	}
	if err := os.MkdirAll(e.Cfg.DataDir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, path)
}

// CFTokenCheck: Ergebnis der Prüfung bei Cloudflare.
type CFTokenCheck struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// VerifyCFToken fragt Cloudflare, ob das Token gültig ist und die Zone des DNS-Namens bearbeiten darf.
func (e *Engine) VerifyCFToken() CFTokenCheck {
	tok := e.cfToken()
	if tok == "" {
		return CFTokenCheck{Message: "Kein Token hinterlegt"}
	}
	if e.Sys.DryRun() {
		return CFTokenCheck{OK: true, Message: "Testmodus: Token gespeichert, Cloudflare wird nicht gefragt"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cf := &cfAPI{token: tok}
	var v struct {
		Status    string `json:"status"`
		ExpiresOn string `json:"expires_on"`
	}
	if err := cf.call(ctx, "GET", "/user/tokens/verify", nil, &v); err != nil {
		return CFTokenCheck{Message: err.Error()}
	}
	if v.Status != "active" {
		return CFTokenCheck{Message: "Token ist nicht aktiv (" + v.Status + ")"}
	}
	msg := "Token gültig"
	if v.ExpiresOn != "" {
		msg += ", läuft ab am " + strings.SplitN(v.ExpiresOn, "T", 2)[0]
	}
	host := e.encDNSHost()
	if host == "" {
		return CFTokenCheck{OK: true, Message: msg + " – Zone wird geprüft, sobald ein DNS-Name eingetragen ist"}
	}
	zone, err := cf.zoneFor(ctx, host)
	if err != nil {
		return CFTokenCheck{Message: msg + ", aber: " + err.Error()}
	}
	var recs []cfRecord
	if err := cf.call(ctx, "GET", "/zones/"+zone+"/dns_records?per_page=1", nil, &recs); err != nil {
		return CFTokenCheck{Message: msg + ", aber DNS-Einträge lesen geht nicht: " + err.Error()}
	}
	return CFTokenCheck{OK: true, Message: msg + " und hat Zugriff auf die Zone von " + host}
}
