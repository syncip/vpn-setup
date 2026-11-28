package engine

// DoH/DoT: Zertifikat per Let's Encrypt (DNS-01 über Cloudflare) und Cloudflare-Token.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/dns/dnsmessage"
)

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

// ---------- Cloudflare-Token über die Oberfläche ----------

var cfTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{20,200}$`)

// SetCFToken schreibt das Token in <data>/secrets.env (Rechte 600) – nie in die Datenbank.
// Leer = Zeile entfernen. Andere Zeilen der Datei bleiben unverändert.
func (e *Engine) SetCFToken(tok string) error {
	tok = strings.TrimSpace(tok)
	if tok != "" && !cfTokenRe.MatchString(tok) {
		return errors.New("das sieht nicht wie ein Cloudflare-API-Token aus (nur Buchstaben, Ziffern, - und _)")
	}
	return e.setSecret("CF_API_TOKEN", tok, "Cloudflare-API-Token (Recht „Zone → DNS → Bearbeiten“) für das Let's-Encrypt-Zertifikat von DoH/DoT")
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
