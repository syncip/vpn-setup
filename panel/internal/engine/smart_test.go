package engine

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// TestParseSNI: Servername aus einem echten ClientHello.
func TestParseSNI(t *testing.T) {
	for _, name := range []string{"www.netflix.com", "a.b.example.org"} {
		c1, c2 := net.Pipe()
		go func() {
			cl := tls.Client(c1, &tls.Config{ServerName: name, InsecureSkipVerify: true})
			_ = cl.Handshake()
		}()
		hello, sni, err := readClientHello(bufio.NewReader(c2))
		c2.Close()
		c1.Close()
		if err != nil || sni != name || len(hello) < 100 {
			t.Errorf("%s: sni=%q len=%d err=%v", name, sni, len(hello), err)
		}
	}
	if _, _, err := readClientHello(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n"))); err == nil {
		t.Error("HTTP als TLS erkannt")
	}
}

// TestSmartDNS: SmartDNS im Profil – VPN-Geräte bekommen eine Ziel-Regel, Geräte ohne VPN die
// Adresse des Servers (und nginx leitet die Namen an den Proxy); DoH/DoT per Kennung.
func TestSmartDNS(t *testing.T) {
	e, _ := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"
	up, _ := fakeUpstream(t)
	oldUp := dnsUpstream
	dnsUpstream = []string{up}
	defer func() { dnsUpstream = oldUp }()
	_ = e.St.SetSetting("dns_enabled", "1")
	_ = e.St.SetSetting("server_host", "198.51.100.77")

	s := &store.Server{Name: "wg", Protocol: "wireguard", Enabled: true, Settings: store.M{}, State: store.M{}}
	if err := e.InitServer(s); err != nil {
		t.Fatal(err)
	}
	if err := e.St.SaveServer(s); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Name: "anna", Enabled: true, SubToken: proto.RandHex(16)}
	if err := e.St.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	p := &store.Peer{UserID: u.ID, ServerID: s.ID, Name: "Handy", Kind: "client", Enabled: true, Settings: store.M{}}
	if err := e.InitPeer(s, p); err != nil {
		t.Fatal(err)
	}
	if err := e.St.SavePeer(p); err != nil {
		t.Fatal(err)
	}
	conf := "[Interface]\nPrivateKey = " + testKey('a') + "\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = " + testKey('b') +
		"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	ex := saveObj(t, e, &store.Object{Kind: "exit", Name: "A", Enabled: true, Data: store.M{"type": "wireguard", "slot": 1}, Secrets: store.M{"config": conf}})
	us := saveObj(t, e, &store.Object{Kind: "group", Name: "USA", Enabled: true, Data: store.M{"slot": 2, "exits": []int64{ex.ID}, "on_fail": "block"}})
	prof := saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "Standard", Enabled: true, Data: store.M{"assign": []string{"global"},
		"smart": []any{map[string]any{"group": us.ID, "domains": []string{"netflix.com", "NFLXVIDEO.net", "kaputt..x"}}}}})
	tv := saveObj(t, e, &store.Object{Kind: "dnsclient", Name: "TV", Enabled: true, Data: store.M{"addrs": []string{"203.0.113.50"}, "profile": float64(0), "learn": true},
		Secrets: store.M{"token": "abc123token"}})
	_ = tv

	if got := DNSProfileFrom(prof).Smart; len(got) != 1 || strings.Join(got[0].Domains, ",") != "netflix.com,nflxvideo.net" {
		t.Fatalf("ParseSmart: %+v", got)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	// VPN-Gerät: Ziel-Regel aus dem Profil
	pol := e.routing().Policies[p.ID]
	if pol == nil || len(pol.Rules) != 1 || pol.Rules[0].ID != SmartRuleID(prof.ID, 0) || pol.Rules[0].Group != us.ID ||
		strings.Join(pol.Rules[0].Domains, ",") != "netflix.com,nflxvideo.net" {
		t.Fatalf("Ziel-Regel: %+v", pol)
	}

	// Gerät ohne VPN: aus, solange „DNS von außen“ aus ist
	tvIP := netip.MustParseAddr("203.0.113.50")
	if r := e.dns.handle(e, tvIP, dnsQuery("www.netflix.com.", dnsmessage.TypeA), false); r != nil {
		t.Error("Antwort ohne DNS von außen")
	}
	_ = e.St.SetSetting("dns_public", "1")
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, got := answers(t, e.dns.handle(e, tvIP, dnsQuery("www.netflix.com.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.77" {
		t.Errorf("SmartDNS A: %v", got)
	}
	if code, got := answers(t, e.dns.handle(e, tvIP, dnsQuery("netflix.com.", dnsmessage.TypeAAAA), false)); code != dnsmessage.RCodeSuccess || len(got) != 0 {
		t.Errorf("SmartDNS AAAA: %v %v", code, got)
	}
	if _, got := answers(t, e.dns.handle(e, tvIP, dnsQuery("example.org.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.9" {
		t.Errorf("normale Domain: %v", got)
	}
	// nginx: Namen samt Unterdomains an den Proxy
	ng, _ := e.Sys.ReadFile(nginxStream)
	if !strings.Contains(string(ng), "hostnames;") || !strings.Contains(string(ng), ".netflix.com "+smartAddr+";") {
		t.Errorf("nginx:\n%s", ng)
	}

	// DoH per Kennung, auch von einer fremden Adresse (Handy im Mobilfunk) – mit „Adresse merken“
	_ = e.St.SetSetting("dns_tls", "1")
	_ = e.St.SetSetting("dns_tls_host", "dns.example.org")
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	ng, _ = e.Sys.ReadFile(nginxStream)
	if !strings.Contains(string(ng), ".dns.example.org "+dohAddr+";") {
		t.Errorf("nginx DoH:\n%s", ng)
	}
	if e.tokenOf("abc123token.dns.example.org") != "abc123token" || e.tokenOf("x.y.dns.example.org") != "" || e.tokenOf("dns.example.org") != "" {
		t.Error("tokenOf")
	}
	q := dnsQuery("www.netflix.com.", dnsmessage.TypeA)
	req := httptest.NewRequest("GET", "https://dns.example.org/dns-query/abc123token?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
	req.RemoteAddr = "198.18.7.7:5555"
	rec := httptest.NewRecorder()
	e.serveDoH(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("DoH: %d %s", rec.Code, rec.Body.String())
	}
	if _, got := answers(t, rec.Body.Bytes()); strings.Join(got, " ") != "198.51.100.77" {
		t.Errorf("DoH SmartDNS: %v", got)
	}
	// gemerkte Adresse darf jetzt normales DNS
	if _, got := answers(t, e.dns.handle(e, netip.MustParseAddr("198.18.7.7"), dnsQuery("example.org.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.9" {
		t.Errorf("gemerkte Adresse: %v", got)
	}
	// falsche Kennung
	req = httptest.NewRequest("GET", "https://falsch.dns.example.org/dns-query?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
	req.RemoteAddr = "198.18.8.8:5555"
	rec = httptest.NewRecorder()
	e.serveDoH(rec, req)
	if rec.Code != 403 {
		t.Errorf("falsche Kennung: %d", rec.Code)
	}
	if st := e.EncDNSState(); !st.HasCert || !st.Cert.SelfSigned || !certCovers(st.Cert, "dns.example.org") {
		t.Errorf("Testzertifikat: %+v", st)
	}

	// Details je Absender: Weg (DoH mit Kennung, Port 53), Namen, nicht freigegebene Absender
	d := e.ExtSeenOf("198.18.7.7")
	if d == nil || d.Via["doh"] != 1 || d.Via["dns"] != 1 || d.ClientName != "TV" || len(d.Domains) != 2 {
		t.Fatalf("Details DoH-Gerät: %+v", d)
	}
	if bad := e.ExtSeenOf("198.18.8.8"); bad == nil || bad.Client != 0 || bad.Refused != 1 || bad.Via["doh"] != 1 ||
		len(bad.Domains) != 1 || bad.Domains[0].Name != "www.netflix.com" {
		t.Errorf("abgewiesene Kennung: %+v", bad)
	}
	for i := 0; i < seenMaxDomainsDenied+10; i++ {
		e.dns.handle(e, netip.MustParseAddr("198.18.9.9"), dnsQuery(fmt.Sprintf("n%d.example.", i), dnsmessage.TypeA), false)
	}
	if sc := e.ExtSeenOf("198.18.9.9"); sc == nil || len(sc.Domains) != seenMaxDomainsDenied || sc.More != 10 || sc.Via["dns"] != seenMaxDomainsDenied+10 {
		t.Errorf("Grenze für Scanner: %d Namen, %d weitere", len(sc.Domains), sc.More)
	}
	if rows := e.DNSExternal().Seen; len(rows) == 0 || rows[0].Domains != nil {
		t.Error("Liste ohne Namen erwartet")
	}
}
