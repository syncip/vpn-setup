package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

func TestParseDomainList(t *testing.T) {
	in := `! Adblock-Kommentar
# Hosts-Kommentar
[Adblock Plus 2.0]
0.0.0.0 ads.example.com tracker.example.com
127.0.0.1 localhost
:: v6ads.example.net
||doubleclick.net^
||werbung.de^$important
||nur-dritte.de^$third-party
@@||ok.example.com^
example.org##.banner
/regex.*/
*.wild.example
plain.example.net # Kommentar
kein_domainname
`
	block, allow, skipped, err := ParseDomainList(strings.NewReader(in), 100)
	if err != nil {
		t.Fatal(err)
	}
	want := "ads.example.com tracker.example.com v6ads.example.net doubleclick.net werbung.de wild.example plain.example.net"
	if got := strings.Join(block, " "); got != want {
		t.Errorf("Sperren:\n%s\nerwartet\n%s", got, want)
	}
	if strings.Join(allow, " ") != "ok.example.com" {
		t.Errorf("Freigaben: %v", allow)
	}
	if skipped != 4 { // $third-party, ##, Regex, kein_domainname
		t.Errorf("übersprungen: %d", skipped)
	}
	if _, _, _, err := ParseDomainList(strings.NewReader("a.de\nb.de\nc.de\n"), 2); err == nil {
		t.Error("Höchstzahl nicht geprüft")
	}
}

func TestParseDNSRules(t *testing.T) {
	r, err := ParseDNSRules("werbung.de\nblock *.tracker.net\n||ads.com^\nallow ok.werbung.de\n@@frei.de\nnas.home = 192.168.1.10, fd00::10 # NAS\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Block, " ") != "werbung.de tracker.net ads.com" || strings.Join(r.Allow, " ") != "ok.werbung.de frei.de" {
		t.Errorf("%+v", r)
	}
	if a := r.Rewrite["nas.home"]; len(a) != 2 || a[0].String() != "192.168.1.10" {
		t.Errorf("Umschreiben: %v", a)
	}
	for _, bad := range []string{"nas.home = keine-ip", "werbung", "x y.de"} {
		if _, err := ParseDNSRules(bad); err == nil || !strings.Contains(err.Error(), "Zeile 1") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// fakeUpstream: DNS-Server, der auf A-Anfragen 198.51.100.9 (TTL 300) und auf AAAA 2001:db8::9 antwortet.
func fakeUpstream(t *testing.T) (addr string, count *int64) {
	t.Helper()
	up, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	var n int64
	go func() {
		buf := make([]byte, 1500)
		for {
			k, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(&n, 1)
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:k])
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			hd := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 300}
			switch q.Type {
			case dnsmessage.TypeA:
				hd.Type = dnsmessage.TypeA
				_ = b.AResource(hd, dnsmessage.AResource{A: [4]byte{198, 51, 100, 9}})
			case dnsmessage.TypeAAAA:
				hd.Type = dnsmessage.TypeAAAA
				_ = b.AAAAResource(hd, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::9").As16()})
			}
			out, _ := b.Finish()
			_, _ = up.WriteTo(out, from)
		}
	}()
	return up.LocalAddr().String(), &n
}

func dnsQuery(name string, typ dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4711, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	out, _ := b.Finish()
	return out
}

func answers(t *testing.T, resp []byte) (dnsmessage.RCode, []string) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatalf("Antwort nicht lesbar: %v", err)
	}
	_ = p.SkipAllQuestions()
	var out []string
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			r, _ := p.AResource()
			out = append(out, netip.AddrFrom4(r.A).String())
		case dnsmessage.TypeAAAA:
			r, _ := p.AAAAResource()
			out = append(out, netip.AddrFrom16(r.AAAA).String())
		default:
			_ = p.SkipAnswer()
		}
	}
	return h.RCode, out
}

// TestPanelDNS: Profile zuordnen, Sperren/Freigeben/Umschreiben, Zwischenspeicher, Protokoll, Configs.
func TestPanelDNS(t *testing.T) {
	e, dry := newTest(t)
	up, count := fakeUpstream(t)
	oldUp := dnsUpstream
	dnsUpstream = []string{up}
	defer func() { dnsUpstream = oldUp }()

	wg := &store.Server{Name: "wg", Protocol: "wireguard", Enabled: true, Settings: store.M{}, State: store.M{}}
	if err := e.InitServer(wg); err != nil {
		t.Fatal(err)
	}
	if err := e.St.SaveServer(wg); err != nil {
		t.Fatal(err)
	}
	mkUser := func(name string) *store.User {
		u := &store.User{Name: name, Enabled: true, SubToken: proto.RandHex(16)}
		if err := e.St.SaveUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	anna, kid := mkUser("anna"), mkUser("kind")
	mkPeer := func(u *store.User, name string) *store.Peer {
		p := &store.Peer{UserID: u.ID, ServerID: wg.ID, Name: name, Kind: "client", Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(wg, p); err != nil {
			t.Fatal(err)
		}
		if err := e.St.SavePeer(p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	annaPhone, kidTab := mkPeer(anna, "Handy"), mkPeer(kid, "Tablet")

	// Blockliste online (Testserver) + eigene Einträge, Freigabeliste
	body := "0.0.0.0 ads.example.com\n||tracker.example^\n@@||good.ads.example.com^\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	listAllowLocal = true
	defer func() { listAllowLocal = false }()
	bl := saveObj(t, e, &store.Object{Kind: "dnslist", Name: "Werbung", Enabled: true, Data: store.M{"mode": "block", "url": srv.URL, "refresh": 24, "entries": []string{"eigen.example"}}})
	if ch, err := e.FetchDNSList(bl.ID); err != nil || !ch {
		t.Fatalf("Abruf: %v %v", ch, err)
	}
	if st, total := e.DNSListInfo(bl); st.Count != 3 || total != 4 {
		t.Fatalf("Liste: %+v %d", st, total)
	}
	kids := saveObj(t, e, &store.Object{Kind: "dnslist", Name: "Kinder", Enabled: true, Data: store.M{"mode": "block", "entries": []string{"spiele.example"}}})

	// global: Werbung sperren; Kind: Werbung + Kinderliste, NXDOMAIN
	saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "Standard", Enabled: true,
		Data: store.M{"lists": []int64{bl.ID}, "rules": "nas.home = 192.168.1.10\nallow eigen.example", "assign": []string{"global"}, "block_doh": false}})
	saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "Kinder", Enabled: true,
		Data: store.M{"lists": []int64{bl.ID, kids.ID}, "assign": []string{fmt.Sprintf("user:%d", kid.ID)}, "block_doh": true, "nxdomain": true}})

	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	// Firewall: alle Geräte zum Panel-DNS, DoH-Sperre nur fürs Kind
	nft := ""
	for _, s := range dry.Stdin {
		if strings.Contains(s, "table inet vpnpanel {") {
			nft = s
		}
	}
	a4 := func(p *store.Peer) string {
		p2, _ := e.St.Peer(p.ID)
		return proto.Str(p2.Settings, "address4")
	}
	dohSet := nft[strings.Index(nft, "set dohsrc {"):]
	dohSet = dohSet[:strings.Index(dohSet, "}")]
	if !strings.Contains(nft, "ip saddr @dnssrc udp dport 53 redirect to :5399") || !strings.Contains(dohSet, a4(kidTab)) || strings.Contains(dohSet, a4(annaPhone)) {
		t.Errorf("Firewall:\n%s", nft)
	}
	if strings.Contains(nft, "vp_pre") {
		t.Error("Markierungen ohne Ziel-Regeln")
	}

	// Configs nennen den Server als DNS
	env := e.Env()
	snap, _ := e.Snapshot()
	d, _ := proto.Get("wireguard")
	cc, err := d.ClientConfig(env, snap.ByProto["wireguard"][0], snap.Peers[annaPhone.ID])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ccText(cc), "DNS = 10.8.0.1") {
		t.Errorf("Config ohne Panel-DNS:\n%s", ccText(cc))
	}

	// Dienst ohne Netz testen: Quellen direkt setzen
	srcs := e.forwardSources(env, snap, e.routing())
	e.dns.configure(e, srcs, e.routing())
	annaIP, kidIP := netip.MustParseAddr(a4(annaPhone)), netip.MustParseAddr(a4(kidTab))

	code, got := answers(t, e.dns.handle(e, annaIP, dnsQuery("x.ads.example.com.", dnsmessage.TypeA), false))
	if code != dnsmessage.RCodeSuccess || strings.Join(got, " ") != "0.0.0.0" {
		t.Errorf("gesperrt (Anna): %v %v", code, got)
	}
	if _, got = answers(t, e.dns.handle(e, annaIP, dnsQuery("good.ads.example.com.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.9" {
		t.Errorf("Ausnahme aus der Liste: %v", got)
	}
	if _, got = answers(t, e.dns.handle(e, annaIP, dnsQuery("eigen.example.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.9" {
		t.Errorf("Freigabe aus eigener Regel: %v", got)
	}
	if _, got = answers(t, e.dns.handle(e, annaIP, dnsQuery("nas.home.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "192.168.1.10" {
		t.Errorf("eigene Antwort: %v", got)
	}
	if _, got = answers(t, e.dns.handle(e, annaIP, dnsQuery("spiele.example.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.9" {
		t.Errorf("Kinderliste gilt für Anna: %v", got)
	}
	if code, _ = answers(t, e.dns.handle(e, kidIP, dnsQuery("spiele.example.", dnsmessage.TypeA), false)); code != dnsmessage.RCodeNameError {
		t.Errorf("Kind: NXDOMAIN erwartet, %v", code)
	}
	if _, got = answers(t, e.dns.handle(e, kidIP, dnsQuery("nas.home.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.9" {
		t.Errorf("Regel von „Standard“ gilt fürs Kind: %v", got)
	}
	// DoH-Namen: nur fürs Kind gesperrt
	if code, _ = answers(t, e.dns.handle(e, kidIP, dnsQuery("dns.google.", dnsmessage.TypeA), false)); code != dnsmessage.RCodeNameError {
		t.Errorf("DoH fürs Kind: %v", code)
	}
	if code, _ = answers(t, e.dns.handle(e, annaIP, dnsQuery("dns.google.", dnsmessage.TypeA), false)); code != dnsmessage.RCodeSuccess {
		t.Errorf("DoH für Anna: %v", code)
	}

	// Zwischenspeicher: zweite Anfrage geht nicht zum Upstream, TTL zählt herunter
	before := atomic.LoadInt64(count)
	r1 := e.dns.handle(e, annaIP, dnsQuery("example.org.", dnsmessage.TypeAAAA), false)
	r2 := e.dns.handle(e, annaIP, dnsQuery("example.org.", dnsmessage.TypeAAAA), false)
	if atomic.LoadInt64(count)-before != 1 {
		t.Errorf("Zwischenspeicher: %d Anfragen beim Upstream", atomic.LoadInt64(count)-before)
	}
	if _, g1 := answers(t, r1); len(g1) != 1 || r2[0] != r1[0] || r2[1] != r1[1] {
		t.Errorf("Antwort aus dem Speicher: %v", g1)
	}
	m := append([]byte(nil), r1...)
	adjustTTL(m, 100)
	var p dnsmessage.Parser
	_, _ = p.Start(m)
	_ = p.SkipAllQuestions()
	if rh, err := p.AnswerHeader(); err != nil || rh.TTL != 200 {
		t.Errorf("TTL: %+v %v", rh, err)
	}

	// Prüfen-Feld
	if c := e.CheckDNS(kidTab.ID, "www.spiele.example"); c.Action != "blocked" || !strings.Contains(c.Detail, "Kinder") || c.Prof != "Kinder" {
		t.Errorf("Prüfen: %+v", c)
	}
	if c := e.CheckDNS(annaPhone.ID, "nas.home"); c.Action != "rewritten" || !strings.Contains(c.Detail, "192.168.1.10") {
		t.Errorf("Prüfen: %+v", c)
	}

	// Protokoll wird gesammelt geschrieben
	deadline := time.Now().Add(5 * time.Second)
	var log []store.DNSEntry
	for time.Now().Before(deadline) {
		log, _ = e.St.DNSLog(store.DNSLogFilter{Action: "blocked"})
		if len(log) >= 3 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(log) < 3 {
		t.Fatalf("Protokoll: %+v", log)
	}
	found := false
	for _, en := range log {
		if en.Name == "spiele.example" && en.PeerID == kidTab.ID && en.UserID == kid.ID && strings.Contains(en.Detail, "Kinder") {
			found = true
		}
	}
	if !found {
		t.Errorf("Eintrag fehlt: %+v", log)
	}
	st, err := e.St.DNSStats(0, 0)
	if err != nil || st.Total < 10 || st.Blocked < 3 || st.Cached < 1 || len(st.TopBlocked) == 0 || len(st.TopClients) != 2 {
		t.Errorf("Auswertung: %+v %v", st, err)
	}
	if rows, _ := e.St.DNSLog(store.DNSLogFilter{Query: "ads.example", PeerID: annaPhone.ID}); len(rows) != 2 {
		t.Errorf("Suche: %+v", rows)
	}
	if info := e.DNSInfo(); info.Devices != 2 || info.Blocked < 3 {
		t.Errorf("Stand: %+v", info)
	}

	// Panel-DNS aus → Config nennt wieder einen öffentlichen DNS-Server
	_ = e.St.SetSetting("dns_enabled", "0")
	cc, _ = d.ClientConfig(e.Env(), snap.ByProto["wireguard"][0], snap.Peers[annaPhone.ID])
	if !strings.Contains(ccText(cc), "DNS = 1.1.1.1") {
		t.Errorf("ohne Panel-DNS:\n%s", ccText(cc))
	}
}

func ccText(cc *proto.ClientConfig) string {
	if cc == nil || len(cc.Files) == 0 {
		return ""
	}
	return cc.Files[0].Content
}
