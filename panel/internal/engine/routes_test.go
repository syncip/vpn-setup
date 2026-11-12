package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/hysteria2"
	_ "vpnpanel/internal/proto/openvpn"
	_ "vpnpanel/internal/proto/proxy"
	_ "vpnpanel/internal/proto/vless"
	"vpnpanel/internal/store"
)

func saveObj(t *testing.T, e *Engine, o *store.Object) *store.Object {
	t.Helper()
	if o.Data == nil {
		o.Data = store.M{}
	}
	if o.Secrets == nil {
		o.Secrets = store.M{}
	}
	if err := e.St.SaveObject(o); err != nil {
		t.Fatal(err)
	}
	o, err := e.St.Object(o.Kind, o.ID) // wie aus der Datenbank gelesen (Listen als []any)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// TestRoutes: Rangfolge der Regeln und was daraus für Firewall, Xray und Hysteria2 entsteht.
func TestRoutes(t *testing.T) {
	e, dry := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"
	mkSrv := func(name, protocol string) *store.Server {
		s := &store.Server{Name: name, Protocol: protocol, Enabled: true, Settings: store.M{}, State: store.M{}}
		if err := e.InitServer(s); err != nil {
			t.Fatal(err)
		}
		if err := e.St.SaveServer(s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	wg, vl, hy := mkSrv("wg", "wireguard"), mkSrv("vl", "vless"), mkSrv("hy", "hysteria2")
	mkUser := func(name string) *store.User {
		u := &store.User{Name: name, Enabled: true, SubToken: proto.RandHex(16)}
		if err := e.St.SaveUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	anna, ben := mkUser("anna"), mkUser("ben")
	mkPeer := func(u *store.User, s *store.Server, name string) *store.Peer {
		d, _ := proto.Get(s.Protocol)
		p := &store.Peer{UserID: u.ID, ServerID: s.ID, Name: name, Kind: d.Info().Kinds[0].ID, Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(s, p); err != nil {
			t.Fatal(err)
		}
		if err := e.St.SavePeer(p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	annaPhone, annaTV, benPhone := mkPeer(anna, wg, "Handy"), mkPeer(anna, wg, "TV"), mkPeer(ben, wg, "Handy")
	annaVL, benVL := mkPeer(anna, vl, "vl"), mkPeer(ben, vl, "vl")
	mkPeer(ben, hy, "hy")

	conf := "[Interface]\nPrivateKey = " + testKey('a') + "\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = " + testKey('b') +
		"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	ex := saveObj(t, e, &store.Object{Kind: "exit", Name: "A", Enabled: true, Data: store.M{"type": "wireguard", "slot": 1}, Secrets: store.M{"config": conf}})
	us := saveObj(t, e, &store.Object{Kind: "group", Name: "US", Enabled: true, Data: store.M{"slot": 2, "exits": []int64{ex.ID}, "on_fail": "block"}})
	nl := saveObj(t, e, &store.Object{Kind: "group", Name: "NL", Enabled: true, Data: store.M{"slot": 3, "exits": []int64{ex.ID}, "on_fail": "block"}})
	off := saveObj(t, e, &store.Object{Kind: "group", Name: "aus", Enabled: false, Data: store.M{"slot": 4, "exits": []int64{ex.ID}}})
	tl := saveObj(t, e, &store.Object{Kind: "iplist", Name: "Dienst", Enabled: true, Data: store.M{"mode": "targets", "entries": []string{"198.18.5.0/24"}}})

	route := func(scope string, id int64, group int64, data store.M) *store.Object {
		d := store.M{"scope": scope, "scope_id": id, "group": group, "match": "all"}
		for k, v := range data {
			d[k] = v
		}
		return saveObj(t, e, &store.Object{Kind: "route", Enabled: true, Data: d})
	}
	// global: Netflix über US; Anna: alles über NL; Annas TV: eine Bank direkt, eine Liste über US
	rGlobal := route("global", 0, us.ID, store.M{"match": "targets", "domains": []string{"netflix.com"}, "nets": []string{"203.0.113.0/24"}})
	rAnna := route("user", anna.ID, nl.ID, nil)
	rTVBank := route("peer", annaTV.ID, 0, store.M{"match": "targets", "domains": []string{"bank.example"}})
	rTVList := route("peer", annaTV.ID, us.ID, store.M{"match": "targets", "lists": []int64{tl.ID}})
	rOff := route("global", 0, off.ID, nil)
	rGone := route("user", 9999, us.ID, nil)

	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	rt := e.routing()
	ruleIDs := func(p *proto.Policy) string {
		if p == nil {
			return "-"
		}
		var s []string
		for _, r := range p.Rules {
			s = append(s, id64(r.ID))
		}
		return strings.Join(s, ",")
	}
	// Gerät vor Nutzer vor global; nach „alles“ ist Schluss
	if got, want := ruleIDs(rt.Policies[annaTV.ID]), id64(rTVBank.ID)+","+id64(rTVList.ID)+","+id64(rAnna.ID); got != want {
		t.Errorf("Annas TV: %s, erwartet %s", got, want)
	}
	if got := ruleIDs(rt.Policies[annaPhone.ID]); got != id64(rAnna.ID) {
		t.Errorf("Annas Handy: %s", got)
	}
	if got := ruleIDs(rt.Policies[benPhone.ID]); got != id64(rGlobal.ID) {
		t.Errorf("Bens Handy: %s", got)
	}
	if rt.Policies[annaPhone.ID] != rt.Policies[annaVL.ID] {
		t.Error("gleiche Regelfolge sollte dieselbe Policy sein")
	}
	if !strings.Contains(rt.Skipped[rOff.ID], "deaktiviert") {
		t.Errorf("Regel mit deaktivierter Gruppe: %q", rt.Skipped[rOff.ID])
	}
	if _, err := e.St.Object("route", rGone.ID); err == nil {
		t.Error("Regel für gelöschten Nutzer nicht entfernt")
	}

	// Firewall
	nft := ""
	for _, s := range dry.Stdin {
		if strings.Contains(s, "table inet vpnpanel {") {
			nft = s
		}
	}
	a4 := func(p *store.Peer) string { return proto.Str(p.Settings, "address4") }
	tvPol, annaPol, benPol := rt.Policies[annaTV.ID].Key, rt.Policies[annaPhone.ID].Key, rt.Policies[benPhone.ID].Key
	for _, want := range []string{
		"type filter hook prerouting priority mangle; policy accept;", "ip daddr @private4 return", "ip saddr vmap @src4",
		a4(annaTV) + "/32 : jump pol_" + tvPol, a4(annaPhone) + "/32 : jump pol_" + annaPol, a4(benPhone) + "/32 : jump pol_" + benPol,
		// TV: Bank direkt (return), Liste über US (Markierung 0x02000000), Rest über NL
		"chain pol_" + tvPol + " {\n\t\tip daddr @d" + id64(rTVBank.ID) + " return\n\t\tip daddr @l" + id64(tl.ID) + "_4 meta mark set 0x02000000 return\n\t\tmeta mark set 0x03000000 return\n\t}",
		"chain pol_" + benPol + " {\n\t\tip daddr { 203.0.113.0/24 } meta mark set 0x02000000 return\n\t\tip daddr @d" + id64(rGlobal.ID) + " meta mark set 0x02000000 return\n\t}",
		"set l" + id64(tl.ID) + "_4 {", "elements = { 198.18.5.0/24 }",
		"set d" + id64(rGlobal.ID) + " {", "flags timeout",
		// DNS-Umleitung zum Panel-DNS für alle Geräte; verschlüsseltes DNS nur bei Domain-Regeln gesperrt
		"ip saddr @dnssrc udp dport 53 redirect to :5399", "ip saddr @dohsrc tcp dport 853 reject with tcp reset",
		// auch DNS über IPv6 wird umgeleitet (Geräte mit IPv6-DNS-Server)
		"set dnssrc6 {", "ip6 saddr @dnssrc6 udp dport 53 redirect to :5399", "ip6 saddr @dohsrc6 tcp dport 853 reject with tcp reset",
		"ip6 saddr @all6 ip6 daddr != fc00::/7 reject with icmpv6 admin-prohibited",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("Firewall ohne:\n%s", want)
		}
	}
	if t.Failed() {
		t.Logf("nft:\n%s", nft)
	}
	setOf := func(name string) string {
		x := nft[strings.Index(nft, "set "+name+" {"):]
		return x[:strings.Index(x, "}")]
	}
	if d := setOf("dnssrc"); !strings.Contains(d, a4(annaTV)) || !strings.Contains(d, a4(benPhone)) || !strings.Contains(d, a4(annaPhone)) {
		t.Errorf("Panel-DNS nicht für alle Geräte: %s", d)
	}
	if d := setOf("dohsrc"); !strings.Contains(d, a4(annaTV)) || !strings.Contains(d, a4(benPhone)) || strings.Contains(d, a4(annaPhone)) {
		t.Errorf("DoH-Sperre für die falschen Geräte: %s", d)
	}
	fw := strings.Join(dry.Stdin, "\n")
	if !strings.Contains(fw, "-A VPNWG-FWD -i wg0 -o ex+ -s "+a4(benPhone)+"/32 -j ACCEPT") {
		t.Error("Weiterleitung zu Ausgängen nicht erlaubt")
	}
	if log := strings.Join(dry.Log(), "\n"); !strings.Contains(log, "ip -4 rule add priority 6201 oif ex"+id64(ex.ID)+" lookup 2001") {
		t.Error("Regel für gebundene Sockets (Hysteria2) fehlt")
	}

	// Xray: Anna alles über NL (IPv6 gesperrt), Ben Netflix über US
	xr, _ := dry.ReadFile("/usr/local/etc/xray/config.json")
	for _, want := range []string{`"tag": "g` + id64(nl.ID) + `"`, `"mark": 50331648`, `"domainStrategy": "UseIPv4"`, `"domain:netflix.com"`,
		`"203.0.113.0/24"`, `"::/0"`, `"domainStrategy": "IPOnDemand"`, `"p` + id64(annaVL.ID) + `"`, `"p` + id64(benVL.ID) + `"`} {
		if !strings.Contains(string(xr), want) {
			t.Errorf("Xray ohne %s", want)
		}
	}
	// Hysteria2: nur globale/Server-Regeln; Gruppe hat noch keinen aktiven Ausgang gemeldet → an ex gebunden oder gesperrt
	hc, _ := os.ReadFile(filepath.Join(dry.Root, "etc/hysteria", "hy"+id64(hy.ID)+".yaml"))
	for _, want := range []string{`(suffix:netflix.com)`, `(203.0.113.0/24)`, `"direct(all)"`} {
		if !strings.Contains(string(hc), want) {
			t.Errorf("Hysteria2 ohne %s:\n%s", want, hc)
		}
	}
	if !strings.Contains(string(hc), `"bindDevice": "ex`+id64(ex.ID)+`"`) && !strings.Contains(string(hc), `"reject(suffix:netflix.com)"`) {
		t.Errorf("Hysteria2: weder gebunden noch gesperrt:\n%s", hc)
	}

	// Regeln weg → Tabelle weg
	objs, _ := e.St.Objects("route")
	for _, o := range objs {
		_ = e.St.DeleteObject("route", o.ID)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	// Panel-DNS bleibt (Umleitung), Markierungen und DoH-Sperre sind weg
	last := ""
	for _, s := range dry.Stdin {
		if strings.Contains(s, "table inet vpnpanel {") {
			last = s
		}
	}
	if !strings.Contains(last, "set dnssrc {") || strings.Contains(last, "vp_pre") || strings.Contains(last, "dohsrc") {
		t.Errorf("ohne Regeln:\n%s", last)
	}
	_ = e.St.SetSetting("dns_enabled", "0")
	n := len(dry.Log())
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(dry.Log()[n:], "\n"), "nft delete table inet vpnpanel") {
		t.Error("Tabelle nicht abgebaut")
	}
	if xr, _ := dry.ReadFile("/usr/local/etc/xray/config.json"); strings.Contains(string(xr), "netflix") {
		t.Error("Xray-Regeln nicht entfernt")
	}
}

func TestParseRouteDomains(t *testing.T) {
	got, err := ParseRouteDomains("Netflix.com, *.nflxvideo.net\nhttps://www.Example.org/pfad?x=1 # Kommentar\n.bbc.co.uk")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "bbc.co.uk netflix.com nflxvideo.net www.example.org" {
		t.Fatalf("%v", got)
	}
	for _, bad := range []string{"localhost", "a b", "exa$mple.com", "-x.com", "1.2.3.4/24"} {
		if _, err := ParseRouteDomains(bad); err == nil && bad != "a b" {
			t.Errorf("%q: Fehler erwartet", bad)
		}
	}
	if !proto.DomainMatch([]string{"netflix.com"}, "www.netflix.com") || proto.DomainMatch([]string{"netflix.com"}, "notnetflix.com") {
		t.Error("Unterdomain-Vergleich falsch")
	}
	if _, err := ParseRouteNets("10.0.0.0/8\n2001:db8::/32"); err == nil {
		t.Error("IPv6-Netz in Regel angenommen")
	}
}

func TestOnlineList(t *testing.T) {
	e, _ := newTest(t)
	body := "# Kommentar\n203.0.113.0/24 ; böse\n198.51.100.7\nkein-eintrag\n0.0.0.0\n2001:db8::/32\n203.0.113.0/24\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	o := saveObj(t, e, &store.Object{Kind: "iplist", Name: "online", Enabled: true,
		Data: store.M{"mode": "block", "all": true, "url": srv.URL, "refresh": 24, "entries": []string{"192.0.2.1/32"}}})
	// lokale Adressen sind als Quelle gesperrt
	if _, err := e.FetchList(o.ID); err == nil || !strings.Contains(err.Error(), "lokalen Netz") {
		t.Fatalf("lokale Adresse nicht abgewiesen: %v", err)
	}
	if st := e.ListStatus(o.ID); st.Error == "" || st.At != 0 {
		t.Fatalf("Stand nach Fehler: %+v", st)
	}
	listAllowLocal = true
	defer func() { listAllowLocal = false }()
	ch, err := e.FetchList(o.ID)
	if err != nil || !ch {
		t.Fatalf("Abruf: %v %v", ch, err)
	}
	st := e.ListStatus(o.ID)
	if st.Count != 3 || st.Skipped != 2 || st.Error != "" || st.At == 0 {
		t.Fatalf("Stand: %+v", st)
	}
	v4, v6 := e.listPrefixes(IPListFrom(o))
	if len(v4) != 3 || len(v6) != 1 {
		t.Fatalf("Einträge: %v %v", v4, v6)
	}
	if ch, _ := e.FetchList(o.ID); ch {
		t.Error("unveränderter Inhalt als Änderung gemeldet")
	}
	// wirkt als Sperrliste
	sv := &store.Server{Name: "wg", Protocol: "wireguard", Enabled: true, Settings: store.M{}, State: store.M{}}
	_ = e.InitServer(sv)
	_ = e.St.SaveServer(sv)
	if a := e.acls()[sv.ID]; a == nil || a.Allowed(netip.MustParseAddr("203.0.113.9")) || !a.Allowed(netip.MustParseAddr("203.0.114.9")) {
		t.Errorf("Sperrliste wirkt nicht: %+v", a)
	}
	// Fälligkeit
	l := IPListFrom(o)
	now := time.Now()
	if listDue(l, st, now) || !listDue(l, st, now.Add(25*time.Hour)) {
		t.Error("Fälligkeit falsch")
	}
	l.Refresh = 0
	if listDue(l, st, now.Add(1000*time.Hour)) || !listDue(l, ListStatus{}, now) {
		t.Error("„nur von Hand“: Fälligkeit falsch")
	}
	// leere Antwort lässt den alten Inhalt stehen
	body = "<html>keine Liste</html>\n"
	if _, err := e.FetchList(o.ID); err == nil {
		t.Error("leere Liste angenommen")
	}
	if v4, _ := e.listPrefixes(IPListFrom(o)); len(v4) != 3 {
		t.Errorf("alter Inhalt verloren: %v", v4)
	}
	e.DeleteListData(o.ID)
	if _, err := os.Stat(e.listPath(o.ID)); err == nil {
		t.Error("Datei nicht gelöscht")
	}
}

// TestDNSGate: Umleiter beantwortet nur bekannte Geräte, lernt Adressen passender Namen und
// gibt für sie keine IPv6-Adressen heraus.
func TestDNSGate(t *testing.T) {
	e, dry := newTest(t)
	// Upstream: antwortet auf jede A-Anfrage mit 198.51.100.9 und 10.0.0.1 (privat → wird nicht gelernt)
	up, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:n])
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				hd := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}
				_ = b.AResource(hd, dnsmessage.AResource{A: [4]byte{198, 51, 100, 9}})
				_ = b.AResource(hd, dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}})
			}
			out, _ := b.Finish()
			_, _ = up.WriteTo(out, from)
		}
	}()
	oldUp := dnsUpstream
	dnsUpstream = []string{up.LocalAddr().String()}
	defer func() { dnsUpstream = oldUp }()

	pol := &proto.Policy{Key: "x", Rules: []proto.RouteRule{{ID: 7, Domains: []string{"netflix.com"}, Group: 0}, {ID: 8, All: true, Group: 0}}}
	e.dns.configure(e, []srcPolicy{{pfx: netip.MustParsePrefix("10.8.0.2/32"), pol: pol, peer: 1, dns: true, doh: true},
		{pfx: netip.MustParsePrefix("fd42::2/128"), pol: pol, peer: 1, dns: true, doh: true}}, &routing{})
	query := func(name string, typ dnsmessage.Type) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4711, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
		out, _ := b.Finish()
		return out
	}
	dev := netip.MustParseAddr("10.8.0.2")
	if r := e.dns.handle(e, netip.MustParseAddr("10.8.0.99"), query("www.netflix.com.", dnsmessage.TypeA), false); r != nil {
		t.Fatal("fremdes Gerät bekam eine Antwort")
	}
	resp := e.dns.handle(e, dev, query("WWW.Netflix.com.", dnsmessage.TypeA), false)
	if got := answerAddrs(resp); len(got) != 1 || got[0].String() != "198.51.100.9" {
		t.Fatalf("Antwort: %v", got)
	}
	stdin := strings.Join(dry.Stdin, "\n")
	if !strings.Contains(stdin, "add element inet vpnpanel d7 { 198.51.100.9 }") || strings.Contains(stdin, "10.0.0.1") {
		t.Fatalf("nicht gelernt:\n%s", stdin)
	}
	n := len(dry.Stdin)
	e.dns.handle(e, dev, query("www.netflix.com.", dnsmessage.TypeA), false)
	if len(dry.Stdin) != n {
		t.Error("bekannte Adresse erneut eingetragen")
	}
	if el := e.dns.elements(7); len(el) != 1 || !strings.HasPrefix(el[0], "198.51.100.9 timeout ") {
		t.Errorf("Elemente: %v", el)
	}
	// IPv6 für passende Namen: leere Antwort, ohne den Upstream zu fragen
	resp = e.dns.handle(e, dev, query("www.netflix.com.", dnsmessage.TypeAAAA), false)
	var p dnsmessage.Parser
	if h, err := p.Start(resp); err != nil || !h.Response || h.ID != 4711 || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("AAAA-Antwort: %+v %v", h, err)
	}
	// HTTPS-Einträge (Typ 65) könnten IPv6-Adressen mitgeben → ebenfalls leer
	resp = e.dns.handle(e, dev, query("www.netflix.com.", dnsmessage.Type(65)), false)
	if h, err := p.Start(resp); err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess || len(answerAddrs(resp)) != 0 {
		t.Fatalf("HTTPS-Eintrag: %+v %v", h, err)
	}
	// Diagnose
	if info := e.DNSInfo(); info.Queries < 4 || info.Clients != 1 || info.Rules[7] == nil || info.Rules[7].Addrs != 1 || info.Rules[7].Queries != 2 || !info.Rules[7].Used {
		t.Errorf("Diagnose: %+v %+v", info, info.Rules[7])
	}
	// dasselbe Gerät über IPv6 (IPv6-DNS-Server im Gerät eingetragen)
	if got := answerAddrs(e.dns.handle(e, netip.MustParseAddr("fd42::2"), query("api.netflix.com.", dnsmessage.TypeA), false)); len(got) != 1 {
		t.Errorf("Anfrage über IPv6: %v", got)
	}
	// Namen bekannter DoH-Server gibt es nicht → Browser bleiben bei normalem DNS
	for _, n := range []string{"chrome.cloudflare-dns.com.", "dns.google.", "use-application-dns.net."} {
		resp = e.dns.handle(e, dev, query(n, dnsmessage.TypeA), false)
		var dp dnsmessage.Parser
		if h, err := dp.Start(resp); err != nil || h.RCode != dnsmessage.RCodeNameError {
			t.Errorf("%s: %+v %v", n, h, err)
		}
	}
	// andere Namen werden nur durchgereicht
	n = len(dry.Stdin)
	if got := answerAddrs(e.dns.handle(e, dev, query("example.org.", dnsmessage.TypeA), false)); len(got) != 1 {
		t.Errorf("Durchreichen: %v", got)
	}
	if len(dry.Stdin) != n {
		t.Error("fremder Name gelernt")
	}
}
