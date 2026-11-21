package engine

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/store"
)

// TestDNSExternal: Geräte ohne VPN – nur freigegebene Absender bekommen Antworten (mit ihrem
// Filterprofil), Fremde werden verworfen und mitgezählt; Port 53 nur, wenn eingeschaltet.
func TestDNSExternal(t *testing.T) {
	e, dry := newTest(t)
	up, _ := fakeUpstream(t)
	oldUp := dnsUpstream
	dnsUpstream = []string{up}
	defer func() { dnsUpstream = oldUp }()

	kids := saveObj(t, e, &store.Object{Kind: "dnslist", Name: "Kinder", Enabled: true, Data: store.M{"mode": "block", "entries": []string{"spiele.example"}}})
	prof := saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "TV", Enabled: true, Data: store.M{"lists": []int64{kids.ID}, "assign": []string{}}})
	tv := saveObj(t, e, &store.Object{Kind: "dnsclient", Name: "Fernseher", Enabled: true,
		Data: store.M{"addrs": []string{"203.0.113.50", "2001:db8:5::/64"}, "profile": float64(prof.ID)}})

	nftOf := func() string {
		for _, s := range dry.Stdin {
			if strings.Contains(s, "table inet vpnpanel {") {
				return s
			}
		}
		return ""
	}
	// aus: kein Port 53 von außen, keine Antworten
	dry.Stdin = nil
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nftOf(), "vp_dnsext") {
		t.Error("Port 53 offen, obwohl ausgeschaltet")
	}
	tvIP := netip.MustParseAddr("203.0.113.50")
	if r := e.dns.handle(e, tvIP, dnsQuery("example.org.", dnsmessage.TypeA), false); r != nil {
		t.Error("Antwort, obwohl ausgeschaltet")
	}

	_ = e.St.SetSetting("dns_public", "1")
	dry.Stdin = nil
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if n := nftOf(); !strings.Contains(n, `iifname "eth0" udp dport 53 redirect to :5399`) || !strings.Contains(n, `iifname "eth0" tcp dport 53 redirect to :5399`) {
		t.Errorf("Firewall:\n%s", n)
	}
	if _, got := answers(t, e.dns.handle(e, tvIP, dnsQuery("example.org.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "198.51.100.9" {
		t.Errorf("Fernseher: %v", got)
	}
	if code, got := answers(t, e.dns.handle(e, tvIP, dnsQuery("www.spiele.example.", dnsmessage.TypeA), false)); code != dnsmessage.RCodeSuccess || strings.Join(got, " ") != "0.0.0.0" {
		t.Errorf("Profil des Fernsehers: %v %v", code, got)
	}
	if r := e.dns.handle(e, netip.MustParseAddr("2001:db8:5::77"), dnsQuery("example.org.", dnsmessage.TypeAAAA), false); r == nil {
		t.Error("Netz des Fernsehers ohne Antwort")
	}
	stranger := netip.MustParseAddr("198.51.100.66")
	for i := 0; i < 3; i++ {
		if r := e.dns.handle(e, stranger, dnsQuery("fremd.example.", dnsmessage.TypeA), false); r != nil {
			t.Fatal("Fremder bekommt Antwort")
		}
	}

	x := e.DNSExternal()
	if !x.Public || len(x.Clients) != 1 {
		t.Fatalf("Übersicht: %+v", x)
	}
	if c := x.Clients[0]; c.ID != tv.ID || c.Queries != 3 || c.Blocked != 1 || len(c.Sources) != 2 {
		t.Errorf("Fernseher: %+v", c)
	}
	var st *ExtSeenRow
	for i := range x.Seen {
		if x.Seen[i].Addr == stranger.String() {
			st = &x.Seen[i]
		}
	}
	if st == nil || st.Client != 0 || st.Refused != 3 || st.Name != "fremd.example" {
		t.Errorf("Fremder: %+v", st)
	}

	// Gerät abgeschaltet → Fremder
	tv.Enabled = false
	_ = e.St.SaveObject(tv)
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if r := e.dns.handle(e, tvIP, dnsQuery("example.org.", dnsmessage.TypeA), false); r != nil {
		t.Error("abgeschaltetes Gerät bekommt Antwort")
	}

	// Eingaben prüfen
	// große Netze sind erlaubt (Warnhinweis), auch 0.0.0.0/0
	if l, err := ParseClientAddrs([]string{"0.0.0.0/0, ::/0, 10.1.2.3/8, 192.0.2.0/24"}); err != nil || strings.Join(LargeNets(l), " ") != "0.0.0.0/0 ::/0 10.0.0.0/8" {
		t.Errorf("große Netze: %v %v", l, err)
	}
	// Begrenzung je Absender (IPv6 je /64), Vorgabe 20/s, kurz bis 60
	var lim extLimiter
	now := time.Now()
	rate, burst := extRateOf(defExtRate, defExtBurst, 0, 0)
	n := 0
	for i := 0; i < 200; i++ {
		if lim.allow(netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i+1)), now, rate, burst, 7) {
			n++
		}
	}
	if n != defExtBurst || lim.allow(netip.MustParseAddr("2001:db8::ffff"), now, rate, burst, 7) || !lim.allow(netip.MustParseAddr("192.0.2.1"), now, rate, burst, 8) {
		t.Errorf("Begrenzung: %d durchgelassen", n)
	}
	if !lim.allow(netip.MustParseAddr("2001:db8::1"), now.Add(time.Second), rate, burst, 7) {
		t.Error("Begrenzung erholt sich nicht")
	}
	if total, by := lim.Dropped(); total != 141 || by[7].Count != 141 || by[8].Count != 0 {
		t.Errorf("verworfen: %d %+v", total, by)
	}
	// eigene Werte je Gerät: unbegrenzt, eigener Wert mit automatischer Spitze, Spitze nie unter dem Wert
	if r, _ := extRateOf(20, 60, -1, 0); r != 0 {
		t.Error("unbegrenzt")
	}
	if r, b := extRateOf(20, 60, 200, 0); r != 200 || b != 600 {
		t.Errorf("eigener Wert: %v %v", r, b)
	}
	if r, b := extRateOf(50, 10, 0, 0); r != 50 || b != 50 {
		t.Errorf("Spitze unter dem Wert: %v %v", r, b)
	}
	if r, _ := extRateOf(0, 0, 0, 0); r != 0 || !lim.allow(netip.MustParseAddr("2001:db8::ffff"), now, 0, 0, 7) {
		t.Error("global aus")
	}
	if l, err := ParseClientAddrs([]string{"Mein.DynDNS.org, 192.0.2.1\n2001:db8::1"}); err != nil || strings.Join(l, " ") != "mein.dyndns.org 192.0.2.1 2001:db8::1" {
		t.Errorf("Adressen: %v %v", l, err)
	}
	if _, err := ParseClientAddrs([]string{"kein host!"}); err == nil {
		t.Error("ungültiger Name angenommen")
	}
}
