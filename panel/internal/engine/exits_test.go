package engine

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/store"
)

func testKey(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32)))
}

func TestExitsAndACL(t *testing.T) {
	e, dry := newTest(t)
	wg := &store.Server{Name: "wg", Protocol: "wireguard", Enabled: true, Settings: store.M{}, State: store.M{}}
	vl := &store.Server{Name: "vl", Protocol: "vless", Enabled: true, Settings: store.M{}, State: store.M{}}
	for _, s := range []*store.Server{wg, vl} {
		if err := e.InitServer(s); err != nil {
			t.Fatal(err)
		}
		if err := e.St.SaveServer(s); err != nil {
			t.Fatal(err)
		}
	}
	// Ausgang (WireGuard-Konfiguration eines Anbieters, mit Skript, das entfernt werden muss)
	conf := "[Interface]\nPrivateKey = " + testKey('a') + "\nAddress = 100.64.0.2/32\nPostUp = iptables -F\n[Peer]\nPublicKey = " + testKey('b') +
		"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	ex := &store.Object{Kind: "exit", Name: "USA", Enabled: true, Data: store.M{"type": "wireguard", "slot": 1}, Secrets: store.M{"config": conf}}
	if err := e.St.SaveObject(ex); err != nil {
		t.Fatal(err)
	}
	gr := &store.Object{Kind: "group", Name: "US", Enabled: true, Data: store.M{"slot": 2, "exits": []int64{ex.ID}, "on_fail": "block"}}
	if err := e.St.SaveObject(gr); err != nil {
		t.Fatal(err)
	}
	// Sperrliste für alle, Freigabeliste nur für VLESS
	bl := &store.Object{Kind: "iplist", Name: "böse", Enabled: true, Data: store.M{"mode": "block", "all": true, "entries": []string{"203.0.113.0/24", "2001:db8::/32"}}}
	al := &store.Object{Kind: "iplist", Name: "nur Familie", Enabled: true, Data: store.M{"mode": "allow", "servers": []int64{vl.ID}, "entries": []string{"198.51.100.7/32"}}}
	for _, o := range []*store.Object{bl, al} {
		if err := e.St.SaveObject(o); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	stdin := strings.Join(dry.Stdin, "\n----\n")
	for _, want := range []string{
		"-A VPNEX-IN -i ex1 -j DROP", "-A VPNEX-NAT -o ex1 -j MASQUERADE", "--clamp-mss-to-pmtu",
		"-A VPNACL -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-A VPNACL -p udp -m udp --dport 51820 -j VPNACL-" + id64(wg.ID),
		"-A VPNACL-" + id64(wg.ID) + " -s 203.0.113.0/24 -j DROP",
		"-A VPNACL-" + id64(wg.ID) + " -s 2001:db8::/32 -j DROP",
	} {
		if !strings.Contains(stdin, want) {
			t.Errorf("fehlt: %s", want)
		}
	}
	if strings.Contains(stdin, "VPNACL-"+id64(vl.ID)) {
		t.Error("VLESS darf keine iptables-Kette bekommen (geteilter Port 443)")
	}
	log := strings.Join(dry.Log(), "\n")
	for _, want := range []string{"wg setconf ex1", "ip -4 rule add priority 6002 fwmark 0x2000000/0x7f000000 lookup 3002",
		"ip -4 rule add priority 6101 fwmark 0x41000000/0x7f000000 lookup 2001", "ip -4 route replace default dev ex1 table 3002"} {
		if !strings.Contains(log, want) {
			t.Errorf("Befehl fehlt: %s", want)
		}
	}
	wgconf, _ := dry.ReadFile("/etc/vpn/exits/ex1.conf")
	if strings.Contains(string(wgconf), "PostUp") || strings.Contains(string(wgconf), "iptables") {
		t.Errorf("Skript nicht entfernt:\n%s", wgconf)
	}
	xr, _ := dry.ReadFile("/usr/local/etc/xray/config.json")
	for _, want := range []string{`"203.0.113.0/24"`, `"198.51.100.7/32"`, `"outboundTag": "block"`} {
		if !strings.Contains(string(xr), want) {
			t.Errorf("Xray-Regel fehlt: %s", want)
		}
	}
	// Treiber kennen die Gruppe
	g := e.Global().Groups[gr.ID]
	if g.Mark != exits.GroupMark(2) || !g.Enabled || len(g.DNS) == 0 {
		t.Errorf("Gruppe für Treiber: %+v", g)
	}
	// Alles wieder weg → Ketten und Regeln werden abgebaut
	for _, o := range []*store.Object{bl, al} {
		_ = e.St.DeleteObject("iplist", o.ID)
	}
	_ = e.St.DeleteObject("group", gr.ID)
	_ = e.St.DeleteObject("exit", ex.ID)
	n := len(dry.Log())
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	log = strings.Join(dry.Log()[n:], "\n")
	for _, want := range []string{"iptables -D INPUT -j VPNACL", "ip link del dev ex1", "ip -4 rule del priority 6002", "iptables -D INPUT -j VPNEX-IN"} {
		if !strings.Contains(log, want) {
			t.Errorf("Abbau fehlt: %s", want)
		}
	}
}

func id64(n int64) string { return strconv.FormatInt(n, 10) }

func TestParseIPEntries(t *testing.T) {
	got, err := ParseIPEntries("# Kommentar\n203.0.113.5\n10.0.0.0/8, 10.1.2.3/8\n2001:db8::1 # Host\n::ffff:1.2.3.4\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "1.2.3.4/32 10.0.0.0/8 203.0.113.5/32 2001:db8::1/128" {
		t.Fatalf("%v", got)
	}
	for _, bad := range []string{"0.0.0.0/0", "kein-ip", "1.2.3.4/33", "::/0"} {
		if _, err := ParseIPEntries(bad); err == nil {
			t.Errorf("%s: Fehler erwartet", bad)
		}
	}
}
