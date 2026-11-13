package engine

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// TestUnboundGroups: mit „Unbound“ bekommt jede Gruppe eine eigene Instanz (Konfiguration, Dienst,
// nftables-Markierung und Kill-Switch); Geräte mit Ziel-Regel fragen zuerst die Instanz der Gruppe.
func TestUnboundGroups(t *testing.T) {
	e, dry := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"
	_ = e.St.SetSetting("dns_enabled", "1")
	_ = e.St.SetSetting("dns_resolver", "unbound")

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
	us := saveObj(t, e, &store.Object{Kind: "group", Name: "USA", Enabled: true, Data: store.M{"slot": 2, "exits": []int64{ex.ID}, "on_fail": "block", "dns": "127.0.0.1"}})
	saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "Standard", Enabled: true, Data: store.M{"assign": []string{"global"},
		"smart": []any{map[string]any{"group": us.ID, "domains": []string{"netflix.com"}}}}})
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", ubgPortBase+2)
	cfgPath := fmt.Sprintf("/etc/unbound/vpnpanel-g%d.conf", us.ID)
	b, err := dry.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("Konfiguration fehlt: %v", err)
	}
	for _, want := range []string{"interface: 127.0.0.1@5402", "port: 5402", "do-ip6: no", fmt.Sprintf(`username: "vpnub%d"`, us.ID),
		"access-control: 0.0.0.0/0 refuse", "control-enable: no", "auto-trust-anchor-file:"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("Konfiguration ohne %q:\n%s", want, b)
		}
	}
	if unit, _ := dry.ReadFile(ubgUnitPath); !strings.Contains(string(unit), "-c /etc/unbound/vpnpanel-%i.conf") {
		t.Errorf("Dienst-Vorlage:\n%s", unit)
	}
	log := strings.Join(dry.Log(), "\n")
	start := strings.Index(log, fmt.Sprintf("systemctl restart vpn-unbound@g%d", us.ID))
	if start < 0 || !strings.Contains(log, "unbound-checkconf "+cfgPath) {
		t.Errorf("Dienst nicht eingerichtet:\n%s", log)
	}
	// Start erst, nachdem nftables (Markierung, Kill-Switch) geladen ist; kein Autostart über systemd
	if nftAt := strings.LastIndex(log[:max(start, 0)], "nft -f -"); nftAt < 0 {
		t.Error("Instanz vor nftables gestartet")
	}
	if strings.Contains(log, "systemctl enable vpn-unbound@") {
		t.Error("Instanz darf nicht beim Booten von selbst starten")
	}
	if unit, _ := dry.ReadFile(ubgUnitPath); !strings.Contains(string(unit), `grep -q "uidrange $$u-$$u blackhole"`) ||
		strings.Contains(string(unit), "[Install]") {
		t.Errorf("Wächter im Dienst fehlt: %s", unit)
	}
	uid := ubgDryUID + int(us.ID)
	// Kill-Switch per Routing: Weg über die Gruppe, dahinter die Sperre (auch IPv6), alles vor dem Start.
	// Keine Firewall-Regel nach Benutzer – sie träfe auch die WireGuard-Pakete des Ausgangs.
	if strings.Contains(dry.Inputs["nft"], "skuid") {
		t.Error("Firewall-Regel nach Benutzer noch vorhanden")
	}
	way := fmt.Sprintf("ip -4 rule add priority %d uidrange %d-%d lookup 3002", ubgRulePrio+2, uid, uid)
	for _, cmd := range []string{way,
		fmt.Sprintf("ip -4 rule add priority %d uidrange %d-%d blackhole", ubgRulePrio+130, uid, uid),
		fmt.Sprintf("ip -6 rule add priority %d uidrange %d-%d blackhole", ubgRulePrio+130, uid, uid)} {
		if at := strings.Index(log, cmd); at < 0 || at > start {
			t.Errorf("Routing-Regel fehlt oder kommt nach dem Start: %s", cmd)
		}
	}
	if strings.Index(log, "uidrange "+fmt.Sprint(uid)+"-"+fmt.Sprint(uid)+" blackhole") > strings.Index(log, way) {
		t.Error("Sperre muss vor dem Weg gesetzt werden")
	}
	if DNSServerName(addr) != "Unbound · USA" {
		t.Errorf("Name: %q", DNSServerName(addr))
	}

	// Instanz übernimmt die Anfragen der Gruppe, sobald die Prüfung sie freigibt
	inst, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Skipf("Port %s belegt: %v", addr, err)
	}
	defer inst.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := inst.ReadFrom(buf)
			if err != nil {
				return
			}
			var pp dnsmessage.Parser
			h, err := pp.Start(buf[:n])
			if err != nil {
				continue
			}
			q, _ := pp.Question()
			_, _ = inst.WriteTo(dnsReply(h, q, dnsmessage.RCodeSuccess, []netip.Addr{netip.MustParseAddr("203.0.113.99")}, 60), from)
		}
	}()
	vpn := netip.MustParseAddr("100.64.0.2")
	if peer4, ok := p.Settings["address4"].(string); ok {
		vpn = netip.MustParseAddr(strings.Split(peer4, "/")[0])
	}
	e.checkUnbound()
	h := e.UnboundHealth()
	if len(h.Groups) != 1 || !h.Groups[0].OK || h.Groups[0].Addr != addr {
		t.Fatalf("Prüfung: %+v", h)
	}
	if _, got := answers(t, e.dns.handle(e, vpn, dnsQuery("www.netflix.com.", dnsmessage.TypeA), false)); strings.Join(got, " ") != "203.0.113.99" {
		t.Errorf("Antwort über die Instanz: %v", got)
	}
	// ausgefallene Instanz wird übersprungen
	st := e.dns.ubStateOf(addr)
	st.down.Store(true)
	if got := e.dns.skipDown([]string{addr, "127.0.0.1:53"}); len(got) != 1 || got[0] != "127.0.0.1:53" {
		t.Errorf("Überspringen: %v", got)
	}

	// zurück auf öffentliche DNS-Server: Instanz verschwindet samt Firewall-Regeln
	_ = e.St.SetSetting("dns_resolver", "upstream")
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	log = strings.Join(dry.Log(), "\n")
	if !strings.Contains(log, fmt.Sprintf("systemctl disable --now vpn-unbound@g%d", us.ID)) || dry.Exists(cfgPath) {
		t.Errorf("Instanz nicht entfernt")
	}
	if strings.Contains(dry.Inputs["nft"], "skuid") {
		t.Error("Firewall-Regeln der Instanz noch da")
	}
	if len(e.ubInstances()) != 0 {
		t.Error("Instanzliste nicht leer")
	}
}
