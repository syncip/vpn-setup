package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/vless"
	_ "vpnpanel/internal/proto/wireguard"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

func newTest(t *testing.T) (*Engine, *system.Dry) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dry := &system.Dry{Root: filepath.Join(dir, "root")}
	return New(st, dry, Config{PanelBackend: "127.0.0.1:8480", DataDir: dir}), dry
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.Local)
	l := &store.Limits{TrafficGB: 100, Period: "monthly", ResetDay: 1, OnLimit: "throttle", LimitDownMbit: 5, LimitUpMbit: 2,
		SpeedDownMbit: 200, Tiers: []store.Tier{{AfterGB: 50, DownMbit: 50, UpMbit: 20}, {AfterGB: 80, DownMbit: 20}}}
	cases := []struct {
		name   string
		user   store.User
		status string
		down   float64
	}{
		{"frei", store.User{Enabled: true, PeriodDown: 10 * GB}, "ok", 200},
		{"Stufe 1", store.User{Enabled: true, PeriodDown: 60 * GB}, "throttled", 50},
		{"Stufe 2", store.User{Enabled: true, PeriodDown: 85 * GB}, "throttled", 20},
		{"Limit", store.User{Enabled: true, PeriodDown: 101 * GB}, "throttled", 5},
		{"deaktiviert", store.User{Enabled: false}, "disabled", 0},
		{"abgelaufen", store.User{Enabled: true, ExpiresAt: now.Add(-time.Hour).Unix()}, "expired", 0},
	}
	for _, c := range cases {
		v := Evaluate(&c.user, l, now)
		if v.Status != c.status || v.RateDown != c.down {
			t.Errorf("%s: %s/%v, erwartet %s/%v", c.name, v.Status, v.RateDown, c.status, c.down)
		}
	}
	l.OnLimit = "block"
	if v := Evaluate(&store.User{Enabled: true, PeriodUp: 100 * GB}, l, now); v.Status != "blocked" || v.Active() {
		t.Errorf("Sperre erwartet, bekommen %s", v.Status)
	}
	if ps := PeriodStart(&store.Limits{Period: "monthly", ResetDay: 15}, now); time.Unix(ps, 0).Day() != 15 || time.Unix(ps, 0).Month() != 10 {
		t.Errorf("Monatsbeginn falsch: %v", time.Unix(ps, 0))
	}
	if ps := PeriodStart(&store.Limits{Period: "weekly", ResetDay: 1}, now); time.Unix(ps, 0).Weekday() != time.Monday {
		t.Errorf("Wochenbeginn falsch: %v", time.Unix(ps, 0))
	}
}

func write(t *testing.T, dry *system.Dry, path, content string) {
	t.Helper()
	if _, err := dry.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Übernahme des alten Bash-Setups: Schlüssel, Adressen, Abo-Token und Statistik bleiben gleich.
func TestImportLegacy(t *testing.T) {
	e, dry := newTest(t)
	priv, _, _ := proto.X25519()
	write(t, dry, "/etc/wireguard/server.key", proto.B64(priv)+"\n")
	write(t, dry, "/etc/vpn/vpn.env", `SERVER_HOST="sys1.1337733.xyz"
PUBLIC_PORT=443
WG_PORT=51820
WG_NET4="10.8.0"
WG_NET6="fd42:42:42::"
WG_IF="wg0"
OUT_IF="eth0"
XRAY_API="127.0.0.1:10085"
declare -a REALITY_TARGETS=([0]="dl.google.com:443|dl.google.com maps.google.com" [1]="web.whatsapp.com:443|web.whatsapp.com")
SUB_HOST="sub.1337733.xyz"
`)
	write(t, dry, "/etc/vpn/reality.env", `XR_PRIV="aGVsbG8td29ybGQtaGVsbG8td29ybGQtaGVsbG8td28"
XR_PUB="cHVi"
XR_SID="0123456789abcdef"
`)
	cp, cpub, _ := proto.X25519()
	write(t, dry, "/etc/vpn/users.json", `{"users":{"client1":{"uuid":"11111111-2222-4333-8444-555555555555","n":10,"wg_priv":"`+proto.B64(cp)+
		`","wg_pub":"`+proto.B64(cpub)+`","psk":"cHNr","created":"2026-11-05 10:00","vless_up":100,"vless_down":2000,"wg_rx":5,"wg_tx":7,
		"wg_last_rx":5,"wg_last_tx":7,"wg_handshake":0,"sub":"0123456789abcdef0123456789abcdef"}}}`)

	ok, err := e.ImportLegacy("/etc/vpn")
	if err != nil || !ok {
		t.Fatalf("Import: %v %v", ok, err)
	}
	u, err := e.St.UserByName("client1")
	if err != nil {
		t.Fatal(err)
	}
	if u.SubToken != "0123456789abcdef0123456789abcdef" || u.TotalDown != 2007 || u.TotalUp != 105 {
		t.Errorf("Nutzer falsch übernommen: %+v", u)
	}
	peers, _ := e.St.PeersOfUser(u.ID)
	if len(peers) != 2 {
		t.Fatalf("2 Zugänge erwartet, %d", len(peers))
	}
	wg := peers[0]
	if proto.Str(wg.Settings, "address4") != "10.8.0.10" || proto.Str(wg.Settings, "address6") != "fd42:42:42::10" {
		t.Errorf("Adressen geändert: %v", wg.Settings)
	}
	if proto.Str(peers[1].Secrets, "uuid") != "11111111-2222-4333-8444-555555555555" {
		t.Errorf("UUID geändert")
	}
	servers, _ := e.St.Servers()
	if proto.Str(servers[0].State, "private_key") != proto.B64(priv) {
		t.Errorf("Server-Schlüssel nicht übernommen")
	}
	if sids := servers[1].Settings["short_ids"].([]any); sids[0] != "0123456789abcdef" {
		t.Errorf("Short-ID nicht übernommen: %v", sids)
	}
	// Zweiter Import tut nichts
	if ok, _ := e.ImportLegacy("/etc/vpn"); ok {
		t.Errorf("zweiter Import sollte nichts tun")
	}

	// Anwenden: VLESS-Links und WireGuard-Config
	if err := e.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	links, _ := e.SubLinks(u.ID)
	// Abo: WireGuard (Handy/Laptop) als wireguard://-Link + VLESS je Tarnziel
	if len(links) != 4 || !strings.HasPrefix(links[0], "wireguard://") || !strings.Contains(links[1], "sid=0123456789abcdef") || !strings.Contains(links[1], "@sys1.1337733.xyz:443") {
		t.Errorf("Links falsch: %v", links)
	}
	xc, _ := os.ReadFile(filepath.Join(dry.Root, "usr/local/etc/xray/config.json"))
	if !strings.Contains(string(xc), `"domainStrategy": "UseIPv6v4"`) {
		t.Errorf("Xray bevorzugt IPv6 nicht:\n%s", xc)
	}
	conf, _ := os.ReadFile(filepath.Join(dry.Root, "etc/wireguard/wg0.conf"))
	if !strings.Contains(string(conf), "AllowedIPs = 10.8.0.10/32, fd42:42:42::10/128") || !strings.Contains(string(conf), "ListenPort = 51820") {
		t.Errorf("wg0.conf falsch:\n%s", conf)
	}
}

// Netzwerk: Zugriffsregeln, Routen und Client-Konfiguration für ein Homelab.
func TestMeshFirewall(t *testing.T) {
	e, dry := newTest(t)
	sv := &store.Server{Name: "Netz", Protocol: "wireguard", Enabled: true, Settings: store.M{"internet": false, "default_access": "own"}}
	if err := e.InitServer(sv); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(sv)
	alice := &store.User{Name: "alice", Enabled: true, SubToken: proto.RandHex(16)}
	bob := &store.User{Name: "bob", Enabled: true, SubToken: proto.RandHex(16)}
	_ = e.St.SaveUser(alice)
	_ = e.St.SaveUser(bob)
	add := func(u *store.User, name, kind string, s store.M) *store.Peer {
		p := &store.Peer{UserID: u.ID, ServerID: sv.ID, Name: name, Kind: kind, Enabled: true, Settings: s}
		if err := e.InitPeer(sv, p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = e.St.SavePeer(p)
		return p
	}
	lab := add(alice, "lab", "site", store.M{"routes": []any{"192.168.1.0/24"}, "lan_nat": true, "lan_interface": "eth0"})
	add(alice, "phone", "client", store.M{"tunnel": "split"})
	bobPC := add(bob, "pc", "server", store.M{})
	// Überschneidendes Netz wird abgelehnt
	bad := &store.Peer{UserID: bob.ID, ServerID: sv.ID, Name: "x", Kind: "site", Settings: store.M{"routes": []any{"192.168.1.0/25"}}}
	if err := e.InitPeer(sv, bad); err == nil {
		t.Errorf("Überschneidung nicht erkannt")
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	fw := dry.Inputs["iptables-restore"]
	if !strings.Contains(fw, "-s 10.8.0.3/32 -d 192.168.1.0/24 -j ACCEPT") {
		t.Errorf("Handy sollte das Homelab-Netz erreichen:\n%s", fw)
	}
	if strings.Contains(fw, "-s 10.8.0.4/32 -d 192.168.1.0/24") {
		t.Errorf("bob sollte alices Netz nicht erreichen (Standard: nur eigene)")
	}
	if strings.Contains(fw, "MASQUERADE") || strings.Contains(fw, "-o eth0 -s") {
		t.Errorf("ohne Internetzugang kein NAT/Ausgang erwartet:\n%s", fw)
	}
	// Bob bekommt Zugriff auf das Homelab
	bobPC.Settings["access"] = "custom"
	bobPC.Settings["access_peers"] = []any{float64(lab.ID)}
	if err := e.InitPeer(sv, bobPC); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SavePeer(bobPC)
	_ = e.Apply()
	if fw := dry.Inputs["iptables-restore"]; !strings.Contains(fw, "-s 10.8.0.4/32 -d 192.168.1.0/24 -j ACCEPT") {
		t.Errorf("benutzerdefinierter Zugriff fehlt:\n%s", fw)
	}
	cc, err := e.ClientConfig(lab.ID)
	if err != nil {
		t.Fatal(err)
	}
	c := cc.Files[0].Content
	if strings.Contains(c, "AllowedIPs = 0.0.0.0/0") || !strings.Contains(c, "MASQUERADE") || strings.Contains(c, "192.168.1.0/24, ") {
		t.Errorf("Homelab-Konfiguration falsch:\n%s", c)
	}
	// Zeilenumbrüche in Namen/Feldern dürfen keine Zeilen in wg0.conf einschleusen
	evil := &store.Peer{UserID: bob.ID, ServerID: sv.ID, Name: "x", Kind: "server",
		Settings: store.M{"endpoint": "1.2.3.4:51820\nPostUp = touch /tmp/pwn"}}
	if err := e.InitPeer(sv, evil); err == nil {
		t.Errorf("Endpunkt mit Zeilenumbruch akzeptiert")
	}
	evil.Settings = store.M{"dns": "1.1.1.1\n[Interface]"}
	if err := e.InitPeer(sv, evil); err == nil {
		t.Errorf("DNS mit Zeilenumbruch akzeptiert")
	}
	evil.Settings = store.M{"endpoint": "[2001:db8::1]:51820", "dns": "1.1.1.1, 2606:4700:4700::1111"}
	if err := e.InitPeer(sv, evil); err != nil {
		t.Errorf("gültige Werte abgelehnt: %v", err)
	}
	lab.Name = "lab\nPostUp = touch /tmp/pwn"
	_ = e.St.SavePeer(lab)
	_ = e.Apply()
	conf, _ := os.ReadFile(filepath.Join(dry.Root, "etc/wireguard/wg0.conf"))
	if strings.Contains(string(conf), "\nPostUp = touch") {
		t.Errorf("Zeilenumbruch im Namen landet in wg0.conf:\n%s", conf)
	}
	// Routen-Befehl für das Netz hinter dem Homelab
	found := false
	for _, l := range dry.Log() {
		if strings.Contains(l, "ip -4 route replace 192.168.1.0/24 dev wg0 proto 77") {
			found = true
		}
	}
	if !found {
		t.Errorf("Route für 192.168.1.0/24 fehlt")
	}
}
