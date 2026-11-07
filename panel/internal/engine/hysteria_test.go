package engine

import (
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/hysteria2"
	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
)

// Hysteria2: Konfiguration, Anmeldung über das Panel, Drosselung per Client-Adresse.
func TestHysteria2(t *testing.T) {
	e, dry := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"

	wg := &store.Server{Name: "WG", Protocol: "wireguard", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(wg); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(wg)
	// Port-Kollision mit WireGuard (UDP 51820) wird erkannt
	bad := &store.Server{Name: "x", Protocol: "hysteria2", Enabled: true, Settings: store.M{"port": float64(51820)}}
	if err := e.InitServer(bad); err == nil {
		t.Errorf("UDP-Port-Kollision nicht erkannt")
	}

	hy := &store.Server{Name: "Schnell", Protocol: "hysteria2", Enabled: true, Settings: store.M{"obfs": true}}
	if err := e.InitServer(hy); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(hy)
	if len(proto.Str(hy.State, "cert_sha256")) != 64 || proto.Str(hy.State, "cert_name") != "sys1.1337733.xyz" {
		t.Errorf("Zertifikat fehlt: %v", hy.State["cert_name"])
	}

	plan := &store.Plan{Name: "Drossel", Limits: store.Limits{SpeedDownMbit: 10, SpeedUpMbit: 5}}
	_ = e.St.SavePlan(plan)
	free := &store.User{Name: "frei", Enabled: true, SubToken: proto.RandHex(16)}
	slow := &store.User{Name: "langsam", Enabled: true, SubToken: proto.RandHex(16), PlanID: &plan.ID}
	off := &store.User{Name: "aus", Enabled: false, SubToken: proto.RandHex(16)}
	var peers []*store.Peer
	for _, u := range []*store.User{free, slow, off} {
		_ = e.St.SaveUser(u)
		p := &store.Peer{UserID: u.ID, ServerID: hy.ID, Name: u.Name, Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(hy, p); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SavePeer(p)
		peers = append(peers, p)
	}
	if err := e.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cfg, err := os.ReadFile(filepath.Join(dry.Root, "etc/hysteria", "hy"+itoa(hy.ID)+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"listen": ":443"`, `"url": "http://127.0.0.1:8479/hook/` + itoa(hy.ID) + `/` + proto.Str(hy.State, "hook_secret"), `"salamander"`, `"ignoreClientBandwidth": true`} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("Konfiguration ohne %s:\n%s", want, cfg)
		}
	}

	// Anmeldung
	secret := proto.Str(hy.State, "hook_secret")
	if _, err := e.Hook(hy.ID, "falsch", []byte(`{}`)); err == nil {
		t.Errorf("falsches Geheimnis akzeptiert")
	}
	auth := func(p *store.Peer, addr string) map[string]any {
		r, err := e.Hook(hy.ID, secret, []byte(`{"addr":"`+addr+`","auth":"`+proto.Str(p.Secrets, "password")+`","tx":0}`))
		if err != nil {
			t.Fatal(err)
		}
		return r.(map[string]any)
	}
	if r := auth(peers[0], "198.51.100.7:40000"); r["ok"] != true || r["id"] != "p"+itoa(peers[0].ID) {
		t.Errorf("Anmeldung abgelehnt: %v", r)
	}
	if r := auth(peers[2], "198.51.100.9:40000"); r["ok"] != false {
		t.Errorf("deaktivierter Nutzer angemeldet")
	}
	if r, _ := e.Hook(hy.ID, secret, []byte(`{"addr":"1.2.3.4:5","auth":"nope"}`)); r.(map[string]any)["ok"] != false {
		t.Errorf("falsches Passwort angemeldet")
	}
	if r := auth(peers[1], "[2001:db8::5]:41000"); r["ok"] != true {
		t.Errorf("gedrosselter Nutzer abgelehnt")
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	log := strings.Join(dry.Log(), "\n")
	if !strings.Contains(log, "match ip6 dst 2001:db8::5/128 match ip6 sport 443 0xffff") || !strings.Contains(log, "rate 10000kbit") {
		t.Errorf("Drosselung für die Client-Adresse fehlt:\n%s", log)
	}
	if !strings.Contains(log, "match ip6 src 2001:db8::5/128 match ip6 dport 443 0xffff") || !strings.Contains(log, "rate 5000kbit") {
		t.Errorf("Upload-Drosselung fehlt")
	}
	if strings.Contains(log, "198.51.100.7") {
		t.Errorf("ungedrosselter Nutzer wird begrenzt")
	}
	if !strings.Contains(log, "fq_codel") {
		t.Errorf("gedrosselte Klassen ohne fq_codel")
	}
	if !strings.Contains(string(cfg), `"maxIdleTimeout": "60s"`) {
		t.Errorf("Leerlauf-Timeout fehlt:\n%s", cfg)
	}

	// Neue Adresse eines gedrosselten Nutzers: Regeln anpassen, ohne die qdisc zu löschen
	// (sonst verlieren alle anderen Verbindungen kurz Pakete)
	_, _ = dry.Run("MARKE")
	auth(peers[1], "203.0.113.20:5000")
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	after := strings.Join(dry.Log(), "\n")
	after = after[strings.LastIndex(after, "MARKE"):]
	if strings.Contains(after, "qdisc del dev eth0 root") || !strings.Contains(after, "match ip dst 203.0.113.20/32") {
		t.Errorf("Anpassung statt Neuaufbau erwartet:\n%s", after)
	}
	// Nach einem Neustart des Panels (Reset) wird komplett neu aufgebaut
	shaping.Reset(e.Env().SetState)
	_, _ = dry.Run("MARKE2")
	_ = e.Apply()
	after = strings.Join(dry.Log(), "\n")
	after = after[strings.LastIndex(after, "MARKE2"):]
	if !strings.Contains(after, "qdisc add dev eth0 root handle 1: htb") {
		t.Errorf("Neuaufbau nach Reset fehlt:\n%s", after)
	}

	// Abo-Link
	links, _ := e.SubLinks(slow.ID)
	if len(links) != 1 || !strings.HasPrefix(links[0], "hysteria2://"+proto.Str(peers[1].Secrets, "password")+"@sys1.1337733.xyz:443/?") ||
		!strings.Contains(links[0], "obfs=salamander") || !strings.Contains(links[0], "pinSHA256="+proto.Str(hy.State, "cert_sha256")) {
		t.Errorf("Link falsch: %v", links)
	}

	// Server deaktivieren → Instanz wird abgebaut
	hy.Enabled = false
	_ = e.St.SaveServer(hy)
	_ = e.Apply()
	if !strings.Contains(strings.Join(dry.Log(), "\n"), "systemctl disable --now vpn-hysteria@hy"+itoa(hy.ID)) {
		t.Errorf("Instanz nicht abgebaut")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// Port-Hopping: Umleitung im Container, Link mit mport, Kollision mit WireGuard erkannt.
func TestHysteria2PortHopping(t *testing.T) {
	e, dry := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"
	wg := &store.Server{Name: "WG", Protocol: "wireguard", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(wg); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(wg)
	bad := &store.Server{Name: "x", Protocol: "hysteria2", Enabled: true, Settings: store.M{"hop_ports": "50000-52000"}}
	if err := e.InitServer(bad); err == nil {
		t.Errorf("Überschneidung mit WireGuard 51820 nicht erkannt")
	}
	bad.Settings = store.M{"hop_ports": "kaputt"}
	if err := e.InitServer(bad); err == nil {
		t.Errorf("ungültiger Bereich akzeptiert")
	}
	hy := &store.Server{Name: "Hop", Protocol: "hysteria2", Enabled: true, Settings: store.M{"hop_ports": "20000:40000"}}
	if err := e.InitServer(hy); err != nil {
		t.Fatal(err)
	}
	if hy.Settings["hop_ports"] != "20000-40000" {
		t.Errorf("Bereich nicht vereinheitlicht: %v", hy.Settings["hop_ports"])
	}
	_ = e.St.SaveServer(hy)
	u := &store.User{Name: "u", Enabled: true, SubToken: proto.RandHex(16)}
	_ = e.St.SaveUser(u)
	p := &store.Peer{UserID: u.ID, ServerID: hy.ID, Name: "u", Enabled: true, Settings: store.M{}}
	_ = e.InitPeer(hy, p)
	_ = e.St.SavePeer(p)
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if in := dry.Inputs["ip6tables-restore"]; !strings.Contains(in, "-A VPNHY -i eth0 -p udp -m udp --dport 20000:40000 -j REDIRECT --to-ports 443") {
		t.Errorf("Umleitung fehlt:\n%s", in)
	}
	links, _ := e.SubLinks(u.ID)
	if len(links) != 1 || !strings.Contains(links[0], "mport=20000-40000") || !strings.Contains(links[0], ":443/") {
		t.Errorf("Link ohne mport: %v", links)
	}
	cc, _ := e.ClientConfig(p.ID)
	if !strings.Contains(cc.Files[0].Content, ":20000-40000\n") || !strings.Contains(cc.Files[0].Content, "hopInterval: 30s") {
		t.Errorf("Client-Datei ohne Port-Hopping:\n%s", cc.Files[0].Content)
	}
	// Aus → Regeln weg
	hy.Settings["hop_ports"] = ""
	_ = e.InitServer(hy)
	_ = e.St.SaveServer(hy)
	_ = e.Apply()
	if !strings.Contains(strings.Join(dry.Log(), "\n"), "iptables -t nat -D PREROUTING -j VPNHY") {
		t.Errorf("Umleitung nicht entfernt")
	}
}

// Links für Hiddify (ray2sing): Port-Hopping im Host-Teil, WireGuard als wireguard://-Link.
func TestShareLinksHiddify(t *testing.T) {
	e, _ := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"
	u := &store.User{Name: "martin", Enabled: true, SubToken: proto.RandHex(16)}
	_ = e.St.SaveUser(u)
	ids := map[string]int64{}
	for _, pr := range []string{"wireguard", "hysteria2"} {
		sv := &store.Server{Name: pr, Protocol: pr, Enabled: true, Settings: store.M{}}
		if pr == "hysteria2" {
			sv.Settings["hop_ports"] = "20000-40000"
		}
		if err := e.InitServer(sv); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SaveServer(sv)
		p := &store.Peer{UserID: u.ID, ServerID: sv.ID, Name: "Handy", Kind: "client", Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(sv, p); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SavePeer(p)
		ids[pr] = p.ID
	}
	hd, _ := e.SubLinksFor(u.ID, "singbox")
	other, _ := e.SubLinks(u.ID)
	if len(hd) != 1 || !strings.Contains(hd[0], ":443,20000-40000/?") || strings.Contains(hd[0], "mport") {
		t.Errorf("Hiddify-Link falsch: %v", hd)
	}
	if len(other) != 1 || !strings.Contains(other[0], ":443/?") || !strings.Contains(other[0], "mport=20000-40000") {
		t.Errorf("Standard-Link falsch: %v", other)
	}
	cc, _ := e.ClientConfig(ids["wireguard"])
	if len(cc.Links) != 1 {
		t.Fatalf("WireGuard-Link fehlt")
	}
	l, err := url.Parse(cc.Links[0].URL)
	if err != nil || l.Scheme != "wireguard" || l.Port() != "51820" {
		t.Fatalf("WireGuard-Link ungültig: %v %v", cc.Links[0].URL, err)
	}
	pb := e.mustPeer(t, ids["wireguard"])
	if l.User.Username() != proto.Str(pb.Secrets, "private_key") || l.Query().Get("presharedkey") != proto.Str(pb.Secrets, "psk") ||
		!strings.Contains(l.Query().Get("address"), "/32") || l.Query().Get("publickey") == "" || l.Query().Get("mtu") != "1280" {
		t.Errorf("WireGuard-Link-Inhalt falsch: %s", cc.Links[0].URL)
	}
	if strings.ContainsAny(l.Fragment, "\r\n") {
		t.Errorf("Zeilenumbruch im Namen")
	}
}

func (e *Engine) mustPeer(t *testing.T, id int64) *store.Peer {
	t.Helper()
	p, err := e.St.Peer(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
