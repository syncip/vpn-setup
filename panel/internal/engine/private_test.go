package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// TestPrivateGuard: private Ziele (internes Netz, Loopback, Server selbst) sind für alle Protokolle
// gesperrt, Ausnahmen und Freigaben gehen vor; abgeschaltet verschwinden die Regeln.
func TestPrivateGuard(t *testing.T) {
	e, dry := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"
	_ = e.St.SetSetting("server_host", "203.0.113.7")
	_ = e.St.SetSetting("private_allow", "192.168.77.0/24")
	mk := func(name, protocol string, set store.M) *store.Server {
		s := &store.Server{Name: name, Protocol: protocol, Enabled: true, Settings: set, State: store.M{}}
		if err := e.InitServer(s); err != nil {
			t.Fatal(err)
		}
		if err := e.St.SaveServer(s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	wg := mk("WG", "wireguard", store.M{})
	wgB := mk("Netz B", "wireguard", store.M{"port": float64(51821), "net4": "10.9.0.0/24", "net6": "fd42:42:43::/64"})
	vl := mk("VLESS", "vless", store.M{})
	hy := mk("Hy", "hysteria2", store.M{})
	u := &store.User{Name: "anna", Enabled: true, SubToken: proto.RandHex(16)}
	_ = e.St.SaveUser(u)
	for _, s := range []*store.Server{wg, vl, hy} {
		p := &store.Peer{UserID: u.ID, ServerID: s.ID, Name: "x", Kind: "client", Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(s, p); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SavePeer(p)
	}
	grant := &store.Object{Kind: "netaccess", Name: "Anna → B", Enabled: true, Data: store.M{"servers": []int64{wgB.ID}, "users": []int64{u.ID}}}
	_ = e.St.SaveObject(grant)

	apply := func() (fw, xray, hyCfg string) {
		dry.Stdin = nil
		if err := e.Apply(); err != nil {
			t.Fatal(err)
		}
		x, _ := os.ReadFile(filepath.Join(dry.Root, "usr/local/etc/xray/config.json"))
		h, _ := os.ReadFile(filepath.Join(dry.Root, "etc/hysteria", "hy"+itoa(hy.ID)+".yaml"))
		return strings.Join(dry.Stdin, "\n"), string(x), string(h)
	}
	fw, xray, hyCfg := apply()
	ifA := proto.Str(wg.Settings, "interface")
	for _, want := range []string{
		"-A VPNWG-FWD -i " + ifA + " -o eth0 -d 192.168.77.0/24 -j ACCEPT",
		"-A VPNWG-FWD -i " + ifA + " -o eth0 -d 10.0.0.0/8 -j DROP",
		"-A VPNWG-FWD -i " + ifA + " -o eth0 -d 203.0.113.7/32 -j DROP",
		"-A VPNWG-FWD -i " + ifA + " -o eth0 -d fc00::/7 -j DROP",
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("Firewall ohne: %s", want)
		}
	}
	// DROP steht vor dem Internet-Zugang
	if i, j := strings.Index(fw, "-d 10.0.0.0/8 -j DROP"), strings.Index(fw, "-o eth0 -s "); i < 0 || j < 0 || i > j {
		t.Errorf("Sperre steht nicht vor dem Internet-Zugang")
	}
	for _, want := range []string{`"127.0.0.0/8"`, `"10.0.0.0/8"`, `"203.0.113.7/32"`, `"outboundTag": "block"`, `"10.9.0.0/24"`, `"domainStrategy"`} {
		if !strings.Contains(xray, want) {
			t.Errorf("Xray-Konfiguration ohne %s", want)
		}
	}
	// Freigabe (direct) steht vor der Sperre
	if i, j := strings.Index(xray, `"10.9.0.0/24"`), strings.Index(xray, `"10.0.0.0/8"`); i > j {
		t.Errorf("Freigabe steht hinter der Sperre")
	}
	// Loopback ist die allererste Regel – vor jeder Freigabe
	if i, j := strings.Index(xray, `"127.0.0.0/8"`), strings.Index(xray, `"10.9.0.0/24"`); i < 0 || i > j {
		t.Errorf("Loopback-Sperre steht nicht vor den Freigaben")
	}
	if i, j := strings.Index(hyCfg, "reject(127.0.0.0/8)"), strings.Index(hyCfg, "direct(192.168.77.0/24)"); i < 0 || i > j {
		t.Errorf("Hysteria: Loopback-Sperre steht nicht vor den Ausnahmen: %s", hyCfg)
	}
	for _, want := range []string{"direct(192.168.77.0/24)", "reject(10.0.0.0/8)", "reject(127.0.0.0/8)", "direct(all)"} {
		if !strings.Contains(hyCfg, want) {
			t.Errorf("Hysteria-ACL ohne %s:\n%s", want, hyCfg)
		}
	}

	_ = e.St.SetSetting("private_block", "0")
	fw, xray, hyCfg = apply()
	if strings.Contains(fw, "-d 10.0.0.0/8 -j DROP") || strings.Contains(xray, `"10.0.0.0/8"`) || strings.Contains(hyCfg, "reject(10.0.0.0/8)") {
		t.Errorf("Sperre trotz Abschalten aktiv")
	}
	// Loopback (Panel, Xray-API, Anmelde-Endpunkt) bleibt auch ohne die Sperre unerreichbar
	if !strings.Contains(xray, `"127.0.0.0/8"`) || !strings.Contains(xray, `"domainStrategy"`) || !strings.Contains(hyCfg, "reject(127.0.0.0/8)") {
		t.Errorf("Loopback ohne die Sperre erreichbar: %s", hyCfg)
	}
	for _, bad := range []string{"127.0.0.1", "127.0.0.0/8", "0.0.0.0/1", "::1", "::ffff:127.0.0.1"} {
		if _, err := ParsePrivateAllow(bad); err == nil {
			t.Errorf("Ausnahme %s angenommen", bad)
		}
	}
	if _, err := ParsePrivateAllow("192.168.77.0/24, 10.1.2.3"); err != nil {
		t.Errorf("gültige Ausnahme abgelehnt: %v", err)
	}
}
