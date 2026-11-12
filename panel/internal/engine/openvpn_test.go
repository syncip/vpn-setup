package engine

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/openvpn"
	"vpnpanel/internal/store"
)

func pemBlock(t *testing.T, s, tag string) *x509.Certificate {
	t.Helper()
	m := regexp.MustCompile(`(?s)<` + tag + `>\n(.*?)</` + tag + `>`).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("<%s> fehlt", tag)
	}
	b, _ := pem.Decode([]byte(m[1]))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// OpenVPN: Konflikte, Konfiguration, ccd nur für aktive Zugänge, Profil mit gültiger Kette.
func TestOpenVPN(t *testing.T) {
	e, dry := newTest(t)
	wg := &store.Server{Name: "WG", Protocol: "wireguard", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(wg); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(wg)

	for _, s := range []store.M{
		{"port": float64(51820)},                   // UDP-Port von WireGuard
		{"port": float64(443), "transport": "tcp"}, // nginx
		{"net4": proto.Str(wg.Settings, "net4")},   // Tunnelnetz von WireGuard
		{"net4": "10.66.0.0/8"},                    // zu groß
		{"dns": "1.1.1.1; rm -rf /"},               // keine IP
		{"host": "evil\nup /bin/sh"},               // Zeilenumbruch
		{"mtu": float64(9000)},
	} {
		bad := &store.Server{Name: "x", Protocol: "openvpn", Enabled: true, Settings: s}
		if err := e.InitServer(bad); err == nil {
			t.Errorf("ungültige Einstellung %v angenommen", s)
		}
	}
	// TCP 1194 neben UDP 1194 ist erlaubt
	ov := &store.Server{Name: "OVPN \"Test\"\nverb 9", Protocol: "openvpn", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(ov); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(ov)
	if proto.Str(ov.Settings, "net4") != "10.66.0.0/24" || proto.Str(ov.Settings, "net6") != "fd66:66:66::/64" {
		t.Errorf("Vorgaben: %v", ov.Settings)
	}
	ov2 := &store.Server{Name: "TCP", Protocol: "openvpn", Enabled: true, Settings: store.M{"transport": "tcp", "net4": "10.66.0.0/24", "net6": "fd66:66:66::/64"}}
	if err := e.InitServer(ov2); err != nil {
		t.Fatal(err)
	}
	if proto.Str(ov2.Settings, "net4") != "10.67.0.0/24" || proto.Str(ov2.Settings, "net6") != "fd66:66:67::/64" {
		t.Errorf("zweiter Server mit Vorgabe-Netz: %v", ov2.Settings)
	}
	_ = e.St.SaveServer(ov2)

	free := &store.User{Name: "frei", Enabled: true, SubToken: proto.RandHex(16)}
	off := &store.User{Name: "aus", Enabled: false, SubToken: proto.RandHex(16)}
	var peers []*store.Peer
	for _, u := range []*store.User{free, off} {
		_ = e.St.SaveUser(u)
		p := &store.Peer{UserID: u.ID, ServerID: ov.ID, Name: u.Name, Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(ov, p); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SavePeer(p)
		peers = append(peers, p)
	}
	if a := proto.Str(peers[0].Settings, "address4"); a != "10.66.0.2" {
		t.Errorf("erste Adresse %s", a)
	}
	if a := proto.Str(peers[1].Settings, "address6"); a != "fd66:66:66::3" {
		t.Errorf("IPv6 %s", a)
	}
	if err := e.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	n := "ovpn" + itoa(ov.ID)
	conf, err := os.ReadFile(filepath.Join(dry.Root, "etc/openvpn/vpn", n+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	c := string(conf)
	for _, want := range []string{"proto udp6\n", "dev " + n + "\n", "server 10.66.0.0 255.255.255.0\n", "server-ipv6 fd66:66:66::/64\n",
		"ccd-exclusive\n", "remote-cert-tls client\n", "management /run/vpn-openvpn/" + n + "/mgmt.sock unix\n",
		"push \"redirect-gateway def1 ipv6 bypass-dhcp\"\n", "push \"dhcp-option DNS 10.66.0.1\"\n", "push \"dhcp-option DNS6 fd66:66:66::1\"\n", "<tls-crypt>\n", "user nobody\n"} {
		if !strings.Contains(c, want) {
			t.Errorf("Konfiguration ohne %q", want)
		}
	}
	if strings.Contains(c, "\nverb 9") || strings.Contains(c, "client-to-client") {
		t.Errorf("Name bricht aus dem Kommentar aus / client-to-client")
	}
	ccd := filepath.Join(dry.Root, "etc/openvpn/vpn", n+"-ccd")
	cn0, cn1 := proto.Str(peers[0].Secrets, "cn"), proto.Str(peers[1].Secrets, "cn")
	if b, err := os.ReadFile(filepath.Join(ccd, cn0)); err != nil || !strings.Contains(string(b), "ifconfig-push 10.66.0.2 255.255.255.0") ||
		!strings.Contains(string(b), "ifconfig-ipv6-push fd66:66:66::2/64 fd66:66:66::1") {
		t.Errorf("ccd aktiver Zugang: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(ccd, cn1)); err == nil {
		t.Errorf("deaktivierter Nutzer hat einen ccd-Eintrag")
	}
	log := strings.Join(dry.Log(), "\n") + strings.Join(dry.Stdin, "\n")
	for _, want := range []string{"systemctl restart vpn-openvpn@" + n, "-A VPNOV-FWD -i " + n + " -o eth0 -s 10.66.0.0/24 -j ACCEPT", "-A VPNOV-FWD -i " + n + " -j DROP", "-A VPNOV-NAT -s fd66:66:66::/64 -o eth0 -j MASQUERADE"} {
		if !strings.Contains(log, want) {
			t.Errorf("Befehl fehlt: %s", want)
		}
	}

	// Profil: Kette gültig, EKU passend, Server-Name geprüft
	name, prof, err := e.OpenVPNProfile(free.ID, peers[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, ".ovpn") || strings.ContainsAny(name, "\"\n/ ") {
		t.Errorf("Dateiname %q", name)
	}
	ca, cert := pemBlock(t, prof, "ca"), pemBlock(t, prof, "cert")
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("Client-Zertifikat: %v", err)
	}
	srvCert := pemBlock(t, c, "cert")
	if _, err := srvCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("Server-Zertifikat: %v", err)
	}
	if !strings.Contains(prof, "verify-x509-name "+srvCert.Subject.CommonName+" name\n") || !strings.Contains(prof, "remote sys1.1337733.xyz 1194\n") {
		t.Errorf("Profil ohne Servernamen/Adresse:\n%s", prof)
	}
	if _, _, err := e.OpenVPNProfile(off.ID, peers[1].ID); err == nil {
		t.Errorf("Profil eines deaktivierten Zugangs ausgeliefert")
	}
	if _, _, err := e.OpenVPNProfile(off.ID, peers[0].ID); err == nil {
		t.Errorf("Profil eines fremden Zugangs ausgeliefert")
	}
	// Nicht im Abo
	if links, _ := e.SubLinks(free.ID); len(links) != 0 {
		t.Errorf("OpenVPN im Abo: %v", links)
	}

	// Sperren → ccd-Eintrag weg
	free.Enabled = false
	_ = e.St.SaveUser(free)
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ccd, cn0)); err == nil {
		t.Errorf("gesperrter Zugang behält ccd-Eintrag")
	}
	// Server löschen → Instanz und Ketten weg
	_ = e.St.DeleteServer(ov.ID)
	_ = e.St.DeleteServer(ov2.ID)
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dry.Root, "etc/openvpn/vpn", n+".conf")); err == nil {
		t.Errorf("Konfiguration gelöschter Instanz bleibt")
	}
	if !strings.Contains(strings.Join(dry.Log(), "\n"), "iptables -X VPNOV-FWD") {
		t.Errorf("Firewall-Ketten nicht entfernt")
	}
}
