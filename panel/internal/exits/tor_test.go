package exits

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnpanel/internal/system"
)

func TestTorCfg(t *testing.T) {
	c := TorFrom(map[string]any{"exit_countries": []any{"de", "ch"}, "strict": true, "circuit_min": 5.0, "isolate": true},
		"Bridge obfs4 192.0.2.1:443 AAAA cert=abc iat-mode=0\n# Kommentar\n\n198.51.100.2:9001 FFFF\r\n")
	if len(c.Bridges) != 2 || c.Bridges[0] != "obfs4 192.0.2.1:443 AAAA cert=abc iat-mode=0" || c.CircuitMin != 5 || !c.Isolate {
		t.Fatalf("TorFrom: %+v", c)
	}
	if msg := c.Check(); msg != "" {
		t.Fatal(msg)
	}
	if got := NormCountries([]string{"DE, ch", "{at} de"}); strings.Join(got, ",") != "at,ch,de" {
		t.Fatalf("NormCountries: %v", got)
	}
	for _, bad := range []*TorCfg{
		{ExitCountries: []string{"deu"}, CircuitMin: 10},
		{ExitCountries: []string{"de"}, ExcludeCountries: []string{"de"}, CircuitMin: 10},
		{CircuitMin: 0},
		{CircuitMin: 10, Bridges: []string{"obfs4 1.2.3.4:1 x\nUseBridges 0"}},
		{CircuitMin: 10, Bridges: []string{"evil 1.2.3.4:1 x"}},
		{CircuitMin: 10, Bridges: []string{"1.2.3.4:1 x;rm"}},
	} {
		if bad.Check() == "" {
			t.Errorf("durchgelassen: %+v", bad)
		}
	}
	if TorFrom(nil, "").CircuitMin != 10 {
		t.Fatal("Vorgabe Identität")
	}
}

func torExit(id int64) *Exit {
	return &Exit{ID: id, Name: "Tor " + string(rune('A'+id)), Enabled: true, Type: "tor", Slot: int(id), Mode: "always",
		Tor: &TorCfg{ExitCountries: []string{"de"}, Strict: true, CircuitMin: 10, Isolate: true, Bridges: []string{"obfs4 192.0.2.1:443 FP cert=x"}}}
}

func TestTorrc(t *testing.T) {
	e := torExit(5)
	s := torrc(e, map[string]string{"obfs4": "/usr/bin/lyrebird"})
	for _, want := range []string{
		"SocksPort 127.0.0.1:19105 IsolateDestAddr\n", "DNSPort 127.0.0.1:19205\n", "ControlPort 127.0.0.1:19305\n",
		"DataDirectory /var/lib/vpn-tor/ex5\n", "ExitNodes {de}\n", "StrictNodes 1\n", "MaxCircuitDirtiness 600\n",
		"ClientUseIPv6 0\n", "UseBridges 1\n", "ClientTransportPlugin obfs4 exec /usr/bin/lyrebird\n",
		"Bridge obfs4 192.0.2.1:443 FP cert=x\n", "WarnUnsafeSocks 0\n",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("fehlt %q:\n%s", want, s)
		}
	}
	// keine Ports nach außen
	for _, l := range strings.Split(s, "\n") {
		if k := strings.Fields(l + " x")[0]; (k == "SocksPort" || k == "DNSPort" || k == "ControlPort") && !strings.Contains(l, " 127.0.0.1:") {
			t.Fatalf("Port nicht auf 127.0.0.1: %s", l)
		}
	}
}

func TestTorApplyDry(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	wg := cascadeWG(t, 1, 1420)
	tor := torExit(6)
	tor.Via = 1
	if err := m.Apply(env, []*Exit{wg, tor}, nil); err != nil {
		t.Fatal(err)
	}
	dry := env.Sys.(*system.Dry)
	log := strings.Join(dry.Log(), "\n")
	for _, want := range []string{
		"ip tuntap add dev ex6 mode tun user vpntor-ex6",
		"ip -4 rule add priority 6706 uidrange 65006-65006 blackhole",
		"ip -6 rule add priority 6706 uidrange 65006-65006 blackhole",
		"ip -4 rule add priority 6606 uidrange 65006-65006 lookup 2001",
		"systemctl restart vpn-tor@ex6",
		"systemctl restart vpn-t2s@ex6",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("fehlt %q:\n%s", want, log)
		}
	}
	// Sperre vor dem Weg, beides vor dem Start
	if i, j, k := strings.Index(log, "priority 6706"), strings.Index(log, "priority 6606"), strings.Index(log, "restart vpn-tor@ex6"); !(i < j && j < k) {
		t.Fatalf("Reihenfolge Sperre/Weg/Start falsch:\n%s", log)
	}
	root := dry.Root
	if b, err := os.ReadFile(filepath.Join(root, torDir, "ex6.via")); err != nil || strings.TrimSpace(string(b)) != "1" {
		t.Fatalf(".via: %q %v", b, err)
	}
	unit, _ := os.ReadFile(filepath.Join(root, torUnitPath))
	if !strings.Contains(string(unit), "uidrange $$u-$$u blackhole") || !strings.Contains(string(unit), "User=vpntor-%i") {
		t.Fatalf("Unit:\n%s", unit)
	}
	// zweites Apply ohne Änderung: kein Neustart
	n := len(dry.Log())
	if err := m.Apply(env, []*Exit{wg, tor}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(dry.Log()[n:], "\n"), "restart vpn-tor@ex6") {
		t.Fatal("Neustart ohne Änderung")
	}
	// Tor-Ausgang entfernt → Dienste, Dateien und Regeln weg
	n = len(dry.Log())
	if err := m.Apply(env, []*Exit{wg}, nil); err != nil {
		t.Fatal(err)
	}
	tail := strings.Join(dry.Log()[n:], "\n")
	for _, want := range []string{"systemctl stop vpn-t2s@ex6 vpn-tor@ex6", "ip link del dev ex6"} {
		if !strings.Contains(tail, want) {
			t.Fatalf("fehlt %q:\n%s", want, tail)
		}
	}
	if _, err := os.Stat(filepath.Join(root, torDir, "ex6.torrc")); err == nil {
		t.Fatal("torrc nicht gelöscht")
	}
}

func TestTorHealthIgnoresRTT(t *testing.T) {
	m := New()
	e := torExit(3)
	g := &Group{MaxLoss: 20, MaxRTT: 400}
	m.status[3] = &ExitStatus{ID: 3, Up: true, RTT: 1500, Samples: []Sample{{OK: true, RTT: 1500}, {OK: true, RTT: 1600}}}
	if ok, why := m.isHealthy(g, e); !ok {
		t.Fatalf("Tor wegen Antwortzeit gestört: %s", why)
	}
	e.Type = "wireguard"
	if ok, _ := m.isHealthy(g, e); ok {
		t.Fatal("WireGuard mit 1500 ms gilt als gesund")
	}
}

func TestTorUnitPaths(t *testing.T) {
	for _, u := range []string{torUnitFile, t2sUnitFile} {
		if strings.Contains(u, "/etc/vpn/") {
			t.Fatalf("Unit liest aus /etc/vpn (0700, für die Tor-Benutzer unlesbar):\n%s", u)
		}
		if !strings.Contains(u, torDir+"/%i.") {
			t.Fatalf("Unit ohne %s:\n%s", torDir, u)
		}
	}
	if !strings.Contains(torUnitFile, "ExecStartPre=+/bin/sh") {
		t.Fatal("Sperrprüfung der Kaskade läuft nicht als root")
	}
	if strings.Contains(t2sUnitFile, "PrivateDevices") {
		t.Fatal("PrivateDevices verbirgt /dev/net/tun")
	}
}

func TestTorLastMsg(t *testing.T) {
	j := "Nov 18 10:00:00.000 [notice] Bootstrapped 10% (conn_done): Connected to a relay\n" +
		"Nov 18 10:00:05.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors\n" +
		"Nov 18 10:00:06.000 [warn] Problem bootstrapping.\n"
	if got := lastMsg(j, "Bootstrapped "); got != ": Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors" {
		t.Fatalf("Bootstrap: %q", got)
	}
	if got := lastMsg(j, ""); got != ": Problem bootstrapping." {
		t.Fatalf("letzte Zeile: %q", got)
	}
	if got := lastMsg("", ""); got != "" {
		t.Fatalf("leer: %q", got)
	}
}

func TestTorControlCountry(t *testing.T) {
	env, _, _ := testEnv(t)
	e := torExit(97)
	dry := env.Sys.(*system.Dry)
	dir := filepath.Join(dry.Root, torStateDir, "ex97")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "control_auth_cookie"), []byte{1, 2, 0xab}, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", torCtlBase+e.Slot))
	if err != nil {
		t.Skip("Port belegt:", err)
	}
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimSpace(l)
			got <- l
			switch {
			case l == "AUTHENTICATE 0102ab":
				fmt.Fprint(c, "250 OK\r\n")
			case l == "GETINFO ip-to-country/192.0.2.9":
				fmt.Fprint(c, "250-ip-to-country/192.0.2.9=ch\r\n250 OK\r\n")
			case l == "QUIT":
				fmt.Fprint(c, "250 closing connection\r\n")
				return
			default:
				fmt.Fprint(c, "515 Authentication failed\r\n")
			}
		}
	}()
	if cc := torCountry(env, e, "192.0.2.9"); cc != "CH" {
		t.Fatalf("Land %q", cc)
	}
	if l := <-got; l != "AUTHENTICATE 0102ab" {
		t.Fatalf("Anmeldung %q", l)
	}
	if torCountry(env, e, "kein; GETINFO x") != "" {
		t.Fatal("ungültige Adresse an Tor geschickt")
	}
}
