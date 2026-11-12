//go:build lab

// Labortest auf echtem Linux (als root, z. B. in WSL) für Unbound je Ausgangsgruppe: Routing-Regel
// (Weg über den Ausgang) und Kill-Switch aus ubNftChains – in eigenen Netzwerk-Namespaces, ohne das
// Netz des Rechners anzufassen. Statt eines Unbound-Benutzers sendet „nobody“.
//
//	GOOS=linux go test -c -tags lab -o enginelab ./internal/engine && sudo ./enginelab -test.run UnboundKillSwitch -test.v
package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	ubLab   = "ublab"  // „Server“ (Container)
	ubProv  = "ubprov" // „Internet“ mit Ausgangs-Anbieter
	ubTable = "3061"
	ubPrio  = "6361"
	ubNoUID = 65534 // nobody
)

// labInst: Instanz in Platz 61 (Tabelle 3061), gesendet wird als „nobody“.
var labInst = ubInstance{GID: 1, Name: "Lab", Slot: 61, UID: ubNoUID}

func ubSh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func ubQuiet(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

func TestUnboundKillSwitch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	cleanup := func() {
		ubQuiet("ip", "netns", "del", ubLab)
		ubQuiet("ip", "netns", "del", ubProv)
	}
	cleanup()
	t.Cleanup(cleanup)
	in := func(ns string, args ...string) []string { return append([]string{"ip", "netns", "exec", ns}, args...) }

	ubSh(t, "ip", "netns", "add", ubLab)
	ubSh(t, "ip", "netns", "add", ubProv)
	// Direktweg (eth0) und Ausgangstunnel (ex7) als zwei Verbindungen zum „Internet“
	ubSh(t, in(ubLab, "ip", "link", "add", "eth0", "type", "veth", "peer", "name", "up0")...)
	ubSh(t, in(ubLab, "ip", "link", "add", "ex7", "type", "veth", "peer", "name", "exp")...)
	ubSh(t, in(ubLab, "ip", "link", "set", "up0", "netns", ubProv)...)
	ubSh(t, in(ubLab, "ip", "link", "set", "exp", "netns", ubProv)...)
	for _, c := range [][]string{
		{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "eth0", "up"}, {"ip", "link", "set", "ex7", "up"},
		{"ip", "addr", "add", "10.98.0.1/24", "dev", "eth0"}, {"ip", "addr", "add", "10.97.0.1/24", "dev", "ex7"},
		{"ip", "-6", "addr", "add", "fd99::1/64", "dev", "eth0", "nodad"},
		{"ip", "route", "add", "default", "via", "10.98.0.2"}, {"ip", "-6", "route", "add", "default", "via", "fd99::2"},
		{"sysctl", "-qw", "net.ipv4.conf.ex7.rp_filter=2"},
		// Gruppe: Tabelle mit Weg über den Ausgang, Regel für den Benutzer der Instanz (wie syncUBRules)
		append([]string{"ip", "-4", "rule", "add", "priority", ubPrio}, strings.Fields(labInst.rule())...),
		{"ip", "route", "add", "default", "via", "10.97.0.2", "dev", "ex7", "table", ubTable},
	} {
		ubSh(t, in(ubLab, c...)...)
	}
	for _, c := range [][]string{
		{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "up0", "up"}, {"ip", "link", "set", "exp", "up"},
		{"ip", "addr", "add", "10.98.0.2/24", "dev", "up0"}, {"ip", "addr", "add", "10.97.0.2/24", "dev", "exp"},
		{"ip", "-6", "addr", "add", "fd99::2/64", "dev", "up0", "nodad"},
		{"ip", "addr", "add", "198.51.100.53/32", "dev", "lo"}, {"ip", "-6", "addr", "add", "2001:db8::53/128", "dev", "lo"},
	} {
		ubSh(t, in(ubProv, c...)...)
	}
	// Firewall wie auf dem Server: Ausgang maskieren, dazu die Ketten für die Instanz
	// Ohne Maskierung: Der Absender muss schon beim Senden die Adresse am Tunnel sein (ein echter
	// Anbieter verwirft fremde Absender) – genau das ging auf sys1 mit der Umleitung per Markierung schief.
	script := "table inet " + nftTable + " {\n" + ubNftChains([]ubInstance{labInst}) + "}\n"
	cmd := exec.Command("ip", "netns", "exec", ubLab, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v\n%s\n%s", err, out, script)
	}

	// Empfänger im „Internet“ und auf Loopback des Servers: schreiben die Absenderadresse in eine Datei
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o777)
	listen := func(ns, bind, file string) {
		py := "import socket,sys\nfam=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET\ns=socket.socket(fam,socket.SOCK_DGRAM)\n" +
			"s.bind((sys.argv[1],5353))\nwhile True:\n  d,a=s.recvfrom(100)\n  open(sys.argv[2],'a').write(a[0]+' '+d.decode()+'\\n')\n"
		c := exec.Command("ip", "netns", "exec", ns, "python3", "-c", py, bind, file)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	}
	inet4, inet6, loop := filepath.Join(dir, "v4"), filepath.Join(dir, "v6"), filepath.Join(dir, "lo")
	listen(ubProv, "198.51.100.53", inet4)
	listen(ubProv, "2001:db8::53", inet6)
	listen(ubLab, "127.0.0.1", loop)
	time.Sleep(500 * time.Millisecond)

	send := func(asNobody bool, host, tag string) {
		args := in(ubLab)
		if asNobody {
			args = append(args, "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups")
		}
		args = append(args, "bash", "-c", "echo "+tag+" > /dev/udp/"+host+"/5353")
		_ = exec.Command(args[0], args[1:]...).Run()
		time.Sleep(300 * time.Millisecond)
	}
	got := func(file, tag string) string {
		b, _ := os.ReadFile(file)
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[1] == tag {
				return f[0]
			}
		}
		return ""
	}

	// 1. Instanz → über den Ausgang (Absender = Adresse am Tunnel), Rest des Servers direkt
	send(true, "198.51.100.53", "inst")
	send(false, "198.51.100.53", "root")
	if src := got(inet4, "inst"); src != "10.97.0.1" {
		out, _ := exec.Command("ip", "netns", "exec", ubLab, "nft", "list", "ruleset").CombinedOutput()
		rt, _ := exec.Command("ip", "netns", "exec", ubLab, "ip", "route", "get", "198.51.100.53", "uid", "65534").CombinedOutput()
		t.Errorf("Instanz nicht über den Ausgang: Absender %q\n%s\n%s", src, out, rt)
	}
	if src := got(inet4, "root"); src != "10.98.0.1" {
		t.Errorf("übriger Verkehr nicht direkt: Absender %q", src)
	}
	// 2. Loopback bleibt erlaubt (Antworten an den Panel-DNS)
	send(true, "127.0.0.1", "lo")
	if got(loop, "lo") == "" {
		t.Error("Loopback für die Instanz gesperrt")
	}
	// 3. IPv6 der Instanz wird verworfen, für den Rest nicht
	send(true, "2001:db8::53", "inst6")
	send(false, "2001:db8::53", "root6")
	if got(inet6, "inst6") != "" {
		t.Error("IPv6 der Instanz ging hinaus")
	}
	if got(inet6, "root6") == "" {
		t.Error("IPv6 des Servers gesperrt")
	}
	// 4. Kill-Switch: Regel der Gruppe fehlt (Routing kaputt) → nichts geht direkt hinaus
	ubSh(t, in(ubLab, "ip", "rule", "del", "priority", ubPrio)...)
	send(true, "198.51.100.53", "norule")
	if src := got(inet4, "norule"); src != "" {
		t.Errorf("Kill-Switch: Instanz ging ohne Gruppenregel hinaus (Absender %s)", src)
	}
	// 5. Ausgang gesperrt (on_fail=block → blackhole) → nichts
	ubSh(t, in(ubLab, append([]string{"ip", "-4", "rule", "add", "priority", ubPrio}, strings.Fields(labInst.rule())...)...)...)
	ubSh(t, in(ubLab, "ip", "route", "replace", "blackhole", "default", "table", ubTable)...)
	send(true, "198.51.100.53", "blocked")
	if src := got(inet4, "blocked"); src != "" {
		t.Errorf("gesperrter Ausgang: Instanz ging trotzdem hinaus (Absender %s)", src)
	}
	// 6. Ausgang wieder da → wieder über den Ausgang
	ubSh(t, in(ubLab, "ip", "route", "replace", "default", "via", "10.97.0.2", "dev", "ex7", "table", ubTable)...)
	send(true, "198.51.100.53", "back")
	if src := got(inet4, "back"); src != "10.97.0.1" {
		t.Errorf("nach dem Ausfall nicht wieder über den Ausgang: %q", src)
	}
}
