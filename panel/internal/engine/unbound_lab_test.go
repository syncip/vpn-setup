//go:build lab

// Labortest auf echtem Linux (als root, z. B. in WSL) für Unbound je Ausgangsgruppe: Weg über den
// Ausgang und Kill-Switch per Routing-Regeln (syncUBRules) – in eigenen Netzwerk-Namespaces, ohne das
// Netz des Rechners anzufassen. Der Ausgang ist ein echter WireGuard-Tunnel: Seine verschlüsselten
// Pakete dürfen nicht vom Kill-Switch getroffen werden (der Fehler auf sys1 mit der Firewall-Regel
// nach Benutzer). Statt eines Unbound-Benutzers sendet „nobody“. Braucht wireguard-tools und python3.
//
//	GOOS=linux go test -c -tags lab -o enginelab ./internal/engine && sudo ./enginelab -test.run UnboundKillSwitch -test.v
package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	ubLab   = "ublab"  // „Server“ (Container)
	ubProv  = "ubprov" // „Internet“ mit Ausgangs-Anbieter
	ubTable = "3061"
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
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wireguard-tools fehlen")
	}
	cleanup := func() {
		ubQuiet("ip", "netns", "del", ubLab)
		ubQuiet("ip", "netns", "del", ubProv)
	}
	cleanup()
	t.Cleanup(cleanup)
	in := func(ns string, args ...string) []string { return append([]string{"ip", "netns", "exec", ns}, args...) }
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o777)

	// Schlüssel für beide Tunnelenden
	key := func(name string) (priv, pub string) {
		priv = filepath.Join(dir, name+".key")
		k := strings.TrimSpace(ubSh(t, "wg", "genkey"))
		if err := os.WriteFile(priv, []byte(k+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c := exec.Command("wg", "pubkey")
		c.Stdin = strings.NewReader(k + "\n")
		out, err := c.Output()
		if err != nil {
			t.Fatal(err)
		}
		return priv, strings.TrimSpace(string(out))
	}
	privA, pubA := key("a")
	privB, pubB := key("b")

	ubSh(t, "ip", "netns", "add", ubLab)
	ubSh(t, "ip", "netns", "add", ubProv)
	// Direktweg: eth0 (Server) ↔ up0 („Internet“); darüber läuft auch der WireGuard-Tunnel
	ubSh(t, in(ubLab, "ip", "link", "add", "eth0", "type", "veth", "peer", "name", "up0")...)
	ubSh(t, in(ubLab, "ip", "link", "set", "up0", "netns", ubProv)...)
	ubSh(t, in(ubLab, "ip", "link", "add", "ex7", "type", "wireguard")...)
	ubSh(t, in(ubProv, "ip", "link", "add", "exp", "type", "wireguard")...)

	block4 := append([]string{"ip", "-4", "rule", "add", "priority", strconv.Itoa(labInst.blockPrio())}, strings.Fields(labInst.block())...)
	block6 := append([]string{"ip", "-6", "rule", "add", "priority", strconv.Itoa(labInst.blockPrio())}, strings.Fields(labInst.block())...)
	way := append([]string{"ip", "-4", "rule", "add", "priority", strconv.Itoa(labInst.prio())}, strings.Fields(labInst.rule())...)
	for _, c := range [][]string{
		{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "eth0", "up"},
		{"ip", "addr", "add", "10.98.0.1/24", "dev", "eth0"},
		{"ip", "-6", "addr", "add", "fd99::1/64", "dev", "eth0", "nodad"},
		{"ip", "route", "add", "default", "via", "10.98.0.2"}, {"ip", "-6", "route", "add", "default", "via", "fd99::2"},
		{"wg", "set", "ex7", "private-key", privA, "listen-port", "51001",
			"peer", pubB, "allowed-ips", "0.0.0.0/0", "endpoint", "10.98.0.2:51002"},
		{"ip", "addr", "add", "10.97.0.1/32", "dev", "ex7"}, {"ip", "link", "set", "ex7", "up"},
		// Gruppe wie syncUBRules: Sperren zuerst, dann der Weg; Tabelle der Gruppe über den Ausgang
		block4, block6, way,
		{"ip", "route", "add", "default", "dev", "ex7", "table", ubTable},
	} {
		ubSh(t, in(ubLab, c...)...)
	}
	for _, c := range [][]string{
		{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "up0", "up"},
		{"ip", "addr", "add", "10.98.0.2/24", "dev", "up0"},
		{"ip", "-6", "addr", "add", "fd99::2/64", "dev", "up0", "nodad"},
		{"wg", "set", "exp", "private-key", privB, "listen-port", "51002", "peer", pubA, "allowed-ips", "10.97.0.1/32"},
		{"ip", "addr", "add", "10.97.0.2/24", "dev", "exp"}, {"ip", "link", "set", "exp", "up"},
		{"ip", "addr", "add", "198.51.100.53/32", "dev", "lo"}, {"ip", "-6", "addr", "add", "2001:db8::53/128", "dev", "lo"},
	} {
		ubSh(t, in(ubProv, c...)...)
	}
	// Keine Maskierung und keine Firewall: Der Absender muss schon beim Senden die Adresse am Tunnel
	// sein (ein echter Anbieter verwirft fremde Absender).

	// Empfänger im „Internet“ und auf Loopback des Servers: schreiben die Absenderadresse in eine Datei
	listen := func(ns, bind, file string) {
		py := "import socket,sys\nfam=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET\ns=socket.socket(fam,socket.SOCK_DGRAM)\n" +
			"s.bind((sys.argv[1],5353))\nwhile True:\n  d,a=s.recvfrom(100)\n  open(sys.argv[2],'a').write(a[0]+' '+d.decode().strip()+'\\n')\n"
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
		time.Sleep(400 * time.Millisecond)
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
	diag := func() string {
		var b strings.Builder
		for _, c := range [][]string{{"ip", "rule", "show"}, {"ip", "-6", "rule", "show"}, {"wg", "show"},
			{"ip", "route", "get", "198.51.100.53", "uid", "65534"}} {
			out, _ := exec.Command("ip", append([]string{"netns", "exec", ubLab}, c...)...).CombinedOutput()
			b.WriteString(strings.Join(c, " ") + ":\n" + string(out))
		}
		return b.String()
	}

	// Handshake anstoßen (wie die erste Anfrage der Instanz)
	send(true, "198.51.100.53", "warm")
	time.Sleep(time.Second)

	// 1. Instanz → durch den Tunnel (Absender = Adresse am Tunnel), Rest des Servers direkt
	send(true, "198.51.100.53", "inst")
	send(false, "198.51.100.53", "root")
	if src := got(inet4, "inst"); src != "10.97.0.1" {
		t.Errorf("Instanz nicht über den Ausgang: Absender %q\n%s", src, diag())
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
	// 4. Kill-Switch: Weg-Regel fehlt → Sperre greift, nichts geht direkt hinaus
	ubSh(t, in(ubLab, "ip", "-4", "rule", "del", "priority", strconv.Itoa(labInst.prio()))...)
	send(true, "198.51.100.53", "norule")
	if src := got(inet4, "norule"); src != "" {
		t.Errorf("Kill-Switch: Instanz ging ohne Weg-Regel hinaus (Absender %s)", src)
	}
	// 5. Tabelle der Gruppe leer (Ausgang weg) → Sperre statt Haupttabelle
	ubSh(t, in(ubLab, way...)...)
	ubSh(t, in(ubLab, "ip", "route", "flush", "table", ubTable)...)
	send(true, "198.51.100.53", "empty")
	if src := got(inet4, "empty"); src != "" {
		t.Errorf("Kill-Switch: Instanz ging bei leerer Tabelle hinaus (Absender %s)", src)
	}
	// 6. Ausgang gesperrt (on_fail=block → blackhole) → nichts
	ubSh(t, in(ubLab, "ip", "route", "replace", "blackhole", "default", "table", ubTable)...)
	send(true, "198.51.100.53", "blocked")
	if src := got(inet4, "blocked"); src != "" {
		t.Errorf("gesperrter Ausgang: Instanz ging trotzdem hinaus (Absender %s)", src)
	}
	// 7. Ausgang wieder da → wieder durch den Tunnel
	ubSh(t, in(ubLab, "ip", "route", "replace", "default", "dev", "ex7", "table", ubTable)...)
	send(true, "198.51.100.53", "back")
	if src := got(inet4, "back"); src != "10.97.0.1" {
		t.Errorf("nach dem Ausfall nicht wieder über den Ausgang: %q\n%s", src, diag())
	}
}
