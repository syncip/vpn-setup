//go:build lab

// Labortest (als root) für die Portprüfung: Zähler der Prüftabelle hinter einer echten
// Portweiterleitung (DNAT) – „Ausgang“ → „Host“ (DNAT) → „Container“ in Netzwerk-Namespaces.
//
//	GOOS=linux go test -c -tags lab -o enginelab ./internal/engine && sudo ./enginelab -test.run PortCheckLab -test.v
package engine

import (
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
)

func TestPortCheckLab(t *testing.T) {
	cmd := func(a []string) *exec.Cmd { return exec.Command(a[0], a[1:]...) }
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	const srv, gw, ext = "pcsrv", "pcgw", "pcext"
	for _, ns := range []string{srv, gw, ext} {
		ubQuiet("ip", "netns", "del", ns)
	}
	t.Cleanup(func() {
		for _, ns := range []string{srv, gw, ext} {
			ubQuiet("ip", "netns", "del", ns)
		}
	})
	in := func(ns string, args ...string) []string { return append([]string{"ip", "netns", "exec", ns}, args...) }
	for _, ns := range []string{srv, gw, ext} {
		ubSh(t, "ip", "netns", "add", ns)
		ubSh(t, in(ns, "ip", "link", "set", "lo", "up")...)
	}
	// Container (10.66.0.3) ↔ Host (10.66.0.1 | 198.51.100.10) ↔ Ausgang (198.51.100.20 = Absender)
	ubSh(t, in(srv, "ip", "link", "add", "eth0", "type", "veth", "peer", "name", "vmbr1")...)
	ubSh(t, in(srv, "ip", "link", "set", "vmbr1", "netns", gw)...)
	ubSh(t, in(gw, "ip", "link", "add", "vmbr0", "type", "veth", "peer", "name", "inet0")...)
	ubSh(t, in(gw, "ip", "link", "set", "inet0", "netns", ext)...)
	for _, c := range [][]string{
		in(srv, "ip", "addr", "add", "10.66.0.3/24", "dev", "eth0"), in(srv, "ip", "link", "set", "eth0", "up"),
		in(srv, "ip", "route", "add", "default", "via", "10.66.0.1"),
		in(gw, "ip", "addr", "add", "10.66.0.1/24", "dev", "vmbr1"), in(gw, "ip", "link", "set", "vmbr1", "up"),
		in(gw, "ip", "addr", "add", "198.51.100.10/24", "dev", "vmbr0"), in(gw, "ip", "link", "set", "vmbr0", "up"),
		in(gw, "sysctl", "-qw", "net.ipv4.ip_forward=1"),
		in(ext, "ip", "addr", "add", "198.51.100.20/24", "dev", "inet0"), in(ext, "ip", "link", "set", "inet0", "up"),
	} {
		ubSh(t, c...)
	}
	// Weiterleitungen wie in /etc/network/interfaces – TCP 8080 absichtlich nicht
	dnat := "table ip nat {\n chain pre {\n  type nat hook prerouting priority dstnat;\n" +
		"  iif vmbr0 udp dport 51820 dnat to 10.66.0.3\n  iif vmbr0 tcp dport { 443, 1080 } dnat to 10.66.0.3\n }\n}\n"
	c := cmd(in(gw, "nft", "-f", "-"))
	c.Stdin = strings.NewReader(dnat)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("DNAT: %v %s", err, out)
	}

	ports := []HostPort{
		{Server: "wg", Port: proto.Port{Port: 51820, Proto: "udp"}},
		{Server: "vless", Port: proto.Port{Port: 443, Proto: "tcp"}},
		{Server: "proxy", Port: proto.Port{Port: 1080, Proto: "tcp"}}, // weitergeleitet, aber kein Dienst
		{Server: "proxy", Port: proto.Port{Port: 8080, Proto: "tcp"}}, // nicht weitergeleitet
	}
	c = cmd(in(srv, "nft", "-f", "-"))
	c.Stdin = strings.NewReader(pcScript(ports, netip.MustParseAddr("198.51.100.20")))
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("Prüftabelle: %v %s\n%s", err, out, pcScript(ports, netip.MustParseAddr("198.51.100.20")))
	}
	// zweimal laden geht (Tabelle wird ersetzt)
	c = cmd(in(srv, "nft", "-f", "-"))
	c.Stdin = strings.NewReader(pcScript(ports, netip.MustParseAddr("198.51.100.20")))
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("Prüftabelle erneut: %v %s", err, out)
	}

	// Dienst auf 443 im Container
	l := cmd(in(srv, "python3", "-c",
		"import socket\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind(('0.0.0.0',443))\ns.listen(5)\nwhile True:\n  c,a=s.accept()\n  c.close()\n"))
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Process.Kill(); _, _ = l.Process.Wait() })
	tcp := func(port string) bool {
		return cmd(in(ext, "timeout", "3", "bash", "-c", "exec 3<>/dev/tcp/198.51.100.10/"+port)).Run() == nil
	}
	ok443 := false
	for i := 0; i < 20 && !ok443; i++ {
		ok443 = tcp("443")
	}
	if !ok443 {
		t.Error("TCP 443 nicht angenommen")
	}
	if tcp("1080") {
		t.Error("TCP 1080 ohne Dienst angenommen")
	}
	_ = tcp("8080")
	// UDP: ein Prüfpaket von einer ANDEREN Adresse als der des Ausgangs (wie bei Cloudflare WARP), dazu
	// fremde Pakete – richtige Länge ohne Kennung, Kennung mit falscher Länge. Nur das Prüfpaket zählt.
	ubSh(t, in(ext, "ip", "addr", "add", "198.51.100.21/24", "dev", "inet0")...)
	py := `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('198.51.100.21',0))
n=int(sys.argv[1])
for d in [b'vpnpanel-portcheck p0'.ljust(n,b'\0'), bytes(n), b'vpnpanel'.ljust(100,b'\0')]:
  s.sendto(d,('198.51.100.10',51820))
`
	ubSh(t, in(ext, "python3", "-c", py, strconv.Itoa(pcUDPLen))...)

	out := ubSh(t, in(srv, "nft", "-j", "list", "table", "inet", pcTable)...)
	n := parsePCCounters(out)
	t.Logf("Zähler: %v", n)
	if n["p0"] != 1 {
		t.Errorf("UDP 51820: %d Pakete, erwartet 1 (nur das Prüfpaket)", n["p0"])
	}
	if n["p1"] < 1 {
		t.Error("TCP 443: kein SYN gezählt")
	}
	if n["p2"] < 1 {
		t.Error("TCP 1080: weitergeleitet, aber kein SYN gezählt")
	}
	if n["p3"] != 0 {
		t.Errorf("TCP 8080: %d Pakete, obwohl nicht weitergeleitet", n["p3"])
	}
}
