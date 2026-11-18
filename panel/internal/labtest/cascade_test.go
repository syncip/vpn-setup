//go:build lab

package labtest

// Labortest Kaskade: Server → Anbieter A („WARP“, WireGuard) → Anbieter B („Windscribe“, WireGuard)
// → Ziel. Der Endpoint von B wäre auch direkt erreichbar; geprüft wird, dass der Tunnel von B
// trotzdem durch A läuft (B sieht als Absender die Adresse von A), dass das Ziel die Adresse von B
// sieht, dass die MTU angepasst wird und dass ohne A nichts direkt hinausgeht (Kill-Switch).
//
//	GOOS=linux go test -c -tags lab -o labtest ./internal/labtest && sudo ./labtest -test.v -test.run Cascade

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/system"
)

const (
	casA, casB         = 911, 912
	casSlotA, casSlotB = 58, 59
)

func wgKey(t *testing.T) (priv, pub string) {
	t.Helper()
	priv = strings.TrimSpace(sh(t, "wg", "genkey"))
	c := exec.Command("wg", "pubkey")
	c.Stdin = strings.NewReader(priv + "\n")
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	return priv, strings.TrimSpace(string(out))
}

// wgServer: WireGuard-Server in einem Namespace (Einstellungen über stdin wegen AppArmor).
func wgServer(t *testing.T, ns, listen, addr, priv, peerPub, peerIP string) {
	t.Helper()
	sh(t, "ip", "-n", ns, "link", "add", "wg0", "type", "wireguard")
	c := exec.Command("ip", "netns", "exec", ns, "wg", "setconf", "wg0", "/dev/stdin")
	c.Stdin = strings.NewReader(fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", priv, listen, peerPub, peerIP))
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("wg setconf %s: %v %s", ns, err, out)
	}
	sh(t, "ip", "-n", ns, "addr", "add", addr, "dev", "wg0")
	sh(t, "ip", "-n", ns, "link", "set", "wg0", "up")
}

func TestLabCascade(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	state := map[string]string{}
	var smu sync.Mutex
	env := &exits.Env{Sys: system.Real{},
		Get: func(k string) string { smu.Lock(); defer smu.Unlock(); return state[k] },
		Set: func(k, v string) { smu.Lock(); defer smu.Unlock(); state[k] = v },
		Log: func(l, m string) { t.Logf("[%s] %s", l, m) }}
	m := exits.New()
	var helperCmd *exec.Cmd
	cleanup := func() {
		_ = m.Apply(env, nil, nil)
		if helperCmd != nil {
			_ = helperCmd.Process.Kill()
			_, _ = helperCmd.Process.Wait()
		}
		quiet("ip", "route", "del", "10.97.2.0/24")
		quiet("ip", "link", "del", "vca")
		quiet("ip", "netns", "del", "casa")
		quiet("ip", "netns", "del", "casb")
	}
	cleanup()
	t.Cleanup(func() {
		cleanup()
		for _, n := range []string{"ex911", "ex912"} {
			if exec.Command("ip", "link", "show", "dev", n).Run() == nil {
				t.Errorf("%s nicht abgebaut", n)
			}
		}
	})

	// Netz: Server (10.97.1.1) ↔ A (10.97.1.2 | 10.97.2.1) ↔ B (10.97.2.2, Ziel auf lo)
	sh(t, "ip", "netns", "add", "casa")
	sh(t, "ip", "netns", "add", "casb")
	sh(t, "ip", "link", "add", "vca", "type", "veth", "peer", "name", "upl", "netns", "casa")
	sh(t, "ip", "link", "add", "dn", "netns", "casa", "type", "veth", "peer", "name", "upl", "netns", "casb")
	sh(t, "ip", "addr", "add", "10.97.1.1/24", "dev", "vca")
	sh(t, "ip", "link", "set", "vca", "up")
	for _, c := range [][]string{
		{"casa", "addr", "add", "10.97.1.2/24", "dev", "upl"}, {"casa", "link", "set", "upl", "up"}, {"casa", "link", "set", "lo", "up"},
		{"casa", "addr", "add", "10.97.2.1/24", "dev", "dn"}, {"casa", "link", "set", "dn", "up"},
		{"casa", "route", "add", target + "/32", "via", "10.97.2.2"},
		{"casb", "addr", "add", "10.97.2.2/24", "dev", "upl"}, {"casb", "link", "set", "upl", "up"}, {"casb", "link", "set", "lo", "up"},
		{"casb", "addr", "add", target + "/32", "dev", "lo"}, {"casb", "route", "add", "default", "via", "10.97.2.1"},
	} {
		sh(t, append([]string{"ip", "-n", c[0]}, c[1:]...)...)
	}
	sh(t, "ip", "netns", "exec", "casa", "sysctl", "-qw", "net.ipv4.ip_forward=1")
	// A maskiert nur den Verkehr seiner WireGuard-Kunden – direkter Verkehr des Servers käme bei B
	// mit 10.97.1.1 an, Verkehr durch A mit 10.97.2.1.
	sh(t, "ip", "netns", "exec", "casa", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.95.1.0/24", "-o", "dn", "-j", "MASQUERADE")
	// Direkter Weg zu B existiert (darf nie benutzt werden)
	sh(t, "ip", "route", "add", "10.97.2.0/24", "via", "10.97.1.2")
	// Zähler bei B: WireGuard-Pakete, die direkt vom Server kommen
	sh(t, "ip", "netns", "exec", "casb", "iptables", "-A", "INPUT", "-s", "10.97.1.1", "-p", "udp", "--dport", "51820")

	helperCmd = exec.Command("ip", "netns", "exec", "casb", os.Args[0])
	helperCmd.Env = append(os.Environ(), "LAB_HELPER=1")
	if err := helperCmd.Start(); err != nil {
		t.Fatal(err)
	}

	aSrv, aSrvPub := wgKey(t)
	aCli, aCliPub := wgKey(t)
	bSrv, bSrvPub := wgKey(t)
	bCli, bCliPub := wgKey(t)
	wgServer(t, "casa", "51820", "10.95.1.1/24", aSrv, aCliPub, "10.95.1.2")
	wgServer(t, "casb", "51820", "10.95.2.1/24", bSrv, bCliPub, "10.95.2.2")

	parse := func(priv, pub, addr, ep string) *exits.WG {
		w, err := exits.ParseWG(fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s\n", priv, addr, pub, ep))
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	xa := &exits.Exit{ID: casA, Name: "WARP", Enabled: true, Type: "wireguard", Slot: casSlotA, Mode: "always",
		WG: parse(aCli, aSrvPub, "10.95.1.2", "10.97.1.2:51820")}
	xb := &exits.Exit{ID: casB, Name: "Windscribe", Enabled: true, Type: "wireguard", Slot: casSlotB, Mode: "always", Via: casA,
		WG: parse(bCli, bSrvPub, "10.95.2.2", "10.97.2.2:51820")}
	xs := []*exits.Exit{xa, xb}
	if err := m.Apply(env, xs, nil); err != nil {
		t.Fatal(err)
	}
	if out := sh(t, "wg", "show", "ex912", "fwmark"); !strings.Contains(out, fmt.Sprintf("0x%x", exits.ProbeMark(casSlotA))) {
		t.Fatalf("fwmark von ex912: %s", out)
	}
	if out := sh(t, "ip", "link", "show", "dev", "ex912"); !strings.Contains(out, "mtu 1340") {
		t.Fatalf("MTU von ex912:\n%s", out)
	}

	exits.SetProbeTargets(target, "http://"+target+"/cdn-cgi/trace", "http://"+target+"/down")
	waitFor(t, "Prüfung beider Ausgänge", 30*time.Second, func() bool {
		m.Check(env, xs, nil, 0)
		es, _ := m.Status()
		return es[casA].IP != "" && es[casB].IP != ""
	})
	es, _ := m.Status()
	t.Logf("A: ip=%s loss=%.0f rtt=%.1f · B: ip=%s loss=%.0f rtt=%.1f", es[casA].IP, es[casA].Loss, es[casA].RTT, es[casB].IP, es[casB].Loss, es[casB].RTT)
	if es[casA].IP != "10.97.2.1" {
		t.Fatalf("Ziel sieht über A %q, erwartet die Adresse von A (10.97.2.1)", es[casA].IP)
	}
	if es[casB].IP != "10.95.2.2" {
		t.Fatalf("Ziel sieht über B %q, erwartet die Tunneladresse bei B (10.95.2.2)", es[casB].IP)
	}
	// B sieht den Tunnel von der Adresse von A – nicht vom Server
	if out := sh(t, "ip", "netns", "exec", "casb", "wg", "show", "wg0", "endpoints"); !strings.Contains(out, "10.97.2.1:") {
		t.Fatalf("Endpoint bei B: %s (erwartet 10.97.2.1 = über A)", out)
	}
	direct := func() int {
		out := sh(t, "ip", "netns", "exec", "casb", "iptables", "-L", "INPUT", "-v", "-n", "-x")
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "10.97.1.1") {
				n, _ := strconv.Atoi(strings.Fields(l)[0])
				return n
			}
		}
		return -1
	}
	if n := direct(); n != 0 {
		t.Fatalf("%d WireGuard-Pakete gingen direkt vom Server zu B", n)
	}

	// Kill-Switch: A fällt weg → der Tunnel von B darf nicht direkt hinaus
	sh(t, "ip", "link", "del", "dev", "ex911")
	sh(t, "wg", "set", "ex912", "peer", strings.TrimSpace(bSrvPub), "endpoint", "10.97.2.2:51820") // neuen Handshake erzwingen
	mark := strconv.FormatUint(uint64(exits.ProbeMark(casSlotB)), 10)
	_ = exec.Command("ping", "-n", "-q", "-c", "4", "-i", "0.3", "-W", "1", "-m", mark, target).Run()
	time.Sleep(2 * time.Second)
	if n := direct(); n != 0 {
		t.Fatalf("ohne A: %d WireGuard-Pakete gingen direkt zu B (Kill-Switch fehlt)", n)
	}

	// Vorgänger abgeschaltet → B wird getrennt statt direkt verbunden
	xa.Enabled = false
	if err := m.Apply(env, xs, nil); err == nil || !strings.Contains(err.Error(), "Vorgänger") {
		t.Fatalf("Apply ohne Vorgänger: %v", err)
	}
	if exec.Command("ip", "link", "show", "dev", "ex912").Run() == nil {
		t.Fatal("ex912 blieb ohne Vorgänger verbunden")
	}
	if n := direct(); n != 0 {
		t.Fatalf("%d Pakete direkt zu B", n)
	}
}
