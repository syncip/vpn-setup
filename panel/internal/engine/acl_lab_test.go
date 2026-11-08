//go:build lab

// Labortest für die IP-Listen auf echtem Linux (als root, z. B. in WSL): iptables/ip6tables-Ketten
// VPNACL, Sperre neuer und bestehender Verbindungen (conntrack), Freigabelisten, Abbau.
//
//	GOOS=linux go test -c -tags lab -o acllab ./internal/engine && sudo ./acllab -test.v -test.run TestACLLab
package engine

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/proxy"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

const (
	aclPort = "41080"
	aclSrv4 = "10.97.0.1"
	aclCli4 = "10.97.0.2"
	aclSrv6 = "fd97::1"
	aclCli6 = "fd97::2"
)

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestACLLab(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e := New(st, system.Real{}, Config{PanelBackend: "127.0.0.1:8480", DataDir: dir})

	srv := &store.Server{ID: 77, Name: "acl", Protocol: "proxy", Enabled: true,
		Settings: store.M{"socks": true, "socks_port": float64(41080), "http": false}}
	snap := &Snapshot{Servers: []*proto.ServerBundle{{Server: srv}}}

	var cleanupProcs []*exec.Cmd
	cleanup := func() {
		_ = e.applyACL(snap, nil)
		for _, p := range cleanupProcs {
			_ = p.Process.Kill()
			_, _ = p.Process.Wait()
		}
		_ = exec.Command("ip", "link", "del", "va0").Run()
		_ = exec.Command("ip", "netns", "del", "aclns").Run()
	}
	cleanup()
	t.Cleanup(func() {
		cleanup()
		for _, c := range []string{"iptables", "ip6tables"} {
			if out, _ := exec.Command(c, "-S").Output(); strings.Contains(string(out), "VPNACL") {
				t.Errorf("%s: Ketten nicht abgebaut:\n%s", c, out)
			}
		}
	})

	run(t, "ip", "netns", "add", "aclns")
	run(t, "ip", "link", "add", "va0", "type", "veth", "peer", "name", "vb0")
	run(t, "ip", "link", "set", "vb0", "netns", "aclns")
	run(t, "ip", "addr", "add", aclSrv4+"/24", "dev", "va0")
	run(t, "ip", "addr", "add", aclSrv6+"/64", "dev", "va0", "nodad")
	run(t, "ip", "link", "set", "va0", "up")
	run(t, "ip", "netns", "exec", "aclns", "ip", "addr", "add", aclCli4+"/24", "dev", "vb0")
	run(t, "ip", "netns", "exec", "aclns", "ip", "addr", "add", aclCli6+"/64", "dev", "vb0", "nodad")
	run(t, "ip", "netns", "exec", "aclns", "ip", "link", "set", "vb0", "up")
	run(t, "ip", "netns", "exec", "aclns", "ip", "link", "set", "lo", "up")

	// Dienst auf dem Port des Servers: zählt empfangene Bytes
	ln, err := net.Listen("tcp", ":"+aclPort)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var got atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 256)
				for {
					n, err := c.Read(b)
					got.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	dial := func(ip string) bool {
		return exec.Command("ip", "netns", "exec", "aclns", "timeout", "3", "bash", "-c", "exec 3<>/dev/tcp/"+ip+"/"+aclPort).Run() == nil
	}
	expect := func(step string, v4, v6 bool) {
		t.Helper()
		if g := dial(aclSrv4); g != v4 {
			t.Errorf("%s: IPv4 verbunden=%v, erwartet %v", step, g, v4)
		}
		if g := dial(aclSrv6); g != v6 {
			t.Errorf("%s: IPv6 verbunden=%v, erwartet %v", step, g, v6)
		}
	}
	apply := func(step string, a *proto.ACL) {
		t.Helper()
		var acls map[int64]*proto.ACL
		if a != nil {
			acls = map[int64]*proto.ACL{srv.ID: a}
		}
		if err := e.applyACL(snap, acls); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	pf := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, x := range s {
			out = append(out, netip.MustParsePrefix(x))
		}
		return out
	}

	expect("ohne Liste", true, true)

	// bestehende Verbindung, die laufend Daten schickt
	stream := exec.Command("ip", "netns", "exec", "aclns", "bash", "-c",
		"exec 3<>/dev/tcp/"+aclSrv4+"/"+aclPort+"; while echo x >&3; do sleep 0.2; done")
	if err := stream.Start(); err != nil {
		t.Fatal(err)
	}
	cleanupProcs = append(cleanupProcs, stream)
	time.Sleep(1500 * time.Millisecond)
	if got.Load() == 0 {
		t.Fatal("Datenstrom kommt nicht an")
	}

	// Sperrliste
	block := &proto.ACL{Deny: pf(aclCli4+"/32", aclCli6+"/128")}
	apply("Sperre", block)
	time.Sleep(time.Second)
	n1 := got.Load()
	time.Sleep(1500 * time.Millisecond)
	if n2 := got.Load(); n2 != n1 {
		t.Errorf("bestehende Verbindung läuft trotz Sperre weiter (%d → %d Bytes)", n1, n2)
	}
	expect("Sperre", false, false)
	for _, c := range []string{"iptables", "ip6tables"} {
		out := run(t, c, "-S")
		for _, w := range []string{"-A INPUT -j VPNACL", "-A VPNACL -p tcp -m tcp --dport " + aclPort + " -j VPNACL-77", "-j DROP"} {
			if !strings.Contains(out, w) {
				t.Errorf("%s: %q fehlt\n%s", c, w, out)
			}
		}
	}
	apply("Sperre erneut (unverändert)", block)
	expect("Sperre erneut", false, false)

	// Freigabeliste ohne den Client → gesperrt; mit dem IPv4-Netz → nur IPv4 frei
	apply("Freigabe fremd", &proto.ACL{AllowOnly: true, Allow: pf("10.97.0.99/32")})
	expect("Freigabe fremd", false, false)
	apply("Freigabe IPv4-Netz", &proto.ACL{AllowOnly: true, Allow: pf("10.97.0.0/24")})
	expect("Freigabe IPv4-Netz", true, false)
	apply("Freigabe beide", &proto.ACL{AllowOnly: true, Allow: pf("10.97.0.0/24", "fd97::/64")})
	expect("Freigabe beide", true, true)
	// Sperre schlägt Freigabe
	apply("Sperre + Freigabe", &proto.ACL{AllowOnly: true, Allow: pf("10.97.0.0/24"), Deny: pf(aclCli4 + "/32")})
	expect("Sperre + Freigabe", false, false)

	// Abbau
	apply("ohne Listen", nil)
	expect("nach Abbau", true, true)
	for _, c := range []string{"iptables", "ip6tables"} {
		if out := run(t, c, "-S"); strings.Contains(out, "VPNACL") {
			t.Errorf("%s: Ketten nach Abbau noch da:\n%s", c, out)
		}
	}
}
