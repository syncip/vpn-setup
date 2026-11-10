//go:build lab

// Labortest der Firewall des Panels auf echtem Linux (als root, z. B. in WSL): nftables-Tabelle
// „inet vpnpanel“ mit Ziel-Regeln (Markierung je Quelle und Ziel), DNS-Umleitung für Domain-Regeln
// und Sperr-/Freigabelisten. Ein „Gerät“ und ein „Anbieter“ sind eigene Netzwerk-Namespaces.
//
//	GOOS=linux go test -c -tags lab -o nftlab ./internal/engine && sudo ./nftlab -test.v -test.run TestNftLab
package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/proxy"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

const (
	labSrv   = "10.97.0.1" // Server, Seite zum Gerät
	labDev   = "10.97.0.2" // Gerät
	labSrv6  = "fd97::1"
	labDev6  = "fd97::2"
	labOut   = "10.96.0.1" // Server, Seite zum Anbieter (Adresse nach Maskierung)
	labProv  = "10.96.0.2"
	labT1    = "198.51.100.10" // Ziele beim Anbieter
	labT2    = "198.51.100.20"
	labMark  = 0x02000000
	labTable = "3902"
	aclPort  = "41080"
)

func TestMain(m *testing.M) {
	switch os.Getenv("LAB_HELPER") {
	case "serve":
		labServe()
	case "dns":
		labQuery(os.Args[len(os.Args)-2], os.Args[len(os.Args)-1])
	default:
		os.Exit(m.Run())
	}
}

// labServe (im Namespace des Anbieters): Webserver, der die Absenderadresse nennt, und ein
// DNS-Server (Namen mit „netflix.test“ → labT2, alle anderen → labT1).
func labServe() {
	go func() {
		pc, err := net.ListenPacket("udp4", labT1+":53")
		if err != nil {
			return
		}
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				a := netip.MustParseAddr(labT1)
				if strings.HasSuffix(strings.ToLower(q.Name.String()), "netflix.test.") {
					a = netip.MustParseAddr(labT2)
				}
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: a.As4()})
			}
			if q.Type == dnsmessage.TypeAAAA {
				_ = b.AAAAResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()})
			}
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "src=%s", host)
	})
	go func() { _ = http.ListenAndServe(labT2+":80", h) }()
	_ = http.ListenAndServe(labT1+":80", h)
}

// labQuery (im Namespace des Geräts): DNS-Anfrage an server, gibt „A=<Adressen> AAAA=<Anzahl>“ aus.
func labQuery(name, server string) {
	ask := func(t dnsmessage.Type) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 99, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: t, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		c, err := net.DialTimeout("udp", net.JoinHostPort(server, "53"), 3*time.Second)
		if err != nil {
			return nil
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		_, _ = c.Write(q)
		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		if err != nil {
			return nil
		}
		return buf[:n]
	}
	var as []string
	for _, a := range answerAddrs(ask(dnsmessage.TypeA)) {
		as = append(as, a.String())
	}
	n6 := -1
	if r := ask(dnsmessage.TypeAAAA); r != nil {
		var p dnsmessage.Parser
		if _, err := p.Start(r); err == nil {
			_ = p.SkipAllQuestions()
			rs, _ := p.AllAnswers()
			n6 = len(rs)
		}
	}
	fmt.Printf("A=%s AAAA=%d", strings.Join(as, ","), n6)
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

func quiet(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

func TestNftLab(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() }) // zuletzt – der Abbau unten braucht die Datenbank noch
	e := New(st, system.Real{}, Config{PanelBackend: "127.0.0.1:8480", DataDir: dir})
	srv := &store.Server{Name: "acl", Protocol: "proxy", Enabled: true, Settings: store.M{"socks": true, "socks_port": float64(41080), "http": false}, State: store.M{}}
	if err := st.SaveServer(srv); err != nil {
		t.Fatal(err)
	}
	snapshot := func() *Snapshot {
		s, err := e.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	var procs []*exec.Cmd
	fwd, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	cleanup := func() {
		_ = e.applyNftWith(snapshot(), &routing{}, &aclPlan{}, nil)
		quiet("nft", "delete", "table", "inet", nftTable)
		for _, p := range procs {
			_ = p.Process.Kill()
			_, _ = p.Process.Wait()
		}
		procs = nil
		quiet("ip", "rule", "del", "priority", "6902")
		quiet("ip", "route", "flush", "table", labTable)
		quiet("iptables", "-t", "nat", "-D", "POSTROUTING", "-m", "mark", "--mark", "0x02000000/0x7f000000", "-j", "MASQUERADE")
		quiet("ip", "link", "del", "va0")
		quiet("ip", "link", "del", "vp0")
		quiet("ip", "netns", "del", "labdev")
		quiet("ip", "netns", "del", "labprov")
	}
	cleanup()
	t.Cleanup(func() {
		cleanup()
		if len(fwd) > 0 {
			_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", fwd, 0o644)
		}
		if out, _ := exec.Command("nft", "list", "tables").Output(); strings.Contains(string(out), nftTable) {
			t.Errorf("Tabelle nicht abgebaut:\n%s", out)
		}
	})

	// Netz: Gerät ↔ Server ↔ Anbieter
	for _, ns := range []string{"labdev", "labprov"} {
		run(t, "ip", "netns", "add", ns)
		run(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	}
	run(t, "ip", "link", "add", "va0", "type", "veth", "peer", "name", "vb0")
	run(t, "ip", "link", "set", "vb0", "netns", "labdev")
	run(t, "ip", "addr", "add", labSrv+"/24", "dev", "va0")
	run(t, "ip", "addr", "add", labSrv6+"/64", "dev", "va0", "nodad")
	run(t, "ip", "link", "set", "va0", "up")
	run(t, "ip", "netns", "exec", "labdev", "ip", "addr", "add", labDev+"/24", "dev", "vb0")
	run(t, "ip", "netns", "exec", "labdev", "ip", "addr", "add", labDev6+"/64", "dev", "vb0", "nodad")
	run(t, "ip", "netns", "exec", "labdev", "ip", "link", "set", "vb0", "up")
	run(t, "ip", "netns", "exec", "labdev", "ip", "route", "add", "default", "via", labSrv)
	run(t, "ip", "netns", "exec", "labdev", "ip", "-6", "route", "add", "default", "via", labSrv6)
	run(t, "ip", "link", "add", "vp0", "type", "veth", "peer", "name", "vq0")
	run(t, "ip", "link", "set", "vq0", "netns", "labprov")
	run(t, "ip", "addr", "add", labOut+"/24", "dev", "vp0")
	run(t, "ip", "link", "set", "vp0", "up")
	run(t, "ip", "netns", "exec", "labprov", "ip", "addr", "add", labProv+"/24", "dev", "vq0")
	run(t, "ip", "netns", "exec", "labprov", "ip", "link", "set", "vq0", "up")
	run(t, "ip", "netns", "exec", "labprov", "ip", "addr", "add", labT1+"/32", "dev", "lo")
	run(t, "ip", "netns", "exec", "labprov", "ip", "addr", "add", labT2+"/32", "dev", "lo")
	run(t, "ip", "netns", "exec", "labprov", "ip", "route", "add", "10.97.0.0/24", "via", labOut) // Rückweg für den direkten Weg
	run(t, "ip", "route", "add", "198.51.100.0/24", "via", labProv)                               // direkter Weg (Haupttabelle)
	// „Ausgangsgruppe“: Markierung → eigene Tabelle, Verkehr wird maskiert (wie bei echten Ausgängen)
	run(t, "ip", "rule", "add", "priority", "6902", "fwmark", "0x02000000/0x7f000000", "lookup", labTable)
	run(t, "ip", "route", "add", "default", "via", labProv, "table", labTable)
	run(t, "iptables", "-t", "nat", "-A", "POSTROUTING", "-m", "mark", "--mark", "0x02000000/0x7f000000", "-j", "MASQUERADE")
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)

	helper := exec.Command("ip", "netns", "exec", "labprov", os.Args[0])
	helper.Env = append(os.Environ(), "LAB_HELPER=serve")
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	procs = append(procs, helper)

	get := func(ip string) string {
		out, _ := exec.Command("ip", "netns", "exec", "labdev", "timeout", "4", "bash", "-c",
			"exec 3<>/dev/tcp/"+ip+"/80 && printf 'GET / HTTP/1.0\\r\\n\\r\\n' >&3 && cat <&3").Output()
		s := string(out)
		if i := strings.LastIndex(s, "src="); i >= 0 {
			return s[i+4:]
		}
		return "FEHLER"
	}
	dnsVia := func(name, server string) string {
		c := exec.Command("ip", "netns", "exec", "labdev", os.Args[0], name, server)
		c.Env = append(os.Environ(), "LAB_HELPER=dns")
		out, _ := c.Output()
		return string(out)
	}
	dns := func(name string) string { return dnsVia(name, "192.0.2.53") } // diesen DNS-Server gibt es nicht
	for i := 0; i < 30 && get(labT1) != labDev; i++ {
		time.Sleep(200 * time.Millisecond)
	}
	if got := get(labT1); got != labDev {
		t.Fatalf("ohne Regeln: Absender %s, erwartet %s (direkt)", got, labDev)
	}

	oldUp := dnsUpstream
	dnsUpstream = []string{labT1 + ":53"}
	defer func() { dnsUpstream = oldUp }()
	groups := map[int64]proto.GroupRoute{5: {ID: 5, Name: "Lab", Enabled: true, Mark: labMark, DNS: []string{labT1}}}
	dev := []netip.Prefix{netip.MustParsePrefix(labDev + "/32"), netip.MustParsePrefix(labDev6 + "/128")}
	apply := func(step string, pol *proto.Policy, lists map[int64][]netip.Prefix) {
		t.Helper()
		var srcs []srcPolicy
		if pol != nil {
			for _, p := range dev {
				srcs = append(srcs, srcPolicy{p, pol})
			}
		}
		if err := e.applyNftWith(snapshot(), &routing{Groups: groups, TargetLists: lists}, e.aclPlan(), srcs); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	expect := func(step, ip, want string) {
		t.Helper()
		if got := get(ip); got != want {
			t.Errorf("%s: Ziel %s kam von %s, erwartet %s", step, ip, got, want)
		}
	}

	// 1) Ziel-Netz und Zielliste über die Gruppe, der Rest direkt
	apply("Netz", &proto.Policy{Key: "a", Rules: []proto.RouteRule{{ID: 11, Nets: []netip.Prefix{netip.MustParsePrefix(labT1 + "/32")}, Group: 5}}}, nil)
	expect("Netz", labT1, labOut)
	expect("Netz", labT2, labDev)
	apply("Liste", &proto.Policy{Key: "b", Rules: []proto.RouteRule{{ID: 12, Lists: []int64{77}, Group: 5}}},
		map[int64][]netip.Prefix{77: {netip.MustParsePrefix("198.51.100.16/28")}})
	expect("Liste", labT1, labDev)
	expect("Liste", labT2, labOut)

	// 2) Domain-Regel: erst nach der DNS-Anfrage (die umgeleitet wird) läuft das Ziel über die Gruppe
	apply("Domain", &proto.Policy{Key: "c", Rules: []proto.RouteRule{{ID: 13, Domains: []string{"netflix.test"}, Group: 5}}}, nil)
	expect("Domain vor DNS", labT2, labDev)
	if got := dns("www.netflix.test."); got != "A="+labT2+" AAAA=0" {
		t.Fatalf("DNS-Umleitung: %q", got)
	}
	expect("Domain nach DNS", labT2, labOut)
	if got := dns("other.test."); got != "A="+labT1+" AAAA=1" {
		t.Errorf("fremder Name: %q", got)
	}
	expect("fremder Name", labT1, labDev)
	if out := run(t, "nft", "list", "set", "inet", nftTable, "d13"); !strings.Contains(out, labT2) || !strings.Contains(out, "expires") {
		t.Errorf("Set d13:\n%s", out)
	}
	// DNS über IPv6 (IPv6-DNS-Server im Gerät) wird genauso umgeleitet; DoH-Server gibt es nicht
	if got := dnsVia("cdn.netflix.test.", "2001:db8::53"); got != "A="+labT2+" AAAA=0" {
		t.Errorf("DNS-Umleitung über IPv6: %q", got)
	}
	if got := dns("dns.google."); got != "A= AAAA=0" {
		t.Errorf("DoH-Server nicht ausgeblendet: %q", got)
	}
	// Neuladen (andere Regel dazu) behält gelernte Adressen
	apply("Domain + Netz", &proto.Policy{Key: "c2", Rules: []proto.RouteRule{{ID: 13, Domains: []string{"netflix.test"}, Group: 5},
		{ID: 14, Nets: []netip.Prefix{netip.MustParsePrefix("192.0.2.200/32")}, Group: 5}}}, nil)
	expect("nach Neuladen", labT2, labOut)

	// 3) Alles über die Gruppe, eine Domain als Ausnahme direkt
	apply("Alles + Ausnahme", &proto.Policy{Key: "d", Rules: []proto.RouteRule{{ID: 15, Domains: []string{"netflix.test"}, Group: 0}, {ID: 16, All: true, Group: 5}}}, nil)
	expect("Alles", labT1, labOut)
	expect("Ausnahme vor DNS", labT2, labOut)
	dns("api.netflix.test.")
	expect("Ausnahme nach DNS", labT2, labDev)
	if out := run(t, "nft", "list", "table", "inet", nftTable); !strings.Contains(out, "all6") || !strings.Contains(out, "admin-prohibited") {
		t.Errorf("IPv6-Sperre fehlt:\n%s", out)
	}
	// Server selbst bleibt für das Gerät erreichbar (lokale Ziele werden nie umgeleitet)
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
		return exec.Command("ip", "netns", "exec", "labdev", "timeout", "3", "bash", "-c", "exec 3<>/dev/tcp/"+ip+"/"+aclPort).Run() == nil
	}
	if !dial(labSrv) {
		t.Error("Server für das Gerät nicht erreichbar, obwohl alles über die Gruppe läuft")
	}
	apply("ohne Regeln", nil, nil)
	expect("ohne Regeln", labT1, labDev)

	// 4) Sperr- und Freigabelisten (IPv4 und IPv6), bestehende Verbindungen
	expectACL := func(step string, v4, v6 bool) {
		t.Helper()
		if g := dial(labSrv); g != v4 {
			t.Errorf("%s: IPv4 verbunden=%v, erwartet %v", step, g, v4)
		}
		if g := dial(labSrv6); g != v6 {
			t.Errorf("%s: IPv6 verbunden=%v, erwartet %v", step, g, v6)
		}
	}
	list := func(o *store.Object, mode string, entries ...string) *store.Object {
		if o == nil {
			o = &store.Object{Kind: "iplist", Name: mode, Secrets: store.M{}}
		}
		o.Enabled, o.Data = true, store.M{"mode": mode, "all": true, "entries": entries}
		if err := st.SaveObject(o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	stream := exec.Command("ip", "netns", "exec", "labdev", "bash", "-c",
		"exec 3<>/dev/tcp/"+labSrv+"/"+aclPort+"; while echo x >&3; do sleep 0.2; done")
	if err := stream.Start(); err != nil {
		t.Fatal(err)
	}
	procs = append(procs, stream)
	time.Sleep(1200 * time.Millisecond)
	if got.Load() == 0 {
		t.Fatal("Datenstrom kommt nicht an")
	}
	bl := list(nil, "block", labDev+"/32", labDev6+"/128")
	apply("Sperre", nil, nil)
	time.Sleep(700 * time.Millisecond)
	n1 := got.Load()
	time.Sleep(1200 * time.Millisecond)
	if n2 := got.Load(); n2 != n1 {
		t.Errorf("bestehende Verbindung läuft trotz Sperre weiter (%d → %d Bytes)", n1, n2)
	}
	expectACL("Sperre", false, false)
	bl.Enabled = false
	_ = st.SaveObject(bl)
	al := list(nil, "allow", "10.97.0.99/32")
	apply("Freigabe fremd", nil, nil)
	expectACL("Freigabe fremd", false, false)
	list(al, "allow", "10.97.0.0/24")
	apply("Freigabe IPv4", nil, nil)
	expectACL("Freigabe IPv4", true, false)
	list(al, "allow", "10.97.0.0/24", "fd97::/64")
	apply("Freigabe beide", nil, nil)
	expectACL("Freigabe beide", true, true)
	list(bl, "block", labDev+"/32")
	apply("Sperre + Freigabe", nil, nil)
	expectACL("Sperre + Freigabe", false, true)
	// große Liste (wie eine Online-Liste)
	var many []string
	for i := 0; i < 60000; i++ {
		many = append(many, fmt.Sprintf("11.%d.%d.0/24", i/256, i%256))
	}
	t0 := time.Now()
	list(bl, "block", append(many, labDev+"/32")...)
	apply("große Liste", nil, nil)
	t.Logf("60000 Einträge geladen in %v", time.Since(t0).Round(time.Millisecond))
	expectACL("große Liste", false, true)

	// 5) Abbau
	_ = st.DeleteObject("iplist", bl.ID)
	_ = st.DeleteObject("iplist", al.ID)
	apply("Abbau", nil, nil)
	expectACL("nach Abbau", true, true)
	if out, _ := exec.Command("nft", "list", "tables").Output(); strings.Contains(string(out), nftTable) {
		t.Errorf("Tabelle nach Abbau noch da:\n%s", out)
	}
}
