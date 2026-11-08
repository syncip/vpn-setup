//go:build lab

// Labortest auf echtem Linux (als root, z. B. in WSL): ein „Anbieter“ in einem eigenen
// Netzwerk-Namespace betreibt einen OpenVPN-Server, ein Ziel-Webserver und einen DNS-Server.
// Geprüft wird der ganze Weg: hochgeladene (bereinigte) Konfiguration → OpenVPN-Ausgang →
// Prüfung → Gruppe → Proxy (SOCKS5/HTTP) mit DNS über den Ausgang → Ausfall → Sperre/direkt.
//
//	GOOS=linux go test -c -tags lab -o labtest ./internal/labtest && sudo ./labtest -test.v
package labtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/proxy"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

const (
	target  = "198.51.100.10" // Ziel im „Internet“ (beim Anbieter)
	provIP  = "10.99.0.2"
	srvIP   = "10.99.0.1"
	exitID  = 901
	groupID = 902
	slot    = 61
	wgID    = 903 // zweiter Ausgang (WireGuard)
	wgSlot  = 62
	wgCli   = "10.96.0.2"
)

// ---------- Hilfsserver im Namespace des Anbieters ----------

var (
	dnsMu   sync.Mutex
	dnsLast string
)

func TestMain(m *testing.M) {
	if os.Getenv("LAB_HELPER") == "1" {
		helper()
		return
	}
	os.Exit(m.Run())
}

func helper() {
	go dnsServer()
	mux := http.NewServeMux()
	src := func(r *http.Request) string { h, _, _ := net.SplitHostPort(r.RemoteAddr); return h }
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "ip=%s\nloc=ZZ\n", src(r)) })
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(make([]byte, 5_000_000)) })
	mux.HandleFunc("/dnslog", func(w http.ResponseWriter, r *http.Request) {
		dnsMu.Lock()
		defer dnsMu.Unlock()
		io.WriteString(w, dnsLast)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "src=%s", src(r)) })
	_ = http.ListenAndServe(target+":80", mux)
}

// dnsServer beantwortet jede A-Anfrage mit target und merkt sich die Absenderadresse.
func dnsServer() {
	pc, err := net.ListenPacket("udp4", target+":53")
	if err != nil {
		return
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			continue
		}
		q := buf[:n]
		dnsMu.Lock()
		dnsLast = strings.Split(from.String(), ":")[0]
		dnsMu.Unlock()
		// Frage-Abschnitt finden
		i := 12
		for i < n && q[i] != 0 {
			i += int(q[i]) + 1
		}
		i += 5
		if i > n {
			continue
		}
		qtype := binary.BigEndian.Uint16(q[i-4:])
		resp := append([]byte{}, q[:i]...)
		resp[2], resp[3] = 0x81, 0x80
		binary.BigEndian.PutUint16(resp[6:], 0) // Antworten
		binary.BigEndian.PutUint16(resp[8:], 0)
		binary.BigEndian.PutUint16(resp[10:], 0)
		if qtype == 1 {
			binary.BigEndian.PutUint16(resp[6:], 1)
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
			resp = append(resp, net.ParseIP(target).To4()...)
		}
		_, _ = pc.WriteTo(resp, from)
	}
}

// ---------- PKI ----------

func pemOf(typ string, der []byte) string {
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})))
}

func pki(t *testing.T) (ca, srvCert, srvKey, cliCert, cliKey string) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lab-CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	issue := func(cn string, server bool, sn int64) (string, string) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ct := &x509.Certificate{SerialNumber: big.NewInt(sn), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			ct.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, ct, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalECPrivateKey(k)
		return pemOf("CERTIFICATE", der), pemOf("EC PRIVATE KEY", kd)
	}
	srvCert, srvKey = issue("server", true, 2)
	cliCert, cliKey = issue("client", false, 3)
	return pemOf("CERTIFICATE", caDER), srvCert, srvKey, cliCert, cliKey
}

// ---------- Test ----------

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

func quiet(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Zeitüberschreitung: %s", what)
}

func TestLab(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	dir := t.TempDir()
	state := map[string]string{}
	var smu sync.Mutex
	env := &exits.Env{Sys: system.Real{},
		Get: func(k string) string { smu.Lock(); defer smu.Unlock(); return state[k] },
		Set: func(k, v string) { smu.Lock(); defer smu.Unlock(); state[k] = v },
		Log: func(l, m string) { t.Logf("[%s] %s", l, m) }}
	m := exits.New()

	// Aufräumen (auch nach Fehlern)
	var procs []*exec.Cmd
	pxEnv := &proto.Env{Sys: system.Real{}, Log: func(string, string) {}}
	cleanup := func() {
		_ = proxy.Driver{}.Apply(pxEnv, nil)
		_ = m.Apply(env, nil, nil)
		for _, p := range procs {
			_ = p.Process.Kill()
			_, _ = p.Process.Wait()
		}
		quiet("ip", "route", "del", "198.51.100.0/24")
		quiet("ip", "link", "del", "vsrv")
		quiet("ip", "netns", "del", "prov")
	}
	cleanup()
	t.Cleanup(func() {
		cleanup()
		if out, _ := exec.Command("ip", "rule").Output(); strings.Contains(string(out), "lookup 3061") || strings.Contains(string(out), "lookup 2061") {
			t.Errorf("Routing-Regeln nicht abgebaut:\n%s", out)
		}
		for _, f := range []string{"ex901.ovpn", "ex903.conf"} {
			if _, err := os.Stat("/etc/vpn/exits/" + f); err == nil {
				t.Errorf("Konfiguration %s nicht gelöscht", f)
			}
		}
		if err := exec.Command("ip", "link", "show", "dev", "ex903").Run(); err == nil {
			t.Error("WireGuard-Ausgang ex903 nicht abgebaut")
		}
		for _, tb := range []string{"filter", "nat", "mangle"} {
			if out, _ := exec.Command("iptables", "-t", tb, "-S").Output(); strings.Contains(string(out), "VPNEX") {
				t.Errorf("Firewall-Ketten (%s) nicht abgebaut:\n%s", tb, out)
			}
		}
	})

	// Netz: Server (Wurzel-Namespace) ↔ Anbieter (Namespace prov)
	sh(t, "ip", "netns", "add", "prov")
	sh(t, "ip", "link", "add", "vsrv", "type", "veth", "peer", "name", "vprov")
	sh(t, "ip", "link", "set", "vprov", "netns", "prov")
	sh(t, "ip", "addr", "add", srvIP+"/24", "dev", "vsrv")
	sh(t, "ip", "link", "set", "vsrv", "up")
	sh(t, "ip", "netns", "exec", "prov", "ip", "addr", "add", provIP+"/24", "dev", "vprov")
	sh(t, "ip", "netns", "exec", "prov", "ip", "link", "set", "vprov", "up")
	sh(t, "ip", "netns", "exec", "prov", "ip", "link", "set", "lo", "up")
	sh(t, "ip", "netns", "exec", "prov", "ip", "addr", "add", target+"/32", "dev", "lo")
	sh(t, "ip", "route", "add", "198.51.100.0/24", "via", provIP) // direkter Weg (ohne Ausgang)

	helperCmd := exec.Command("ip", "netns", "exec", "prov", os.Args[0])
	helperCmd.Env = append(os.Environ(), "LAB_HELPER=1")
	if err := helperCmd.Start(); err != nil {
		t.Fatal(err)
	}
	procs = append(procs, helperCmd)

	// OpenVPN-Server beim Anbieter
	ca, sc, sk, cc, ck := pki(t)
	srvConf := fmt.Sprintf("dev tun\nproto udp\nlocal %s\nport 1194\ntopology subnet\nserver 10.98.0.0 255.255.255.0\ndh none\n"+
		"keepalive 2 8\npush \"redirect-gateway def1\"\npush \"dhcp-option DNS 10.98.0.1\"\nverb 3\n<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n", provIP, ca, sc, sk)
	_ = os.WriteFile(filepath.Join(dir, "server.conf"), []byte(srvConf), 0o600)
	startServer := func() *exec.Cmd {
		c := exec.Command("ip", "netns", "exec", "prov", "openvpn", "--config", filepath.Join(dir, "server.conf"))
		log, _ := os.Create(filepath.Join(dir, "server.log"))
		c.Stdout, c.Stderr = log, log
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		procs = append(procs, c)
		return c
	}
	ovpnSrv := startServer()

	// Hochgeladene Client-Konfiguration – mit Einträgen, die entfernt werden müssen
	upload := fmt.Sprintf("client\ndev tun\nproto udp\nremote %s 1194\nnobind\nremote-cert-tls server\nscript-security 2\nup \"/bin/touch %s/HACKED\"\n"+
		"route-up /bin/false\nlog /etc/passwd\n<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n", provIP, dir, ca, cc, ck)
	ov, err := exits.ParseOVPN(upload)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("entfernt: %v", ov.Removed)
	ex := &exits.Exit{ID: exitID, Name: "Lab-Anbieter", Enabled: true, Type: "openvpn", Slot: slot, OVPN: ov}
	g := &exits.Group{ID: groupID, Name: "Lab", Enabled: true, Slot: slot, Exits: []int64{exitID}, OnFail: "block", MaxLoss: 20, MaxRTT: 400, DNS: []string{target}}
	xs, gs := []*exits.Exit{ex}, []*exits.Group{g}
	if err := m.Apply(env, xs, gs); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "OpenVPN-Ausgang ex901", 40*time.Second, func() bool {
		out, err := exec.Command("ip", "-4", "addr", "show", "dev", "ex901").Output()
		return err == nil && strings.Contains(string(out), "10.98.0.")
	})
	if _, err := os.Stat(filepath.Join(dir, "HACKED")); err == nil {
		t.Fatal("up-Skript der hochgeladenen Konfiguration wurde ausgeführt!")
	}
	// Prüfung
	exits.SetProbeTargets(target, "http://"+target+"/cdn-cgi/trace", "http://"+target+"/down")
	m.Check(env, xs, gs, time.Nanosecond)
	// Der Server selbst darf seinen Weg nicht ändern (redirect-gateway/DNS/Netzroute vom Anbieter weg)
	if out := sh(t, "ip", "-4", "route", "show", "table", "main"); strings.Contains(out, "ex901") || strings.Contains(out, "0.0.0.0/1") {
		t.Fatalf("Ausgang hat Routen in der Haupttabelle:\n%s", out)
	}
	es, gst := m.Status()
	st := es[exitID]
	t.Logf("Ausgang: up=%v loss=%.0f rtt=%.1f ip=%s loc=%s mbit=%.0f err=%q", st.Up, st.Loss, st.RTT, st.IP, st.Loc, st.Mbit, st.Error)
	if !st.Up || st.Loss > 0 || !strings.HasPrefix(st.IP, "10.98.0.") || st.Loc != "ZZ" || st.Mbit <= 0 {
		t.Fatalf("Prüfung fehlerhaft: %+v", st)
	}
	if gst[groupID].Active != exitID || gst[groupID].State != "ok" {
		t.Fatalf("Gruppe: %+v", gst[groupID])
	}

	// Proxy über die Gruppe
	routes := map[int64]proto.GroupRoute{groupID: {ID: groupID, Name: "Lab", Enabled: true, Mark: exits.GroupMark(slot), DNS: []string{target}}}
	pxEnv.Global.Groups = routes
	mk := func(id int64, group int64, socks, hp int) *proto.ServerBundle {
		srv := &store.Server{ID: id, Name: fmt.Sprint("px", id), Protocol: "proxy", Enabled: true,
			Settings: store.M{"socks_port": float64(socks), "http_port": float64(hp), "group": float64(group)}}
		if err := (proxy.Driver{}).InitServer(pxEnv, srv, nil); err != nil {
			t.Fatal(err)
		}
		p := &store.Peer{ID: id * 10, ServerID: id, Settings: store.M{}, Secrets: store.M{}, Enabled: true}
		if err := (proxy.Driver{}).InitPeer(pxEnv, srv, p, nil); err != nil {
			t.Fatal(err)
		}
		return &proto.ServerBundle{Server: srv, Peers: []*proto.PeerBundle{{Peer: p, User: &store.User{ID: 1, Name: "lab"}, Active: true}}}
	}
	viaGroup, direct := mk(1, groupID, 31080, 38080), mk(2, 0, 31081, 38081)
	if err := (proxy.Driver{}).Apply(pxEnv, []*proto.ServerBundle{viaGroup, direct}); err != nil {
		t.Fatal(err)
	}
	get := func(sb *proto.ServerBundle, rawURL string, socks bool) (string, error) {
		c := sb.Server.Settings
		user, pass := proto.Str(sb.Peers[0].Peer.Secrets, "username"), proto.Str(sb.Peers[0].Peer.Secrets, "password")
		pu := &url.URL{Scheme: "http", User: url.UserPassword(user, pass), Host: fmt.Sprintf("127.0.0.1:%v", c["http_port"])}
		if socks {
			pu = &url.URL{Scheme: "socks5", User: url.UserPassword(user, pass), Host: fmt.Sprintf("127.0.0.1:%v", c["socks_port"])}
		}
		cl := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
		resp, err := cl.Get(rawURL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
		}
		return string(b), nil
	}
	for _, socks := range []bool{false, true} {
		body, err := get(viaGroup, "http://ziel.test/", socks)
		if err != nil || !strings.HasPrefix(body, "src=10.98.0.") {
			t.Fatalf("Proxy über Gruppe (socks=%v): %q %v", socks, body, err)
		}
		t.Logf("über Gruppe (socks=%v): %s", socks, body)
	}
	if dl, _ := http.Get("http://" + target + "/dnslog"); dl != nil {
		b, _ := io.ReadAll(dl.Body)
		dl.Body.Close()
		if !strings.HasPrefix(string(b), "10.98.0.") {
			t.Fatalf("DNS lief nicht über den Ausgang: %q", b)
		}
		t.Logf("DNS-Anfrage kam von %s (über den Ausgang)", b)
	}
	if body, err := get(direct, "http://"+target+"/", false); err != nil || body != "src="+srvIP {
		t.Fatalf("Proxy direkt: %q %v", body, err)
	}

	// Ausfall des Anbieters → Gruppe sperrt, Proxy über die Gruppe kommt nicht mehr durch
	_ = ovpnSrv.Process.Kill()
	_, _ = ovpnSrv.Process.Wait()
	m.Check(env, xs, gs, 0)
	_, gst = m.Status()
	t.Logf("nach Ausfall: %+v", gst[groupID])
	if gst[groupID].State != "blocked" || gst[groupID].Active != 0 {
		t.Fatalf("Gruppe nicht gesperrt: %+v", gst[groupID])
	}
	if body, err := get(viaGroup, "http://"+target+"/", false); err == nil {
		t.Fatalf("trotz Sperre durchgekommen: %q", body)
	}
	// „direkt“ bei Ausfall: über den Server selbst
	g.OnFail = "direct"
	if err := m.Apply(env, xs, gs); err != nil { // zweites Apply: iptables-restore -n mit bestehenden Ketten
		t.Fatal(err)
	}
	if body, err := get(viaGroup, "http://"+target+"/", false); err != nil || body != "src="+srvIP {
		t.Fatalf("Ausfall → direkt: %q %v", body, err)
	}
	// Anbieter wieder da → Ausgang verbindet neu, Gruppe nimmt ihn wieder
	ovpnSrv = startServer()
	waitFor(t, "Neuverbindung", 60*time.Second, func() bool {
		m.Check(env, xs, gs, 0)
		_, gst = m.Status()
		return gst[groupID].Active == exitID
	})
	if body, err := get(viaGroup, "http://"+target+"/", true); err != nil || !strings.HasPrefix(body, "src=10.98.0.") {
		t.Fatalf("nach Neuverbindung: %q %v", body, err)
	}
	// ---------- WireGuard-Ausgang als zweiter Ausgang der Gruppe ----------
	genkey := func() (priv, pub string) {
		p := strings.TrimSpace(sh(t, "wg", "genkey"))
		c := exec.Command("wg", "pubkey")
		c.Stdin = strings.NewReader(p + "\n")
		out, err := c.Output()
		if err != nil {
			t.Fatal(err)
		}
		return p, strings.TrimSpace(string(out))
	}
	sPriv, sPub := genkey()
	cPriv, cPub := genkey()
	_ = os.WriteFile(filepath.Join(dir, "wgp.key"), []byte(sPriv+"\n"), 0o600)
	sh(t, "ip", "netns", "exec", "prov", "ip", "link", "add", "wgp", "type", "wireguard")
	sh(t, "ip", "netns", "exec", "prov", "wg", "set", "wgp", "private-key", filepath.Join(dir, "wgp.key"), "listen-port", "51820",
		"peer", cPub, "allowed-ips", wgCli+"/32")
	sh(t, "ip", "netns", "exec", "prov", "ip", "addr", "add", "10.96.0.1/24", "dev", "wgp")
	sh(t, "ip", "netns", "exec", "prov", "ip", "link", "set", "wgp", "up")
	wgUpload := "[Interface]\nPrivateKey = " + cPriv + "\nAddress = " + wgCli + "/32\nDNS = 10.96.0.1\nPostUp = /bin/touch " + dir + "/HACKED-WG\n" +
		"Table = off\n\n[Peer]\nPublicKey = " + sPub + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = " + provIP + ":51820\n"
	wgc, err := exits.ParseWG(wgUpload)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("WireGuard entfernt: %v", wgc.Removed)
	wex := &exits.Exit{ID: wgID, Name: "Lab-WG", Enabled: true, Type: "wireguard", Slot: wgSlot, WG: wgc}
	xs = append(xs, wex)
	g.Exits = []int64{exitID, wgID}
	if err := m.Apply(env, xs, gs); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "WireGuard-Ausgang gesund", 30*time.Second, func() bool {
		m.Check(env, xs, gs, time.Nanosecond)
		es, _ := m.Status()
		s := es[wgID]
		return s.Up && s.IP == wgCli && s.Loss == 0
	})
	es, _ = m.Status()
	st = es[wgID]
	t.Logf("WG-Ausgang: up=%v loss=%.0f rtt=%.1f ip=%s loc=%s mbit=%.0f", st.Up, st.Loss, st.RTT, st.IP, st.Loc, st.Mbit)
	if st.Mbit <= 0 {
		t.Errorf("WG: keine Geschwindigkeit gemessen")
	}
	if _, err := os.Stat(filepath.Join(dir, "HACKED-WG")); err == nil {
		t.Fatal("PostUp der hochgeladenen WireGuard-Konfiguration wurde ausgeführt!")
	}
	if out := sh(t, "ip", "-4", "route", "show", "table", "main"); strings.Contains(out, "ex903") || strings.Contains(out, "0.0.0.0/1") {
		t.Fatalf("WG-Ausgang hat Routen in der Haupttabelle:\n%s", out)
	}
	if out := sh(t, "ip", "-6", "route", "show"); strings.Contains(out, "ex903") {
		t.Fatalf("WG-Ausgang hat IPv6-Routen:\n%s", out)
	}
	wcfg, _ := os.ReadFile("/etc/vpn/exits/ex903.conf")
	for _, bad := range []string{"PostUp", "HACKED", "Table", "DNS", "::/0"} {
		if strings.Contains(string(wcfg), bad) {
			t.Errorf("%q steht noch in der WG-Konfiguration", bad)
		}
	}
	if fi, err := os.Stat("/etc/vpn/exits/ex903.conf"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("Rechte der WG-Konfiguration: %v %v", fi, err)
	}
	// Firewall: beide Ausgänge nach innen dicht, NAT und MSS
	for tb, want := range map[string][]string{
		"filter": {"-A VPNEX-IN -i ex901 -j DROP", "-A VPNEX-IN -i ex903 -j DROP", "-A INPUT -j VPNEX-IN"},
		"nat":    {"-A VPNEX-NAT -o ex903 -j MASQUERADE", "-A POSTROUTING -j VPNEX-NAT"},
		"mangle": {"-A VPNEX-MSS -o ex903 -p tcp", "--clamp-mss-to-pmtu", "-A FORWARD -j VPNEX-MSS"},
	} {
		out := sh(t, "iptables", "-t", tb, "-S")
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("iptables %s: %q fehlt\n%s", tb, w, out)
			}
		}
	}
	// Anbieter versucht, über den Tunnel einen Dienst des Servers zu erreichen → verworfen
	ln, err := net.Listen("tcp4", "0.0.0.0:41999")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	dial := func(ip string) error {
		return exec.Command("ip", "netns", "exec", "prov", "timeout", "3", "bash", "-c", "exec 3<>/dev/tcp/"+ip+"/41999").Run()
	}
	if err := dial(srvIP); err != nil {
		t.Fatalf("Gegenprobe über veth schlägt fehl: %v", err)
	}
	if err := dial(wgCli); err == nil {
		t.Fatal("Anbieter erreicht über den Tunnel einen Dienst des Servers")
	}
	if out := sh(t, "iptables", "-L", "VPNEX-IN", "-v", "-n", "-x"); !dropCounted(out, "ex903") {
		t.Errorf("DROP-Zähler für ex903 nicht gestiegen:\n%s", out)
	}
	// OpenVPN-Anbieter fällt aus → Gruppe weicht auf WireGuard aus
	_ = ovpnSrv.Process.Kill()
	_, _ = ovpnSrv.Process.Wait()
	m.Check(env, xs, gs, 0)
	_, gst = m.Status()
	t.Logf("nach OpenVPN-Ausfall: %+v", gst[groupID])
	if gst[groupID].Active != wgID || gst[groupID].State != "failover" {
		t.Fatalf("kein Ausweichen auf WireGuard: %+v", gst[groupID])
	}
	for _, socks := range []bool{false, true} {
		if body, err := get(viaGroup, "http://ziel2.test/", socks); err != nil || body != "src="+wgCli {
			t.Fatalf("Proxy über WG-Ausgang (socks=%v): %q %v", socks, body, err)
		}
	}
	if dl, _ := http.Get("http://" + target + "/dnslog"); dl != nil {
		b, _ := io.ReadAll(dl.Body)
		dl.Body.Close()
		if string(b) != wgCli {
			t.Fatalf("DNS lief nicht über den WG-Ausgang: %q", b)
		}
	}
	// beide weg → (OnFail direct) über den Server selbst
	sh(t, "ip", "netns", "exec", "prov", "ip", "link", "set", "wgp", "down")
	m.Check(env, xs, gs, 0)
	_, gst = m.Status()
	if gst[groupID].State != "direct" {
		t.Fatalf("beide Ausgänge weg: %+v", gst[groupID])
	}
	if body, err := get(viaGroup, "http://"+target+"/", false); err != nil || body != "src="+srvIP {
		t.Fatalf("beide weg → direkt: %q %v", body, err)
	}
	ovpnSrv = startServer()

	cfg, _ := os.ReadFile("/etc/vpn/exits/ex901.ovpn")
	for _, bad := range []string{"script-security 2", "/bin/touch", "route-up", "log /etc/passwd"} {
		if strings.Contains(string(cfg), bad) {
			t.Errorf("%q steht noch in der Konfiguration", bad)
		}
	}
	if fi, err := os.Stat("/etc/vpn/exits/ex901.ovpn"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("Rechte der Konfiguration: %v %v", fi.Mode(), err)
	}
}

// dropCounted: hat die DROP-Regel für die Schnittstelle Pakete gezählt? (iptables -L -v -n -x)
func dropCounted(out, iface string) bool {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 6 && f[2] == "DROP" && f[5] == iface && f[0] != "0" {
			return true
		}
	}
	return false
}
