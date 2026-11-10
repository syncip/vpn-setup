package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type fixture struct {
	env       *proto.Env
	sb        *proto.ServerBundle
	socks, hp int
}

func setup(t *testing.T) *fixture {
	allowLocal = true
	t.Cleanup(func() {
		allowLocal = false
		_ = Driver{}.Apply(&proto.Env{Sys: &system.Dry{Root: t.TempDir()}}, nil)
	})
	f := &fixture{socks: freePort(t), hp: freePort(t)}
	f.env = &proto.Env{Sys: &system.Dry{Root: t.TempDir()}, Log: func(string, string) {}}
	srv := &store.Server{ID: 7, Name: "px", Protocol: "proxy", Enabled: true,
		Settings: store.M{"socks_port": float64(f.socks), "http_port": float64(f.hp), "max_conns": float64(4)}}
	if err := (Driver{}).InitServer(f.env, srv, nil); err != nil {
		t.Fatal(err)
	}
	mk := func(id int64, active bool) *proto.PeerBundle {
		p := &store.Peer{ID: id, ServerID: 7, Settings: store.M{}, Secrets: store.M{}, Enabled: true}
		if err := (Driver{}).InitPeer(f.env, srv, p, nil); err != nil {
			t.Fatal(err)
		}
		return &proto.PeerBundle{Peer: p, User: &store.User{ID: id, Name: fmt.Sprint("u", id)}, Active: active}
	}
	f.sb = &proto.ServerBundle{Server: srv, Peers: []*proto.PeerBundle{mk(1, true), mk(2, false)}}
	if err := (Driver{}).Apply(f.env, []*proto.ServerBundle{f.sb}); err != nil {
		t.Fatal(err)
	}
	return f
}

func creds(pb *proto.PeerBundle) (string, string) {
	return proto.Str(pb.Peer.Secrets, "username"), proto.Str(pb.Peer.Secrets, "password")
}

// socksGet: minimaler SOCKS5-Client (Benutzer/Passwort, CONNECT per Domain), dann HTTP GET.
func socksGet(t *testing.T, port int, user, pass, target string) (string, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{5, 1, 2})
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || b[1] != 2 {
		return "", fmt.Errorf("Methode %v %v", b, err)
	}
	msg := append([]byte{1, byte(len(user))}, user...)
	msg = append(append(msg, byte(len(pass))), pass...)
	_, _ = c.Write(msg)
	if _, err := io.ReadFull(c, b); err != nil || b[1] != 0 {
		return "", fmt.Errorf("Anmeldung abgelehnt")
	}
	host, ps, _ := net.SplitHostPort(target)
	port2, _ := strconv.Atoi(ps)
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, byte(port2>>8), byte(port2))
	_, _ = c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return "", err
	}
	if rep[1] != 0 {
		return "", fmt.Errorf("SOCKS-Antwort %d", rep[1])
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func TestProxy(t *testing.T) {
	f := setup(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hallo "+r.URL.Path) }))
	defer up.Close()
	tlsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "sicher") }))
	defer tlsUp.Close()
	target := strings.TrimPrefix(up.URL, "http://")
	target = strings.Replace(target, "127.0.0.1", "localhost", 1)
	u1, p1 := creds(f.sb.Peers[0])
	u2, p2 := creds(f.sb.Peers[1])

	// SOCKS5
	if body, err := socksGet(t, f.socks, u1, p1, target); err != nil || body != "hallo /" {
		t.Fatalf("SOCKS5: %q %v", body, err)
	}
	if _, err := socksGet(t, f.socks, u1, "falsch", target); err == nil {
		t.Fatal("falsches Passwort angenommen")
	}
	if _, err := socksGet(t, f.socks, u2, p2, target); err == nil {
		t.Fatal("gesperrter Zugang angenommen")
	}

	// HTTP-Proxy: normale Anfrage und CONNECT
	client := func(user, pass string) *http.Client {
		pu := &url.URL{Scheme: "http", User: url.UserPassword(user, pass), Host: fmt.Sprintf("127.0.0.1:%d", f.hp)}
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	resp, err := client(u1, p1).Get(up.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hallo /x" {
		t.Fatalf("HTTP: %q", body)
	}
	resp, err = client(u1, p1).Get(tlsUp.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "sicher" {
		t.Fatalf("CONNECT: %q", body)
	}
	resp, err = client(u1, "nein").Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("Status %d statt 407", resp.StatusCode)
	}

	// Statistik
	use, _ := Driver{}.Collect(f.env, []*proto.ServerBundle{f.sb})
	if u := use[1]; u.Up <= 0 || u.Down <= 0 || u.Seen == 0 {
		t.Fatalf("keine Statistik: %+v", u)
	}
	if u := use[2]; u.Up+u.Down != 0 {
		t.Fatalf("gesperrter Zugang mit Verkehr: %+v", u)
	}

	// Lokale Ziele sind normalerweise gesperrt
	allowLocal = false
	if _, err := socksGet(t, f.socks, u1, p1, target); err == nil || !strings.Contains(err.Error(), "SOCKS-Antwort 2") {
		t.Fatalf("lokales Ziel erreichbar: %v", err)
	}
	allowLocal = true

	// IP-Sperrliste: 127.0.0.1 gesperrt → Verbindung wird sofort getrennt
	f.env.Global.ACLs = map[int64]*proto.ACL{7: {Deny: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	if err := (Driver{}).Apply(f.env, []*proto.ServerBundle{f.sb}); err != nil {
		t.Fatal(err)
	}
	if _, err := socksGet(t, f.socks, u1, p1, target); err == nil {
		t.Fatal("gesperrte Client-IP angenommen")
	}
	f.env.Global.ACLs = nil

	// Anmeldung per IP (ohne Passwort)
	f.sb.Peers[0].Peer.Settings["source_ips"] = []any{"127.0.0.1"}
	if err := (Driver{}).Apply(f.env, []*proto.ServerBundle{f.sb}); err != nil {
		t.Fatal(err)
	}
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", f.hp)})}}
	resp, err = plain.Get(up.URL + "/ip")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hallo /ip" {
		t.Fatalf("Anmeldung per IP: %d %q", resp.StatusCode, body)
	}
}

func TestBucket(t *testing.T) {
	var b bucket
	b.setRate(8) // 8 Mbit/s = 1 MB/s
	t0 := time.Now()
	for i := 0; i < 20; i++ {
		b.take(64 * 1024) // 1,25 MB
	}
	if d := time.Since(t0); d < 900*time.Millisecond || d > 2*time.Second {
		t.Fatalf("Drosselung ungenau: %v", d)
	}
}

func TestInitPeerSourceIPs(t *testing.T) {
	env := &proto.Env{Sys: &system.Dry{Root: t.TempDir()}}
	srv := &store.Server{ID: 1, Settings: store.M{}}
	p := &store.Peer{Settings: store.M{"source_ips": []any{"10.0.0.0/8"}}, Secrets: store.M{}}
	if err := (Driver{}).InitPeer(env, srv, p, nil); err == nil {
		t.Fatal("zu großes Netz angenommen")
	}
	p.Settings["source_ips"] = []any{"203.0.113.7", "2001:db8::/64"}
	if err := (Driver{}).InitPeer(env, srv, p, nil); err != nil {
		t.Fatal(err)
	}
	if len(proto.Str(p.Secrets, "password")) != 24 || !strings.HasPrefix(proto.Str(p.Secrets, "username"), "u") {
		t.Fatal("Zugangsdaten fehlen")
	}
}

// TestNotes: abgelehnte Verbindungen und Anmeldungen landen (gedrosselt) im Ereignisprotokoll;
// eine Sperre nach Fehlversuchen gibt es nicht.
func TestNotes(t *testing.T) {
	f := setup(t)
	var mu sync.Mutex
	var logs []string
	f.env.Log = func(level, msg string) { mu.Lock(); logs = append(logs, level+" "+msg); mu.Unlock() }
	reset := func() {
		resetNotes()
		mu.Lock()
		logs = nil
		mu.Unlock()
	}
	reset()
	if err := (Driver{}).Apply(f.env, []*proto.ServerBundle{f.sb}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reset)
	has := func(s string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, l := range logs {
			if strings.Contains(l, s) {
				return true
			}
		}
		return false
	}
	count := func(s string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, l := range logs {
			if strings.Contains(l, s) {
				n++
			}
		}
		return n
	}
	noAuth := func() {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.socks))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte{5, 1, 0})
		b := make([]byte, 2)
		if _, err := io.ReadFull(c, b); err != nil || b[1] != 0xff {
			t.Fatalf("ohne Anmeldung: %v %v", b, err)
		}
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer web.Close()
	target := strings.TrimPrefix(web.URL, "http://")
	// SOCKS5 ohne Zugangsdaten: mehrfach versucht → nur eine Meldung
	for i := 0; i < 15; i++ {
		noAuth()
	}
	time.Sleep(100 * time.Millisecond)
	if count("ohne Benutzername/Passwort") != 1 {
		t.Fatalf("ohne Anmeldung: Meldungen=%d %v", count("ohne Benutzername/Passwort"), logs)
	}
	// richtiges Passwort eines gesperrten Zugangs: Meldung mit Grund
	u2, p2 := creds(f.sb.Peers[1])
	if _, err := socksGet(t, f.socks, u2, p2, target); err == nil {
		t.Fatal("gesperrter Zugang angenommen")
	}
	time.Sleep(100 * time.Millisecond)
	if !has("Zugang „" + u2 + "“ abgewiesen – Zugang gesperrt") {
		t.Fatalf("gesperrter Zugang: %v", logs)
	}
	// falsches Passwort (SOCKS5 und HTTP) → Meldung ohne Passwort
	u1, p1 := creds(f.sb.Peers[0])
	pu := &url.URL{Scheme: "http", User: url.UserPassword(u1, "falsch-http"), Host: fmt.Sprintf("127.0.0.1:%d", f.hp)}
	cl := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	if resp, err := cl.Get(web.URL); err != nil || resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP falsches Passwort: %v %v", resp, err)
	}
	for i := 0; i < 30; i++ {
		_, _ = socksGet(t, f.socks, u1, "falsch-socks", target)
	}
	time.Sleep(100 * time.Millisecond)
	if !has("(HTTP) fehlgeschlagen") || count("fehlgeschlagen") != 1 { // gedrosselt: eine Meldung je Adresse
		t.Fatalf("Fehlversuche nicht (gedrosselt) gemeldet: %v", logs)
	}
	if has("falsch-") || has(p1) {
		t.Fatal("Passwort im Protokoll")
	}
	// keine Sperre: nach vielen Fehlversuchen klappt die richtige Anmeldung sofort
	if body, err := socksGet(t, f.socks, u1, p1, target); err != nil || body != "ok" {
		t.Fatalf("nach Fehlversuchen ausgesperrt: %q %v", body, err)
	}
	// IP-Liste
	reset()
	f.env.Global.ACLs = map[int64]*proto.ACL{7: {Deny: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	_ = (Driver{}).Apply(f.env, []*proto.ServerBundle{f.sb})
	_, _ = socksGet(t, f.socks, u1, p1, "example.com:80")
	time.Sleep(100 * time.Millisecond)
	f.env.Global.ACLs = nil
	_ = (Driver{}).Apply(f.env, []*proto.ServerBundle{f.sb})
	if !has("Verbindung von 127.0.0.1 abgelehnt – durch eine IP-Liste gesperrt") {
		t.Fatalf("IP-Liste nicht gemeldet: %v", logs)
	}
}

func TestNoteThrottle(t *testing.T) {
	var got []string
	setLog(func(_, m string) { got = append(got, m) })
	t.Cleanup(func() { setLog(nil); resetNotes() })
	resetNotes()
	for i := 0; i < 100; i++ {
		note("info", "a", "gleich")
		note("info", fmt.Sprint("k", i), "verschieden")
	}
	if len(got) != noteMax {
		t.Fatalf("%d Meldungen, erwartet %d", len(got), noteMax)
	}
	if strings.Count(strings.Join(got, "|"), "gleich") != 1 {
		t.Fatal("gleiche Meldung mehrfach")
	}
}

func TestIPv6Targets(t *testing.T) {
	f := setup(t)
	var mu sync.Mutex
	var logs []string
	f.env.Log = func(_, msg string) { mu.Lock(); logs = append(logs, msg); mu.Unlock() }
	resetNotes()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("kein IPv6-Loopback")
	}
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "v6") }))
	web.Listener = ln
	web.Start()
	defer web.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	u, p := creds(f.sb.Peers[0])
	// SOCKS5 CONNECT mit IPv6-Adresse (Adresstyp 4), wie curl mit socks5:// bei IPv6-Namen
	connect := func() (byte, *bufio.Reader, net.Conn) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.socks))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte{5, 1, 2})
		b := make([]byte, 2)
		_, _ = io.ReadFull(c, b)
		msg := append([]byte{1, byte(len(u))}, u...)
		_, _ = c.Write(append(append(msg, byte(len(p))), p...))
		_, _ = io.ReadFull(c, b)
		_, _ = c.Write(append([]byte{5, 1, 0, 4}, append(net.ParseIP("::1").To16(), byte(port>>8), byte(port))...))
		rep := make([]byte, 10)
		if _, err := io.ReadFull(c, rep); err != nil {
			t.Fatal(err)
		}
		return rep[1], bufio.NewReader(c), c
	}
	// direkt: IPv6 geht
	code, br, c := connect()
	if code != 0 {
		t.Fatalf("direkt IPv6: Antwort %d", code)
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	c.Close()
	if string(body) != "v6" {
		t.Fatalf("direkt IPv6: %q", body)
	}
	// über eine Gruppe: Ausgänge können nur IPv4 → Antwort 8 und Ereignis mit Hinweis
	f.env.Global.Groups = map[int64]proto.GroupRoute{5: {ID: 5, Name: "G", Enabled: true, Mark: 1 << 24}}
	f.env.Global.Policies = map[int64]*proto.Policy{f.sb.Peers[0].Peer.ID: {Key: "t", Rules: []proto.RouteRule{{All: true, Group: 5}}}}
	_ = (Driver{}).Apply(f.env, []*proto.ServerBundle{f.sb})
	if code, _, c := connect(); code != 8 {
		t.Fatalf("Gruppe IPv6: Antwort %d", code)
	} else {
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(logs, "\n"), "Ausgangsgruppen können nur IPv4") {
		t.Fatalf("keine Meldung: %v", logs)
	}
}

func TestBlocked(t *testing.T) {
	for _, s := range []string{"10.10.10.1", "100.100.1.1", "fd10:10:10::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1", "2001:db8::1", "ff02::1"} {
		if !blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s nicht gesperrt", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s gesperrt", s)
		}
	}
	self := []netip.Prefix{hostPrefix(netip.MustParseAddr("51.77.247.118")), hostPrefix(netip.MustParseAddr("2001:41d0:203:4a76::10"))}
	for _, s := range []string{"51.77.247.118", "2001:41d0:203:4a76::1"} {
		if !inPrefixes(self, netip.MustParseAddr(s)) {
			t.Errorf("%s (Server selbst) nicht erkannt", s)
		}
	}
	if inPrefixes(self, netip.MustParseAddr("51.77.247.119")) {
		t.Error("Nachbar-IPv4 fälschlich gesperrt")
	}
}
