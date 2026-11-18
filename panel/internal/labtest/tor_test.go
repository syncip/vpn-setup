//go:build lab

package labtest

// Labortest Tor-Ausgang ohne Tor-Netz: Die TUN-Schnittstelle ex914 wird wie im Panel über eine
// Markierung und eine eigene Tabelle angesprochen; dahinter läuft der Handler aus tor2socks, der
// statt an Tor an einen Test-SOCKS5-Server (127.0.0.1) und einen Test-DNS weitergibt.
//
//	GOOS=linux go test -c -tags lab -o labtest ./internal/labtest && sudo ./labtest -test.v -test.run Tor

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/tor2socks"
)

const (
	torLabDev  = "ex914"
	torLabSlot = 57
	torLabDst  = "198.51.100.77"
)

// fakeSocks: SOCKS5 ohne Anmeldung; merkt sich die Ziele und antwortet selbst mit „dst=<Ziel>“.
func fakeSocks(t *testing.T) (string, func() []string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 3)
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				h := make([]byte, 4)
				if _, err := io.ReadFull(c, h); err != nil || h[3] != 1 {
					return
				}
				a := make([]byte, 6)
				io.ReadFull(c, a)
				dst := fmt.Sprintf("%s:%d", net.IP(a[:4]), binary.BigEndian.Uint16(a[4:]))
				mu.Lock()
				seen = append(seen, dst)
				mu.Unlock()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				c.Read(buf) // HTTP-Anfrage
				body := "dst=" + dst
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// fakeDNS beantwortet A-Anfragen mit torLabDst.
func fakeDNS(t *testing.T) string {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			i := 12
			for i < n && q[i] != 0 {
				i += int(q[i]) + 1
			}
			i += 5
			if i > n {
				continue
			}
			resp := append([]byte{}, q[:i]...)
			resp[2], resp[3] = 0x81, 0x80
			binary.BigEndian.PutUint16(resp[6:], 1)
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
			resp = append(resp, net.ParseIP(torLabDst).To4()...)
			pc.WriteTo(resp, from)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

func markDialer(mark uint32) *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return serr
	}}
}

func dnsQuery(name string) []byte {
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(append(q, byte(len(l))), l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func TestLabTor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	mark := exits.ProbeMark(torLabSlot)
	table := strconv.Itoa(2000 + torLabSlot)
	prio := strconv.Itoa(6100 + torLabSlot)
	cleanup := func() {
		quiet("ip", "rule", "del", "priority", prio)
		quiet("ip", "route", "flush", "table", table)
		quiet("ip", "link", "del", torLabDev)
	}
	cleanup()
	t.Cleanup(cleanup)
	sh(t, "ip", "tuntap", "add", "dev", torLabDev, "mode", "tun")
	sh(t, "ip", "addr", "add", "10.254.57.1/32", "dev", torLabDev, "noprefixroute")
	sh(t, "ip", "link", "set", "dev", torLabDev, "mtu", "1500", "up")
	sh(t, "ip", "route", "replace", "default", "dev", torLabDev, "table", table)
	sh(t, "ip", "route", "replace", "blackhole", "default", "metric", "10000", "table", table)
	sh(t, "ip", "rule", "add", "priority", prio, "fwmark", fmt.Sprintf("0x%x/0x7f000000", mark), "lookup", table)

	socks, seen := fakeSocks(t)
	dns := fakeDNS(t)
	h := &tor2socks.Handler{Socks: socks, DNS: dns, Log: func(s string) { t.Log(s) }}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tor2socks.Run(torLabDev, h, stop) }()
	defer func() {
		close(stop)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run endet nicht")
		}
	}()
	time.Sleep(300 * time.Millisecond)

	// 1. TCP: HTTP über die Markierung → Schnittstelle → SOCKS mit der richtigen Zieladresse
	cl := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: markDialer(mark).DialContext}}
	resp, err := cl.Get("http://" + torLabDst + "/x")
	if err != nil {
		t.Fatalf("HTTP über den Tor-Ausgang: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "dst="+torLabDst+":80" {
		t.Fatalf("Antwort %q", body)
	}
	if s := seen(); len(s) != 1 || s[0] != torLabDst+":80" {
		t.Fatalf("SOCKS sah: %v", s)
	}

	// 2. DNS (UDP 53 an einen beliebigen Server) → DNSPort
	uc, err := markDialer(mark).DialContext(context.Background(), "udp", "9.9.9.9:53")
	if err != nil {
		t.Fatal(err)
	}
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	uc.Write(dnsQuery("example.org"))
	buf := make([]byte, 1500)
	n, err := uc.Read(buf)
	uc.Close()
	if err != nil || n < 16 || net.IP(buf[n-4:n]).String() != torLabDst {
		t.Fatalf("DNS über den Tor-Ausgang: n=%d err=%v", n, err)
	}

	// 3. anderes UDP wird verworfen
	_, _, d0 := h.Stats()
	if uo, err := markDialer(mark).DialContext(context.Background(), "udp", torLabDst+":5000"); err == nil {
		uo.Write([]byte("x"))
		uo.SetReadDeadline(time.Now().Add(1 * time.Second))
		if _, err := uo.Read(buf); err == nil {
			t.Fatal("Antwort auf UDP (nicht DNS)")
		}
		uo.Close()
	}
	time.Sleep(200 * time.Millisecond)
	if _, _, d1 := h.Stats(); d1 <= d0 {
		t.Fatal("UDP (nicht DNS) nicht als verworfen gezählt")
	}

	// 4. Ping wird nicht beantwortet (sonst wirkte ein gestörtes Tor gesund)
	out, _ := exec.Command("ping", "-n", "-q", "-c", "2", "-W", "1", "-m", strconv.FormatUint(uint64(mark), 10), torLabDst).CombinedOutput()
	if !strings.Contains(string(out), "100% packet loss") {
		t.Fatalf("Ping über den Tor-Ausgang beantwortet:\n%s", out)
	}
	tcp, udp, dropped := h.Stats()
	t.Logf("TCP %d, DNS %d, verworfen %d", tcp, udp, dropped)
}
