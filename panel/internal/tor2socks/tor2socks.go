//go:build linux

// Package tor2socks macht aus einem Tor-SOCKS-Port eine Netzwerkschnittstelle (Tor-Ausgang):
// TCP-Verbindungen, die über die Schnittstelle exN hinausgehen, landen per SOCKS5 bei Tor;
// DNS-Anfragen (UDP 53, an beliebige Server) gehen an Tors DNSPort. Anderes UDP und ICMP verwirft
// der Ausgang – Tor kann beides nicht transportieren, und ein lokal beantworteter Ping würde
// einen gestörten Tor-Ausgang als gesund erscheinen lassen.
//
// Läuft als eigener Prozess („vpnpanel tun2socks“, Dienst vpn-t2s@exN) unter dem Benutzer der
// Tor-Instanz; die TUN-Schnittstelle legt das Panel dauerhaft an. Endet der Prozess, verwirft der
// Kernel die Pakete – nichts geht direkt hinaus.
package tor2socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

const (
	dialTimeout = 30 * time.Second // Tor braucht für neue Kreise manchmal einige Sekunden
	udpIdle     = 30 * time.Second
)

// Handler verbindet die Schnittstelle mit Tor.
type Handler struct {
	Socks string // 127.0.0.1:Port (SocksPort)
	DNS   string // 127.0.0.1:Port (DNSPort)
	Log   func(string)

	tcp, udp, dropped atomic.Int64
}

func (h *Handler) logf(f string, a ...any) {
	if h.Log != nil {
		h.Log(fmt.Sprintf(f, a...))
	}
}

// HandleTCP: Verbindung über Tor (SOCKS5 CONNECT zur Zieladresse).
func (h *Handler) HandleTCP(c adapter.TCPConn) {
	go func() {
		defer c.Close()
		id := c.ID()
		dst := addrPort(id.LocalAddress.AsSlice(), id.LocalPort)
		if !dst.IsValid() {
			return
		}
		up, err := DialSocks(h.Socks, dst, dialTimeout)
		if err != nil {
			h.dropped.Add(1)
			h.logf("TCP %s: %v", dst, err)
			return
		}
		defer up.Close()
		h.tcp.Add(1)
		relay(c, up)
	}()
}

// HandleUDP: nur DNS (Port 53) – an Tors DNSPort; alles andere wird verworfen.
func (h *Handler) HandleUDP(c adapter.UDPConn) {
	id := c.ID()
	if id.LocalPort != 53 || h.DNS == "" {
		h.dropped.Add(1)
		c.Close()
		return
	}
	go func() {
		defer c.Close()
		up, err := net.Dial("udp", h.DNS)
		if err != nil {
			return
		}
		defer up.Close()
		h.udp.Add(1)
		done := make(chan struct{})
		go func() { // Antworten zurück
			defer close(done)
			buf := make([]byte, 65535)
			for {
				_ = up.SetReadDeadline(time.Now().Add(udpIdle))
				n, err := up.Read(buf)
				if err != nil {
					c.Close()
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 65535)
		for {
			_ = c.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if _, err := up.Write(buf[:n]); err != nil {
				break
			}
		}
		up.Close()
		<-done
	}()
}

// HandlePacket: ICMP (Ping) – verworfen. Ohne diese Behandlung beantwortete der Stack jeden Ping
// selbst, und ein Tor-Ausgang ohne Verbindung zum Tor-Netz sähe gesund aus.
func (h *Handler) HandlePacket(adapter.Packet) bool {
	h.dropped.Add(1)
	return true
}

// Stats: Zähler (TCP-Verbindungen, DNS-Sitzungen, verworfen).
func (h *Handler) Stats() (tcp, udp, dropped int64) {
	return h.tcp.Load(), h.udp.Load(), h.dropped.Load()
}

func addrPort(ip []byte, port uint16) netip.AddrPort {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(a.Unmap(), port)
}

type closeWriter interface{ CloseWrite() error }

// relay kopiert in beide Richtungen; das Ende einer Richtung wird weitergegeben (halbes Schließen).
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// DialSocks: SOCKS5 CONNECT ohne Anmeldung (Tors SocksPort auf 127.0.0.1).
func DialSocks(proxy string, dst netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return nil, fmt.Errorf("Tor nicht erreichbar: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return fail(err)
	}
	if sel[0] != 5 || sel[1] != 0 {
		return fail(errors.New("SOCKS: Anmeldung verlangt"))
	}
	req := []byte{5, 1, 0}
	if dst.Addr().Is4() {
		a := dst.Addr().As4()
		req = append(append(req, 1), a[:]...)
	} else {
		a := dst.Addr().As16()
		req = append(append(req, 4), a[:]...)
	}
	req = binary.BigEndian.AppendUint16(req, dst.Port())
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	var rep [4]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return fail(err)
	}
	if rep[1] != 0 {
		return fail(fmt.Errorf("SOCKS: %s", socksErr(rep[1])))
	}
	skip := 0
	switch rep[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return fail(err)
		}
		skip = int(l[0])
	default:
		return fail(errors.New("SOCKS: ungültige Antwort"))
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip+2)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func socksErr(code byte) string {
	switch code {
	case 1:
		return "allgemeiner Fehler"
	case 2:
		return "nicht erlaubt"
	case 3:
		return "Netz nicht erreichbar"
	case 4:
		return "Ziel nicht erreichbar"
	case 5:
		return "Verbindung abgelehnt"
	case 6:
		return "Zeitüberschreitung (TTL)"
	default:
		return "Fehler " + strconv.Itoa(int(code))
	}
}
