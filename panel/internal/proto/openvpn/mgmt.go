package openvpn

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OpenVPN bedient nur eine Management-Verbindung gleichzeitig → Aufrufe (Live, Statistik,
// Trennen) nacheinander.
var mgmtMu sync.Mutex

// Management-Schnittstelle von OpenVPN (Unix-Socket, nur root): Liste der verbundenen
// Zugänge mit Zählern und Adresse, Trennen einzelner Zugänge.

type session struct {
	CN       string
	Real     string // öffentliche Adresse ohne Port
	Rx, Tx   int64  // Bytes vom Client empfangen (= Upload) bzw. an ihn gesendet (= Download)
	Since    int64  // verbunden seit (Unix)
	ClientID string
}

func mgmtCall(sock, cmd string, multi bool) ([]string, error) {
	mgmtMu.Lock()
	defer mgmtMu.Unlock()
	c, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil { // Begrüßung (>INFO:…)
		return nil, err
	}
	if _, err := fmt.Fprintf(c, "%s\n", cmd); err != nil {
		return nil, err
	}
	var out []string
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" && !strings.HasPrefix(line, ">") { // >…: Meldungen nebenbei
			if !multi {
				if strings.HasPrefix(line, "ERROR") {
					return nil, fmt.Errorf("%s", line)
				}
				return []string{line}, nil
			}
			if line == "END" {
				_, _ = fmt.Fprintf(c, "quit\n")
				return out, nil
			}
			out = append(out, line)
		}
		if err != nil {
			return out, fmt.Errorf("Management-Antwort unvollständig: %w", err)
		}
	}
}

// sessions liest „status 3“ (tabulatorgetrennt, Spalten laut HEADER-Zeile).
func sessions(sock string) ([]session, error) {
	lines, err := mgmtCall(sock, "status 3", true)
	if err != nil {
		return nil, err
	}
	return parseStatus(lines), nil
}

func parseStatus(lines []string) []session {
	col := map[string]int{}
	var out []session
	for _, l := range lines {
		f := strings.Split(l, "\t")
		switch {
		case len(f) > 2 && f[0] == "HEADER" && f[1] == "CLIENT_LIST":
			for i, n := range f[2:] {
				col[n] = i + 1
			}
		case len(f) > 1 && f[0] == "CLIENT_LIST" && len(col) > 0:
			get := func(n string) string {
				if i, ok := col[n]; ok && i < len(f) {
					return f[i]
				}
				return ""
			}
			s := session{CN: get("Common Name"), Real: realAddr(get("Real Address")), ClientID: get("Client ID")}
			s.Rx, _ = strconv.ParseInt(get("Bytes Received"), 10, 64)
			s.Tx, _ = strconv.ParseInt(get("Bytes Sent"), 10, 64)
			s.Since, _ = strconv.ParseInt(get("Connected Since (time_t)"), 10, 64)
			if s.CN != "" && s.CN != "UNDEF" {
				out = append(out, s)
			}
		}
	}
	return out
}

// realAddr: öffentliche Adresse ohne Port. OpenVPN schreibt je nach Version und Socket z. B.
// „1.2.3.4:5555“, „[AF_INET]1.2.3.4:5555“, „[AF_INET6]::ffff:1.2.3.4:5555“, „udp6:[2001:db8::1]:5555“
// oder „2001:db8::1:5555“ (der Port ist dort immer die letzte Gruppe).
var (
	addrPrefixRe = regexp.MustCompile(`^(\[AF_INET6?\]|(udp|tcp)[46]?(-server|-client)?:)`)
	v4TailRe     = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$`)
)

func realAddr(v string) string {
	v = addrPrefixRe.ReplaceAllString(strings.TrimSpace(v), "")
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap().String()
	}
	if m := v4TailRe.FindStringSubmatch(v); m != nil { // IPv4, auch als ::ffff:1.2.3.4
		if a, err := netip.ParseAddr(m[1]); err == nil {
			return a.String()
		}
	}
	v = strings.Trim(v, "[]")
	if i := strings.LastIndex(v, ":"); i > 0 {
		if a, err := netip.ParseAddr(strings.Trim(v[:i], "[]")); err == nil {
			return a.Unmap().String()
		}
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().String()
	}
	return v
}

// kill trennt eine Verbindung („client-kill“: der Client bekommt sofort RESTART, verbindet neu
// und wird dann abgewiesen – „kill <CN>“ würde ihn erst nach dem Keepalive-Timeout merken lassen).
func kill(sock, clientID string) error {
	if _, err := strconv.ParseUint(clientID, 10, 64); err != nil {
		return fmt.Errorf("Client-ID %q ungültig", clientID)
	}
	_, err := mgmtCall(sock, "client-kill "+clientID, false)
	return err
}
