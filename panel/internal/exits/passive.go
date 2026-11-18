package exits

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Passive Erkennung: Verbindungen über einen Ausgang, deren Aufbau hängt (TCP SYN ohne Antwort) –
// ein typisches Zeichen, dass ein Ziel die Adresse des Ausgangs sperrt (Pakete werden verworfen).
// Gelesen aus conntrack, gefiltert nach der Ausgangs-Markierung der Verbindung; kein eigener
// Verkehr, keine Prüfanfragen.

// Conn: eine Verbindung (Richtung vom Gerät bzw. Server zum Ziel).
type Conn struct {
	Src   netip.Addr
	SPort uint16
	Dst   netip.Addr
	DPort uint16
}

func (c Conn) Key() string { return fmt.Sprintf("%s:%d>%s:%d", c.Src, c.SPort, c.Dst, c.DPort) }

var ctLineRe = regexp.MustCompile(`src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)`)

// parseSynSent liest die Ausgabe von „conntrack -L -p tcp --state SYN_SENT“ (erste Richtung).
func parseSynSent(out string) []Conn {
	var res []Conn
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "SYN_SENT") {
			continue
		}
		m := ctLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		src, err1 := netip.ParseAddr(m[1])
		dst, err2 := netip.ParseAddr(m[2])
		sp, _ := strconv.Atoi(m[3])
		dp, _ := strconv.Atoi(m[4])
		if err1 != nil || err2 != nil || !dst.Is4() {
			continue
		}
		res = append(res, Conn{Src: src, SPort: uint16(sp), Dst: dst, DPort: uint16(dp)})
	}
	return res
}

// PendingConns: Verbindungen über den Ausgang id, die gerade im Aufbau hängen.
func (m *Manager) PendingConns(env *Env, id int64) ([]Conn, error) {
	m.mu.Lock()
	slot := m.slotOfExitLocked(id)
	m.mu.Unlock()
	if slot == 0 {
		return nil, nil
	}
	out, err := env.Sys.Run("conntrack", "-L", "-p", "tcp", "--state", "SYN_SENT",
		"-m", fmt.Sprintf("0x%08x/0x%08x", probeMark(slot), MarkMask))
	if err != nil && !strings.Contains(out, "flow entries") {
		return nil, err
	}
	return parseSynSent(out), nil
}
