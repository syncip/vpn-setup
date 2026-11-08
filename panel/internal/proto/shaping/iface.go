package shaping

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"vpnpanel/internal/system"
)

// IfaceRule: Begrenzung eines Geräts auf einer Tunnel-Schnittstelle (wg0, ovpn3 …).
// Down = Server → Gerät (HTB ausgehend), Up = Gerät → Server (Policer am Eingang). Mbit/s, 0 = frei.
type IfaceRule struct {
	ID       int64 // Zugang (bestimmt die tc-Klasse)
	Down, Up float64
	Prefixes []netip.Prefix // Adressen/Netze des Geräts im Tunnel
}

func ifaceHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:8]) }

// ApplyIface spielt die Begrenzungen einer Tunnel-Schnittstelle ein (Zustand unter „tc:<iface>“).
// Unverändert und noch vorhanden → nichts tun.
func ApplyIface(sys system.Runner, iface string, rules []IfaceRule, get func(string) string, set func(string, string)) error {
	var cmds [][]string
	anyDown, anyUp := false, false
	for _, r := range rules {
		anyDown = anyDown || r.Down > 0
		anyUp = anyUp || r.Up > 0
	}
	if anyDown {
		cmds = append(cmds,
			[]string{"qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "1"},
			[]string{"class", "add", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"})
		for _, r := range rules {
			if r.Down <= 0 {
				continue
			}
			cls := fmt.Sprintf("1:%x", r.ID+0x10)
			rate := mbit(r.Down)
			cmds = append(cmds, []string{"class", "add", "dev", iface, "parent", "1:", "classid", cls, "htb", "rate", rate, "ceil", rate})
			for _, p := range r.Prefixes {
				if p.Addr().Is4() {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dst", p.String(), "flowid", cls})
				} else {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ipv6", "prio", "2", "u32", "match", "ip6", "dst", p.String(), "flowid", cls})
				}
			}
		}
	}
	if anyUp {
		cmds = append(cmds, []string{"qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"})
		for _, r := range rules {
			if r.Up <= 0 {
				continue
			}
			rate := mbit(r.Up)
			burst := fmt.Sprintf("%dk", max(32, int(r.Up*1000/8/10))) // ~100 ms
			for _, p := range r.Prefixes {
				if p.Addr().Is4() {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "src", p.String(), "police", "rate", rate, "burst", burst, "drop", "flowid", ":1"})
				} else {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ipv6", "prio", "2", "u32", "match", "ip6", "src", p.String(), "police", "rate", rate, "burst", burst, "drop", "flowid", ":1"})
				}
			}
		}
	}
	var sig strings.Builder
	for _, c := range cmds {
		sig.WriteString(strings.Join(c, " ") + "\n")
	}
	h := ""
	if len(cmds) > 0 {
		h = ifaceHash(sig.String())
	}
	if get("tc:"+iface) == h {
		if h == "" {
			return nil
		}
		if out, err := sys.Run("tc", "qdisc", "show", "dev", iface); err == nil && (sys.DryRun() || strings.Contains(out, "htb") || strings.Contains(out, "ingress")) {
			return nil
		}
	}
	_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "root")
	_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "ingress")
	for _, c := range cmds {
		if _, err := sys.Run("tc", c...); err != nil {
			_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "root")
			_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "ingress")
			set("tc:"+iface, "")
			return err
		}
	}
	set("tc:"+iface, h)
	return nil
}
