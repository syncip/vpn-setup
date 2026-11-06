// Package shaping verwaltet die Geschwindigkeitsbegrenzung auf der Internet-Schnittstelle
// (eth0) für alle Protokolle gemeinsam. Treiber melden Regeln an, die Engine spielt sie
// einmal pro Anwenden ein (eine Schnittstelle kann nur einen Satz qdiscs haben).
//
//   - ausgehend (Egress):  HTB direkt auf eth0
//   - eingehend (Ingress): eth0-Ingress → connmark zurückholen → ifb „ifbvl“ → HTB
//
// Zuordnung über Paketmarkierungen (VLESS: Xray setzt sockopt.mark) oder über die
// Adresse des Gegenübers (Hysteria2: Client-IP aus der Anmeldung).
package shaping

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"vpnpanel/internal/system"
)

const (
	IfbDev   = "ifbvl"
	stateKey = "tc:eth"
)

// Rule: eine Begrenzung (z. B. ein Nutzer). Raten in Mbit/s, 0 = frei.
type Rule struct {
	Key     string  // eindeutig, z. B. „vl-u5“
	Egress  float64 // Richtung Internet-Schnittstelle hinaus
	Ingress float64 // Richtung herein
	Mark    uint32  // Paketmarkierung (0 = keine)
	Addrs   []netip.Addr
	Port    int // eigener Port der Verbindung (Egress: Quellport, Ingress: Zielport), 0 = alle
}

type Plan struct {
	mu    sync.Mutex
	rules []Rule
}

func (p *Plan) Add(r Rule) {
	if p == nil || (r.Egress <= 0 && r.Ingress <= 0) || (r.Mark == 0 && len(r.Addrs) == 0) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = append(p.rules, r)
}

func (p *Plan) Rules() []Rule {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append([]Rule(nil), p.rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func mbit(v float64) string { return strconv.FormatFloat(v*1000, 'f', 0, 64) + "kbit" }

// filters erzeugt die tc-Filter einer Regel für eine Richtung.
func filters(dev, cls string, r Rule, ingress bool) [][]string {
	var out [][]string
	if r.Mark != 0 {
		out = append(out, []string{"filter", "add", "dev", dev, "parent", "1:", "protocol", "all", "prio", "1",
			"handle", strconv.FormatUint(uint64(r.Mark), 10), "fw", "flowid", cls})
	}
	for _, a := range r.Addrs {
		a = a.Unmap()
		peer, own := "dst", "sport"
		if ingress {
			peer, own = "src", "dport"
		}
		if a.Is4() {
			f := []string{"filter", "add", "dev", dev, "parent", "1:", "protocol", "ip", "prio", "2", "u32",
				"match", "ip", peer, a.String() + "/32"}
			if r.Port > 0 {
				f = append(f, "match", "ip", own, strconv.Itoa(r.Port), "0xffff")
			}
			out = append(out, append(f, "flowid", cls))
		} else {
			f := []string{"filter", "add", "dev", dev, "parent", "1:", "protocol", "ipv6", "prio", "3", "u32",
				"match", "ip6", peer, a.String() + "/128"}
			if r.Port > 0 {
				f = append(f, "match", "ip6", own, strconv.Itoa(r.Port), "0xffff")
			}
			out = append(out, append(f, "flowid", cls))
		}
	}
	return out
}

// Apply spielt den Plan ein. Unverändert (Prüfsumme) → nichts tun.
func Apply(sys system.Runner, dev string, p *Plan, get func(string) string, set func(string, string), log func(string, string)) error {
	if dev == "" {
		dev = "eth0"
	}
	rules := p.Rules()
	var sig strings.Builder
	sig.WriteString(dev + "\n")
	for _, r := range rules {
		fmt.Fprintf(&sig, "%s %.2f %.2f %d %d %v\n", r.Key, r.Egress, r.Ingress, r.Mark, r.Port, r.Addrs)
	}
	h := ""
	if len(rules) > 0 {
		s := sha256.Sum256([]byte(sig.String()))
		h = hex.EncodeToString(s[:8])
	}
	if get(stateKey) == h && get("tc:vless") == "" {
		return nil
	}
	set("tc:vless", "") // alter Schlüssel vor dem gemeinsamen Paket

	clear := func() {
		_, _ = sys.Run("tc", "qdisc", "del", "dev", dev, "root")
		_, _ = sys.Run("tc", "qdisc", "del", "dev", dev, "ingress")
		_, _ = sys.Run("tc", "qdisc", "del", "dev", IfbDev, "root")
	}
	clear()
	anyMark, anyIn := false, false
	for _, r := range rules {
		anyMark = anyMark || r.Mark != 0
		anyIn = anyIn || r.Ingress > 0
	}
	// Markierung der Verbindung merken, damit Antworten (eingehend) zugeordnet werden können
	for _, bin := range []string{"iptables", "ip6tables"} {
		if anyMark {
			rs := "*mangle\n:VPNVL - [0:0]\n-F VPNVL\n-A VPNVL -m mark ! --mark 0 -j CONNMARK --save-mark\nCOMMIT\n"
			if _, err := sys.RunInput(rs, bin+"-restore", "-n"); err != nil {
				return err
			}
			if _, err := sys.Run(bin, "-t", "mangle", "-C", "OUTPUT", "-j", "VPNVL"); err != nil {
				if _, err := sys.Run(bin, "-t", "mangle", "-A", "OUTPUT", "-j", "VPNVL"); err != nil {
					return err
				}
			}
		} else {
			_, _ = sys.Run(bin, "-t", "mangle", "-D", "OUTPUT", "-j", "VPNVL")
		}
	}
	if len(rules) == 0 {
		_, _ = sys.Run("ip", "link", "del", IfbDev)
		set(stateKey, "")
		return nil
	}
	run := func(args ...string) error { _, err := sys.Run("tc", args...); return err }
	fail := func(err error) error { clear(); set(stateKey, ""); return err }

	if err := run("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "1"); err != nil {
		return fail(err)
	}
	if err := run("class", "add", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"); err != nil {
		return fail(err)
	}
	for i, r := range rules {
		if r.Egress <= 0 {
			continue
		}
		cls := fmt.Sprintf("1:%x", i+0x10)
		if err := run("class", "add", "dev", dev, "parent", "1:", "classid", cls, "htb", "rate", mbit(r.Egress), "ceil", mbit(r.Egress)); err != nil {
			return fail(err)
		}
		for _, f := range filters(dev, cls, r, false) {
			if err := run(f...); err != nil {
				return fail(err)
			}
		}
	}
	if anyIn {
		_, _ = sys.Run("ip", "link", "add", IfbDev, "type", "ifb")
		if _, err := sys.Run("ip", "link", "set", IfbDev, "up"); err != nil {
			set(stateKey, h)
			return fmt.Errorf("ifb-Gerät nicht verfügbar (Modul ifb auf dem Host laden): %v – nur ausgehend wird begrenzt", err)
		}
		steps := [][]string{
			{"qdisc", "add", "dev", IfbDev, "root", "handle", "1:", "htb", "default", "1"},
			{"class", "add", "dev", IfbDev, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"},
		}
		for i, r := range rules {
			if r.Ingress <= 0 {
				continue
			}
			cls := fmt.Sprintf("1:%x", i+0x10)
			steps = append(steps, []string{"class", "add", "dev", IfbDev, "parent", "1:", "classid", cls, "htb", "rate", mbit(r.Ingress), "ceil", mbit(r.Ingress)})
			steps = append(steps, filters(IfbDev, cls, r, true)...)
		}
		steps = append(steps,
			[]string{"qdisc", "add", "dev", dev, "handle", "ffff:", "ingress"},
			[]string{"filter", "add", "dev", dev, "parent", "ffff:", "protocol", "all", "prio", "1", "u32", "match", "u32", "0", "0",
				"action", "connmark", "action", "mirred", "egress", "redirect", "dev", IfbDev})
		for _, s := range steps {
			if err := run(s...); err != nil {
				_, _ = sys.Run("tc", "qdisc", "del", "dev", dev, "ingress")
				_, _ = sys.Run("tc", "qdisc", "del", "dev", IfbDev, "root")
				set(stateKey, h)
				return fmt.Errorf("eingehende Begrenzung nicht möglich (Module act_connmark/act_mirred auf dem Host laden?): %v – nur ausgehend wird begrenzt", err)
			}
		}
	} else {
		_, _ = sys.Run("ip", "link", "del", IfbDev)
	}
	set(stateKey, h)
	if log != nil {
		log("info", fmt.Sprintf("Geschwindigkeitsbegrenzung auf %s aktualisiert (%d Regeln)", dev, len(rules)))
	}
	return nil
}
