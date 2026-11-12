package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"vpnpanel/internal/proto"
)

// Sperre für private Ziele: VPN-Nutzer (alle Protokolle) erreichen weder private Netze – darunter
// das interne Netz des Containers mit dem Proxmox-Host – noch Loopback oder die öffentlichen
// Adressen des Servers. Ausnahmen: Einstellung „private_allow“ (für alle) und Freigaben unter
// Netzwerk → Zugriff (je Gerät).

// ParsePrivateAllow: Netze/Adressen, eins pro Zeile bzw. mit Komma getrennt.
func ParsePrivateAllow(v string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == ';' }) {
		if i := strings.IndexByte(f, '#'); i == 0 {
			continue
		}
		var p netip.Prefix
		if a, err := netip.ParseAddr(f); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else if q, err := netip.ParsePrefix(f); err == nil {
			p = q.Masked()
		} else {
			return nil, fmt.Errorf("Ausnahme „%s“: bitte ein Netz (192.168.1.0/24) oder eine Adresse angeben", f)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("Ausnahme „%s“ ist zu groß", f)
		}
		if !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, p.String())
		}
	}
	if len(out) > 50 {
		return nil, fmt.Errorf("höchstens 50 Ausnahmen")
	}
	return out, nil
}

// selfAddrs: öffentliche Adressen des Servers (Domain bzw. IP aus den Einstellungen) – IPv4 genau,
// IPv6 als /64. Im Testmodus nur eingetragene IP-Adressen.
func (e *Engine) selfAddrs() []netip.Prefix {
	h := e.Setting("server_host")
	if h == "" {
		return nil
	}
	pfx := func(a netip.Addr) netip.Prefix {
		a = a.Unmap()
		if a.Is4() {
			return netip.PrefixFrom(a, 32)
		}
		p, _ := a.Prefix(64)
		return p
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return []netip.Prefix{pfx(a)}
	}
	if e.Sys.DryRun() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range ips {
		if !a.Unmap().IsPrivate() && !a.IsLoopback() {
			out = append(out, pfx(a))
		}
	}
	return out
}

func (e *Engine) privateGuard() *proto.PrivateGuard {
	if e.Setting("private_block") != "1" {
		return nil
	}
	g := &proto.PrivateGuard{Nets: append([]netip.Prefix{}, proto.PrivateBase...)}
	g.Nets = append(g.Nets, e.selfAddrs()...)
	list, _ := ParsePrivateAllow(e.Setting("private_allow"))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			g.Allow = append(g.Allow, p)
		}
	}
	sort.Slice(g.Nets, func(i, j int) bool { return g.Nets[i].String() < g.Nets[j].String() })
	return g
}
