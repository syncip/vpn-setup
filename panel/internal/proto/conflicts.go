package proto

import (
	"fmt"
	"net/netip"
	"strings"

	"vpnpanel/internal/store"
)

// Tunnelnetze und Ports über alle Protokolle hinweg prüfen: WireGuard und OpenVPN legen
// Netze auf dem Server an (Routen, Firewall), die sich nicht überschneiden dürfen.

// TunnelNet: ein Tunnelnetz eines anderen Servers.
type TunnelNet struct {
	Server string
	Prefix netip.Prefix
}

// TunnelNets liefert die Tunnelnetze (Einstellungen net4/net6) aller Server außer except.
func TunnelNets(all []*store.Server, except int64) []TunnelNet {
	var out []TunnelNet
	for _, s := range all {
		if s.ID == except {
			continue
		}
		for _, k := range []string{"net4", "net6"} {
			v := strings.TrimSpace(Str(s.Settings, k))
			if v == "" {
				continue
			}
			if p, err := netip.ParsePrefix(v); err == nil {
				out = append(out, TunnelNet{s.Name, p.Masked()})
			}
		}
	}
	return out
}

// NetConflict: Überschneidung mit einem anderen Tunnelnetz (leer = frei).
func NetConflict(all []*store.Server, except int64, p netip.Prefix) string {
	for _, t := range TunnelNets(all, except) {
		if t.Prefix.Overlaps(p) {
			return fmt.Sprintf("Tunnelnetz %s überschneidet sich mit %s von „%s“", p, t.Prefix, t.Server)
		}
	}
	return ""
}

// PortConflict: Port (bzw. Bereich from–to) des Protokolls proto („udp“/„tcp“) schon belegt?
// Prüft die Ports aller anderen Server und die festen Ports des Panels (TCP).
func PortConflict(g Global, all []*store.Server, except int64, proto string, from, to int) string {
	if to == 0 {
		to = from
	}
	if proto == "tcp" {
		pub := g.PublicPort
		if pub == 0 {
			pub = 443
		}
		fixed := []struct {
			p    int
			note string
		}{{pub, "nginx (Panel, Abo, VLESS)"}, {9443, "Webinterface"}, {8479, "Panel intern"}, {8480, "Panel intern"}, {10085, "Xray-API"}}
		for _, f := range fixed {
			if f.p >= from && f.p <= to {
				return fmt.Sprintf("TCP-Port %d ist belegt (%s)", f.p, f.note)
			}
		}
		if from <= 8499 && to >= 8443 {
			return "TCP-Ports 8443–8499 sind für Xray reserviert"
		}
		if from <= 26399 && to >= 25400 {
			return "TCP-Ports 25400–26399 sind für die Hysteria2-Statistik reserviert"
		}
	}
	for _, o := range all {
		if o.ID == except {
			continue
		}
		d, ok := Get(o.Protocol)
		if !ok {
			continue
		}
		for _, p := range d.Ports(o) {
			if p.Proto != proto {
				continue
			}
			end := p.To
			if end == 0 {
				end = p.Port
			}
			if from <= end && to >= p.Port {
				return fmt.Sprintf("%s-Port %d wird schon von „%s“ verwendet", strings.ToUpper(proto), p.Port, o.Name)
			}
		}
	}
	return ""
}
