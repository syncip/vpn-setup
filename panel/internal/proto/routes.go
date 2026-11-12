package proto

import (
	"net/netip"
	"strings"
)

// Ziel-Regeln („Routen“): welcher Verkehr eines Zugangs über welche Ausgangsgruppe geht.
// Die Engine stellt pro Zugang die wirksame Regelfolge zusammen (Gerät vor Nutzer vor Server
// vor Global, innerhalb einer Ebene Ziel-Regeln vor „alles“); die erste passende Regel gilt.

// RouteRule ist eine Regel in der Folge eines Zugangs.
type RouteRule struct {
	ID      int64          // ID der Regel (0 = aus der Server-Einstellung „Ausgang“ des Proxys)
	All     bool           // alle Ziele
	Nets    []netip.Prefix // IPv4-Netze der Regel selbst
	Lists   []int64        // Ziellisten (IP-Listen der Art „Ziele“), Inhalt in Global.TargetLists
	Domains []string       // Domains samt Unterdomains, kleingeschrieben, ohne Punkt am Ende
	Group   int64          // Ausgangsgruppe; 0 = direkt über den Server (Ausnahme)
}

// Policy: Regelfolge eines Zugangs bzw. Servers. Gleiche Folgen teilen sich denselben Key.
type Policy struct {
	Key   string
	Rules []RouteRule
}

// HasDomains: enthält die Folge Domain-Regeln?
func (p *Policy) HasDomains() bool {
	if p == nil {
		return false
	}
	for _, r := range p.Rules {
		if len(r.Domains) > 0 {
			return true
		}
	}
	return false
}

// AllGroup: Gruppe der „alles“-Regel (ok = es gibt eine).
func (p *Policy) AllGroup() (group int64, ok bool) {
	if p == nil {
		return 0, false
	}
	for _, r := range p.Rules {
		if r.All {
			return r.Group, true
		}
	}
	return 0, false
}

// DomainMatch: passt host (kleingeschrieben) auf eine der Domains (gleich oder Unterdomain)?
func DomainMatch(domains []string, host string) bool {
	host = strings.TrimSuffix(host, ".")
	for _, d := range domains {
		if host == d || (len(host) > len(d) && strings.HasSuffix(host, d) && host[len(host)-len(d)-1] == '.') {
			return true
		}
	}
	return false
}

// MatchDomain: erste Regel, deren Domains auf host passen (für die DNS-Auswertung). Eine
// „alles“-Regel davor beendet die Suche nicht – sie steht per Aufbau immer am Ende.
func (p *Policy) MatchDomain(host string) (RouteRule, bool) {
	if p == nil {
		return RouteRule{}, false
	}
	host = strings.ToLower(host)
	for _, r := range p.Rules {
		if len(r.Domains) > 0 && DomainMatch(r.Domains, host) {
			return r, true
		}
	}
	return RouteRule{}, false
}

// Match: Gruppe für ein Ziel (host = Name, falls bekannt; ip = Adresse, falls bekannt).
// ok = false: keine Regel passt → direkt über den Server.
func (p *Policy) Match(host string, ip netip.Addr, lists map[int64][]netip.Prefix) (group int64, ok bool) {
	if p == nil {
		return 0, false
	}
	host = strings.ToLower(host)
	ip = ip.Unmap()
	for _, r := range p.Rules {
		if r.All {
			return r.Group, true
		}
		if host != "" && len(r.Domains) > 0 && DomainMatch(r.Domains, host) {
			return r.Group, true
		}
		if ip.IsValid() {
			for _, n := range r.Nets {
				if n.Contains(ip) {
					return r.Group, true
				}
			}
			for _, id := range r.Lists {
				for _, n := range lists[id] {
					if n.Contains(ip) {
						return r.Group, true
					}
				}
			}
		}
	}
	return 0, false
}

// Forwarder: Treiber, deren Geräte als weitergeleiteter Verkehr mit fester Quelladresse am Server
// ankommen (WireGuard, OpenVPN). Die Engine leitet deren Verkehr per Firewall-Markierung über
// Ausgangsgruppen.
type Forwarder interface {
	// Sources: Zugang (Peer-ID) → Adressen und Netze, von denen sein Verkehr kommt.
	Sources(env *Env, sb *ServerBundle) map[int64][]netip.Prefix
}

// Networker: Treiber, deren Server ein Netz bilden, auf das Geräte anderer Server Zugriff bekommen
// können (WireGuard): Schnittstelle und Netze (Tunnelnetz und Netze hinter Geräten).
type Networker interface {
	Network(sb *ServerBundle) (iface string, nets []netip.Prefix)
}

// NetTarget: ein Netz, das ein Gerät erreichen darf (Freigabe unter Netzwerk → Zugriff).
type NetTarget struct {
	Server int64
	Name   string
	Iface  string
	Nets   []netip.Prefix
}

// NetAccess: Freigaben zwischen Netzen. Targets: Zugang (Peer-ID) → erreichbare Netze; Masq:
// Ziel-Schnittstelle → fremde Quelladressen, die dort per NAT die Adresse des Servers bekommen
// (die Geräte im Ziel-Netz kennen nur ihr eigenes Tunnelnetz als Rückweg).
type NetAccess struct {
	Targets map[int64][]NetTarget
	Masq    map[string][]netip.Prefix
}

// For: Netze, die ein Zugang zusätzlich erreichen darf (nil-sicher).
func (n *NetAccess) For(peer int64) []NetTarget {
	if n == nil {
		return nil
	}
	return n.Targets[peer]
}

// MasqFor: fremde Quellen, die auf dieser Schnittstelle per NAT umgeschrieben werden (nil-sicher).
func (n *NetAccess) MasqFor(iface string) []netip.Prefix {
	if n == nil {
		return nil
	}
	return n.Masq[iface]
}

// PrivateGuard: Ziele, die VPN-Nutzer nicht erreichen dürfen – private Netze (auch das interne
// Netz des Containers mit dem Proxmox-Host), Loopback, Link-local, CGNAT/Tailscale und die
// öffentlichen Adressen des Servers selbst. Allow: Ausnahmen für alle (Einstellung). Freigaben
// unter Netzwerk → Zugriff gelten zusätzlich je Gerät (Global.Net).
type PrivateGuard struct {
	Nets  []netip.Prefix
	Allow []netip.Prefix
}

// PrivateBase: die immer gesperrten Bereiche.
var PrivateBase = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "2002::/16"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// NeverNets: Loopback und „dieses Netz“ – darüber wären die internen Dienste des Servers erreichbar
// (Panel, Xray-API, Anmelde-Endpunkt für Hysteria2, DoH, SmartDNS-Proxy). Für Nutzer von VLESS und
// Hysteria2 immer gesperrt, auch wenn die Sperre privater Ziele ausgeschaltet ist; Ausnahmen dafür
// gibt es nicht.
var NeverNets = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::/127")}

// OverlapsNever: Netz enthält oder berührt einen Bereich aus NeverNets.
func OverlapsNever(p netip.Prefix) bool {
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
	}
	for _, n := range NeverNets {
		if n.Overlaps(p) {
			return true
		}
	}
	return false
}

// Blocked: alle gesperrten Netze (nil-sicher: ohne Wächter nichts).
func (g *PrivateGuard) Blocked() []netip.Prefix {
	if g == nil {
		return nil
	}
	return g.Nets
}

// Allowed: Ausnahmen (nil-sicher).
func (g *PrivateGuard) Allowed() []netip.Prefix {
	if g == nil {
		return nil
	}
	return g.Allow
}

// Split46 teilt Netze in IPv4 und IPv6.
func Split46(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}

// PrefixStrings: Netze als Text.
func PrefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
