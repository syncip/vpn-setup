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
