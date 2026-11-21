package engine

import (
	"fmt"
	"sort"
	"strings"

	"vpnpanel/internal/store"
)

// SmartDNS-Profile (Objekte „smartdns“): Diese Domains laufen über eine Ausgangsgruppe
// (z. B. Netflix über „USA“). Unabhängig von den Filterprofilen, mit eigener Zuordnung:
//
//	global      alle Geräte (mit und ohne VPN)
//	vpn         alle VPN-Geräte (WireGuard, OpenVPN, VLESS, Hysteria2 – je nach Ziel-Regel-Unterstützung)
//	ext         alle Geräte ohne VPN (DNS von außen, DoH/DoT)
//	server:<id> user:<id> peer:<id>   VPN-Geräte eines Servers / Nutzers / ein Gerät
//	client:<id> ein Gerät ohne VPN
//
// Mehrere Profile wirken zusammen; gibt es dieselbe Domain mehrfach, gilt die genauere Zuordnung
// (Gerät vor Nutzer vor Server vor „alle mit/ohne VPN“ vor „alle“), auf derselben Ebene das ältere Profil.
// VPN-Geräte: wie eine Ziel-Regel. Geräte ohne VPN: Der DNS antwortet mit der Adresse des Servers,
// der die HTTPS-Verbindung anhand des Namens (SNI) über die Gruppe weiterreicht (smartproxy.go).

// SmartProfile: ein SmartDNS-Profil.
type SmartProfile struct {
	ID      int64
	Name    string
	Enabled bool
	Assign  []string
	Routes  []SmartRoute
}

func SmartProfileFrom(o *store.Object) *SmartProfile {
	return &SmartProfile{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Assign: strs(o.Data["assign"]), Routes: ParseSmart(o.Data["routes"])}
}

// smartRule: wirksamer Teil eines Profils für ein Gerät (wird zur Ziel-Regel).
type smartRule struct {
	ID      int64
	Profile int64
	Group   int64
	Domains []string
	Scope   string // Zuordnung, über die die Regel kommt (peer:3, vpn, global …)
}

// smartSet: SmartDNS eines Geräts.
type smartSet struct {
	rules []smartRule
	m     map[string]int64 // Domain → Gruppe
}

// match: Läuft der Name per SmartDNS über eine Gruppe? (Unterdomains zählen mit.)
func (s *smartSet) match(name string) (group int64, domain string, ok bool) {
	if s == nil || len(s.m) == 0 {
		return 0, "", false
	}
	for n := name; ; {
		if g, ok := s.m[n]; ok {
			return g, n, true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return 0, "", false
		}
		n = n[i+1:]
	}
}

// smartProfiles: aktive SmartDNS-Profile (nach ID).
func (e *Engine) smartProfiles() []*SmartProfile {
	objs, _ := e.St.Objects("smartdns")
	var out []*SmartProfile
	for _, o := range objs {
		if p := SmartProfileFrom(o); p.Enabled && len(p.Routes) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// smartFor setzt die SmartDNS eines Geräts aus den Zuordnungen zusammen (scopes: genaueste zuerst).
func smartFor(profiles []*SmartProfile, scopes ...string) *smartSet {
	var s *smartSet
	for _, sc := range scopes {
		for _, p := range profiles {
			hit := false
			for _, a := range p.Assign {
				if a == sc {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			for i, r := range p.Routes {
				var doms []string
				for _, d := range r.Domains {
					if s == nil {
						s = &smartSet{m: map[string]int64{}}
					}
					if _, taken := s.m[d]; !taken {
						s.m[d] = r.Group
						doms = append(doms, d)
					}
				}
				if len(doms) > 0 {
					s.rules = append(s.rules, smartRule{ID: SmartRuleID(p.ID, i), Profile: p.ID, Group: r.Group, Domains: doms, Scope: sc})
				}
			}
		}
	}
	return s
}

// compileSmart: SmartDNS je VPN-Gerät.
func (e *Engine) compileSmart(snap *Snapshot) map[int64]*smartSet {
	out := map[int64]*smartSet{}
	profiles := e.smartProfiles()
	if len(profiles) == 0 {
		return out
	}
	for id, pb := range snap.Peers {
		if s := smartFor(profiles, fmt.Sprintf("peer:%d", id), fmt.Sprintf("user:%d", pb.User.ID), fmt.Sprintf("server:%d", pb.Peer.ServerID), "vpn", "global"); s != nil {
			out[id] = s
		}
	}
	return out
}

// smartForClient: SmartDNS eines Geräts ohne VPN.
func smartForClient(profiles []*SmartProfile, clientID int64) *smartSet {
	return smartFor(profiles, fmt.Sprintf("client:%d", clientID), "ext", "global")
}

// SmartDomains: alle SmartDNS-Domains aktiver Profile (für nginx).
func (e *Engine) SmartDomains() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range e.smartProfiles() {
		for _, r := range p.Routes {
			for _, d := range r.Domains {
				if !seen[d] {
					seen[d] = true
					out = append(out, d)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// MigrateSmartDNS übernimmt SmartDNS-Einträge aus Filterprofilen (bis v0.30.0) in eigene
// SmartDNS-Profile mit derselben Zuordnung. Geräte ohne VPN, die das Filterprofil nutzten,
// werden dem neuen Profil einzeln zugeordnet. Danach steht in den Filterprofilen kein SmartDNS mehr.
func (e *Engine) MigrateSmartDNS() {
	profs, err := e.St.Objects("dnsprofile")
	if err != nil {
		return
	}
	clients, _ := e.St.Objects("dnsclient")
	for _, o := range profs {
		raw, ok := o.Data["smart"]
		if !ok {
			continue
		}
		routes := ParseSmart(raw)
		if len(routes) > 0 {
			p := DNSProfileFrom(o)
			// „alle“ galt im Filterprofil nur für VPN-Geräte und Geräte ohne VPN ohne eigenes Profil
			var assign []string
			global := false
			for _, a := range p.Assign {
				if a == "global" {
					global = true
					a = "vpn"
				}
				assign = append(assign, a)
			}
			for _, c := range clients {
				cl := DNSClientFrom(c)
				// Profil 0 = Geräte ohne VPN mit dem Profil für „alle“
				if cl.Profile == o.ID || (cl.Profile == 0 && global) {
					assign = append(assign, fmt.Sprintf("client:%d", cl.ID))
				}
			}
			var rs []any
			for _, r := range routes {
				rs = append(rs, map[string]any{"group": r.Group, "domains": r.Domains})
			}
			n := &store.Object{Kind: "smartdns", Name: o.Name, Enabled: o.Enabled, Data: store.M{"assign": assign, "routes": rs}, Secrets: store.M{}}
			if err := e.St.SaveObject(n); err != nil {
				e.Log("error", "SmartDNS aus Filterprofil „"+o.Name+"“ übernehmen: "+err.Error())
				continue
			}
			e.Log("info", "SmartDNS aus Filterprofil „"+o.Name+"“ in ein eigenes SmartDNS-Profil übernommen")
		}
		delete(o.Data, "smart")
		_ = e.St.SaveObject(o)
	}
}

// SmartUsing: SmartDNS-Profile, die eine Ausgangsgruppe verwenden (Löschschutz).
func (e *Engine) SmartUsing(groupID int64) []string {
	objs, _ := e.St.Objects("smartdns")
	var out []string
	for _, o := range objs {
		for _, r := range SmartProfileFrom(o).Routes {
			if r.Group == groupID {
				out = append(out, o.Name)
				break
			}
		}
	}
	return out
}
