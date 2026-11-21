package engine

import (
	"fmt"
	"sort"
	"strconv"
)

// Hilfen für die Übersicht „Was gilt?“ (System → Was gilt?): dieselbe Auswahl wie beim Anwenden,
// aber mit Herkunft (über welche Zuordnung eine Einstellung kommt).

// EffProfile: wirksames Filterprofil.
type EffProfile struct {
	ID       int64
	Name     string
	Scope    string   // Zuordnung, über die es gilt (peer:3, user:1, server:2, global, client:…)
	Lists    []string // aktive Blocklisten
	Rules    int      // eigene Regeln (Sperren, Freigaben, Umschreibungen)
	BlockDoH bool
	NXDomain bool
}

// DNSProfileFor: das Filterprofil der ersten passenden Zuordnung (wie beim Anwenden: je Ebene das
// älteste aktive Profil). „id:<n>“ wählt ein Profil direkt (Geräte ohne VPN). nil = kein Profil.
func (e *Engine) DNSProfileFor(scopes ...string) *EffProfile {
	objs, _ := e.St.Objects("dnsprofile")
	if len(objs) == 0 {
		return nil
	}
	lists := map[int64]*DNSList{}
	if lo, err := e.St.Objects("dnslist"); err == nil {
		for _, o := range lo {
			if l := DNSListFrom(o); l.Enabled {
				lists[l.ID] = l
			}
		}
	}
	for _, sc := range scopes {
		for _, o := range objs {
			p := DNSProfileFrom(o)
			if !p.Enabled || !(hasStr(p.Assign, sc) || sc == fmt.Sprintf("id:%d", p.ID)) {
				continue
			}
			out := &EffProfile{ID: p.ID, Name: p.Name, Scope: sc, BlockDoH: p.BlockDoH, NXDomain: p.NXDomain}
			for _, id := range p.Lists {
				if l := lists[id]; l != nil {
					out.Lists = append(out.Lists, l.Name)
				}
			}
			if r, err := ParseDNSRules(p.Rules); err == nil {
				out.Rules = len(r.Block) + len(r.Allow) + len(r.Rewrite)
			}
			return out
		}
	}
	return nil
}

func hasStr(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

// EffSmart: eine wirksame SmartDNS-Weiterleitung.
type EffSmart struct {
	Profile     int64
	ProfileName string
	Scope       string
	Group       int64
	Domains     []string
}

// SmartFor: SmartDNS für die Zuordnungen (genaueste zuerst), wie beim Anwenden zusammengesetzt.
func (e *Engine) SmartFor(scopes ...string) []EffSmart {
	profiles := e.smartProfiles()
	names := map[int64]string{}
	for _, p := range profiles {
		names[p.ID] = p.Name
	}
	s := smartFor(profiles, scopes...)
	if s == nil {
		return nil
	}
	out := make([]EffSmart, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, EffSmart{Profile: r.Profile, ProfileName: names[r.Profile], Scope: r.Scope, Group: r.Group, Domains: r.Domains})
	}
	return out
}

// PeerScopes: Zuordnungen eines VPN-Geräts, genaueste zuerst.
func PeerScopes(peer, user, server int64) []string {
	return []string{fmt.Sprintf("peer:%d", peer), fmt.Sprintf("user:%d", user), fmt.Sprintf("server:%d", server)}
}

// EffACL: Sperr- und Freigabelisten (eingehende Verbindungen) eines Servers.
type EffACL struct {
	Deny, Allow []string
}

// ACLFor: IP-Listen, die für die Verbindungen zu einem Server gelten.
func (e *Engine) ACLFor(server int64) EffACL {
	var out EffACL
	plan := e.aclPlan()
	a := plan.ByServer[server]
	if a == nil {
		return out
	}
	for _, id := range a.Deny {
		if l := plan.Lists[id]; l != nil {
			out.Deny = append(out.Deny, l.Name)
		}
	}
	for _, id := range a.Allow {
		if l := plan.Lists[id]; l != nil {
			out.Allow = append(out.Allow, l.Name)
		}
	}
	sort.Strings(out.Deny)
	sort.Strings(out.Allow)
	return out
}

// PrivateBlock: Sperre privater Netze aktiv? (Zusatz-Freigaben)
func (e *Engine) PrivateBlock() (on bool, allow int) {
	g := e.privateGuard()
	if g == nil {
		return false, 0
	}
	return true, len(g.Allow)
}

// ExtRateOf: wirksame Begrenzung eines Geräts ohne VPN (Anfragen je Sekunde, kurzzeitig; 0 = keine).
func (e *Engine) ExtRateOf(c *DNSClient) (rate, burst float64) {
	return extRateOf(atoi(e.Setting("dns_ext_rate"), defExtRate), atoi(e.Setting("dns_ext_burst"), defExtBurst), c.Rate, c.Burst)
}

// DNSPublic: DNS von außen (Port 53) eingeschaltet?
func (e *Engine) DNSPublic() bool { return e.dnsPublic() }

// ToInt64: Zahl aus gespeicherten Einstellungen (JSON-Zahl oder Text).
func ToInt64(v any) int64 {
	if s, ok := v.(string); ok {
		n, _ := strconv.ParseInt(s, 10, 64)
		return n
	}
	return numData(v)
}
