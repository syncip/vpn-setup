package engine

import (
	"regexp"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// TestDomainPatterns: Einträge gelten genau; Platzhalter nur, wo ein „*“ steht.
func TestDomainPatterns(t *testing.T) {
	for in, want := range map[string]string{
		"Netflix.COM": "netflix.com", "*.netflix.com": "*.netflix.com", "netflix.*": "netflix.*", "ipv4-*.nflxvideo.net": "ipv4-*.nflxvideo.net",
		"*nflx*": "*nflx*", "**.nflx**.net": "*.nflx*.net", "*": "", "*.*": "", "a*": "", "net flix.*": "", "kaputt..x": "", "*.com": "",
		".netflix.com": "netflix.com",
	} {
		if got := CleanDomainEntry(in); got != want {
			t.Errorf("CleanDomainEntry(%q) = %q, erwartet %q", in, got, want)
		}
	}
	m := func(p, host string) bool { return proto.DomainMatch([]string{p}, host) }
	cases := []struct {
		p, host string
		ok      bool
	}{
		{"netflix.com", "netflix.com", true},
		{"netflix.com", "api.netflix.com", false}, // ohne „*“ genau dieser Name
		{"*.netflix.com", "api.netflix.com", true},
		{"*.netflix.com", "a.b.netflix.com", true},
		{"*.netflix.com", "netflix.com", false},
		{"*.netflix.com", "notnetflix.com", false},
		{"netflix.*", "netflix.de", true},
		{"netflix.*", "netflix.co.uk", true},
		{"netflix.*", "www.netflix.de", false},
		{"netflix.*", "notnetflix.de", false},
		{"ipv4-*.nflxvideo.net", "ipv4-c001-fra.nflxvideo.net", true},
		{"ipv4-*.nflxvideo.net", "ipv6-c001.nflxvideo.net", false},
		{"*nflx*", "occ-0-1.nflxso.net", true},
		{"*nflx*", "netflix.com", false},
	}
	for _, c := range cases {
		if got := m(c.p, c.host); got != c.ok {
			t.Errorf("%s ~ %s = %v", c.p, c.host, got)
		}
		if proto.IsDomainPattern(c.p) {
			re := regexp.MustCompile(proto.DomainPatternRegexp(c.p))
			if re.MatchString(c.host) != c.ok {
				t.Errorf("Regexp %s ~ %s", re, c.host)
			}
		}
	}
	// interne Listen (DoH-Anbieter) zählen Unterdomains weiter mit
	if !proto.DomainSuffixMatch([]string{"dns.google"}, "x.dns.google") || proto.DomainSuffixMatch([]string{"dns.google"}, "xdns.google") {
		t.Error("DomainSuffixMatch")
	}
	// Proxy: „*“ ohne Punkte, außer „*.“ am Anfang
	for _, c := range []struct {
		p, host string
		ok      bool
	}{
		{"netflix.*", "netflix.de", true},
		{"netflix.*", "netflix.boese-domain.com", false},
		{"netflix.*", "netflix.co.uk", false},
		{"*.netflix.com", "a.b.netflix.com", true},
		{"*.netflix.com", "netflix.com", false},
		{"ipv4-*.nflxvideo.net", "ipv4-c001-fra.nflxvideo.net", true},
		{"ipv4-*.nflxvideo.net", "ipv4-x.boese.nflxvideo.net", false},
		{"*nflx*", "occ-0-1.nflxso.net", false}, // „*“ deckt nur einen Namensteil ab
		{"*.nflx*.net", "occ-0-1.nflxso.net", true},
		{"*.nflx*.net", "nflx.boese.com", false},
		{"*.disney*.*", "www.disneyplus.com", true},
		{"*.disney*.*", "disney.boese.example", false},
	} {
		if got := proto.DomainPatternMatchLabel(c.p, c.host); got != c.ok {
			t.Errorf("Label %s ~ %s = %v", c.p, c.host, got)
		}
		re := regexp.MustCompile(proto.DomainPatternRegexpLabel(c.p))
		if re.MatchString(c.host) != c.ok {
			t.Errorf("Label-Regexp %s ~ %s", re, c.host)
		}
	}
	// SmartDNS: genauer Name vor *.domain (nächste zuerst) vor übrigen Mustern
	prof := []*SmartProfile{{ID: 1, Enabled: true, Assign: []string{"global"}, Routes: []SmartRoute{
		{Group: 5, Domains: []string{"*nflx*", "*.nflxvideo.net"}}, {Group: 6, Domains: []string{"nflxvideo.net", "*.a.nflxvideo.net", "netflix.*"}}}}}
	s := smartFor(prof, "global")
	for host, g := range map[string]int64{"nflxvideo.net": 6, "b.nflxvideo.net": 5, "x.a.nflxvideo.net": 6, "b.nflxso.net": 5, "netflix.de": 6, "www.netflix.de": 0, "example.org": 0} {
		got, _, _ := s.match(host)
		if got != g {
			t.Errorf("SmartDNS %s → %d, erwartet %d", host, got, g)
		}
	}
	if rid, _, dom, ok := s.matchRule("netflix.fr"); !ok || dom != "netflix.*" || rid != SmartRuleID(1, 1) {
		t.Errorf("matchRule: %d %s", rid, dom)
	}
	if rid, _, dom, ok := s.matchRule("y.b.nflxvideo.net"); !ok || dom != "*.nflxvideo.net" || rid != SmartRuleID(1, 0) {
		t.Errorf("matchRule *.: %d %s", rid, dom)
	}
	if got := ParseSmart([]any{map[string]any{"group": float64(3), "domains": []any{"netflix.*", "*"}}}); len(got) != 1 || len(got[0].Domains) != 1 {
		t.Errorf("ParseSmart: %+v", got)
	}
	if ds, err := ParseRouteDomains("netflix.*\nhttps://www.example.org/x"); err != nil || len(ds) != 2 {
		t.Errorf("ParseRouteDomains: %v %v", ds, err)
	}
}

// TestMigrateExactDomains: Bestehende Einträge ohne „*“ bekommen einmalig ihr *.-Gegenstück.
func TestMigrateExactDomains(t *testing.T) {
	e, _ := newTest(t)
	g := saveObj(t, e, &store.Object{Kind: "group", Name: "USA", Enabled: true, Data: store.M{"slot": 2}})
	prof := saveObj(t, e, &store.Object{Kind: "smartdns", Name: "S", Enabled: true, Data: store.M{"assign": []string{"global"},
		"routes": []any{map[string]any{"group": float64(g.ID), "domains": []any{"netflix.com", "netflix.*", "*.bbc.co.uk", "bbc.co.uk"}}}}})
	rt := saveObj(t, e, &store.Object{Kind: "route", Name: "R", Enabled: true, Data: store.M{"match": "targets", "domains": []any{"example.org"}}})
	e.MigrateExactDomains()
	e.MigrateExactDomains() // nur einmal
	p, _ := e.St.Object("smartdns", prof.ID)
	if got := strings.Join(SmartProfileFrom(p).Routes[0].Domains, ","); got != "netflix.com,*.netflix.com,netflix.*,*.bbc.co.uk,bbc.co.uk" {
		t.Errorf("SmartDNS: %s", got)
	}
	r, _ := e.St.Object("route", rt.ID)
	if got := strings.Join(RouteFrom(r).Domains, ","); got != "example.org,*.example.org" {
		t.Errorf("Ziel-Regel: %s", got)
	}
	// Neue Einträge nach der Übernahme bleiben genau
	p.Data["routes"] = []any{map[string]any{"group": float64(g.ID), "domains": []any{"hulu.com"}}}
	_ = e.St.SaveObject(p)
	e.MigrateExactDomains()
	p, _ = e.St.Object("smartdns", prof.ID)
	if got := strings.Join(SmartProfileFrom(p).Routes[0].Domains, ","); got != "hulu.com" {
		t.Errorf("nach der Übernahme: %s", got)
	}
}
