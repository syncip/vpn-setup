package engine

import (
	"regexp"
	"testing"

	"vpnpanel/internal/proto"
)

// TestDomainPatterns: Platzhalter „*“ in SmartDNS und Ziel-Regeln.
func TestDomainPatterns(t *testing.T) {
	for in, want := range map[string]string{
		"Netflix.COM": "netflix.com", "*.netflix.com": "netflix.com", "netflix.*": "netflix.*", "ipv4-*.nflxvideo.net": "ipv4-*.nflxvideo.net",
		"*nflx*": "*nflx*", "**.nflx**.net": "nflx*.net", "*": "", "*.*": "", "a*": "", "net flix.*": "", "kaputt..x": "", "*.com": "",
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
		{"netflix.*", "netflix.de", true},
		{"netflix.*", "www.netflix.co.uk", true},
		{"netflix.*", "notnetflix.de", false},
		{"ipv4-*.nflxvideo.net", "ipv4-c001-fra.nflxvideo.net", true},
		{"ipv4-*.nflxvideo.net", "ipv6-c001.nflxvideo.net", false},
		{"*nflx*", "occ-0-1.nflxso.net", true},
		{"*nflx*", "netflix.com", false},
		{"netflix.com", "api.netflix.com", true},
	}
	for _, c := range cases {
		if got := m(c.p, c.host); got != c.ok {
			t.Errorf("%s ~ %s = %v", c.p, c.host, got)
		}
		re := regexp.MustCompile(proto.DomainPatternRegexp(c.p))
		if proto.IsDomainPattern(c.p) && re.MatchString(c.host) != c.ok {
			t.Errorf("Regexp %s ~ %s", re, c.host)
		}
	}
	// SmartDNS: feste Domain vor Muster, Muster in Reihenfolge
	prof := []*SmartProfile{{ID: 1, Enabled: true, Assign: []string{"global"}, Routes: []SmartRoute{
		{Group: 5, Domains: []string{"*nflx*"}}, {Group: 6, Domains: []string{"nflxvideo.net", "netflix.*"}}}}}
	s := smartFor(prof, "global")
	for host, g := range map[string]int64{"a.nflxvideo.net": 6, "b.nflxso.net": 5, "netflix.de": 6, "example.org": 0} {
		got, _, _ := s.match(host)
		if got != g {
			t.Errorf("SmartDNS %s → %d, erwartet %d", host, got, g)
		}
	}
	if rid, _, dom, ok := s.matchRule("www.netflix.fr"); !ok || dom != "netflix.*" || rid != SmartRuleID(1, 1) {
		t.Errorf("matchRule: %d %s", rid, dom)
	}
	if got := ParseSmart([]any{map[string]any{"group": float64(3), "domains": []any{"netflix.*", "*"}}}); len(got) != 1 || len(got[0].Domains) != 1 {
		t.Errorf("ParseSmart: %+v", got)
	}
	if ds, err := ParseRouteDomains("netflix.*\nhttps://www.example.org/x"); err != nil || len(ds) != 2 {
		t.Errorf("ParseRouteDomains: %v %v", ds, err)
	}
}
