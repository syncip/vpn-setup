package engine

import (
	"strings"
	"testing"

	"vpnpanel/internal/store"
)

// SmartDNS-Profile wirken zusammen; die genauere Zuordnung gewinnt je Domain.
func TestSmartFor(t *testing.T) {
	ps := []*SmartProfile{
		{ID: 1, Assign: []string{"global"}, Routes: []SmartRoute{{Group: 10, Domains: []string{"netflix.com", "bbc.co.uk"}}}},
		{ID: 2, Assign: []string{"user:5"}, Routes: []SmartRoute{{Group: 20, Domains: []string{"netflix.com"}}}},
		{ID: 3, Assign: []string{"ext", "client:7"}, Routes: []SmartRoute{{Group: 30, Domains: []string{"disneyplus.com"}}}},
		{ID: 4, Assign: []string{"vpn"}, Routes: []SmartRoute{{Group: 40, Domains: []string{"hulu.com"}}}},
	}
	s := smartFor(ps, "peer:1", "user:5", "server:1", "vpn", "global")
	if g, _, _ := s.match("www.netflix.com"); g != 20 {
		t.Errorf("Nutzer vor alle: %d", g)
	}
	if g, _, _ := s.match("bbc.co.uk"); g != 10 {
		t.Errorf("alle: %d", g)
	}
	if g, _, _ := s.match("hulu.com"); g != 40 {
		t.Errorf("alle VPN-Geräte: %d", g)
	}
	if _, _, ok := s.match("disneyplus.com"); ok {
		t.Error("„ohne VPN“ gilt für VPN-Geräte")
	}
	if len(s.rules) != 3 || s.rules[0].ID != SmartRuleID(2, 0) || strings.Join(s.rules[2].Domains, ",") != "bbc.co.uk" {
		t.Errorf("Regeln: %+v", s.rules)
	}
	c := smartForClient(ps, 9)
	if g, _, _ := c.match("disneyplus.com"); g != 30 {
		t.Errorf("ohne VPN: %d", g)
	}
	if _, _, ok := c.match("hulu.com"); ok {
		t.Error("„alle VPN-Geräte“ gilt ohne VPN")
	}
	if smartFor(ps, "peer:9", "user:9", "server:9") != nil {
		t.Error("ohne Zuordnung erwartet nil")
	}
}

// Übernahme aus Filterprofilen (bis v0.30.0).
func TestMigrateSmartDNS(t *testing.T) {
	e, _ := newTest(t)
	g := saveObj(t, e, &store.Object{Kind: "group", Name: "USA", Enabled: true, Data: store.M{}})
	glob := saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "Standard", Enabled: true, Data: store.M{"assign": []string{"global", "user:3"},
		"smart": []any{map[string]any{"group": float64(g.ID), "domains": []any{"netflix.com"}}}}})
	own := saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "TV", Enabled: false, Data: store.M{"assign": []string{},
		"smart": []any{map[string]any{"group": float64(g.ID), "domains": []any{"disneyplus.com"}}}}})
	plain := saveObj(t, e, &store.Object{Kind: "dnsprofile", Name: "Leer", Enabled: true, Data: store.M{"smart": []any{}}})
	c0 := saveObj(t, e, &store.Object{Kind: "dnsclient", Name: "A", Enabled: true, Data: store.M{"profile": float64(0)}})
	c1 := saveObj(t, e, &store.Object{Kind: "dnsclient", Name: "B", Enabled: true, Data: store.M{"profile": float64(own.ID)}})
	saveObj(t, e, &store.Object{Kind: "dnsclient", Name: "C", Enabled: true, Data: store.M{"profile": float64(-1)}})

	e.MigrateSmartDNS()
	e.MigrateSmartDNS() // zweimal: nichts doppelt

	objs, _ := e.St.Objects("smartdns")
	if len(objs) != 2 {
		t.Fatalf("%d SmartDNS-Profile", len(objs))
	}
	a, b := SmartProfileFrom(objs[0]), SmartProfileFrom(objs[1])
	if a.Name != "Standard" || !a.Enabled || strings.Join(a.Assign, ",") != "vpn,user:3,client:"+itoa(c0.ID) ||
		len(a.Routes) != 1 || a.Routes[0].Group != g.ID || a.Routes[0].Domains[0] != "netflix.com" {
		t.Errorf("Standard: %+v", a)
	}
	if b.Name != "TV" || b.Enabled || strings.Join(b.Assign, ",") != "client:"+itoa(c1.ID) {
		t.Errorf("TV: %+v", b)
	}
	for _, id := range []int64{glob.ID, own.ID, plain.ID} {
		o, _ := e.St.Object("dnsprofile", id)
		if _, ok := o.Data["smart"]; ok {
			t.Errorf("Profil %d hat noch SmartDNS", id)
		}
	}
}
