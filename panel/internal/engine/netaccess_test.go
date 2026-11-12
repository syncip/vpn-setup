package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// TestNetAccess: Freigabe „Nutzer anna → Netz B“ – Weiterleitung von wg0 und OpenVPN nach wg1,
// NAT auf wg1, AllowedIPs bzw. push route für die Netze von B; ohne Freigabe nichts davon.
func TestNetAccess(t *testing.T) {
	e, dry := newTest(t)
	mkServer := func(name, protocol string, set store.M) *store.Server {
		s := &store.Server{Name: name, Protocol: protocol, Enabled: true, Settings: set, State: store.M{}}
		if err := e.InitServer(s); err != nil {
			t.Fatal(err)
		}
		if err := e.St.SaveServer(s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	wgA := mkServer("Netz A", "wireguard", store.M{})
	wgB := mkServer("Netz B", "wireguard", store.M{"port": float64(51821), "net4": "10.9.0.0/24", "net6": "fd42:42:43::/64", "internet": false})
	ov := mkServer("OVPN", "openvpn", store.M{"internet": false})
	ifA, ifB := proto.Str(wgA.Settings, "interface"), proto.Str(wgB.Settings, "interface")
	if ifA == "" || ifB == "" || ifA == ifB {
		t.Fatalf("Schnittstellen %q %q", ifA, ifB)
	}

	mkUser := func(name string) *store.User {
		u := &store.User{Name: name, Enabled: true, SubToken: proto.RandHex(16)}
		if err := e.St.SaveUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	mkPeer := func(srv *store.Server, u *store.User, name, kind string, set store.M) *store.Peer {
		p := &store.Peer{UserID: u.ID, ServerID: srv.ID, Name: name, Kind: kind, Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(srv, p); err != nil {
			t.Fatal(err)
		}
		for k, v := range set {
			p.Settings[k] = v
		}
		if err := e.St.SavePeer(p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	anna, ben := mkUser("anna"), mkUser("ben")
	annaPhone := mkPeer(wgA, anna, "Handy", "client", store.M{"tunnel": "split"})
	annaOV := mkPeer(ov, anna, "Laptop", "access", nil)
	benPhone := mkPeer(wgA, ben, "Handy", "client", store.M{"tunnel": "split"})
	mkPeer(wgB, ben, "Homelab", "site", store.M{"routes": []any{"192.168.50.0/24"}})

	grant := &store.Object{Kind: "netaccess", Name: "Anna → B", Enabled: true, Data: store.M{"servers": []int64{wgB.ID}, "users": []int64{anna.ID}}}
	if err := e.St.SaveObject(grant); err != nil {
		t.Fatal(err)
	}
	apply := func() string {
		dry.Stdin = nil
		if err := e.Apply(); err != nil {
			t.Fatal(err)
		}
		return strings.Join(dry.Stdin, "\n")
	}
	fw := apply()
	a4 := func(p *store.Peer) string { return proto.Str(p.Settings, "address4") }
	for _, want := range []string{
		"-A VPNWG-FWD -i " + ifA + " -o " + ifB + " -s " + a4(annaPhone) + "/32 -d 10.9.0.0/24 -j ACCEPT",
		"-A VPNWG-FWD -i " + ifA + " -o " + ifB + " -s " + a4(annaPhone) + "/32 -d 192.168.50.0/24 -j ACCEPT",
		"-A VPNWG-NAT -s " + a4(annaPhone) + "/32 -o " + ifB + " -j MASQUERADE",
		"-A VPNWG-NAT -s " + a4(annaOV) + "/32 -o " + ifB + " -j MASQUERADE",
		"-A VPNOV-FWD -i ovpn" + itoa(ov.ID) + " -o " + ifB + " -s " + a4(annaOV) + " -d 192.168.50.0/24 -j ACCEPT",
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("fehlt: %s", want)
		}
	}
	if strings.Contains(fw, "-s "+a4(benPhone)+"/32 -d 10.9.0.0/24") || strings.Contains(fw, "-s "+a4(benPhone)+"/32 -o "+ifB) {
		t.Errorf("ben hat keine Freigabe, bekommt aber Regeln")
	}

	// Gerät mit geteiltem Tunnel: Netze von B in AllowedIPs, ben nicht
	cc, err := e.ClientConfig(annaPhone.ID)
	if err != nil {
		t.Fatal(err)
	}
	conf := cc.Files[0].Content
	if !strings.Contains(conf, "10.9.0.0/24") || !strings.Contains(conf, "192.168.50.0/24") {
		t.Errorf("AllowedIPs ohne Netz B:\n%s", conf)
	}
	if cc2, _ := e.ClientConfig(benPhone.ID); strings.Contains(cc2.Files[0].Content, "10.9.0.0/24") {
		t.Errorf("ben bekommt Netz B in AllowedIPs")
	}
	// OpenVPN ohne Internet: Routen per ccd
	ccd := filepath.Join(dry.Root, "etc/openvpn/vpn", "ovpn"+itoa(ov.ID)+"-ccd", proto.Str(annaOV.Secrets, "cn"))
	if b, err := os.ReadFile(ccd); err != nil || !strings.Contains(string(b), "push \"route 192.168.50.0 255.255.255.0\"") ||
		!strings.Contains(string(b), "push \"route 10.9.0.0 255.255.255.0\"") {
		t.Errorf("ccd ohne Routen: %q %v", b, err)
	}

	// Freigabe aus → keine Regeln mehr
	grant.Enabled = false
	if err := e.St.SaveObject(grant); err != nil {
		t.Fatal(err)
	}
	fw = apply()
	if strings.Contains(fw, "-o "+ifB+" -s "+a4(annaPhone)) || strings.Contains(fw, "-o "+ifB+" -j MASQUERADE") {
		t.Errorf("Regeln trotz abgeschalteter Freigabe:\n%s", fw)
	}
	if b, _ := os.ReadFile(ccd); strings.Contains(string(b), "192.168.50.0") {
		t.Errorf("ccd behält Route nach Abschalten")
	}
}
