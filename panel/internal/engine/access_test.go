package engine

import (
	"strconv"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// TestWireGuardAccessRules: Zugriff zwischen Geräten (alle / eigene / ausgewählte) und dass die
// Regelzahl bei vielen Geräten nicht quadratisch wächst.
func TestWireGuardAccessRules(t *testing.T) {
	e, dry := newTest(t)
	wg := &store.Server{Name: "wg", Protocol: "wireguard", Enabled: true, Settings: store.M{}, State: store.M{}}
	if err := e.InitServer(wg); err != nil {
		t.Fatal(err)
	}
	if err := e.St.SaveServer(wg); err != nil {
		t.Fatal(err)
	}
	mkUser := func(name string) *store.User {
		u := &store.User{Name: name, Enabled: true, SubToken: proto.RandHex(16)}
		if err := e.St.SaveUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	mkPeer := func(u *store.User, name string, set store.M) *store.Peer {
		p := &store.Peer{UserID: u.ID, ServerID: wg.ID, Name: name, Kind: "client", Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(wg, p); err != nil {
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
	annaPhone := mkPeer(anna, "Handy", nil)
	benPhone := mkPeer(ben, "Handy", store.M{"access": "own"})
	annaTV := mkPeer(anna, "TV", store.M{"access": "custom", "access_peers": []int64{benPhone.ID}})

	fwText := func() string {
		if err := e.Apply(); err != nil {
			t.Fatal(err)
		}
		in := dry.Inputs["iptables-restore"]
		return in[:strings.Index(in, "*nat")]
	}
	fw := fwText()
	a4 := func(p *store.Peer) string { return proto.Str(p.Settings, "address4") + "/32" }
	for _, want := range []string{
		"-A VPNWG-FWD -i wg0 -o wg0 -s " + a4(annaPhone) + " -j ACCEPT",                      // alle: eine Regel
		"-A VPNWG-FWD -i wg0 -o wg0 -s " + a4(annaTV) + " -d " + a4(benPhone) + " -j ACCEPT", // ausgewählt
		"-A VPNWG-FWD -i wg0 -j DROP",
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("fehlt: %s\n%s", want, fw)
		}
	}
	for _, bad := range []string{
		"-s " + a4(annaPhone) + " -d ",              // keine Paar-Regeln bei „alle“
		"-o wg0 -s " + a4(benPhone),                 // ben: „eigene“, hat kein zweites Gerät
		"-s " + a4(annaTV) + " -d " + a4(annaPhone), // TV darf nur Bens Handy
		"-o wg0 -s " + a4(annaTV) + " -j ACCEPT",    // TV nicht pauschal
	} {
		if strings.Contains(fw, bad) {
			t.Errorf("unerwartet: %s\n%s", bad, fw)
		}
	}

	// 150 Geräte mit Standard „alle“: höchstens einige hundert Zeilen statt ~22 000
	for i := 0; i < 150; i++ {
		mkPeer(anna, "Gerät"+strconv.Itoa(i), nil)
	}
	fw = fwText()
	if n := strings.Count(fw, "\n"); n > 600 {
		t.Errorf("%d Firewall-Zeilen für 153 Geräte – wächst quadratisch", n)
	}
}
