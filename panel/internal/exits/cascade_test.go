package exits

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnpanel/internal/system"
)

func TestCheckVia(t *testing.T) {
	exists := func(id int64) bool { return id >= 1 && id <= 5 }
	vias := map[int64]int64{2: 1, 3: 2} // 3 → 2 → 1
	cases := []struct {
		id, via int64
		ok      bool
	}{
		{4, 0, true},
		{4, 4, false}, // über sich selbst
		{4, 9, false}, // fehlt
		{4, 1, true},  // 4 → 1
		{4, 2, true},  // 4 → 2 → 1 (3 Stufen)
		{4, 3, false}, // 4 → 3 → 2 → 1 (4 Stufen)
		{1, 3, false}, // Kreis 1 → 3 → 2 → 1
		{1, 4, false}, // 3 → 2 → 1 → 4: zu lang
		{0, 2, true},  // neuer Ausgang
		{2, 5, true},  // 3 → 2 → 5: drei Stufen samt Nachfolger 3
		{1, 5, false}, // 3 → 2 → 1 → 5: vier Stufen
	}
	for _, c := range cases {
		msg := CheckVia(c.id, c.via, vias, exists)
		if (msg == "") != c.ok {
			t.Errorf("CheckVia(%d, %d) = %q, erwartet ok=%v", c.id, c.via, msg, c.ok)
		}
	}
}

func cascadeWG(t *testing.T, id int64, mtu int) *Exit {
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 100.64.%d.2/32\nMTU = %d\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.%d:51820\n",
		key('a'), id, mtu, key('b'), id)
	w, err := ParseWG(conf)
	if err != nil {
		t.Fatal(err)
	}
	return &Exit{ID: id, Name: fmt.Sprintf("X%d", id), Enabled: true, Type: "wireguard", Slot: int(id), WG: w, Mode: "always"}
}

func TestCascadeApply(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	warp, ws := cascadeWG(t, 1, 1420), cascadeWG(t, 2, 1420)
	ws.Via = 1
	if err := m.Apply(env, []*Exit{warp, ws}, nil); err != nil {
		t.Fatal(err)
	}
	dry := env.Sys.(*system.Dry)
	in := strings.Join(dry.Stdin, "\n---\n")
	if !strings.Contains(in, "FwMark = 0x41000000") {
		t.Fatalf("FwMark des Vorgängers fehlt:\n%s", in)
	}
	log := strings.Join(dry.Log(), "\n")
	if !strings.Contains(log, "wg set ex1 fwmark off") || !strings.Contains(log, "wg set ex2 fwmark 0x41000000") {
		t.Fatalf("fwmark:\n%s", log)
	}
	if !strings.Contains(log, "ip link set dev ex2 mtu 1340 up") || !strings.Contains(log, "ip link set dev ex1 mtu 1420 up") {
		t.Fatalf("MTU:\n%s", log)
	}
	// Vorgänger abgeschaltet → Ausgang wird nicht verbunden (nie direkt hinaus)
	warp.Enabled = false
	err := m.Apply(env, []*Exit{warp, ws}, nil)
	if err == nil || !strings.Contains(err.Error(), "Vorgänger") {
		t.Fatalf("erwartet Fehler wegen Vorgänger: %v", err)
	}
	if env.Get("exits:cfg:ex2") != "" {
		t.Fatal("Ausgang ohne Vorgänger blieb eingerichtet")
	}
}

func TestCascadeOpenVPN(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	warp := cascadeWG(t, 1, 1420)
	o, err := ParseOVPN("client\nremote vpn.example.net 1194\nproto udp\n<ca>\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n</ca>\n")
	if err != nil {
		t.Fatal(err)
	}
	ov := &Exit{ID: 3, Name: "OV", Enabled: true, Type: "openvpn", Slot: 3, OVPN: o, Mode: "always", Via: 1}
	if err := m.Apply(env, []*Exit{warp, ov}, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(env.Sys.(*system.Dry).Root, confDir, "ex3.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), fmt.Sprintf("mark %d\n", probeMark(1))) || !strings.Contains(string(b), "tun-mtu 1340\n") {
		t.Fatalf("OpenVPN ohne mark/tun-mtu:\n%s", b)
	}
}

func TestCascadeNeeded(t *testing.T) {
	env, _, _ := testEnv(t)
	m := New()
	warp, ws := cascadeWG(t, 1, 1420), cascadeWG(t, 2, 1420)
	warp.Mode, ws.Mode, ws.Via = "standby", "standby", 1
	m.remember([]*Exit{warp, ws}, nil)
	if m.neededSet()[1] {
		t.Fatal("ohne Bedarf darf der Vorgänger getrennt sein")
	}
	m.setConn(2, true) // Nachfolger verbunden (z. B. zur Prüfung)
	if !m.neededSet()[1] {
		t.Fatal("Vorgänger eines verbundenen Ausgangs muss verbunden bleiben")
	}
	m.setConn(2, false)
	if err := m.connect(env, ws); err != nil {
		t.Fatal(err)
	}
	if !m.isConn(1) || !m.isConn(2) {
		t.Fatal("connect verbindet den Vorgänger nicht mit")
	}
	if c := m.ViaChain(2); len(c) != 1 || c[0] != 1 {
		t.Fatalf("ViaChain: %v", c)
	}
}
