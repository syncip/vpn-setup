package engine

import (
	"os"
	"path/filepath"
	"testing"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// Nur für den Test auf echtem Linux: OVPN_DUMP=<ordner> schreibt Server-Konfiguration und Profile.
func TestOpenVPNDump(t *testing.T) {
	dir := os.Getenv("OVPN_DUMP")
	if dir == "" {
		t.Skip("OVPN_DUMP nicht gesetzt")
	}
	e, dry := newTest(t)
	ov := &store.Server{Name: "Test", Protocol: "openvpn", Enabled: true, Settings: store.M{"host": "10.200.0.1", "dns": "10.200.0.1"}}
	if err := e.InitServer(ov); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(ov)
	var ids []int64
	for _, n := range []string{"a", "b", "c"} {
		u := &store.User{Name: n, Enabled: n != "c", SubToken: proto.RandHex(16)}
		_ = e.St.SaveUser(u)
		p := &store.Peer{UserID: u.ID, ServerID: ov.ID, Name: n, Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(ov, p); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SavePeer(p)
		ids = append(ids, p.ID)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(dir)
	if err := os.CopyFS(filepath.Join(dir, "root"), os.DirFS(dry.Root)); err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		cc, err := e.ClientConfig(id)
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".ovpn"), []byte(cc.Files[0].Content), 0o600)
	}
}
