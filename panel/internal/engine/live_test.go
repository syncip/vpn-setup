package engine

import (
	"testing"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// Live-Messung: Raten aus Zählerdifferenzen, Verlauf, zurückgesetzte Zähler.
func TestLive(t *testing.T) {
	e, _ := newTest(t)
	sv := &store.Server{Name: "WG", Protocol: "wireguard", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(sv); err != nil {
		t.Fatal(err)
	}
	_ = e.St.SaveServer(sv)
	u := &store.User{Name: "u", Enabled: true, SubToken: proto.RandHex(16)}
	_ = e.St.SaveUser(u)
	for _, n := range []string{"a", "b"} {
		p := &store.Peer{UserID: u.ID, ServerID: sv.ID, Name: n, Kind: "client", Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(sv, p); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SavePeer(p)
	}
	e.sampleLive() // erster Messpunkt: noch keine Rate
	if d := e.Live(); len(d.History) != 0 {
		t.Errorf("erster Messpunkt sollte keinen Verlauf erzeugen")
	}
	time.Sleep(200 * time.Millisecond)
	e.sampleLive()
	d := e.Live()
	if len(d.History) != 1 || d.History[0].Down <= 0 {
		t.Fatalf("Verlauf/Rate fehlt: %+v", d.History)
	}
	on := 0
	for _, p := range d.Peers {
		if p.Online {
			on++
		}
	}
	if on == 0 {
		t.Errorf("kein Zugang online")
	}
	// zurückgesetzter Zähler ergibt keine negative Rate
	e.live.mu.Lock()
	for id, s := range e.live.prev {
		s.Down += 1 << 40
		e.live.prev[id] = s
	}
	e.live.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	e.sampleLive()
	for _, p := range e.Live().Peers {
		if p.Down < 0 || p.Up < 0 {
			t.Errorf("negative Rate: %+v", p)
		}
	}
}
