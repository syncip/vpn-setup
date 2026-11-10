package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/hysteria2"
	_ "vpnpanel/internal/proto/vless"
	_ "vpnpanel/internal/proto/wireguard"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

// TestAssignAndReach: Ausgang zuweisen und Zugriff setzen (wie per Drag & Drop auf der Netzwerk-Seite).
func TestAssignAndReach(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_ = st.SetSetting("server_host", "vpn.example.org")
	e := engine.New(st, &system.Dry{Root: filepath.Join(dir, "root")}, engine.Config{PanelBackend: "127.0.0.1:8480", DataDir: dir, HookAddr: "127.0.0.1:8479"})
	a := New(e, nil, false, "test")

	mkSrv := func(name, protocol string) *store.Server {
		s := &store.Server{Name: name, Protocol: protocol, Enabled: true, Settings: store.M{}, State: store.M{}}
		if err := e.InitServer(s); err != nil {
			t.Fatal(err)
		}
		_ = st.SaveServer(s)
		return s
	}
	wg, hy := mkSrv("wg", "wireguard"), mkSrv("hy", "hysteria2")
	u := &store.User{Name: "anna", Enabled: true, SubToken: proto.RandHex(16)}
	_ = st.SaveUser(u)
	mkPeer := func(s *store.Server, name string) *store.Peer {
		d, _ := proto.Get(s.Protocol)
		p := &store.Peer{UserID: u.ID, ServerID: s.ID, Name: name, Kind: d.Info().Kinds[0].ID, Enabled: true, Settings: store.M{}}
		if err := e.InitPeer(s, p); err != nil {
			t.Fatal(err)
		}
		_ = st.SavePeer(p)
		return p
	}
	phone, tv, hyp := mkPeer(wg, "Handy"), mkPeer(wg, "TV"), mkPeer(hy, "hy")
	conf := "[Interface]\nPrivateKey = " + proto.B64(proto.RandBytes(32)) + "\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = " + proto.B64(proto.RandBytes(32)) +
		"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	ex := &store.Object{Kind: "exit", Name: "A", Enabled: true, Data: store.M{"type": "wireguard", "slot": 1}, Secrets: store.M{"config": conf}}
	_ = st.SaveObject(ex)
	gr := &store.Object{Kind: "group", Name: "US", Enabled: true, Data: store.M{"slot": 2, "exits": []int64{ex.ID}, "on_fail": "block"}, Secrets: store.M{}}
	_ = st.SaveObject(gr)

	call := func(h http.HandlerFunc, id int64, body string) (int, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		r.SetPathValue("id", fmt.Sprint(id))
		w := httptest.NewRecorder()
		h(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	routes := func() string {
		objs, _ := st.Objects("route")
		var s []string
		for _, o := range objs {
			r := engine.RouteFrom(o)
			s = append(s, fmt.Sprintf("%s/%d/%v/%d", r.Scope, r.ScopeID, r.All, r.Group))
		}
		return strings.Join(s, " ")
	}
	assign := func(scope string, id, group int64) int {
		code, _ := call(a.assignRoute, 0, fmt.Sprintf(`{"scope":%q,"scope_id":%d,"group":%d}`, scope, id, group))
		return code
	}
	// Gerät auf Gruppe; nochmal direkt → Regel wieder weg (nichts geerbt)
	if assign("peer", phone.ID, gr.ID) != 200 || routes() != fmt.Sprintf("peer/%d/true/%d", phone.ID, gr.ID) {
		t.Fatalf("Gerät → Gruppe: %s", routes())
	}
	if assign("peer", phone.ID, 0) != 200 || routes() != "" {
		t.Fatalf("Gerät → direkt: %s", routes())
	}
	// alle über die Gruppe, ein Gerät direkt → ausdrückliche Ausnahme am Gerät
	assign("global", 0, gr.ID)
	assign("peer", tv.ID, 0)
	if want := fmt.Sprintf("global/0/true/%d peer/%d/true/0", gr.ID, tv.ID); routes() != want {
		t.Fatalf("Ausnahme: %s, erwartet %s", routes(), want)
	}
	// erneut zuweisen ersetzt, statt zu sammeln
	assign("peer", tv.ID, gr.ID)
	assign("peer", tv.ID, gr.ID)
	if want := fmt.Sprintf("global/0/true/%d peer/%d/true/%d", gr.ID, tv.ID, gr.ID); routes() != want {
		t.Fatalf("Ersetzen: %s", routes())
	}
	if assign("peer", hyp.ID, gr.ID) != 400 {
		t.Error("Hysteria2-Gerät einzeln zugewiesen")
	}
	if assign("server", hy.ID, gr.ID) != 200 || assign("global", 0, 999) != 400 || assign("user", 999, gr.ID) != 400 {
		t.Error("Prüfung der Eingaben")
	}

	// Übersicht: Weg der Geräte und Hinweise
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.topology(w, httptest.NewRequest(http.MethodGet, "/", nil))
	var topo struct {
		Peers []struct {
			ID  int64
			Via viaOut
		}
		Issues []issue
	}
	if err := json.Unmarshal(w.Body.Bytes(), &topo); err != nil {
		t.Fatal(err)
	}
	via := map[int64]viaOut{}
	for _, p := range topo.Peers {
		via[p.ID] = p.Via
	}
	if via[tv.ID].All != gr.ID || via[tv.ID].Scope != "peer" || via[phone.ID].All != gr.ID || via[phone.ID].Scope != "global" || via[hyp.ID].Scope != "server" {
		t.Errorf("Wege: %+v", via)
	}

	// Zugriff: Handy darf den TV (Vorgabe: alle) – entziehen, wieder erlauben
	code, out := call(a.setReach, phone.ID, fmt.Sprintf(`{"target":%d,"allow":false}`, tv.ID))
	if code != 200 || len(out["reach"].([]any)) != 0 {
		t.Fatalf("entziehen: %d %v", code, out)
	}
	p, _ := st.Peer(phone.ID)
	if p.Settings["access"] != "custom" {
		t.Errorf("Zugriff nicht als Auswahl gespeichert: %v", p.Settings["access"])
	}
	code, out = call(a.setReach, phone.ID, fmt.Sprintf(`{"target":%d,"allow":true}`, tv.ID))
	if code != 200 || len(out["reach"].([]any)) != 1 {
		t.Fatalf("erlauben: %d %v", code, out)
	}
	if code, _ := call(a.setReach, phone.ID, fmt.Sprintf(`{"target":%d,"allow":true}`, hyp.ID)); code != 400 {
		t.Error("Zugriff über Server-Grenzen angenommen")
	}
}
