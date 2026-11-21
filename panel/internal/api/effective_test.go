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
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

// TestEffective: „Was gilt?“ zeigt Routing mit Herkunft (SmartDNS am Gerät vor der Server-Regel),
// Filterprofil mit Ebene und Limits vom Tarif.
func TestEffective(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_ = st.SetSetting("server_host", "vpn.example.org")
	_ = st.SetSetting("dns_enabled", "1")
	e := engine.New(st, &system.Dry{Root: filepath.Join(dir, "root")}, engine.Config{PanelBackend: "127.0.0.1:8480", DataDir: dir, HookAddr: "127.0.0.1:8479"})
	a := New(e, nil, false, "test")

	srv := &store.Server{Name: "wg", Protocol: "wireguard", Enabled: true, Settings: store.M{}, State: store.M{}}
	if err := e.InitServer(srv); err != nil {
		t.Fatal(err)
	}
	_ = st.SaveServer(srv)
	plan := &store.Plan{Name: "Basis", Limits: store.Limits{TrafficGB: 50, Period: "monthly", MaxDevices: 3}}
	_ = st.SavePlan(plan)
	u := &store.User{Name: "anna", Enabled: true, SubToken: proto.RandHex(16), PlanID: &plan.ID}
	_ = st.SaveUser(u)
	d, _ := proto.Get("wireguard")
	p := &store.Peer{UserID: u.ID, ServerID: srv.ID, Name: "Handy", Kind: d.Info().Kinds[0].ID, Enabled: true, Settings: store.M{}}
	if err := e.InitPeer(srv, p); err != nil {
		t.Fatal(err)
	}
	_ = st.SavePeer(p)
	conf := "[Interface]\nPrivateKey = " + proto.B64(proto.RandBytes(32)) + "\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = " + proto.B64(proto.RandBytes(32)) +
		"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	mkGroup := func(name string, slot int) *store.Object {
		ex := &store.Object{Kind: "exit", Name: name + "-A", Enabled: true, Data: store.M{"type": "wireguard", "slot": slot}, Secrets: store.M{"config": conf}}
		_ = st.SaveObject(ex)
		g := &store.Object{Kind: "group", Name: name, Enabled: true, Data: store.M{"slot": slot, "exits": []int64{ex.ID}, "on_fail": "block"}, Secrets: store.M{}}
		_ = st.SaveObject(g)
		return g
	}
	nl, us := mkGroup("NL", 1), mkGroup("US", 2)
	_ = st.SaveObject(&store.Object{Kind: "route", Name: "Server über NL", Enabled: true, Data: store.M{"scope": "server", "scope_id": srv.ID, "all": true, "group": nl.ID}})
	_ = st.SaveObject(&store.Object{Kind: "smartdns", Name: "Streaming", Enabled: true, Data: store.M{"assign": []string{fmt.Sprintf("peer:%d", p.ID)},
		"routes": []any{map[string]any{"group": float64(us.ID), "domains": []any{"google.de"}}}}})
	_ = st.SaveObject(&store.Object{Kind: "dnsprofile", Name: "Familie", Enabled: true, Data: store.M{"assign": []string{fmt.Sprintf("user:%d", u.ID)}}})
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}

	get := func(q string) (int, effOut, string) {
		t.Helper()
		w := httptest.NewRecorder()
		a.effective(w, httptest.NewRequest(http.MethodGet, "/api/effective?"+q, nil))
		var out effOut
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out, w.Body.String()
	}
	sec := func(o effOut, key string) []effRow {
		for _, s := range o.Sections {
			if s.Key == key {
				return s.Rows
			}
		}
		t.Fatalf("Abschnitt %s fehlt", key)
		return nil
	}

	code, out, body := get(fmt.Sprintf("kind=peer&id=%d", p.ID))
	if code != 200 {
		t.Fatal(code, body)
	}
	rt := sec(out, "routing")
	if len(rt) != 2 || rt[0].Label != "google.de" || !strings.Contains(rt[0].Value, "US") || !strings.Contains(rt[0].From, "SmartDNS") ||
		rt[1].Label != "alles andere" || !strings.Contains(rt[1].Value, "NL") || !strings.Contains(rt[1].From, "Server über NL") {
		t.Errorf("Routing: %+v", rt)
	}
	dns := sec(out, "dns")
	if dns[0].Label != "Filterprofil" || !strings.Contains(dns[0].Value, "Familie") || !strings.Contains(dns[0].From, "anna") {
		t.Errorf("DNS: %+v", dns)
	}
	lim := sec(out, "limits")
	found := false
	for _, r := range lim {
		if r.Label == "Datenvolumen" && strings.Contains(r.Value, "50 GB") && strings.Contains(r.From, "Basis") {
			found = true
		}
	}
	if !found {
		t.Errorf("Limits: %+v", lim)
	}

	// Gruppe: wer nutzt sie?
	_, out, _ = get(fmt.Sprintf("kind=group&id=%d", us.ID))
	if used := sec(out, "used"); len(used) != 1 || !strings.Contains(used[0].Label, "Streaming") {
		t.Errorf("Gruppe: %+v", used)
	}
	// Liste zum Suchen enthält alle Arten
	w := httptest.NewRecorder()
	a.effective(w, httptest.NewRequest(http.MethodGet, "/api/effective", nil))
	var list []effTarget
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	kinds := map[string]int{}
	for _, x := range list {
		kinds[x.Kind]++
	}
	if kinds["user"] != 1 || kinds["peer"] != 1 || kinds["server"] != 1 || kinds["group"] != 2 {
		t.Errorf("Liste: %v", kinds)
	}
	if code, _, _ := get("kind=peer&id=999"); code != 404 {
		t.Errorf("unbekannt: %d", code)
	}
}
