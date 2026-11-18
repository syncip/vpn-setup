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

// TestRouteChains: Kaskade über die Stufen einer Ziel-Regel.
func TestRouteChains(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := engine.New(st, &system.Dry{Root: filepath.Join(dir, "root")}, engine.Config{PanelBackend: "127.0.0.1:8480", DataDir: dir, HookAddr: "127.0.0.1:8479"})
	a := New(e, nil, false, "test")

	conf := func() string {
		return "[Interface]\nPrivateKey = " + proto.B64(proto.RandBytes(32)) + "\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = " + proto.B64(proto.RandBytes(32)) +
			"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	}
	slot := 1
	mkExit := func(name, typ string) *store.Object {
		o := &store.Object{Kind: "exit", Name: name, Enabled: true, Data: store.M{"type": typ, "slot": slot}, Secrets: store.M{}}
		if typ != "tor" {
			o.Secrets["config"] = conf()
		}
		slot++
		if err := st.SaveObject(o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	warp, zh1, zh2, tor := mkExit("WARP", "wireguard"), mkExit("Zürich 1", "wireguard"), mkExit("Zürich 2", "wireguard"), mkExit("Tor", "tor")
	ch := &store.Object{Kind: "group", Name: "Schweiz", Enabled: true, Data: store.M{"slot": 20, "exits": []int64{zh1.ID, zh2.ID}, "on_fail": "block"}, Secrets: store.M{}}
	_ = st.SaveObject(ch)

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
	via := func(o *store.Object) string {
		x, _ := st.Object("exit", o.ID)
		return fmt.Sprintf("%d/%v", numOf(x.Data["via"]), x.Data["via_rule"] == true)
	}
	stage := func(kind string, id int64) string { return fmt.Sprintf(`{"kind":%q,"id":%d}`, kind, id) }
	rule := func(name string, stages ...string) string {
		return fmt.Sprintf(`{"name":%q,"scope":"global","match":"all","stages":[%s]}`, name, strings.Join(stages, ","))
	}

	// 1. WARP → Gruppe Schweiz: beide Zürich-Ausgänge über WARP, WARP direkt
	code, out := call(a.createRoute, 0, rule("CH über WARP", stage("exit", warp.ID), stage("group", ch.ID)))
	if code != 200 {
		t.Fatalf("Regel 1: %d %v", code, out)
	}
	r1 := int64(out["id"].(float64))
	if via(zh1) != fmt.Sprintf("%d/true", warp.ID) || via(zh2) != fmt.Sprintf("%d/true", warp.ID) || via(warp) != "0/true" {
		t.Fatalf("Wege: zh1 %s zh2 %s warp %s", via(zh1), via(zh2), via(warp))
	}

	// 2. Widerspruch: Zürich 1 direkt verlangt → abgelehnt, nichts geändert
	code, out = call(a.createRoute, 0, rule("ZH direkt", stage("exit", zh1.ID)))
	if code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "nur einen Weg") {
		t.Fatalf("Widerspruch nicht erkannt: %d %v", code, out)
	}
	if gs, _ := st.Objects("group"); len(gs) != 1 {
		t.Fatalf("Gruppe trotz Fehler angelegt: %d", len(gs))
	}

	// 3. WARP → Tor (einzelner Ausgang am Ende → automatische Gruppe)
	code, out = call(a.createRoute, 0, rule("Tor über WARP", stage("exit", warp.ID), stage("exit", tor.ID)))
	if code != 200 {
		t.Fatalf("Regel 3: %d %v", code, out)
	}
	r3 := int64(out["id"].(float64))
	ro, _ := st.Object("route", r3)
	g, err := st.Object("group", numOf(ro.Data["group"]))
	if err != nil || numOf(g.Data["auto"]) != tor.ID || g.Name != "Tor" {
		t.Fatalf("automatische Gruppe: %v %+v", err, g)
	}
	if via(tor) != fmt.Sprintf("%d/true", warp.ID) {
		t.Fatalf("Tor: %s", via(tor))
	}

	// 4. Von Hand ändern geht nicht, solange eine Regel den Weg bestimmt
	if code, out = call(a.updateExit, tor.ID, `{"via":0}`); code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "Tor über WARP") {
		t.Fatalf("Handänderung: %d %v", code, out)
	}
	// … und löschen auch nicht
	if code, _ = call(a.deleteExit, warp.ID, ``); code != 409 {
		t.Fatalf("Stufe gelöscht: %d", code)
	}

	// 5. WireGuard über Tor ist nicht möglich
	if code, out = call(a.createRoute, 0, rule("WG über Tor", stage("exit", tor.ID), stage("exit", zh2.ID))); code != 400 {
		t.Fatalf("WireGuard über Tor: %d %v", code, out)
	}
	// Gruppe nur als letzte Stufe
	if code, _ = call(a.createRoute, 0, rule("x", stage("group", ch.ID), stage("exit", tor.ID))); code != 400 {
		t.Fatal("Gruppe vorn angenommen")
	}

	// 6. Regel 3 auf direkt umstellen → Tor wieder direkt, automatische Gruppe weg
	if code, out = call(a.updateRoute, r3, rule("Tor über WARP")); code != 200 {
		t.Fatalf("direkt: %d %v", code, out)
	}
	if via(tor) != "0/false" {
		t.Fatalf("Tor nach Freigabe: %s", via(tor))
	}
	if _, err := st.Object("group", g.ID); err == nil {
		t.Fatal("automatische Gruppe nicht entfernt")
	}

	// 7. Neuer Ausgang in der Gruppe Schweiz bekommt den Weg der Kette
	zh3 := mkExit("Zürich 3", "wireguard")
	if code, out = call(a.updateGroup, ch.ID, fmt.Sprintf(`{"exits":[%d,%d,%d]}`, zh1.ID, zh2.ID, zh3.ID)); code != 200 {
		t.Fatalf("Gruppe: %d %v", code, out)
	}
	if via(zh3) != fmt.Sprintf("%d/true", warp.ID) {
		t.Fatalf("Zürich 3: %s", via(zh3))
	}

	// 8. Regel 1 löschen → alle wieder direkt; von Hand gesetzte Wege bleiben
	if code, _ = call(a.updateExit, tor.ID, fmt.Sprintf(`{"via":%d}`, warp.ID)); code != 200 {
		t.Fatalf("Tor von Hand über WARP: %d", code)
	}
	if code, _ = call(a.deleteRoute, r1, ``); code != 200 {
		t.Fatal("Regel 1 löschen")
	}
	for _, x := range []*store.Object{zh1, zh2, zh3, warp} {
		if via(x) != "0/false" {
			t.Fatalf("%s nach Löschen: %s", x.Name, via(x))
		}
	}
	if via(tor) != fmt.Sprintf("%d/false", warp.ID) {
		t.Fatalf("Handeinstellung verloren: %s", via(tor))
	}
}
