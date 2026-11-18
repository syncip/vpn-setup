package engine

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/store"
)

func TestClassifyBlock(t *testing.T) {
	cf := http.Header{}
	cf.Set("cf-mitigated", "challenge")
	for _, c := range []struct {
		code int
		hdr  http.Header
		body string
		want string
	}{
		{200, http.Header{}, "<html><title>Shop</title>" + strings.Repeat("x", 70000) + "</html>", "ok"},
		{403, cf, "<html>Just a moment...</html>", "captcha"},
		{403, http.Header{}, `<script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>`, "captcha"},
		{200, http.Header{}, `<div class="g-recaptcha" data-sitekey="x"></div>`, "captcha"},
		{403, http.Header{}, "<h1>Access Denied</h1> You don't have permission to access", "blocked"},
		{403, http.Header{}, "forbidden", "blocked"},
		{451, http.Header{}, "", "blocked"},
		{429, http.Header{}, "", "blocked"},
		{200, http.Header{}, "<p>This service is not available in your country.</p>", "blocked"},
		{503, http.Header{}, "Service Unavailable", "error"},
		{301, http.Header{}, "", "ok"},
	} {
		if got, d := classifyBlock(c.code, c.hdr, c.body); got != c.want {
			t.Errorf("HTTP %d %q: %s (%s), erwartet %s", c.code, c.body[:min(len(c.body), 40)], got, d, c.want)
		}
	}
}

func TestBlockDue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b := exits.BlockCheckFrom(map[string]any{"on": true})
	h := func(x float64) int64 { return now.Add(-time.Duration(x * float64(time.Hour))).Unix() }
	for i, c := range []struct {
		r   store.BlockResult
		has bool
		due bool
	}{
		{store.BlockResult{}, false, true},                                                 // unbekannt
		{store.BlockResult{Status: "ok", Checked: h(23)}, true, false},                     // ok, 23 h alt
		{store.BlockResult{Status: "ok", Checked: h(25)}, true, true},                      // ok, älter als 24 h
		{store.BlockResult{Status: "captcha", Checked: h(5)}, true, false},                 // gesperrt, 5 h
		{store.BlockResult{Status: "captcha", Checked: h(7)}, true, true},                  // gesperrt, älter als 6 h
		{store.BlockResult{Status: "error", Fails: 1, Checked: h(0.1)}, true, false},       // Fehler, 6 min
		{store.BlockResult{Status: "error", Fails: 1, Checked: h(0.2)}, true, true},        // Fehler, 12 min
		{store.BlockResult{Status: "ok", Fails: 2, Checked: h(1)}, true, true},             // Proxy meldet Fehler nach ok
		{store.BlockResult{Status: "error", Fails: 4, Checked: h(1)}, true, false},         // 4 Fehler = gesperrt
		{store.BlockResult{Status: "error", Fails: 1, Seen: h(0), Checked: 0}, true, true}, // nur gemeldet
	} {
		if got := blockDue(c.r, c.has, b, now); got != c.due {
			t.Errorf("Fall %d: fällig=%v, erwartet %v (%+v)", i, got, c.due, c.r)
		}
	}
}

func TestPickOverride(t *testing.T) {
	ok := store.BlockResult{Status: "ok", Checked: 1}
	cap := store.BlockResult{Status: "captcha", Checked: 1, Detail: "Captcha"}
	err3 := store.BlockResult{Status: "error", Fails: 3, Checked: 1}
	err4 := store.BlockResult{Status: "error", Fails: 4, Checked: 1}
	usable := []int64{1, 2, 3}
	// Captcha über den aktiven Ausgang, 2 und 3 ok → erster in der Reihenfolge
	if p, bad, _, chk := pickOverride(false, 4, usable, 1, map[int64]store.BlockResult{1: cap, 2: ok, 3: ok}, 0); p != 2 || bad != 1 || chk {
		t.Fatalf("Captcha: %d %d %v", p, bad, chk)
	}
	// bestehende Ausnahme bleibt (Stabilität)
	if p, _, _, _ := pickOverride(false, 4, usable, 1, map[int64]store.BlockResult{1: cap, 2: ok, 3: ok}, 3); p != 3 {
		t.Fatalf("Ausnahme gewechselt: %d", p)
	}
	// 3 Fehler: noch kein Ausweichen; 4 Fehler: ausweichen
	if p, _, _, _ := pickOverride(false, 4, usable, 1, map[int64]store.BlockResult{1: err3, 2: ok}, 0); p != 0 {
		t.Fatal("schon bei 3 Fehlern ausgewichen")
	}
	if p, _, _, _ := pickOverride(false, 4, usable, 1, map[int64]store.BlockResult{1: err4, 2: ok}, 0); p != 2 {
		t.Fatal("bei 4 Fehlern nicht ausgewichen")
	}
	// keine Gegenprobe (andere unbekannt bzw. ebenfalls gesperrt) → nicht ausweichen, prüfen
	if p, _, _, chk := pickOverride(false, 4, usable, 1, map[int64]store.BlockResult{1: cap, 2: cap}, 0); p != 0 || !chk {
		t.Fatalf("ohne Gegenprobe: %d %v", p, chk)
	}
	// Ziel über einen anderen Ausgang gesperrt, über den eigenen nicht → keine Ausnahme
	if p, _, _, chk := pickOverride(false, 4, usable, 1, map[int64]store.BlockResult{1: ok, 2: cap}, 0); p != 0 || chk {
		t.Fatal("unnötige Ausnahme")
	}
	// je Ziel: gesperrter Ausgang in der Verteilung zählt, auch wenn er nicht „nat“ ist
	if p, bad, _, _ := pickOverride(true, 4, usable, 1, map[int64]store.BlockResult{1: ok, 2: cap, 3: ok}, 0); p != 1 || bad != 2 {
		t.Fatalf("je Ziel: %d %d", p, bad)
	}
}

func TestBlockStoreAndReport(t *testing.T) {
	e, _ := newTest(t)
	gr := &store.Object{Kind: "group", Name: "US", Enabled: true, Data: store.M{"slot": 2, "exits": []int64{1, 2}, "on_fail": "block",
		"block": exits.BlockCheck{On: true, Domains: []string{"example.org"}, Fails: 4, Top: 5, OkHours: 24, BadHours: 6}.Map()}}
	if err := e.St.SaveObject(gr); err != nil {
		t.Fatal(err)
	}
	g := exits.GroupFrom(gr)
	if !g.Block.On || len(g.Block.Domains) != 1 || g.Block.Fails != 4 {
		t.Fatalf("Einstellung: %+v", g.Block)
	}
	// Fehlschläge aus dem Proxy zählen (höchstens alle 10 s je Ziel/Ausgang)
	e.BlockFail(gr.ID, "Shop.Example.net", 1, "Proxy: Zeitüberschreitung")
	e.BlockFail(gr.ID, "shop.example.net", 1, "Proxy: Zeitüberschreitung")
	r, err := e.St.BlockResult("shop.example.net", 1)
	if err != nil || r.Fails != 1 || r.Status != "error" {
		t.Fatalf("Fehlschlag: %+v %v", r, err)
	}
	// aktive Prüfung: ok setzt die Fehler zurück
	if r, _ = e.St.SetBlockResult("shop.example.net", 1, "ok", "HTTP 200", 100); r.Fails != 0 {
		t.Fatalf("ok: %+v", r)
	}
	if _, err := e.St.SetBlockResult("example.org", 2, "captcha", "Captcha", 100); err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.BlockReport(gr.ID)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, row := range rows {
		names = append(names, row.Domain)
	}
	if strings.Join(names, ",") != "example.org" {
		t.Fatalf("Übersicht: %v", names) // shop.example.net ist wieder ok → nicht mehr aufgeführt
	}
	if rows[0].Results[2].Status != "captcha" || !rows[0].Manual {
		t.Fatalf("Zeile: %+v", rows[0])
	}
}

func TestNormDomain(t *testing.T) {
	for in, want := range map[string]string{"https://www.Example.org/x?y": "www.example.org", "*.foo.de": "foo.de", "localhost": "",
		"a b.de": "", "shop.example.net.": "shop.example.net", "example.org:443": "example.org"} {
		if got := exits.NormDomain(in); got != want {
			t.Errorf("%q → %q, erwartet %q", in, got, want)
		}
	}
}

func TestNoteNames(t *testing.T) {
	e, _ := newTest(t)
	a := netip.MustParseAddr("192.0.2.13")
	e.noteNames(4, "shop.example.net.", []netip.Addr{a})
	if e.nameOf(4, a, time.Now()) != "" {
		t.Fatal("Gruppe ohne Block-Prüfung darf keine Namen sammeln")
	}
	e.blk.mu.Lock()
	e.blk.on = map[int64]bool{4: true}
	e.blk.mu.Unlock()
	e.noteNames(4, "Shop.Example.net.", []netip.Addr{a, netip.MustParseAddr("2001:db8::1")})
	if n := e.nameOf(4, a, time.Now()); n != "shop.example.net" {
		t.Fatalf("Name: %q", n)
	}
	if e.nameOf(4, a, time.Now().Add(3*time.Hour)) != "" || e.nameOf(5, a, time.Now()) != "" {
		t.Fatal("Zuordnung zu lange bzw. für fremde Gruppe gültig")
	}
}
