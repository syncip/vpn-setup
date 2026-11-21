package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpnpanel/internal/store"
)

// Blocklisten durchsuchen und anpassen: herausnehmen, wieder aufnehmen, eigene ergänzen, Suche über alle Listen.
func TestDNSListEdit(t *testing.T) {
	e, _ := newTest(t)
	body := "0.0.0.0 ads.example.com\n||tracker.example^\n0.0.0.0 example.org\n@@||good.ads.example.com^\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	listAllowLocal = true
	defer func() { listAllowLocal = false }()
	bl := saveObj(t, e, &store.Object{Kind: "dnslist", Name: "Werbung", Enabled: true, Data: store.M{"mode": "block", "url": srv.URL, "refresh": 24, "entries": []string{"eigen.example"}}})
	if _, err := e.FetchDNSList(bl.ID); err != nil {
		t.Fatal(err)
	}
	load := func() *store.Object {
		o, err := e.St.Object("dnslist", bl.ID)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}

	p := e.DNSListEntries(load(), "", "", 0, 100)
	if p.Total != 5 || p.Matched != 5 || p.Own != 1 || p.Items[0] != (DNSListEntry{"eigen.example", "own"}) {
		t.Fatalf("Inhalt: %+v", p)
	}
	if p := e.DNSListEntries(load(), "ads", "", 0, 100); p.Matched != 2 {
		t.Fatalf("Suche „ads“: %+v", p)
	}
	if p := e.DNSListEntries(load(), "", "allow", 0, 100); p.Matched != 1 || p.Items[0].Domain != "good.ads.example.com" {
		t.Fatalf("Ausnahmen: %+v", p)
	}

	// Domain der Online-Liste herausnehmen + eigene löschen + neue ergänzen
	msg, err := e.EditDNSList(load(), []string{"neu.example"}, []string{"ads.example.com", "eigen.example"}, nil)
	if err != nil || msg != "1 ergänzt, 1 eigene gelöscht, 1 herausgenommen" {
		t.Fatalf("Anpassen: %q %v", msg, err)
	}
	d := e.dnsListSets(DNSListFrom(load()))
	if _, ok := d.block["ads.example.com"]; ok {
		t.Error("herausgenommene Domain sperrt noch")
	}
	if _, ok := d.block["neu.example"]; !ok {
		t.Error("ergänzte Domain fehlt")
	}
	if _, ok := d.block["eigen.example"]; ok {
		t.Error("gelöschter eigener Eintrag sperrt noch")
	}
	// bleibt nach dem Neuladen draußen
	body += "0.0.0.0 mehr.example\n"
	if _, err := e.FetchDNSList(bl.ID); err != nil {
		t.Fatal(err)
	}
	if d := e.dnsListSets(DNSListFrom(load())); func() bool { _, ok := d.block["ads.example.com"]; return ok }() {
		t.Error("nach dem Neuladen wieder gesperrt")
	}
	if p := e.DNSListEntries(load(), "", "excluded", 0, 100); p.Matched != 1 || p.Excluded != 1 {
		t.Fatalf("Herausgenommene: %+v", p)
	}

	// Suche über alle Listen: Unterdomain wird über den übergeordneten Namen erfasst
	hits := e.SearchDNSLists("x.example.org")
	if len(hits) != 1 || hits[0].Via != "example.org" {
		t.Fatalf("Suche über alle Listen: %+v", hits)
	}

	// wieder aufnehmen (auch über „ergänzen“)
	if msg, err := e.EditDNSList(load(), []string{"ads.example.com"}, nil, nil); err != nil || msg != "1 wieder aufgenommen" {
		t.Fatalf("Wieder aufnehmen: %q %v", msg, err)
	}
	if _, ok := e.dnsListSets(DNSListFrom(load())).block["ads.example.com"]; !ok {
		t.Error("wieder aufgenommene Domain sperrt nicht")
	}
	if _, err := e.EditDNSList(load(), []string{"kein domain"}, nil, nil); err == nil {
		t.Error("ungültige Domain angenommen")
	}

	// reine eigene Liste darf nicht leer werden
	own := saveObj(t, e, &store.Object{Kind: "dnslist", Name: "Eigen", Enabled: true, Data: store.M{"mode": "block", "entries": []string{"a.example"}}})
	if _, err := e.EditDNSList(own, nil, []string{"a.example"}, nil); err == nil {
		t.Error("leere Liste gespeichert")
	}
}
