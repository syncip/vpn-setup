package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPickFastest(t *testing.T) {
	res := []DNSSpeed{
		{Addr: "127.0.0.1:5335", Median: 1, OK: 30, Total: 30},
		{Addr: "9.9.9.9", Median: 10, OK: 30, Total: 30},
		{Addr: "1.1.1.1", Median: 11, OK: 30, Total: 30},
		{Addr: "8.8.8.8", Median: 30, OK: 30, Total: 30},
		{Addr: "6.6.6.6", OK: 0, Total: 3},
	}
	// Unbound zählt nicht als Upstream; gleiche Auswahl → kein Wechsel
	if c, ch, _, _, _ := pickFastest(res, []string{"9.9.9.9", "1.1.1.1"}, 2); ch || strings.Join(c, ",") != "9.9.9.9,1.1.1.1" {
		t.Errorf("gleich: %v %v", c, ch)
	}
	// deutlich schneller → Wechsel
	if c, ch, _, _, _ := pickFastest(res, []string{"8.8.8.8"}, 1); !ch || c[0] != "9.9.9.9" {
		t.Errorf("schneller: %v %v", c, ch)
	}
	// knapp schneller → bleibt
	if _, ch, why, _, _ := pickFastest(res, []string{"1.1.1.1"}, 1); ch {
		t.Errorf("knapp: %s", why)
	}
	// toter Server → Wechsel
	if _, ch, _, _, _ := pickFastest(res, []string{"6.6.6.6"}, 1); !ch {
		t.Error("toter Server bleibt")
	}
}

func TestUnboundAndCandidates(t *testing.T) {
	e, dry := newTest(t)
	_ = e.St.SetSetting("dns_resolver", "unbound")
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dry.Root, "etc/unbound/unbound.conf.d/vpnpanel.conf"))
	if err != nil || !strings.Contains(string(b), "interface: 127.0.0.1@5335") {
		t.Fatalf("Unbound-Konfiguration: %v %s", err, b)
	}
	if !strings.Contains(strings.Join(dry.Log(), "\n"), "systemctl restart unbound") {
		t.Error("Unbound nicht gestartet")
	}
	_ = e.St.SetSetting("dns_resolver", "upstream")
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dry.Root, "etc/unbound/unbound.conf.d/vpnpanel.conf")); err == nil {
		t.Error("Konfiguration bleibt liegen")
	}
	if v, err := ValidateSetting("dns_candidates", "9.9.9.9 Quad9\n# Kommentar\n1.1.1.1\n9.9.9.9 doppelt"); err != nil || v != "9.9.9.9 Quad9\n1.1.1.1 1.1.1.1" {
		t.Errorf("Liste: %q %v", v, err)
	}
	if _, err := ValidateSetting("dns_candidates", "127.0.0.1:5335 lokal"); err == nil {
		t.Error("lokale Adresse angenommen")
	}
	_ = e.St.SetSetting("dns_candidates", "9.9.9.9 Quad9")
	if l := e.DNSCandidateList(); len(l) != 1 || l[0].Name != "Quad9" {
		t.Errorf("Liste: %+v", l)
	}
}
