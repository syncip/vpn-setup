package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnpanel/internal/backup"
	"vpnpanel/internal/store"
)

// Neue Version → Punkt (Art „update“) mit dem alten Stand, danach Version vermerkt; gleiche Version → nichts.
func TestPointBeforeUpgrade(t *testing.T) {
	dir := t.TempDir()
	o := &opts{dataDir: dir, db: filepath.Join(dir, "panel.db")}
	old := version
	t.Cleanup(func() { version = old })

	// erster Start ohne Datenbank: nur Version vermerken
	version = "1.0.0"
	pointBeforeUpgrade(o)
	if b, _ := os.ReadFile(filepath.Join(dir, backup.VersionFile)); strings.TrimSpace(string(b)) != "1.0.0" {
		t.Fatalf("Version nicht vermerkt: %q", b)
	}
	st, err := store.Open(o.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("server_host", "vpn.example.org"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	pointBeforeUpgrade(o) // gleiche Version
	if ps, _ := backup.ListPoints(dir); len(ps) != 0 {
		t.Fatalf("gleiche Version darf keinen Punkt anlegen: %v", ps)
	}

	version = "1.1.0"
	pointBeforeUpgrade(o)
	ps, err := backup.ListPoints(dir)
	if err != nil || len(ps) != 1 {
		t.Fatalf("Punkte: %v %v", ps, err)
	}
	p := ps[0]
	if p.Kind != backup.KindUpdate || p.Version != "1.0.0" || p.Schema != store.SchemaVersion() || !strings.Contains(p.Note, "1.1.0") {
		t.Fatalf("Punkt: %+v", p)
	}
	if _, err := backup.OpenPoint(dir, p.ID); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, backup.VersionFile)); strings.TrimSpace(string(b)) != "1.1.0" {
		t.Fatalf("neue Version nicht vermerkt: %q", b)
	}
}
