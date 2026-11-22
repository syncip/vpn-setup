package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPoints(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "secrets.env"), []byte("X=1\n"), 0o600))
	snap := func(p string) error { return os.WriteFile(p, []byte("db"), 0o600) }
	m := Manifest{Version: "1.0.0", Schema: 3}

	a, err := CreatePoint(dir, snap, m, KindManual, "erster")
	must(err)
	if !ValidPointID(a.ID) || a.Files != 2 || a.Note != "erster" {
		t.Fatalf("Punkt: %+v", a)
	}
	// Schlüssel und Punkte landen nie in einer Sicherung
	if _, err := os.Stat(filepath.Join(dir, KeyFile)); err != nil {
		t.Fatal("kein Schlüssel")
	}
	b, err := CreatePoint(dir, snap, m, KindManual, "")
	must(err)
	arc, err := OpenPoint(dir, b.ID)
	must(err)
	for name := range arc.Files {
		if name == KeyFile || filepath.Dir(name) == PointsDir || name == PointsDir {
			t.Fatalf("%s mitgesichert", name)
		}
	}
	if string(arc.Files[DBName]) != "db" || string(arc.Files["secrets.env"]) != "X=1\n" {
		t.Fatalf("Inhalt: %v", arc.Files)
	}
	if _, err := CreatePoint(dir, snap, m, "Böse/../x", ""); err == nil {
		t.Fatal("ungültige Art angenommen")
	}

	// Herunterladen: mit eigenem Passwort lesbar, mit dem Schlüssel nicht mehr
	if _, err := ExportPoint(dir, b.ID, "kurz"); err == nil {
		t.Fatal("kurzes Passwort angenommen")
	}
	exp, err := ExportPoint(dir, b.ID, "ein-langes-passwort")
	must(err)
	if _, err := Open(exp, "ein-langes-passwort"); err != nil {
		t.Fatal(err)
	}
	key, _ := pointKey(dir)
	if _, err := Open(exp, key); err == nil {
		t.Fatal("Export mit Installationsschlüssel lesbar")
	}

	// Pfade von außen werden abgelehnt
	for _, id := range []string{"../panel", "x", "20260101-000000-auto/../../a"} {
		if _, err := OpenPoint(dir, id); err == nil {
			t.Fatalf("%q angenommen", id)
		}
		if DeletePoint(dir, id) == nil {
			t.Fatalf("Löschen %q angenommen", id)
		}
	}

	// Aufräumen: je Art die neuesten behalten, manuelle nur mit Grenze
	var autos []string
	for i := 0; i < 4; i++ {
		p, err := CreatePoint(dir, snap, m, KindAuto, "")
		must(err)
		autos = append(autos, p.ID)
	}
	must(os.MkdirAll(filepath.Join(dir, "restore-bak-20260101-000000"), 0o700))
	for _, n := range []string{"20260102", "20260103", "20260104"} {
		must(os.MkdirAll(filepath.Join(dir, "restore-bak-"+n+"-000000"), 0o700))
	}
	removed, err := PrunePoints(dir, map[string]int{KindAuto: 2}, autos[0])
	must(err)
	if len(removed) != 1 {
		t.Fatalf("gelöscht: %v", removed)
	}
	list, err := ListPoints(dir)
	must(err)
	kinds := map[string]int{}
	for _, p := range list {
		kinds[p.Kind]++
	}
	if kinds[KindAuto] != 3 || kinds[KindManual] != 2 { // autos[0] geschützt
		t.Fatalf("nach Aufräumen: %v", kinds)
	}
	if _, err := os.Stat(filepath.Join(dir, "restore-bak-20260101-000000")); !os.IsNotExist(err) {
		t.Fatal("ältester restore-bak-Ordner nicht gelöscht")
	}
	must(DeletePoint(dir, a.ID))
	if _, err := GetPoint(dir, a.ID); err == nil {
		t.Fatal("gelöschter Punkt noch da")
	}
	// Einspielen über Stage/ApplyPending
	arc, err = OpenPoint(dir, b.ID)
	must(err)
	must(os.WriteFile(filepath.Join(dir, "secrets.env"), []byte("X=2\n"), 0o600))
	must(Stage(dir, arc, nil))
	if _, err := ApplyPending(dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "secrets.env")); string(got) != "X=1\n" {
		t.Fatalf("nach Einspielen: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, PointsDir, b.ID+".vpnbak")); err != nil {
		t.Fatal("Punkte nach dem Einspielen weg")
	}
}
