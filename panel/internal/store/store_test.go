package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotAndLoginLog(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SaveAdmin(&Admin{Username: "admin", PassHash: "x", Email: "a@example.org", Notify: true}); err != nil {
		t.Fatal(err)
	}
	s.AddLogin(&LoginEntry{Username: "admin", OK: true})
	s.AddLogin(&LoginEntry{Username: "x", Reason: "Passwort falsch"})
	if ok, failed, _ := s.LoginCounts(0); ok != 1 || failed != 1 {
		t.Fatalf("Zähler %d/%d", ok, failed)
	}
	adm, _ := s.AdminByName("ADMIN")
	if adm.Email != "a@example.org" || !adm.Notify {
		t.Fatalf("Admin: %+v", adm)
	}

	full, slim := filepath.Join(dir, "full.db"), filepath.Join(dir, "slim.db")
	if err := s.Snapshot(full, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Snapshot(slim, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{full, slim} {
		if err := CheckBackupDB(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	c, _ := Open(slim)
	if l, _ := c.Logins(10); len(l) != 0 {
		t.Error("Anmeldeprotokoll trotz „ohne Protokolle“")
	}
	if a, _ := c.Admins(); len(a) != 1 {
		t.Error("Administrator fehlt in der Kopie")
	}
	c.Close()
	c, _ = Open(full)
	if l, _ := c.Logins(10); len(l) != 2 {
		t.Error("Anmeldeprotokoll fehlt in der vollen Kopie")
	}
	_, _ = c.db.Exec(`INSERT INTO schema_version (v) VALUES (999)`)
	c.Close()
	if err := CheckBackupDB(full); err == nil || !strings.Contains(err.Error(), "neueren") {
		t.Errorf("neuere Datenbank: %v", err)
	}
}
