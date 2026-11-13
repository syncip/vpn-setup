package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, rel, s string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	src := t.TempDir()
	write(t, src, "panel.db", "laufende Datenbank – darf nicht direkt gesichert werden")
	write(t, src, "secrets.env", "SMTP_PASSWORD=x\n")
	write(t, src, "dns-tls/cert.pem", "CERT")
	write(t, src, "geo.gob", "neu ladbar")
	write(t, src, "lists/1.txt", "neu ladbar")
	write(t, src, "dryroot/etc/x", "Testmodus")
	write(t, src, "panel-admin.txt", "Startpasswort")
	snap := func(p string) error { return os.WriteFile(p, []byte("SNAPSHOT"), 0o600) }
	data, err := Create(src, snap, Manifest{Version: "0.15.0", Host: "h"}, "richtig-langes-passwort")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("SMTP_PASSWORD")) || bytes.Contains(data, []byte("SNAPSHOT")) {
		t.Fatal("Inhalt nicht verschlüsselt")
	}
	if _, err := Open(data, "falsches-passwort-123"); !errors.Is(err, ErrPassword) {
		t.Fatalf("falsches Passwort: %v", err)
	}
	bad := append([]byte(nil), data...)
	bad[len(bad)-40] ^= 1
	if _, err := Open(bad, "richtig-langes-passwort"); !errors.Is(err, ErrPassword) {
		t.Fatalf("veränderte Datei: %v", err)
	}
	a, err := Open(data, "richtig-langes-passwort")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"panel.db": "SNAPSHOT", "secrets.env": "SMTP_PASSWORD=x\n", "dns-tls/cert.pem": "CERT"}
	if len(a.Files) != len(want) {
		t.Fatalf("Dateien: %v", keys(a.Files))
	}
	for k, v := range want {
		if string(a.Files[k]) != v {
			t.Errorf("%s = %q", k, a.Files[k])
		}
	}
	if a.Manifest.Version != "0.15.0" {
		t.Errorf("Manifest: %+v", a.Manifest)
	}

	// Ablegen und beim „Start“ einspielen
	dst := t.TempDir()
	write(t, dst, "panel.db", "ALT")
	write(t, dst, "panel.db-wal", "ALT-WAL")
	write(t, dst, "secrets.env", "ALT\n")
	if err := Stage(dst, a, func(p string) error { return errors.New("zu neu") }); err == nil {
		t.Fatal("Prüfung der Datenbank ignoriert")
	}
	if _, ok := Pending(dst); ok {
		t.Fatal("abgelehnte Sicherung liegt bereit")
	}
	if err := Stage(dst, a, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "panel.db")); string(b) != "ALT" {
		t.Fatal("Stage darf nichts überschreiben")
	}
	bak, err := ApplyPending(dst)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if b, _ := os.ReadFile(filepath.Join(dst, filepath.FromSlash(k))); string(b) != v {
			t.Errorf("nach dem Einspielen %s = %q", k, b)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "panel.db-wal")); err == nil {
		t.Error("alte WAL-Datei noch da")
	}
	if b, _ := os.ReadFile(filepath.Join(bak, "panel.db")); string(b) != "ALT" {
		t.Error("alte Datenbank nicht aufgehoben")
	}
	if _, ok := Pending(dst); ok {
		t.Error("Wiederherstellung liegt noch bereit")
	}
	// Ohne Wiederherstellung passiert nichts
	if b, err := ApplyPending(dst); err != nil || b != "" {
		t.Errorf("leer: %q %v", b, err)
	}
}

func TestShortPassword(t *testing.T) {
	if _, err := Create(t.TempDir(), func(string) error { return nil }, Manifest{}, "kurz"); err == nil {
		t.Fatal("kurzes Passwort angenommen")
	}
}

func TestSafeName(t *testing.T) {
	for n, ok := range map[string]bool{"panel.db": true, "dns-tls/a.pem": true, "../x": false, "/etc/passwd": false, "a/../../b": false,
		"a//b": false, "C:x": false, "dryroot/x": false, "restore-bak-1/x": false, "": false, "a\\b": false} {
		if safeName(n) != ok {
			t.Errorf("safeName(%q) != %v", n, ok)
		}
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
