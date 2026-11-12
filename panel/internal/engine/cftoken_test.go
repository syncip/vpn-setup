package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetCFToken: Token landet nur in secrets.env (600), andere Zeilen bleiben, Entfernen geht.
func TestSetCFToken(t *testing.T) {
	e, _ := newTest(t)
	path := filepath.Join(e.Cfg.DataDir, "secrets.env")
	if err := os.WriteFile(path, []byte("# Kommentar\nANDERES=1\nCF_API_TOKEN=alt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := strings.Repeat("Ab3_-", 8)
	if err := e.SetCFToken(tok); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "# Kommentar\nANDERES=1\nCF_API_TOKEN="+tok+"\n" || e.cfToken() != tok {
		t.Errorf("Datei:\n%s", b)
	}
	if err := e.SetCFToken("mit leerzeichen und so weiter"); err == nil {
		t.Error("ungültiges Token angenommen")
	}
	if err := e.SetCFToken(""); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "CF_API_TOKEN") || !strings.Contains(string(b), "ANDERES=1") || e.cfToken() != "" {
		t.Errorf("nach dem Entfernen:\n%s", b)
	}
}
