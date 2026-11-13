package engine

import (
	"os"
	"path/filepath"
	"strings"
)

// Zugangsdaten (Cloudflare-Token, SMTP-Passwort) liegen nur in <data>/secrets.env (Rechte 600),
// nie in der Datenbank und nie in einer Sicherung ohne Verschlüsselung.

func (e *Engine) secretsPath() string { return filepath.Join(e.Cfg.DataDir, "secrets.env") }

// secret liest KEY=… aus secrets.env (oder der Umgebung).
func (e *Engine) secret(key string) string {
	if b, err := os.ReadFile(e.secretsPath()); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "export "))
			if v, ok := strings.CutPrefix(l, key+"="); ok {
				return strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	return os.Getenv(key)
}

// setSecret schreibt KEY=val in secrets.env; leer = Zeile entfernen. Andere Zeilen bleiben unverändert.
// comment steht vor einer neuen Zeile.
func (e *Engine) setSecret(key, val, comment string) error {
	path := e.secretsPath()
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var lines []string
	done := false
	for _, l := range strings.Split(strings.TrimRight(string(old), "\n"), "\n") {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "export "))
		if strings.HasPrefix(t, key+"=") {
			if val != "" && !done {
				lines = append(lines, key+"="+val)
				done = true
			}
			continue
		}
		if l != "" || len(lines) > 0 {
			lines = append(lines, l)
		}
	}
	if val != "" && !done {
		if comment != "" {
			lines = append(lines, "# "+comment)
		}
		lines = append(lines, key+"="+val)
	}
	if err := os.MkdirAll(e.Cfg.DataDir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, path)
}
