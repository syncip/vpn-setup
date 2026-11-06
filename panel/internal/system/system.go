// Package system kapselt Befehle und Dateizugriffe. Im Trockenlauf (Entwicklung
// unter Windows) werden Befehle nur protokolliert und Dateien in ein Testverzeichnis geschrieben.
package system

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runner interface {
	// Run führt einen Befehl aus und liefert stdout (stderr steht im Fehler).
	Run(name string, args ...string) (string, error)
	// RunInput wie Run, schreibt input auf stdin.
	RunInput(input, name string, args ...string) (string, error)
	// WriteFile schreibt nur bei Änderung, liefert true wenn geändert.
	WriteFile(path string, data []byte, perm os.FileMode) (bool, error)
	ReadFile(path string) ([]byte, error)
	Remove(path string) error
	Exists(path string) bool
	DryRun() bool
	// Log liefert die letzten Befehle (nur Trockenlauf, für Diagnose).
	Log() []string
}

// ---------- echtes System ----------

type Real struct{}

func (Real) DryRun() bool   { return false }
func (Real) Log() []string { return nil }

func (r Real) Run(name string, args ...string) (string, error) { return r.RunInput("", name, args...) }

func (Real) RunInput(input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		return out.String(), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, msg)
	}
	return out.String(), nil
}

func (Real) WriteFile(path string, data []byte, perm os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		_ = os.Chmod(path, perm)
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}

func (Real) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (Real) Remove(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (Real) Exists(path string) bool { _, err := os.Stat(path); return err == nil }

// ---------- Trockenlauf ----------

type Dry struct {
	Root string // Dateien landen unter Root/<pfad>
	mu   sync.Mutex
	log  []string
	// Inputs: letzte stdin-Eingabe pro Befehl (für Tests, z. B. iptables-restore)
	Inputs map[string]string
}

func (d *Dry) DryRun() bool { return true }

func (d *Dry) add(s string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, time.Now().Format("15:04:05 ")+s)
	if len(d.log) > 500 {
		d.log = d.log[len(d.log)-500:]
	}
	log.Printf("[dry] %s", s)
}

func (d *Dry) Log() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.log...)
}

func (d *Dry) Run(name string, args ...string) (string, error) { return d.RunInput("", name, args...) }

func (d *Dry) RunInput(input, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	if input != "" {
		line += fmt.Sprintf("  <<stdin %d Zeilen>>", strings.Count(input, "\n")+1)
		d.mu.Lock()
		if d.Inputs == nil {
			d.Inputs = map[string]string{}
		}
		d.Inputs[name] = input
		d.mu.Unlock()
	}
	d.add(line)
	return "", nil
}

func (d *Dry) path(p string) string {
	return filepath.Join(d.Root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
}

func (d *Dry) WriteFile(path string, data []byte, perm os.FileMode) (bool, error) {
	changed, err := Real{}.WriteFile(d.path(path), data, perm)
	if changed {
		d.add("write " + path)
	}
	return changed, err
}

func (d *Dry) ReadFile(path string) ([]byte, error) { return os.ReadFile(d.path(path)) }
func (d *Dry) Remove(path string) error {
	if d.Exists(path) {
		d.add("rm " + path)
	}
	return Real{}.Remove(d.path(path))
}
func (d *Dry) Exists(path string) bool { _, err := os.Stat(d.path(path)); return err == nil }
