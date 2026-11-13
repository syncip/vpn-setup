// Package backup: verschlüsselte Sicherung des Datenverzeichnisses (Datenbank, Zugangsdaten,
// Zertifikate) und Wiederherstellung beim nächsten Start des Dienstes.
//
// Dateiformat: „VPNPBAK1“ | log2(N) | r | p | Salz (16) | Nonce (12) | AES-256-GCM(tar.gz)
// Der Schlüssel kommt per scrypt aus dem Passwort, der Kopf ist als Zusatzdaten mit geschützt.
// Im Archiv liegt manifest.json (Version, Zeitpunkt, Dateien mit SHA-256) und files/<pfad>.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	magic       = "VPNPBAK1"
	headerLen   = len(magic) + 3 + 16 + 12
	scryptLogN  = 15
	MinPassword = 12
	maxFile     = 50 << 20  // einzelne Datei
	maxTotal    = 768 << 20 // ganzes Archiv entpackt
	DBName      = "panel.db"
	PendingDir  = "restore-pending"
)

// Manifest: Inhalt einer Sicherung.
type Manifest struct {
	Format   int      `json:"format"`
	Version  string   `json:"version"` // Panel-Version
	Schema   int      `json:"schema"`  // Datenbank-Stand
	Created  int64    `json:"created"`
	Host     string   `json:"host"`
	WithLogs bool     `json:"with_logs"`
	Files    []Entry  `json:"files"`
	Skipped  []string `json:"skipped,omitempty"`
}

type Entry struct {
	Name   string `json:"name"` // relativ zum Datenverzeichnis, mit /
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// Archive: entschlüsselte, geprüfte Sicherung.
type Archive struct {
	Manifest Manifest
	Files    map[string][]byte
}

// skipDirs/skipFiles: nicht sichern (neu ladbar, Laufzeitdaten oder Testmodus).
var skipDirs = map[string]bool{"dryroot": true, "lists": true, "dnslists": true, PendingDir: true}

func skipFile(name string) bool {
	base := path.Base(name)
	switch base {
	case DBName, DBName + "-wal", DBName + "-shm", DBName + "-journal", "dnscache.json", "geo.gob", "panel-admin.txt":
		return true
	}
	for _, suf := range []string{".exe", ".tmp", ".log", ".vpnbak"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return strings.HasPrefix(base, ".backup-") || strings.Contains(base, ".bak-")
}

// Create sichert dataDir: snapshot schreibt die Datenbank-Kopie, m liefert Version/Host.
func Create(dataDir string, snapshot func(dbPath string) error, m Manifest, password string) ([]byte, error) {
	if len([]rune(password)) < MinPassword {
		return nil, fmt.Errorf("Passwort für die Sicherung: mindestens %d Zeichen", MinPassword)
	}
	tmp, err := os.MkdirTemp(dataDir, ".backup-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	_ = os.Chmod(tmp, 0o700)
	dbPath := filepath.Join(tmp, DBName)
	if err := snapshot(dbPath); err != nil {
		return nil, fmt.Errorf("Datenbank-Kopie: %w", err)
	}
	files := map[string][]byte{}
	db, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, err
	}
	files[DBName] = db
	modes := map[string]uint32{DBName: 0o600}
	total := int64(len(db))
	tmpBase := filepath.Base(tmp)
	err = filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dataDir, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if skipDirs[rel] || rel == tmpBase || strings.HasPrefix(path.Base(rel), "restore-bak-") || strings.HasPrefix(path.Base(rel), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || skipFile(rel) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxFile || total+info.Size() > maxTotal {
			m.Skipped = append(m.Skipped, rel)
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		files[rel] = b
		modes[rel] = uint32(info.Mode().Perm())
		total += int64(len(b))
		return nil
	})
	if err != nil {
		return nil, err
	}
	m.Format, m.Created, m.Files = 1, time.Now().Unix(), nil
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		m.Files = append(m.Files, Entry{Name: n, Size: int64(len(files[n])), SHA256: hex.EncodeToString(sum[:]), Mode: modes[n]})
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	man, _ := json.MarshalIndent(m, "", "  ")
	put := func(name string, b []byte, mode uint32) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(mode), Size: int64(len(b)), ModTime: time.Unix(m.Created, 0), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := put("manifest.json", man, 0o600); err != nil {
		return nil, err
	}
	for _, e := range m.Files {
		if err := put("files/"+e.Name, files[e.Name], e.Mode); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return seal(buf.Bytes(), password)
}

func deriveKey(password string, salt []byte, logN, r, p int) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<logN, r, p, 32)
}

func seal(plain []byte, password string) ([]byte, error) {
	head := make([]byte, headerLen)
	copy(head, magic)
	head[len(magic)], head[len(magic)+1], head[len(magic)+2] = scryptLogN, 8, 1
	if _, err := rand.Read(head[len(magic)+3:]); err != nil {
		return nil, err
	}
	salt := head[len(magic)+3 : len(magic)+19]
	nonce := head[len(magic)+19:]
	key, err := deriveKey(password, salt, scryptLogN, 8, 1)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	return gcm.Seal(head, nonce, plain, head), nil
}

// ErrPassword: falsches Passwort oder veränderte Datei (GCM unterscheidet das nicht).
var ErrPassword = errors.New("Passwort falsch oder Datei beschädigt bzw. verändert")

// Open entschlüsselt und prüft eine Sicherung (Pfade, Größen, Prüfsummen, Manifest).
func Open(data []byte, password string) (*Archive, error) {
	if len(data) < headerLen+16 || string(data[:len(magic)]) != magic {
		return nil, errors.New("keine Sicherung des VPN-Panels")
	}
	head := data[:headerLen]
	logN, r, p := int(head[len(magic)]), int(head[len(magic)+1]), int(head[len(magic)+2])
	if logN < 14 || logN > 20 || r < 1 || r > 16 || p < 1 || p > 4 { // gegen künstlich teure Schlüsselableitung
		return nil, errors.New("Sicherung mit unbekannten Parametern")
	}
	key, err := deriveKey(password, head[len(magic)+3:len(magic)+19], logN, r, p)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	plain, err := gcm.Open(nil, head[len(magic)+19:], data[headerLen:], head)
	if err != nil {
		return nil, ErrPassword
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(io.LimitReader(gz, maxTotal+(1<<20)))
	a := &Archive{Files: map[string][]byte{}}
	var man []byte
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Archiv: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("Archiv: unerwarteter Eintrag %q", h.Name)
		}
		if h.Size > maxFile || total+h.Size > maxTotal {
			return nil, errors.New("Archiv: Datei zu groß")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, err
		}
		total += int64(len(b))
		switch {
		case h.Name == "manifest.json":
			man = b
		case strings.HasPrefix(h.Name, "files/"):
			name := strings.TrimPrefix(h.Name, "files/")
			if !safeName(name) {
				return nil, fmt.Errorf("Archiv: ungültiger Pfad %q", name)
			}
			if _, dup := a.Files[name]; dup {
				return nil, fmt.Errorf("Archiv: %q doppelt", name)
			}
			a.Files[name] = b
		default:
			return nil, fmt.Errorf("Archiv: unerwarteter Eintrag %q", h.Name)
		}
	}
	if man == nil {
		return nil, errors.New("Archiv ohne Inhaltsverzeichnis")
	}
	if err := json.Unmarshal(man, &a.Manifest); err != nil {
		return nil, fmt.Errorf("Inhaltsverzeichnis: %w", err)
	}
	if a.Manifest.Format != 1 {
		return nil, errors.New("unbekanntes Sicherungsformat")
	}
	if len(a.Manifest.Files) != len(a.Files) {
		return nil, errors.New("Inhaltsverzeichnis passt nicht zu den Dateien")
	}
	hasDB := false
	for _, e := range a.Manifest.Files {
		b, ok := a.Files[e.Name]
		sum := sha256.Sum256(b)
		if !ok || !safeName(e.Name) || int64(len(b)) != e.Size || hex.EncodeToString(sum[:]) != e.SHA256 {
			return nil, fmt.Errorf("Prüfsumme von %s stimmt nicht", e.Name)
		}
		hasDB = hasDB || e.Name == DBName
	}
	if !hasDB {
		return nil, errors.New("Sicherung ohne Datenbank")
	}
	return a, nil
}

// safeName: relativer Pfad ohne „..“, ohne Laufwerk, nicht in übersprungenen Ordnern.
func safeName(n string) bool {
	if n == "" || len(n) > 255 || strings.ContainsAny(n, "\\:\x00") || path.IsAbs(n) || path.Clean(n) != n || n == "." {
		return false
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	first, _, _ := strings.Cut(n, "/")
	return !skipDirs[first] && !strings.HasPrefix(first, "restore-bak-")
}

// Stage legt die Sicherung zum Einspielen beim nächsten Start ab (<data>/restore-pending).
// check prüft die Datenbank (z. B. Version, Administratoren) vorher.
func Stage(dataDir string, a *Archive, check func(dbPath string) error) error {
	pend := filepath.Join(dataDir, PendingDir)
	_ = os.RemoveAll(pend)
	if err := os.MkdirAll(pend, 0o700); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(pend)
		}
	}()
	for _, e := range a.Manifest.Files {
		dst := filepath.Join(pend, "files", filepath.FromSlash(e.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		mode := os.FileMode(e.Mode & 0o777)
		if mode == 0 {
			mode = 0o600
		}
		if err := os.WriteFile(dst, a.Files[e.Name], mode); err != nil {
			return err
		}
	}
	if check != nil {
		if err := check(filepath.Join(pend, "files", DBName)); err != nil {
			return err
		}
	}
	man, _ := json.Marshal(a.Manifest)
	// manifest.json zuletzt: erst damit gilt die Wiederherstellung als vollständig abgelegt
	if err := os.WriteFile(filepath.Join(pend, "manifest.json"), man, 0o600); err != nil {
		return err
	}
	ok = true
	return nil
}

// Pending: liegt eine vollständig abgelegte Wiederherstellung bereit?
func Pending(dataDir string) (*Manifest, bool) {
	b, err := os.ReadFile(filepath.Join(dataDir, PendingDir, "manifest.json"))
	if err != nil {
		return nil, false
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	return &m, true
}

// Discard verwirft eine abgelegte Wiederherstellung.
func Discard(dataDir string) error { return os.RemoveAll(filepath.Join(dataDir, PendingDir)) }

// ApplyPending spielt eine abgelegte Wiederherstellung ein (vor dem Öffnen der Datenbank!).
// Bisherige Dateien wandern nach <data>/restore-bak-<zeit>/. Liefert den Ordner der alten Dateien.
func ApplyPending(dataDir string) (string, error) {
	m, ok := Pending(dataDir)
	if !ok {
		_ = os.RemoveAll(filepath.Join(dataDir, PendingDir)) // unvollständig abgelegt → verwerfen
		return "", nil
	}
	pend := filepath.Join(dataDir, PendingDir)
	bak := filepath.Join(dataDir, "restore-bak-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(bak, 0o700); err != nil {
		return "", err
	}
	moveOld := func(rel string) error {
		src := filepath.Join(dataDir, filepath.FromSlash(rel))
		if _, err := os.Lstat(src); err != nil {
			return nil
		}
		dst := filepath.Join(bak, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return os.Rename(src, dst)
	}
	for _, rel := range []string{DBName + "-wal", DBName + "-shm", DBName + "-journal"} {
		if err := moveOld(rel); err != nil {
			return "", err
		}
	}
	for _, e := range m.Files {
		if !safeName(e.Name) {
			return "", fmt.Errorf("ungültiger Pfad %q", e.Name)
		}
		src := filepath.Join(pend, "files", filepath.FromSlash(e.Name))
		b, err := os.ReadFile(src)
		if err != nil {
			return "", fmt.Errorf("%s: %w", e.Name, err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != e.SHA256 {
			return "", fmt.Errorf("Prüfsumme von %s stimmt nicht", e.Name)
		}
		if err := moveOld(e.Name); err != nil {
			return "", err
		}
		dst := filepath.Join(dataDir, filepath.FromSlash(e.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		if err := os.Rename(src, dst); err != nil {
			return "", err
		}
	}
	return bak, os.RemoveAll(pend)
}
