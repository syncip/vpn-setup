package backup

// Wiederherstellungspunkte: Sicherungen, die das Panel selbst im Datenverzeichnis ablegt
// (<data>/backups/<id>.vpnbak + <id>.json). Verschlüsselt mit einem Schlüssel dieser Installation
// (<data>/backup.key, wird nie mitgesichert). Zum Herunterladen wird mit einem eigenen Passwort
// neu verschlüsselt, damit die Datei auch auf einem anderen Server eingespielt werden kann.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	PointsDir       = "backups"
	KeyFile         = "backup.key"
	UpdateStateFile = "update.json" // Zustand eines laufenden Updates (siehe engine/selfupdate.go)
)

// Arten von Punkten
const (
	KindAuto    = "auto"    // täglich
	KindManual  = "manual"  // von Hand angelegt
	KindUpdate  = "update"  // vor einem Update
	KindRestore = "restore" // vor dem Einspielen einer Sicherung oder einem Rücksprung
)

// Point: ein Wiederherstellungspunkt.
type Point struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Kind    string `json:"kind"`
	Note    string `json:"note,omitempty"`
	Version string `json:"version"`
	Schema  int    `json:"schema"`
	Size    int64  `json:"size"`
	Files   int    `json:"files"`
}

var pointIDRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[a-z]+(-[0-9]+)?$`)

// ValidPointID: nur selbst erzeugte Namen (kein Pfad).
func ValidPointID(id string) bool { return pointIDRe.MatchString(id) }

func pointsDir(dataDir string) string { return filepath.Join(dataDir, PointsDir) }

// pointKey liest den Schlüssel der Installation oder legt ihn an.
func pointKey(dataDir string) (string, error) {
	f := filepath.Join(dataDir, KeyFile)
	if b, err := os.ReadFile(f); err == nil {
		k := strings.TrimSpace(string(b))
		if len(k) >= 32 {
			return k, nil
		}
		return "", fmt.Errorf("%s ist beschädigt", f)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	k := hex.EncodeToString(raw)
	// O_EXCL: zwei gleichzeitige Aufrufe dürfen sich nicht gegenseitig den Schlüssel überschreiben
	fh, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return pointKey(dataDir)
		}
		return "", err
	}
	if _, err := fh.WriteString(k + "\n"); err != nil {
		fh.Close()
		return "", err
	}
	return k, fh.Close()
}

// CreatePoint legt einen Wiederherstellungspunkt an.
func CreatePoint(dataDir string, snapshot func(dbPath string) error, m Manifest, kind, note string) (*Point, error) {
	if !pointIDRe.MatchString("20000101-000000-" + kind) {
		return nil, fmt.Errorf("unbekannte Art %q", kind)
	}
	if len([]rune(note)) > 200 {
		note = string([]rune(note)[:200])
	}
	key, err := pointKey(dataDir)
	if err != nil {
		return nil, fmt.Errorf("Schlüssel: %w", err)
	}
	dir := pointsDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	data, err := Create(dataDir, snapshot, m, key)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	base := now.Format("20060102-150405") + "-" + kind
	id := base
	for i := 2; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, id+".vpnbak")); errors.Is(err, os.ErrNotExist) {
			break
		}
		id = fmt.Sprintf("%s-%d", base, i)
	}
	// Dateianzahl aus dem Archiv (Create liefert nur die verschlüsselten Bytes)
	files := 0
	if a, err := Open(data, key); err == nil {
		files = len(a.Manifest.Files)
	} else {
		return nil, fmt.Errorf("Prüfung der neuen Sicherung: %w", err)
	}
	p := &Point{ID: id, Created: now.Unix(), Kind: kind, Note: note, Version: m.Version, Schema: m.Schema, Size: int64(len(data)), Files: files}
	tmp := filepath.Join(dir, "."+id+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, id+".vpnbak")); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	meta, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, id+".json"), meta, 0o600); err != nil {
		return nil, err
	}
	return p, nil
}

// ListPoints: alle Punkte, neueste zuerst.
func ListPoints(dataDir string) ([]Point, error) {
	ents, err := os.ReadDir(pointsDir(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return []Point{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Point{}
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidPointID(id) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(pointsDir(dataDir), e.Name()))
		if err != nil {
			continue
		}
		var p Point
		if json.Unmarshal(b, &p) != nil || p.ID != id {
			continue
		}
		if st, err := os.Stat(filepath.Join(pointsDir(dataDir), id+".vpnbak")); err != nil {
			continue // Datei fehlt → nicht anbieten
		} else {
			p.Size = st.Size()
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created > out[j].Created
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// GetPoint: Angaben zu einem Punkt.
func GetPoint(dataDir, id string) (*Point, error) {
	all, err := ListPoints(dataDir)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, errors.New("Wiederherstellungspunkt nicht gefunden")
}

func readPoint(dataDir, id string) ([]byte, string, error) {
	if !ValidPointID(id) {
		return nil, "", errors.New("ungültiger Wiederherstellungspunkt")
	}
	data, err := os.ReadFile(filepath.Join(pointsDir(dataDir), id+".vpnbak"))
	if err != nil {
		return nil, "", errors.New("Wiederherstellungspunkt nicht gefunden")
	}
	key, err := pointKey(dataDir)
	if err != nil {
		return nil, "", err
	}
	return data, key, nil
}

// OpenPoint entschlüsselt und prüft einen Punkt.
func OpenPoint(dataDir, id string) (*Archive, error) {
	data, key, err := readPoint(dataDir, id)
	if err != nil {
		return nil, err
	}
	a, err := Open(data, key)
	if err != nil {
		return nil, fmt.Errorf("Wiederherstellungspunkt %s: %w", id, err)
	}
	return a, nil
}

// ExportPoint: Punkt mit eigenem Passwort neu verschlüsselt (zum Herunterladen).
func ExportPoint(dataDir, id, password string) ([]byte, error) {
	data, key, err := readPoint(dataDir, id)
	if err != nil {
		return nil, err
	}
	return Reseal(data, key, password)
}

// DeletePoint löscht einen Punkt.
func DeletePoint(dataDir, id string) error {
	if !ValidPointID(id) {
		return errors.New("ungültiger Wiederherstellungspunkt")
	}
	dir := pointsDir(dataDir)
	err := os.Remove(filepath.Join(dir, id+".vpnbak"))
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if e2 := os.Remove(filepath.Join(dir, id+".json")); e2 != nil && !errors.Is(e2, os.ErrNotExist) && err == nil {
		err = e2
	}
	return err
}

// PrunePoints löscht je Art die ältesten Punkte über keep[art] hinaus (0 oder fehlend = alle behalten)
// und protect nie. Außerdem bleiben nur die letzten 3 Ordner „restore-bak-*“ (alte Dateien nach dem Einspielen).
func PrunePoints(dataDir string, keep map[string]int, protect ...string) (removed []string, err error) {
	all, err := ListPoints(dataDir)
	if err != nil {
		return nil, err
	}
	keepID := map[string]bool{}
	for _, id := range protect {
		keepID[id] = true
	}
	seen := map[string]int{}
	for _, p := range all { // neueste zuerst
		seen[p.Kind]++
		if n := keep[p.Kind]; n > 0 && seen[p.Kind] > n && !keepID[p.ID] {
			if err := DeletePoint(dataDir, p.ID); err != nil {
				return removed, err
			}
			removed = append(removed, p.ID)
		}
	}
	// alte Dateien früherer Wiederherstellungen
	ents, _ := os.ReadDir(dataDir)
	var baks []string
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "restore-bak-") {
			baks = append(baks, e.Name())
		}
	}
	sort.Strings(baks)
	for len(baks) > 3 {
		_ = os.RemoveAll(filepath.Join(dataDir, baks[0]))
		baks = baks[1:]
	}
	return removed, nil
}
