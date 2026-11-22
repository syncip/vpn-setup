package engine

// Wiederherstellungspunkte (siehe internal/backup/points.go): täglich automatisch, vor Updates,
// vor dem Einspielen einer Sicherung und von Hand. Die Datenbank wird ohne Protokolle gesichert.

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"vpnpanel/internal/backup"
	"vpnpanel/internal/store"
)

type pointState struct {
	mu      sync.Mutex
	lastErr string
	lastAt  int64
}

// Aufbewahrung je Art (manuelle Punkte löscht das Panel nie selbst)
const (
	keepUpdatePoints  = 5
	keepRestorePoints = 5
)

func (e *Engine) pointKeep() map[string]int {
	return map[string]int{
		backup.KindAuto:    atoi(e.Setting("backup_keep"), 7),
		backup.KindUpdate:  keepUpdatePoints,
		backup.KindRestore: keepRestorePoints,
	}
}

// CreatePoint legt einen Wiederherstellungspunkt an und räumt danach alte auf.
func (e *Engine) CreatePoint(version, kind, note string) (*backup.Point, error) {
	e.pts.mu.Lock()
	defer e.pts.mu.Unlock()
	p, err := backup.CreatePoint(e.Cfg.DataDir, func(path string) error { return e.St.Snapshot(path, false) },
		backup.Manifest{Version: version, Schema: store.SchemaVersion(), Host: e.Setting("server_host")}, kind, note)
	if err != nil {
		e.pts.lastErr = err.Error()
		e.Log("error", "Wiederherstellungspunkt anlegen: "+err.Error())
		return nil, err
	}
	e.pts.lastErr, e.pts.lastAt = "", p.Created
	if removed, err := backup.PrunePoints(e.Cfg.DataDir, e.pointKeep(), p.ID); err != nil {
		e.Log("warn", "Alte Wiederherstellungspunkte aufräumen: "+err.Error())
	} else if len(removed) > 0 {
		e.Log("info", fmt.Sprintf("%d alte Wiederherstellungspunkte gelöscht", len(removed)))
	}
	return p, nil
}

// PointsInfo: Liste und Einstellungen für die Oberfläche.
func (e *Engine) PointsInfo() map[string]any {
	list, err := backup.ListPoints(e.Cfg.DataDir)
	out := map[string]any{"points": list, "auto": e.Setting("backup_auto") != "0", "keep": atoi(e.Setting("backup_keep"), 7),
		"keep_update": keepUpdatePoints, "keep_restore": keepRestorePoints}
	var total int64
	for _, p := range list {
		total += p.Size
	}
	out["total"] = total
	e.pts.mu.Lock()
	if e.pts.lastErr != "" {
		out["error"] = e.pts.lastErr
	}
	e.pts.mu.Unlock()
	if err != nil {
		out["error"] = err.Error()
	}
	return out
}

// RunBackups: einmal am Tag einen automatischen Punkt (Prüfung stündlich, erste nach 2 Minuten).
func (e *Engine) RunBackups(stop <-chan struct{}, version string) {
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		e.autoPoint(version, time.Now())
		t.Reset(time.Hour)
	}
}

func (e *Engine) autoPoint(version string, now time.Time) {
	if e.Setting("backup_auto") == "0" {
		return
	}
	list, err := backup.ListPoints(e.Cfg.DataDir)
	if err != nil {
		e.Log("error", "Wiederherstellungspunkte lesen: "+err.Error())
		return
	}
	for _, p := range list {
		if p.Kind == backup.KindAuto {
			if now.Unix()-p.Created < 23*3600+30*60 {
				return // heute schon
			}
			break
		}
	}
	if p, err := e.CreatePoint(version, backup.KindAuto, ""); err == nil {
		e.Log("info", "Täglicher Wiederherstellungspunkt angelegt ("+p.ID+", "+strconv.FormatInt(p.Size/1024, 10)+" KB)")
	}
}
