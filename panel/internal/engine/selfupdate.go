package engine

// Update aus dem Panel mit automatischem Rücksprung.
//
// Ablauf:
//  1. Panel lädt das Programm des neuesten Releases neben das laufende (/usr/local/bin/.vpnpanel.new)
//     und prüft es gegen die SHA-256-Prüfsumme, die GitHub zur Release-Datei angibt; danach muss
//     „.vpnpanel.new version“ die erwartete Version melden.
//  2. Wiederherstellungspunkt „vor Update“, Kopie des laufenden Programms als vpnpanel.prev.
//  3. Ein eigener Wächter (systemd-run, außerhalb von vpnpanel.service, läuft mit dem ALTEN Programm)
//     tauscht das Programm aus und startet den Dienst neu.
//  4. Das neue Programm meldet nach dem Start „ok“ (ConfirmUpdate). Kommt das nicht innerhalb von
//     2 Minuten oder stürzt der Dienst danach ab, setzt der Wächter das alte Programm und den
//     Wiederherstellungspunkt zurück und startet erneut.
//
// Der Zustand steht in <data>/update.json (beide Prozesse lesen und schreiben ihn).
// vpn-setup.sh führt das Panel nicht aus – ändert ein Release auch das Setup, wird das angezeigt.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/backup"
	"vpnpanel/internal/store"
)

const (
	releaseTagAPI   = "https://api.github.com/repos/syncip/vpn-setup/releases/tags/"
	releaseDownload = "https://github.com/syncip/vpn-setup/releases/download/"
	maxBinary       = 200 << 20
	updateWait      = 2 * time.Minute  // so lange darf das neue Programm bis „ok“ brauchen
	updateSettle    = 20 * time.Second // danach muss es noch so lange ohne Absturz laufen
	updateStale     = 15 * time.Minute // ohne Rückmeldung gilt ein Update als abgebrochen
	updateUnit      = "vpnpanel-update"
	newBinaryName   = ".vpnpanel.new"
	prevBinaryName  = "vpnpanel.prev"
)

// UpdateRun: Zustand eines Updates bzw. Rücksprungs (update.json).
type UpdateRun struct {
	Mode     string   `json:"mode"`  // update | rollback
	State    string   `json:"state"` // download, backup, apply, restart, ok, failed, rollback, rolled_back
	From     string   `json:"from"`
	To       string   `json:"to"`
	Started  int64    `json:"started"`
	Finished int64    `json:"finished,omitempty"`
	Point    string   `json:"point,omitempty"` // Wiederherstellungspunkt von vorher
	Target   string   `json:"target,omitempty"`
	New      string   `json:"new,omitempty"`
	Prev     string   `json:"prev,omitempty"`
	Error    string   `json:"error,omitempty"`
	Log      []string `json:"log,omitempty"`
	Noted    bool     `json:"noted,omitempty"` // Ergebnis schon im Ereignisprotokoll
	Admin    string   `json:"admin,omitempty"`
}

func (r *UpdateRun) logf(format string, a ...any) {
	r.Log = append(r.Log, time.Now().Format("15:04:05")+" "+fmt.Sprintf(format, a...))
	if len(r.Log) > 60 {
		r.Log = r.Log[len(r.Log)-60:]
	}
}

// Terminal: Lauf ist beendet.
func (r *UpdateRun) Terminal() bool {
	switch r.State {
	case "ok", "failed", "rolled_back":
		return true
	}
	return false
}

type selfUpdate struct {
	mu sync.Mutex // ein Update zur Zeit (innerhalb des Panels)
}

var runFileMu sync.Mutex

func updateFile(dataDir string) string { return filepath.Join(dataDir, backup.UpdateStateFile) }

// ReadUpdateRun liest den Zustand (nil, wenn es noch kein Update gab).
func ReadUpdateRun(dataDir string) *UpdateRun {
	runFileMu.Lock()
	defer runFileMu.Unlock()
	b, err := os.ReadFile(updateFile(dataDir))
	if err != nil {
		return nil
	}
	var r UpdateRun
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}

// WriteUpdateRun schreibt den Zustand (atomar).
func WriteUpdateRun(dataDir string, r *UpdateRun) error {
	runFileMu.Lock()
	defer runFileMu.Unlock()
	b, _ := json.MarshalIndent(r, "", "  ")
	tmp := updateFile(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, updateFile(dataDir))
}

// releaseAsset: Datei eines Releases mit Prüfsumme.
type releaseAsset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	URL    string `json:"browser_download_url"`
}

type releaseInfo struct {
	Tag    string         `json:"tag_name"`
	Assets []releaseAsset `json:"assets"`
}

func (r *releaseInfo) asset(name string) *releaseAsset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

func fetchRelease(url, current string) (*releaseInfo, error) {
	c := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vpnpanel/"+current)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub antwortet mit %d", resp.StatusCode)
	}
	var r releaseInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// fetchReleaseFn: austauschbar für Tests (kein Netz)
var fetchReleaseFn = fetchRelease

func binaryAssetName() string { return "vpnpanel-linux-" + runtime.GOARCH }

// assetSHA: Prüfsumme aus „sha256:<hex>“ (GitHub gibt sie zu jeder Release-Datei an).
func assetSHA(a *releaseAsset) (string, error) {
	h, ok := strings.CutPrefix(a.Digest, "sha256:")
	if !ok || len(h) != 64 {
		return "", errors.New("GitHub nennt keine SHA-256-Prüfsumme für " + a.Name)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", errors.New("ungültige Prüfsumme für " + a.Name)
	}
	return strings.ToLower(h), nil
}

// installCheck: kann das Release aus dem Panel installiert werden? (Datei mit Prüfsumme vorhanden)
// Dazu: ändert sich vpn-setup.sh gegenüber dem installierten Release?
func installCheck(latest *releaseInfo, current string) (canInstall bool, reason string, setupChanged bool) {
	a := latest.asset(binaryAssetName())
	if a == nil {
		return false, "Im Release fehlt " + binaryAssetName(), false
	}
	if _, err := assetSHA(a); err != nil {
		return false, err.Error(), false
	}
	if !strings.HasPrefix(a.URL, releaseDownload) {
		return false, "unerwartete Download-Adresse", false
	}
	if cur, err := fetchReleaseFn(releaseTagAPI+"v"+strings.TrimPrefix(current, "v"), current); err == nil {
		if n, o := latest.asset("vpn-setup.sh"), cur.asset("vpn-setup.sh"); n != nil && o != nil && n.Digest != o.Digest {
			setupChanged = true
		}
	}
	return true, "", setupChanged
}

// InDocker: läuft im Docker-Image (setzt docker/entrypoint.sh in panel.env). Dort ersetzt ein neues
// Image das Update aus dem Panel – ein ausgetauschtes Programm ginge beim Neuerstellen verloren.
func InDocker() bool { return os.Getenv("VPNPANEL_DOCKER") == "1" }

const dockerUpdateHint = "Im Docker-Container: neues Image ziehen – docker compose pull && docker compose up -d"

// UpdateStatus: alles für die Update-Karte.
func (e *Engine) UpdateStatus(current string) map[string]any {
	out := map[string]any{"info": e.updateOffer(current), "dry_run": e.Sys.DryRun(), "docker": InDocker()}
	r := ReadUpdateRun(e.Cfg.DataDir)
	if r != nil {
		if !r.Terminal() && time.Since(time.Unix(r.Started, 0)) > updateStale {
			r.State, r.Error = "failed", "keine Rückmeldung – Update abgebrochen"
		}
		out["run"] = r
		if InDocker() {
			return out
		}
		// Rücksprung: nach einem erfolgreichen Update, solange das alte Programm noch daliegt
		if r.Mode == "update" && r.State == "ok" && strings.TrimPrefix(r.To, "v") == strings.TrimPrefix(current, "v") && r.Prev != "" {
			if _, err := os.Stat(r.Prev); err == nil || e.Sys.DryRun() {
				out["rollback"] = map[string]any{"to": r.From, "point": r.Point}
			}
		}
	}
	return out
}

// StartUpdate startet das Update auf das neueste Release im Hintergrund.
func (e *Engine) StartUpdate(current, admin string) error {
	if InDocker() {
		return errors.New(dockerUpdateHint)
	}
	if !e.self.mu.TryLock() {
		return errors.New("Ein Update läuft bereits")
	}
	if r := ReadUpdateRun(e.Cfg.DataDir); r != nil && !r.Terminal() && time.Since(time.Unix(r.Started, 0)) < updateStale {
		e.self.mu.Unlock()
		return errors.New("Ein Update läuft bereits")
	}
	info := e.updateOffer(current)
	if !info.Available || !info.CanInstall {
		e.self.mu.Unlock()
		if info.InstallReason != "" {
			return errors.New(info.InstallReason)
		}
		return errors.New("Keine neuere Version zum Installieren – erst „Jetzt prüfen“")
	}
	r := &UpdateRun{Mode: "update", State: "download", From: current, To: info.Latest, Started: time.Now().Unix(), Admin: admin}
	r.logf("Update von %s auf %s gestartet von %s", current, info.Latest, admin)
	if err := WriteUpdateRun(e.Cfg.DataDir, r); err != nil {
		e.self.mu.Unlock()
		return err
	}
	e.Log("warn", fmt.Sprintf("Update auf %s gestartet von %s", info.Latest, admin))
	go func() {
		defer e.self.mu.Unlock()
		if err := e.runUpdate(r, current); err != nil {
			r.State, r.Error, r.Finished = "failed", err.Error(), time.Now().Unix()
			r.logf("Abgebrochen: %v", err)
			_ = WriteUpdateRun(e.Cfg.DataDir, r)
			e.Log("error", "Update abgebrochen: "+err.Error())
		}
	}()
	return nil
}

func (e *Engine) runUpdate(r *UpdateRun, current string) error {
	dd := e.Cfg.DataDir
	save := func(state, msg string, a ...any) {
		if state != "" {
			r.State = state
		}
		r.logf(msg, a...)
		_ = WriteUpdateRun(dd, r)
	}
	if e.Sys.DryRun() {
		// Testmodus: Ablauf zeigen, nichts austauschen
		save("download", "Testmodus: Programm würde geladen und geprüft")
		time.Sleep(1500 * time.Millisecond)
		p, err := e.CreatePoint(current, backup.KindUpdate, "vor Update auf "+r.To)
		if err != nil {
			return err
		}
		r.Point = p.ID
		save("backup", "Wiederherstellungspunkt %s angelegt", p.ID)
		time.Sleep(1500 * time.Millisecond)
		save("restart", "Testmodus: Dienst würde neu starten")
		time.Sleep(2 * time.Second)
		r.Prev, r.Finished = filepath.Join(dd, "dryroot", prevBinaryName), time.Now().Unix()
		save("ok", "Testmodus: fertig – nichts installiert")
		return nil
	}
	latest, err := fetchReleaseFn(releaseAPI, current)
	if err != nil {
		return fmt.Errorf("Release abfragen: %w", err)
	}
	if strings.TrimSpace(latest.Tag) != r.To {
		r.To = strings.TrimSpace(latest.Tag)
		if !newerVersion(r.To, current) {
			return errors.New("Das neueste Release ist nicht neuer als die installierte Version")
		}
	}
	a := latest.asset(binaryAssetName())
	if a == nil {
		return errors.New("Im Release fehlt " + binaryAssetName())
	}
	want, err := assetSHA(a)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(a.URL, releaseDownload) {
		return errors.New("unerwartete Download-Adresse")
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("laufendes Programm nicht gefunden: %w", err)
	}
	dir := filepath.Dir(exe)
	newPath, prevPath := filepath.Join(dir, newBinaryName), filepath.Join(dir, prevBinaryName)
	r.Target, r.New, r.Prev = exe, newPath, prevPath

	save("download", "Lade %s (%.1f MB)", a.Name, float64(a.Size)/(1<<20))
	if err := downloadVerified(a.URL, newPath, want, current); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	save("", "Prüfsumme stimmt (SHA-256 %s…)", want[:16])
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	out, err := exec.CommandContext(ctx, newPath, "version").Output()
	cancel()
	if got := strings.TrimSpace(string(out)); err != nil || got != strings.TrimPrefix(r.To, "v") {
		_ = os.Remove(newPath)
		return fmt.Errorf("das neue Programm meldet nicht Version %s (%q, %v)", r.To, got, err)
	}
	save("", "Neues Programm startet und meldet %s", r.To)

	p, err := e.CreatePoint(current, backup.KindUpdate, "vor Update auf "+r.To)
	if err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("Wiederherstellungspunkt: %w", err)
	}
	r.Point = p.ID
	save("backup", "Wiederherstellungspunkt %s angelegt", p.ID)
	if err := copyFile(exe, prevPath, 0o755); err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("altes Programm sichern: %w", err)
	}
	save("apply", "Altes Programm gesichert als %s, Wächter startet", prevPath)
	if err := startWatcher(prevPath, dd); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	return nil
}

// StartRollback: zurück zum Programm und Stand vor dem letzten Update.
func (e *Engine) StartRollback(current, admin string) error {
	if InDocker() {
		return errors.New("Im Docker-Container: das vorherige Image starten (Tag in docker-compose.yml) und bei Bedarf einen Wiederherstellungspunkt einspielen")
	}
	if !e.self.mu.TryLock() {
		return errors.New("Ein Update läuft gerade")
	}
	defer e.self.mu.Unlock()
	st := e.UpdateStatus(current)
	if st["rollback"] == nil {
		return errors.New("Kein Rücksprung möglich (kein erfolgreiches Update mit gesichertem Programm)")
	}
	last := st["run"].(*UpdateRun)
	r := &UpdateRun{Mode: "rollback", State: "rollback", From: current, To: last.From, Started: time.Now().Unix(),
		Point: last.Point, Target: last.Target, Prev: last.Prev, Admin: admin}
	r.logf("Rücksprung von %s auf %s gestartet von %s", current, last.From, admin)
	// aktuellen Stand vorher sichern (falls man wieder vor will)
	if p, err := e.CreatePoint(current, backup.KindRestore, "vor Rücksprung auf "+last.From); err == nil {
		r.logf("Aktueller Stand gesichert: %s", p.ID)
	} else {
		return fmt.Errorf("aktuellen Stand sichern: %w", err)
	}
	if err := WriteUpdateRun(e.Cfg.DataDir, r); err != nil {
		return err
	}
	e.Log("warn", fmt.Sprintf("Rücksprung auf %s gestartet von %s", last.From, admin))
	if e.Sys.DryRun() {
		go func() {
			time.Sleep(2 * time.Second)
			r.State, r.Finished = "rolled_back", time.Now().Unix()
			r.logf("Testmodus: nichts geändert")
			_ = WriteUpdateRun(e.Cfg.DataDir, r)
		}()
		return nil
	}
	return startWatcher(r.Prev, e.Cfg.DataDir)
}

// ConfirmUpdate: vom neuen Programm nach dem Start aufgerufen. Meldet „ok“ an den Wächter und
// trägt das Ergebnis eines Updates bzw. Rücksprungs einmal ins Ereignisprotokoll ein.
func (e *Engine) ConfirmUpdate(current string) {
	r := ReadUpdateRun(e.Cfg.DataDir)
	if r == nil {
		return
	}
	if r.Mode == "update" && r.State == "restart" && strings.TrimPrefix(r.To, "v") == strings.TrimPrefix(current, "v") {
		r.State, r.Finished = "ok", time.Now().Unix()
		r.logf("Neues Programm %s läuft", current)
		_ = WriteUpdateRun(e.Cfg.DataDir, r)
		e.Log("info", fmt.Sprintf("Panel aktualisiert: %s → %s", r.From, r.To))
		e.Notify("update", "installed:"+r.To, "Panel aktualisiert", fmt.Sprintf("Das Panel wurde von %s auf %s aktualisiert (gestartet von %s).", r.From, r.To, r.Admin))
		return
	}
	if r.State == "rolled_back" && !r.Noted {
		r.Noted = true
		_ = WriteUpdateRun(e.Cfg.DataDir, r)
		msg := fmt.Sprintf("Panel auf %s zurückgesetzt (gestartet von %s)", r.To, r.Admin)
		if r.Mode == "update" {
			msg = fmt.Sprintf("Update auf %s fehlgeschlagen, zurück auf %s: %s", r.To, r.From, r.Error)
		}
		e.Log("warn", msg)
		e.Notify("update", "rollback:"+r.To+":"+fmt.Sprint(r.Started), "Panel zurückgesetzt", msg+".")
	}
}

func downloadVerified(url, dst, wantSHA, current string) error {
	c := &http.Client{Timeout: 10 * time.Minute}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "vpnpanel/"+current)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("Download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Download: Antwort %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBinary+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("Download: %w", err)
	}
	if n > maxBinary {
		return errors.New("Download: Datei zu groß")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		return fmt.Errorf("Prüfsumme stimmt nicht (erwartet %s…, erhalten %s…)", wantSHA[:16], got[:16])
	}
	return os.Chmod(dst, 0o755)
}

// copyFile kopiert über eine temporäre Datei und benennt sie dann um (atomar im selben Ordner).
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// startWatcher startet den Wächter als eigene systemd-Einheit (überlebt den Neustart des Panels).
func startWatcher(bin, dataDir string) error {
	_ = exec.Command("systemctl", "reset-failed", updateUnit).Run()
	_ = exec.Command("systemctl", "stop", updateUnit).Run()
	out, err := exec.Command("systemd-run", "--unit="+updateUnit, "--collect", "--quiet",
		"--description=VPN-Panel Update", bin, "update-apply", dataDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Wächter starten: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------- Wächter (läuft mit dem alten Programm außerhalb des Dienstes) ----------

func sysctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func nRestarts() string {
	s, _ := sysctl("show", "-p", "NRestarts", "--value", "vpnpanel")
	return s
}

// UpdateApply: Einstieg des Wächters („vpnpanel update-apply <datenordner>“).
func UpdateApply(dataDir string) error {
	r := ReadUpdateRun(dataDir)
	if r == nil {
		return errors.New("kein Update vorbereitet")
	}
	save := func(state, msg string, a ...any) {
		// erst frisch lesen: das neue Programm schreibt zwischendurch „ok“
		if cur := ReadUpdateRun(dataDir); cur != nil {
			r = cur
		}
		if state != "" {
			r.State = state
		}
		r.logf(msg, a...)
		_ = WriteUpdateRun(dataDir, r)
	}
	if r.Mode == "rollback" {
		rollbackTo(dataDir, r, "auf Wunsch", save)
		return nil
	}
	if r.State != "apply" || r.New == "" || r.Target == "" {
		return fmt.Errorf("unerwarteter Zustand %q", r.State)
	}
	if err := os.Rename(r.New, r.Target); err != nil {
		save("failed", "Programm austauschen: %v", err)
		r.Error = err.Error()
		_ = WriteUpdateRun(dataDir, r)
		return err
	}
	save("restart", "Programm ausgetauscht, Dienst startet neu")
	if out, err := sysctl("restart", "vpnpanel"); err != nil {
		rollbackTo(dataDir, r, "Neustart fehlgeschlagen: "+cmdErr(out, err), save)
		return nil
	}
	base := nRestarts()
	deadline := time.Now().Add(updateWait)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		if cur := ReadUpdateRun(dataDir); cur != nil && cur.State == "ok" {
			time.Sleep(updateSettle)
			active, _ := sysctl("is-active", "vpnpanel")
			if active == "active" && nRestarts() == base {
				save("", "Läuft stabil – Update abgeschlossen")
				return nil
			}
			rollbackTo(dataDir, r, "Dienst nach dem Start abgestürzt", save)
			return nil
		}
	}
	rollbackTo(dataDir, r, "Neues Programm hat sich nicht innerhalb von 2 Minuten gemeldet", save)
	return nil
}

func cmdErr(out string, err error) string {
	if out == "" {
		return err.Error()
	}
	l, _, _ := strings.Cut(out, "\n")
	return l
}

// rollbackTo: altes Programm und Wiederherstellungspunkt zurück, Dienst neu starten.
func rollbackTo(dataDir string, r *UpdateRun, reason string, save func(state, msg string, a ...any)) {
	save("rollback", "Rücksprung: %s", reason)
	if j, err := exec.Command("journalctl", "-u", "vpnpanel", "-n", "12", "--no-pager", "-o", "cat").Output(); err == nil && r.Mode == "update" {
		for _, l := range strings.Split(strings.TrimSpace(string(j)), "\n") {
			if l != "" {
				r.logf("journal: %s", l)
			}
		}
	}
	var errs []string
	if r.Prev != "" && r.Target != "" {
		if err := copyFile(r.Prev, r.Target, 0o755); err != nil {
			errs = append(errs, "Programm zurück: "+err.Error())
		} else {
			r.logf("Altes Programm wieder eingesetzt")
		}
	}
	if r.Point != "" {
		if a, err := backup.OpenPoint(dataDir, r.Point); err != nil {
			errs = append(errs, "Wiederherstellungspunkt: "+err.Error())
		} else if err := backup.Stage(dataDir, a, store.CheckBackupDB); err != nil {
			errs = append(errs, "Wiederherstellungspunkt: "+err.Error())
		} else {
			r.logf("Wiederherstellungspunkt %s wird beim Start eingespielt", r.Point)
		}
	}
	if r.New != "" {
		_ = os.Remove(r.New)
	}
	r.Error = reason
	if len(errs) > 0 {
		r.Error += " · " + strings.Join(errs, " · ")
	}
	r.State, r.Finished = "rolled_back", time.Now().Unix()
	_ = WriteUpdateRun(dataDir, r) // vor dem Neustart, damit das alte Programm das Ergebnis meldet
	_, _ = sysctl("reset-failed", "vpnpanel")
	if out, err := sysctl("restart", "vpnpanel"); err != nil {
		save("", "Neustart nach dem Rücksprung fehlgeschlagen: %s – bitte „bash vpn-setup.sh“ im Container ausführen", cmdErr(out, err))
		return
	}
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		if s, _ := sysctl("is-active", "vpnpanel"); s == "active" {
			v := r.To
			if r.Mode == "update" {
				v = r.From
			}
			save("", "Dienst läuft wieder mit %s", v)
			return
		}
	}
	save("", "Dienst startet nach dem Rücksprung nicht – bitte im Container prüfen (journalctl -u vpnpanel)")
}
