package api

// Update aus dem Panel und Wiederherstellungspunkte (engine/selfupdate.go, engine/points.go).
// Alles, was Daten herausgibt oder den Stand ändert, braucht Passwort und ggf. 2FA-Code.

import (
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"time"

	"vpnpanel/internal/backup"
	"vpnpanel/internal/store"
)

func (a *API) updateStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.E.UpdateStatus(a.Version))
}

func (a *API) confirmed(w http.ResponseWriter, r *http.Request, extra any) (*store.Admin, bool) {
	var in struct{ Current, Code string }
	if extra == nil {
		extra = &in
	}
	if err := readJSON(r, extra); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	cur, code := in.Current, in.Code
	if c, ok := extra.(interface{ creds() (string, string) }); ok {
		cur, code = c.creds()
	}
	adm := adminOf(r)
	if err := a.confirm(adm, cur, code); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	return adm, true
}

func (a *API) updateInstall(w http.ResponseWriter, r *http.Request) {
	adm, ok := a.confirmed(w, r, nil)
	if !ok {
		return
	}
	if err := a.E.StartUpdate(a.Version, adm.Username); err != nil {
		errJSON(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, a.E.UpdateStatus(a.Version))
}

func (a *API) updateRollback(w http.ResponseWriter, r *http.Request) {
	adm, ok := a.confirmed(w, r, nil)
	if !ok {
		return
	}
	if err := a.E.StartRollback(a.Version, adm.Username); err != nil {
		errJSON(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, a.E.UpdateStatus(a.Version))
}

// ---------- Wiederherstellungspunkte ----------

func (a *API) listPoints(w http.ResponseWriter, r *http.Request) {
	out := a.E.PointsInfo()
	out["restart"] = a.Restart != nil
	out["min_password"] = backup.MinPassword
	writeJSON(w, out)
}

func (a *API) createPoint(w http.ResponseWriter, r *http.Request) {
	var in struct{ Note string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	p, err := a.E.CreatePoint(a.Version, backup.KindManual, in.Note)
	if err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", fmt.Sprintf("Wiederherstellungspunkt %s angelegt von %s", p.ID, adminOf(r).Username))
	writeJSON(w, p)
}

func (a *API) deletePoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := backup.GetPoint(a.E.Cfg.DataDir, id); err != nil {
		errJSON(w, http.StatusNotFound, err.Error())
		return
	}
	if err := backup.DeletePoint(a.E.Cfg.DataDir, id); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", fmt.Sprintf("Wiederherstellungspunkt %s gelöscht von %s", id, adminOf(r).Username))
	writeJSON(w, map[string]bool{"ok": true})
}

type pointDownload struct{ Password, Current, Code string }

func (p *pointDownload) creds() (string, string) { return p.Current, p.Code }

// downloadPoint: Punkt mit eigenem Passwort neu verschlüsselt herunterladen.
func (a *API) downloadPoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in pointDownload
	adm, ok := a.confirmed(w, r, &in)
	if !ok {
		return
	}
	p, err := backup.GetPoint(a.E.Cfg.DataDir, id)
	if err != nil {
		errJSON(w, http.StatusNotFound, err.Error())
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
	data, err := backup.ExportPoint(a.E.Cfg.DataDir, id, in.Password)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	name := "vpnpanel"
	if host := a.E.Setting("server_host"); host != "" && hostSafe(host) {
		name += "-" + host
	}
	name += "-" + time.Unix(p.Created, 0).Format("2006-01-02-1504") + ".vpnbak"
	msg := fmt.Sprintf("Wiederherstellungspunkt %s heruntergeladen von %s (%s)", id, adm.Username, a.clientIP(r))
	a.E.Log("warn", msg)
	a.E.Notify("backup", "export:"+strconv.FormatInt(time.Now().Unix(), 10), "Sicherung heruntergeladen", msg+".")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// restorePoint: Punkt einspielen – vorher wird der aktuelle Stand als eigener Punkt gesichert.
func (a *API) restorePoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	adm, ok := a.confirmed(w, r, nil)
	if !ok {
		return
	}
	arc, err := backup.OpenPoint(a.E.Cfg.DataDir, id)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	before, err := a.E.CreatePoint(a.Version, backup.KindRestore, "vor Wiederherstellung von "+id)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "aktuellen Stand sichern: "+err.Error())
		return
	}
	if err := backup.Stage(a.E.Cfg.DataDir, arc, store.CheckBackupDB); err != nil {
		errJSON(w, http.StatusBadRequest, "Wiederherstellungspunkt abgelehnt: "+err.Error())
		return
	}
	m := arc.Manifest
	msg := fmt.Sprintf("Wiederherstellungspunkt %s (Version %s) zum Einspielen abgelegt von %s (%s), bisheriger Stand in %s",
		id, m.Version, adm.Username, a.clientIP(r), before.ID)
	a.E.Log("warn", msg)
	a.E.Notify("backup", "restore", "Sicherung wird eingespielt", msg+". Das Panel startet dafür neu.")
	writeJSON(w, map[string]any{"ok": true, "restart": a.Restart != nil, "before": before.ID})
	if a.Restart != nil {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			a.Restart()
		}()
	}
}
