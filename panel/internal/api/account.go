package api

// Konto (Name, E-Mail, Benachrichtigungen), Anmeldeprotokoll, Mailversand und Sicherung.

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pquerna/otp/totp"

	"vpnpanel/internal/backup"
	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

const maxRestoreUpload = 800 << 20

// cleanName: Benutzername für das Protokoll (ohne Steuerzeichen, gekürzt).
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}

func (a *API) logLogin(r *http.Request, name string, adminID int64, ok bool, reason string) {
	agent := r.UserAgent()
	if len(agent) > 200 {
		agent = agent[:200]
	}
	a.St.AddLogin(&store.LoginEntry{Username: cleanName(name), AdminID: adminID, IP: a.clientIP(r), Agent: agent, OK: ok, Reason: reason})
}

// confirm: Passwort (und bei aktivem 2FA ein Code) für heikle Aktionen.
func (a *API) confirm(adm *store.Admin, password, code string) error {
	if !checkPassword(adm.PassHash, password) {
		return errors.New("Passwort falsch")
	}
	if adm.TOTPEnabled {
		code = strings.ReplaceAll(code, " ", "")
		if code == "" {
			return errors.New("2FA-Code fehlt")
		}
		if !totp.Validate(code, adm.TOTPSecret) || !a.codes.take(strconv.FormatInt(adm.ID, 10)+":"+code) {
			return errors.New("2FA-Code falsch")
		}
	}
	return nil
}

// ---------- Konto ----------

func meJSON(adm *store.Admin) map[string]any {
	return map[string]any{"username": adm.Username, "totp_enabled": adm.TOTPEnabled, "id": adm.ID, "email": adm.Email, "notify": adm.Notify, "created": adm.Created}
}

// updateProfile: Benutzername, E-Mail und Benachrichtigungen; Name/E-Mail nur mit Passwort.
func (a *API) updateProfile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username, Email, Current string
		Notify                   bool
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	adm := adminOf(r)
	in.Username, in.Email = strings.TrimSpace(in.Username), strings.TrimSpace(in.Email)
	if !nameRe.MatchString(in.Username) {
		errJSON(w, http.StatusBadRequest, "Benutzername ungültig (A-Z a-z 0-9 _ - ., max. 32 Zeichen)")
		return
	}
	if in.Email != "" {
		m, err := mail.ParseAddress(in.Email)
		if err != nil || m.Name != "" || m.Address != in.Email || len(in.Email) > 254 {
			errJSON(w, http.StatusBadRequest, "E-Mail-Adresse ungültig")
			return
		}
	}
	if in.Notify && in.Email == "" {
		errJSON(w, http.StatusBadRequest, "Für Benachrichtigungen eine E-Mail-Adresse eintragen")
		return
	}
	nameChanged := in.Username != adm.Username
	if (nameChanged || in.Email != adm.Email) && !checkPassword(adm.PassHash, in.Current) {
		errJSON(w, http.StatusBadRequest, "Zum Ändern von Name oder E-Mail das aktuelle Passwort eingeben")
		return
	}
	if nameChanged {
		if other, err := a.St.AdminByName(in.Username); err == nil && other.ID != adm.ID {
			errJSON(w, http.StatusBadRequest, "Benutzername schon vergeben")
			return
		}
	}
	old := adm.Username
	adm.Username, adm.Email, adm.Notify = in.Username, in.Email, in.Notify
	if err := a.St.SaveAdmin(adm); err != nil {
		errJSON(w, http.StatusBadRequest, "Speichern fehlgeschlagen (Name vergeben?)")
		return
	}
	if nameChanged {
		a.E.Log("warn", "Administrator "+old+" heißt jetzt "+adm.Username)
	} else {
		a.E.Log("info", "Konto von "+adm.Username+" geändert")
	}
	writeJSON(w, meJSON(adm))
}

// loginLog: Zähler (24 h / 30 Tage) und die letzten Anmeldeversuche.
func (a *API) loginLog(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	now := time.Now().Unix()
	d1o, d1f, err := a.St.LoginCounts(now - 86400)
	if err != nil {
		fail(w, err)
		return
	}
	d30o, d30f, _ := a.St.LoginCounts(now - 30*86400)
	list, err := a.St.Logins(limit)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"day":     map[string]int64{"ok": d1o, "failed": d1f},
		"month":   map[string]int64{"ok": d30o, "failed": d30f},
		"entries": orEmptyT(list),
	})
}

// ---------- Benachrichtigungen ----------

func (a *API) notifyState(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"password_set": a.E.SMTPPasswordSet(), "recipients": orEmptyT(a.E.NotifyRecipients()), "events": engine.NotifyEvents}
	if a.E.Sys.DryRun() {
		out["sent"] = orEmptyT(a.E.SentMails())
	}
	writeJSON(w, out)
}

func (a *API) notifyPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password string }
	if r.Method == http.MethodPut {
		if err := readJSON(r, &in); err != nil {
			fail(w, err)
			return
		}
		if in.Password == "" {
			errJSON(w, http.StatusBadRequest, "Passwort fehlt")
			return
		}
	}
	if err := a.E.SetSMTPPassword(in.Password); err != nil {
		fail(w, err)
		return
	}
	if in.Password == "" {
		a.E.Log("warn", "Passwort des Mailservers entfernt von "+adminOf(r).Username)
	} else {
		a.E.Log("info", "Passwort des Mailservers hinterlegt von "+adminOf(r).Username)
	}
	writeJSON(w, map[string]bool{"ok": true, "password_set": a.E.SMTPPasswordSet()})
}

func (a *API) notifyTest(w http.ResponseWriter, r *http.Request) {
	adm := adminOf(r)
	if adm.Email == "" {
		errJSON(w, http.StatusBadRequest, "In „Mein Konto“ zuerst eine E-Mail-Adresse eintragen")
		return
	}
	if err := a.E.SendTestMail(adm.Email); err != nil {
		errJSON(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "to": adm.Email})
}

// ---------- Sicherung ----------

func (a *API) backupState(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"min_password": backup.MinPassword, "restart": a.Restart != nil, "dry_run": a.E.Sys.DryRun()}
	if m, ok := backup.Pending(a.E.Cfg.DataDir); ok {
		out["pending"] = map[string]any{"created": m.Created, "version": m.Version, "host": m.Host, "files": len(m.Files)}
	}
	writeJSON(w, out)
}

func (a *API) backupExport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password, Current, Code string
		Logs                    bool
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	adm := adminOf(r)
	if err := a.confirm(adm, in.Current, in.Code); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
	host := a.E.Setting("server_host")
	data, err := backup.Create(a.E.Cfg.DataDir, func(p string) error { return a.St.Snapshot(p, in.Logs) },
		backup.Manifest{Version: a.Version, Schema: store.SchemaVersion(), Host: host, WithLogs: in.Logs}, in.Password)
	if err != nil {
		fail(w, err)
		return
	}
	name := "vpnpanel"
	if host != "" && hostSafe(host) {
		name += "-" + host
	}
	name += "-" + time.Now().Format("2006-01-02-1504") + ".vpnbak"
	msg := fmt.Sprintf("Sicherung heruntergeladen von %s (%s, %s)", adm.Username, a.clientIP(r), humanSize(len(data)))
	a.E.Log("warn", msg)
	a.E.Notify("backup", "export:"+strconv.FormatInt(time.Now().Unix(), 10), "Sicherung heruntergeladen", msg+".")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func hostSafe(s string) bool {
	for _, c := range s {
		if !(c == '.' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func humanSize(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d KB", (n+1023)/1024)
}

// backupRestore: Datei hochladen (multipart: file, password, current, code), prüfen und zum
// Einspielen beim nächsten Start ablegen; danach startet der Dienst neu.
func (a *API) backupRestore(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Minute))
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(16 * time.Minute))
	mr, err := r.MultipartReader()
	if err != nil {
		errJSON(w, http.StatusBadRequest, "Upload erwartet")
		return
	}
	fields := map[string]string{}
	var data []byte
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			errJSON(w, http.StatusBadRequest, "Upload abgebrochen oder zu groß")
			return
		}
		switch p.FormName() {
		case "file":
			data, err = io.ReadAll(io.LimitReader(p, maxRestoreUpload+1))
			if err != nil || len(data) > maxRestoreUpload {
				errJSON(w, http.StatusBadRequest, "Datei zu groß oder unvollständig")
				return
			}
		case "password", "current", "code":
			b, _ := io.ReadAll(io.LimitReader(p, 1024))
			fields[p.FormName()] = string(b)
		}
	}
	adm := adminOf(r)
	if err := a.confirm(adm, fields["current"], fields["code"]); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(data) == 0 {
		errJSON(w, http.StatusBadRequest, "Keine Datei ausgewählt")
		return
	}
	arc, err := backup.Open(data, fields["password"])
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := backup.Stage(a.E.Cfg.DataDir, arc, store.CheckBackupDB); err != nil {
		errJSON(w, http.StatusBadRequest, "Sicherung abgelehnt: "+err.Error())
		return
	}
	m := arc.Manifest
	msg := fmt.Sprintf("Sicherung vom %s (Version %s, %d Dateien) zum Einspielen abgelegt von %s (%s)",
		time.Unix(m.Created, 0).Format("02.01.2006 15:04"), m.Version, len(m.Files), adm.Username, a.clientIP(r))
	a.E.Log("warn", msg)
	a.E.Notify("backup", "restore", "Sicherung wird eingespielt", msg+". Das Panel startet dafür neu.")
	writeJSON(w, map[string]any{"ok": true, "restart": a.Restart != nil, "created": m.Created, "version": m.Version, "files": len(m.Files)})
	if a.Restart != nil {
		go func() {
			time.Sleep(1500 * time.Millisecond) // Antwort und Mail noch hinausschicken
			a.Restart()
		}()
	}
}

// backupCancel: abgelegte Wiederherstellung verwerfen (falls der Neustart noch aussteht).
func (a *API) backupCancel(w http.ResponseWriter, r *http.Request) {
	if _, ok := backup.Pending(a.E.Cfg.DataDir); !ok {
		errJSON(w, http.StatusNotFound, "Keine Wiederherstellung abgelegt")
		return
	}
	if err := backup.Discard(a.E.Cfg.DataDir); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Abgelegte Wiederherstellung verworfen von "+adminOf(r).Username)
	writeJSON(w, map[string]bool{"ok": true})
}
