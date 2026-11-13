package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vpnpanel/internal/backup"
	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

type client struct {
	t      *testing.T
	h      http.Handler
	cookie string
}

func (c *client) do(method, path string, body any) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	ct := "application/json"
	switch b := body.(type) {
	case nil:
	case *multipart.Writer:
		c.t.Fatal("multipart über doRaw")
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	return c.doRaw(method, path, rd, ct)
}

func (c *client) doRaw(method, path string, rd io.Reader, ct string) (int, []byte) {
	c.t.Helper()
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("X-Requested-With", "vpnpanel")
	req.Header.Set("Content-Type", ct)
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: c.cookie})
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == cookieName && ck.Value != "" {
			c.cookie = ck.Value
		}
	}
	return rec.Code, rec.Body.Bytes()
}

func TestAccountLoginLogNotifyBackup(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_ = st.SetSetting("server_host", "vpn.example.org")
	e := engine.New(st, &system.Dry{Root: filepath.Join(dir, "dryroot")}, engine.Config{PanelBackend: "127.0.0.1:8480", DataDir: dir})
	a := New(e, nil, false, "0.15.0")
	var restarted atomic.Bool
	a.Restart = func() { restarted.Store(true) }
	h, _ := HashPassword("geheimes-passwort-1")
	if err := st.SaveAdmin(&store.Admin{Username: "admin", PassHash: h}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go e.RunNotify(stop, "0.15.0")
	c := &client{t: t, h: a.Handler()}

	// Anmeldeprotokoll: zwei Fehlversuche, dann Erfolg
	if code, _ := c.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "falsch"}); code != 401 {
		t.Fatalf("falsches Passwort: %d", code)
	}
	c.do("POST", "/api/auth/login", map[string]string{"username": "niemand\n", "password": "x"})
	if code, b := c.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "geheimes-passwort-1"}); code != 200 {
		t.Fatalf("Anmeldung: %d %s", code, b)
	}
	_, b := c.do("GET", "/api/auth/logins", nil)
	var lg struct {
		Day     struct{ OK, Failed int64 }
		Entries []store.LoginEntry
	}
	_ = json.Unmarshal(b, &lg)
	if lg.Day.OK != 1 || lg.Day.Failed != 2 || len(lg.Entries) != 3 {
		t.Fatalf("Protokoll: %s", b)
	}
	if lg.Entries[0].Reason != "ohne 2FA" || lg.Entries[1].Reason != "unbekannter Benutzername" || lg.Entries[1].Username != "niemand" ||
		lg.Entries[2].Reason != "Passwort falsch" {
		t.Errorf("Einträge: %+v", lg.Entries)
	}

	// Konto: Name und E-Mail nur mit Passwort
	if code, _ := c.do("PUT", "/api/auth/profile", map[string]any{"username": "martin", "email": "m@example.org"}); code != 400 {
		t.Fatal("Namensänderung ohne Passwort angenommen")
	}
	if code, _ := c.do("PUT", "/api/auth/profile", map[string]any{"username": "martin", "email": "kein mail", "current": "geheimes-passwort-1"}); code != 400 {
		t.Fatal("ungültige E-Mail angenommen")
	}
	if code, b := c.do("PUT", "/api/auth/profile", map[string]any{"username": "martin", "email": "m@example.org", "notify": true, "current": "geheimes-passwort-1"}); code != 200 {
		t.Fatalf("Profil: %d %s", code, b)
	}
	_, b = c.do("GET", "/api/auth/me", nil)
	if !strings.Contains(string(b), `"username":"martin"`) || !strings.Contains(string(b), `"email":"m@example.org"`) {
		t.Fatalf("me: %s", b)
	}
	// Benachrichtigung nur noch ohne Passwort umschalten
	if code, _ := c.do("PUT", "/api/auth/profile", map[string]any{"username": "martin", "email": "m@example.org", "notify": true}); code != 200 {
		t.Fatal("Schalter ohne Namensänderung braucht kein Passwort")
	}

	// Mailserver: Einstellungen prüfen, Passwort nur in secrets.env, Testmail (Testmodus merkt sie nur)
	if code, _ := c.do("PUT", "/api/settings", map[string]string{"mail_from": "nicht gültig"}); code != 400 {
		t.Error("ungültiger Absender angenommen")
	}
	if code, _ := c.do("PUT", "/api/settings", map[string]string{"notify_events": "exit,hack"}); code != 400 {
		t.Error("unbekannter Anlass angenommen")
	}
	if code, b := c.do("PUT", "/api/settings", map[string]string{"mail_enabled": "1", "smtp_host": "mail.example.org", "mail_from": "panel@example.org",
		"notify_events": "lockout,login,backup"}); code != 200 {
		t.Fatalf("Einstellungen: %s", b)
	}
	if code, _ := c.do("PUT", "/api/notify/password", map[string]string{"password": "smtp-geheim"}); code != 200 {
		t.Fatal("SMTP-Passwort")
	}
	_, b = c.do("GET", "/api/notify", nil)
	if !strings.Contains(string(b), `"password_set":true`) || strings.Contains(string(b), "smtp-geheim") || !strings.Contains(string(b), `{"key":"exit","label":`) {
		t.Fatalf("notify: %s", b)
	}
	if _, err := st.AllSettings(); err == nil {
		all, _ := st.AllSettings()
		for k, v := range all {
			if strings.Contains(v, "smtp-geheim") {
				t.Fatalf("SMTP-Passwort in der Datenbank (%s)", k)
			}
		}
	}
	if code, b := c.do("POST", "/api/notify/test", nil); code != 200 {
		t.Fatalf("Testmail: %d %s", code, b)
	}
	// Sperre nach Fehlversuchen → genau eine Meldung
	other := &client{t: t, h: a.Handler()}
	for i := 0; i < 9; i++ {
		other.do("POST", "/api/auth/login", map[string]string{"username": "martin", "password": "falsch"})
	}
	waitMail := func(part string) {
		t.Helper()
		for i := 0; i < 50; i++ {
			for _, m := range e.SentMails() {
				if strings.Contains(m, part) {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Errorf("Mail %q fehlt: %v", part, e.SentMails())
	}
	waitMail("m@example.org | Testmail")
	waitMail("Anmeldung gesperrt")

	// Sicherung: Bestätigung nötig, Herunterladen, Einspielen ablegen, Neustart anstoßen
	if code, _ := c.do("POST", "/api/backup/export", map[string]any{"password": "sicherungs-passwort", "current": "falsch"}); code != 400 {
		t.Fatal("Sicherung ohne Passwort-Bestätigung")
	}
	code, data := c.do("POST", "/api/backup/export", map[string]any{"password": "sicherungs-passwort", "current": "geheimes-passwort-1", "logs": true})
	if code != 200 || !bytes.HasPrefix(data, []byte("VPNPBAK1")) {
		t.Fatalf("Export: %d %.200s", code, data)
	}
	if bytes.Contains(data, []byte("smtp-geheim")) {
		t.Fatal("Sicherung nicht verschlüsselt")
	}
	upload := func(file []byte, pw, current string) (int, []byte) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("password", pw)
		_ = mw.WriteField("current", current)
		fw, _ := mw.CreateFormFile("file", "x.vpnbak")
		_, _ = fw.Write(file)
		_ = mw.Close()
		return c.doRaw("POST", "/api/backup/restore", &buf, mw.FormDataContentType())
	}
	if code, b := upload(data, "falsches-passwort", "geheimes-passwort-1"); code != 400 || !strings.Contains(string(b), "Passwort falsch") {
		t.Fatalf("falsches Sicherungs-Passwort: %d %s", code, b)
	}
	if code, b := upload(data, "sicherungs-passwort", "geheimes-passwort-1"); code != 200 {
		t.Fatalf("Restore: %d %s", code, b)
	}
	m, ok := backup.Pending(dir)
	if !ok || m.Version != "0.15.0" {
		t.Fatalf("nicht abgelegt: %+v", m)
	}
	for i := 0; i < 100 && !restarted.Load(); i++ {
		time.Sleep(30 * time.Millisecond)
	}
	if !restarted.Load() {
		t.Error("kein Neustart angestoßen")
	}
	waitMail("Sicherung wird eingespielt")
	if code, _ := c.do("DELETE", "/api/backup/restore", nil); code != 200 {
		t.Error("Verwerfen")
	}
	if _, ok := backup.Pending(dir); ok {
		t.Error("noch abgelegt")
	}
}
