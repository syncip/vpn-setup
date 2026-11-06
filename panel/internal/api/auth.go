package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"vpnpanel/internal/store"
)

const cookieName = "vp_session"

// ---------- Schutz gegen Durchprobieren ----------

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{hits: map[string][]time.Time{}} }

// allow: höchstens 8 Fehlversuche pro 15 Minuten und Adresse.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var keep []time.Time
	for _, t := range l.hits[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	l.hits[key] = keep
	return len(keep) < 8
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.hits[key], time.Now())
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

// ---------- Passwörter ----------

func HashPassword(pw string) (string, error) {
	if len(pw) < 10 {
		return "", errors.New("Passwort muss mindestens 10 Zeichen haben")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func RandomPassword() string {
	const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func tokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// ---------- Middleware ----------

func (a *API) sessionHours() int64 {
	h, _ := strconv.ParseInt(a.E.Setting("session_hours"), 10, 64)
	if h <= 0 {
		h = 168
	}
	return h
}

func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" {
			errJSON(w, http.StatusUnauthorized, "nicht angemeldet")
			return
		}
		id := tokenHash(c.Value)
		se, err := a.St.Session(id)
		now := nowUnix()
		if err != nil || se.Expires < now {
			errJSON(w, http.StatusUnauthorized, "Sitzung abgelaufen")
			return
		}
		adm, err := a.St.Admin(se.AdminID)
		if err != nil {
			errJSON(w, http.StatusUnauthorized, "nicht angemeldet")
			return
		}
		if now-se.LastUsed > 60 {
			a.St.TouchSession(id, now, now+a.sessionHours()*3600)
		}
		ctx := context.WithValue(r.Context(), adminKey, adm)
		ctx = context.WithValue(ctx, adminKey+1, id)
		next(w, r.WithContext(ctx))
	}
}

func adminOf(r *http.Request) *store.Admin { a, _ := r.Context().Value(adminKey).(*store.Admin); return a }
func sessionOf(r *http.Request) string     { s, _ := r.Context().Value(adminKey + 1).(string); return s }

// ---------- Handler ----------

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password, Code string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	ip := a.clientIP(r)
	if !a.limiter.allow(ip) {
		errJSON(w, http.StatusTooManyRequests, "Zu viele Fehlversuche – bitte 15 Minuten warten")
		return
	}
	adm, err := a.St.AdminByName(strings.TrimSpace(in.Username))
	if err != nil || !checkPassword(adm.PassHash, in.Password) {
		a.limiter.fail(ip)
		a.E.Log("warn", "Fehlgeschlagene Anmeldung von "+ip)
		errJSON(w, http.StatusUnauthorized, "Benutzername oder Passwort falsch")
		return
	}
	if adm.TOTPEnabled {
		if in.Code == "" {
			writeJSON(w, map[string]any{"need_totp": true})
			return
		}
		if !totp.Validate(strings.ReplaceAll(in.Code, " ", ""), adm.TOTPSecret) {
			a.limiter.fail(ip)
			errJSON(w, http.StatusUnauthorized, "Code falsch")
			return
		}
	}
	a.limiter.reset(ip)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	tok := hex.EncodeToString(raw)
	now := nowUnix()
	exp := now + a.sessionHours()*3600
	agent := r.UserAgent()
	if len(agent) > 200 {
		agent = agent[:200]
	}
	if err := a.St.CreateSession(&store.Session{ID: tokenHash(tok), AdminID: adm.ID, Created: now, Expires: exp, LastUsed: now, IP: ip, Agent: agent}); err != nil {
		fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(exp - now)})
	a.E.Log("info", "Anmeldung "+adm.Username+" von "+ip)
	writeJSON(w, map[string]any{"ok": true, "username": adm.Username, "totp_enabled": adm.TOTPEnabled})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.St.DeleteSession(tokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	adm := adminOf(r)
	writeJSON(w, map[string]any{"username": adm.Username, "totp_enabled": adm.TOTPEnabled, "id": adm.ID})
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, New string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	adm := adminOf(r)
	if !checkPassword(adm.PassHash, in.Current) {
		errJSON(w, http.StatusBadRequest, "Aktuelles Passwort falsch")
		return
	}
	h, err := HashPassword(in.New)
	if err != nil {
		fail(w, err)
		return
	}
	adm.PassHash = h
	if err := a.St.SaveAdmin(adm); err != nil {
		fail(w, err)
		return
	}
	a.St.DeleteSessionsOf(adm.ID, sessionOf(r))
	a.E.Log("info", "Passwort von "+adm.Username+" geändert")
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) totpSetup(w http.ResponseWriter, r *http.Request) {
	adm := adminOf(r)
	if adm.TOTPEnabled {
		errJSON(w, http.StatusBadRequest, "2FA ist schon aktiv")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "VPN-Panel " + a.E.Setting("server_host"), AccountName: adm.Username})
	if err != nil {
		fail(w, err)
		return
	}
	adm.TOTPSecret = key.Secret()
	if err := a.St.SaveAdmin(adm); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]string{"secret": key.Secret(), "url": key.URL()})
}

func (a *API) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	adm := adminOf(r)
	if adm.TOTPSecret == "" || !totp.Validate(strings.ReplaceAll(in.Code, " ", ""), adm.TOTPSecret) {
		errJSON(w, http.StatusBadRequest, "Code falsch – Uhrzeit am Handy prüfen")
		return
	}
	adm.TOTPEnabled = true
	if err := a.St.SaveAdmin(adm); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "2FA für "+adm.Username+" aktiviert")
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	adm := adminOf(r)
	if !checkPassword(adm.PassHash, in.Password) {
		errJSON(w, http.StatusBadRequest, "Passwort falsch")
		return
	}
	adm.TOTPEnabled, adm.TOTPSecret = false, ""
	if err := a.St.SaveAdmin(adm); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("warn", "2FA für "+adm.Username+" deaktiviert")
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) sessions(w http.ResponseWriter, r *http.Request) {
	list, err := a.St.SessionsOf(adminOf(r).ID)
	if err != nil {
		fail(w, err)
		return
	}
	cur := sessionOf(r)
	out := []map[string]any{}
	for _, s := range list {
		out = append(out, map[string]any{"created": s.Created, "last_used": s.LastUsed, "ip": s.IP, "agent": s.Agent, "current": s.ID == cur})
	}
	writeJSON(w, out)
}

func (a *API) logoutOthers(w http.ResponseWriter, r *http.Request) {
	a.St.DeleteSessionsOf(adminOf(r).ID, sessionOf(r))
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) listAdmins(w http.ResponseWriter, r *http.Request) {
	list, err := a.St.Admins()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, list)
}

func (a *API) createAdmin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if !nameRe.MatchString(in.Username) {
		errJSON(w, http.StatusBadRequest, "Benutzername ungültig (A-Z a-z 0-9 _ - ., max. 32 Zeichen)")
		return
	}
	h, err := HashPassword(in.Password)
	if err != nil {
		fail(w, err)
		return
	}
	adm := &store.Admin{Username: in.Username, PassHash: h}
	if err := a.St.SaveAdmin(adm); err != nil {
		errJSON(w, http.StatusBadRequest, "Benutzername schon vergeben")
		return
	}
	a.E.Log("info", "Administrator "+adm.Username+" angelegt von "+adminOf(r).Username)
	writeJSON(w, adm)
}

func (a *API) deleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if id == adminOf(r).ID {
		errJSON(w, http.StatusBadRequest, "Du kannst dich nicht selbst löschen")
		return
	}
	if err := a.St.DeleteAdmin(id); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
