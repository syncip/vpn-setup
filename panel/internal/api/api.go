// Package api: JSON-API für die Oberfläche, Abo-Auslieferung und statische Dateien.
package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

type API struct {
	E       *engine.Engine
	St      *store.Store
	Static  fs.FS
	Secure  bool // Cookies nur über HTTPS
	Version string
	limiter *limiter
}

func New(e *engine.Engine, static fs.FS, secure bool, version string) *API {
	return &API{E: e, St: e.St, Static: static, Secure: secure, Version: version, limiter: newLimiter()}
}

type ctxKey int

const adminKey ctxKey = 1

func (a *API) Handler() http.Handler {
	api := http.NewServeMux()
	// Anmeldung
	api.HandleFunc("POST /api/auth/login", a.login)
	api.HandleFunc("POST /api/auth/logout", a.logout)
	api.HandleFunc("GET /api/auth/me", a.auth(a.me))
	api.HandleFunc("POST /api/auth/password", a.auth(a.changePassword))
	api.HandleFunc("POST /api/auth/totp/setup", a.auth(a.totpSetup))
	api.HandleFunc("POST /api/auth/totp/enable", a.auth(a.totpEnable))
	api.HandleFunc("POST /api/auth/totp/disable", a.auth(a.totpDisable))
	api.HandleFunc("GET /api/auth/sessions", a.auth(a.sessions))
	api.HandleFunc("DELETE /api/auth/sessions", a.auth(a.logoutOthers))
	api.HandleFunc("GET /api/admins", a.auth(a.listAdmins))
	api.HandleFunc("POST /api/admins", a.auth(a.createAdmin))
	api.HandleFunc("DELETE /api/admins/{id}", a.auth(a.deleteAdmin))

	api.HandleFunc("GET /api/meta", a.auth(a.meta))
	api.HandleFunc("GET /api/overview", a.auth(a.overview))

	api.HandleFunc("GET /api/users", a.auth(a.listUsers))
	api.HandleFunc("POST /api/users", a.auth(a.createUser))
	api.HandleFunc("GET /api/users/{id}", a.auth(a.getUser))
	api.HandleFunc("PUT /api/users/{id}", a.auth(a.updateUser))
	api.HandleFunc("DELETE /api/users/{id}", a.auth(a.deleteUser))
	api.HandleFunc("POST /api/users/{id}/reset", a.auth(a.resetUser))
	api.HandleFunc("POST /api/users/{id}/token", a.auth(a.newToken))
	api.HandleFunc("GET /api/users/{id}/traffic", a.auth(a.userTraffic))

	api.HandleFunc("POST /api/peers", a.auth(a.createPeer))
	api.HandleFunc("GET /api/peers/{id}", a.auth(a.getPeer))
	api.HandleFunc("PUT /api/peers/{id}", a.auth(a.updatePeer))
	api.HandleFunc("DELETE /api/peers/{id}", a.auth(a.deletePeer))
	api.HandleFunc("GET /api/peers/{id}/config", a.auth(a.peerConfig))
	api.HandleFunc("GET /api/peers/{id}/traffic", a.auth(a.peerTraffic))

	api.HandleFunc("GET /api/servers", a.auth(a.listServers))
	api.HandleFunc("POST /api/servers", a.auth(a.createServer))
	api.HandleFunc("GET /api/servers/{id}", a.auth(a.getServer))
	api.HandleFunc("PUT /api/servers/{id}", a.auth(a.updateServer))
	api.HandleFunc("DELETE /api/servers/{id}", a.auth(a.deleteServer))
	api.HandleFunc("GET /api/servers/{id}/network", a.auth(a.network))
	api.HandleFunc("GET /api/servers/{id}/traffic", a.auth(a.serverTraffic))

	api.HandleFunc("GET /api/plans", a.auth(a.listPlans))
	api.HandleFunc("POST /api/plans", a.auth(a.createPlan))
	api.HandleFunc("PUT /api/plans/{id}", a.auth(a.updatePlan))
	api.HandleFunc("DELETE /api/plans/{id}", a.auth(a.deletePlan))

	api.HandleFunc("GET /api/settings", a.auth(a.getSettings))
	api.HandleFunc("PUT /api/settings", a.auth(a.putSettings))
	api.HandleFunc("GET /api/system", a.auth(a.system))
	api.HandleFunc("POST /api/system/apply", a.auth(a.applyNow))
	api.HandleFunc("POST /api/system/collect", a.auth(a.collectNow))
	api.HandleFunc("GET /api/events", a.auth(a.events))
	api.HandleFunc("GET /api/traffic", a.auth(a.traffic))

	static := a.staticHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		host := hostOnly(r.Host)
		// Abo: https://sub.domain/<token> oder https://panel.domain/sub/<token>
		if sub := a.E.Setting("sub_host"); sub != "" && strings.EqualFold(host, sub) && !strings.HasPrefix(r.URL.Path, "/api/") {
			a.subscription(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/sub/") {
			a.subscription(w, r, strings.TrimPrefix(r.URL.Path, "/sub/"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "vpnpanel" {
				errJSON(w, http.StatusForbidden, "ungültige Anfrage")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			api.ServeHTTP(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
}

func secHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

func (a *API) staticHandler() http.Handler {
	files := http.FileServer(http.FS(a.Static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := a.Static.Open(p); err == nil {
				f.Close()
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		// Single-Page-App: alles andere liefert index.html
		data, err := fs.ReadFile(a.Static, "index.html")
		if err != nil {
			http.Error(w, "Oberfläche nicht gebaut", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
}

// ---------- Hilfen ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func fail(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "nicht gefunden")
		return
	}
	errJSON(w, http.StatusBadRequest, err.Error())
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return errors.New("ungültige Eingabe: " + err.Error())
	}
	return nil
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func (a *API) clientIP(r *http.Request) string {
	if a.E.Setting("trust_cloudflare") == "1" {
		if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func nowUnix() int64 { return time.Now().Unix() }
