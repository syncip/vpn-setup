// Package api: JSON-API für die Oberfläche, Abo-Auslieferung und statische Dateien.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
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
	codes   usedCodes
}

func New(e *engine.Engine, static fs.FS, secure bool, version string) *API {
	liveOnline = e.PeerLiveOnline
	liveSince = e.PeerLiveSince
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
	api.HandleFunc("POST /api/update/check", a.auth(a.checkUpdate))
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

	api.HandleFunc("GET /api/exits", a.auth(a.listExits))
	api.HandleFunc("POST /api/exits", a.auth(a.createExit))
	api.HandleFunc("PUT /api/exits/{id}", a.auth(a.updateExit))
	api.HandleFunc("DELETE /api/exits/{id}", a.auth(a.deleteExit))
	api.HandleFunc("POST /api/exits/check", a.auth(a.checkExits))
	api.HandleFunc("GET /api/exits/traffic", a.auth(a.exitTraffic))
	api.HandleFunc("POST /api/exits/{id}/check", a.auth(a.checkExit))
	api.HandleFunc("POST /api/groups", a.auth(a.createGroup))
	api.HandleFunc("PUT /api/groups/{id}", a.auth(a.updateGroup))
	api.HandleFunc("DELETE /api/groups/{id}", a.auth(a.deleteGroup))
	api.HandleFunc("POST /api/groups/{id}/switch", a.auth(a.switchGroup))
	api.HandleFunc("GET /api/iplists", a.auth(a.listIPLists))
	api.HandleFunc("POST /api/iplists", a.auth(a.createIPList))
	api.HandleFunc("PUT /api/iplists/{id}", a.auth(a.updateIPList))
	api.HandleFunc("DELETE /api/iplists/{id}", a.auth(a.deleteIPList))
	api.HandleFunc("POST /api/iplists/{id}/refresh", a.auth(a.refreshIPList))
	api.HandleFunc("GET /api/netaccess", a.auth(a.listNetAccess))
	api.HandleFunc("POST /api/netaccess", a.auth(a.createNetAccess))
	api.HandleFunc("PUT /api/netaccess/{id}", a.auth(a.updateNetAccess))
	api.HandleFunc("DELETE /api/netaccess/{id}", a.auth(a.deleteNetAccess))
	api.HandleFunc("GET /api/routes", a.auth(a.listRoutes))
	api.HandleFunc("POST /api/routes", a.auth(a.createRoute))
	api.HandleFunc("PUT /api/routes/{id}", a.auth(a.updateRoute))
	api.HandleFunc("DELETE /api/routes/{id}", a.auth(a.deleteRoute))
	api.HandleFunc("POST /api/routes/assign", a.auth(a.assignRoute))
	api.HandleFunc("GET /api/topology", a.auth(a.topology))
	api.HandleFunc("POST /api/peers/{id}/reach", a.auth(a.setReach))

	api.HandleFunc("GET /api/dns", a.auth(a.dnsOverview))
	api.HandleFunc("PUT /api/dns/settings", a.auth(a.dnsSettings))
	api.HandleFunc("POST /api/dns/profiles", a.auth(a.createDNSProfile))
	api.HandleFunc("PUT /api/dns/profiles/{id}", a.auth(a.updateDNSProfile))
	api.HandleFunc("DELETE /api/dns/profiles/{id}", a.auth(a.deleteDNSProfile))
	api.HandleFunc("POST /api/dns/lists", a.auth(a.createDNSList))
	api.HandleFunc("PUT /api/dns/lists/{id}", a.auth(a.updateDNSList))
	api.HandleFunc("DELETE /api/dns/lists/{id}", a.auth(a.deleteDNSList))
	api.HandleFunc("POST /api/dns/lists/{id}/refresh", a.auth(a.refreshDNSList))
	api.HandleFunc("GET /api/dns/log", a.auth(a.dnsLog))
	api.HandleFunc("GET /api/dns/stats", a.auth(a.dnsStats))
	api.HandleFunc("POST /api/dns/check", a.auth(a.dnsCheck))
	api.HandleFunc("POST /api/dns/speedtest", a.auth(a.dnsSpeedTest))
	api.HandleFunc("GET /api/dns/clients", a.auth(a.dnsExternal))
	api.HandleFunc("POST /api/dns/auto", a.auth(a.dnsAutoNow))
	api.HandleFunc("POST /api/dns/clients", a.auth(a.createDNSClient))
	api.HandleFunc("PUT /api/dns/clients/{id}", a.auth(a.updateDNSClient))
	api.HandleFunc("DELETE /api/dns/clients/{id}", a.auth(a.deleteDNSClient))
	api.HandleFunc("DELETE /api/dns/seen", a.auth(a.forgetDNSSeen))

	api.HandleFunc("GET /api/settings", a.auth(a.getSettings))
	api.HandleFunc("PUT /api/settings", a.auth(a.putSettings))
	api.HandleFunc("GET /api/system", a.auth(a.system))
	api.HandleFunc("POST /api/system/apply", a.auth(a.applyNow))
	api.HandleFunc("POST /api/system/collect", a.auth(a.collectNow))
	api.HandleFunc("GET /api/events", a.auth(a.events))
	api.HandleFunc("GET /api/traffic", a.auth(a.traffic))
	api.HandleFunc("GET /api/live", a.auth(a.live))

	static := a.staticHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		host := hostOnly(r.Host)
		// Abo: https://sub.domain/<token> oder https://panel.domain/sub/<token>
		// Auf der Abo-Domain gibt es nur die Abo-Links – keine Oberfläche, keine API.
		if sub := a.E.Setting("sub_host"); sub != "" && strings.EqualFold(host, sub) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			a.subscription(w, r, strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/sub/"), "/"))
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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// CF-Connecting-IP nur glauben, wenn die Verbindung wirklich von Cloudflare kommt –
	// sonst könnte jeder die Login-Sperre mit einem erfundenen Header umgehen.
	if a.E.Setting("trust_cloudflare") == "1" {
		if ip := r.Header.Get("CF-Connecting-IP"); ip != "" && fromCloudflare(host) {
			if p, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
				return p.String()
			}
		}
	}
	return host
}

// Cloudflare-Netze (https://www.cloudflare.com/ips/)
var cfNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Fields(`173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18
		108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
		104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32
		2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32`) {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func fromCloudflare(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, n := range cfNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func nowUnix() int64 { return time.Now().Unix() }

// HookHandler: interner Endpunkt (nur 127.0.0.1) für Dienste wie Hysteria2.
// POST /hook/<server-id>/<geheimnis>
func (a *API) HookHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hook/{id}/{secret}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := a.E.Hook(id, r.PathValue("secret"), body)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, resp)
	})
	return mux
}
