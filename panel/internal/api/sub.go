package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"vpnpanel/internal/engine"
)

var subTokenRe = regexp.MustCompile(`^[a-f0-9]{32}$`)

// subscription liefert das Abo für v2RayTun & Co. (Base64-Liste der Links + Traffic-Header).
func (a *API) subscription(w http.ResponseWriter, r *http.Request, tok string) {
	tok = strings.TrimSuffix(tok, "/")
	var ovpnPeer string // <token>/openvpn/<Zugang>: .ovpn-Profil (OpenVPN steht nicht in der Link-Liste)
	if t, rest, ok := strings.Cut(tok, "/openvpn/"); ok {
		tok, ovpnPeer = t, rest
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	if !subTokenRe.MatchString(tok) {
		http.NotFound(w, r)
		return
	}
	u, err := a.St.UserByToken(tok)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if ovpnPeer != "" {
		a.openVPNProfile(w, r, u.ID, ovpnPeer)
		return
	}
	// Offizielle sing-box-Apps: fertiges JSON-Profil statt Link-Liste („Remote Profile“)
	if f := r.URL.Query().Get("format"); f == "singbox" || f == "sing-box" {
		a.singBoxProfile(w, u.ID)
		return
	}
	// Hiddify & andere sing-box-Apps lesen manche Angaben anders (z. B. Port-Hopping)
	client := ""
	if ua := strings.ToLower(r.UserAgent()); strings.Contains(ua, "hiddify") || strings.Contains(ua, "sing-box") || strings.Contains(ua, "singbox") {
		client = "singbox"
	} else if strings.Contains(ua, "v2raytun") {
		client = "v2raytun" // WireGuard als Xray-JSON (v2RayTun liest keine wireguard://-Links)
	}
	links, err := a.E.SubLinksFor(u.ID, client)
	if err != nil {
		http.Error(w, "Fehler", http.StatusInternalServerError)
		return
	}
	var total int64
	plans := a.planMap()
	if l := engine.EffectiveLimits(u, plans); l != nil && l.TrafficGB > 0 {
		total = int64(l.TrafficGB * engine.GB)
	}
	title := a.E.Setting("profile_title")
	if title == "" {
		title = "VPN"
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte(title)))
	h.Set("profile-update-interval", a.E.Setting("sub_update_interval"))
	h.Set("subscription-userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.PeriodUp, u.PeriodDown, total, u.ExpiresAt))
	h.Set("content-disposition", `attachment; filename="`+asciiName(title)+`"`)
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	_, _ = w.Write([]byte(body))
}

// openVPNProfile: .ovpn-Datei eines OpenVPN-Zugangs des Nutzers (für den Import-Link von
// OpenVPN Connect und zum Herunterladen). Nur aktive Zugänge.
func (a *API) openVPNProfile(w http.ResponseWriter, r *http.Request, userID int64, peer string) {
	id, err := strconv.ParseInt(peer, 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	name, body, err := a.E.OpenVPNProfile(userID, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/x-openvpn-profile")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", `attachment; filename="`+asciiName(name)+`"`)
	_, _ = w.Write([]byte(body))
}

func (a *API) singBoxProfile(w http.ResponseWriter, userID int64) {
	b, err := a.E.SingBoxProfile(userID)
	if errors.Is(err, engine.ErrNoSingBox) {
		http.Error(w, "Keine Zugänge für sing-box (Hysteria2 oder WireGuard „Handy / Laptop“ mit vollem Tunnel)", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Fehler", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// singBoxImport: Link für den QR-Code der sing-box-App (legt das Profil als „Remote Profile“ an,
// die App aktualisiert es dann selbst).
func singBoxImport(subURL, name string) string {
	if subURL == "" {
		return ""
	}
	return "sing-box://import-remote-profile?url=" + url.QueryEscape(subURL+"?format=singbox") + "#" + url.PathEscape(name)
}

// asciiName: Dateiname für den Header (nur einfache Zeichen).
func asciiName(s string) string {
	out := []rune{}
	for _, r := range s {
		if r >= 0x20 && r < 0x7f && r != '"' && r != 92 {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "vpn"
	}
	return string(out)
}
