package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"vpnpanel/internal/engine"
)

var subTokenRe = regexp.MustCompile(`^[a-f0-9]{32}$`)

// subscription liefert das Abo für v2RayTun & Co. (Base64-Liste der Links + Traffic-Header).
func (a *API) subscription(w http.ResponseWriter, r *http.Request, tok string) {
	tok = strings.TrimSuffix(tok, "/")
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
	// Hiddify & andere sing-box-Apps lesen manche Angaben anders (z. B. Port-Hopping)
	client := ""
	if ua := strings.ToLower(r.UserAgent()); strings.Contains(ua, "hiddify") || strings.Contains(ua, "sing-box") || strings.Contains(ua, "singbox") {
		client = "singbox"
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
