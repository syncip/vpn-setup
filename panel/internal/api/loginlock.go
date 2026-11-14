package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// Login-Sperre nach Adresse: Nach login_max_fails Fehlversuchen innerhalb von login_window Minuten
// wird die Adresse für login_lock Minuten gesperrt; bei Wiederholung innerhalb eines Tages
// verdoppelt sich die Dauer (login_lock_grow, höchstens 24 h). IPv6 zählt je /64, weil ein
// Angreifer innerhalb seines Netzes beliebig viele Adressen hat. Adressen aus login_allow
// werden nie gesperrt. Benutzernamen werden bewusst nie gesperrt.

const maxLockGrow = 24 * time.Hour

// lockKey: IPv4 einzeln, IPv6 als /64-Präfix
func lockKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

func (a *API) settingInt(k string, def int) int {
	n, err := strconv.Atoi(a.E.Setting(k))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func (a *API) lockAllowed(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	list, _ := engine.ParseNetList(a.E.Setting("login_allow"))
	for _, p := range list {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// lockNet: Eintrag als Präfix (einzelne Adresse = /32 bzw. /128)
func lockNet(net string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(net); err == nil {
		return p.Masked(), true
	}
	if ad, err := netip.ParseAddr(net); err == nil {
		ad = ad.Unmap()
		return netip.PrefixFrom(ad, ad.BitLen()), true
	}
	return netip.Prefix{}, false
}

// lockedUntil: Ist die Adresse gesperrt? until 0 = dauerhaft.
func (a *API) lockedUntil(ip string) (int64, bool) {
	if a.lockAllowed(ip) {
		return 0, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, false
	}
	addr = addr.Unmap()
	locks, _ := a.St.LoginLocks()
	now := time.Now().Unix()
	for _, l := range locks {
		if l.Until != 0 && l.Until <= now {
			continue
		}
		if p, ok := lockNet(l.Net); ok && p.Contains(addr) {
			return l.Until, true
		}
	}
	return 0, false
}

// recordFail: Fehlversuch zählen; true, wenn die Adresse dadurch jetzt gesperrt wurde.
func (a *API) recordFail(ip, name string) (int64, bool) {
	key := lockKey(ip)
	a.limiter.fail(key)
	if a.lockAllowed(ip) {
		return 0, false
	}
	max := a.settingInt("login_max_fails", 8)
	window := time.Duration(a.settingInt("login_window", 15)) * time.Minute
	if a.limiter.count(key, window) < max {
		return 0, false
	}
	a.limiter.reset(key)
	strikes := 1
	locks, _ := a.St.LoginLocks()
	for _, l := range locks {
		if l.Net == key {
			if l.Manual { // von Hand gesperrt: nicht überschreiben
				return l.Until, false
			}
			if l.Created > time.Now().Add(-24*time.Hour).Unix() {
				strikes = l.Strikes + 1
			}
		}
	}
	dur := time.Duration(a.settingInt("login_lock", 15)) * time.Minute
	if a.E.Setting("login_lock_grow") != "0" {
		for i := 1; i < strikes && dur < maxLockGrow; i++ {
			dur *= 2
		}
		if dur > maxLockGrow {
			dur = maxLockGrow
		}
	}
	until := time.Now().Add(dur).Unix()
	reason := fmt.Sprintf("%d Fehlversuche in %d Min.", max, int(window.Minutes()))
	if strikes > 1 {
		reason += fmt.Sprintf(" · %d. Sperre in Folge", strikes)
	}
	_ = a.St.PutLoginLock(&store.LoginLock{Net: key, Until: until, Strikes: strikes, Reason: reason})
	a.St.PruneLoginLocks()
	a.E.Log("warn", "Anmeldung von "+key+" gesperrt "+lockSpan(until)+" ("+reason+")")
	a.E.Notify("lockout", key, "Adresse für die Anmeldung gesperrt",
		"Nach zu vielen fehlgeschlagenen Anmeldungen ist die Anmeldung am Panel von dieser Adresse aus gesperrt "+lockSpan(until)+".\n\nAdresse: "+key+
			"\nZuletzt versuchter Benutzername: "+name+"\nGrund: "+reason+"\n\nEntsperren: Einstellungen → Sicherheit → Login-Sperre.")
	return until, true
}

func lockSpan(until int64) string {
	if until == 0 {
		return "dauerhaft"
	}
	return "bis " + time.Unix(until, 0).Local().Format("02.01. 15:04")
}

func lockMessage(until int64) string {
	if until == 0 {
		return "Anmeldung von dieser Adresse ist gesperrt"
	}
	return "Zu viele Fehlversuche – Anmeldung von dieser Adresse gesperrt " + lockSpan(until)
}

// ---------- API ----------

// GET /api/security/locks – Sperren (aktive zuerst) und die eigene Adresse
func (a *API) listLocks(w http.ResponseWriter, r *http.Request) {
	locks, err := a.St.LoginLocks()
	if err != nil {
		fail(w, err)
		return
	}
	now := time.Now().Unix()
	type row struct {
		*store.LoginLock
		Active bool `json:"active"`
	}
	out := []row{}
	for _, l := range locks {
		out = append(out, row{l, l.Until == 0 || l.Until > now})
	}
	writeJSON(w, map[string]any{"locks": out, "you": a.clientIP(r), "you_net": lockKey(a.clientIP(r))})
}

// POST /api/security/locks {net, minutes (0 = dauerhaft), reason} – von Hand sperren
func (a *API) addLock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Net     string `json:"net"`
		Minutes int64  `json:"minutes"`
		Reason  string `json:"reason"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	p, ok := lockNet(strings.TrimSpace(in.Net))
	if !ok {
		fail(w, errors.New("bitte eine IP-Adresse oder ein Netz angeben, z. B. 203.0.113.7 oder 2001:db8::/48"))
		return
	}
	if in.Minutes < 0 || in.Minutes > 525600 {
		fail(w, errors.New("Dauer: 0 (dauerhaft) bis 525600 Minuten"))
		return
	}
	if p.Bits() < 8 && p.Addr().Is4() || p.Bits() < 16 && p.Addr().Is6() {
		fail(w, errors.New("das Netz ist zu groß"))
		return
	}
	you, _ := netip.ParseAddr(a.clientIP(r))
	if you.IsValid() && p.Contains(you.Unmap()) {
		fail(w, errors.New("das würde deine eigene Adresse sperren"))
		return
	}
	net := p.String()
	if p.IsSingleIP() {
		net = p.Addr().String()
	}
	var until int64
	if in.Minutes > 0 {
		until = time.Now().Add(time.Duration(in.Minutes) * time.Minute).Unix()
	}
	reason := cleanName(strings.TrimSpace(in.Reason))
	if len([]rune(reason)) > 120 {
		reason = string([]rune(reason)[:120])
	}
	if reason == "" {
		reason = "von Hand gesperrt"
	}
	if err := a.St.PutLoginLock(&store.LoginLock{Net: net, Until: until, Manual: true, Reason: reason}); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Anmeldung von "+net+" gesperrt "+lockSpan(until)+" (von "+adminOf(r).Username+")")
	writeJSON(w, map[string]bool{"ok": true})
}

// POST /api/security/locks/remove {net} – entsperren
func (a *API) removeLock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Net string `json:"net"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteLoginLock(in.Net); err != nil {
		fail(w, err)
		return
	}
	a.limiter.reset(in.Net)
	a.E.Log("info", "Login-Sperre für "+cleanName(in.Net)+" aufgehoben (von "+adminOf(r).Username+")")
	writeJSON(w, map[string]bool{"ok": true})
}
