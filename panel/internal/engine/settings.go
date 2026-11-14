package engine

import (
	"fmt"
	"net/mail"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	hostSettingRe = regexp.MustCompile(`^[a-zA-Z0-9.-]*$`)
	ifaceRe       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
)

// ValidateSetting prüft einen Wert für die Einstellungen (Webinterface und „vpn config“)
// und gibt ihn bereinigt zurück.
func ValidateSetting(k, v string) (string, error) {
	if _, ok := settingDefaults[k]; !ok {
		return "", fmt.Errorf("unbekannte Einstellung %s", k)
	}
	v = strings.TrimSpace(v)
	switch k {
	case "server_host", "panel_host", "sub_host":
		v = strings.ToLower(strings.TrimSuffix(v, "."))
		if !hostSettingRe.MatchString(v) {
			return "", fmt.Errorf("%s: ungültiger Hostname", k)
		}
	case "collect_interval", "sub_update_interval", "traffic_retention", "public_port", "session_hours":
		if n, err := strconv.Atoi(v); err != nil || n <= 0 {
			return "", fmt.Errorf("%s: bitte eine positive Zahl", k)
		}
	case "xray_api":
		// nur lokal: darüber liest das Panel die Statistik, Xray lauscht dort ohne Anmeldung
		ap, err := netip.ParseAddrPort(v)
		if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
			return "", fmt.Errorf("Xray-API: lokale Adresse mit Port, z. B. 127.0.0.1:10085")
		}
		v = ap.String()
	case "profile_title":
		if len([]rune(v)) > 64 {
			return "", fmt.Errorf("Profilname: höchstens 64 Zeichen")
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return "", fmt.Errorf("Profilname: keine Steuerzeichen")
			}
		}
	case "out_interface":
		if !ifaceRe.MatchString(v) {
			return "", fmt.Errorf("Schnittstelle ungültig")
		}
	case "exit_speedtest":
		if n, err := strconv.Atoi(v); err != nil || n < 0 {
			return "", fmt.Errorf("%s: bitte eine Zahl ab 0", k)
		}
	case "login_max_fails":
		if n, err := strconv.Atoi(v); err != nil || n < 3 || n > 100 {
			return "", fmt.Errorf("Login-Sperre: 3 bis 100 Fehlversuche")
		}
	case "login_window", "login_lock":
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 1440 {
			return "", fmt.Errorf("Login-Sperre: 1 bis 1440 Minuten")
		}
	case "login_allow":
		list, err := ParseNetList(v)
		if err != nil {
			return "", fmt.Errorf("Nie sperren: %v", err)
		}
		var parts []string
		for _, p := range list {
			if p.IsSingleIP() {
				parts = append(parts, p.Addr().String())
			} else {
				parts = append(parts, p.String())
			}
		}
		v = strings.Join(parts, "\n")
	case "trust_cloudflare", "update_check", "dns_enabled", "private_block", "dns_public", "dns_auto", "dns_tls", "login_lock_grow", "pkg_refresh":
		if v != "0" && v != "1" {
			v = "0"
		}
	case "dns_log_days":
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 365 {
			return "", fmt.Errorf("DNS-Protokoll: Tage von 0 bis 365")
		}
	case "private_allow":
		list, err := ParsePrivateAllow(v)
		if err != nil {
			return "", err
		}
		v = strings.Join(list, "\n")
	case "dns_cache_size":
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 1000000 {
			return "", fmt.Errorf("DNS-Zwischenspeicher: 0 (aus) bis 1 000 000 Antworten")
		}
	case "dns_ttl_min", "dns_ttl_max":
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 7*86400 {
			return "", fmt.Errorf("DNS-Speicherdauer: 0 bis 604800 Sekunden (7 Tage)")
		}
	case "dns_nocache":
		list, err := ParseRouteDomains(v)
		if err != nil {
			return "", err
		}
		if len(list) > 500 {
			return "", fmt.Errorf("höchstens 500 Domains ohne Zwischenspeicher")
		}
		v = strings.Join(list, "\n")
	case "dns_strategy":
		switch v {
		case "order", "fastest", "roundrobin", "parallel":
		default:
			return "", fmt.Errorf("DNS-Verteilung: order, fastest, roundrobin oder parallel")
		}
	case "dns_resolver":
		if v != "upstream" && v != "unbound" {
			return "", fmt.Errorf("Auflösung: upstream oder unbound")
		}
	case "dns_auto_hours":
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 168 {
			return "", fmt.Errorf("Automatischer Test: alle 1 bis 168 Stunden")
		}
	case "dns_tls_host":
		v = strings.ToLower(strings.Trim(strings.TrimSpace(v), "."))
		if v != "" && (!hostnameRe.MatchString(v) || strings.Count(v, ".") < 2) {
			return "", fmt.Errorf("DNS-Name: eine eigene Subdomain wie dns.example.org angeben")
		}
		return v, nil
	case "dns_dot_port":
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("DoT-Port: 1 bis 65535")
		}
	case "dns_acme_email":
		v = strings.TrimSpace(v)
		if v != "" && (!strings.Contains(v, "@") || strings.ContainsAny(v, " <>\n")) {
			return "", fmt.Errorf("E-Mail-Adresse ungültig")
		}
		return v, nil
	case "dns_auto_count":
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 4 {
			return "", fmt.Errorf("Automatischer Test: 1 bis 4 Server übernehmen")
		}
	case "dns_candidates":
		if v != "" {
			list, err := ParseCandidates(v)
			if err != nil {
				return "", err
			}
			v = CandidatesText(list)
		}
	case "mail_enabled":
		if v != "1" {
			v = "0"
		}
	case "smtp_host":
		v = strings.ToLower(strings.TrimSuffix(v, "."))
		if v != "" && (!hostSettingRe.MatchString(v) || strings.HasPrefix(v, "-") || len(v) > 253) {
			if _, err := netip.ParseAddr(v); err != nil {
				return "", fmt.Errorf("Mailserver: Hostname oder IP-Adresse")
			}
		}
	case "smtp_port":
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("Mailserver-Port: 1 bis 65535")
		}
	case "smtp_security":
		if v != "starttls" && v != "tls" && v != "none" {
			return "", fmt.Errorf("Verschlüsselung: starttls, tls oder none")
		}
	case "smtp_user":
		if len(v) > 200 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return "", fmt.Errorf("Benutzername des Mailservers ungültig")
		}
	case "mail_from":
		if v != "" {
			// so speichern, wie eingegeben; kodiert wird erst beim Versand (buildMail)
			if _, err := mail.ParseAddress(v); err != nil || len(v) > 254 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
				return "", fmt.Errorf("Absender: gültige E-Mail-Adresse, z. B. panel@example.org oder „VPN-Panel <panel@example.org>“")
			}
		}
	case "notify_events":
		known := map[string]bool{}
		for _, ev := range NotifyEvents {
			known[ev.Key] = true
		}
		var keep []string
		seen := map[string]bool{}
		for _, k := range strings.Split(v, ",") {
			k = strings.TrimSpace(k)
			if k == "" || seen[k] {
				continue
			}
			if !known[k] {
				return "", fmt.Errorf("unbekannter Anlass %q", k)
			}
			seen[k] = true
			keep = append(keep, k)
		}
		v = strings.Join(keep, ",")
	case "dns_upstream":
		list, err := ParseUpstream(v)
		if err != nil {
			return "", err
		}
		v = strings.Join(list, ", ")
	}
	return v, nil
}

// oldHostDefaults: Vorgaben bis v0.4.2. Installationen aus dieser Zeit, die die Werte nie
// gespeichert haben, behalten sie (siehe PinOldDefaults).
var oldHostDefaults = map[string]string{"server_host": "sys1.1337733.xyz", "sub_host": "sub.1337733.xyz"}

// PinOldDefaults: Bestehende Installation (es gibt schon Server) ohne gespeicherte Domains →
// die früheren Vorgaben fest speichern, damit sich Links und Abos nicht ändern.
func (e *Engine) PinOldDefaults() {
	servers, err := e.St.Servers()
	if err != nil || len(servers) == 0 {
		return
	}
	all, err := e.St.AllSettings()
	if err != nil {
		return
	}
	for k, v := range oldHostDefaults {
		if _, ok := all[k]; !ok {
			_ = e.St.SetSetting(k, v)
		}
	}
}
