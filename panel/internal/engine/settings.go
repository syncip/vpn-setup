package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	hostSettingRe = regexp.MustCompile(`^[a-zA-Z0-9.-]*$`)
	ifaceRe       = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
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
	case "out_interface":
		if !ifaceRe.MatchString(v) {
			return "", fmt.Errorf("Schnittstelle ungültig")
		}
	case "exit_speedtest":
		if n, err := strconv.Atoi(v); err != nil || n < 0 {
			return "", fmt.Errorf("%s: bitte eine Zahl ab 0", k)
		}
	case "trust_cloudflare", "update_check", "dns_enabled", "private_block", "dns_public", "dns_auto":
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
