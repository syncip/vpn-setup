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
	case "trust_cloudflare", "update_check":
		if v != "0" && v != "1" {
			v = "0"
		}
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
