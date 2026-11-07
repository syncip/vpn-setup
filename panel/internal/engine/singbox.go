package engine

import (
	"encoding/json"
	"errors"
	"fmt"

	"vpnpanel/internal/proto"
)

// ErrNoSingBox: der Nutzer hat keinen Zugang, den sing-box nutzen kann.
var ErrNoSingBox = errors.New("keine Zugänge für sing-box")

// SingBoxProfile erzeugt ein vollständiges sing-box-Profil (JSON, Format ab sing-box 1.12) mit allen
// sing-box-tauglichen Zugängen eines Nutzers: Hysteria2 und WireGuard (Handy/Laptop, voller Tunnel).
// VLESS/Reality fehlt bewusst: Xray-Server ab v26.9.9 lehnen sing-box-Clients ab.
// Die Auswahl „VPN“ startet auf „Automatisch“ (schnellster erreichbarer Server).
func (e *Engine) SingBoxProfile(userID int64) ([]byte, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return nil, err
	}
	env := e.Env()
	env.Global.Client = "singbox"
	var outbounds, endpoints []any
	var tags []string
	seen := map[string]int{}
	for _, sb := range snap.Servers {
		if !sb.Server.Enabled {
			continue
		}
		d, ok := proto.Get(sb.Server.Protocol)
		if !ok {
			continue
		}
		sbx, ok := d.(proto.SingBoxer)
		if !ok {
			continue
		}
		for _, pb := range sb.Peers {
			if pb.Peer.UserID != userID || !pb.Peer.Enabled {
				continue
			}
			out, ep := sbx.SingBox(env, sb, pb)
			if out == nil && ep == nil {
				continue
			}
			// eindeutige, lesbare Namen („Server - Gerät“)
			tag := oneLineTag(sb.Server.Name + " - " + pb.Peer.Name)
			seen[tag]++
			if n := seen[tag]; n > 1 {
				tag = fmt.Sprintf("%s (%d)", tag, n)
			}
			tags = append(tags, tag)
			if out != nil {
				out["tag"] = tag
				outbounds = append(outbounds, out)
			} else {
				ep["tag"] = tag
				endpoints = append(endpoints, ep)
			}
		}
	}
	if len(tags) == 0 {
		return nil, ErrNoSingBox
	}
	all := append([]any{
		// Auswahl in der App (Groups → VPN, sichtbar sobald der Dienst läuft); beim Umschalten
		// wechseln auch bestehende Verbindungen sofort
		map[string]any{"type": "selector", "tag": "VPN", "outbounds": append([]string{"Automatisch"}, tags...), "default": "Automatisch",
			"interrupt_exist_connections": true},
		map[string]any{"type": "urltest", "tag": "Automatisch", "outbounds": tags,
			"url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
	}, outbounds...)
	all = append(all, map[string]any{"type": "direct", "tag": "direct"})
	cfg := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{
			"servers": []any{
				// Namensauflösung durch den Tunnel (verschlüsselt), Server-Adressen selbst über das lokale DNS
				map[string]any{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "VPN"},
				map[string]any{"type": "local", "tag": "local"},
			},
			"final": "remote",
		},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route": true, "strict_route": true,
		}},
		"outbounds": all,
		// merkt sich die gewählte Verbindung über Neustarts und Profil-Updates hinweg
		"experimental": map[string]any{"cache_file": map[string]any{"enabled": true}},
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
			},
			"final":                   "VPN",
			"auto_detect_interface":   true,
			"default_domain_resolver": "local",
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// oneLineTag: Steuerzeichen raus (Namen landen in der App-Oberfläche).
func oneLineTag(s string) string {
	r := []rune{}
	for _, c := range s {
		if c >= 0x20 && c != 0x7f && c != 0x2028 && c != 0x2029 {
			r = append(r, c)
		}
	}
	return string(r)
}
