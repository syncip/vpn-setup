package engine

// nginx: SNI-Verteiler auf Port 443 (/etc/nginx/stream.d/vpn.conf).

import (
	"fmt"
	"sort"
	"strings"

	"vpnpanel/internal/proto"
)

// ---------- nginx SNI-Verteiler ----------

const nginxStream = "/etc/nginx/stream.d/vpn.conf"

func (e *Engine) applyNginx(snap *Snapshot) error {
	if !e.Sys.Exists("/etc/nginx/nginx.conf") && !e.Sys.DryRun() {
		return nil
	}
	routes := map[int][]proto.SNIRoute{}
	defaults := map[int]string{}
	pub := atoi(e.Setting("public_port"), 443)
	for _, h := range []string{e.Setting("panel_host"), e.Setting("sub_host")} {
		if h != "" {
			routes[pub] = append(routes[pub], proto.SNIRoute{Port: pub, SNI: h, Backend: e.Cfg.PanelBackend})
		}
	}
	for _, d := range proto.All() {
		r, ok := d.(proto.SNIRouter)
		if !ok {
			continue
		}
		for _, rt := range r.SNIRoutes(snap.ByProto[d.Info().ID]) {
			if rt.SNI == "" {
				if _, ok := defaults[rt.Port]; !ok {
					defaults[rt.Port] = rt.Backend
				}
				continue
			}
			routes[rt.Port] = append(routes[rt.Port], rt)
		}
	}
	if _, ok := defaults[pub]; !ok {
		defaults[pub] = e.Cfg.PanelBackend
	}
	// Verschlüsseltes DNS (DoH) und SmartDNS: Namen samt Unterdomains („.name“ in nginx)
	wild := map[int][]proto.SNIRoute{}
	if h := e.encDNSHost(); h != "" && e.encDNSOn() {
		wild[pub] = append(wild[pub], proto.SNIRoute{Port: pub, SNI: "." + h, Backend: dohAddr})
	}
	exact := map[string]bool{}
	for _, r := range routes[pub] {
		exact[r.SNI] = true
	}
	for _, d := range e.smartNginxNames() {
		if exact[d] || d == e.encDNSHost() {
			continue
		}
		sni := d                                                     // genau dieser Name; *.domain versteht nginx selbst (alle Unterdomains)
		if proto.IsDomainPattern(d) && proto.SubdomainsOf(d) == "" { // Muster als regulärer Ausdruck (nginx: „~“)
			sni = "\"~" + proto.DomainPatternRegexpLabel(d) + "\""
		}
		wild[pub] = append(wild[pub], proto.SNIRoute{Port: pub, SNI: sni, Backend: smartAddr})
	}
	var ports []int
	for p := range defaults {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var b strings.Builder
	b.WriteString("# Vom VPN-Panel erzeugt – Änderungen werden überschrieben.\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "\nmap $ssl_preread_server_name $vpn_backend_%d {\n", p)
		if len(wild[p]) > 0 {
			b.WriteString("    hostnames;\n")
		}
		seen := map[string]bool{}
		for _, r := range routes[p] {
			if seen[r.SNI] {
				continue
			}
			seen[r.SNI] = true
			fmt.Fprintf(&b, "    %s %s;\n", r.SNI, r.Backend)
		}
		for _, r := range wild[p] {
			if seen[r.SNI] {
				continue
			}
			seen[r.SNI] = true
			fmt.Fprintf(&b, "    %s %s;\n", r.SNI, r.Backend)
		}
		fmt.Fprintf(&b, "    default %s;\n}\n\nserver {\n    listen %d;\n    listen [::]:%d;\n    ssl_preread on;\n    proxy_pass $vpn_backend_%d;\n    proxy_protocol on;\n    proxy_connect_timeout 5s;\n}\n", defaults[p], p, p, p)
	}
	data := []byte(b.String())
	old, _ := e.Sys.ReadFile(nginxStream)
	legacy := e.Sys.Exists("/etc/nginx/stream.d/vless.conf")
	if string(old) == string(data) && !legacy {
		return nil
	}
	if _, err := e.Sys.WriteFile(nginxStream, data, 0o644); err != nil {
		return err
	}
	_ = e.Sys.Remove("/etc/nginx/stream.d/vless.conf")
	if _, err := e.Sys.Run("nginx", "-t"); err != nil {
		if len(old) > 0 {
			_, _ = e.Sys.WriteFile(nginxStream, old, 0o644)
		}
		return err
	}
	if _, err := e.Sys.Run("systemctl", "reload-or-restart", "nginx"); err != nil {
		return err
	}
	e.Log("info", "nginx-SNI-Verteiler aktualisiert")
	return nil
}

func atoi(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def
	}
	return n
}
