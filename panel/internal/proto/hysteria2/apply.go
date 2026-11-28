package hysteria2

// Client-Adressen aus der Anmeldung und Anwenden (Instanzen vpn-hysteria@).

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
)

// ---------- Client-Adressen aus der Anmeldung ----------

type seenAddr struct {
	addr netip.Addr
	at   time.Time
}

var (
	addrMu sync.Mutex
	addrs  = map[int64][]seenAddr{} // Peer-ID → Adressen
)

func rememberAddr(id int64, a netip.Addr) (isNew bool) {
	addrMu.Lock()
	defer addrMu.Unlock()
	for i, s := range addrs[id] {
		if s.addr == a {
			addrs[id][i].at = time.Now()
			return false
		}
	}
	addrs[id] = append(addrs[id], seenAddr{a, time.Now()})
	return true
}

// lastAddr: zuletzt bei der Anmeldung gesehene Client-Adresse („“ = unbekannt, z. B. nach Panel-Neustart
// bis zur nächsten Anmeldung).
func lastAddr(id int64) string {
	addrMu.Lock()
	defer addrMu.Unlock()
	var best seenAddr
	for _, s := range addrs[id] {
		if s.at.After(best.at) {
			best = s
		}
	}
	if !best.addr.IsValid() {
		return ""
	}
	return best.addr.Unmap().String()
}

func addrsOf(id int64) []netip.Addr {
	addrMu.Lock()
	defer addrMu.Unlock()
	var out []netip.Addr
	for _, s := range addrs[id] {
		out = append(out, s.addr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// forget entfernt Adressen von Zugängen, die nicht mehr online sind (mit Schonfrist).
func forget(online map[int64]bool, ids []int64) bool {
	addrMu.Lock()
	defer addrMu.Unlock()
	changed := false
	for _, id := range ids {
		if online[id] {
			continue
		}
		var keep []seenAddr
		for _, s := range addrs[id] {
			if time.Since(s.at) < 3*time.Minute {
				keep = append(keep, s)
			}
		}
		if len(keep) != len(addrs[id]) {
			changed = true
		}
		if len(keep) == 0 {
			delete(addrs, id)
		} else {
			addrs[id] = keep
		}
	}
	return changed
}

// Hook: Anmeldung einer Hysteria2-Instanz (auth type http).
func (Driver) Hook(env *proto.Env, sb *proto.ServerBundle, body []byte) (any, bool, error) {
	var req struct {
		Addr string `json:"addr"`
		Auth string `json:"auth"`
	}
	deny := map[string]any{"ok": false, "id": ""}
	if err := json.Unmarshal(body, &req); err != nil || req.Auth == "" {
		return deny, false, nil
	}
	if !sb.Server.Enabled {
		return deny, false, nil
	}
	for _, pb := range sb.Peers {
		pw := proto.Str(pb.Peer.Secrets, "password")
		if pw == "" || subtle.ConstantTimeCompare([]byte(pw), []byte(req.Auth)) != 1 {
			continue
		}
		if !pb.Active {
			return deny, false, nil
		}
		reshape := false
		if ap, err := netip.ParseAddrPort(req.Addr); err == nil {
			isNew := rememberAddr(pb.Peer.ID, ap.Addr().Unmap())
			reshape = isNew && load(sb.Server).Shaping && (pb.RateDown > 0 || pb.RateUp > 0)
		}
		return map[string]any{"ok": true, "id": peerID(pb.Peer)}, reshape, nil
	}
	return deny, false, nil
}

// ---------- Anwenden ----------

func (d Driver) Apply(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	want := map[string]bool{}
	var errs []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		want[name(sb.Server)] = true
		if err := applyServer(env, sb); err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
		}
	}
	if err := applyHopping(env, servers); err != nil {
		errs = append(errs, "Port-Hopping: "+err.Error())
	}
	// Entfernte/deaktivierte Instanzen abbauen
	var prev []string
	_ = json.Unmarshal([]byte(env.GetState("hy:instances")), &prev)
	for _, n := range prev {
		if want[n] {
			continue
		}
		_, _ = sys.Run("systemctl", "disable", "--now", "vpn-hysteria@"+n)
		for _, ext := range []string{".yaml", ".crt", ".key"} {
			_ = sys.Remove(confDir + "/" + n + ext)
		}
		env.Log("info", "Hysteria2-Instanz "+n+" entfernt")
	}
	var now []string
	for n := range want {
		now = append(now, n)
	}
	sort.Strings(now)
	b, _ := json.Marshal(now)
	env.SetState("hy:instances", string(b))
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func bw(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) + " mbps" }

func applyServer(env *proto.Env, sb *proto.ServerBundle) error {
	sys := env.Sys
	srv := sb.Server
	c := load(srv)
	n := name(srv)
	if !sys.DryRun() && !sys.Exists(binPath) {
		return fmt.Errorf("Hysteria ist nicht installiert (%s fehlt – Setup-Script erneut ausführen)", binPath)
	}
	if env.Global.HookURL == "" {
		return fmt.Errorf("interner Anmelde-Endpunkt des Panels fehlt (Option -hook)")
	}
	changed := false
	if ch, err := sys.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	} else if ch {
		_, _ = sys.Run("systemctl", "daemon-reload")
	}
	certFile, keyFile := c.CertFile, c.KeyFile
	if certFile == "" {
		certFile, keyFile = confDir+"/"+n+".crt", confDir+"/"+n+".key"
		ch1, err := sys.WriteFile(certFile, []byte(proto.Str(srv.State, "cert_pem")), 0o644)
		if err != nil {
			return err
		}
		ch2, err := sys.WriteFile(keyFile, []byte(proto.Str(srv.State, "key_pem")), 0o600)
		if err != nil {
			return err
		}
		changed = changed || ch1 || ch2
	}
	cfg := map[string]any{
		"listen": fmt.Sprintf(":%d", c.Port),
		"tls":    map[string]any{"cert": certFile, "key": keyFile},
		"auth": map[string]any{"type": "http", "http": map[string]any{
			"url": fmt.Sprintf("%s/%d/%s", env.Global.HookURL, srv.ID, proto.Str(srv.State, "hook_secret"))}},
		"trafficStats":          map[string]any{"listen": statsAddr(srv), "secret": proto.Str(srv.State, "stats_secret")},
		"ignoreClientBandwidth": c.IgnoreClientBandwidth,
		"quic": map[string]any{
			"maxIdleTimeout":          fmt.Sprintf("%ds", idle(c.IdleTimeout)),
			"disablePathMTUDiscovery": c.DisableMTUDiscovery,
		},
	}
	if c.Obfs {
		cfg["obfs"] = map[string]any{"type": "salamander", "salamander": map[string]any{"password": proto.Str(srv.State, "obfs_password")}}
	}
	if c.Masquerade != "" {
		cfg["masquerade"] = map[string]any{"type": "proxy", "proxy": map[string]any{"url": c.Masquerade, "rewriteHost": true}}
	}
	if c.BandwidthDown > 0 || c.BandwidthUp > 0 {
		// aus Sicht des Servers: „up“ = senden = Download der Nutzer
		b := map[string]any{}
		if c.BandwidthDown > 0 {
			b["up"] = bw(c.BandwidthDown)
		}
		if c.BandwidthUp > 0 {
			b["down"] = bw(c.BandwidthUp)
		}
		cfg["bandwidth"] = b
	}
	// Ziel-Regeln (nur Server- und globale Regeln – Hysteria kann Nutzer nicht einzeln leiten):
	// je Gruppe ein Ausgang, gebunden an die Schnittstelle des gerade aktiven Ausgangs.
	if pol := env.Global.ServerPolicies[srv.ID]; pol != nil {
		var outs []map[string]any
		var acl []string
		seen := map[string]bool{}
		target := func(group int64) string {
			g, ok := env.Global.Groups[group]
			switch {
			case group == 0 || !ok || !g.Enabled || (g.Dev == "" && g.State == "direct"):
				return "direct"
			case g.Dev == "": // alle Ausgänge gestört (bzw. noch nicht geprüft) → sperren
				return "reject"
			}
			name := fmt.Sprintf("g%d", group)
			if !seen[name] {
				seen[name] = true
				outs = append(outs, map[string]any{"name": name, "type": "direct", "direct": map[string]any{"mode": "4", "bindDevice": g.Dev}})
			}
			return name
		}
		for _, r := range pol.Rules {
			t := target(r.Group)
			if r.All {
				acl = append(acl, t+"(all)")
				break
			}
			for _, d := range r.Domains {
				// genau der Name bzw. Hysterias Platzhalter (*.netflix.com, netflix.*)
				acl = append(acl, fmt.Sprintf("%s(%s)", t, d))
			}
			for _, n := range r.Nets {
				acl = append(acl, fmt.Sprintf("%s(%s)", t, n))
			}
			for _, id := range r.Lists {
				for _, n := range env.Global.TargetLists[id] {
					acl = append(acl, fmt.Sprintf("%s(%s)", t, n))
				}
			}
		}
		acl = append(acl, "direct(all)")
		if len(outs) > 0 {
			cfg["outbounds"] = outs
		}
		cfg["acl"] = map[string]any{"inline": acl}
	}
	// Private Ziele (internes Netz, Proxmox-Host, Loopback) und der Server selbst sind gesperrt –
	// Hysteria kann Nutzer nicht einzeln unterscheiden, deshalb gelten nur die Ausnahmen für alle.
	if pg := env.Global.Private; pg != nil {
		var pre []string
		for _, p := range pg.Allow {
			pre = append(pre, fmt.Sprintf("direct(%s)", p))
		}
		for _, p := range pg.Nets {
			pre = append(pre, fmt.Sprintf("reject(%s)", p))
		}
		var rest []string
		if a, ok := cfg["acl"].(map[string]any); ok {
			rest, _ = a["inline"].([]string)
		}
		if rest == nil {
			rest = []string{"direct(all)"}
		}
		cfg["acl"] = map[string]any{"inline": append(pre, rest...)}
	}
	// Loopback ist immer gesperrt – auch ohne die Sperre privater Ziele und vor allen Ausnahmen
	{
		var never, rest []string
		for _, p := range proto.NeverNets {
			never = append(never, fmt.Sprintf("reject(%s)", p))
		}
		if a, ok := cfg["acl"].(map[string]any); ok {
			rest, _ = a["inline"].([]string)
		}
		if rest == nil {
			rest = []string{"direct(all)"}
		}
		cfg["acl"] = map[string]any{"inline": append(never, rest...)}
	}
	// JSON ist gültiges YAML – Hysteria liest die Datei mit einem YAML-Parser.
	data, _ := json.MarshalIndent(cfg, "", "  ")
	data = append([]byte("# Vom VPN-Panel erzeugt – Änderungen werden überschrieben.\n"), append(data, '\n')...)
	ch, err := sys.WriteFile(confDir+"/"+n+".yaml", data, 0o600)
	if err != nil {
		return err
	}
	changed = changed || ch
	unit := "vpn-hysteria@" + n
	if changed {
		_, _ = sys.Run("systemctl", "enable", unit)
		if _, err := sys.Run("systemctl", "restart", unit); err != nil {
			return fmt.Errorf("Hysteria2 neu starten: %w", err)
		}
		env.Log("info", "Hysteria2 „"+srv.Name+"“ konfiguriert und neu gestartet")
	} else if _, err := sys.Run("systemctl", "is-active", "--quiet", unit); err != nil {
		_, _ = sys.Run("systemctl", "enable", unit)
		if _, err := sys.Run("systemctl", "restart", unit); err != nil {
			return fmt.Errorf("Hysteria2 starten: %w", err)
		}
	}

	// Gesperrte Zugänge sofort trennen, Begrenzungen anmelden
	var kick []string
	for _, pb := range sb.Peers {
		if !pb.Active {
			kick = append(kick, peerID(pb.Peer))
			continue
		}
		if c.Shaping && (pb.RateDown > 0 || pb.RateUp > 0) {
			if as := addrsOf(pb.Peer.ID); len(as) > 0 {
				// ausgehend = Download des Nutzers, eingehend = Upload
				// Beim Port-Hopping kommen Pakete auf vielen Ports an (tc sieht sie vor der Umleitung) →
				// dann alles von/zu der Client-Adresse begrenzen.
				port := c.Port
				if f, _, _ := hopRange(c.HopPorts); f > 0 {
					port = 0
				}
				env.Shape.Add(shaping.Rule{Key: fmt.Sprintf("hy-p%d", pb.Peer.ID), Egress: pb.RateDown, Ingress: pb.RateUp, Addrs: as, Port: port})
			}
		}
	}
	if len(kick) > 0 && !sys.DryRun() && !changed {
		if err := statsCall(srv, "POST", "/kick", kick, nil); err != nil {
			env.Log("warn", "Hysteria2: Trennen gesperrter Zugänge: "+err.Error())
		}
	}
	return nil
}

var client = &http.Client{Timeout: 5 * time.Second}

func statsCall(srv *store.Server, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+statsAddr(srv)+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", proto.Str(srv.State, "stats_secret"))
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
	}
	return nil
}
