// Package vless: Xray VLESS + Reality + Vision. Alle VLESS-Server teilen sich einen
// Xray-Prozess; nginx verteilt auf dem öffentlichen Port per SNI an die Inbounds.
package vless

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
)

const (
	xrayCfg     = "/usr/local/etc/xray/config.json"
	xrayNew     = "/usr/local/etc/xray/config.new.json" // Xray erkennt das Format an der Endung
	backendBase = 8443
	markBase    = 0x5600 // Markierung = markBase + Nutzer-ID
)

type Target struct {
	Dest        string   `json:"dest"`         // z. B. dl.google.com:443
	ServerNames []string `json:"server_names"` // SNIs, die dieses Ziel bedient
}

type serverCfg struct {
	PublicPort  int      `json:"public_port"`
	Targets     []Target `json:"targets"`
	Fingerprint string   `json:"fingerprint"`
	Flow        string   `json:"flow"`
	Host        string   `json:"host"`
	ShortIDs    []string `json:"short_ids"`
	Shaping     bool     `json:"shaping"`
}

type Driver struct{}

func init() { proto.Register(Driver{}) }

func (Driver) Info() proto.Info {
	return proto.Info{
		ID:          "vless",
		Label:       "VLESS Reality",
		Description: "Getarntes Protokoll (Xray) – sieht aus wie eine normale HTTPS-Verbindung zu großen Webseiten. Gut gegen Sperren.",
		ServerFields: []proto.Field{
			{Key: "targets", Label: "Tarnziele", Type: "targets", Default: []Target{
				{Dest: "dl.google.com:443", ServerNames: []string{"dl.google.com", "maps.google.com"}},
				{Dest: "web.whatsapp.com:443", ServerNames: []string{"web.whatsapp.com"}},
				{Dest: "www.apple.com:443", ServerNames: []string{"www.apple.com"}},
			}, Help: "Echte TLS-1.3-Webseiten, als die sich der Server ausgibt. Jeder SNI wird ein eigener Link im Abo."},
			{Key: "public_port", Label: "Öffentlicher TCP-Port", Type: "number", Default: 443, Advanced: true,
				Help: "Über nginx geteilt mit dem Panel und dem Abo. Andere Ports müssen auf dem Host weitergeleitet werden."},
			{Key: "fingerprint", Label: "TLS-Fingerabdruck", Type: "select", Default: "chrome", Advanced: true, Options: []proto.Option{
				{Value: "chrome", Label: "Chrome"}, {Value: "firefox", Label: "Firefox"}, {Value: "safari", Label: "Safari"},
				{Value: "ios", Label: "iOS"}, {Value: "edge", Label: "Edge"}, {Value: "random", Label: "Zufällig"},
			}},
			{Key: "flow", Label: "Flow", Type: "select", Default: "xtls-rprx-vision", Advanced: true, Options: []proto.Option{
				{Value: "xtls-rprx-vision", Label: "xtls-rprx-vision (empfohlen)"}, {Value: "", Label: "keiner"},
			}},
			{Key: "host", Label: "Adresse in den Links", Type: "text", Advanced: true, Placeholder: "Server-Domain aus den Einstellungen"},
			{Key: "shaping", Label: "Geschwindigkeitsbegrenzung", Type: "bool", Default: true, Advanced: true,
				Help: "Begrenzt VLESS-Nutzer per Markierung und tc auf der ausgehenden Schnittstelle. Braucht die Kernelmodule ifb und act_connmark auf dem Host."},
			{Key: "short_ids", Label: "Short-IDs", Type: "textlist", Advanced: true, Help: "Werden automatisch erzeugt. Hex, max. 16 Zeichen."},
		},
		Kinds: []proto.Kind{{ID: "access", Label: "Zugang", Icon: "key", Description: "Ein VLESS-Zugang (UUID) mit Links für alle Tarnziele.", Defaults: store.M{}}},
	}
}

func load(srv *store.Server) serverCfg {
	c := serverCfg{PublicPort: 443, Fingerprint: "chrome", Flow: "xtls-rprx-vision", Shaping: true}
	_ = proto.Decode(srv.Settings, &c)
	return c
}

var (
	hostRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	sidRe  = regexp.MustCompile(`^[0-9a-f]{0,16}$`)
)

func (Driver) InitServer(env *proto.Env, srv *store.Server, all []*store.Server) error {
	c := serverCfg{PublicPort: 443, Fingerprint: "chrome", Flow: "xtls-rprx-vision", Shaping: true, Targets: nil}
	if _, ok := srv.Settings["targets"]; !ok {
		c.Targets = []Target{{Dest: "dl.google.com:443", ServerNames: []string{"dl.google.com", "maps.google.com"}}}
	}
	_ = proto.Decode(srv.Settings, &c)
	if len(c.Targets) == 0 {
		return fmt.Errorf("mindestens ein Tarnziel nötig")
	}
	snis := map[string]bool{}
	for _, o := range all {
		if o.Protocol == "vless" && o.ID != srv.ID {
			oc := load(o)
			if oc.PublicPort == c.PublicPort {
				for _, t := range oc.Targets {
					for _, n := range t.ServerNames {
						snis[strings.ToLower(n)] = true
					}
				}
			}
		}
	}
	for i := range c.Targets {
		t := &c.Targets[i]
		t.Dest = strings.TrimSpace(t.Dest)
		if t.Dest == "" {
			return fmt.Errorf("Tarnziel %d: Ziel fehlt", i+1)
		}
		if !strings.Contains(t.Dest, ":") {
			t.Dest += ":443"
		}
		h, p, _ := strings.Cut(t.Dest, ":")
		if !hostRe.MatchString(h) {
			return fmt.Errorf("Tarnziel %q ungültig", t.Dest)
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("Tarnziel %q: Port ungültig", t.Dest)
		}
		var names []string
		for _, n := range t.ServerNames {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" {
				continue
			}
			if !hostRe.MatchString(n) {
				return fmt.Errorf("SNI %q ungültig", n)
			}
			if snis[n] {
				return fmt.Errorf("SNI %s wird auf Port %d schon verwendet", n, c.PublicPort)
			}
			snis[n] = true
			names = append(names, n)
		}
		if len(names) == 0 {
			names = []string{h}
			if snis[h] {
				return fmt.Errorf("SNI %s wird auf Port %d schon verwendet", h, c.PublicPort)
			}
			snis[h] = true
		}
		t.ServerNames = names
	}
	if c.PublicPort < 1 || c.PublicPort > 65535 {
		return fmt.Errorf("Port %d ungültig", c.PublicPort)
	}
	if c.Host != "" && !hostRe.MatchString(c.Host) {
		return fmt.Errorf("Adresse %q ungültig", c.Host)
	}
	var sids []string
	for _, s := range c.ShortIDs {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !sidRe.MatchString(s) || len(s)%2 != 0 {
			return fmt.Errorf("Short-ID %q ungültig (Hex, gerade Länge, max. 16)", s)
		}
		sids = append(sids, s)
	}
	if len(sids) == 0 {
		sids = []string{proto.RandHex(8)}
	}
	c.ShortIDs = sids
	srv.Settings = proto.Encode(c)

	if proto.Str(srv.State, "private_key") == "" {
		priv, pub, err := proto.X25519()
		if err != nil {
			return err
		}
		srv.State["private_key"] = proto.B64URL(priv)
		srv.State["public_key"] = proto.B64URL(pub)
	}
	return nil
}

func (Driver) InitPeer(env *proto.Env, srv *store.Server, p *store.Peer, others []*store.Peer) error {
	p.Kind = "access"
	if proto.Str(p.Secrets, "uuid") == "" {
		p.Secrets["uuid"] = proto.UUID()
	}
	return nil
}

// layout ordnet jedem Tarnziel aller aktiven VLESS-Server einen internen Port zu.
type inbound struct {
	sb     *proto.ServerBundle
	cfg    serverCfg
	target Target
	port   int
	tag    string
}

func layout(servers []*proto.ServerBundle) []inbound {
	var out []inbound
	port := backendBase
	sorted := append([]*proto.ServerBundle(nil), servers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Server.ID < sorted[j].Server.ID })
	for _, sb := range sorted {
		if !sb.Server.Enabled {
			continue
		}
		c := load(sb.Server)
		for i, t := range c.Targets {
			out = append(out, inbound{sb: sb, cfg: c, target: t, port: port, tag: fmt.Sprintf("s%d-t%d", sb.Server.ID, i)})
			port++
		}
	}
	return out
}

func email(p *store.Peer) string { return fmt.Sprintf("p%d", p.ID) }

func (Driver) SNIRoutes(servers []*proto.ServerBundle) []proto.SNIRoute {
	var out []proto.SNIRoute
	first := map[int]bool{}
	for _, in := range layout(servers) {
		backend := fmt.Sprintf("127.0.0.1:%d", in.port)
		if !first[in.cfg.PublicPort] {
			first[in.cfg.PublicPort] = true
			out = append(out, proto.SNIRoute{Port: in.cfg.PublicPort, SNI: "", Backend: backend})
		}
		for _, n := range in.target.ServerNames {
			out = append(out, proto.SNIRoute{Port: in.cfg.PublicPort, SNI: n, Backend: backend})
		}
	}
	return out
}

func (d Driver) Apply(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	ins := layout(servers)
	if len(ins) == 0 {
		if sys.Exists(xrayCfg) {
			_, _ = sys.Run("systemctl", "disable", "--now", "xray")
		}
		return nil
	}

	// Nutzer mit Geschwindigkeitslimit bekommen einen eigenen Ausgang mit Markierung
	type lim struct{ down, up float64 }
	limited := map[int64]lim{}
	var rules []map[string]any
	// Ziele selbst auflösen und IPv6 bevorzugen: Ohne das sortiert das System nach RFC 6724,
	// und weil der Container für IPv6 nur eine ULA-Adresse (NAT66) hat, gewinnt sonst immer IPv4.
	freedom := map[string]any{"domainStrategy": "UseIPv6v4"}
	outbounds := []map[string]any{{"protocol": "freedom", "tag": "direct", "settings": freedom}, {"protocol": "blackhole", "tag": "block"}}
	byUser := map[int64][]string{}
	// Ziel-Regeln: Zugänge mit gleicher Regelfolge (und gleichem Tempo-Limit) bilden eine Klasse
	type class struct {
		pol    *proto.Policy
		uid    int64 // Nutzer mit Tempo-Limit (0 = keins)
		emails []string
	}
	classes := map[string]*class{}
	var classKeys []string
	grantEmails := map[string][]string{} // freigegebene Netze (Netzwerk → Zugriff) → Zugänge

	var inbounds []map[string]any
	for _, in := range ins {
		var clients []map[string]any
		for _, pb := range in.sb.Peers {
			if !pb.Active {
				continue
			}
			clients = append(clients, map[string]any{"id": proto.Str(pb.Peer.Secrets, "uuid"), "flow": in.cfg.Flow, "email": email(pb.Peer), "level": 0})
			for _, t := range env.Global.Net.For(pb.Peer.ID) {
				k := strings.Join(proto.PrefixStrings(t.Nets), ",")
				grantEmails[k] = appendUnique(grantEmails[k], email(pb.Peer))
			}
			uid := int64(0)
			if in.cfg.Shaping && (pb.RateDown > 0 || pb.RateUp > 0) {
				limited[pb.User.ID] = lim{pb.RateDown, pb.RateUp}
				byUser[pb.User.ID] = appendUnique(byUser[pb.User.ID], email(pb.Peer))
				uid = pb.User.ID
			}
			if pol := env.Global.Policies[pb.Peer.ID]; pol != nil {
				k := fmt.Sprintf("%s/%d", pol.Key, uid)
				if classes[k] == nil {
					classes[k] = &class{pol: pol, uid: uid}
					classKeys = append(classKeys, k)
				}
				classes[k].emails = appendUnique(classes[k].emails, email(pb.Peer))
			}
		}
		if clients == nil {
			clients = []map[string]any{}
		}
		inbounds = append(inbounds, map[string]any{
			"tag": in.tag, "listen": "127.0.0.1", "port": in.port, "protocol": "vless",
			"settings": map[string]any{"clients": clients, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"sockopt": map[string]any{"acceptProxyProtocol": true},
				"realitySettings": map[string]any{
					"dest": in.target.Dest, "serverNames": in.target.ServerNames,
					"privateKey": proto.Str(in.sb.Server.State, "private_key"), "shortIds": in.cfg.ShortIDs,
				},
			},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
		})
	}
	uids := make([]int64, 0, len(byUser))
	for id := range byUser {
		uids = append(uids, id)
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	// Ziel-Regeln stehen vor den Tempo-Regeln: Ausgang je Gruppe (bei Tempo-Limit je Gruppe und
	// Nutzer – die Markierung trägt oben die Gruppe, unten den Nutzer für die Drosselung).
	sort.Strings(classKeys)
	groupOut := map[string]bool{}
	ipRules := false
	outTag := func(group, uid int64) string {
		g, ok := env.Global.Groups[group]
		if group == 0 || !ok || !g.Enabled {
			if uid != 0 {
				return fmt.Sprintf("lim-%d", uid)
			}
			return "direct"
		}
		tag, mark := fmt.Sprintf("g%d", group), int64(g.Mark)
		if uid != 0 {
			tag, mark = fmt.Sprintf("g%d-lim%d", group, uid), int64(g.Mark)|(markBase+uid)
		}
		if !groupOut[tag] {
			groupOut[tag] = true
			// Ausgänge können nur IPv4 – Namen deshalb nur zu IPv4-Adressen auflösen
			outbounds = append(outbounds, map[string]any{"protocol": "freedom", "tag": tag, "settings": map[string]any{"domainStrategy": "UseIPv4"},
				"streamSettings": map[string]any{"sockopt": map[string]any{"mark": mark}}})
		}
		return tag
	}
	for _, k := range classKeys {
		c := classes[k]
		for _, r := range c.pol.Rules {
			tag := outTag(r.Group, c.uid)
			if r.All {
				if r.Group != 0 { // IPv6-Ziele gingen sonst am Ausgang vorbei
					rules = append(rules, map[string]any{"type": "field", "user": c.emails, "ip": []string{"::/0"}, "outboundTag": "block"})
				}
				rules = append(rules, map[string]any{"type": "field", "user": c.emails, "outboundTag": tag})
				break
			}
			if len(r.Domains) > 0 {
				ds := make([]string, len(r.Domains))
				for i, d := range r.Domains {
					ds[i] = "domain:" + d
				}
				rules = append(rules, map[string]any{"type": "field", "user": c.emails, "domain": ds, "outboundTag": tag})
			}
			var ips []string
			for _, n := range r.Nets {
				ips = append(ips, n.String())
			}
			for _, id := range r.Lists {
				for _, n := range env.Global.TargetLists[id] {
					ips = append(ips, n.String())
				}
			}
			if len(ips) > 0 {
				ipRules = true
				rules = append(rules, map[string]any{"type": "field", "user": c.emails, "ip": ips, "outboundTag": tag})
			}
		}
	}
	for _, id := range uids {
		tag := fmt.Sprintf("lim-%d", id)
		outbounds = append(outbounds, map[string]any{"protocol": "freedom", "tag": tag, "settings": freedom,
			"streamSettings": map[string]any{"sockopt": map[string]any{"mark": markBase + id}}})
		rules = append(rules, map[string]any{"type": "field", "user": byUser[id], "outboundTag": tag})
	}
	// Private Ziele (internes Netz, Proxmox-Host, Loopback mit Xray-API und Panel) und der Server
	// selbst sind gesperrt – außer Ausnahmen und Freigaben. Steht vor allen anderen Regeln.
	if pg := env.Global.Private; pg != nil {
		var pre []map[string]any
		var keys []string
		for k := range grantEmails {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pre = append(pre, map[string]any{"type": "field", "user": grantEmails[k], "ip": strings.Split(k, ","), "outboundTag": "direct"})
		}
		if len(pg.Allow) > 0 {
			pre = append(pre, map[string]any{"type": "field", "ip": proto.PrefixStrings(pg.Allow), "outboundTag": "direct"})
		}
		pre = append(pre, map[string]any{"type": "field", "ip": proto.PrefixStrings(pg.Nets), "outboundTag": "block"})
		rules = append(pre, rules...)
		ipRules = true // auch Namen, die auf private Adressen zeigen, müssen auffallen
	}
	rules = aclRules(env, ins, rules)
	routing := map[string]any{"rules": orEmpty(rules)}
	if ipRules {
		// Regeln nach Zieladresse brauchen die Adresse auch dann, wenn die App einen Namen schickt
		routing["domainStrategy"] = "IPOnDemand"
	}
	cfg := map[string]any{
		"log":   map[string]any{"loglevel": "warning"},
		"api":   map[string]any{"tag": "api", "listen": env.Global.XrayAPI, "services": []string{"StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true,
			"statsUserOnline": true}}}, // merkt sich die Client-IPs (xray api statsonlineiplist)
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   routing,
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	data = append(data, '\n')

	old, _ := sys.ReadFile(xrayCfg)
	if string(old) != string(data) {
		if _, err := sys.WriteFile(xrayNew, data, 0o644); err != nil {
			return err
		}
		if out, err := sys.Run("xray", "run", "-test", "-config", xrayNew); err != nil {
			return fmt.Errorf("Xray-Konfiguration ungültig: %v %s", err, out)
		}
		if _, err := sys.WriteFile(xrayCfg, data, 0o644); err != nil {
			return err
		}
		_ = sys.Remove(xrayNew)
		// vor dem Neustart Zähler sichern übernimmt die Engine (Collect vor Apply)
		_, _ = sys.Run("systemctl", "enable", "xray")
		if _, err := sys.Run("systemctl", "restart", "xray"); err != nil {
			return fmt.Errorf("Xray neu starten: %w", err)
		}
		env.Log("info", "Xray-Konfiguration aktualisiert und neu gestartet")
	} else if _, err := sys.Run("systemctl", "is-active", "--quiet", "xray"); err != nil {
		_, _ = sys.Run("systemctl", "enable", "xray")
		if _, err := sys.Run("systemctl", "restart", "xray"); err != nil {
			return fmt.Errorf("Xray starten: %w", err)
		}
	}

	for _, id := range uids {
		env.Shape.Add(shaping.Rule{Key: fmt.Sprintf("vl-u%d", id), Egress: limited[id].up, Ingress: limited[id].down, Mark: uint32(markBase + id)})
	}
	return nil
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func orEmpty(r []map[string]any) []map[string]any {
	if r == nil {
		return []map[string]any{}
	}
	return r
}

func (Driver) Collect(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.Usage, error) {
	if len(layout(servers)) == 0 {
		return nil, nil
	}
	if _, err := env.Sys.Run("systemctl", "is-active", "--quiet", "xray"); err != nil {
		return nil, nil
	}
	out, err := env.Sys.Run("xray", "api", "statsquery", "--server="+env.Global.XrayAPI, "-pattern", "user>>>", "-reset")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("Xray-Statistik lesen: %w", err)
	}
	byEmail := map[string]*proto.Usage{}
	for _, s := range resp.Stat {
		f := strings.Split(s.Name, ">>>")
		if len(f) != 4 {
			continue
		}
		v, _ := strconv.ParseInt(strings.Trim(string(s.Value), `"`), 10, 64)
		u := byEmail[f[1]]
		if u == nil {
			u = &proto.Usage{}
			byEmail[f[1]] = u
		}
		if f[3] == "uplink" {
			u.Up += v
		} else {
			u.Down += v
		}
	}
	now := time.Now().Unix()
	res := map[int64]proto.Usage{}
	for _, sb := range servers {
		for _, pb := range sb.Peers {
			if u := byEmail[email(pb.Peer)]; u != nil {
				if u.Up+u.Down > 0 {
					u.Seen = now
				}
				res[pb.Peer.ID] = *u
			}
		}
	}
	return res, nil
}

func linkHost(env *proto.Env, c serverCfg) string {
	if c.Host != "" {
		return c.Host
	}
	return env.Global.ServerHost
}

func links(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []proto.Link {
	c := load(sb.Server)
	var out []proto.Link
	for _, t := range c.Targets {
		for _, sni := range t.ServerNames {
			q := url.Values{}
			q.Set("encryption", "none")
			if c.Flow != "" {
				q.Set("flow", c.Flow)
			}
			q.Set("security", "reality")
			q.Set("sni", sni)
			q.Set("fp", c.Fingerprint)
			q.Set("pbk", proto.Str(sb.Server.State, "public_key"))
			q.Set("sid", c.ShortIDs[0])
			q.Set("type", "tcp")
			q.Set("headerType", "none")
			label := fmt.Sprintf("%s - %s (%s)", sb.Server.Name, pb.Peer.Name, sni)
			u := fmt.Sprintf("vless://%s@%s:%d?%s#%s", proto.Str(pb.Peer.Secrets, "uuid"), linkHost(env, c), c.PublicPort, q.Encode(), url.PathEscape(label))
			out = append(out, proto.Link{Label: sni, URL: u})
		}
	}
	return out
}

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
	c := load(sb.Server)
	return &proto.ClientConfig{
		Title: "VLESS – " + sb.Server.Name,
		Links: links(env, sb, pb),
		Info: [][2]string{
			{"UUID", proto.Str(pb.Peer.Secrets, "uuid")},
			{"Server", fmt.Sprintf("%s:%d (TCP)", linkHost(env, c), c.PublicPort)},
			{"Public Key", proto.Str(sb.Server.State, "public_key")},
			{"Short-ID", c.ShortIDs[0]},
		},
		Instructions: []string{
			"Am einfachsten: den Abo-Link des Nutzers in v2RayTun (Android) oder Streisand/V2Box (iOS) importieren – dann kommen Änderungen automatisch.",
			"Alternativ einen einzelnen Link kopieren oder den QR-Code scannen.",
		},
	}, nil
}

func (Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	var out []string
	for _, l := range links(env, sb, pb) {
		out = append(out, l.URL)
	}
	return out
}

// SelfACL: VLESS teilt sich Port 443 mit Panel und Abo – die IP-Listen setzt Xray durch
// (Routing nach Quelladresse, die über das PROXY-Protocol von nginx bekannt ist).
func (Driver) SelfACL() bool { return true }

// aclRules stellt die Regeln der IP-Listen vor die übrigen Routing-Regeln.
func aclRules(env *proto.Env, ins []inbound, rules []map[string]any) []map[string]any {
	if len(env.Global.ACLs) == 0 {
		return rules
	}
	tags := map[int64][]string{}
	var ids []int64
	for _, in := range ins {
		id := in.sb.Server.ID
		if tags[id] == nil {
			ids = append(ids, id)
		}
		tags[id] = append(tags[id], in.tag)
	}
	strs := func(p []netip.Prefix) []string {
		out := make([]string, len(p))
		for i, x := range p {
			out[i] = x.String()
		}
		return out
	}
	var out []map[string]any
	for _, id := range ids {
		a := env.Global.ACLs[id]
		if a == nil {
			continue
		}
		if len(a.Deny) > 0 {
			out = append(out, map[string]any{"type": "field", "inboundTag": tags[id], "source": strs(a.Deny), "outboundTag": "block"})
		}
		if !a.AllowOnly {
			continue
		}
		if len(a.Allow) > 0 {
			allow := strs(a.Allow)
			for _, r := range rules { // Drosselung gilt auch für freigegebene Adressen
				c := map[string]any{}
				for k, v := range r {
					c[k] = v
				}
				c["inboundTag"], c["source"] = tags[id], allow
				out = append(out, c)
			}
			out = append(out, map[string]any{"type": "field", "inboundTag": tags[id], "source": allow, "outboundTag": "direct"})
		}
		out = append(out, map[string]any{"type": "field", "inboundTag": tags[id], "outboundTag": "block"})
	}
	return append(out, rules...)
}

func (Driver) Ports(srv *store.Server) []proto.Port {
	c := load(srv)
	return []proto.Port{{Port: c.PublicPort, Proto: "tcp", Note: "nginx (SNI-Verteiler)"}}
}

func (Driver) Status(env *proto.Env, srv *store.Server) proto.Status {
	if !srv.Enabled {
		return proto.Status{Detail: "deaktiviert"}
	}
	if env.Sys.DryRun() {
		return proto.Status{Running: true, Detail: "Xray (Testmodus)"}
	}
	if _, err := env.Sys.Run("systemctl", "is-active", "--quiet", "xray"); err != nil {
		return proto.Status{Detail: "Xray läuft nicht"}
	}
	out, _ := env.Sys.Run("xray", "version")
	v := strings.Fields(out)
	if len(v) >= 2 {
		return proto.Status{Running: true, Detail: "Xray " + v[1]}
	}
	return proto.Status{Running: true, Detail: "Xray läuft"}
}

// ImportKeys übernimmt vorhandene Reality-Schlüssel (Migration).
func ImportKeys(srv *store.Server, priv, pub, sid string) error {
	if _, err := base64.RawURLEncoding.DecodeString(priv); err != nil {
		return fmt.Errorf("ungültiger Reality-Schlüssel")
	}
	srv.State["private_key"] = priv
	srv.State["public_key"] = pub
	if sid != "" {
		srv.Settings["short_ids"] = []string{sid}
	}
	return nil
}

// Live: Xray-Zähler ohne Zurücksetzen (Collect setzt sie alle paar Sekunden/Minuten zurück –
// die Engine erkennt das am fallenden Zähler).
func (Driver) Live(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.LiveSample, error) {
	if len(layout(servers)) == 0 {
		return nil, nil
	}
	out, err := env.Sys.Run("xray", "api", "statsquery", "--server="+env.Global.XrayAPI, "-pattern", "user>>>")
	if err != nil || strings.TrimSpace(out) == "" {
		return nil, err
	}
	var resp struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("Xray-Statistik lesen: %w", err)
	}
	byEmail := map[string]*proto.LiveSample{}
	for _, s := range resp.Stat {
		f := strings.Split(s.Name, ">>>")
		if len(f) != 4 {
			continue
		}
		v, _ := strconv.ParseInt(strings.Trim(string(s.Value), `"`), 10, 64)
		u := byEmail[f[1]]
		if u == nil {
			u = &proto.LiveSample{}
			byEmail[f[1]] = u
		}
		if f[3] == "uplink" {
			u.Up += v
		} else {
			u.Down += v
		}
	}
	// Verbundene Client-Adressen (echte IPs dank PROXY-Protocol von nginx)
	ips := onlineIPs(env)
	res := map[int64]proto.LiveSample{}
	for _, sb := range servers {
		for _, pb := range sb.Peers {
			u, ip := byEmail[email(pb.Peer)], ips[email(pb.Peer)]
			if u == nil && ip == "" {
				continue
			}
			s := proto.LiveSample{}
			if u != nil {
				s = *u
			}
			if ip != "" {
				s.Endpoint, s.Online = ip, true
			}
			res[pb.Peer.ID] = s
		}
	}
	return res, nil
}

// onlineIPs: E-Mail → zuletzt gesehene Client-Adresse laut Xray (leer, wenn Xray das nicht kann).
func onlineIPs(env *proto.Env) map[string]string {
	out, err := env.Sys.Run("xray", "api", "statsonlineiplist", "--server="+env.Global.XrayAPI, "-all")
	if err != nil {
		return nil
	}
	return parseOnlineIPs(out)
}

func parseOnlineIPs(out string) map[string]string {
	var resp struct {
		Users []struct {
			Email string `json:"email"`
			IPs   []struct {
				IP       string `json:"ip"`
				LastSeen int64  `json:"lastSeen"`
			} `json:"ips"`
		} `json:"users"`
	}
	if json.Unmarshal([]byte(out), &resp) != nil {
		return nil
	}
	res := map[string]string{}
	for _, u := range resp.Users {
		var best int64 = -1
		for _, ip := range u.IPs {
			if ip.IP != "" && ip.LastSeen > best {
				best, res[u.Email] = ip.LastSeen, ip.IP
			}
		}
	}
	return res
}
