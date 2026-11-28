package hysteria2

// Statistik (trafficStats) sowie Links und Client-Konfiguration.

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// ---------- Statistik ----------

func (Driver) Collect(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.Usage, error) {
	if env.Sys.DryRun() {
		return nil, nil
	}
	res := map[int64]proto.Usage{}
	now := time.Now().Unix()
	var errs []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		// tx = vom Client gesendet (Upload), rx = an den Client (Download)
		var traffic map[string]struct{ Tx, Rx int64 }
		if err := statsCall(sb.Server, "GET", "/traffic?clear=1", nil, &traffic); err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
			continue
		}
		var online map[string]int
		_ = statsCall(sb.Server, "GET", "/online", nil, &online)
		on := map[int64]bool{}
		var ids []int64
		for _, pb := range sb.Peers {
			id := peerID(pb.Peer)
			ids = append(ids, pb.Peer.ID)
			u := proto.Usage{}
			if t, ok := traffic[id]; ok {
				u.Up, u.Down = t.Tx, t.Rx
			}
			if online[id] > 0 {
				on[pb.Peer.ID] = true
				u.Seen = now
			} else if u.Up+u.Down > 0 {
				u.Seen = now
			}
			if u.Up+u.Down > 0 || u.Seen > 0 {
				res[pb.Peer.ID] = u
			}
		}
		forget(on, ids)
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return res, nil
}

// ---------- Links und Konfiguration ----------

// link: hysteria2://-Link. singbox=true: Port-Hopping-Bereich im Host-Teil
// („host:443,20000-50000“, so liest es Hiddify/sing-box), sonst als mport-Parameter
// (v2rayN, NekoBox; Apps ohne Unterstützung nutzen einfach den normalen Port).
func link(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle, singbox bool) string {
	c := load(sb.Server)
	ports := strconv.Itoa(c.Port)
	q := url.Values{}
	q.Set("sni", sniOf(env, c))
	if c.CertFile == "" {
		q.Set("insecure", "1")
		q.Set("pinSHA256", proto.Str(sb.Server.State, "cert_sha256"))
	}
	if f, t, err := hopRange(c.HopPorts); err == nil && f > 0 {
		if singbox {
			ports = fmt.Sprintf("%d,%d-%d", c.Port, f, t)
		} else {
			q.Set("mport", fmt.Sprintf("%d-%d", f, t))
		}
	}
	if c.Obfs {
		q.Set("obfs", "salamander")
		q.Set("obfs-password", proto.Str(sb.Server.State, "obfs_password"))
	}
	label := sb.Server.Name + " - " + pb.Peer.Name
	return fmt.Sprintf("hysteria2://%s@%s:%s/?%s#%s", url.PathEscape(proto.Str(pb.Peer.Secrets, "password")),
		linkHost(env, c), ports, q.Encode(), url.PathEscape(oneLine(label)))
}

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
	c := load(sb.Server)
	host := fmt.Sprintf("%s:%d", linkHost(env, c), c.Port)
	hopFrom, hopTo, _ := hopRange(c.HopPorts)
	server := host
	if hopFrom > 0 {
		server = fmt.Sprintf("%s:%d-%d", linkHost(env, c), hopFrom, hopTo)
	}
	var y strings.Builder
	fmt.Fprintf(&y, "# Hysteria2 – %s (%s)\nserver: %s\nauth: %s\ntls:\n  sni: %s\n", oneLine(sb.Server.Name), oneLine(pb.User.Name), server,
		proto.Str(pb.Peer.Secrets, "password"), sniOf(env, c))
	if c.CertFile == "" {
		fmt.Fprintf(&y, "  insecure: true\n  pinSHA256: %s\n", proto.Str(sb.Server.State, "cert_sha256"))
	}
	if c.Obfs {
		fmt.Fprintf(&y, "obfs:\n  type: salamander\n  salamander:\n    password: %s\n", proto.Str(sb.Server.State, "obfs_password"))
	}
	if hopFrom > 0 {
		fmt.Fprintf(&y, "transport:\n  udp:\n    hopInterval: %ds\n", c.HopInterval)
	}
	y.WriteString("socks5:\n  listen: 127.0.0.1:1080\nhttp:\n  listen: 127.0.0.1:8080\n")
	links := []proto.Link{{Label: "Hysteria2", URL: link(env, sb, pb, false)}}
	if hopFrom > 0 {
		links = []proto.Link{
			// zuerst das Format, das (fast) jede App lesen kann; Hiddify nutzt dabei nur den Hauptport
			{Label: "v2rayNG, v2RayTun, NekoBox & Co.", URL: link(env, sb, pb, false)},
			{Label: "Hiddify / sing-box (mit Port-Hopping)", URL: link(env, sb, pb, true)},
		}
	}
	info := [][2]string{
		{"Server", server + " (UDP)"},
		{"Passwort", proto.Str(pb.Peer.Secrets, "password")},
		{"SNI", sniOf(env, c)},
	}
	if c.CertFile == "" {
		info = append(info, [2]string{"Zertifikat (SHA-256)", proto.Str(sb.Server.State, "cert_sha256")})
	}
	return &proto.ClientConfig{
		Title: "Hysteria2 – " + sb.Server.Name,
		Links: links,
		Files: []proto.File{{Name: "hysteria-" + safeName(pb.User.Name) + ".yaml", Content: y.String()}},
		Info:  info,
		Instructions: []string{
			"Am einfachsten: den Abo-Link des Nutzers importieren (v2RayTun, Hiddify, NekoBox, Streisand) – dann kommen Änderungen automatisch.",
			"Alternativ den hysteria2://-Link kopieren oder den QR-Code scannen.",
			"Die Datei ist für den offiziellen Hysteria-Client (hysteria client -c datei.yaml).",
			"Das Zertifikat ist selbst erzeugt; die Links prüfen es über den Fingerabdruck (pinSHA256).",
		},
	}, nil
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}

func safeName(s string) string {
	return regexp.MustCompile(`[^A-Za-z0-9_-]+`).ReplaceAllString(s, "_")
}

func (Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	return []string{link(env, sb, pb, env.Global.Client == "singbox")}
}

// SingBox: hysteria2-Ausgang für das sing-box-Profil. Das selbst erzeugte Zertifikat wird
// mitgeliefert und damit richtig geprüft (kein „insecure“ nötig).
func (Driver) SingBox(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (map[string]any, map[string]any) {
	if !pb.Active {
		return nil, nil
	}
	c := load(sb.Server)
	t := map[string]any{"enabled": true, "server_name": sniOf(env, c)}
	if c.CertFile == "" {
		pem := proto.Str(sb.Server.State, "cert_pem")
		if pem == "" {
			return nil, nil
		}
		t["certificate"] = strings.TrimSpace(pem)
	}
	o := map[string]any{"type": "hysteria2", "server": strings.Trim(linkHost(env, c), "[]"),
		"password": proto.Str(pb.Peer.Secrets, "password"), "tls": t}
	if f, to, err := hopRange(c.HopPorts); err == nil && f > 0 {
		// server_ports ersetzt server_port: Hauptport plus Hopping-Bereich
		iv := c.HopInterval
		if iv <= 0 {
			iv = 30
		}
		o["server_ports"] = []string{fmt.Sprintf("%d:%d", c.Port, c.Port), fmt.Sprintf("%d:%d", f, to)}
		o["hop_interval"] = fmt.Sprintf("%ds", iv)
	} else {
		o["server_port"] = c.Port
	}
	if c.Obfs {
		o["obfs"] = map[string]any{"type": "salamander", "password": proto.Str(sb.Server.State, "obfs_password")}
	}
	return o, nil
}

func (Driver) Ports(srv *store.Server) []proto.Port {
	c := load(srv)
	out := []proto.Port{{Port: c.Port, Proto: "udp", Note: "Hysteria2 " + srv.Name}}
	if f, t, err := hopRange(c.HopPorts); err == nil && f > 0 {
		out = append(out, proto.Port{Port: f, To: t, Proto: "udp", Note: "Hysteria2 Port-Hopping " + srv.Name})
	}
	return out
}

// hopRange: „20000-50000“ → 20000, 50000 (leer → 0, 0).
func hopRange(v string) (from, to int, err error) {
	v = strings.TrimSpace(strings.ReplaceAll(v, ":", "-"))
	if v == "" {
		return 0, 0, nil
	}
	a, b, ok := strings.Cut(v, "-")
	from, err1 := strconv.Atoi(strings.TrimSpace(a))
	to, err2 := strconv.Atoi(strings.TrimSpace(b))
	if !ok || err1 != nil || err2 != nil || from < 1024 || to > 65535 || to <= from {
		return 0, 0, fmt.Errorf("Port-Hopping: bitte einen Bereich wie 20000-50000 (1024–65535)")
	}
	return from, to, nil
}

func (Driver) Status(env *proto.Env, srv *store.Server) proto.Status {
	if !srv.Enabled {
		return proto.Status{Detail: "deaktiviert"}
	}
	if env.Sys.DryRun() {
		return proto.Status{Running: true, Detail: name(srv) + " (Testmodus)"}
	}
	if _, err := env.Sys.Run("systemctl", "is-active", "--quiet", "vpn-hysteria@"+name(srv)); err != nil {
		return proto.Status{Detail: "Hysteria2 läuft nicht"}
	}
	return proto.Status{Running: true, Detail: fmt.Sprintf("Hysteria2 auf UDP %d", load(srv).Port)}
}

func idle(s int) int {
	if s < 4 || s > 120 {
		return 60
	}
	return s
}

// Live: trafficStats ohne Zurücksetzen plus Liste der verbundenen Zugänge.
func (Driver) Live(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.LiveSample, error) {
	if env.Sys.DryRun() {
		return nil, nil
	}
	res := map[int64]proto.LiveSample{}
	var errs []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		var traffic map[string]struct{ Tx, Rx int64 }
		if err := statsCall(sb.Server, "GET", "/traffic", nil, &traffic); err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
			continue
		}
		var online map[string]int
		_ = statsCall(sb.Server, "GET", "/online", nil, &online)
		for _, pb := range sb.Peers {
			id := peerID(pb.Peer)
			t, ok := traffic[id]
			if ok || online[id] > 0 {
				s := proto.LiveSample{Up: t.Tx, Down: t.Rx, Online: online[id] > 0}
				if s.Online {
					s.Endpoint = lastAddr(pb.Peer.ID)
				}
				res[pb.Peer.ID] = s
			}
		}
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return res, nil
}

// applyHopping: Port-Hopping – eingehende UDP-Pakete im Bereich auf den Port der Instanz
// umleiten (iptables/ip6tables REDIRECT, eigene Kette VPNHY in der nat-Tabelle).
func applyHopping(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	dev := env.Global.OutIf
	if dev == "" {
		dev = "eth0"
	}
	var rules []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		c := load(sb.Server)
		if f, t, err := hopRange(c.HopPorts); err == nil && f > 0 {
			rules = append(rules, fmt.Sprintf("-A VPNHY -i %s -p udp -m udp --dport %d:%d -j REDIRECT --to-ports %d", dev, f, t, c.Port))
		}
	}
	sort.Strings(rules)
	// immer setzen (billig) – nach einem Neustart des Containers sind die Regeln weg
	sig := strings.Join(rules, "\n")
	changed := env.GetState("hy:hop") != sig
	if !changed && len(rules) == 0 {
		return nil
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if len(rules) == 0 {
			_, _ = sys.Run(bin, "-t", "nat", "-D", "PREROUTING", "-j", "VPNHY")
			_, _ = sys.Run(bin, "-t", "nat", "-F", "VPNHY")
			_, _ = sys.Run(bin, "-t", "nat", "-X", "VPNHY")
			continue
		}
		rs := "*nat\n:VPNHY - [0:0]\n-F VPNHY\n" + strings.Join(rules, "\n") + "\nCOMMIT\n"
		if _, err := sys.RunInput(rs, bin+"-restore", "-n"); err != nil {
			return fmt.Errorf("%s: %w", bin, err)
		}
		if _, err := sys.Run(bin, "-t", "nat", "-C", "PREROUTING", "-j", "VPNHY"); err != nil {
			if _, err := sys.Run(bin, "-t", "nat", "-I", "PREROUTING", "-j", "VPNHY"); err != nil {
				return fmt.Errorf("%s: %w", bin, err)
			}
		}
	}
	env.SetState("hy:hop", sig)
	if changed && len(rules) > 0 {
		env.Log("info", fmt.Sprintf("Hysteria2 Port-Hopping aktiv (%d Bereich(e))", len(rules)))
	}
	return nil
}
