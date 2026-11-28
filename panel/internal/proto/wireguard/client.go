package wireguard

// Statistik und Client-Konfiguration (Config-Datei, QR, Links).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// ---------- Statistik ----------

func (Driver) Collect(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.Usage, error) {
	out, err := env.Sys.Run("wg", "show", "all", "dump")
	if err != nil {
		return nil, err
	}
	type row struct {
		rx, tx, hs int64
		ep         string
	}
	rows := map[string]row{} // iface|pubkey
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 9 {
			continue
		}
		hs, _ := strconv.ParseInt(f[5], 10, 64)
		rx, _ := strconv.ParseInt(f[6], 10, 64)
		tx, _ := strconv.ParseInt(f[7], 10, 64)
		ep := f[3]
		if ep == "(none)" {
			ep = ""
		}
		rows[f[0]+"|"+f[1]] = row{rx, tx, hs, ep}
	}
	res := map[int64]proto.Usage{}
	for _, sb := range servers {
		sc := load(sb.Server)
		for _, pb := range sb.Peers {
			p := pb.Peer
			r, ok := rows[sc.Interface+"|"+proto.Str(p.Secrets, "public_key")]
			if !ok {
				p.LastRx, p.LastTx = 0, 0
				continue
			}
			du := r.rx - p.LastRx // rx am Server = Upload des Geräts
			if r.rx < p.LastRx {
				du = r.rx
			}
			dd := r.tx - p.LastTx
			if r.tx < p.LastTx {
				dd = r.tx
			}
			p.LastRx, p.LastTx = r.rx, r.tx
			res[p.ID] = proto.Usage{Up: du, Down: dd, Seen: r.hs, Handshake: r.hs, Endpoint: r.ep}
		}
	}
	return res, nil
}

// ---------- Client-Konfiguration ----------

func endpointHost(env *proto.Env, sc serverCfg) string {
	h := sc.Endpoint
	if h == "" {
		h = env.Global.ServerHost
	}
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") && strings.Count(h, ":") > 1 {
		h = "[" + h + "]"
	}
	return h
}

// clientParams: gemeinsame Werte für Config-Datei, Link und sing-box-Profil eines Geräts.
type clientParams struct {
	sc             serverCfg
	all            []*node
	me             *node
	c              peerCfg
	addrs, allowed []string
	reach          []*node
	dns            string
	mtu, ka        int
}

// oldDefaultDNS: Vorgabe bis v0.9 – gilt wie „auto“, damit bestehende Server den Panel-DNS bekommen.
const oldDefaultDNS = "1.1.1.1, 2606:4700:4700::1111"

// deviceDNS: DNS-Server für Geräte. „auto“: Tunneladressen des Servers (dort antwortet der Panel-DNS),
// ohne Panel-DNS die frühere Vorgabe.
func deviceDNS(env *proto.Env, sc serverCfg, dns string) string {
	if dns != "auto" && dns != oldDefaultDNS {
		return dns
	}
	if env == nil || !env.Global.PanelDNS {
		return oldDefaultDNS
	}
	n4, err := parsePrefix(sc.Net4)
	if err != nil {
		return oldDefaultDNS
	}
	a4, _ := addrAt(n4, 1)
	out := a4.String()
	if sc.Net6 != "" {
		if n6, err := parsePrefix(sc.Net6); err == nil {
			if a6, err := addrAt(n6, 1); err == nil {
				out += ", " + a6.String()
			}
		}
	}
	return out
}

func params(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*clientParams, error) {
	sc := load(sb.Server)
	all := nodes(sb, false)
	var me *node
	for _, n := range all {
		if n.pb.Peer.ID == pb.Peer.ID {
			me = n
		}
	}
	if me == nil {
		return nil, fmt.Errorf("Gerät nicht gefunden")
	}
	c := me.cfg
	var addrs []string
	if c.Address4 != "" {
		addrs = append(addrs, c.Address4+"/32")
	}
	if c.Address6 != "" {
		addrs = append(addrs, c.Address6+"/128")
	}
	// Was schickt das Gerät in den Tunnel?
	var allowed []string
	reach := reachable(sc, me, all)
	if c.Tunnel == "full" {
		allowed = []string{"0.0.0.0/0"}
		if sc.Net6 != "" {
			allowed = append(allowed, "::/0")
		}
	} else {
		allowed = append(allowed, sc.Net4)
		if sc.Net6 != "" {
			allowed = append(allowed, sc.Net6)
		}
		for _, t := range reach {
			for _, r := range t.routes {
				allowed = append(allowed, r.String())
			}
		}
		// freigegebene Netze (Netzwerk → Zugriff)
		have := map[string]bool{}
		for _, a := range allowed {
			have[a] = true
		}
		for _, t := range netTargets(env, pb.Peer.ID) {
			for _, r := range t.Nets {
				if !have[r.String()] {
					have[r.String()] = true
					allowed = append(allowed, r.String())
				}
			}
		}
	}
	allowed = append(allowed, c.ExtraAllowed...)
	dns := c.DNS
	if dns == "" {
		dns = sc.DNS
	}
	if dns == "none" {
		dns = ""
	} else {
		dns = deviceDNS(env, sc, dns)
	}
	mtu := c.MTU
	if mtu == 0 {
		mtu = sc.MTU
	}
	ka := c.Keepalive
	if ka == 0 {
		ka = sc.Keepalive
	}
	return &clientParams{sc: sc, all: all, me: me, c: c, addrs: addrs, allowed: allowed, reach: reach, dns: dns, mtu: mtu, ka: ka}, nil
}

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
	cp, err := params(env, sb, pb)
	if err != nil {
		return nil, err
	}
	sc, all, me, c, addrs, allowed, reach, dns, mtu, ka := cp.sc, cp.all, cp.me, cp.c, cp.addrs, cp.allowed, cp.reach, cp.dns, cp.mtu, cp.ka

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n# %s – %s (%s)\nPrivateKey = %s\nAddress = %s\n", oneLine(sb.Server.Name), oneLine(pb.Peer.Name), oneLine(pb.User.Name),
		proto.Str(pb.Peer.Secrets, "private_key"), strings.Join(addrs, ", "))
	if dns != "" && pb.Peer.Kind == "client" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	if mtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", mtu)
	}
	if pb.Peer.Kind == "site" {
		// Weiterleitung ins Heimnetz einschalten; optional NAT, damit der Router keine Rückroute braucht
		lan := c.LANInterface
		up := []string{"sysctl -w net.ipv4.ip_forward=1", "iptables -A FORWARD -i %i -j ACCEPT", "iptables -A FORWARD -o %i -j ACCEPT"}
		down := []string{"iptables -D FORWARD -i %i -j ACCEPT", "iptables -D FORWARD -o %i -j ACCEPT"}
		if c.Address6 != "" {
			up = append(up, "sysctl -w net.ipv6.conf.all.forwarding=1", "ip6tables -A FORWARD -i %i -j ACCEPT", "ip6tables -A FORWARD -o %i -j ACCEPT")
			down = append(down, "ip6tables -D FORWARD -i %i -j ACCEPT", "ip6tables -D FORWARD -o %i -j ACCEPT")
		}
		if c.LANNat {
			srcs := []string{sc.Net4}
			for _, n := range all {
				if n != me {
					for _, r := range n.routes {
						if r.Addr().Is4() {
							srcs = append(srcs, r.String())
						}
					}
				}
			}
			for _, s := range srcs {
				up = append(up, fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", s, lan))
				down = append(down, fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", s, lan))
			}
			if sc.Net6 != "" {
				up = append(up, fmt.Sprintf("ip6tables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", sc.Net6, lan))
				down = append(down, fmt.Sprintf("ip6tables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", sc.Net6, lan))
			}
		}
		fmt.Fprintf(&b, "PostUp = %s\nPostDown = %s\n", strings.Join(up, "; "), strings.Join(down, "; "))
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s:%d\nAllowedIPs = %s\n",
		proto.Str(sb.Server.State, "public_key"), proto.Str(pb.Peer.Secrets, "psk"), endpointHost(env, sc), sc.Port, strings.Join(allowed, ", "))
	if ka > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
	}

	fname := sanitize(pb.Peer.Name)
	cc := &proto.ClientConfig{
		Title: "WireGuard – " + pb.Peer.Name,
		Files: []proto.File{{Name: fname + ".conf", Content: b.String(), QR: pb.Peer.Kind == "client"}},
		Info: [][2]string{
			{"Adresse im Tunnel", strings.Join(addrs, ", ")},
			{"Server", fmt.Sprintf("%s:%d (UDP)", endpointHost(env, sc), sc.Port)},
			{"Tunnel", map[string]string{"full": "Voll (gesamter Verkehr)", "split": "Geteilt (nur VPN-Netze)"}[c.Tunnel]},
		},
	}
	if len(me.routes) > 0 {
		cc.Info = append(cc.Info, [2]string{"Netze hinter dem Gerät", joinPrefixes(me.routes)})
	}
	var rn []string
	for _, t := range reach {
		rn = append(rn, t.pb.Peer.Name)
	}
	if len(rn) > 0 {
		cc.Info = append(cc.Info, [2]string{"Erreicht", strings.Join(rn, ", ")})
	}
	var tn []string
	for _, t := range netTargets(env, pb.Peer.ID) {
		tn = append(tn, t.Name)
	}
	if len(tn) > 0 {
		cc.Info = append(cc.Info, [2]string{"Zugriff auf Netze", strings.Join(tn, ", ")})
	}
	switch pb.Peer.Kind {
	case "client":
		cc.Links = []proto.Link{{Label: "Hiddify / v2rayNG", URL: shareLink(env, sc, sb, pb, c, addrs, allowed, ka)}}
		cc.Instructions = []string{
			"WireGuard-App (Android, iOS, Windows, macOS): „+“ → „QR-Code scannen“ (Konfiguration) oder die Datei importieren.",
			"Hiddify, v2rayNG, v2rayN & Co.: den QR-Code des wireguard://-Links scannen oder den Link kopieren und einfügen – er steckt auch im Abo.",
			"v2RayTun: am einfachsten über das Abo (WireGuard kommt dort automatisch passend an). Apps, die den Link nicht annehmen: die Konfiguration (.conf) als Datei oder Text importieren.",
			"Denselben Zugang nicht gleichzeitig in zwei Apps verbinden – für jedes Gerät/jede App einen eigenen Zugang anlegen.",
		}
	default:
		ifn := "wg-" + fname
		if len(ifn) > 15 {
			ifn = ifn[:15]
		}
		cc.Files[0].Name = ifn + ".conf"
		cc.Instructions = []string{
			"Auf dem Gerät (Debian/Ubuntu/Proxmox): apt install wireguard-tools iptables",
			fmt.Sprintf("Die Konfiguration als /etc/wireguard/%s.conf speichern (chmod 600).", ifn),
			fmt.Sprintf("Starten und beim Booten aktivieren: systemctl enable --now wg-quick@%s", ifn),
		}
		if pb.Peer.Kind == "site" {
			cc.Instructions = append(cc.Instructions,
				"Das Gerät leitet dann Anfragen aus dem VPN in sein lokales Netz weiter.",
				"Ohne „NAT ins lokale Netz“: im Heimrouter eine Route für "+sc.Net4+" über die LAN-IP dieses Geräts eintragen.")
		}
	}
	return cc, nil
}

var nameRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitize(s string) string {
	s = nameRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "wireguard"
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

// ShareLinks: Geräte der Art „Handy / Laptop“ kommen als wireguard://-Link ins Abo
// (Hiddify, v2rayN). Server und Homelabs laufen mit wg-quick und brauchen das nicht.
func (d Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	if pb.Peer.Kind != "client" || !pb.Active {
		return nil
	}
	if env.Global.Client == "v2raytun" {
		// v2RayTun liest keine wireguard://-Links aus dem Abo, nimmt aber Xray-JSON-Zeilen an
		if j := xrayJSON(env, sb, pb); j != "" {
			return []string{j}
		}
		return nil
	}
	cc, err := d.ClientConfig(env, sb, pb)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range cc.Links {
		out = append(out, l.URL)
	}
	return out
}

// shareLink: wireguard://<privater Schlüssel>@host:port?… – Format von v2rayN/Hiddify
// (ray2sing: publickey, presharedkey, address, mtu, keepalive, allowedips).
func shareLink(env *proto.Env, sc serverCfg, sb *proto.ServerBundle, pb *proto.PeerBundle, c peerCfg, addrs, allowed []string, ka int) string {
	q := url.Values{}
	q.Set("publickey", proto.Str(sb.Server.State, "public_key"))
	q.Set("presharedkey", proto.Str(pb.Peer.Secrets, "psk"))
	q.Set("address", strings.Join(addrs, ","))
	mtu := c.MTU
	if mtu == 0 {
		mtu = sc.MTU
	}
	if mtu == 0 {
		mtu = 1280 // Mobilfunk-tauglich; die Apps nehmen sonst sehr unterschiedliche Vorgaben
	}
	q.Set("mtu", strconv.Itoa(mtu))
	if ka > 0 {
		q.Set("keepalive", strconv.Itoa(ka))
	}
	if c.Tunnel != "full" {
		q.Set("allowedips", strings.Join(allowed, ","))
	}
	u := url.URL{Scheme: "wireguard", Host: fmt.Sprintf("%s:%d", endpointHost(env, sc), sc.Port),
		Path: "/", RawQuery: q.Encode(), Fragment: oneLine(sb.Server.Name + " - " + pb.Peer.Name)}
	// Privater Schlüssel vollständig kodiert (+ / = als %2B %2F %3D), so wie v2rayNG ihn selbst
	// exportiert – url.User ließe „+“ und „=“ stehen, was manche Apps falsch lesen.
	key := url.QueryEscape(proto.Str(pb.Peer.Secrets, "private_key"))
	return "wireguard://" + key + "@" + strings.TrimPrefix(u.String(), "wireguard://")
}

// xrayJSON: vollständige Xray-Konfiguration (eine Zeile) mit WireGuard-Ausgang, für Apps wie
// v2RayTun, die Xray-JSON im Abo verstehen, aber keine wireguard://-Links. Beim geteilten
// Tunnel gehen nur die Netze des WireGuard-Servers durch den Tunnel, der Rest direkt.
func xrayJSON(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) string {
	cp, err := params(env, sb, pb)
	if err != nil {
		return ""
	}
	mtu := cp.mtu
	if mtu == 0 {
		mtu = 1280
	}
	peer := map[string]any{
		"publicKey":  proto.Str(sb.Server.State, "public_key"),
		"endpoint":   fmt.Sprintf("%s:%d", endpointHost(env, cp.sc), cp.sc.Port),
		"allowedIPs": []string{"0.0.0.0/0", "::/0"},
	}
	if psk := proto.Str(pb.Peer.Secrets, "psk"); psk != "" {
		peer["preSharedKey"] = psk
	}
	if cp.ka > 0 {
		peer["keepAlive"] = cp.ka
	}
	wg := map[string]any{"tag": "proxy", "protocol": "wireguard", "settings": map[string]any{
		"secretKey": proto.Str(pb.Peer.Secrets, "private_key"), "address": cp.addrs, "mtu": mtu,
		"peers": []any{peer}}}
	direct := map[string]any{"tag": "direct", "protocol": "freedom"}
	outbounds := []any{wg, direct} // der erste Ausgang ist der Standard
	routing := map[string]any{"domainStrategy": "AsIs"}
	if cp.c.Tunnel != "full" {
		outbounds = []any{direct, wg}
		routing["rules"] = []any{map[string]any{"type": "field", "ip": cp.allowed, "outboundTag": "proxy"}}
	}
	cfg := map[string]any{
		"remarks": oneLine(sb.Server.Name + " - " + pb.Peer.Name),
		"log":     map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
			"settings": map[string]any{"udp": true}, "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}}}},
		"outbounds": outbounds,
		"routing":   routing,
	}
	if cp.dns != "" {
		var servers []string
		for _, s := range strings.Split(cp.dns, ",") {
			if s = strings.TrimSpace(s); s != "" {
				servers = append(servers, s)
			}
		}
		if len(servers) > 0 {
			cfg["dns"] = map[string]any{"servers": servers}
		}
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	return string(b)
}

// SingBox: WireGuard-Endpunkt für das sing-box-Profil. Nur Geräte „Handy / Laptop“ mit vollem
// Tunnel – das Profil schickt den gesamten Verkehr über den gewählten Server.
func (Driver) SingBox(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (map[string]any, map[string]any) {
	if pb.Peer.Kind != "client" || !pb.Active {
		return nil, nil
	}
	cp, err := params(env, sb, pb)
	if err != nil || cp.c.Tunnel != "full" {
		return nil, nil
	}
	mtu := cp.mtu
	if mtu == 0 {
		mtu = 1280
	}
	peer := map[string]any{
		"address":     strings.Trim(endpointHost(env, cp.sc), "[]"),
		"port":        cp.sc.Port,
		"public_key":  proto.Str(sb.Server.State, "public_key"),
		"allowed_ips": []string{"0.0.0.0/0", "::/0"},
	}
	if psk := proto.Str(pb.Peer.Secrets, "psk"); psk != "" {
		peer["pre_shared_key"] = psk
	}
	if cp.ka > 0 {
		peer["persistent_keepalive_interval"] = cp.ka
	}
	return nil, map[string]any{"type": "wireguard", "mtu": mtu, "address": cp.addrs,
		"private_key": proto.Str(pb.Peer.Secrets, "private_key"), "peers": []any{peer}}
}

func (Driver) Ports(srv *store.Server) []proto.Port {
	sc := load(srv)
	return []proto.Port{{Port: sc.Port, Proto: "udp", Note: "WireGuard " + sc.Interface}}
}

func (Driver) Status(env *proto.Env, srv *store.Server) proto.Status {
	sc := load(srv)
	if !srv.Enabled {
		return proto.Status{Running: false, Detail: "deaktiviert"}
	}
	if env.Sys.DryRun() {
		return proto.Status{Running: true, Detail: sc.Interface + " (Testmodus)"}
	}
	out, err := env.Sys.Run("wg", "show", sc.Interface, "latest-handshakes")
	if err != nil {
		return proto.Status{Running: false, Detail: sc.Interface + " läuft nicht"}
	}
	online := 0
	cut := time.Now().Add(-3 * time.Minute).Unix()
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if ts, _ := strconv.ParseInt(f[1], 10, 64); ts > cut {
				online++
			}
		}
	}
	return proto.Status{Running: true, Detail: fmt.Sprintf("%s, %d verbunden", sc.Interface, online)}
}

// PublicKey für die Oberfläche.
func PublicKey(srv *store.Server) string { return proto.Str(srv.State, "public_key") }

// ImportKey übernimmt einen vorhandenen privaten Schlüssel (Migration).
func ImportKey(srv *store.Server, privB64 string) error {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(priv) != 32 {
		return fmt.Errorf("ungültiger WireGuard-Schlüssel")
	}
	pub, err := proto.PubFromPriv(priv)
	if err != nil {
		return err
	}
	srv.State["private_key"] = proto.B64(priv)
	srv.State["public_key"] = proto.B64(pub)
	return nil
}

// Live: Zählerstände aus „wg show all dump“ (ohne etwas zurückzusetzen).
func (Driver) Live(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.LiveSample, error) {
	out, err := env.Sys.Run("wg", "show", "all", "dump")
	if err != nil {
		return nil, err
	}
	type row struct {
		rx, tx, hs int64
		ep         string
	}
	rows := map[string]row{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 9 {
			continue
		}
		hs, _ := strconv.ParseInt(f[5], 10, 64)
		rx, _ := strconv.ParseInt(f[6], 10, 64)
		tx, _ := strconv.ParseInt(f[7], 10, 64)
		ep := f[3]
		if ep == "(none)" {
			ep = ""
		}
		rows[f[0]+"|"+f[1]] = row{rx, tx, hs, ep}
	}
	now := time.Now().Unix()
	res := map[int64]proto.LiveSample{}
	for _, sb := range servers {
		sc := load(sb.Server)
		for _, pb := range sb.Peers {
			if r, ok := rows[sc.Interface+"|"+proto.Str(pb.Peer.Secrets, "public_key")]; ok {
				// rx am Server = Upload des Geräts; online = Handshake in den letzten 3 Minuten
				res[pb.Peer.ID] = proto.LiveSample{Up: r.rx, Down: r.tx, Online: r.hs > 0 && now-r.hs < 180, Endpoint: r.ep}
			}
		}
	}
	return res, nil
}

// netTargets: freigegebene Netze eines Zugangs (env darf nil sein).
func netTargets(env *proto.Env, peer int64) []proto.NetTarget {
	if env == nil {
		return nil
	}
	return env.Global.Net.For(peer)
}

// Network: Schnittstelle und Netze dieses Servers (Tunnelnetz und Netze hinter aktiven Geräten) –
// Ziel für Freigaben unter Netzwerk → Zugriff.
func (Driver) Network(sb *proto.ServerBundle) (string, []netip.Prefix) {
	sc := load(sb.Server)
	var nets []netip.Prefix
	for _, v := range []string{sc.Net4, sc.Net6} {
		if p, err := parsePrefix(v); err == nil {
			nets = append(nets, p.Masked())
		}
	}
	for _, n := range nodes(sb, true) {
		nets = append(nets, n.routes...)
	}
	return sc.Interface, nets
}

// Sources: Adressen und Netze, von denen der Verkehr eines Geräts kommt (für Ziel-Regeln).
func (Driver) Sources(env *proto.Env, sb *proto.ServerBundle) map[int64][]netip.Prefix {
	out := map[int64][]netip.Prefix{}
	for _, n := range nodes(sb, true) {
		out[n.pb.Peer.ID] = n.all()
	}
	return out
}
