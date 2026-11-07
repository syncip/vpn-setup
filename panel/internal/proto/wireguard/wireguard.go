// Package wireguard: WireGuard-Server als Sternnetz (Hub) mit Netzen hinter Geräten,
// Zugriffsregeln zwischen Geräten, Internet-Ausgang und Geschwindigkeitsbegrenzung (tc).
package wireguard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

const routeProto = "77" // Kennung unserer Routen in der Routing-Tabelle

type serverCfg struct {
	Interface     string `json:"interface"`
	Port          int    `json:"port"`
	Net4          string `json:"net4"`
	Net6          string `json:"net6"`
	Internet      bool   `json:"internet"`
	DefaultAccess string `json:"default_access"` // all | own | none
	Endpoint      string `json:"endpoint"`
	DNS           string `json:"dns"`
	MTU           int    `json:"mtu"`
	Keepalive     int    `json:"keepalive"`
	OutInterface  string `json:"out_interface"`
}

type peerCfg struct {
	Address4     string   `json:"address4"`
	Address6     string   `json:"address6"`
	Routes       []string `json:"routes"`
	Tunnel       string   `json:"tunnel"` // full | split
	Access       string   `json:"access"` // default | all | own | none | custom
	AccessPeers  []int64  `json:"access_peers"`
	LANInterface string   `json:"lan_interface"`
	LANNat       bool     `json:"lan_nat"`
	DNS          string   `json:"dns"`
	Keepalive    int      `json:"keepalive"`
	MTU          int      `json:"mtu"`
	ExtraAllowed []string `json:"extra_allowed"`
	Endpoint     string   `json:"endpoint"`
}

type Driver struct{}

func init() { proto.Register(Driver{}) }

func (Driver) Info() proto.Info {
	return proto.Info{
		ID:          "wireguard",
		Label:       "WireGuard",
		Description: "Schnelles VPN und Netzwerk für Geräte, Server und ganze Heimnetze (Sternnetz über diesen Server).",
		Mesh:        true,
		ServerFields: []proto.Field{
			{Key: "port", Label: "UDP-Port", Type: "number", Default: 51820, Help: "Muss auf dem Proxmox-Host an den Container weitergeleitet sein."},
			{Key: "net4", Label: "Tunnelnetz IPv4", Type: "cidr", Default: "10.8.0.0/24", Help: "Jedes Gerät bekommt eine Adresse daraus, der Server die erste."},
			{Key: "internet", Label: "Internetzugang über diesen Server", Type: "bool", Default: true, Help: "Geräte mit vollem Tunnel gehen über diesen Server ins Internet."},
			{Key: "default_access", Label: "Standard-Zugriff zwischen Geräten", Type: "select", Default: "all", Options: []proto.Option{
				{Value: "all", Label: "Alle Geräte und Netze dieses Servers"},
				{Value: "own", Label: "Nur Geräte desselben Nutzers"},
				{Value: "none", Label: "Kein Zugriff (nur Internet)"},
			}, Help: "Gilt für alle Geräte, die keine eigene Regel haben."},
			{Key: "dns", Label: "DNS für Geräte", Type: "text", Default: "1.1.1.1, 2606:4700:4700::1111"},
			{Key: "net6", Label: "Tunnelnetz IPv6", Type: "cidr", Default: "fd42:42:42::/64", Advanced: true, Help: "Leer lassen für reines IPv4."},
			{Key: "endpoint", Label: "Öffentliche Adresse", Type: "text", Advanced: true, Placeholder: "Server-Domain aus den Einstellungen", Help: "Hostname oder IP, unter der Geräte den Server erreichen."},
			{Key: "interface", Label: "Schnittstelle", Type: "text", Advanced: true, Placeholder: "automatisch (wg0, wg1, …)"},
			{Key: "mtu", Label: "MTU", Type: "number", Default: 0, Advanced: true, Help: "0 = automatisch. Bei Verbindungsproblemen z. B. 1380 versuchen."},
			{Key: "keepalive", Label: "Keepalive (Sekunden)", Type: "number", Default: 25, Advanced: true, Help: "Hält die Verbindung hinter NAT offen. 0 = aus."},
			{Key: "out_interface", Label: "Ausgehende Schnittstelle", Type: "text", Advanced: true, Placeholder: "aus den Einstellungen (eth0)"},
		},
		PeerFields: []proto.Field{
			{Key: "routes", Label: "Netze hinter diesem Gerät", Type: "cidrlist", Kinds: []string{"site", "server"}, Placeholder: "192.168.1.0/24",
				Help: "Diese Netze werden über das Gerät erreichbar (z. B. das Heimnetz hinter dem Homelab)."},
			{Key: "tunnel", Label: "Tunnel", Type: "select", Options: []proto.Option{
				{Value: "full", Label: "Voll – gesamter Verkehr über den Server"},
				{Value: "split", Label: "Geteilt – nur VPN-Netze über den Server"},
			}},
			{Key: "access", Label: "Zugriff auf andere Geräte", Type: "select", Default: "default", Options: []proto.Option{
				{Value: "default", Label: "Standard des Servers"},
				{Value: "all", Label: "Alle Geräte und Netze"},
				{Value: "own", Label: "Nur eigene Geräte"},
				{Value: "none", Label: "Keine"},
				{Value: "custom", Label: "Ausgewählte Geräte"},
			}},
			{Key: "access_peers", Label: "Erlaubte Geräte", Type: "peers", Help: "Nur bei „Ausgewählte Geräte“."},
			{Key: "lan_nat", Label: "NAT ins lokale Netz", Type: "bool", Kinds: []string{"site"}, Advanced: true,
				Help: "Das Gerät setzt Anfragen aus dem VPN auf seine eigene Adresse um. Dann braucht der Router im Heimnetz keine Route zurück."},
			{Key: "lan_interface", Label: "LAN-Schnittstelle des Geräts", Type: "text", Kinds: []string{"site"}, Advanced: true, Placeholder: "eth0"},
			{Key: "address4", Label: "IPv4-Adresse im Tunnel", Type: "text", Advanced: true, Placeholder: "automatisch"},
			{Key: "address6", Label: "IPv6-Adresse im Tunnel", Type: "text", Advanced: true, Placeholder: "automatisch"},
			{Key: "dns", Label: "DNS", Type: "text", Advanced: true, Placeholder: "Vorgabe des Servers", Help: "„none“ = keinen DNS setzen."},
			{Key: "extra_allowed", Label: "Zusätzliche Ziele (AllowedIPs)", Type: "cidrlist", Advanced: true, Help: "Weitere Netze, die das Gerät über den Tunnel schickt."},
			{Key: "endpoint", Label: "Feste Adresse des Geräts", Type: "text", Advanced: true, Placeholder: "host:port",
				Help: "Nur wenn das Gerät selbst öffentlich erreichbar ist – dann kann der Server die Verbindung aufbauen."},
			{Key: "keepalive", Label: "Keepalive (Sekunden)", Type: "number", Advanced: true, Placeholder: "Vorgabe des Servers"},
			{Key: "mtu", Label: "MTU", Type: "number", Advanced: true, Placeholder: "Vorgabe des Servers"},
		},
		Kinds: []proto.Kind{
			{ID: "client", Label: "Handy / Laptop", Icon: "phone", Description: "Unterwegs sicher ins Internet und ins Heimnetz.",
				Defaults: store.M{"tunnel": "full", "access": "default"}},
			{ID: "server", Label: "Server / PC", Icon: "server", Description: "Ein einzelnes Gerät, das im Netzwerk erreichbar sein soll.",
				Defaults: store.M{"tunnel": "split", "access": "default"}},
			{ID: "site", Label: "Netzwerk / Homelab", Icon: "network", Description: "Ein Gerät (Router, Raspberry Pi, Proxmox) macht ein ganzes Netz erreichbar.",
				Defaults: store.M{"tunnel": "split", "access": "default", "lan_nat": true, "lan_interface": "eth0"}},
		},
	}
}

// ---------- Vorgaben & Prüfungen ----------

func load(srv *store.Server) serverCfg {
	c := serverCfg{Port: 51820, Internet: true, DefaultAccess: "all", Keepalive: 25, DNS: "1.1.1.1, 2606:4700:4700::1111"}
	_ = proto.Decode(srv.Settings, &c)
	return c
}

func loadPeer(p *store.Peer) peerCfg {
	var c peerCfg
	_ = proto.Decode(p.Settings, &c)
	return c
}

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

var (
	hostRe     = regexp.MustCompile(`^([A-Za-z0-9.-]{1,253}|\[?[0-9A-Fa-f:.]{2,45}\]?)$`)
	hostPortRe = regexp.MustCompile(`^([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\]):[0-9]{1,5}$`)
	dnsItemRe  = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)
)

// checkDNS: Liste von DNS-Servern (IPs) bzw. Suchdomains, oder „none“.
func checkDNS(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || v == "none" {
		return v, nil
	}
	var out []string
	for _, it := range strings.Split(v, ",") {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if !dnsItemRe.MatchString(it) {
			return "", fmt.Errorf("DNS-Eintrag %q ungültig", it)
		}
		out = append(out, it)
	}
	return strings.Join(out, ", "), nil
}

// oneLine: Text für Kommentare in Konfigurationsdateien (keine Zeilenumbrüche).
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}

func (Driver) InitServer(env *proto.Env, srv *store.Server, all []*store.Server) error {
	c := serverCfg{Port: 0, Internet: true, DefaultAccess: "all", Keepalive: 25, DNS: "1.1.1.1, 2606:4700:4700::1111", Net6: "\x00"}
	_ = proto.Decode(srv.Settings, &c)
	var others []serverCfg
	for _, o := range all {
		if o.Protocol == "wireguard" && o.ID != srv.ID {
			others = append(others, load(o))
		}
	}
	used := func(f func(serverCfg) bool) bool {
		for _, o := range others {
			if f(o) {
				return true
			}
		}
		return false
	}
	if c.Interface == "" {
		for i := 0; ; i++ {
			n := fmt.Sprintf("wg%d", i)
			if !used(func(o serverCfg) bool { return o.Interface == n }) {
				c.Interface = n
				break
			}
		}
	}
	if !ifaceRe.MatchString(c.Interface) {
		return fmt.Errorf("Schnittstellenname %q ungültig (max. 15 Zeichen, a-z 0-9 _ -)", c.Interface)
	}
	if used(func(o serverCfg) bool { return o.Interface == c.Interface }) {
		return fmt.Errorf("Schnittstelle %s wird schon von einem anderen Server benutzt", c.Interface)
	}
	if c.Port == 0 {
		c.Port = 51820
		for used(func(o serverCfg) bool { return o.Port == c.Port }) {
			c.Port++
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("Port %d ungültig", c.Port)
	}
	if used(func(o serverCfg) bool { return o.Port == c.Port }) {
		return fmt.Errorf("UDP-Port %d wird schon von einem anderen WireGuard-Server benutzt", c.Port)
	}
	if c.Net4 == "" {
		p := netip.MustParsePrefix("10.8.0.0/24")
		for used(func(o serverCfg) bool { q, err := parsePrefix(o.Net4); return err == nil && q.Overlaps(p) }) {
			p = nextNet(p)
		}
		c.Net4 = p.String()
	}
	n4, err := parsePrefix(c.Net4)
	if err != nil || !n4.Addr().Is4() || n4.Bits() > 30 {
		return fmt.Errorf("Tunnelnetz IPv4 %q ungültig (z. B. 10.8.0.0/24)", c.Net4)
	}
	c.Net4 = n4.String()
	if used(func(o serverCfg) bool { q, err := parsePrefix(o.Net4); return err == nil && q.Overlaps(n4) }) {
		return fmt.Errorf("Tunnelnetz %s überschneidet sich mit einem anderen WireGuard-Server", c.Net4)
	}
	if c.Net6 == "\x00" { // nicht gesetzt → Vorgabe
		p := netip.MustParsePrefix("fd42:42:42::/64")
		for used(func(o serverCfg) bool { q, err := parsePrefix(o.Net6); return err == nil && q.Overlaps(p) }) {
			p = nextNet(p)
		}
		c.Net6 = p.String()
	}
	if c.Net6 != "" {
		n6, err := parsePrefix(c.Net6)
		if err != nil || n6.Addr().Is4() || n6.Bits() > 120 {
			return fmt.Errorf("Tunnelnetz IPv6 %q ungültig (z. B. fd42:42:42::/64)", c.Net6)
		}
		c.Net6 = n6.String()
		if used(func(o serverCfg) bool { q, err := parsePrefix(o.Net6); return err == nil && q.Overlaps(n6) }) {
			return fmt.Errorf("Tunnelnetz %s überschneidet sich mit einem anderen WireGuard-Server", c.Net6)
		}
	}
	switch c.DefaultAccess {
	case "all", "own", "none":
	default:
		c.DefaultAccess = "all"
	}
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 9000) {
		return fmt.Errorf("MTU %d ungültig (1280–9000 oder 0)", c.MTU)
	}
	if c.OutInterface != "" && !ifaceRe.MatchString(c.OutInterface) {
		return fmt.Errorf("Schnittstellenname %q ungültig", c.OutInterface)
	}
	c.Endpoint = strings.TrimSpace(c.Endpoint)
	if c.Endpoint != "" && !hostRe.MatchString(c.Endpoint) {
		return fmt.Errorf("Adresse %q ungültig (Hostname oder IP ohne Port)", c.Endpoint)
	}
	if c.DNS, err = checkDNS(c.DNS); err != nil {
		return err
	}
	if c.Keepalive < 0 || c.Keepalive > 3600 {
		return fmt.Errorf("Keepalive %d ungültig (0–3600)", c.Keepalive)
	}
	srv.Settings = proto.Encode(c)

	if proto.Str(srv.State, "private_key") == "" {
		priv, pub, err := proto.X25519()
		if err != nil {
			return err
		}
		srv.State["private_key"] = proto.B64(priv)
		srv.State["public_key"] = proto.B64(pub)
	}
	return nil
}

func (Driver) InitPeer(env *proto.Env, srv *store.Server, p *store.Peer, others []*store.Peer) error {
	sc := load(srv)
	c := loadPeer(p)
	switch p.Kind {
	case "client", "server", "site":
	default:
		return fmt.Errorf("unbekannte Geräteart %q", p.Kind)
	}
	if c.Tunnel != "full" && c.Tunnel != "split" {
		if p.Kind == "client" {
			c.Tunnel = "full"
		} else {
			c.Tunnel = "split"
		}
	}
	switch c.Access {
	case "default", "all", "own", "none", "custom":
	default:
		c.Access = "default"
	}
	if p.Kind == "site" && c.LANInterface == "" {
		c.LANInterface = "eth0"
	}
	if c.LANInterface != "" && !ifaceRe.MatchString(c.LANInterface) {
		return fmt.Errorf("LAN-Schnittstelle %q ungültig", c.LANInterface)
	}

	n4, _ := parsePrefix(sc.Net4)
	var n6 netip.Prefix
	if sc.Net6 != "" {
		n6, _ = parsePrefix(sc.Net6)
	}
	srvAddr4, _ := addrAt(n4, 1)

	usedAddr := map[netip.Addr]bool{srvAddr4: true}
	var otherRoutes []netip.Prefix
	for _, o := range others {
		if o.ID == p.ID {
			continue
		}
		oc := loadPeer(o)
		if a, err := netip.ParseAddr(oc.Address4); err == nil {
			usedAddr[a] = true
		}
		if a, err := netip.ParseAddr(oc.Address6); err == nil {
			usedAddr[a] = true
		}
		for _, r := range oc.Routes {
			if q, err := parsePrefix(r); err == nil {
				otherRoutes = append(otherRoutes, q)
			}
		}
	}

	// IPv4-Adresse
	if c.Address4 == "" {
		for i := uint64(2); i <= hostCount(n4); i++ {
			a, err := addrAt(n4, i)
			if err != nil {
				break
			}
			if !usedAddr[a] {
				c.Address4 = a.String()
				break
			}
		}
		if c.Address4 == "" {
			return fmt.Errorf("keine freien Adressen mehr in %s", sc.Net4)
		}
	}
	a4, err := netip.ParseAddr(strings.TrimSpace(c.Address4))
	if err != nil || !n4.Contains(a4) {
		return fmt.Errorf("IPv4-Adresse %q liegt nicht im Tunnelnetz %s", c.Address4, sc.Net4)
	}
	if usedAddr[a4] {
		return fmt.Errorf("IPv4-Adresse %s ist schon vergeben", a4)
	}
	c.Address4 = a4.String()

	// IPv6-Adresse: gleiche Endung wie IPv4, wenn möglich
	if n6.IsValid() {
		if c.Address6 == "" {
			off := uint64(a4.As4()[3]) | uint64(a4.As4()[2])<<8
			base4 := n4.Masked().Addr().As4()
			off -= uint64(base4[3]) | uint64(base4[2])<<8
			if a, err := addrAt(n6, off); err == nil && !usedAddr[a] {
				c.Address6 = a.String()
			} else {
				for i := uint64(2); i < 65534; i++ {
					if a, err := addrAt(n6, i); err == nil && !usedAddr[a] {
						c.Address6 = a.String()
						break
					}
				}
			}
		}
		a6, err := netip.ParseAddr(strings.TrimSpace(c.Address6))
		if err != nil || !n6.Contains(a6) {
			return fmt.Errorf("IPv6-Adresse %q liegt nicht im Tunnelnetz %s", c.Address6, sc.Net6)
		}
		if usedAddr[a6] {
			return fmt.Errorf("IPv6-Adresse %s ist schon vergeben", a6)
		}
		c.Address6 = a6.String()
	} else {
		c.Address6 = ""
	}

	// Netze hinter dem Gerät
	var routes []string
	for _, r := range c.Routes {
		if strings.TrimSpace(r) == "" {
			continue
		}
		q, err := parsePrefix(r)
		if err != nil {
			return err
		}
		if q.Bits() == 0 {
			return fmt.Errorf("%s kann kein Netz hinter einem Gerät sein (dafür „Voller Tunnel“ verwenden)", q)
		}
		if q.Overlaps(n4) || (n6.IsValid() && q.Overlaps(n6)) {
			return fmt.Errorf("Netz %s überschneidet sich mit dem Tunnelnetz", q)
		}
		for _, o := range otherRoutes {
			if q.Overlaps(o) {
				return fmt.Errorf("Netz %s überschneidet sich mit %s eines anderen Geräts", q, o)
			}
		}
		routes = append(routes, q.String())
	}
	c.Routes = routes
	var extra []string
	for _, r := range c.ExtraAllowed {
		if strings.TrimSpace(r) == "" {
			continue
		}
		q, err := parsePrefix(r)
		if err != nil {
			return err
		}
		extra = append(extra, q.String())
	}
	c.ExtraAllowed = extra
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 9000) {
		return fmt.Errorf("MTU %d ungültig", c.MTU)
	}
	c.Endpoint = strings.TrimSpace(c.Endpoint)
	if c.Endpoint != "" && !hostPortRe.MatchString(c.Endpoint) {
		return fmt.Errorf("Endpunkt %q ungültig (Host:Port, IPv6 in [ ])", c.Endpoint)
	}
	var err2 error
	if c.DNS, err2 = checkDNS(c.DNS); err2 != nil {
		return err2
	}
	if c.Keepalive < 0 || c.Keepalive > 3600 {
		return fmt.Errorf("Keepalive %d ungültig (0–3600)", c.Keepalive)
	}
	p.Settings = proto.Encode(c)

	if proto.Str(p.Secrets, "private_key") == "" {
		priv, pub, err := proto.X25519()
		if err != nil {
			return err
		}
		p.Secrets["private_key"] = proto.B64(priv)
		p.Secrets["public_key"] = proto.B64(pub)
	}
	if proto.Str(p.Secrets, "psk") == "" {
		p.Secrets["psk"] = proto.B64(proto.RandBytes(32))
	}
	return nil
}

// ---------- Netz-Logik ----------

// node: ein aktives Gerät mit Adressen und Netzen.
type node struct {
	pb     *proto.PeerBundle
	cfg    peerCfg
	addrs  []netip.Prefix // eigene /32 bzw. /128
	routes []netip.Prefix
}

func (n *node) all() []netip.Prefix { return append(append([]netip.Prefix{}, n.addrs...), n.routes...) }

func nodes(sb *proto.ServerBundle, activeOnly bool) []*node {
	var out []*node
	for _, pb := range sb.Peers {
		if activeOnly && !pb.Active {
			continue
		}
		c := loadPeer(pb.Peer)
		n := &node{pb: pb, cfg: c}
		if a, err := netip.ParseAddr(c.Address4); err == nil {
			n.addrs = append(n.addrs, hostPrefix(a))
		}
		if a, err := netip.ParseAddr(c.Address6); err == nil {
			n.addrs = append(n.addrs, hostPrefix(a))
		}
		for _, r := range c.Routes {
			if q, err := parsePrefix(r); err == nil {
				n.routes = append(n.routes, q)
			}
		}
		out = append(out, n)
	}
	return out
}

// reachable: welche anderen Geräte darf n erreichen?
func reachable(sc serverCfg, n *node, all []*node) []*node {
	mode := n.cfg.Access
	if mode == "" || mode == "default" {
		mode = sc.DefaultAccess
	}
	allowed := map[int64]bool{}
	for _, id := range n.cfg.AccessPeers {
		allowed[id] = true
	}
	var out []*node
	for _, o := range all {
		if o == n {
			continue
		}
		ok := false
		switch mode {
		case "all":
			ok = true
		case "own":
			ok = o.pb.Peer.UserID == n.pb.Peer.UserID
		case "custom":
			ok = allowed[o.pb.Peer.ID]
		}
		if ok {
			out = append(out, o)
		}
	}
	return out
}

// Reachable ist für die Oberfläche (Netzwerk-Ansicht): Peer-ID → erreichbare Peer-IDs.
func Reachable(sb *proto.ServerBundle) map[int64][]int64 {
	sc := load(sb.Server)
	all := nodes(sb, false)
	out := map[int64][]int64{}
	for _, n := range all {
		for _, o := range reachable(sc, n, all) {
			out[n.pb.Peer.ID] = append(out[n.pb.Peer.ID], o.pb.Peer.ID)
		}
	}
	return out
}

func outIf(env *proto.Env, sc serverCfg) string {
	if sc.OutInterface != "" {
		return sc.OutInterface
	}
	if env.Global.OutIf != "" {
		return env.Global.OutIf
	}
	return "eth0"
}

// ---------- Anwenden ----------

func ifaceConf(sb *proto.ServerBundle, sc serverCfg) (head, full string) {
	n4, _ := parsePrefix(sc.Net4)
	a4, _ := addrAt(n4, 1)
	addrs := []string{fmt.Sprintf("%s/%d", a4, n4.Bits())}
	if sc.Net6 != "" {
		n6, _ := parsePrefix(sc.Net6)
		a6, _ := addrAt(n6, 1)
		addrs = append(addrs, fmt.Sprintf("%s/%d", a6, n6.Bits()))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Vom VPN-Panel erzeugt – Änderungen werden überschrieben.\n[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\nListenPort = %d\nPrivateKey = %s\nTable = off\n", strings.Join(addrs, ", "), sc.Port, proto.Str(sb.Server.State, "private_key"))
	if sc.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", sc.MTU)
	}
	head = b.String()
	for _, n := range nodes(sb, true) {
		fmt.Fprintf(&b, "\n[Peer]\n# %s / %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n",
			oneLine(n.pb.User.Name), oneLine(n.pb.Peer.Name), proto.Str(n.pb.Peer.Secrets, "public_key"), proto.Str(n.pb.Peer.Secrets, "psk"), joinPrefixes(n.all()))
		if n.cfg.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", n.cfg.Endpoint)
			ka := n.cfg.Keepalive
			if ka == 0 {
				ka = sc.Keepalive
			}
			if ka > 0 {
				fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
			}
		}
	}
	return head, b.String()
}

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:8]) }

func (d Driver) Apply(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	var errs []string
	want := map[string]bool{}
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		sc := load(sb.Server)
		want[sc.Interface] = true
		if err := d.applyServer(env, sb, sc); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", sb.Server.Name, err))
		}
	}
	// Schnittstellen abbauen, die es nicht mehr gibt bzw. die deaktiviert wurden
	for _, iface := range strings.Fields(env.GetState("wg:ifaces")) {
		if !want[iface] {
			_, _ = sys.Run("systemctl", "disable", "--now", "wg-quick@"+iface)
			_ = sys.Remove("/etc/wireguard/" + iface + ".conf")
			env.SetState("wgif:"+iface, "")
			env.SetState("tc:"+iface, "")
			env.Log("info", "WireGuard-Schnittstelle "+iface+" gestoppt")
		}
	}
	var list []string
	for k := range want {
		list = append(list, k)
	}
	sort.Strings(list)
	env.SetState("wg:ifaces", strings.Join(list, " "))

	if err := applyFirewall(env, servers); err != nil {
		errs = append(errs, "Firewall: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (Driver) applyServer(env *proto.Env, sb *proto.ServerBundle, sc serverCfg) error {
	sys := env.Sys
	iface := sc.Interface
	path := "/etc/wireguard/" + iface + ".conf"
	head, full := ifaceConf(sb, sc)
	changed, err := sys.WriteFile(path, []byte(full), 0o600)
	if err != nil {
		return err
	}
	_, linkErr := sys.Run("ip", "link", "show", iface)
	up := linkErr == nil
	headHash := hash(head)
	switch {
	case !up:
		_, _ = sys.Run("systemctl", "enable", "wg-quick@"+iface)
		if _, err := sys.Run("systemctl", "restart", "wg-quick@"+iface); err != nil {
			return fmt.Errorf("WireGuard starten: %w", err)
		}
		env.SetState("tc:"+iface, "")
		env.Log("info", "WireGuard-Schnittstelle "+iface+" gestartet")
	case env.GetState("wgif:"+iface) != headHash && env.GetState("wgif:"+iface) != "":
		// Adresse/Port/Schlüssel geändert → Neustart nötig
		if _, err := sys.Run("systemctl", "restart", "wg-quick@"+iface); err != nil {
			return fmt.Errorf("WireGuard neu starten: %w", err)
		}
		env.SetState("tc:"+iface, "")
		env.Log("info", "WireGuard-Schnittstelle "+iface+" neu gestartet")
	case changed:
		stripped, err := sys.Run("wg-quick", "strip", iface)
		if err != nil {
			return err
		}
		tmp := "/run/vpnpanel-" + iface + ".conf"
		if _, err := sys.WriteFile(tmp, []byte(stripped), 0o600); err != nil {
			return err
		}
		_, err = sys.Run("wg", "syncconf", iface, tmp)
		_ = sys.Remove(tmp)
		if err != nil {
			return err
		}
	}
	env.SetState("wgif:"+iface, headHash)

	if err := syncRoutes(env, sb, iface); err != nil {
		return fmt.Errorf("Routen: %w", err)
	}
	if err := applyShaping(env, sb, iface); err != nil {
		env.Log("warn", fmt.Sprintf("Geschwindigkeitsbegrenzung auf %s: %v", iface, err))
	}
	return nil
}

// syncRoutes legt Routen für die Netze hinter Geräten an und entfernt veraltete.
func syncRoutes(env *proto.Env, sb *proto.ServerBundle, iface string) error {
	sys := env.Sys
	want := map[string]bool{}
	for _, n := range nodes(sb, true) {
		for _, r := range n.routes {
			want[r.String()] = true
		}
	}
	for _, fam := range []string{"-4", "-6"} {
		out, err := sys.Run("ip", fam, "route", "show", "dev", iface, "proto", routeProto)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			p, err := parsePrefix(f[0])
			if err != nil || !want[p.String()] {
				_, _ = sys.Run("ip", fam, "route", "del", f[0], "dev", iface, "proto", routeProto)
			}
		}
	}
	for r := range want {
		fam := "-4"
		if strings.Contains(r, ":") {
			fam = "-6"
		}
		if _, err := sys.Run("ip", fam, "route", "replace", r, "dev", iface, "proto", routeProto); err != nil {
			return err
		}
	}
	return nil
}

// applyFirewall: eigene Ketten für Weiterleitung (Zugriffsregeln) und NAT.
func applyFirewall(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	for _, v6 := range []bool{false, true} {
		var filter, nat strings.Builder
		filter.WriteString("*filter\n:VPNWG-FWD - [0:0]\n-F VPNWG-FWD\n-A VPNWG-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n")
		nat.WriteString("*nat\n:VPNWG-NAT - [0:0]\n-F VPNWG-NAT\n")
		pick := func(ps []netip.Prefix) []netip.Prefix {
			v4, v6s := split46(ps)
			if v6 {
				return v6s
			}
			return v4
		}
		for _, sb := range servers {
			if !sb.Server.Enabled {
				continue
			}
			sc := load(sb.Server)
			iface, out := sc.Interface, outIf(env, sc)
			all := nodes(sb, true)
			for _, n := range all {
				srcs := pick(n.all())
				for _, t := range reachable(sc, n, all) {
					dsts := pick(t.all())
					for _, s := range srcs {
						for _, dd := range dsts {
							fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -s %s -d %s -j ACCEPT\n", iface, iface, s, dd)
						}
					}
				}
				if sc.Internet {
					for _, s := range srcs {
						fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -s %s -j ACCEPT\n", iface, out, s)
					}
				}
			}
			fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -j DROP\n", iface)
			if sc.Internet {
				net := sc.Net4
				if v6 {
					net = sc.Net6
				}
				if net != "" {
					fmt.Fprintf(&nat, "-A VPNWG-NAT -s %s -o %s -j MASQUERADE\n", net, out)
				}
				for _, n := range all {
					for _, r := range pick(n.routes) {
						fmt.Fprintf(&nat, "-A VPNWG-NAT -s %s -o %s -j MASQUERADE\n", r, out)
					}
				}
			}
		}
		filter.WriteString("COMMIT\n")
		nat.WriteString("COMMIT\n")
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		if _, err := sys.RunInput(filter.String()+nat.String(), bin+"-restore", "-n"); err != nil {
			return err
		}
		if _, err := sys.Run(bin, "-C", "FORWARD", "-j", "VPNWG-FWD"); err != nil {
			if _, err := sys.Run(bin, "-I", "FORWARD", "1", "-j", "VPNWG-FWD"); err != nil {
				return err
			}
		}
		if _, err := sys.Run(bin, "-t", "nat", "-C", "POSTROUTING", "-j", "VPNWG-NAT"); err != nil {
			if _, err := sys.Run(bin, "-t", "nat", "-A", "POSTROUTING", "-j", "VPNWG-NAT"); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyShaping: Download (Server → Gerät) per HTB auf der Schnittstelle,
// Upload (Gerät → Server) per Policer am Eingang.
func applyShaping(env *proto.Env, sb *proto.ServerBundle, iface string) error {
	sys := env.Sys
	var cmds [][]string
	anyDown, anyUp := false, false
	all := nodes(sb, true)
	for _, n := range all {
		anyDown = anyDown || n.pb.RateDown > 0
		anyUp = anyUp || n.pb.RateUp > 0
	}
	if anyDown {
		cmds = append(cmds,
			[]string{"qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "1"},
			[]string{"class", "add", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"})
		for _, n := range all {
			if n.pb.RateDown <= 0 {
				continue
			}
			cls := fmt.Sprintf("1:%x", n.pb.Peer.ID+0x10)
			rate := mbit(n.pb.RateDown)
			cmds = append(cmds, []string{"class", "add", "dev", iface, "parent", "1:", "classid", cls, "htb", "rate", rate, "ceil", rate})
			for _, p := range n.all() {
				if p.Addr().Is4() {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dst", p.String(), "flowid", cls})
				} else {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ipv6", "prio", "2", "u32", "match", "ip6", "dst", p.String(), "flowid", cls})
				}
			}
		}
	}
	if anyUp {
		cmds = append(cmds, []string{"qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"})
		for _, n := range all {
			if n.pb.RateUp <= 0 {
				continue
			}
			rate := mbit(n.pb.RateUp)
			burst := fmt.Sprintf("%dk", max(32, int(n.pb.RateUp*1000/8/10))) // ~100 ms
			for _, p := range n.all() {
				if p.Addr().Is4() {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "src", p.String(), "police", "rate", rate, "burst", burst, "drop", "flowid", ":1"})
				} else {
					cmds = append(cmds, []string{"filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ipv6", "prio", "2", "u32", "match", "ip6", "src", p.String(), "police", "rate", rate, "burst", burst, "drop", "flowid", ":1"})
				}
			}
		}
	}
	var sig strings.Builder
	for _, c := range cmds {
		sig.WriteString(strings.Join(c, " ") + "\n")
	}
	h := ""
	if len(cmds) > 0 {
		h = hash(sig.String())
	}
	if env.GetState("tc:"+iface) == h {
		if h == "" {
			return nil
		}
		if out, err := sys.Run("tc", "qdisc", "show", "dev", iface); err == nil && (sys.DryRun() || strings.Contains(out, "htb") || strings.Contains(out, "ingress")) {
			return nil
		}
	}
	_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "root")
	_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "ingress")
	for _, c := range cmds {
		if _, err := sys.Run("tc", c...); err != nil {
			_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "root")
			_, _ = sys.Run("tc", "qdisc", "del", "dev", iface, "ingress")
			env.SetState("tc:"+iface, "")
			return err
		}
	}
	env.SetState("tc:"+iface, h)
	return nil
}

func mbit(v float64) string { return strconv.FormatFloat(v*1000, 'f', 0, 64) + "kbit" }

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

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
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
	}
	allowed = append(allowed, c.ExtraAllowed...)
	dns := c.DNS
	if dns == "" {
		dns = sc.DNS
	}
	if dns == "none" {
		dns = ""
	}
	mtu := c.MTU
	if mtu == 0 {
		mtu = sc.MTU
	}
	ka := c.Keepalive
	if ka == 0 {
		ka = sc.Keepalive
	}

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
	switch pb.Peer.Kind {
	case "client":
		cc.Links = []proto.Link{{Label: "Hiddify / v2rayN", URL: shareLink(env, sc, sb, pb, c, addrs, allowed, ka)}}
		cc.Instructions = []string{
			"WireGuard-App (Android, iOS, Windows, macOS): „+“ → „QR-Code scannen“ (Konfiguration) oder die Datei importieren.",
			"Hiddify, v2rayN & Co.: den QR-Code des wireguard://-Links scannen oder den Link kopieren und einfügen.",
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

func (Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	return nil
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
	u := url.URL{Scheme: "wireguard", User: url.User(proto.Str(pb.Peer.Secrets, "private_key")),
		Host: fmt.Sprintf("%s:%d", endpointHost(env, sc), sc.Port), Path: "/", RawQuery: q.Encode(),
		Fragment: oneLine(pb.User.Name + "-" + pb.Peer.Name)}
	return u.String()
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
