// Package wireguard: WireGuard-Server als Sternnetz (Hub) mit Netzen hinter Geräten,
// Zugriffsregeln zwischen Geräten, Internet-Ausgang und Geschwindigkeitsbegrenzung (tc).
package wireguard

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/shaping"
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
			{Key: "dns", Label: "DNS für Geräte", Type: "text", Default: "auto",
				Help: "„auto“ = Panel-DNS (Filter, Protokoll, Domain-Regeln) über die Tunneladresse des Servers. Sonst eigene DNS-Server, mit Komma getrennt."},
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
			{Key: "dns", Label: "DNS", Type: "text", Advanced: true, Placeholder: "Vorgabe des Servers", Help: "„auto“ = Panel-DNS, „none“ = keinen DNS setzen."},
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
	c := serverCfg{Port: 51820, Internet: true, DefaultAccess: "all", Keepalive: 25, DNS: "auto"}
	_ = proto.Decode(srv.Settings, &c)
	return c
}

func loadPeer(p *store.Peer) peerCfg {
	var c peerCfg
	_ = proto.Decode(p.Settings, &c)
	return c
}

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}$`) // kein führendes „-“: der Name ist Befehlsargument

// exitIfRe: Schnittstellen der Ausgänge (externe VPNs, Paket exits)
var exitIfRe = regexp.MustCompile(`^ex[0-9]+$`)

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
	c := serverCfg{Port: 0, Internet: true, DefaultAccess: "all", Keepalive: 25, DNS: "auto", Net6: "\x00"}
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
	if strings.HasPrefix(c.Interface, "ovpn") || exitIfRe.MatchString(c.Interface) || c.Interface == shaping.IfbDev || c.Interface == outIf(env, c) || c.Interface == "lo" {
		return fmt.Errorf("Schnittstellenname %q ist reserviert", c.Interface)
	}
	if used(func(o serverCfg) bool { return o.Interface == c.Interface }) {
		return fmt.Errorf("Schnittstelle %s wird schon von einem anderen Server benutzt", c.Interface)
	}
	if c.Port == 0 {
		c.Port = 51820
		for used(func(o serverCfg) bool { return o.Port == c.Port }) || proto.PortConflict(env.Global, all, srv.ID, "udp", c.Port, 0) != "" {
			c.Port++
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("Port %d ungültig", c.Port)
	}
	if used(func(o serverCfg) bool { return o.Port == c.Port }) {
		return fmt.Errorf("UDP-Port %d wird schon von einem anderen WireGuard-Server benutzt", c.Port)
	}
	if msg := proto.PortConflict(env.Global, all, srv.ID, "udp", c.Port, 0); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	if c.Net4 == "" {
		p := netip.MustParsePrefix("10.8.0.0/24")
		for used(func(o serverCfg) bool { q, err := parsePrefix(o.Net4); return err == nil && q.Overlaps(p) }) || proto.NetConflict(all, srv.ID, p) != "" {
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
	if msg := proto.NetConflict(all, srv.ID, n4); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	if c.Net6 == "\x00" { // nicht gesetzt → Vorgabe
		p := netip.MustParsePrefix("fd42:42:42::/64")
		for used(func(o serverCfg) bool { q, err := parsePrefix(o.Net6); return err == nil && q.Overlaps(p) }) || proto.NetConflict(all, srv.ID, p) != "" {
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
		if msg := proto.NetConflict(all, srv.ID, n6); msg != "" {
			return fmt.Errorf("%s", msg)
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
