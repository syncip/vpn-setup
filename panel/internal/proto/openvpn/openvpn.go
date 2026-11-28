// Package openvpn: OpenVPN-Server (UDP oder TCP). Pro Server läuft eine eigene Instanz
// (systemd-Vorlage vpn-openvpn@ovpn<ID>, Tunnel-Schnittstelle ovpn<ID>).
//
//   - Jeder Zugang hat ein eigenes Zertifikat aus der CA des Servers (im Panel erzeugt).
//   - Nur aktive Zugänge bekommen eine Datei im client-config-dir; mit „ccd-exclusive“ weist
//     OpenVPN alle anderen sofort ab (gesperrt, deaktiviert, gelöscht, alte Schlüssel).
//   - tls-crypt verschlüsselt schon den Handshake: ohne Profil antwortet der Server nicht.
//   - Über die Management-Schnittstelle (Unix-Socket, nur root) kommen Verbrauch, Adresse und
//     „verbunden seit“; gesperrte Zugänge werden darüber sofort getrennt.
//   - Feste Tunnel-Adresse pro Zugang → Drosselung per tc auf ovpn<ID> wie bei WireGuard.
package openvpn

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

const (
	confDir  = "/etc/openvpn/vpn"
	unitPath = "/etc/systemd/system/vpn-openvpn@.service"
	binPath  = "/usr/sbin/openvpn"
	runDir   = "/run/vpn-openvpn"
)

const unitFile = `# Vom VPN-Panel erzeugt – eine OpenVPN-Instanz pro Server (/etc/openvpn/vpn/<name>.conf)
[Unit]
Description=OpenVPN (VPN-Panel) %i
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
RuntimeDirectory=vpn-openvpn/%i
RuntimeDirectoryMode=0700
WorkingDirectory=/etc/openvpn/vpn
ExecStart=/usr/sbin/openvpn --suppress-timestamps --config /etc/openvpn/vpn/%i.conf
Restart=on-failure
RestartSec=3
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`

const (
	defaultDNS = "auto"
	// oldDefaultDNS: Vorgabe bis v0.9 – gilt wie „auto“
	oldDefaultDNS = "1.1.1.1, 2606:4700:4700::1111"
)

type serverCfg struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"` // udp | tcp
	Net4      string `json:"net4"`
	Net6      string `json:"net6"`
	Internet  bool   `json:"internet"` // gesamter Verkehr über den Server
	DNS       string `json:"dns"`
	Host      string `json:"host"`
	MTU       int    `json:"mtu"`
}

type peerCfg struct {
	Address4 string `json:"address4"`
	Address6 string `json:"address6"`
}

func load(srv *store.Server) serverCfg {
	c := serverCfg{Port: 1194, Transport: "udp", Internet: true, DNS: defaultDNS}
	_ = proto.Decode(srv.Settings, &c)
	if c.Transport != "tcp" {
		c.Transport = "udp"
	}
	return c
}

func loadPeer(p *store.Peer) peerCfg {
	var c peerCfg
	_ = proto.Decode(p.Settings, &c)
	return c
}

type Driver struct{}

func init() { proto.Register(Driver{}) }

func (Driver) Info() proto.Info {
	return proto.Info{
		ID:    "openvpn",
		Label: "OpenVPN",
		Description: "Klassisches VPN – läuft auf fast allen Routern, Firewalls, NAS und Betriebssystemen (OpenVPN Connect). " +
			"Langsamer als WireGuard und leicht zu erkennen, also kein Schutz vor Sperren.",
		ServerFields: []proto.Field{
			{Key: "port", Label: "Port", Type: "number", Default: 1194,
				Help: "Muss nach außen offen bzw. auf dem Host an den Container weitergeleitet sein."},
			{Key: "transport", Label: "Übertragung", Type: "select", Default: "udp", Options: []proto.Option{
				{Value: "udp", Label: "UDP (schneller, empfohlen)"},
				{Value: "tcp", Label: "TCP (nur wenn UDP im Netz gesperrt ist)"},
			}},
			{Key: "internet", Label: "Internetzugang über diesen Server", Type: "bool", Default: true,
				Help: "An: gesamter Verkehr der Geräte geht über den Server. Aus: nur das Tunnelnetz."},
			{Key: "dns", Label: "DNS für Geräte", Type: "text", Default: defaultDNS, Help: "„auto“ = Panel-DNS (Filter, Protokoll, Domain-Regeln) über die Tunneladresse des Servers. Sonst IP-Adressen, mit Komma getrennt. Nur mit Internetzugang."},
			{Key: "net4", Label: "Tunnelnetz IPv4", Type: "cidr", Default: "10.66.0.0/24", Advanced: true,
				Help: "Jeder Zugang bekommt eine feste Adresse daraus, der Server die erste (/16 bis /29)."},
			{Key: "net6", Label: "Tunnelnetz IPv6", Type: "cidr", Default: "fd66:66:66::/64", Advanced: true, Help: "Leer lassen für reines IPv4 (/64 bis /112)."},
			{Key: "host", Label: "Adresse im Profil", Type: "text", Advanced: true, Placeholder: "Server-Adresse aus den Einstellungen"},
			{Key: "mtu", Label: "MTU im Tunnel", Type: "number", Default: 0, Advanced: true, Help: "0 = Vorgabe (1500). Bei hängenden Verbindungen z. B. 1400."},
		},
		PeerFields: []proto.Field{
			{Key: "address4", Label: "IPv4-Adresse im Tunnel", Type: "text", Advanced: true, Placeholder: "automatisch"},
			{Key: "address6", Label: "IPv6-Adresse im Tunnel", Type: "text", Advanced: true, Placeholder: "automatisch"},
		},
		Kinds: []proto.Kind{{ID: "access", Label: "Gerät", Icon: "key",
			Description: "Ein OpenVPN-Profil (.ovpn) mit eigenem Zertifikat – für OpenVPN Connect, Router oder Firewalls.", Defaults: store.M{}}},
	}
}

// ---------- Prüfen & Vorgaben ----------

var hostRe = regexp.MustCompile(`^([A-Za-z0-9.-]{1,253}|\[?[0-9A-Fa-f:.]{2,45}\]?)$`)

// checkDNS: nur IP-Adressen (OpenVPN schiebt sie als „dhcp-option DNS/DNS6“).
func checkDNS(v string) (string, error) {
	if strings.TrimSpace(v) == "auto" {
		return "auto", nil
	}
	var out []string
	for _, it := range strings.Split(v, ",") {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		a, err := netip.ParseAddr(it)
		if err != nil {
			return "", fmt.Errorf("DNS %q ist keine IP-Adresse", it)
		}
		out = append(out, a.String())
	}
	return strings.Join(out, ", "), nil
}

func (Driver) InitServer(env *proto.Env, srv *store.Server, all []*store.Server) error {
	c := serverCfg{Port: 0, Transport: "udp", Internet: true, DNS: defaultDNS, Net6: "\x00"}
	_ = proto.Decode(srv.Settings, &c)
	if c.Transport != "tcp" {
		c.Transport = "udp"
	}
	if c.Port == 0 {
		c.Port = 1194
		for proto.PortConflict(env.Global, all, srv.ID, c.Transport, c.Port, 0) != "" && c.Port < 65535 {
			c.Port++
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("Port %d ungültig", c.Port)
	}
	if msg := proto.PortConflict(env.Global, all, srv.ID, c.Transport, c.Port, 0); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	// Neuer Server mit dem vorgeschlagenen Netz (das Formular schickt die Vorgabe mit), das schon
	// vergeben ist → automatisch das nächste freie nehmen statt eines Fehlers.
	if srv.ID == 0 && c.Net4 == "10.66.0.0/24" && proto.NetConflict(all, srv.ID, netip.MustParsePrefix(c.Net4)) != "" {
		c.Net4 = ""
	}
	if srv.ID == 0 && c.Net6 == "fd66:66:66::/64" && proto.NetConflict(all, srv.ID, netip.MustParsePrefix(c.Net6)) != "" {
		c.Net6 = "\x00"
	}
	if c.Net4 == "" {
		p := netip.MustParsePrefix("10.66.0.0/24")
		for i := 0; proto.NetConflict(all, srv.ID, p) != "" && i < 200; i++ {
			p = nextNet(p)
		}
		c.Net4 = p.String()
	}
	n4, err := netip.ParsePrefix(strings.TrimSpace(c.Net4))
	if err != nil || !n4.Addr().Is4() || n4.Bits() < 16 || n4.Bits() > 29 {
		return fmt.Errorf("Tunnelnetz IPv4 %q ungültig (z. B. 10.66.0.0/24, /16 bis /29)", c.Net4)
	}
	n4 = n4.Masked()
	c.Net4 = n4.String()
	if msg := proto.NetConflict(all, srv.ID, n4); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	if c.Net6 == "\x00" {
		p := netip.MustParsePrefix("fd66:66:66::/64")
		for i := 0; proto.NetConflict(all, srv.ID, p) != "" && i < 200; i++ {
			p = nextNet(p)
		}
		c.Net6 = p.String()
	}
	c.Net6 = strings.TrimSpace(c.Net6)
	if c.Net6 != "" {
		n6, err := netip.ParsePrefix(c.Net6)
		if err != nil || n6.Addr().Is4() || n6.Bits() < 64 || n6.Bits() > 112 {
			return fmt.Errorf("Tunnelnetz IPv6 %q ungültig (z. B. fd66:66:66::/64, /64 bis /112)", c.Net6)
		}
		n6 = n6.Masked()
		c.Net6 = n6.String()
		if msg := proto.NetConflict(all, srv.ID, n6); msg != "" {
			return fmt.Errorf("%s", msg)
		}
	}
	if c.DNS, err = checkDNS(c.DNS); err != nil {
		return err
	}
	c.Host = strings.TrimSpace(c.Host)
	if c.Host != "" && !hostRe.MatchString(c.Host) {
		return fmt.Errorf("Adresse %q ungültig (Hostname oder IP ohne Port)", c.Host)
	}
	if c.MTU != 0 && (c.MTU < 1200 || c.MTU > 1500) {
		return fmt.Errorf("MTU %d ungültig (1200–1500 oder 0)", c.MTU)
	}
	srv.Settings = proto.Encode(c)

	// Schlüssel: CA, Server-Zertifikat, tls-crypt (nur wenn sie fehlen)
	if proto.Str(srv.State, "ca_cert") == "" || proto.Str(srv.State, "ca_key") == "" {
		ca, key, err := newCA("VPN-Panel OpenVPN CA " + proto.RandHex(4))
		if err != nil {
			return err
		}
		srv.State["ca_cert"], srv.State["ca_key"] = ca, key
		delete(srv.State, "server_cert")
	}
	if proto.Str(srv.State, "server_cn") == "" {
		srv.State["server_cn"] = "vpnpanel-" + proto.RandHex(6)
	}
	if !signedBy(proto.Str(srv.State, "server_cert"), proto.Str(srv.State, "ca_cert")) {
		cert, key, err := issue(proto.Str(srv.State, "ca_cert"), proto.Str(srv.State, "ca_key"), proto.Str(srv.State, "server_cn"), true)
		if err != nil {
			return err
		}
		srv.State["server_cert"], srv.State["server_key"] = cert, key
	}
	if proto.Str(srv.State, "tls_crypt") == "" {
		srv.State["tls_crypt"] = tlsCryptKey()
	}
	return nil
}

var cnRe = regexp.MustCompile(`^p-[0-9a-f]{16}$`)

func (Driver) InitPeer(env *proto.Env, srv *store.Server, p *store.Peer, others []*store.Peer) error {
	p.Kind = "access"
	sc := load(srv)
	c := loadPeer(p)
	n4, err := netip.ParsePrefix(sc.Net4)
	if err != nil {
		return fmt.Errorf("Tunnelnetz des Servers ungültig")
	}
	var n6 netip.Prefix
	if sc.Net6 != "" {
		n6, _ = netip.ParsePrefix(sc.Net6)
	}
	used := map[netip.Addr]bool{}
	if a, err := addrAt(n4, 1); err == nil {
		used[a] = true
	}
	if n6.IsValid() {
		if a, err := addrAt(n6, 1); err == nil {
			used[a] = true
		}
	}
	for _, o := range others {
		if o.ID == p.ID {
			continue
		}
		oc := loadPeer(o)
		for _, s := range []string{oc.Address4, oc.Address6} {
			if a, err := netip.ParseAddr(s); err == nil {
				used[a] = true
			}
		}
	}
	// IPv4: erste freie ab .2 (Netz- und Broadcast-Adresse ausgenommen)
	last := lastHost(n4)
	if strings.TrimSpace(c.Address4) == "" {
		for i := uint64(2); ; i++ {
			a, err := addrAt(n4, i)
			if err != nil || !a.Less(last.Next()) {
				return fmt.Errorf("keine freien Adressen mehr in %s", sc.Net4)
			}
			if !used[a] {
				c.Address4 = a.String()
				break
			}
		}
	}
	a4, err := netip.ParseAddr(strings.TrimSpace(c.Address4))
	if err != nil || !a4.Is4() || !n4.Contains(a4) || a4 == n4.Masked().Addr() || last.Less(a4) {
		return fmt.Errorf("IPv4-Adresse %q liegt nicht im Tunnelnetz %s", c.Address4, sc.Net4)
	}
	if used[a4] {
		return fmt.Errorf("IPv4-Adresse %s ist schon vergeben", a4)
	}
	c.Address4 = a4.String()
	if n6.IsValid() {
		if strings.TrimSpace(c.Address6) == "" {
			off := uint64(binary.BigEndian.Uint32(a4.AsSlice()) - binary.BigEndian.Uint32(n4.Masked().Addr().AsSlice()))
			if a, err := addrAt(n6, off); err == nil && !used[a] {
				c.Address6 = a.String()
			} else {
				for i := uint64(2); i < 1<<20; i++ {
					if a, err := addrAt(n6, i); err == nil && !used[a] {
						c.Address6 = a.String()
						break
					}
				}
			}
		}
		a6, err := netip.ParseAddr(strings.TrimSpace(c.Address6))
		if err != nil || a6.Is4() || !n6.Contains(a6) || a6 == n6.Masked().Addr() {
			return fmt.Errorf("IPv6-Adresse %q liegt nicht im Tunnelnetz %s", c.Address6, sc.Net6)
		}
		if used[a6] {
			return fmt.Errorf("IPv6-Adresse %s ist schon vergeben", a6)
		}
		c.Address6 = a6.String()
	} else {
		c.Address6 = ""
	}
	p.Settings = proto.Encode(c)

	// Zertifikat: neu, wenn es fehlt oder nicht (mehr) zur CA des Servers passt (z. B. nach
	// „Neue Schlüssel“ am Server). Neuer Common Name → das alte Profil wird abgewiesen.
	ca := proto.Str(srv.State, "ca_cert")
	if !cnRe.MatchString(proto.Str(p.Secrets, "cn")) || !signedBy(proto.Str(p.Secrets, "cert"), ca) {
		cn := "p-" + proto.RandHex(8)
		cert, key, err := issue(ca, proto.Str(srv.State, "ca_key"), cn, false)
		if err != nil {
			return fmt.Errorf("Zertifikat ausstellen: %w", err)
		}
		p.Secrets["cn"], p.Secrets["cert"], p.Secrets["key"] = cn, cert, key
	}
	return nil
}
