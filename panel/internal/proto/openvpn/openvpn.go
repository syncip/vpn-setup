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
	"encoding/json"
	"fmt"
	"net/netip"
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

// ---------- Netz-Hilfen ----------

func addrAt(p netip.Prefix, i uint64) (netip.Addr, error) {
	base := p.Masked().Addr()
	b := base.AsSlice()
	if base.Is4() {
		v := uint64(binary.BigEndian.Uint32(b)) + i
		if v > 0xffffffff {
			return netip.Addr{}, fmt.Errorf("Adressbereich erschöpft")
		}
		binary.BigEndian.PutUint32(b, uint32(v))
	} else {
		lo := binary.BigEndian.Uint64(b[8:])
		if lo+i < lo {
			return netip.Addr{}, fmt.Errorf("Adressbereich erschöpft")
		}
		binary.BigEndian.PutUint64(b[8:], lo+i)
	}
	a, _ := netip.AddrFromSlice(b)
	if base.Is4() {
		a = a.Unmap()
	}
	if !p.Contains(a) {
		return netip.Addr{}, fmt.Errorf("Adressbereich %s erschöpft", p)
	}
	return a, nil
}

// lastHost: letzte nutzbare IPv4-Adresse (vor der Broadcast-Adresse).
func lastHost(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	binary.BigEndian.PutUint32(b[:], v-1)
	return netip.AddrFrom4(b)
}

func nextNet(p netip.Prefix) netip.Prefix {
	b := p.Masked().Addr().AsSlice()
	if p.Addr().Is4() {
		b[1]++
	} else {
		v := binary.BigEndian.Uint16(b[4:6]) + 1
		binary.BigEndian.PutUint16(b[4:6], v)
	}
	a, _ := netip.AddrFromSlice(b)
	return netip.PrefixFrom(a.Unmap(), p.Bits())
}

func mask4(p netip.Prefix) string {
	m := uint32(0xffffffff) << (32 - p.Bits())
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, m>>16&255, m>>8&255, m&255)
}

// ---------- Anwenden ----------

func name(srv *store.Server) string     { return fmt.Sprintf("ovpn%d", srv.ID) }
func sockPath(srv *store.Server) string { return runDir + "/" + name(srv) + "/mgmt.sock" }

// ready: Zugang aktiv und Zertifikat passt zur CA (sonst kein Eintrag → abgewiesen).
func ready(sb *proto.ServerBundle, pb *proto.PeerBundle) bool {
	return pb.Active && cnRe.MatchString(proto.Str(pb.Peer.Secrets, "cn")) &&
		signedBy(proto.Str(pb.Peer.Secrets, "cert"), proto.Str(sb.Server.State, "ca_cert"))
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}

func block(tag, content string) string {
	return "<" + tag + ">\n" + strings.TrimSpace(content) + "\n</" + tag + ">\n"
}

// serverConf: Konfiguration einer Instanz (Schlüssel eingebettet, Datei 0600 root; OpenVPN liest
// sie vor dem Wechsel auf „nobody“).
func serverConf(env *proto.Env, sb *proto.ServerBundle, c serverCfg) string {
	srv := sb.Server
	n := name(srv)
	n4, _ := netip.ParsePrefix(c.Net4)
	ipv6 := env.Sys.DryRun() || hostHasIPv6(env)
	pr := "udp"
	if c.Transport == "tcp" {
		pr = "tcp-server"
	}
	if ipv6 {
		pr = strings.Replace(pr, "udp", "udp6", 1)
		pr = strings.Replace(pr, "tcp-server", "tcp6-server", 1)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Vom VPN-Panel erzeugt – Änderungen werden überschrieben.\n# %s\n", oneLine(srv.Name))
	fmt.Fprintf(&b, "port %d\nproto %s\ndev %s\ndev-type tun\ntopology subnet\n", c.Port, pr, n)
	fmt.Fprintf(&b, "server %s %s\n", n4.Masked().Addr(), mask4(n4))
	if c.Net6 != "" {
		fmt.Fprintf(&b, "server-ipv6 %s\n", c.Net6)
	}
	fmt.Fprintf(&b, "client-config-dir %s/%s-ccd\nccd-exclusive\n", confDir, n)
	b.WriteString("keepalive 10 60\npersist-key\npersist-tun\nuser nobody\ngroup nogroup\n")
	b.WriteString("dh none\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n")
	b.WriteString("remote-cert-tls client\nallow-compression no\n")
	if c.Transport == "udp" {
		b.WriteString("explicit-exit-notify 1\n")
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "tun-mtu %d\nmssfix\n", c.MTU)
	}
	fmt.Fprintf(&b, "management %s unix\nmanagement-client-user root\n", sockPath(srv))
	b.WriteString("verb 3\nmute 20\n")
	if c.Internet {
		if c.Net6 != "" {
			b.WriteString("push \"redirect-gateway def1 ipv6 bypass-dhcp\"\n")
		} else {
			b.WriteString("push \"redirect-gateway def1 bypass-dhcp\"\n")
		}
		dns := c.DNS
		if dns == "auto" || dns == oldDefaultDNS {
			dns = oldDefaultDNS
			if env != nil && env.Global.PanelDNS { // Tunneladressen des Servers – dort antwortet der Panel-DNS
				dns = n4.Masked().Addr().Next().String()
				if c.Net6 != "" {
					if n6, err := netip.ParsePrefix(c.Net6); err == nil {
						dns += ", " + n6.Masked().Addr().Next().String()
					}
				}
			}
		}
		for _, d := range strings.Split(dns, ",") {
			d = strings.TrimSpace(d)
			if a, err := netip.ParseAddr(d); err == nil {
				if a.Is4() {
					fmt.Fprintf(&b, "push \"dhcp-option DNS %s\"\n", a)
				} else if c.Net6 != "" {
					fmt.Fprintf(&b, "push \"dhcp-option DNS6 %s\"\n", a)
				}
			}
		}
	}
	b.WriteString(block("ca", proto.Str(srv.State, "ca_cert")))
	b.WriteString(block("cert", proto.Str(srv.State, "server_cert")))
	b.WriteString(block("key", proto.Str(srv.State, "server_key")))
	b.WriteString(block("tls-crypt", proto.Str(srv.State, "tls_crypt")))
	return b.String()
}

// hostHasIPv6: Ohne IPv6 im Kernel schlägt „udp6“ fehl – dann nur IPv4 lauschen.
func hostHasIPv6(env *proto.Env) bool {
	b, err := env.Sys.ReadFile("/proc/net/if_inet6")
	return err == nil && len(strings.TrimSpace(string(b))) > 0
}

func ccdConf(sc serverCfg, pc peerCfg, targets []proto.NetTarget) string {
	n4, _ := netip.ParsePrefix(sc.Net4)
	s := fmt.Sprintf("ifconfig-push %s %s\n", pc.Address4, mask4(n4))
	has6 := sc.Net6 != "" && pc.Address6 != ""
	if has6 {
		n6, _ := netip.ParsePrefix(sc.Net6)
		srv6, _ := addrAt(n6, 1)
		s += fmt.Sprintf("ifconfig-ipv6-push %s/%d %s\n", pc.Address6, n6.Bits(), srv6)
	}
	// Freigegebene Netze (Netzwerk → Zugriff): ohne Internet über den Server braucht das Gerät
	// Routen dafür (mit „redirect-gateway“ geht ohnehin alles durch den Tunnel)
	if !sc.Internet {
		for _, t := range targets {
			for _, p := range t.Nets {
				if p.Addr().Is4() {
					s += fmt.Sprintf("push \"route %s %s\"\n", p.Masked().Addr(), mask4(p))
				} else if has6 {
					s += fmt.Sprintf("push \"route-ipv6 %s\"\n", p.Masked())
				}
			}
		}
	}
	return s
}

func (Driver) Apply(env *proto.Env, servers []*proto.ServerBundle) error {
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
	if err := applyFirewall(env, servers); err != nil {
		errs = append(errs, "Firewall: "+err.Error())
	}
	// Entfernte/deaktivierte Instanzen abbauen
	var prev []string
	_ = json.Unmarshal([]byte(env.GetState("ovpn:instances")), &prev)
	for _, n := range prev {
		if want[n] {
			continue
		}
		_, _ = sys.Run("systemctl", "disable", "--now", "vpn-openvpn@"+n)
		_ = sys.Remove(confDir + "/" + n + ".conf")
		for _, cn := range strings.Fields(env.GetState("ovpn:ccd:" + n)) {
			_ = sys.Remove(confDir + "/" + n + "-ccd/" + cn)
		}
		_ = sys.Remove(confDir + "/" + n + "-ccd")
		env.SetState("ovpn:ccd:"+n, "")
		env.SetState("tc:"+n, "")
		env.Log("info", "OpenVPN-Instanz "+n+" entfernt")
	}
	var now []string
	for n := range want {
		now = append(now, n)
	}
	sort.Strings(now)
	b, _ := json.Marshal(now)
	env.SetState("ovpn:instances", string(b))
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func applyServer(env *proto.Env, sb *proto.ServerBundle) error {
	sys := env.Sys
	srv := sb.Server
	c := load(srv)
	n := name(srv)
	if !sys.DryRun() && !hostHasIPv6(env) {
		c.Net6 = "" // IPv6 im Kernel aus → Tunnel nur mit IPv4 (sonst startet OpenVPN nicht)
	}
	if !sys.DryRun() {
		if !sys.Exists(binPath) {
			return fmt.Errorf("OpenVPN ist nicht installiert (%s fehlt – Setup-Script erneut ausführen)", binPath)
		}
		if !sys.Exists("/dev/net/tun") {
			return fmt.Errorf("/dev/net/tun fehlt – im Container auf dem Host freigeben (siehe README, Abschnitt OpenVPN)")
		}
	}
	if ch, err := sys.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	} else if ch {
		_, _ = sys.Run("systemctl", "daemon-reload")
	}
	changed, err := sys.WriteFile(confDir+"/"+n+".conf", []byte(serverConf(env, sb, c)), 0o600)
	if err != nil {
		return err
	}
	// ccd-Verzeichnis muss existieren (sonst startet OpenVPN nicht) und für „nobody“ lesbar sein:
	// OpenVPN liest die Einträge erst nach dem Wechsel des Benutzers.
	if !sys.DryRun() {
		if _, err := sys.Run("install", "-d", "-m", "0755", confDir, confDir+"/"+n+"-ccd"); err != nil {
			return err
		}
	}
	// Ein Eintrag pro aktivem Zugang, alle anderen entfernen (→ ccd-exclusive weist sie ab)
	active := map[string]bool{}
	var rules []shaping.IfaceRule
	for _, pb := range sb.Peers {
		if !ready(sb, pb) {
			continue
		}
		cn := proto.Str(pb.Peer.Secrets, "cn")
		pc := loadPeer(pb.Peer)
		if _, err := sys.WriteFile(confDir+"/"+n+"-ccd/"+cn, []byte(ccdConf(c, pc, env.Global.Net.For(pb.Peer.ID))), 0o644); err != nil {
			return err
		}
		active[cn] = true
		var pfx []netip.Prefix
		for _, s := range []string{pc.Address4, pc.Address6} {
			if a, err := netip.ParseAddr(s); err == nil {
				pfx = append(pfx, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		rules = append(rules, shaping.IfaceRule{ID: pb.Peer.ID, Down: pb.RateDown, Up: pb.RateUp, Prefixes: pfx})
	}
	for _, cn := range strings.Fields(env.GetState("ovpn:ccd:" + n)) {
		if !active[cn] && cnRe.MatchString(cn) {
			_ = sys.Remove(confDir + "/" + n + "-ccd/" + cn)
		}
	}
	var list []string
	for cn := range active {
		list = append(list, cn)
	}
	sort.Strings(list)
	env.SetState("ovpn:ccd:"+n, strings.Join(list, " "))

	unit := "vpn-openvpn@" + n
	restarted := false
	if changed {
		_, _ = sys.Run("systemctl", "enable", unit)
		if _, err := sys.Run("systemctl", "restart", unit); err != nil {
			return fmt.Errorf("OpenVPN neu starten: %w", err)
		}
		restarted = true
		env.Log("info", "OpenVPN „"+srv.Name+"“ konfiguriert und neu gestartet")
	} else if _, err := sys.Run("systemctl", "is-active", "--quiet", unit); err != nil {
		_, _ = sys.Run("systemctl", "enable", unit)
		if _, err := sys.Run("systemctl", "restart", unit); err != nil {
			return fmt.Errorf("OpenVPN starten: %w", err)
		}
		restarted = true
	}
	// Verbundene, aber nicht (mehr) erlaubte Zugänge sofort trennen
	if !restarted && !sys.DryRun() {
		ss, err := sessions(sockPath(srv))
		if err != nil {
			env.Log("warn", "OpenVPN „"+srv.Name+"“: Verbindungsliste: "+err.Error())
		}
		for _, s := range ss {
			if !active[s.CN] {
				if err := kill(sockPath(srv), s.ClientID); err != nil {
					env.Log("warn", "OpenVPN: Trennen von "+s.CN+": "+err.Error())
				}
			}
		}
	}
	if err := shaping.ApplyIface(sys, n, rules, env.GetState, env.SetState); err != nil {
		env.Log("warn", fmt.Sprintf("Geschwindigkeitsbegrenzung auf %s: %v", n, err))
	}
	return nil
}

func outIf(env *proto.Env) string {
	if env.Global.OutIf != "" {
		return env.Global.OutIf
	}
	return "eth0"
}

// applyFirewall: eigene Ketten VPNOV-FWD (Weiterleitung) und VPNOV-NAT. Geräte dürfen nur ins
// Internet (wenn erlaubt), nicht untereinander und nicht in andere VPN-Netze.
func applyFirewall(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	any := false
	for _, sb := range servers {
		any = any || sb.Server.Enabled
	}
	if !any {
		if env.GetState("ovpn:fw") == "" {
			return nil
		}
		for _, bin := range []string{"iptables", "ip6tables"} {
			_, _ = sys.Run(bin, "-D", "FORWARD", "-j", "VPNOV-FWD")
			_, _ = sys.Run(bin, "-F", "VPNOV-FWD")
			_, _ = sys.Run(bin, "-X", "VPNOV-FWD")
			_, _ = sys.Run(bin, "-t", "nat", "-D", "POSTROUTING", "-j", "VPNOV-NAT")
			_, _ = sys.Run(bin, "-t", "nat", "-F", "VPNOV-NAT")
			_, _ = sys.Run(bin, "-t", "nat", "-X", "VPNOV-NAT")
		}
		env.SetState("ovpn:fw", "")
		return nil
	}
	out := outIf(env)
	for _, v6 := range []bool{false, true} {
		var filter, nat strings.Builder
		filter.WriteString("*filter\n:VPNOV-FWD - [0:0]\n-F VPNOV-FWD\n-A VPNOV-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n")
		nat.WriteString("*nat\n:VPNOV-NAT - [0:0]\n-F VPNOV-NAT\n")
		for _, sb := range servers {
			if !sb.Server.Enabled {
				continue
			}
			c := load(sb.Server)
			iface := name(sb.Server)
			net := c.Net4
			if v6 {
				net = c.Net6
			}
			if c.Internet && net != "" {
				// keine privaten Ziele (internes Netz, Proxmox-Host) und nicht der Server selbst
				for _, p := range env.Global.Private.Allowed() {
					if p.Addr().Is4() != v6 {
						fmt.Fprintf(&filter, "-A VPNOV-FWD -i %s -o %s -d %s -j ACCEPT\n", iface, out, p)
					}
				}
				for _, p := range env.Global.Private.Blocked() {
					if p.Addr().Is4() != v6 {
						fmt.Fprintf(&filter, "-A VPNOV-FWD -i %s -o %s -d %s -j DROP\n", iface, out, p)
					}
				}
				fmt.Fprintf(&filter, "-A VPNOV-FWD -i %s -o %s -s %s -j ACCEPT\n", iface, out, net)
				if !v6 { // über Ausgänge (externe VPNs, Schnittstellen ex<ID>) – siehe Ziel-Regeln
					fmt.Fprintf(&filter, "-A VPNOV-FWD -i %s -o ex+ -s %s -j ACCEPT\n", iface, net)
				}
				fmt.Fprintf(&nat, "-A VPNOV-NAT -s %s -o %s -j MASQUERADE\n", net, out)
			}
			// Freigaben (Netzwerk → Zugriff): WireGuard-Netze, die einzelne Geräte erreichen dürfen
			for _, pb := range sb.Peers {
				if !ready(sb, pb) {
					continue
				}
				pc := loadPeer(pb.Peer)
				src := pc.Address4
				if v6 {
					src = pc.Address6
				}
				if src == "" {
					continue
				}
				for _, t := range env.Global.Net.For(pb.Peer.ID) {
					for _, p := range t.Nets {
						if p.Addr().Is4() != !v6 {
							continue
						}
						fmt.Fprintf(&filter, "-A VPNOV-FWD -i %s -o %s -s %s -d %s -j ACCEPT\n", iface, t.Iface, src, p)
					}
				}
			}
			fmt.Fprintf(&filter, "-A VPNOV-FWD -i %s -j DROP\n", iface)
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
		if _, err := sys.Run(bin, "-C", "FORWARD", "-j", "VPNOV-FWD"); err != nil {
			if _, err := sys.Run(bin, "-I", "FORWARD", "1", "-j", "VPNOV-FWD"); err != nil {
				return err
			}
		}
		if _, err := sys.Run(bin, "-t", "nat", "-C", "POSTROUTING", "-j", "VPNOV-NAT"); err != nil {
			if _, err := sys.Run(bin, "-t", "nat", "-A", "POSTROUTING", "-j", "VPNOV-NAT"); err != nil {
				return err
			}
		}
	}
	env.SetState("ovpn:fw", "1")
	return nil
}

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
		ss, err := sessions(sockPath(sb.Server))
		if err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
			continue
		}
		byCN := map[string]session{}
		for _, s := range ss {
			byCN[s.CN] = s
		}
		for _, pb := range sb.Peers {
			p := pb.Peer
			s, ok := byCN[proto.Str(p.Secrets, "cn")]
			if !ok {
				p.LastRx, p.LastTx = 0, 0
				continue
			}
			// Zähler gelten pro Verbindung: neue Verbindung → alles zählt, sonst die Differenz
			key := fmt.Sprintf("%d/%s", s.Since, s.ClientID)
			sk := "ovpn:sess:" + strconv.FormatInt(p.ID, 10)
			du, dd := s.Rx, s.Tx
			if env.GetState(sk) == key {
				du, dd = s.Rx-p.LastRx, s.Tx-p.LastTx
				if du < 0 {
					du = s.Rx
				}
				if dd < 0 {
					dd = s.Tx
				}
			} else {
				env.SetState(sk, key)
			}
			p.LastRx, p.LastTx = s.Rx, s.Tx
			res[p.ID] = proto.Usage{Up: du, Down: dd, Seen: now, Endpoint: s.Real}
		}
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return res, nil
}

// Live: Zähler der laufenden Verbindungen, Adresse und „verbunden seit“.
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
		ss, err := sessions(sockPath(sb.Server))
		if err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
			continue
		}
		byCN := map[string]session{}
		for _, s := range ss {
			byCN[s.CN] = s
		}
		for _, pb := range sb.Peers {
			if s, ok := byCN[proto.Str(pb.Peer.Secrets, "cn")]; ok {
				res[pb.Peer.ID] = proto.LiveSample{Up: s.Rx, Down: s.Tx, Online: true, Endpoint: s.Real, Since: s.Since}
			}
		}
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return res, nil
}

// ---------- Profil ----------

func profileHost(env *proto.Env, c serverCfg) string {
	h := c.Host
	if h == "" {
		h = env.Global.ServerHost
	}
	return strings.Trim(h, "[]")
}

var umlaute = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "Ä", "Ae", "Ö", "Oe", "Ü", "Ue", "ß", "ss")

func safeName(s string) string {
	s = umlaute.Replace(s)
	s = regexp.MustCompile(`[^A-Za-z0-9_-]+`).ReplaceAllString(s, "_")
	if s == "" || s == "_" {
		return "vpn"
	}
	return s
}

// Profile: .ovpn-Datei eines Zugangs (alles eingebettet). Läuft mit OpenVPN Connect,
// OpenVPN ab 2.4 und Firewalls wie OPNsense/pfSense.
func Profile(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) string {
	c := load(sb.Server)
	var b strings.Builder
	fmt.Fprintf(&b, "# OpenVPN – %s – %s (%s)\n", oneLine(sb.Server.Name), oneLine(pb.Peer.Name), oneLine(pb.User.Name))
	b.WriteString("client\ndev tun\n")
	fmt.Fprintf(&b, "proto %s\nremote %s %d\n", c.Transport, profileHost(env, c), c.Port)
	b.WriteString("resolv-retry infinite\nnobind\npersist-key\npersist-tun\n")
	fmt.Fprintf(&b, "remote-cert-tls server\nverify-x509-name %s name\ntls-version-min 1.2\n", proto.Str(sb.Server.State, "server_cn"))
	b.WriteString("verb 3\n")
	b.WriteString(block("ca", proto.Str(sb.Server.State, "ca_cert")))
	b.WriteString(block("cert", proto.Str(pb.Peer.Secrets, "cert")))
	b.WriteString(block("key", proto.Str(pb.Peer.Secrets, "key")))
	b.WriteString(block("tls-crypt", proto.Str(sb.Server.State, "tls_crypt")))
	return b.String()
}

// ProfileName: Dateiname der .ovpn-Datei.
func ProfileName(sb *proto.ServerBundle, pb *proto.PeerBundle) string {
	return safeName(sb.Server.Name) + "-" + safeName(pb.Peer.Name) + ".ovpn"
}

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
	c := load(sb.Server)
	pc := loadPeer(pb.Peer)
	addr := pc.Address4
	if pc.Address6 != "" {
		addr += " · " + pc.Address6
	}
	info := [][2]string{
		{"Server", fmt.Sprintf("%s:%d (%s)", profileHost(env, c), c.Port, strings.ToUpper(c.Transport))},
		{"Adresse im Tunnel", addr},
		{"Zertifikat", proto.Str(pb.Peer.Secrets, "cn")},
	}
	if t := notAfter(proto.Str(pb.Peer.Secrets, "cert")); !t.IsZero() {
		info = append(info, [2]string{"Gültig bis", t.Format("02.01.2006")})
	}
	ins := []string{
		"Handy/PC: OpenVPN Connect installieren und den QR-Code scannen bzw. den Import-Link öffnen – oder die .ovpn-Datei herunterladen und in der App importieren.",
		"Router/Firewall (z. B. OPNsense, pfSense): die .ovpn-Datei als Client-Profil importieren. Eine Fritz!Box kann kein OpenVPN.",
		"Jedes Gerät braucht einen eigenen Zugang – dasselbe Profil gleichzeitig auf zwei Geräten trennt das jeweils andere.",
	}
	if !pb.Active {
		ins = append([]string{"Dieser Zugang ist derzeit gesperrt bzw. deaktiviert – der Server weist ihn ab."}, ins...)
	}
	return &proto.ClientConfig{
		Title:        "OpenVPN – " + sb.Server.Name,
		Files:        []proto.File{{Name: ProfileName(sb, pb), Content: Profile(env, sb, pb)}},
		Info:         info,
		Instructions: ins,
	}, nil
}

// ShareLinks: OpenVPN steht nicht im Abo (keine der Abo-Apps kann OpenVPN).
func (Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	return nil
}

func (Driver) Ports(srv *store.Server) []proto.Port {
	c := load(srv)
	return []proto.Port{{Port: c.Port, Proto: c.Transport, Note: "OpenVPN " + srv.Name}}
}

func (Driver) Status(env *proto.Env, srv *store.Server) proto.Status {
	if !srv.Enabled {
		return proto.Status{Detail: "deaktiviert"}
	}
	c := load(srv)
	if env.Sys.DryRun() {
		return proto.Status{Running: true, Detail: name(srv) + " (Testmodus)"}
	}
	if _, err := env.Sys.Run("systemctl", "is-active", "--quiet", "vpn-openvpn@"+name(srv)); err != nil {
		return proto.Status{Detail: "OpenVPN läuft nicht"}
	}
	return proto.Status{Running: true, Detail: fmt.Sprintf("OpenVPN auf %s %d", strings.ToUpper(c.Transport), c.Port)}
}

// Sources: Adressen, von denen der Verkehr eines Geräts kommt (für Ziel-Regeln).
func (Driver) Sources(env *proto.Env, sb *proto.ServerBundle) map[int64][]netip.Prefix {
	out := map[int64][]netip.Prefix{}
	for _, pb := range sb.Peers {
		if !pb.Active {
			continue
		}
		pc := loadPeer(pb.Peer)
		for _, s := range []string{pc.Address4, pc.Address6} {
			if a, err := netip.ParseAddr(s); err == nil {
				out[pb.Peer.ID] = append(out[pb.Peer.ID], netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	return out
}
