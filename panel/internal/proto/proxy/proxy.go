// Package proxy: SOCKS5- und HTTP-Proxy mit Anmeldung (Benutzername/Passwort oder Client-IP),
// direkt im Panel-Prozess. Verbindungen laufen auf Wunsch über eine Ausgangsgruppe (externe VPNs,
// Paket exits): Sockets bekommen die Markierung der Gruppe, DNS wird ebenfalls über die Gruppe
// abgefragt. Nur IPv4 nach draußen.
//
// Weil alles im Prozess läuft, kennt das Panel jeden Zugang sofort: gesperrte Nutzer werden beim
// nächsten Anwenden getrennt, die Drosselung pro Nutzer ist ein Token-Bucket, Statistik und
// Online-Status kommen ohne Umweg.
package proxy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

const (
	handshakeTimeout = 15 * time.Second
	idleTimeout      = 10 * time.Minute
	maxPerIP         = 512
	maxTotal         = 8192
)

type serverCfg struct {
	Socks     bool   `json:"socks"`
	SocksPort int    `json:"socks_port"`
	HTTP      bool   `json:"http"`
	HTTPPort  int    `json:"http_port"`
	Group     any    `json:"group"` // ID der Ausgangsgruppe, 0/leer = direkt über den Server
	Host      string `json:"host"`
	MaxConns  int    `json:"max_conns"`
	BlockSMTP bool   `json:"block_smtp"`
}

func load(srv *store.Server) serverCfg {
	c := serverCfg{Socks: true, SocksPort: 1080, HTTP: true, HTTPPort: 8080, MaxConns: 256, BlockSMTP: true}
	_ = proto.Decode(srv.Settings, &c)
	return c
}

func groupOf(c serverCfg) int64 {
	switch v := c.Group.(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

type Driver struct{}

func init() { proto.Register(Driver{}) }

func (Driver) Info() proto.Info {
	return proto.Info{
		ID:          "proxy",
		Label:       "Proxy",
		Description: "SOCKS5- und HTTP-Proxy mit Benutzername und Passwort – für Fernseher und Apps. Auf Wunsch über eine Ausgangsgruppe (externes VPN, anderer Standort). Unverschlüsselt.",
		ServerFields: []proto.Field{
			{Key: "group", Label: "Ausgang", Type: "exitgroup", Default: 0,
				Help: "Ausgangsgruppe (Menü „Proxy“ → Ausgänge), über die der Verkehr läuft. „Direkt“ = über die Adresse dieses Servers."},
			{Key: "socks", Label: "SOCKS5 aktiv", Type: "bool", Default: true},
			{Key: "socks_port", Label: "SOCKS5-Port (TCP)", Type: "number", Default: 1080,
				Help: "Muss auf dem Proxmox-Host per TCP an den Container weitergeleitet werden."},
			{Key: "http", Label: "HTTP-Proxy aktiv", Type: "bool", Default: true},
			{Key: "http_port", Label: "HTTP-Proxy-Port (TCP)", Type: "number", Default: 8080,
				Help: "Muss auf dem Proxmox-Host per TCP an den Container weitergeleitet werden."},
			{Key: "max_conns", Label: "Max. gleichzeitige Verbindungen pro Zugang", Type: "number", Default: 256, Advanced: true},
			{Key: "block_smtp", Label: "Mailversand (Port 25) sperren", Type: "bool", Default: true, Advanced: true,
				Help: "Verhindert, dass über den Proxy Spam verschickt wird."},
			{Key: "host", Label: "Adresse in den Zugangsdaten", Type: "text", Advanced: true, Placeholder: "Server-Domain aus den Einstellungen"},
		},
		PeerFields: []proto.Field{
			{Key: "source_ips", Label: "Anmeldung per IP (ohne Passwort)", Type: "cidrlist", Advanced: true, Placeholder: "z. B. 203.0.113.7",
				Help: "Für Geräte, die keinen Proxy mit Passwort können (z. B. viele Fernseher): Verbindungen von diesen Adressen gelten ohne Anmeldung als dieser Zugang. Nur feste Adressen eintragen!"},
		},
		Kinds: []proto.Kind{{ID: "access", Label: "Zugang", Icon: "key", Description: "Benutzername und Passwort für SOCKS5/HTTP.", Defaults: store.M{}}},
	}
}

var hostRe = netHostRe()

func netHostRe() func(string) bool {
	return func(h string) bool {
		if h == "" || len(h) > 253 {
			return false
		}
		for _, r := range h {
			if !(r == '.' || r == '-' || r == ':' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return false
			}
		}
		return true
	}
}

func (Driver) InitServer(env *proto.Env, srv *store.Server, all []*store.Server) error {
	c := load(srv)
	for _, p := range []struct {
		on   bool
		port int
		name string
	}{{c.Socks, c.SocksPort, "SOCKS5"}, {c.HTTP, c.HTTPPort, "HTTP"}} {
		if p.port < 1 || p.port > 65535 {
			return fmt.Errorf("%s-Port %d ungültig", p.name, p.port)
		}
		if !p.on {
			continue
		}
		if msg := proto.PortConflict(env.Global, all, srv.ID, "tcp", p.port, 0); msg != "" {
			return fmt.Errorf("%s", msg)
		}
	}
	if c.Socks && c.HTTP && c.SocksPort == c.HTTPPort {
		return fmt.Errorf("SOCKS5 und HTTP brauchen verschiedene Ports")
	}
	if g := groupOf(c); g != 0 {
		if _, ok := env.Global.Groups[g]; !ok {
			return fmt.Errorf("Ausgangsgruppe %d gibt es nicht", g)
		}
	}
	if c.MaxConns < 1 || c.MaxConns > 4096 {
		return fmt.Errorf("max. Verbindungen: 1–4096")
	}
	c.Host = strings.TrimSpace(c.Host)
	if c.Host != "" && !hostRe(c.Host) {
		return fmt.Errorf("Adresse %q ungültig", c.Host)
	}
	srv.Settings["group"] = groupOf(c)
	srv.Settings["host"] = c.Host
	return nil
}

const pwChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randStr(n int) string {
	b := proto.RandBytes(n)
	for i := range b {
		b[i] = pwChars[int(b[i])%len(pwChars)]
	}
	return string(b)
}

func (Driver) InitPeer(env *proto.Env, srv *store.Server, p *store.Peer, others []*store.Peer) error {
	p.Kind = "access"
	if proto.Str(p.Secrets, "username") == "" {
		used := map[string]bool{}
		for _, o := range others {
			used[proto.Str(o.Secrets, "username")] = true
		}
		for {
			u := "u" + strings.ToLower(randStr(7))
			if !used[u] {
				p.Secrets["username"] = u
				break
			}
		}
	}
	if proto.Str(p.Secrets, "password") == "" {
		p.Secrets["password"] = randStr(24)
	}
	// Anmeldung per IP: normalisieren, keine Netze größer als /24 bzw. /56
	ips := strList(p.Settings["source_ips"])
	if v, ok := p.Settings["source_ips"].(string); ok {
		ips = strings.Fields(strings.ReplaceAll(v, ",", " "))
	}
	var out []string
	for _, s := range ips {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		pf, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("Anmeldung per IP: %q ungültig", s)
		}
		if (pf.Addr().Is4() && pf.Bits() < 24) || (!pf.Addr().Is4() && pf.Bits() < 56) {
			return fmt.Errorf("Anmeldung per IP: %s ist zu groß (höchstens /24 bzw. /56)", pf)
		}
		out = append(out, pf.String())
	}
	if len(out) > 32 {
		return fmt.Errorf("Anmeldung per IP: höchstens 32 Einträge")
	}
	p.Settings["source_ips"] = out
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("ungültig")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("ungültig")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
