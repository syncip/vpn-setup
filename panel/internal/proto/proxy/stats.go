package proxy

// Statistik und Anzeige (Links, Felder für die Oberfläche).

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// ---------- Statistik ----------

func (Driver) Collect(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.Usage, error) {
	mgr.Lock()
	defer mgr.Unlock()
	res := map[int64]proto.Usage{}
	now := time.Now().Unix()
	for _, sb := range servers {
		for _, pb := range sb.Peers {
			rt := mgr.peers[pb.Peer.ID]
			if rt == nil {
				continue
			}
			up, down := rt.up.Load(), rt.down.Load()
			u := proto.Usage{Up: up - rt.lastUp, Down: down - rt.lastDown}
			rt.lastUp, rt.lastDown = up, down
			if rt.conns > 0 || u.Up+u.Down > 0 {
				u.Seen = now
				u.Endpoint = rt.lastIP
			}
			if u.Up+u.Down > 0 || u.Seen > 0 {
				res[pb.Peer.ID] = u
			}
		}
	}
	return res, nil
}

func (Driver) Live(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.LiveSample, error) {
	mgr.Lock()
	defer mgr.Unlock()
	res := map[int64]proto.LiveSample{}
	for _, sb := range servers {
		for _, pb := range sb.Peers {
			rt := mgr.peers[pb.Peer.ID]
			if rt == nil {
				continue
			}
			s := proto.LiveSample{Up: rt.up.Load(), Down: rt.down.Load(), Online: rt.conns > 0}
			if s.Online {
				s.Endpoint, s.Since = rt.lastIP, rt.since
			}
			res[pb.Peer.ID] = s
		}
	}
	return res, nil
}

// ---------- Anzeige ----------

func linkHost(env *proto.Env, c serverCfg) string {
	if c.Host != "" {
		return c.Host
	}
	if env.Global.ServerHost != "" {
		return env.Global.ServerHost
	}
	return "SERVER"
}

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
	c := load(sb.Server)
	host := linkHost(env, c)
	user, pass := proto.Str(pb.Peer.Secrets, "username"), proto.Str(pb.Peer.Secrets, "password")
	ui := url.UserPassword(user, pass)
	info := [][2]string{{"Server", host}}
	var links []proto.Link
	if c.Socks {
		info = append(info, [2]string{"SOCKS5-Port", strconv.Itoa(c.SocksPort)})
		// socks5h: Namen löst der Proxy auf (DNS über den Ausgang, keine IPv6-Ziele vom Client)
		links = append(links, proto.Link{Label: "SOCKS5", URL: (&url.URL{Scheme: "socks5h", User: ui, Host: net.JoinHostPort(host, strconv.Itoa(c.SocksPort))}).String()})
	}
	if c.HTTP {
		info = append(info, [2]string{"HTTP-Proxy-Port", strconv.Itoa(c.HTTPPort)})
		links = append(links, proto.Link{Label: "HTTP-Proxy", URL: (&url.URL{Scheme: "http", User: ui, Host: net.JoinHostPort(host, strconv.Itoa(c.HTTPPort))}).String()})
	}
	info = append(info, [2]string{"Benutzername", user}, [2]string{"Passwort", pass})
	exit := "direkt über den Server"
	if pol := env.Global.Policies[pb.Peer.ID]; pol != nil {
		if g, ok := env.Global.Groups[pol.Rules[0].Group]; len(pol.Rules) == 1 && pol.Rules[0].All && ok {
			exit = "Ausgangsgruppe „" + g.Name + "“"
		} else {
			exit = fmt.Sprintf("nach Ziel-Regeln (%d)", len(pol.Rules))
		}
	}
	info = append(info, [2]string{"Ausgang", exit})
	if s := strList(pb.Peer.Settings["source_ips"]); len(s) > 0 {
		info = append(info, [2]string{"Anmeldung per IP", strings.Join(s, ", ")})
	}
	return &proto.ClientConfig{
		Title: "Proxy – " + sb.Server.Name,
		Links: links,
		Info:  info,
		Instructions: []string{
			"In der App bzw. in den Netzwerkeinstellungen des Geräts einen Proxy eintragen: Server, Port, Benutzername und Passwort.",
			"SOCKS5 ist für Apps meist die bessere Wahl; Fernseher und Browser kennen oft nur „HTTP-Proxy“.",
			"Kann ein Gerät kein Passwort (häufig bei Fernsehern), beim Zugang unter „Erweitert“ die feste öffentliche IP des Anschlusses für die Anmeldung per IP eintragen.",
			"Achtung: Die Verbindung zum Proxy ist unverschlüsselt – Benutzername und Passwort können unterwegs mitgelesen werden. Inhalte von HTTPS-Seiten bleiben verschlüsselt.",
		},
	}, nil
}

func (Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	return nil
}

func (Driver) Ports(srv *store.Server) []proto.Port {
	c := load(srv)
	var out []proto.Port
	if c.Socks {
		out = append(out, proto.Port{Port: c.SocksPort, Proto: "tcp", Note: "SOCKS5-Proxy " + srv.Name})
	}
	if c.HTTP {
		out = append(out, proto.Port{Port: c.HTTPPort, Proto: "tcp", Note: "HTTP-Proxy " + srv.Name})
	}
	return out
}

func (Driver) Status(env *proto.Env, srv *store.Server) proto.Status {
	if !srv.Enabled {
		return proto.Status{Detail: "deaktiviert"}
	}
	mgr.Lock()
	defer mgr.Unlock()
	in := mgr.inst[srv.ID]
	if in == nil {
		return proto.Status{Detail: "noch nicht gestartet"}
	}
	if in.err != "" {
		return proto.Status{Detail: in.err}
	}
	var parts []string
	if in.socks != nil {
		parts = append(parts, fmt.Sprintf("SOCKS5 %d", in.cfg.SocksPort))
	}
	if in.http != nil {
		parts = append(parts, fmt.Sprintf("HTTP %d", in.cfg.HTTPPort))
	}
	if len(parts) == 0 {
		return proto.Status{Detail: "SOCKS5 und HTTP ausgeschaltet"}
	}
	n := 0
	for t := range mgr.conns {
		if t.inst == in {
			n++
		}
	}
	detail := strings.Join(parts, ", ") + fmt.Sprintf(" – %d Verbindungen", n)
	if g, ok := mgr.groups[groupOf(in.cfg)]; ok {
		if !g.Enabled {
			detail += " – Ausgangsgruppe „" + g.Name + "“ ist deaktiviert, Verkehr geht direkt"
		} else {
			detail += " – über „" + g.Name + "“"
		}
	}
	return proto.Status{Running: true, Detail: detail}
}

// strList: Liste aus den Einstellungen ([]any aus der Datenbank oder []string).
func strList(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		var out []string
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
