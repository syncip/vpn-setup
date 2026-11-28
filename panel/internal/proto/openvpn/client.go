package openvpn

// Statistik (Management-Schnittstelle) und Client-Profil (.ovpn).

import (
	"fmt"
	"net/netip"
	"regexp"
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
