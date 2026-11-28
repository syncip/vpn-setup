package wireguard

// Netz-Logik (Stern, Erreichbarkeit) und Anwenden (wgN.conf, Routen, Firewall, Drosselung).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/shaping"
)

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

// accessMode: wirksamer Zugriff des Geräts (all | own | none | custom)
func accessMode(sc serverCfg, n *node) string {
	mode := n.cfg.Access
	if mode == "" || mode == "default" {
		mode = sc.DefaultAccess
	}
	return mode
}

// reachable: welche anderen Geräte darf n erreichen?
func reachable(sc serverCfg, n *node, all []*node) []*node {
	mode := accessMode(sc, n)
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
		// über stdin statt einer Zwischendatei (AppArmor erlaubt wg auf manchen Systemen keine eigenen Pfade)
		if _, err = sys.RunInput(stripped, "wg", "syncconf", iface, "/dev/stdin"); err != nil {
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
			// Keine privaten Ziele (internes Netz, Proxmox-Host) und nicht der Server selbst über den Internet-Ausgang
			for _, a := range pick(env.Global.Private.Allowed()) {
				fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -d %s -j ACCEPT\n", iface, out, a)
			}
			for _, b := range pick(env.Global.Private.Blocked()) {
				fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -d %s -j DROP\n", iface, out, b)
			}
			for _, n := range all {
				srcs := pick(n.all())
				if accessMode(sc, n) == "all" {
					// darf alle Geräte dieses Servers erreichen: eine Regel je Quelle statt je Paar
					// (sonst wächst die Kette quadratisch – 150 Geräte ≈ 22 000 Regeln)
					for _, s := range srcs {
						fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -s %s -j ACCEPT\n", iface, iface, s)
					}
				} else {
					for _, t := range reachable(sc, n, all) {
						dsts := pick(t.all())
						for _, s := range srcs {
							for _, dd := range dsts {
								fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -s %s -d %s -j ACCEPT\n", iface, iface, s, dd)
							}
						}
					}
				}
				// Freigaben (Netzwerk → Zugriff): andere bzw. eigene WireGuard-Netze
				for _, t := range env.Global.Net.For(n.pb.Peer.ID) {
					for _, s := range srcs {
						for _, dd := range pick(t.Nets) {
							fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -s %s -d %s -j ACCEPT\n", iface, t.Iface, s, dd)
						}
					}
				}
				if sc.Internet {
					for _, s := range srcs {
						fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o %s -s %s -j ACCEPT\n", iface, out, s)
						if !v6 { // über Ausgänge (externe VPNs, Schnittstellen ex<ID>) – siehe Ziel-Regeln
							fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -o ex+ -s %s -j ACCEPT\n", iface, s)
						}
					}
				}
			}
			fmt.Fprintf(&filter, "-A VPNWG-FWD -i %s -j DROP\n", iface)
			// Zugriff aus anderen Netzen: Absender bekommt die Serveradresse dieses Netzes (Rückweg)
			for _, s := range pick(env.Global.Net.MasqFor(iface)) {
				fmt.Fprintf(&nat, "-A VPNWG-NAT -s %s -o %s -j MASQUERADE\n", s, iface)
			}
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
	var rules []shaping.IfaceRule
	for _, n := range nodes(sb, true) {
		rules = append(rules, shaping.IfaceRule{ID: n.pb.Peer.ID, Down: n.pb.RateDown, Up: n.pb.RateUp, Prefixes: n.all()})
	}
	return shaping.ApplyIface(env.Sys, iface, rules, env.GetState, env.SetState)
}

func mbit(v float64) string { return strconv.FormatFloat(v*1000, 'f', 0, 64) + "kbit" }
