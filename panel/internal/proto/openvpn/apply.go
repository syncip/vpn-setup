package openvpn

// Netz-Hilfen und Anwenden (Instanzen vpn-openvpn@, Firewall).

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
)

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
