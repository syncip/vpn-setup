package engine

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"vpnpanel/internal/proto"
)

// Firewall des Panels: eine eigene nftables-Tabelle „inet vpnpanel“, bei jeder Änderung als Ganzes
// (atomar) neu geladen. Sie enthält
//   - die Sperr-/Freigabelisten je Server (Kette vp_in, pro Liste ein Set – auch große Online-Listen
//     kosten so pro Paket nur eine Suche),
//   - die Ziel-Regeln für Geräte, deren Verkehr weitergeleitet wird (WireGuard, OpenVPN): Kette vp_pre
//     markiert Pakete je nach Quelle und Ziel mit der Markierung der Ausgangsgruppe,
//   - die DNS-Umleitung zum Panel-DNS (Kette vp_dns), die Sperre für verschlüsseltes DNS und
//   - die IPv6-Sperre für Geräte, deren ganzer Verkehr über einen (IPv4-)Ausgang läuft (Kette vp_fwd).
//
// Die iptables-Ketten der Protokolltreiber (VPNWG-*, VPNOV-*, VPNEX-*) bleiben daneben bestehen.

const (
	nftTable = "vpnpanel"
	dnsPort  = 5399 // lokaler Port des DNS-Umleiters
)

// srcPolicy: Adressen eines Geräts, dessen Verkehr weitergeleitet wird, mit dem, was für es gilt.
type srcPolicy struct {
	pfx  netip.Prefix
	pol  *proto.Policy // Ziel-Regeln (nil = keine)
	peer int64
	user int64
	filt *dnsFilter // Filterprofil (nil = keins)
	dns  bool       // DNS-Anfragen an den Panel-DNS umleiten
	doh  bool       // verschlüsseltes DNS (DoH/DoT) sperren
}

// forwardSources: Quelladressen aller Geräte, deren Verkehr weitergeleitet wird und für die
// Ziel-Regeln oder der Panel-DNS gelten.
func (e *Engine) forwardSources(env *proto.Env, snap *Snapshot, rt *routing) []srcPolicy {
	var out []srcPolicy
	seen := map[netip.Prefix]bool{}
	panelDNS := e.Setting("dns_enabled") == "1"
	filters := map[int64]*dnsFilter{}
	if panelDNS {
		filters = e.compileDNSFilters(snap)
	}
	for _, d := range proto.All() {
		f, ok := d.(proto.Forwarder)
		if !ok {
			continue
		}
		for _, sb := range snap.ByProto[d.Info().ID] {
			if !sb.Server.Enabled {
				continue
			}
			for id, pfxs := range f.Sources(env, sb) {
				pol := rt.Policies[id]
				if pol == nil && !panelDNS {
					continue
				}
				sp := srcPolicy{pol: pol, peer: id, filt: filters[id], dns: panelDNS || pol.HasDomains()}
				if pb := snap.Peers[id]; pb != nil {
					sp.user = pb.User.ID
				}
				sp.doh = pol.HasDomains() || (sp.filt != nil && sp.filt.BlockDoH)
				for _, p := range pfxs {
					p = p.Masked()
					if !seen[p] && p.Bits() > 0 {
						seen[p] = true
						sp.pfx = p
						out = append(out, sp)
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].pfx.Addr().Compare(out[j].pfx.Addr()); c != 0 {
			return c < 0
		}
		return out[i].pfx.Bits() < out[j].pfx.Bits()
	})
	return out
}

func joinPfx(ps []netip.Prefix) string {
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteString(", ")
			if i%8 == 0 {
				b.WriteString("\n\t\t\t")
			}
		}
		if p.IsSingleIP() {
			b.WriteString(p.Addr().String())
		} else {
			b.WriteString(p.String())
		}
	}
	return b.String()
}

// nftScript erzeugt die Tabelle. dyn liefert die bekannten Adressen einer Domain-Regel (mit
// Restlaufzeit); static = ohne diese (für den Vergleich, ob sich etwas geändert hat).
func (e *Engine) nftScript(snap *Snapshot, rt *routing, plan *aclPlan, srcs []srcPolicy, dyn func(ruleID int64) []string) (script, static string, needed bool) {
	var sets, chains strings.Builder
	var dynSets []int64
	defined := map[string]bool{}
	// listSet legt (einmal) die Sets einer Liste an und meldet, ob es IPv4- bzw. IPv6-Einträge gibt.
	listSet := func(id int64, v4, v6 []netip.Prefix) (has4, has6 bool) {
		name := fmt.Sprintf("l%d", id)
		if !defined[name] {
			defined[name] = true
			if len(v4) > 0 {
				fmt.Fprintf(&sets, "\tset %s_4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}\n", name, joinPfx(v4))
			}
			if len(v6) > 0 {
				fmt.Fprintf(&sets, "\tset %s_6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}\n", name, joinPfx(v6))
			}
		}
		return len(v4) > 0, len(v6) > 0
	}

	// ---------- Sperr-/Freigabelisten ----------
	var inp strings.Builder
	var sids []int64
	for id := range plan.ByServer {
		sids = append(sids, id)
	}
	sort.Slice(sids, func(i, j int) bool { return sids[i] < sids[j] })
	for _, sid := range sids {
		var sb *proto.ServerBundle
		for _, x := range snap.Servers {
			if x.Server.ID == sid {
				sb = x
			}
		}
		if sb == nil || !sb.Server.Enabled {
			continue
		}
		d, ok := proto.Get(sb.Server.Protocol)
		if !ok {
			continue
		}
		if s, ok := d.(proto.SelfACL); ok && s.SelfACL() {
			continue
		}
		var jumps []string
		for _, p := range d.Ports(sb.Server) {
			if p.To > 0 || p.Port <= 0 {
				continue // Bereiche (Port-Hopping) werden auf den Hauptport umgeleitet
			}
			jumps = append(jumps, fmt.Sprintf("\t\t%s dport %d jump acl_%d\n", p.Proto, p.Port, sid))
		}
		if len(jumps) == 0 {
			continue
		}
		a := plan.ByServer[sid]
		fmt.Fprintf(&chains, "\tchain acl_%d {\n", sid)
		for _, lid := range a.Deny {
			v4, v6 := e.listPrefixes(plan.Lists[lid])
			h4, h6 := listSet(lid, v4, v6)
			if h4 {
				fmt.Fprintf(&chains, "\t\tip saddr @l%d_4 drop\n", lid)
			}
			if h6 {
				fmt.Fprintf(&chains, "\t\tip6 saddr @l%d_6 drop\n", lid)
			}
		}
		if a.AllowOnly {
			for _, lid := range a.Allow {
				v4, v6 := e.listPrefixes(plan.Lists[lid])
				h4, h6 := listSet(lid, v4, v6)
				if h4 {
					fmt.Fprintf(&chains, "\t\tip saddr @l%d_4 return\n", lid)
				}
				if h6 {
					fmt.Fprintf(&chains, "\t\tip6 saddr @l%d_6 return\n", lid)
				}
			}
			chains.WriteString("\t\tdrop\n")
		}
		chains.WriteString("\t}\n")
		for _, j := range jumps {
			inp.WriteString(j)
		}
	}
	if inp.Len() > 0 {
		fmt.Fprintf(&chains, "\tchain vp_in {\n\t\ttype filter hook input priority -10; policy accept;\n%s\t}\n", inp.String())
	}

	// ---------- Ziel-Regeln für weitergeleiteten Verkehr ----------
	if len(srcs) > 0 {
		done := map[string]bool{}
		var src4, dns4, dns6, doh4, doh6, all6 []string
		for _, s := range srcs {
			pol := s.pol
			allGroup, hasAll := pol.AllGroup()
			if !s.pfx.Addr().Is4() {
				if hasAll && allGroup != 0 {
					all6 = append(all6, s.pfx.String())
				}
				if s.dns {
					dns6 = append(dns6, s.pfx.String())
				}
				if s.doh {
					doh6 = append(doh6, s.pfx.String())
				}
				continue
			}
			if s.dns {
				dns4 = append(dns4, s.pfx.String())
			}
			if s.doh {
				doh4 = append(doh4, s.pfx.String())
			}
			if pol == nil {
				continue
			}
			src4 = append(src4, fmt.Sprintf("%s : jump pol_%s", s.pfx, pol.Key))
			if done[pol.Key] {
				continue
			}
			done[pol.Key] = true
			fmt.Fprintf(&chains, "\tchain pol_%s {\n", pol.Key)
			for _, r := range pol.Rules {
				act := "return"
				if r.Group != 0 {
					g := rt.Groups[r.Group]
					act = fmt.Sprintf("meta mark set 0x%08x return", g.Mark)
				}
				if r.All {
					fmt.Fprintf(&chains, "\t\t%s\n", act)
					break
				}
				if len(r.Nets) > 0 {
					fmt.Fprintf(&chains, "\t\tip daddr { %s } %s\n", joinPfx(r.Nets), act)
				}
				for _, lid := range r.Lists {
					if h4, _ := listSet(lid, rt.TargetLists[lid], nil); h4 {
						fmt.Fprintf(&chains, "\t\tip daddr @l%d_4 %s\n", lid, act)
					}
				}
				if len(r.Domains) > 0 {
					name := fmt.Sprintf("d%d", r.ID)
					if !defined[name] {
						defined[name] = true
						dynSets = append(dynSets, r.ID)
					}
					fmt.Fprintf(&chains, "\t\tip daddr @%s %s\n", name, act)
				}
			}
			chains.WriteString("\t}\n")
		}
		if len(src4) > 0 {
			fmt.Fprintf(&sets, "\tset private4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 }\n\t}\n")
			fmt.Fprintf(&sets, "\tmap src4 {\n\t\ttype ipv4_addr : verdict\n\t\tflags interval\n\t\telements = { %s }\n\t}\n", strings.Join(src4, ",\n\t\t\t"))
			chains.WriteString("\tchain vp_pre {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n" +
				"\t\tfib daddr type local return\n\t\tip daddr @private4 return\n\t\tip saddr vmap @src4\n\t}\n")
		}
		var fwd, nat strings.Builder
		set := func(name, typ string, el []string) {
			fmt.Fprintf(&sets, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\telements = { %s }\n\t}\n", name, typ, strings.Join(el, ", "))
		}
		// DNS-Anfragen (auch über IPv6) gehen an den Panel-DNS, egal welchen Server das Gerät eingetragen hat
		if len(dns4) > 0 {
			set("dnssrc", "ipv4_addr", dns4)
			fmt.Fprintf(&nat, "\t\tip saddr @dnssrc udp dport 53 redirect to :%d\n\t\tip saddr @dnssrc tcp dport 53 redirect to :%d\n", dnsPort, dnsPort)
		}
		if len(dns6) > 0 {
			set("dnssrc6", "ipv6_addr", dns6)
			fmt.Fprintf(&nat, "\t\tip6 saddr @dnssrc6 udp dport 53 redirect to :%d\n\t\tip6 saddr @dnssrc6 tcp dport 53 redirect to :%d\n", dnsPort, dnsPort)
		}
		// Verschlüsseltes DNS abweisen: DNS über TLS (Android „Privates DNS: automatisch“ fällt dann auf
		// normales DNS zurück) und DoH direkt per Adresse (https://1.1.1.1/dns-query u. ä.)
		if len(doh4) > 0 {
			set("dohsrc", "ipv4_addr", doh4)
			fwd.WriteString("\t\tip saddr @dohsrc tcp dport 853 reject with tcp reset\n")
			fwd.WriteString("\t\tip saddr @dohsrc ip daddr { 1.0.0.1, 1.1.1.1, 8.8.4.4, 8.8.8.8, 9.9.9.9, 149.112.112.112 } tcp dport 443 reject with tcp reset\n")
			fwd.WriteString("\t\tip saddr @dohsrc ip daddr { 1.0.0.1, 1.1.1.1, 8.8.4.4, 8.8.8.8, 9.9.9.9, 149.112.112.112 } udp dport 443 reject\n")
		}
		if len(doh6) > 0 {
			set("dohsrc6", "ipv6_addr", doh6)
			fwd.WriteString("\t\tip6 saddr @dohsrc6 tcp dport 853 reject with tcp reset\n")
			fwd.WriteString("\t\tip6 saddr @dohsrc6 ip6 daddr { 2001:4860:4860::8844, 2001:4860:4860::8888, 2606:4700:4700::1001, 2606:4700:4700::1111, 2620:fe::9, 2620:fe::fe } tcp dport 443 reject with tcp reset\n")
			fwd.WriteString("\t\tip6 saddr @dohsrc6 ip6 daddr { 2001:4860:4860::8844, 2001:4860:4860::8888, 2606:4700:4700::1001, 2606:4700:4700::1111, 2620:fe::9, 2620:fe::fe } udp dport 443 reject\n")
		}
		if nat.Len() > 0 {
			fmt.Fprintf(&chains, "\tchain vp_dns {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n%s\t}\n", nat.String())
		}
		if len(all6) > 0 {
			fmt.Fprintf(&sets, "\tset all6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n", strings.Join(all6, ", "))
			fwd.WriteString("\t\tip6 saddr @all6 ip6 daddr != fc00::/7 reject with icmpv6 admin-prohibited\n")
		}
		if fwd.Len() > 0 {
			fmt.Fprintf(&chains, "\tchain vp_fwd {\n\t\ttype filter hook forward priority -10; policy accept;\n%s\t}\n", fwd.String())
		}
	}
	if chains.Len() == 0 {
		return "", "", false
	}
	head := fmt.Sprintf("add table inet %s\ndelete table inet %s\ntable inet %s {\n", nftTable, nftTable, nftTable)
	var dynStatic, dynFull strings.Builder
	sort.Slice(dynSets, func(i, j int) bool { return dynSets[i] < dynSets[j] })
	for _, id := range dynSets {
		def := fmt.Sprintf("\tset d%d {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\ttimeout %ds\n\t\tsize 65535\n", id, int(dnsKeep.Seconds()))
		dynStatic.WriteString(def + "\t}\n")
		dynFull.WriteString(def)
		if el := dyn(id); len(el) > 0 {
			fmt.Fprintf(&dynFull, "\t\telements = { %s }\n", strings.Join(el, ", "))
		}
		dynFull.WriteString("\t}\n")
	}
	return head + sets.String() + dynFull.String() + chains.String() + "}\n", head + sets.String() + dynStatic.String() + chains.String() + "}\n", true
}

// applyNft lädt die Tabelle neu, wenn sich etwas geändert hat.
func (e *Engine) applyNft(env *proto.Env, snap *Snapshot, rt *routing, plan *aclPlan) error {
	return e.applyNftWith(snap, rt, plan, e.forwardSources(env, snap, rt))
}

// applyNftWith: wie applyNft, mit vorgegebenen Quellen (Labortests ohne echte VPN-Dienste).
func (e *Engine) applyNftWith(snap *Snapshot, rt *routing, plan *aclPlan, srcs []srcPolicy) error {
	e.removeLegacyACL()
	e.dns.configure(e, srcs, rt)
	script, static, needed := e.nftScript(snap, rt, plan, srcs, e.dns.elements)
	const stateKey = "state:nft"
	prev := e.St.GetSetting(stateKey, "")
	if !needed {
		if prev != "" {
			_, _ = e.Sys.Run("nft", "delete", "table", "inet", nftTable)
			_ = e.St.SetSetting(stateKey, "")
		}
		return nil
	}
	sig := hashStr(static) + fmt.Sprint(len(static))
	if prev == sig {
		if _, err := e.Sys.Run("nft", "-t", "list", "table", "inet", nftTable); err == nil {
			return nil
		}
	}
	if out, err := e.Sys.RunInput(script, "nft", "-f", "-"); err != nil {
		msg := strings.TrimSpace(out)
		if len(msg) > 400 {
			msg = msg[:400] + " …"
		}
		if strings.Contains(err.Error(), "executable file not found") || strings.Contains(err.Error(), "no such file") {
			return fmt.Errorf("nftables fehlt (Paket „nftables“ installieren bzw. Setup-Script erneut ausführen)")
		}
		return fmt.Errorf("nftables: %v %s", err, msg)
	}
	_ = e.St.SetSetting(stateKey, sig)
	return nil
}

// groupMarkOf: Markierung einer Gruppe (0 = unbekannt/deaktiviert).
func groupMarkOf(groups map[int64]proto.GroupRoute, id int64) uint32 {
	if g, ok := groups[id]; ok && g.Enabled {
		return g.Mark
	}
	return 0
}
