package engine

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// IP-Listen: Sperrlisten (diese Adressen nie) und Freigabelisten (nur diese Adressen) je Server.
// Durchsetzung: iptables/ip6tables in INPUT auf den Ports des Servers (Kette VPNACL, pro Server
// eine Unterkette VPNACL-<ID>); VLESS (geteilter Port 443) regelt es selbst über Xray-Routing.

const maxIPEntries = 20000

type IPList struct {
	ID      int64
	Name    string
	Enabled bool
	Mode    string // block | allow
	Entries []string
	All     bool
	Servers []int64
}

func IPListFrom(o *store.Object) *IPList {
	l := &IPList{ID: o.ID, Name: o.Name, Enabled: o.Enabled}
	l.Mode, _ = o.Data["mode"].(string)
	if l.Mode != "allow" {
		l.Mode = "block"
	}
	l.All, _ = o.Data["all"].(bool)
	if v, ok := o.Data["entries"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok {
				l.Entries = append(l.Entries, s)
			}
		}
	}
	if v, ok := o.Data["servers"].([]any); ok {
		for _, x := range v {
			if f, ok := x.(float64); ok {
				l.Servers = append(l.Servers, int64(f))
			}
		}
	}
	return l
}

// ParseIPEntries: eine Adresse oder ein Netz pro Zeile (auch durch Komma/Leerzeichen getrennt),
// „#“ leitet einen Kommentar ein. Ergebnis normalisiert, sortiert, ohne Doppelte.
func ParseIPEntries(text string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for n, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' || r == '\r' }) {
			p, err := parsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("Zeile %d: „%s“ ist keine IP-Adresse bzw. kein Netz", n+1, f)
			}
			if p.Bits() == 0 {
				return nil, fmt.Errorf("Zeile %d: „%s“ umfasst alle Adressen", n+1, f)
			}
			s := p.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
			if len(out) > maxIPEntries {
				return nil, fmt.Errorf("höchstens %d Einträge pro Liste", maxIPEntries)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := netip.MustParsePrefix(out[i]), netip.MustParsePrefix(out[j])
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	return out, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("ungültig")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("ungültig")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// acls: wirksame Regeln je Server-ID.
func (e *Engine) acls() map[int64]*proto.ACL {
	objs, err := e.St.Objects("iplist")
	if err != nil || len(objs) == 0 {
		return nil
	}
	servers, err := e.St.Servers()
	if err != nil {
		return nil
	}
	out := map[int64]*proto.ACL{}
	for _, o := range objs {
		l := IPListFrom(o)
		if !l.Enabled {
			continue
		}
		var pfx []netip.Prefix
		for _, s := range l.Entries {
			if p, err := netip.ParsePrefix(s); err == nil {
				pfx = append(pfx, p)
			}
		}
		targets := map[int64]bool{}
		for _, id := range l.Servers {
			targets[id] = true
		}
		for _, sv := range servers {
			if !l.All && !targets[sv.ID] {
				continue
			}
			a := out[sv.ID]
			if a == nil {
				a = &proto.ACL{}
				out[sv.ID] = a
			}
			if l.Mode == "allow" {
				a.AllowOnly = true
				a.Allow = append(a.Allow, pfx...)
			} else {
				a.Deny = append(a.Deny, pfx...)
			}
		}
	}
	return out
}

// applyACL schreibt die iptables-Ketten (IPv4 und IPv6) für alle Server mit Listen.
func (e *Engine) applyACL(snap *Snapshot, acls map[int64]*proto.ACL) error {
	type portRule struct {
		proto string
		port  int
	}
	byServer := map[int64][]portRule{}
	var ids []int64
	for _, sb := range snap.Servers {
		sv := sb.Server
		a := acls[sv.ID]
		if a == nil || !sv.Enabled {
			continue
		}
		d, ok := proto.Get(sv.Protocol)
		if !ok {
			continue
		}
		if s, ok := d.(proto.SelfACL); ok && s.SelfACL() {
			continue
		}
		for _, p := range d.Ports(sv) {
			if p.To > 0 || p.Port <= 0 {
				continue // Bereiche (Port-Hopping) werden auf den Hauptport umgeleitet
			}
			byServer[sv.ID] = append(byServer[sv.ID], portRule{p.Proto, p.Port})
		}
		if len(byServer[sv.ID]) > 0 {
			ids = append(ids, sv.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var errs []string
	for _, fam := range []struct {
		cmd, restore, state, ctFam string
		v4                         bool
	}{{"iptables", "iptables-restore", "acl:v4", "ipv4", true}, {"ip6tables", "ip6tables-restore", "acl:v6", "ipv6", false}} {
		env := e.Env()
		var prev struct {
			Chains []string          `json:"c"`
			Sig    map[string]string `json:"s"` // Port → Prüfsumme der Regeln
		}
		_ = json.Unmarshal([]byte(env.GetState(fam.state)), &prev)
		if len(ids) == 0 {
			if len(prev.Chains) == 0 {
				continue
			}
			_, _ = e.Sys.Run(fam.cmd, "-D", "INPUT", "-j", "VPNACL")
			_, _ = e.Sys.Run(fam.cmd, "-F", "VPNACL")
			_, _ = e.Sys.Run(fam.cmd, "-X", "VPNACL")
			for _, c := range prev.Chains {
				_, _ = e.Sys.Run(fam.cmd, "-F", c)
				_, _ = e.Sys.Run(fam.cmd, "-X", c)
			}
			env.SetState(fam.state, "")
			continue
		}
		var b strings.Builder
		b.WriteString("*filter\n:VPNACL - [0:0]\n")
		var chains []string
		for _, id := range ids {
			c := fmt.Sprintf("VPNACL-%d", id)
			chains = append(chains, c)
			fmt.Fprintf(&b, ":%s - [0:0]\n", c)
		}
		b.WriteString("-A VPNACL -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n")
		sig := map[string]string{}
		for i, id := range ids {
			a := acls[id]
			var body strings.Builder
			for _, p := range a.Deny {
				if p.Addr().Is4() == fam.v4 {
					fmt.Fprintf(&body, "-A %s -s %s -j DROP\n", chains[i], p)
				}
			}
			if a.AllowOnly {
				for _, p := range a.Allow {
					if p.Addr().Is4() == fam.v4 {
						fmt.Fprintf(&body, "-A %s -s %s -j RETURN\n", chains[i], p)
					}
				}
				fmt.Fprintf(&body, "-A %s -j DROP\n", chains[i])
			}
			b.WriteString(body.String())
			for _, pr := range byServer[id] {
				fmt.Fprintf(&b, "-A VPNACL -p %s -m %s --dport %d -j %s\n", pr.proto, pr.proto, pr.port, chains[i])
				sig[pr.proto+"/"+strconv.Itoa(pr.port)] = hashStr(body.String())
			}
		}
		b.WriteString("COMMIT\n")
		if _, err := e.Sys.RunInput(b.String(), fam.restore, "-n"); err != nil {
			errs = append(errs, fam.cmd+": "+err.Error())
			continue
		}
		if _, err := e.Sys.Run(fam.cmd, "-C", "INPUT", "-j", "VPNACL"); err != nil {
			if _, err := e.Sys.Run(fam.cmd, "-I", "INPUT", "-j", "VPNACL"); err != nil {
				errs = append(errs, fam.cmd+": "+err.Error())
				continue
			}
		}
		keep := map[string]bool{}
		for _, c := range chains {
			keep[c] = true
		}
		for _, c := range prev.Chains {
			if !keep[c] {
				_, _ = e.Sys.Run(fam.cmd, "-F", c)
				_, _ = e.Sys.Run(fam.cmd, "-X", c)
			}
		}
		// Bestehende Verbindungen neu bewerten, wenn sich die Regeln eines Ports geändert haben
		// (sonst liefe z. B. eine gesperrte WireGuard-Verbindung über conntrack einfach weiter).
		for k, v := range sig {
			if prev.Sig[k] == v {
				continue
			}
			pr, port, _ := strings.Cut(k, "/")
			_, _ = e.Sys.Run("conntrack", "-D", "-f", fam.ctFam, "-p", pr, "--orig-port-dst", port)
		}
		prev.Chains, prev.Sig = chains, sig
		js, _ := json.Marshal(prev)
		env.SetState(fam.state, string(js))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func hashStr(s string) string {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return strconv.FormatUint(h, 36)
}
