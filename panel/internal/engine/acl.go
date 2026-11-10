package engine

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// IP-Listen: Sperrlisten (diese Adressen nie) und Freigabelisten (nur diese Adressen) je Server,
// dazu Ziellisten für Ziel-Regeln (siehe routes.go). Durchsetzung der Sperr-/Freigabelisten:
// nftables (Tabelle „inet vpnpanel“, siehe nft.go) auf den Ports des Servers; VLESS (geteilter
// Port 443) regelt es selbst über Xray-Routing. Listen können online nachgeladen werden (lists.go).

const maxIPEntries = 20000

type IPList struct {
	ID      int64
	Name    string
	Enabled bool
	Mode    string // block | allow | targets (Zielliste für Ziel-Regeln)
	Entries []string
	All     bool
	Servers []int64
	URL     string // Online-Liste: Adresse, von der zusätzlich geladen wird
	Refresh int    // Stunden zwischen den Abrufen, 0 = nur von Hand
}

func IPListFrom(o *store.Object) *IPList {
	l := &IPList{ID: o.ID, Name: o.Name, Enabled: o.Enabled}
	l.Mode, _ = o.Data["mode"].(string)
	if l.Mode != "allow" && l.Mode != "targets" {
		l.Mode = "block"
	}
	l.URL, _ = o.Data["url"].(string)
	if f, ok := o.Data["refresh"].(float64); ok {
		l.Refresh = int(f)
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

// serverACL: Listen (IDs), die für einen Server gelten.
type serverACL struct {
	Deny, Allow []int64
	AllowOnly   bool // es gibt eine Freigabeliste → nur deren Adressen
}

// aclPlan: wirksame Listen je Server – als Listen-IDs (für die Firewall, die pro Liste ein Set
// anlegt) und zusammengeführt (für Treiber, die selbst prüfen: Proxy, VLESS).
type aclPlan struct {
	ByServer map[int64]*serverACL
	Merged   map[int64]*proto.ACL
	Lists    map[int64]*IPList // alle aktiven Sperr-/Freigabelisten
}

type aclState struct {
	mu   sync.Mutex
	sig  string
	plan *aclPlan
}

// aclPlan berechnet die wirksamen Listen (zwischengespeichert, solange sich nichts ändert).
func (e *Engine) aclPlan() *aclPlan {
	objs, err := e.St.Objects("iplist")
	if err != nil || len(objs) == 0 {
		return &aclPlan{}
	}
	servers, err := e.St.Servers()
	if err != nil {
		return &aclPlan{}
	}
	var sig strings.Builder
	for _, sv := range servers {
		fmt.Fprintf(&sig, "s%d,", sv.ID)
	}
	for _, o := range objs {
		fmt.Fprintf(&sig, "|%d:%v:%v", o.ID, o.Enabled, o.Data)
		if fi, err := os.Stat(e.listPath(o.ID)); err == nil {
			fmt.Fprintf(&sig, ":%d:%d", fi.ModTime().UnixNano(), fi.Size())
		}
	}
	key := hashStr(sig.String()) + strconv.Itoa(sig.Len())
	e.acl.mu.Lock()
	defer e.acl.mu.Unlock()
	if e.acl.plan != nil && e.acl.sig == key {
		return e.acl.plan
	}
	plan := &aclPlan{ByServer: map[int64]*serverACL{}, Merged: map[int64]*proto.ACL{}, Lists: map[int64]*IPList{}}
	for _, o := range objs {
		l := IPListFrom(o)
		if !l.Enabled || l.Mode == "targets" {
			continue
		}
		plan.Lists[l.ID] = l
		v4, v6 := e.listPrefixes(l)
		targets := map[int64]bool{}
		for _, id := range l.Servers {
			targets[id] = true
		}
		for _, sv := range servers {
			if !l.All && !targets[sv.ID] {
				continue
			}
			a, m := plan.ByServer[sv.ID], plan.Merged[sv.ID]
			if a == nil {
				a, m = &serverACL{}, &proto.ACL{}
				plan.ByServer[sv.ID], plan.Merged[sv.ID] = a, m
			}
			if l.Mode == "allow" {
				a.AllowOnly, m.AllowOnly = true, true
				a.Allow = append(a.Allow, l.ID)
				m.Allow = append(append(m.Allow, v4...), v6...)
			} else {
				a.Deny = append(a.Deny, l.ID)
				m.Deny = append(append(m.Deny, v4...), v6...)
			}
		}
	}
	e.acl.sig, e.acl.plan = key, plan
	return plan
}

// acls: wirksame Regeln je Server-ID (für die Treiber).
func (e *Engine) acls() map[int64]*proto.ACL {
	m := e.aclPlan().Merged
	if len(m) == 0 {
		return nil
	}
	return m
}

// removeLegacyACL baut die iptables-Ketten älterer Versionen (bis 0.7) ab.
func (e *Engine) removeLegacyACL() {
	for _, fam := range []struct{ cmd, state string }{{"iptables", "state:acl:v4"}, {"ip6tables", "state:acl:v6"}} {
		raw := e.St.GetSetting(fam.state, "")
		if raw == "" {
			continue
		}
		_, _ = e.Sys.Run(fam.cmd, "-D", "INPUT", "-j", "VPNACL")
		_, _ = e.Sys.Run(fam.cmd, "-F", "VPNACL")
		for _, c := range legacyChains(raw) {
			_, _ = e.Sys.Run(fam.cmd, "-F", c)
			_, _ = e.Sys.Run(fam.cmd, "-X", c)
		}
		_, _ = e.Sys.Run(fam.cmd, "-X", "VPNACL")
		_ = e.St.SetSetting(fam.state, "")
	}
}

// legacyChains liest die Kettennamen aus dem alten Zustand ({"c":["VPNACL-3",…],…}).
func legacyChains(raw string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == '"' || r == ',' || r == '[' || r == ']' }) {
		if strings.HasPrefix(f, "VPNACL-") {
			out = append(out, f)
		}
	}
	return out
}

func hashStr(s string) string {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return strconv.FormatUint(h, 36)
}
