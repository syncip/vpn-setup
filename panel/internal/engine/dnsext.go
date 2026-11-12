package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/store"
)

// Panel-DNS für Geräte ohne VPN (Fernseher, Router, …).
//
// Ist „DNS von außen“ an, leitet die Firewall Port 53 auf der Außenschnittstelle an den Panel-DNS.
// Antworten bekommen nur freigegebene Absender (Objekt „dnsclient“: IP-Adressen, Netze oder
// DynDNS-Namen); alle anderen werden verworfen, aber mitgezählt – so sieht man, ob Fremde es versuchen.
// Ein offener Resolver für alle wäre ein Werkzeug für DDoS-Verstärkung, deshalb gibt es das nicht.

// DNSClient: freigegebener Absender.
type DNSClient struct {
	ID      int64
	Name    string
	Enabled bool
	Addrs   []string // IP-Adressen, Netze, Hostnamen (DynDNS)
	Profile int64    // Filterprofil: 0 = das globale, -1 = ohne Filter
	Note    string
}

func DNSClientFrom(o *store.Object) *DNSClient {
	c := &DNSClient{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Addrs: strs(o.Data["addrs"])}
	if f, ok := o.Data["profile"].(float64); ok {
		c.Profile = int64(f)
	} else if n, ok := o.Data["profile"].(int64); ok {
		c.Profile = n
	}
	c.Note, _ = o.Data["note"].(string)
	return c
}

var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)

// ParseClientAddrs prüft Adressen eines Absenders (IP, Netz oder Hostname).
func ParseClientAddrs(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
			f = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(f), "."))
			if f == "" {
				continue
			}
			switch {
			case strings.Contains(f, "/"):
				p, err := netip.ParsePrefix(f)
				if err != nil {
					return nil, fmt.Errorf("„%s“ ist kein gültiges Netz", f)
				}
				if (p.Addr().Is4() && p.Bits() < 16) || (!p.Addr().Is4() && p.Bits() < 48) {
					return nil, fmt.Errorf("„%s“ ist zu groß (höchstens /16 bzw. /48)", f)
				}
				f = p.Masked().String()
			default:
				if a, err := netip.ParseAddr(f); err == nil {
					f = a.Unmap().String()
				} else if !hostnameRe.MatchString(f) {
					return nil, fmt.Errorf("„%s“ ist weder IP-Adresse, Netz noch Hostname", f)
				}
			}
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("mindestens eine Adresse oder einen Hostnamen angeben")
	}
	if len(out) > 20 {
		return nil, fmt.Errorf("höchstens 20 Adressen je Gerät")
	}
	return out, nil
}

// extSrc: freigegebener Absender, aufgelöst.
type extSrc struct {
	pfx  netip.Prefix
	id   int64
	name string
	filt *dnsFilter
}

// hostRes: aufgelöster DynDNS-Name.
type hostRes struct {
	Addrs []netip.Addr `json:"addrs"`
	At    int64        `json:"at"`
	Err   string       `json:"err,omitempty"`
	Name  string       `json:"-"` // Rückwärtsauflösung
}

// extSeen: was der Dienst von einem Absender außerhalb des VPN gesehen hat.
type extSeen struct {
	Client  int64  `json:"client"` // freigegebener Absender (0 = fremd)
	Queries int    `json:"queries"`
	Refused int    `json:"refused"`
	Blocked int    `json:"blocked"`
	First   int64  `json:"first"`
	Last    int64  `json:"last"`
	Name    string `json:"name"` // zuletzt gefragter Name
}

type dnsExt struct {
	mu     sync.Mutex
	public bool
	srcs   []extSrc
	hosts  map[string]hostRes
	seen   map[netip.Addr]*extSeen
	rdns   map[netip.Addr]hostRes
	loaded bool
	dirty  bool
}

func (x *dnsExt) isPublic() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.public
}

// dnsPublic: Port 53 von außen an den Panel-DNS.
func (e *Engine) dnsPublic() bool {
	return e.Setting("dns_enabled") == "1" && e.Setting("dns_public") == "1"
}

// resolveHost liefert die Adressen eines DynDNS-Namens (zwischengespeichert, alle 5 Minuten neu).
func (e *Engine) resolveHost(name string, force bool) hostRes {
	x := &e.dnsx
	x.mu.Lock()
	r, ok := x.hosts[name]
	x.mu.Unlock()
	if ok && !force && time.Since(time.Unix(r.At, 0)) < 5*time.Minute {
		return r
	}
	if e.Sys.DryRun() {
		return hostRes{At: time.Now().Unix(), Err: "Trockenlauf: Namen werden nicht aufgelöst"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	nr := hostRes{At: time.Now().Unix()}
	if err != nil {
		nr.Err = err.Error()
		nr.Addrs = r.Addrs // letzte bekannte Adressen behalten
	} else {
		for _, a := range ips {
			nr.Addrs = append(nr.Addrs, a.Unmap())
		}
		sort.Slice(nr.Addrs, func(i, j int) bool { return nr.Addrs[i].Less(nr.Addrs[j]) })
	}
	x.mu.Lock()
	if x.hosts == nil {
		x.hosts = map[string]hostRes{}
	}
	x.hosts[name] = nr
	x.mu.Unlock()
	return nr
}

// extSources: freigegebene Absender mit ihren Adressen und Filterprofilen.
func (e *Engine) extSources(force bool) []extSrc {
	objs, _ := e.St.Objects("dnsclient")
	if len(objs) == 0 {
		return nil
	}
	byScope, byID := e.dnsProfileFilters()
	var out []extSrc
	for _, o := range objs {
		c := DNSClientFrom(o)
		if !c.Enabled {
			continue
		}
		var filt *dnsFilter
		switch {
		case c.Profile > 0:
			filt = byID[c.Profile]
		case c.Profile == 0:
			filt = byScope["global"]
		}
		for _, a := range c.Addrs {
			var pfxs []netip.Prefix
			if p, err := netip.ParsePrefix(a); err == nil {
				pfxs = append(pfxs, p.Masked())
			} else if ip, err := netip.ParseAddr(a); err == nil {
				pfxs = append(pfxs, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
			} else {
				for _, ip := range e.resolveHost(a, force).Addrs {
					pfxs = append(pfxs, netip.PrefixFrom(ip, ip.BitLen()))
				}
			}
			for _, p := range pfxs {
				out = append(out, extSrc{pfx: p, id: c.ID, name: c.Name, filt: filt})
			}
		}
	}
	return out
}

// configureExt übernimmt Freigaben und Schalter (beim Anwenden).
func (e *Engine) configureExt() {
	x := &e.dnsx
	srcs := e.extSources(false)
	x.mu.Lock()
	x.public = e.dnsPublic()
	x.srcs = srcs
	e.loadExt()
	x.mu.Unlock()
}

// refreshExtHosts löst DynDNS-Namen neu auf (jede Minute geprüft, alle 5 Minuten fällig).
func (e *Engine) refreshExtHosts() {
	if !e.dnsPublic() {
		return
	}
	srcs := e.extSources(false)
	x := &e.dnsx
	x.mu.Lock()
	x.srcs = srcs
	dirty := x.dirty
	x.dirty = false
	x.mu.Unlock()
	if dirty {
		e.saveExt()
	}
}

// extSourceOf: freigegebener Absender für eine Adresse (nil = fremd).
func (e *Engine) extSourceOf(a netip.Addr) *srcPolicy {
	x := &e.dnsx
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.public {
		return nil
	}
	for _, s := range x.srcs {
		if s.pfx.Contains(a) {
			return &srcPolicy{pfx: s.pfx, peer: -s.id, filt: s.filt, dns: true, doh: s.filt != nil && s.filt.BlockDoH}
		}
	}
	return nil
}

// noteExt zählt eine Anfrage von außerhalb des VPN.
func (e *Engine) noteExt(a netip.Addr, client int64, name string, refused, blocked bool) {
	x := &e.dnsx
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.seen == nil {
		x.seen = map[netip.Addr]*extSeen{}
	}
	s := x.seen[a]
	now := time.Now().Unix()
	if s == nil {
		if len(x.seen) >= 1000 { // ältesten fremden Absender vergessen
			var old netip.Addr
			var t int64 = 1 << 62
			for k, v := range x.seen {
				if v.Client == 0 && v.Last < t {
					old, t = k, v.Last
				}
			}
			if !old.IsValid() {
				return
			}
			delete(x.seen, old)
		}
		s = &extSeen{First: now}
		x.seen[a] = s
	}
	s.Client, s.Last, s.Queries = client, now, s.Queries+1
	if len(name) > 120 {
		name = name[:120]
	}
	if name != "" {
		s.Name = name
	}
	if refused {
		s.Refused++
	}
	if blocked {
		s.Blocked++
	}
	x.dirty = true
}

func (e *Engine) extPath() string { return filepath.Join(e.Cfg.DataDir, "dnsclients.json") }

// loadExt (mit x.mu): gesehene Absender vom letzten Lauf.
func (e *Engine) loadExt() {
	x := &e.dnsx
	if x.loaded {
		return
	}
	x.loaded = true
	b, err := os.ReadFile(e.extPath())
	if err != nil {
		return
	}
	var raw map[string]*extSeen
	if json.Unmarshal(b, &raw) != nil {
		return
	}
	if x.seen == nil {
		x.seen = map[netip.Addr]*extSeen{}
	}
	cut := time.Now().Add(-30 * 24 * time.Hour).Unix()
	for k, v := range raw {
		if a, err := netip.ParseAddr(k); err == nil && v != nil && v.Last > cut {
			x.seen[a] = v
		}
	}
}

func (e *Engine) saveExt() {
	x := &e.dnsx
	x.mu.Lock()
	raw := map[string]*extSeen{}
	for a, v := range x.seen {
		c := *v
		raw[a.String()] = &c
	}
	x.mu.Unlock()
	b, _ := json.Marshal(raw)
	_ = os.WriteFile(e.extPath(), b, 0o600)
}

// ForgetExt löscht die Liste der gesehenen Absender (alle oder einen).
func (e *Engine) ForgetExt(addr string) {
	x := &e.dnsx
	x.mu.Lock()
	if addr == "" {
		x.seen = map[netip.Addr]*extSeen{}
	} else if a, err := netip.ParseAddr(addr); err == nil {
		delete(x.seen, a)
	}
	x.mu.Unlock()
	e.saveExt()
}

// ---------- Anzeige ----------

// ExtClient: freigegebener Absender für die Oberfläche.
type ExtClient struct {
	ID       int64        `json:"id"`
	Name     string       `json:"name"`
	Enabled  bool         `json:"enabled"`
	Addrs    []string     `json:"addrs"`
	Resolved []ExtHostRes `json:"resolved"` // DynDNS-Namen → Adressen
	Profile  int64        `json:"profile"`
	Note     string       `json:"note"`
	Queries  int          `json:"queries"`
	Blocked  int          `json:"blocked"`
	Last     int64        `json:"last"`
	Sources  []string     `json:"sources"` // Adressen, von denen Anfragen kamen
}

type ExtHostRes struct {
	Host  string   `json:"host"`
	Addrs []string `json:"addrs"`
	Err   string   `json:"err,omitempty"`
}

// ExtSeenRow: Absender außerhalb des VPN, der gefragt hat.
type ExtSeenRow struct {
	Addr string `json:"addr"`
	Host string `json:"host"` // Rückwärtsauflösung
	extSeen
	ClientName string `json:"client_name,omitempty"`
}

// DNSExternal: Freigaben und alle Absender außerhalb des VPN, die gefragt haben.
type DNSExternal struct {
	Public  bool         `json:"public"`
	Clients []ExtClient  `json:"clients"`
	Seen    []ExtSeenRow `json:"seen"`
	Self    string       `json:"self"`     // eigene öffentliche Adresse (Einstellung server_host)
	SelfIPs []string     `json:"self_ips"` // deren Adressen – die tragen Geräte als DNS-Server ein
}

func (e *Engine) DNSExternal() DNSExternal {
	out := DNSExternal{Public: e.dnsPublic(), Clients: []ExtClient{}, Seen: []ExtSeenRow{}, Self: e.Setting("server_host")}
	out.SelfIPs = []string{}
	if a, err := netip.ParseAddr(out.Self); err == nil {
		out.SelfIPs = append(out.SelfIPs, a.String())
	} else if out.Self != "" {
		for _, a := range e.resolveHost(out.Self, false).Addrs {
			out.SelfIPs = append(out.SelfIPs, a.String())
		}
	}
	objs, _ := e.St.Objects("dnsclient")
	x := &e.dnsx
	x.mu.Lock()
	e.loadExt()
	idx := map[int64]int{}
	for _, o := range objs {
		c := DNSClientFrom(o)
		row := ExtClient{ID: c.ID, Name: c.Name, Enabled: c.Enabled, Addrs: orEmpty(c.Addrs), Profile: c.Profile, Note: c.Note,
			Resolved: []ExtHostRes{}, Sources: []string{}}
		for _, a := range c.Addrs {
			if _, err := netip.ParsePrefix(a); err == nil {
				continue
			}
			if _, err := netip.ParseAddr(a); err == nil {
				continue
			}
			hr := ExtHostRes{Host: a, Addrs: []string{}}
			if r, ok := x.hosts[a]; ok {
				hr.Err = r.Err
				for _, ip := range r.Addrs {
					hr.Addrs = append(hr.Addrs, ip.String())
				}
			} else {
				hr.Err = "noch nicht aufgelöst"
			}
			row.Resolved = append(row.Resolved, hr)
		}
		idx[c.ID] = len(out.Clients)
		out.Clients = append(out.Clients, row)
	}
	var addrs []netip.Addr
	for a, s := range x.seen {
		r := ExtSeenRow{Addr: a.String(), extSeen: *s}
		if i, ok := idx[s.Client]; ok && s.Client != 0 {
			c := &out.Clients[i]
			r.ClientName = c.Name
			c.Queries += s.Queries
			c.Blocked += s.Blocked
			c.Last = max(c.Last, s.Last)
			c.Sources = append(c.Sources, a.String())
		}
		out.Seen = append(out.Seen, r)
		addrs = append(addrs, a)
	}
	x.mu.Unlock()
	sort.Slice(out.Seen, func(i, j int) bool { return out.Seen[i].Last > out.Seen[j].Last })
	if len(out.Seen) > 300 {
		out.Seen = out.Seen[:300]
	}
	// Rückwärtsauflösung (zwischengespeichert, höchstens 2 Sekunden warten)
	names := e.reverseNames(addrs)
	for i := range out.Seen {
		if a, err := netip.ParseAddr(out.Seen[i].Addr); err == nil {
			out.Seen[i].Host = names[a]
		}
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// reverseNames: PTR-Namen der Adressen (zwischengespeichert für 6 Stunden).
func (e *Engine) reverseNames(addrs []netip.Addr) map[netip.Addr]string {
	x := &e.dnsx
	out := map[netip.Addr]string{}
	var todo []netip.Addr
	x.mu.Lock()
	if x.rdns == nil {
		x.rdns = map[netip.Addr]hostRes{}
	}
	for _, a := range addrs {
		if r, ok := x.rdns[a]; ok && time.Since(time.Unix(r.At, 0)) < 6*time.Hour {
			out[a] = r.Name
			continue
		}
		todo = append(todo, a)
	}
	x.mu.Unlock()
	if len(todo) == 0 || e.Sys.DryRun() {
		return out
	}
	if len(todo) > 40 {
		todo = todo[:40]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, a := range todo {
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			names, err := net.DefaultResolver.LookupAddr(ctx, a.String())
			if err != nil && ctx.Err() != nil {
				return // Zeit abgelaufen – beim nächsten Mal
			}
			n := ""
			if len(names) > 0 {
				n = strings.TrimSuffix(names[0], ".")
			}
			mu.Lock()
			out[a] = n
			mu.Unlock()
			x.mu.Lock()
			x.rdns[a] = hostRes{At: time.Now().Unix(), Name: n}
			x.mu.Unlock()
		}(a)
	}
	wg.Wait()
	return out
}
