package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/store"
)

// Panel-DNS: Filterprofile und Blocklisten.
//
// Blocklisten (Objekte „dnslist“) sind Domainlisten – eigene Einträge und/oder eine Online-Liste
// (Hosts-Datei, Adblock-Format „||domain^“ oder eine Domain pro Zeile), die regelmäßig neu geladen
// wird. Eine Liste kann sperren („block“) oder freigeben („allow“, Ausnahmen).
//
// Filterprofile (Objekte „dnsprofile“) fassen Listen und eigene Regeln zusammen und gelten global,
// je Server, je Nutzer oder je Gerät – mit derselben Rangfolge wie die Ziel-Regeln (Gerät vor Nutzer
// vor Server vor global). Ohne Profil wird nichts gefiltert.

const (
	maxDNSListEntries = 1000000
	maxDNSRules       = 5000
)

// DNSList: Blockliste.
type DNSList struct {
	ID      int64
	Name    string
	Enabled bool
	Mode    string // block | allow
	URL     string
	Refresh int // Stunden, 0 = nur von Hand
	Entries []string
}

func DNSListFrom(o *store.Object) *DNSList {
	l := &DNSList{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Mode: "block", Refresh: 24}
	if m, _ := o.Data["mode"].(string); m == "allow" {
		l.Mode = "allow"
	}
	l.URL, _ = o.Data["url"].(string)
	if f, ok := o.Data["refresh"].(float64); ok {
		l.Refresh = int(f)
	}
	l.Entries = strs(o.Data["entries"])
	return l
}

// DNSProfile: Filterprofil.
type DNSProfile struct {
	ID       int64
	Name     string
	Enabled  bool
	Lists    []int64
	Rules    string
	Assign   []string // global | server:<id> | user:<id> | peer:<id>
	BlockDoH bool     // verschlüsseltes DNS (DoH/DoT) der Geräte sperren
	NXDomain bool     // gesperrte Namen mit „gibt es nicht“ beantworten statt 0.0.0.0
	Smart    []SmartRoute
}

// SmartRoute: SmartDNS – diese Domains laufen über eine Ausgangsgruppe (z. B. Netflix über „USA“).
// VPN-Geräte: wie eine Ziel-Regel. Geräte ohne VPN: Der DNS antwortet mit der Adresse des Servers,
// der die HTTPS-Verbindung anhand des Namens (SNI) über die Gruppe weiterreicht.
type SmartRoute struct {
	Group   int64    `json:"group"`
	Domains []string `json:"domains"`
}

// ParseSmart liest die SmartDNS-Einträge eines Profils (doppelte und ungültige Domains fallen weg).
func ParseSmart(v any) []SmartRoute {
	var out []SmartRoute
	arr, _ := v.([]any)
	for _, x := range arr {
		m, _ := x.(map[string]any)
		if m == nil {
			continue
		}
		r := SmartRoute{}
		switch g := m["group"].(type) {
		case float64:
			r.Group = int64(g)
		case int64:
			r.Group = g
		}
		seen := map[string]bool{}
		for _, d := range strs(m["domains"]) {
			if c := cleanDomain(d); c != "" && !seen[c] {
				seen[c] = true
				r.Domains = append(r.Domains, c)
			}
		}
		if r.Group > 0 && len(r.Domains) > 0 {
			out = append(out, r)
		}
	}
	return out
}

func DNSProfileFrom(o *store.Object) *DNSProfile {
	p := &DNSProfile{ID: o.ID, Name: o.Name, Enabled: o.Enabled, BlockDoH: true}
	p.Lists = ids(o.Data["lists"])
	p.Rules, _ = o.Data["rules"].(string)
	p.Assign = strs(o.Data["assign"])
	if b, ok := o.Data["block_doh"].(bool); ok {
		p.BlockDoH = b
	}
	p.NXDomain, _ = o.Data["nxdomain"].(bool)
	p.Smart = ParseSmart(o.Data["smart"])
	return p
}

// ---------- Domains erkennen ----------

// domainSet: Namen; ein Eintrag gilt auch für alle Unterdomains.
type domainSet map[string]struct{}

// match liefert den passenden Eintrag (der Name selbst oder eine übergeordnete Domain).
func (s domainSet) match(name string) (string, bool) {
	if len(s) == 0 {
		return "", false
	}
	for {
		if _, ok := s[name]; ok {
			return name, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", false
		}
		name = name[i+1:]
	}
}

// CleanDomain: wie cleanDomain (für die API).
func CleanDomain(d string) string { return cleanDomain(d) }

// cleanDomain: Kleinbuchstaben, ohne „*.“ und Punkte am Rand; "" = kein gültiger Name.
func cleanDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")
	if len(d) > 253 || !domainRe.MatchString(d) {
		return ""
	}
	return d
}

var hostsSkip = map[string]bool{"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true}

// ParseDomainList liest eine Domainliste: Hosts-Datei („0.0.0.0 werbung.de“), Adblock-Format
// („||werbung.de^“, Ausnahmen „@@||…^“) oder eine Domain pro Zeile. Regeln mit Zusätzen
// („$third-party“ u. ä.), Element-Regeln („##“) und reguläre Ausdrücke gelten im DNS nicht und
// werden übersprungen (gezählt).
func ParseDomainList(r io.Reader, max int) (block, allow []string, skipped int, err error) {
	seenB, seenA := map[string]bool{}, map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '!' || line[0] == '#' || line[0] == '[' {
			continue
		}
		if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") || line[0] == '/' {
			skipped++
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		isAllow := false
		var names []string
		switch {
		case strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "||"):
			if strings.HasPrefix(line, "@@") {
				isAllow = true
				line = line[2:]
			}
			if i := strings.IndexByte(line, '$'); i >= 0 {
				if mod := line[i+1:]; mod != "important" && mod != "all" {
					skipped++
					continue
				}
				line = line[:i]
			}
			line = strings.TrimPrefix(line, "||")
			line = strings.TrimSuffix(line, "^|")
			line = strings.TrimSuffix(line, "^")
			if strings.ContainsAny(line, "/*^|") {
				skipped++
				continue
			}
			names = []string{line}
		default:
			f := strings.Fields(line)
			if len(f) >= 2 {
				if _, perr := netip.ParseAddr(f[0]); perr == nil { // Hosts-Datei
					names = f[1:]
					break
				}
			}
			names = f[:1]
		}
		for _, n := range names {
			if hostsSkip[strings.ToLower(n)] {
				continue
			}
			d := cleanDomain(n)
			if d == "" {
				skipped++
				continue
			}
			if isAllow {
				if !seenA[d] {
					seenA[d] = true
					allow = append(allow, d)
				}
			} else if !seenB[d] {
				seenB[d] = true
				block = append(block, d)
			}
			if len(block)+len(allow) > max {
				return nil, nil, skipped, fmt.Errorf("mehr als %d Einträge", max)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, skipped, err
	}
	return block, allow, skipped, nil
}

// DNSRules: eigene Regeln eines Profils.
type DNSRules struct {
	Block   []string
	Allow   []string
	Rewrite map[string][]netip.Addr
}

// ParseDNSRules liest die eigenen Regeln eines Profils, eine pro Zeile:
//
//	werbung.de                sperren (auch „block werbung.de“ oder „||werbung.de^“)
//	allow beispiel.de         freigeben (auch „@@beispiel.de“) – geht vor Sperren
//	nas.home = 192.168.1.10   eigene Antwort (mehrere Adressen mit Komma)
func ParseDNSRules(text string) (*DNSRules, error) {
	r := &DNSRules{Rewrite: map[string][]netip.Addr{}}
	n := 0
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if j := strings.Index(line, "#"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		n++
		if n > maxDNSRules {
			return nil, fmt.Errorf("höchstens %d Regeln – für mehr eine Blockliste anlegen", maxDNSRules)
		}
		bad := func(msg string) error { return fmt.Errorf("Zeile %d („%s“): %s", i+1, line, msg) }
		if k := strings.IndexByte(line, '='); k >= 0 {
			d := cleanDomain(line[:k])
			if d == "" {
				return nil, bad("kein gültiger Domainname vor dem „=“")
			}
			for _, a := range strings.Split(line[k+1:], ",") {
				ip, err := netip.ParseAddr(strings.TrimSpace(a))
				if err != nil {
					return nil, bad("nach dem „=“ bitte IP-Adressen angeben (z. B. 192.168.1.10)")
				}
				r.Rewrite[d] = append(r.Rewrite[d], ip.Unmap())
			}
			continue
		}
		allow := false
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "allow "):
			allow, line = true, line[6:]
		case strings.HasPrefix(low, "block "):
			line = line[6:]
		case strings.HasPrefix(line, "@@"):
			allow, line = true, line[2:]
		}
		line = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "||"), "^")
		d := cleanDomain(line)
		if d == "" {
			return nil, bad("kein gültiger Domainname (Beispiel: werbung.de)")
		}
		if allow {
			r.Allow = append(r.Allow, d)
		} else {
			r.Block = append(r.Block, d)
		}
	}
	return r, nil
}

// ---------- Listen laden ----------

type dnsListData struct {
	sig          string
	id           int64
	name         string
	block, allow domainSet
}

type dnsListState struct {
	mu    sync.Mutex
	cache map[int64]*dnsListData
	busy  map[int64]bool
}

func (e *Engine) dnsListPath(id int64) string {
	return filepath.Join(e.Cfg.DataDir, "dnslists", strconv.FormatInt(id, 10)+".txt")
}

func (e *Engine) DNSListStatus(id int64) ListStatus {
	var st ListStatus
	_ = json.Unmarshal([]byte(e.St.GetSetting(fmt.Sprintf("state:dnslist:%d", id), "")), &st)
	return st
}

func (e *Engine) setDNSListStatus(id int64, st ListStatus) {
	b, _ := json.Marshal(st)
	_ = e.St.SetSetting(fmt.Sprintf("state:dnslist:%d", id), string(b))
}

// DeleteDNSListData entfernt geladenen Inhalt und Stand einer Blockliste.
func (e *Engine) DeleteDNSListData(id int64) {
	_ = os.Remove(e.dnsListPath(id))
	_ = e.St.SetSetting(fmt.Sprintf("state:dnslist:%d", id), "")
	e.dnsLists.mu.Lock()
	delete(e.dnsLists.cache, id)
	e.dnsLists.mu.Unlock()
}

// dnsListSets: eigene Einträge plus geladener Inhalt (zwischengespeichert, solange sich nichts ändert).
func (e *Engine) dnsListSets(l *DNSList) *dnsListData {
	sig := fmt.Sprintf("%s|%d|%s", l.Mode, len(l.Entries), hashStr(strings.Join(l.Entries, ",")))
	path := e.dnsListPath(l.ID)
	fi, ferr := os.Stat(path)
	if l.URL != "" && ferr == nil {
		sig += fmt.Sprintf("|%d|%d", fi.ModTime().UnixNano(), fi.Size())
	}
	e.dnsLists.mu.Lock()
	if c := e.dnsLists.cache[l.ID]; c != nil && c.sig == sig {
		c.name = l.Name
		e.dnsLists.mu.Unlock()
		return c
	}
	e.dnsLists.mu.Unlock()
	d := &dnsListData{sig: sig, id: l.ID, name: l.Name, block: domainSet{}, allow: domainSet{}}
	own := d.block
	if l.Mode == "allow" {
		own = d.allow
	}
	for _, s := range l.Entries {
		if c := cleanDomain(s); c != "" {
			own[c] = struct{}{}
		}
	}
	if l.URL != "" && ferr == nil {
		if f, err := os.Open(path); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				t := sc.Text()
				if strings.HasPrefix(t, "@") {
					d.allow[t[1:]] = struct{}{}
				} else if t != "" {
					own[t] = struct{}{}
				}
			}
			f.Close()
		}
	}
	e.dnsLists.mu.Lock()
	if e.dnsLists.cache == nil {
		e.dnsLists.cache = map[int64]*dnsListData{}
	}
	e.dnsLists.cache[l.ID] = d
	e.dnsLists.mu.Unlock()
	return d
}

// dnsListSample: Inhalt für den Testmodus (nichts aus dem Netz laden).
const dnsListSample = "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n||doubleclick.net^\n||googlesyndication.com^\n@@||ok.example.com^\n"

// FetchDNSList lädt eine Online-Blockliste neu. changed = Inhalt hat sich geändert.
func (e *Engine) FetchDNSList(id int64) (changed bool, err error) {
	o, err := e.St.Object("dnslist", id)
	if err != nil {
		return false, err
	}
	l := DNSListFrom(o)
	if l.URL == "" {
		return false, fmt.Errorf("die Liste hat keine Adresse")
	}
	e.dnsLists.mu.Lock()
	if e.dnsLists.busy == nil {
		e.dnsLists.busy = map[int64]bool{}
	}
	if e.dnsLists.busy[id] {
		e.dnsLists.mu.Unlock()
		return false, fmt.Errorf("die Liste wird gerade geladen")
	}
	e.dnsLists.busy[id] = true
	e.dnsLists.mu.Unlock()
	defer func() {
		e.dnsLists.mu.Lock()
		delete(e.dnsLists.busy, id)
		e.dnsLists.mu.Unlock()
	}()

	st := e.DNSListStatus(id)
	st.Tried = time.Now().Unix()
	fail := func(err error) (bool, error) {
		if st.Error != err.Error() {
			e.Log("warn", fmt.Sprintf("Blockliste „%s“: Abruf fehlgeschlagen – %v", l.Name, err))
		}
		st.Error = err.Error()
		e.setDNSListStatus(id, st)
		return false, err
	}
	if err := CheckListURL(l.URL); err != nil {
		return fail(err)
	}
	var body io.Reader
	if u, _ := url.Parse(l.URL); e.Sys.DryRun() && u != nil && u.Hostname() != "127.0.0.1" {
		body = strings.NewReader(dnsListSample)
	} else {
		req, _ := http.NewRequest(http.MethodGet, l.URL, nil)
		req.Header.Set("User-Agent", "vpnpanel")
		resp, err := listHTTP().Do(req)
		if err != nil {
			return fail(fmt.Errorf("nicht erreichbar: %v", err))
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fail(fmt.Errorf("Antwort %d vom Server der Liste", resp.StatusCode))
		}
		body = &io.LimitedReader{R: resp.Body, N: 4*maxListBytes + 1}
	}
	block, allow, skipped, err := ParseDomainList(body, maxDNSListEntries)
	if err != nil {
		return fail(err)
	}
	if lr, ok := body.(*io.LimitedReader); ok && lr.N <= 0 {
		return fail(fmt.Errorf("Liste ist größer als %d MB", 4*maxListBytes>>20))
	}
	if len(block)+len(allow) == 0 {
		return fail(fmt.Errorf("keine Domains gefunden (%d Zeilen nicht lesbar) – Hosts-Datei, Adblock-Liste oder eine Domain pro Zeile?", skipped))
	}
	var b strings.Builder
	for _, d := range block {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	for _, d := range allow {
		b.WriteByte('@')
		b.WriteString(d)
		b.WriteByte('\n')
	}
	path := e.dnsListPath(id)
	data := []byte(b.String())
	old, _ := os.ReadFile(path)
	if string(old) != string(data) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fail(err)
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return fail(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return fail(err)
		}
		changed = true
	}
	if st.Error != "" || st.At == 0 || changed {
		e.Log("info", fmt.Sprintf("Blockliste „%s“ geladen: %d Domains", l.Name, len(block)+len(allow)))
	}
	st.At, st.Count, st.Skipped, st.Error = st.Tried, len(block)+len(allow), skipped, ""
	e.setDNSListStatus(id, st)
	return changed, nil
}

func (e *Engine) refreshDNSLists(now time.Time) (changed bool) {
	objs, _ := e.St.Objects("dnslist")
	for _, o := range objs {
		l := DNSListFrom(o)
		if !l.Enabled || l.URL == "" || !listDueRefresh(l.Refresh, e.DNSListStatus(l.ID), now) {
			continue
		}
		if ch, _ := e.FetchDNSList(l.ID); ch {
			changed = true
		}
	}
	return changed
}

// DNSListInfo: Stand und Anzahl der Domains (für die Oberfläche).
func (e *Engine) DNSListInfo(o *store.Object) (ListStatus, int) {
	d := e.dnsListSets(DNSListFrom(o))
	return e.DNSListStatus(o.ID), len(d.block) + len(d.allow)
}

// ---------- Profile zuordnen ----------

// dnsFilter: wirksames Profil (zusammengesetzt) für ein Gerät.
type dnsFilter struct {
	ID       int64
	Name     string
	Lists    []*dnsListData
	Rules    *DNSRules
	block    domainSet
	allow    domainSet
	BlockDoH bool
	NXDomain bool
	Smart    []SmartRoute
	smart    map[string]int64 // Domain → Gruppe
}

// smartMatch: Läuft der Name per SmartDNS über eine Gruppe? (Unterdomains zählen mit.)
func (f *dnsFilter) smartMatch(name string) (group int64, domain string, ok bool) {
	if f == nil || len(f.smart) == 0 {
		return 0, "", false
	}
	for n := name; ; {
		if g, ok := f.smart[n]; ok {
			return g, n, true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return 0, "", false
		}
		n = n[i+1:]
	}
}

// verdict: Was passiert mit dem Namen? action: "" (normal), "blocked", "rewritten"; detail = Grund.
func (f *dnsFilter) verdict(name string) (action, detail string, addrs []netip.Addr) {
	if f == nil {
		return "", "", nil
	}
	if d, ok := f.allow.match(name); ok {
		return "", "freigegeben (eigene Regel: " + d + ")", nil
	}
	for _, l := range f.Lists {
		if d, ok := l.allow.match(name); ok {
			return "", "freigegeben (Liste „" + l.name + "“: " + d + ")", nil
		}
	}
	for n := name; ; {
		if a, ok := f.Rules.Rewrite[n]; ok {
			return "rewritten", "eigene Antwort (" + n + ")", a
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	if d, ok := f.block.match(name); ok {
		return "blocked", "eigene Regel: " + d, nil
	}
	for _, l := range f.Lists {
		if d, ok := l.block.match(name); ok {
			return "blocked", "Liste „" + l.name + "“: " + d, nil
		}
	}
	return "", "", nil
}

// compileDNSFilters ordnet jedem Gerät sein Filterprofil zu (nil = kein Profil).
func (e *Engine) compileDNSFilters(snap *Snapshot) map[int64]*dnsFilter {
	out := map[int64]*dnsFilter{}
	byScope, _ := e.dnsProfileFilters()
	for id, pb := range snap.Peers {
		for _, k := range []string{fmt.Sprintf("peer:%d", id), fmt.Sprintf("user:%d", pb.User.ID), fmt.Sprintf("server:%d", pb.Peer.ServerID), "global"} {
			if f := byScope[k]; f != nil {
				out[id] = f
				break
			}
		}
	}
	return out
}

// dnsProfileFilters: aktive Profile nach Zuordnung (global, server:…, user:…, peer:…) und nach ID.
func (e *Engine) dnsProfileFilters() (byScope map[string]*dnsFilter, byID map[int64]*dnsFilter) {
	byScope, byID = map[string]*dnsFilter{}, map[int64]*dnsFilter{}
	objs, _ := e.St.Objects("dnsprofile")
	if len(objs) == 0 {
		return
	}
	lists := map[int64]*DNSList{}
	if lo, err := e.St.Objects("dnslist"); err == nil {
		for _, o := range lo {
			if l := DNSListFrom(o); l.Enabled {
				lists[l.ID] = l
			}
		}
	}
	for _, o := range objs { // nach ID sortiert – bei mehreren Profilen auf derselben Ebene gilt das älteste
		p := DNSProfileFrom(o)
		if !p.Enabled {
			continue
		}
		rules, err := ParseDNSRules(p.Rules)
		if err != nil {
			rules = &DNSRules{Rewrite: map[string][]netip.Addr{}}
		}
		f := &dnsFilter{ID: p.ID, Name: p.Name, Rules: rules, block: domainSet{}, allow: domainSet{}, BlockDoH: p.BlockDoH, NXDomain: p.NXDomain,
			Smart: p.Smart, smart: map[string]int64{}}
		for _, sr := range p.Smart {
			for _, d := range sr.Domains {
				if _, ok := f.smart[d]; !ok {
					f.smart[d] = sr.Group
				}
			}
		}
		for _, d := range rules.Block {
			f.block[d] = struct{}{}
		}
		for _, d := range rules.Allow {
			f.allow[d] = struct{}{}
		}
		for _, id := range p.Lists {
			if l := lists[id]; l != nil {
				f.Lists = append(f.Lists, e.dnsListSets(l))
			}
		}
		byID[p.ID] = f
		for _, a := range p.Assign {
			if _, ok := byScope[a]; !ok {
				byScope[a] = f
			}
		}
	}
	return
}

// ProfilesUsing: Profile, die eine Blockliste verwenden (Löschschutz).
func (e *Engine) ProfilesUsing(listID int64) []string {
	objs, _ := e.St.Objects("dnsprofile")
	var out []string
	for _, o := range objs {
		for _, id := range DNSProfileFrom(o).Lists {
			if id == listID {
				out = append(out, o.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
