package engine

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/store"
)

// Blocklisten durchsuchen und anpassen:
//   - Inhalt einer Liste seitenweise durchsuchen (eigene Einträge, Online-Liste, Ausnahmen, herausgenommene)
//   - einzelne Domains aus einer Online-Liste herausnehmen (bleiben auch nach dem Neuladen draußen),
//     wieder aufnehmen oder eigene ergänzen
//   - alle Listen auf einmal durchsuchen („Welche Liste sperrt werbung.example?“)
//   - bekannte Listen vor dem Hinzufügen ansehen (Vorschau, nur im Speicher)

const (
	maxDNSListOwn      = 20000 // eigene Einträge je Liste
	maxDNSListExcluded = 20000 // herausgenommene Domains je Liste
)

// DNSListEntry: eine Domain einer Liste und woher sie kommt.
type DNSListEntry struct {
	Domain string `json:"d"`
	// own = eigener Eintrag, url = aus der Online-Liste, allow = Ausnahme („@@“) der Online-Liste,
	// excluded = aus der Online-Liste herausgenommen (wirkt nicht)
	Src string `json:"src"`
}

// DNSListPage: ein Ausschnitt der Treffer.
type DNSListPage struct {
	Items    []DNSListEntry `json:"items"`
	Matched  int            `json:"matched"`  // Treffer insgesamt
	Total    int            `json:"total"`    // wirksame Domains der Liste
	Excluded int            `json:"excluded"` // herausgenommen
	Own      int            `json:"own"`      // eigene Einträge
}

// scanDNSList ruft fn für jede Domain der Liste auf (eigene, Online-Liste, zuletzt herausgenommene).
func (e *Engine) scanDNSList(l *DNSList, fn func(d, src string)) {
	excl := make(map[string]bool, len(l.Excluded))
	for _, x := range l.Excluded {
		excl[x] = true
	}
	own := map[string]bool{}
	for _, s := range l.Entries {
		if c := cleanDomain(s); c != "" && !own[c] {
			own[c] = true
			fn(c, "own")
		}
	}
	if l.URL != "" {
		if f, err := os.Open(e.dnsListPath(l.ID)); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				t := sc.Text()
				src := "url"
				if strings.HasPrefix(t, "@") {
					t, src = t[1:], "allow"
				}
				if t == "" || excl[t] || (src == "url" && own[t]) {
					continue
				}
				fn(t, src)
			}
			f.Close()
		}
	}
	for _, x := range l.Excluded {
		fn(x, "excluded")
	}
}

// pageOf sammelt Treffer (Teiltext q, Herkunft src) ab offset, höchstens limit.
func pageOf(q, src string, offset, limit int) (*DNSListPage, func(d, s string)) {
	q = strings.ToLower(strings.TrimSpace(q))
	p := &DNSListPage{Items: []DNSListEntry{}}
	return p, func(d, s string) {
		switch s {
		case "excluded":
			p.Excluded++
		case "own":
			p.Own++
			p.Total++
		default:
			p.Total++
		}
		if (src != "" && src != s) || (q != "" && !strings.Contains(d, q)) {
			return
		}
		if src == "" && s == "excluded" && q == "" {
			return // Herausgenommene nur bei Suche oder eigenem Filter zeigen
		}
		p.Matched++
		if p.Matched > offset && len(p.Items) < limit {
			p.Items = append(p.Items, DNSListEntry{d, s})
		}
	}
}

func clampPage(offset, limit int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return offset, limit
}

// DNSListEntries: Inhalt einer Liste durchsuchen.
func (e *Engine) DNSListEntries(o *store.Object, q, src string, offset, limit int) *DNSListPage {
	offset, limit = clampPage(offset, limit)
	p, add := pageOf(q, src, offset, limit)
	e.scanDNSList(DNSListFrom(o), add)
	return p
}

// DNSListHit: Treffer der Suche über alle Listen.
type DNSListHit struct {
	ID      int64          `json:"id"`
	Name    string         `json:"name"`
	Mode    string         `json:"mode"`
	Enabled bool           `json:"enabled"`
	Matched int            `json:"matched"`
	Items   []DNSListEntry `json:"items"`
	// Via: die Liste sperrt/erlaubt die gesuchte Domain über einen übergeordneten Namen (z. B. example.com)
	Via string `json:"via,omitempty"`
}

// SearchDNSLists durchsucht alle Listen nach einem Teiltext. Ist q ein Domainname, wird zusätzlich
// gemeldet, welche Liste ihn über einen übergeordneten Namen erfasst.
func (e *Engine) SearchDNSLists(q string) []DNSListHit {
	out := []DNSListHit{}
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) < 2 {
		return out
	}
	dom := cleanDomain(q)
	objs, _ := e.St.Objects("dnslist")
	for _, o := range objs {
		l := DNSListFrom(o)
		p, add := pageOf(q, "", 0, 8)
		e.scanDNSList(l, add)
		h := DNSListHit{ID: l.ID, Name: l.Name, Mode: l.Mode, Enabled: l.Enabled, Matched: p.Matched, Items: p.Items}
		if dom != "" {
			d := e.dnsListSets(l)
			for n := dom; n != ""; {
				if _, ok := d.block[n]; ok {
					h.Via = n
					break
				}
				if _, ok := d.allow[n]; ok {
					h.Via = n
					break
				}
				i := strings.IndexByte(n, '.')
				if i < 0 {
					break
				}
				n = n[i+1:]
			}
		}
		if h.Matched > 0 || h.Via != "" {
			out = append(out, h)
		}
	}
	return out
}

// EditDNSList passt eine Liste an:
//
//	add:     eigene Domains ergänzen (eine herausgenommene Domain wird stattdessen wieder aufgenommen)
//	remove:  eigene Einträge löschen; Domains der Online-Liste werden herausgenommen
//	restore: herausgenommene Domains wieder aufnehmen
func (e *Engine) EditDNSList(o *store.Object, add, remove, restore []string) (msg string, err error) {
	l := DNSListFrom(o)
	own := map[string]bool{}
	var ownList []string
	for _, s := range l.Entries {
		if c := cleanDomain(s); c != "" && !own[c] {
			own[c] = true
			ownList = append(ownList, c)
		}
	}
	excl := map[string]bool{}
	for _, x := range l.Excluded {
		excl[x] = true
	}
	clean := func(in []string) ([]string, error) {
		var out []string
		for _, s := range in {
			c := cleanDomain(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "||"), "^"))
			if c == "" {
				return nil, fmt.Errorf("„%s“ ist kein gültiger Domainname (Beispiel: werbung.de)", s)
			}
			out = append(out, c)
		}
		return out, nil
	}
	a, err := clean(add)
	if err != nil {
		return "", err
	}
	r, err := clean(remove)
	if err != nil {
		return "", err
	}
	rs, err := clean(restore)
	if err != nil {
		return "", err
	}
	// Welche der zu entfernenden Domains stehen in der Online-Liste?
	inURL := map[string]bool{}
	if len(r) > 0 && l.URL != "" {
		want := map[string]bool{}
		for _, d := range r {
			want[d] = true
		}
		if f, ferr := os.Open(e.dnsListPath(l.ID)); ferr == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				t := strings.TrimPrefix(sc.Text(), "@")
				if want[t] {
					inURL[t] = true
				}
			}
			f.Close()
		}
	}
	nAdd, nRem, nExcl, nRes := 0, 0, 0, 0
	for _, d := range rs {
		if excl[d] {
			delete(excl, d)
			nRes++
		}
	}
	for _, d := range a {
		if excl[d] {
			delete(excl, d)
			nRes++
		} else if !own[d] {
			own[d] = true
			ownList = append(ownList, d)
			nAdd++
		}
	}
	for _, d := range r {
		if own[d] {
			delete(own, d)
			nRem++
		}
		if inURL[d] && !excl[d] {
			excl[d] = true
			nExcl++
		}
	}
	entries := []string{}
	for _, d := range ownList {
		if own[d] {
			entries = append(entries, d)
		}
	}
	exclList := make([]string, 0, len(excl))
	for d := range excl {
		exclList = append(exclList, d)
	}
	sort.Strings(exclList)
	if len(entries) > maxDNSListOwn {
		return "", fmt.Errorf("höchstens %d eigene Einträge je Liste", maxDNSListOwn)
	}
	if len(exclList) > maxDNSListExcluded {
		return "", fmt.Errorf("höchstens %d herausgenommene Domains je Liste", maxDNSListExcluded)
	}
	if l.URL == "" && len(entries) == 0 {
		return "", fmt.Errorf("die Liste wäre danach leer – lösche sie stattdessen")
	}
	if nAdd+nRem+nExcl+nRes == 0 {
		return "Keine Änderung", nil
	}
	o.Data["entries"] = entries
	o.Data["excluded"] = exclList
	if err := e.St.SaveObject(o); err != nil {
		return "", err
	}
	var parts []string
	if nAdd > 0 {
		parts = append(parts, fmt.Sprintf("%d ergänzt", nAdd))
	}
	if nRem > 0 {
		parts = append(parts, fmt.Sprintf("%d eigene gelöscht", nRem))
	}
	if nExcl > 0 {
		parts = append(parts, fmt.Sprintf("%d herausgenommen", nExcl))
	}
	if nRes > 0 {
		parts = append(parts, fmt.Sprintf("%d wieder aufgenommen", nRes))
	}
	msg = strings.Join(parts, ", ")
	e.Log("info", "Blockliste „"+l.Name+"“ angepasst: "+msg)
	e.RequestApply()
	return msg, nil
}

// ---------- Vorschau bekannter Listen ----------

type listPreview struct {
	at           time.Time
	block, allow []string
	err          error
}

var previews = struct {
	mu sync.Mutex
	m  map[string]*listPreview
}{m: map[string]*listPreview{}}

// PreviewDNSList lädt eine Online-Liste (15 Minuten im Speicher, höchstens 3 gleichzeitig) und
// durchsucht sie – ohne sie anzulegen.
func (e *Engine) PreviewDNSList(raw, q string, offset, limit int) (*DNSListPage, error) {
	offset, limit = clampPage(offset, limit)
	previews.mu.Lock()
	pv := previews.m[raw]
	if pv != nil && time.Since(pv.at) > 15*time.Minute {
		pv = nil
	}
	previews.mu.Unlock()
	if pv == nil {
		block, allow, _, err := e.downloadDomainList(raw)
		pv = &listPreview{at: time.Now(), block: block, allow: allow, err: err}
		previews.mu.Lock()
		if len(previews.m) >= 3 {
			var oldest string
			for k, v := range previews.m {
				if oldest == "" || v.at.Before(previews.m[oldest].at) {
					oldest = k
				}
			}
			delete(previews.m, oldest)
		}
		previews.m[raw] = pv
		previews.mu.Unlock()
	}
	if pv.err != nil {
		return nil, pv.err
	}
	p, add := pageOf(q, "", offset, limit)
	for _, d := range pv.block {
		add(d, "url")
	}
	for _, d := range pv.allow {
		add(d, "allow")
	}
	return p, nil
}
