package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vpnpanel/internal/store"
)

// Online-Listen: IP-Listen können zusätzlich zu den eigenen Einträgen eine Adresse (URL) haben,
// von der regelmäßig eine Liste geladen wird (eine Adresse bzw. ein Netz pro Zeile). Der geladene
// Inhalt liegt als Datei im Datenverzeichnis (lists/<ID>.txt), der Stand in den Einstellungen.

const (
	maxOnlineEntries = 300000
	maxListBytes     = 32 << 20
)

// ListStatus: Stand des letzten Abrufs einer Online-Liste.
type ListStatus struct {
	At      int64  `json:"at"`              // letzter erfolgreicher Abruf
	Tried   int64  `json:"tried"`           // letzter Versuch
	Count   int    `json:"count"`           // geladene Einträge
	Skipped int    `json:"skipped"`         // nicht lesbare Zeilen
	Error   string `json:"error,omitempty"` // Fehler des letzten Versuchs
}

type listCacheEntry struct {
	sig    string
	v4, v6 []netip.Prefix
}

type listState struct {
	mu    sync.Mutex
	cache map[int64]*listCacheEntry
	busy  map[int64]bool
}

func (e *Engine) listPath(id int64) string {
	return filepath.Join(e.Cfg.DataDir, "lists", strconv.FormatInt(id, 10)+".txt")
}

func (e *Engine) ListStatus(id int64) ListStatus {
	var st ListStatus
	_ = json.Unmarshal([]byte(e.St.GetSetting(fmt.Sprintf("state:list:%d", id), "")), &st)
	return st
}

func (e *Engine) setListStatus(id int64, st ListStatus) {
	b, _ := json.Marshal(st)
	_ = e.St.SetSetting(fmt.Sprintf("state:list:%d", id), string(b))
}

// DeleteListData entfernt geladenen Inhalt und Stand (beim Löschen der Liste bzw. der Adresse).
func (e *Engine) DeleteListData(id int64) {
	_ = os.Remove(e.listPath(id))
	_ = e.St.SetSetting(fmt.Sprintf("state:list:%d", id), "")
	e.lists.mu.Lock()
	delete(e.lists.cache, id)
	e.lists.mu.Unlock()
}

// listPrefixes: eigene Einträge plus geladener Inhalt, getrennt nach IPv4 und IPv6 (zwischengespeichert).
func (e *Engine) listPrefixes(l *IPList) (v4, v6 []netip.Prefix) {
	sig := fmt.Sprintf("%d|%s", len(l.Entries), hashStr(strings.Join(l.Entries, ",")))
	var fi os.FileInfo
	if l.URL != "" {
		if f, err := os.Stat(e.listPath(l.ID)); err == nil {
			fi = f
			sig += fmt.Sprintf("|%d|%d", f.ModTime().UnixNano(), f.Size())
		}
	}
	e.lists.mu.Lock()
	defer e.lists.mu.Unlock()
	if c := e.lists.cache[l.ID]; c != nil && c.sig == sig {
		return c.v4, c.v6
	}
	c := &listCacheEntry{sig: sig}
	seen := map[netip.Prefix]bool{}
	add := func(s string) {
		p, err := netip.ParsePrefix(s)
		if err != nil || seen[p] {
			return
		}
		seen[p] = true
		if p.Addr().Is4() {
			c.v4 = append(c.v4, p)
		} else {
			c.v6 = append(c.v6, p)
		}
	}
	for _, s := range l.Entries {
		add(s)
	}
	if fi != nil {
		if f, err := os.Open(e.listPath(l.ID)); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				add(sc.Text())
			}
			f.Close()
		}
	}
	if e.lists.cache == nil {
		e.lists.cache = map[int64]*listCacheEntry{}
	}
	e.lists.cache[l.ID] = c
	return c.v4, c.v6
}

// ParseOnlineList liest eine Liste aus dem Netz: pro Zeile das erste Feld als Adresse oder Netz.
// Kommentare (#, ;, //) und nicht lesbare Zeilen werden übersprungen (gezählt), Doppelte entfernt.
func ParseOnlineList(r io.Reader, max int) (entries []string, skipped int, err error) {
	seen := map[netip.Prefix]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		for _, c := range []string{"#", ";", "//"} {
			if i := strings.Index(line, c); i >= 0 {
				line = line[:i]
			}
		}
		f := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == '\r' })
		if len(f) == 0 {
			continue
		}
		p, perr := parsePrefix(f[0])
		if perr != nil || p.Bits() == 0 || p.Addr().IsUnspecified() {
			skipped++
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		entries = append(entries, p.String())
		if len(entries) > max {
			return nil, skipped, fmt.Errorf("mehr als %d Einträge", max)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, skipped, err
	}
	return entries, skipped, nil
}

// listAllowLocal: nur für Tests (Testserver auf 127.0.0.1).
var listAllowLocal = false

// listHTTP: Abruf nur von öffentlichen Adressen – die Adresse der Liste kommt zwar vom Admin,
// soll aber keine Dienste im lokalen Netz des Servers ansprechen können (auch nicht per Umleitung).
func listHTTP() *http.Client {
	d := &net.Dialer{Timeout: 15 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		a, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		a = a.Unmap()
		if !listAllowLocal && (a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() ||
			netip.MustParsePrefix("100.64.0.0/10").Contains(a)) {
			return fmt.Errorf("Adresse %s liegt im lokalen Netz", a)
		}
		return nil
	}}
	return &http.Client{Timeout: 120 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("zu viele Umleitungen")
			}
			return nil
		}}
}

// CheckListURL prüft die Adresse einer Online-Liste.
func CheckListURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return fmt.Errorf("Adresse der Liste muss mit http:// oder https:// beginnen")
	}
	if len(raw) > 500 {
		return fmt.Errorf("Adresse der Liste ist zu lang")
	}
	return nil
}

// FetchList lädt eine Online-Liste neu. changed = Inhalt hat sich geändert.
func (e *Engine) FetchList(id int64) (changed bool, err error) {
	o, err := e.St.Object("iplist", id)
	if err != nil {
		return false, err
	}
	l := IPListFrom(o)
	if l.URL == "" {
		return false, fmt.Errorf("die Liste hat keine Adresse")
	}
	e.lists.mu.Lock()
	if e.lists.busy == nil {
		e.lists.busy = map[int64]bool{}
	}
	if e.lists.busy[id] {
		e.lists.mu.Unlock()
		return false, fmt.Errorf("die Liste wird gerade geladen")
	}
	e.lists.busy[id] = true
	e.lists.mu.Unlock()
	defer func() {
		e.lists.mu.Lock()
		delete(e.lists.busy, id)
		e.lists.mu.Unlock()
	}()

	st := e.ListStatus(id)
	st.Tried = time.Now().Unix()
	fail := func(err error) (bool, error) {
		if st.Error != err.Error() {
			e.Log("warn", fmt.Sprintf("IP-Liste „%s“: Abruf fehlgeschlagen – %v", l.Name, err))
		}
		st.Error = err.Error()
		e.setListStatus(id, st)
		return false, err
	}
	if err := CheckListURL(l.URL); err != nil {
		return fail(err)
	}
	var entries []string
	var skipped int
	if u, _ := url.Parse(l.URL); e.Sys.DryRun() && u != nil && u.Hostname() != "127.0.0.1" {
		// Testmodus: nichts aus dem Netz laden – Beispielinhalt
		entries = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"}
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
		lr := &io.LimitedReader{R: resp.Body, N: maxListBytes + 1}
		entries, skipped, err = ParseOnlineList(lr, maxOnlineEntries)
		if err != nil {
			return fail(err)
		}
		if lr.N <= 0 {
			return fail(fmt.Errorf("Liste ist größer als %d MB", maxListBytes>>20))
		}
	}
	if len(entries) == 0 {
		return fail(fmt.Errorf("keine Adressen gefunden (%d Zeilen nicht lesbar) – ist das eine Liste mit einer Adresse pro Zeile?", skipped))
	}
	data := []byte(strings.Join(entries, "\n") + "\n")
	path := e.listPath(id)
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
		e.Log("info", fmt.Sprintf("IP-Liste „%s“ geladen: %d Einträge", l.Name, len(entries)))
	}
	st.At, st.Count, st.Skipped, st.Error = st.Tried, len(entries), skipped, ""
	e.setListStatus(id, st)
	return changed, nil
}

// RunLists lädt fällige Online-Listen (prüft jede Minute).
func (e *Engine) RunLists(stop <-chan struct{}) {
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		e.refreshExtHosts()
		e.RunDNSAuto(false)
		if e.encDNSOn() && !e.Sys.DryRun() {
			_ = e.RenewEncCert(false)
		}
		if ch1, ch2 := e.refreshLists(time.Now()), e.refreshDNSLists(time.Now()); ch1 || ch2 {
			e.RequestApply()
		}
		t.Reset(time.Minute)
	}
}

func (e *Engine) refreshLists(now time.Time) (changed bool) {
	objs, _ := e.St.Objects("iplist")
	for _, o := range objs {
		l := IPListFrom(o)
		if !l.Enabled || l.URL == "" {
			continue
		}
		if !listDue(l, e.ListStatus(l.ID), now) {
			continue
		}
		if ch, _ := e.FetchList(l.ID); ch {
			changed = true
		}
	}
	return changed
}

// listDue: Ist ein Abruf fällig? Nie geladene Listen sofort; nach einem Fehler spätestens nach
// einer Stunde erneut; „nur von Hand“ (Refresh 0) nach dem ersten Erfolg nicht mehr.
func listDue(l *IPList, st ListStatus, now time.Time) bool { return listDueRefresh(l.Refresh, st, now) }

func listDueRefresh(refresh int, st ListStatus, now time.Time) bool {
	if st.At == 0 && st.Tried == 0 {
		return true
	}
	wait := time.Duration(refresh) * time.Hour
	if st.Error != "" && (wait == 0 || wait > time.Hour) {
		wait = time.Hour
	}
	if wait == 0 {
		return false
	}
	return now.Sub(time.Unix(st.Tried, 0)) >= wait
}

// ListInfo: Angaben für die Oberfläche.
func (e *Engine) ListInfo(o *store.Object) (st ListStatus, total int) {
	l := IPListFrom(o)
	v4, v6 := e.listPrefixes(l)
	return e.ListStatus(l.ID), len(v4) + len(v6)
}
