package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpnpanel/internal/store"
)

// Statistik je SmartDNS-Profil: wie oft eine Weiterleitung gegriffen hat (DNS-Anfragen), für welche
// Domains, Namen und Geräte, wann (Stundenverlauf, 7 Tage) und wie viel Verkehr darüber lief.
//
// Verkehr: VPN-Geräte (WireGuard, OpenVPN) über benannte nft-Zähler je Weiterleitung (s<Regel>_up an der
// Ziel-Regel, s<Regel>_dn für Antworten aus den Zieladressen); Geräte ohne VPN über den SmartDNS-Proxy
// (genau, beide Richtungen). VLESS und Hysteria2 leiten selbst – dort zählen nur die Anfragen.
// Gespeichert in <Daten>/smartstats.json (bei jedem Einsammeln, wenn sich etwas geändert hat).

const (
	smartRuleBase  = 1_000_000_000
	smartKeepHours = 7 * 24
	smartMaxNames  = 200
	smartMaxDevs   = 1000
)

// SmartCount: Zähler einer Domain, eines Namens, eines Geräts, einer Weiterleitung oder Stunde.
type SmartCount struct {
	Q     int64  `json:"q"`               // DNS-Anfragen (A)
	Bytes int64  `json:"bytes,omitempty"` // Verkehr (beide Richtungen)
	Conns int64  `json:"conns,omitempty"` // Verbindungen über den Proxy
	Last  int64  `json:"last,omitempty"`
	Err   string `json:"err,omitempty"` // letzter Fehler des Proxys
}

// SmartProfStat: Statistik eines Profils.
type SmartProfStat struct {
	Since   int64                  `json:"since"`
	Queries int64                  `json:"queries"`
	Last    int64                  `json:"last"`
	Up      int64                  `json:"up"`         // VPN: zu den Zielen
	Down    int64                  `json:"down"`       // VPN: von den Zielen
	Proxy   int64                  `json:"proxy"`      // ohne VPN über den Proxy (beide Richtungen)
	PUp     int64                  `json:"proxy_up"`   // ohne VPN: vom Gerät zum Ziel
	PDown   int64                  `json:"proxy_down"` // ohne VPN: vom Ziel zum Gerät
	Conns   int64                  `json:"conns"`
	Routes  map[int]*SmartCount    `json:"routes"`  // Weiterleitung (Index im Profil)
	Domains map[string]*SmartCount `json:"domains"` // Eintrag im Profil
	Names   map[string]*SmartCount `json:"names"`   // tatsächlich angefragter Name
	Devices map[int64]*SmartCount  `json:"devices"` // VPN-Gerät (>0) bzw. Gerät ohne VPN (<0)
	Hours   map[int64]*SmartCount  `json:"hours"`   // Unix-Stunde
}

func newSmartProfStat(now int64) *SmartProfStat {
	return &SmartProfStat{Since: now, Routes: map[int]*SmartCount{}, Domains: map[string]*SmartCount{}, Names: map[string]*SmartCount{},
		Devices: map[int64]*SmartCount{}, Hours: map[int64]*SmartCount{}}
}

type smartStats struct {
	mu     sync.Mutex
	loaded bool
	dirty  bool
	p      map[int64]*SmartProfStat
	nft    map[string]int64 // letzter Stand der nft-Zähler
	nftMu  sync.Mutex       // Lesen und Auswerten der nft-Zähler nacheinander (sonst doppelt gezählt)
	nftAt  time.Time        // zuletzt gelesen
	nftOK  bool             // Ausgangsstand bekannt (sonst: erstes Lesen nach dem Start setzt ihn nur)
	pend   [2][2]int64      // noch nicht gespeicherter Verkehr für den Verlauf: [VPN|Proxy][up|down]
	vUp    atomic.Int64     // VPN über SmartDNS seit dem Start (für die Live-Grafik)
	vDown  atomic.Int64
}

// splitSmartRule: Regel-ID → Profil und Index der Weiterleitung.
func splitSmartRule(rid int64) (profile int64, idx int, ok bool) {
	if rid < smartRuleBase {
		return 0, 0, false
	}
	return (rid - smartRuleBase) / 100, int((rid - smartRuleBase) % 100), true
}

func (e *Engine) smartStatsPath() string { return filepath.Join(e.Cfg.DataDir, "smartstats.json") }

// stat liefert (und legt an) die Statistik eines Profils; mu muss gehalten sein.
func (s *smartStats) stat(e *Engine, profile int64, now int64) *SmartProfStat {
	if !s.loaded {
		s.loaded = true
		s.p = map[int64]*SmartProfStat{}
		if b, err := os.ReadFile(e.smartStatsPath()); err == nil {
			_ = json.Unmarshal(b, &s.p)
		}
		for _, st := range s.p {
			st.fix()
		}
	}
	st := s.p[profile]
	if st == nil {
		st = newSmartProfStat(now)
		s.p[profile] = st
	}
	return st
}

func (st *SmartProfStat) fix() {
	if st.Routes == nil {
		st.Routes = map[int]*SmartCount{}
	}
	if st.Domains == nil {
		st.Domains = map[string]*SmartCount{}
	}
	if st.Names == nil {
		st.Names = map[string]*SmartCount{}
	}
	if st.Devices == nil {
		st.Devices = map[int64]*SmartCount{}
	}
	if st.Hours == nil {
		st.Hours = map[int64]*SmartCount{}
	}
}

func cnt[K comparable](m map[K]*SmartCount, k K) *SmartCount {
	c := m[k]
	if c == nil {
		c = &SmartCount{}
		m[k] = c
	}
	return c
}

// smartQuery: Eine DNS-Anfrage (A) wurde per SmartDNS über eine Gruppe geleitet.
func (e *Engine) smartQuery(rid int64, dom, name string, dev int64) {
	profile, idx, ok := splitSmartRule(rid)
	if !ok {
		return
	}
	now := time.Now().Unix()
	s := &e.smartStat
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stat(e, profile, now)
	st.Queries++
	st.Last = now
	for _, c := range []*SmartCount{cnt(st.Routes, idx), cnt(st.Domains, dom), cnt(st.Hours, now/3600)} {
		c.Q++
		c.Last = now
	}
	if _, ok := st.Names[name]; ok || len(st.Names) < smartMaxNames*2 {
		c := cnt(st.Names, name)
		c.Q++
		c.Last = now
	}
	if _, ok := st.Devices[dev]; ok || len(st.Devices) < smartMaxDevs {
		c := cnt(st.Devices, dev)
		c.Q++
		c.Last = now
	}
	s.dirty = true
}

// smartProxied: Verbindung (n < 0) bzw. Verkehr (n ≥ 0) eines Geräts ohne VPN über den Proxy.
func (e *Engine) smartProxied(rid int64, dom string, dev int64, n int64, errText string) {
	profile, idx, ok := splitSmartRule(rid)
	if !ok {
		return
	}
	now := time.Now().Unix()
	s := &e.smartStat
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stat(e, profile, now)
	cs := []*SmartCount{cnt(st.Routes, idx), cnt(st.Domains, dom), cnt(st.Hours, now/3600)}
	if _, ok := st.Devices[dev]; ok || len(st.Devices) < smartMaxDevs {
		cs = append(cs, cnt(st.Devices, dev))
	}
	for _, c := range cs {
		if n < 0 {
			c.Conns++
		} else {
			c.Bytes += n
		}
		c.Last = now
	}
	if errText != "" {
		cnt(st.Domains, dom).Err = errText
	} else if n < 0 {
		cnt(st.Domains, dom).Err = ""
	}
	if n < 0 {
		st.Conns++
	} else {
		st.Proxy += n
	}
	st.Last = now
	s.dirty = true
}

// smartProxyBytes: Verkehr eines Geräts ohne VPN über den Proxy, getrennt nach Richtung (läuft während
// der Verbindung alle paar Sekunden ein, nicht erst am Ende).
func (e *Engine) smartProxyBytes(rid int64, dom string, dev int64, up, down int64) {
	if up+down <= 0 {
		return
	}
	e.smartProxied(rid, dom, dev, up+down, "")
	profile, _, ok := splitSmartRule(rid)
	if !ok {
		return
	}
	s := &e.smartStat
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stat(e, profile, time.Now().Unix())
	st.PUp += up
	st.PDown += down
	s.pend[store.SmartProxy][0] += up
	s.pend[store.SmartProxy][1] += down
}

// smartTraffic: Verkehr einer Weiterleitung laut nft-Zählern (Zuwachs seit dem letzten Lesen).
func (e *Engine) smartTraffic(rid int64, up, down int64, now int64) {
	profile, idx, ok := splitSmartRule(rid)
	if !ok || up+down <= 0 {
		return
	}
	s := &e.smartStat
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stat(e, profile, now)
	st.Up += up
	st.Down += down
	for _, c := range []*SmartCount{cnt(st.Routes, idx), cnt(st.Hours, now/3600)} {
		c.Bytes += up + down
	}
	s.pend[store.SmartVPN][0] += up
	s.pend[store.SmartVPN][1] += down
	s.vUp.Add(up)
	s.vDown.Add(down)
	s.dirty = true
}

// collectSmart: nft-Zähler lesen und die Statistik speichern (beim Einsammeln).
func (e *Engine) collectSmart(now time.Time) {
	e.readSmartCounters(now)
	e.saveSmartStats(now)
	e.flushSmartTraffic(now)
}

// flushSmartTraffic schreibt den SmartDNS-Verkehr seit dem letzten Mal in den Stundenverlauf.
func (e *Engine) flushSmartTraffic(now time.Time) {
	s := &e.smartStat
	s.mu.Lock()
	p := s.pend
	s.pend = [2][2]int64{}
	s.mu.Unlock()
	for kind, v := range p {
		if err := e.St.AddSmartTraffic(kind, now.Unix(), v[0], v[1]); err != nil {
			e.Log("error", "SmartDNS-Verkehr speichern: "+err.Error())
		}
	}
}

// readSmartCounters liest die nft-Zähler der SmartDNS-Weiterleitungen (VPN-Verkehr).
func (e *Engine) readSmartCounters(now time.Time) {
	if e.Sys.DryRun() {
		return
	}
	s := &e.smartStat
	s.nftMu.Lock()
	defer s.nftMu.Unlock()
	s.nftAt = now
	if out, err := e.Sys.Run("nft", "-j", "list", "counters", "table", "inet", nftTable); err == nil {
		// Nach einem Neustart des Panels läuft die nft-Tabelle samt Zählern weiter (unverändert) –
		// das erste Lesen setzt nur den Ausgangsstand, sonst zählte alles bisherige noch einmal.
		e.smartCountersMode(out, now.Unix(), !s.nftOK)
		s.nftOK = true
	}
}

// smartNftFresh: Die nft-Tabelle wurde eben neu angelegt – alle Zähler beginnen bei 0 und zählen ganz.
func (e *Engine) smartNftFresh() {
	s := &e.smartStat
	s.nftMu.Lock()
	defer s.nftMu.Unlock()
	s.mu.Lock()
	s.nft = map[string]int64{}
	s.mu.Unlock()
	s.nftOK = true
}

// RefreshSmartCounters: VPN-Verkehr für die Live-Ansicht nachlesen (höchstens alle 4 Sekunden).
func (e *Engine) RefreshSmartCounters() {
	s := &e.smartStat
	s.nftMu.Lock()
	recent := time.Since(s.nftAt) < 4*time.Second
	s.nftMu.Unlock()
	if !recent {
		e.readSmartCounters(time.Now())
	}
}

// smartCounters wertet `nft -j list counters` aus. Die Tabelle wird bei Änderungen neu angelegt
// (Zähler beginnen bei 0) – ein kleinerer Wert als zuletzt zählt deshalb ganz.
func (e *Engine) smartCounters(out string, now int64) { e.smartCountersMode(out, now, false) }

// smartCountersMode: base = nur den Stand merken, nichts zählen.
func (e *Engine) smartCountersMode(out string, now int64, base bool) {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name  string `json:"name"`
				Bytes int64  `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return
	}
	type ud struct{ up, down int64 }
	delta := map[int64]*ud{}
	s := &e.smartStat
	s.mu.Lock()
	if s.nft == nil {
		s.nft = map[string]int64{}
	}
	seen := map[string]bool{}
	for _, it := range doc.Nftables {
		c := it.Counter
		if c == nil || !strings.HasPrefix(c.Name, "s") {
			continue
		}
		var rid int64
		var dir string
		if n, _ := fmt.Sscanf(c.Name, "s%d_%s", &rid, &dir); n != 2 || rid < smartRuleBase {
			continue
		}
		seen[c.Name] = true
		d := c.Bytes
		if last, ok := s.nft[c.Name]; ok && c.Bytes >= last {
			d = c.Bytes - last
		}
		s.nft[c.Name] = c.Bytes
		x := delta[rid]
		if x == nil {
			x = &ud{}
			delta[rid] = x
		}
		if dir == "up" {
			x.up += d
		} else {
			x.down += d
		}
	}
	for k := range s.nft {
		if !seen[k] {
			delete(s.nft, k)
		}
	}
	s.mu.Unlock()
	if base {
		return
	}
	for rid, x := range delta {
		e.smartTraffic(rid, x.up, x.down, now)
	}
}

// saveSmartStats: alte Stunden und seltene Namen wegräumen, speichern.
func (e *Engine) saveSmartStats(now time.Time) {
	s := &e.smartStat
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.p == nil {
		return
	}
	cut := now.Unix()/3600 - smartKeepHours
	for _, st := range s.p {
		for h := range st.Hours {
			if h < cut {
				delete(st.Hours, h)
			}
		}
		if len(st.Names) > smartMaxNames {
			type kv struct {
				k string
				c *SmartCount
			}
			var all []kv
			for k, c := range st.Names {
				all = append(all, kv{k, c})
			}
			sort.Slice(all, func(i, j int) bool { return all[i].c.Q > all[j].c.Q })
			for _, x := range all[smartMaxNames:] {
				delete(st.Names, x.k)
			}
		}
	}
	b, err := json.Marshal(s.p)
	if err != nil {
		return
	}
	tmp := e.smartStatsPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, e.smartStatsPath()) == nil {
		s.dirty = false
	}
}

// SmartStats: Kopie der Statistik aller Profile (für die Oberfläche).
func (e *Engine) SmartStats() map[int64]*SmartProfStat {
	s := &e.smartStat
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stat(e, 0, 0) // laden
	delete(s.p, 0)
	b, _ := json.Marshal(s.p)
	out := map[int64]*SmartProfStat{}
	_ = json.Unmarshal(b, &out)
	for _, st := range out {
		st.fix()
	}
	return out
}

// ResetSmartStats: Statistik eines Profils (0 = aller) zurücksetzen.
func (e *Engine) ResetSmartStats(profile int64) {
	s := &e.smartStat
	s.mu.Lock()
	s.stat(e, 0, 0)
	if profile == 0 {
		s.p = map[int64]*SmartProfStat{}
	} else {
		delete(s.p, profile)
	}
	delete(s.p, 0)
	s.dirty = true
	s.mu.Unlock()
	e.saveSmartStats(time.Now())
}

// ForgetSmartStats: Statistik eines gelöschten Profils entfernen.
func (e *Engine) ForgetSmartStats(profile int64) { e.ResetSmartStats(profileOrSkip(profile)) }

func profileOrSkip(p int64) int64 {
	if p == 0 {
		return -1 // nichts löschen
	}
	return p
}

// DemoSmartStats: ausgedachte Statistik für den Testmodus (nur, wenn noch keine da ist).
func (e *Engine) DemoSmartStats() {
	if !e.Sys.DryRun() || len(e.SmartStats()) > 0 {
		return
	}
	snap, err := e.Snapshot()
	if err != nil {
		return
	}
	var peers []int64
	for id := range snap.Peers {
		peers = append(peers, id)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i] < peers[j] })
	var clients []int64
	if cs, err := e.St.Objects("dnsclient"); err == nil {
		for _, o := range cs {
			clients = append(clients, -o.ID)
		}
	}
	now := time.Now()
	rnd := uint64(42)
	next := func(n int) int { // einfacher Zufall, immer gleich
		rnd = rnd*6364136223846793005 + 1442695040888963407
		return int((rnd >> 33) % uint64(n))
	}
	s := &e.smartStat
	s.mu.Lock()
	for pi, p := range e.smartProfiles() {
		st := s.stat(e, p.ID, now.Add(-6*24*time.Hour).Unix())
		devs := append([]int64{}, clients...)
		for i := 0; i < 6+pi*3 && i < len(peers); i++ {
			devs = append(devs, peers[(i*7+pi)%len(peers)])
		}
		for ri, r := range p.Routes {
			for di, d := range r.Domains {
				if di%5 == 4 { // ein paar Einträge greifen nie
					continue
				}
				weight := 40 / (di + 1)
				for h := 0; h < smartKeepHours; h++ {
					t := now.Add(-time.Duration(h) * time.Hour)
					hour := t.Hour()
					busy := 1
					if hour >= 18 && hour <= 23 {
						busy = 5
					} else if hour >= 8 {
						busy = 2
					}
					q := next(weight*busy + 1)
					if q == 0 {
						continue
					}
					ts := t.Unix() - int64(next(3500))
					dev := devs[next(len(devs))]
					name := d
					if next(3) > 0 {
						name = []string{"www.", "api.", "cdn.", "assets.", "ipv4-c0" + fmt.Sprint(next(90)+10) + "."}[next(5)] + d
					}
					bytes := int64(q) * int64(next(4_000_000)+200_000)
					for _, c := range []*SmartCount{cnt(st.Routes, ri), cnt(st.Domains, d), cnt(st.Hours, ts/3600), cnt(st.Names, name), cnt(st.Devices, dev)} {
						c.Q += int64(q)
						c.Bytes += bytes
						if ts > c.Last {
							c.Last = ts
						}
					}
					st.Queries += int64(q)
					if dev < 0 {
						st.Proxy += bytes
						st.PUp += bytes / 15
						st.PDown += bytes - bytes/15
						st.Conns += int64(q)
						cnt(st.Devices, dev).Conns += int64(q)
					} else {
						st.Up += bytes / 12
						st.Down += bytes - bytes/12
					}
					if ts > st.Last {
						st.Last = ts
					}
				}
			}
			if ri == 0 && len(r.Domains) > 1 {
				cnt(st.Domains, r.Domains[1]).Err = "Verbinden über die Gruppe: Zeitüberschreitung"
			}
		}
	}
	s.dirty = true
	s.mu.Unlock()
	e.saveSmartStats(now)
}
