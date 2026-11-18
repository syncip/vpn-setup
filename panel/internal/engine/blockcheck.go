package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto/proxy"
	"vpnpanel/internal/store"
)

// Block-Prüfung je Ausgangsgruppe (siehe exits.BlockCheck): Ziele werden über jeden Ausgang der
// Gruppe geprüft, die Ergebnisse liegen in der Datenbank (block_results) und werden nur in großen
// Abständen erneuert. Sperrt ein Ziel den Ausgang, über den es gerade laufen würde (Captcha,
// Sperrseite, Fehlversuche in Folge), und ist es über einen anderen Ausgang der Gruppe erreichbar,
// bekommt es eine Ausnahme: Es läuft dann über diesen Ausgang (nft-Sets bzw. Proxy).
//
// Auslöser: Takt (jede Minute, nur fällige Prüfungen), Fehlschläge aus dem Verkehr (Proxy, passive
// Erkennung) und der Knopf „Jetzt prüfen“.

const (
	blockTick       = time.Minute
	blockPerTick    = 30               // höchstens so viele Prüfungen je Takt
	blockParallel   = 4                // gleichzeitig
	blockErrRetry   = 10 * time.Minute // Fehler (noch unter der Grenze) bald erneut prüfen
	blockKeep       = 30 * 24 * time.Hour
	blockTopWindow  = 7 * 24 * time.Hour
	blockFailRepeat = 10 * time.Second // Fehlschläge desselben Ziels/Ausgangs zählen höchstens so oft
)

type blockState struct {
	mu      sync.Mutex
	wake    chan struct{}
	urgent  map[string]bool      // „Gruppe|Domain“ → alle Ausgänge sofort prüfen
	lastErr map[string]time.Time // „Domain|Ausgang“ → letzter gemeldeter Fehlschlag
	ov      map[int64]map[string]int64
	running map[string]bool // laufende Prüfungen „Domain|Ausgang“
	pruned  time.Time
	last    time.Time
	on      map[int64]bool                   // Gruppen mit Block-Prüfung → Echtzeit-Ausweichen im Proxy
	names   map[int64]map[netip.Addr]nameRec // Gruppe → Adresse → Name (DNS-Antworten)
	syn     map[string]*synRec               // hängende Verbindungen (passive Erkennung)
}

func (b *blockState) init() {
	if b.wake == nil {
		b.wake = make(chan struct{}, 1)
		b.urgent, b.lastErr, b.running = map[string]bool{}, map[string]time.Time{}, map[string]bool{}
	}
}

func (e *Engine) blockKick() {
	e.blk.mu.Lock()
	e.blk.init()
	w := e.blk.wake
	e.blk.mu.Unlock()
	select {
	case w <- struct{}{}:
	default:
	}
}

// RunBlockCheck: Takt der Block-Prüfung.
func (e *Engine) RunBlockCheck(stop <-chan struct{}) {
	e.blk.mu.Lock()
	e.blk.init()
	w := e.blk.wake
	e.blk.mu.Unlock()
	proxy.ExitRoute = e.proxyRoute
	proxy.ExitFail = e.BlockFail
	t := time.NewTicker(blockTick)
	defer t.Stop()
	pt := time.NewTicker(passiveEvery)
	defer pt.Stop()
	select { // erst nach dem Hochfahren der Ausgänge
	case <-stop:
		return
	case <-time.After(20 * time.Second):
	}
	for {
		e.BlockTick()
	wait:
		select {
		case <-stop:
			return
		case <-pt.C:
			e.passiveTick()
			goto wait
		case <-t.C:
		case <-w:
		}
	}
}

// blockGroups: Gruppen mit eingeschalteter Block-Prüfung.
func (e *Engine) blockGroups() []*exits.Group {
	_, gs := e.LoadExits()
	var out []*exits.Group
	for _, g := range gs {
		if g.Enabled && g.Block.On && g.Blocked == "" {
			out = append(out, g)
		}
	}
	return out
}

// blockTargets: Ziele einer Gruppe (fest eingetragene + meistbesuchte).
func (e *Engine) blockTargets(g *exits.Group, now time.Time) []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		if d = exits.NormDomain(d); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, d := range g.Block.Domains {
		add(d)
	}
	if g.Block.Auto {
		top, _ := e.St.TopGroupDomains(g.ID, now.Add(-blockTopWindow).Unix(), g.Block.Top)
		for _, d := range top {
			add(d)
		}
	}
	return out
}

func blockBad(r store.BlockResult, fails int) bool {
	return r.Status == "captcha" || r.Status == "blocked" || r.Fails >= fails
}

func blockDue(r store.BlockResult, ok bool, b exits.BlockCheck, now time.Time) bool {
	if !ok || r.Checked == 0 {
		return true
	}
	age := now.Sub(time.Unix(r.Checked, 0))
	switch {
	case r.Status == "ok" && r.Fails == 0:
		return age >= time.Duration(b.OkHours)*time.Hour
	case blockBad(r, b.Fails):
		return age >= time.Duration(b.BadHours)*time.Hour
	}
	return age >= blockErrRetry // Fehler unter der Grenze bzw. gemeldet nach „ok“: bald nachprüfen
}

type blockJob struct {
	gid    int64
	domain string
	exit   int64
	mark   uint32
}

// BlockTick: fällige Prüfungen ausführen, danach die Ausnahmen neu bestimmen.
func (e *Engine) BlockTick() {
	now := time.Now()
	groups := e.blockGroups()
	e.blk.mu.Lock()
	e.blk.init()
	urgent := e.blk.urgent
	e.blk.urgent = map[string]bool{}
	e.blk.last = now
	e.blk.on = map[int64]bool{}
	for _, g := range groups {
		e.blk.on[g.ID] = g.Block.Realtime
	}
	e.blk.mu.Unlock()
	res, _ := e.St.BlockResults()
	if res == nil {
		res = map[string]map[int64]store.BlockResult{}
	}
	var jobs, later []blockJob
	targets := map[int64][]string{}
	for _, g := range groups {
		ts := e.blockTargets(g, now)
		// gemeldete Fehlschläge (Proxy) zählen auch für Ziele außerhalb der Liste
		for d, byExit := range res {
			for _, x := range g.Exits {
				if r, ok := byExit[x]; ok && r.Status != "ok" || ok && r.Fails > 0 {
					ts = append(ts, d)
					break
				}
			}
		}
		ts = uniq(ts)
		targets[g.ID] = ts
		usable := e.Exits.Usable(g.ID)
		for _, d := range ts {
			force := urgent[fmt.Sprintf("%d|%s", g.ID, d)]
			for _, c := range usable {
				r, ok := res[d][c.Exit]
				if force || blockDue(r, ok, g.Block, now) {
					j := blockJob{g.ID, d, c.Exit, c.Mark}
					if force || !ok || r.Checked == 0 || r.Fails > 0 {
						jobs = append(jobs, j)
					} else {
						later = append(later, j)
					}
				}
			}
		}
	}
	jobs = append(jobs, later...)
	jobs = dedupJobs(jobs)
	if len(jobs) > blockPerTick {
		jobs = jobs[:blockPerTick]
		e.blockKickLater()
	}
	e.runBlockJobs(jobs)
	e.decideOverrides(groups, targets)
	if now.Sub(e.blk.pruned) > 24*time.Hour {
		_ = e.St.PruneBlockResults(now.Add(-blockKeep).Unix())
		e.blk.pruned = now
	}
}

func (e *Engine) blockKickLater() {
	go func() { time.Sleep(5 * time.Second); e.blockKick() }()
}

func uniq(l []string) []string {
	seen := map[string]bool{}
	out := l[:0]
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupJobs(l []blockJob) []blockJob {
	seen := map[string]bool{}
	var out []blockJob
	for _, j := range l {
		k := fmt.Sprintf("%s|%d", j.domain, j.exit)
		if !seen[k] {
			seen[k] = true
			out = append(out, j)
		}
	}
	return out
}

func (e *Engine) runBlockJobs(jobs []blockJob) {
	sem := make(chan struct{}, blockParallel)
	var wg sync.WaitGroup
	for _, j := range jobs {
		k := fmt.Sprintf("%s|%d", j.domain, j.exit)
		e.blk.mu.Lock()
		busy := e.blk.running[k]
		e.blk.running[k] = true
		e.blk.mu.Unlock()
		if busy {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(j blockJob, k string) {
			defer func() {
				<-sem
				e.blk.mu.Lock()
				delete(e.blk.running, k)
				e.blk.mu.Unlock()
				wg.Done()
			}()
			var st, detail string
			if e.Sys.DryRun() {
				st, detail = demoProbe(j.domain, j.exit)
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				st, detail = probeTarget(ctx, j.mark, j.domain)
				cancel()
			}
			_, _ = e.St.SetBlockResult(j.domain, j.exit, st, detail, time.Now().Unix())
		}(j, k)
	}
	wg.Wait()
}

// decideOverrides bestimmt die Ausnahmen aller Gruppen neu und gibt sie an die Ausgänge weiter.
func (e *Engine) decideOverrides(groups []*exits.Group, targets map[int64][]string) {
	res, _ := e.St.BlockResults()
	e.blk.mu.Lock()
	prev := e.blk.ov
	e.blk.mu.Unlock()
	ov := map[int64]map[string]int64{}
	var msgs []string
	for _, g := range groups {
		usable := e.Exits.Usable(g.ID)
		for _, d := range targets[g.ID] {
			nat := e.Exits.Natural(g.ID, d)
			if nat == 0 {
				continue
			}
			var ids []int64
			for _, c := range usable {
				ids = append(ids, c.Exit)
			}
			pick, badX, r, check := pickOverride(g.Rotate.Mode == "dest", g.Block.Fails, ids, nat, res[d], prev[g.ID][d])
			if check {
				// noch keine Gegenprobe: die anderen Ausgänge bald prüfen
				e.blk.mu.Lock()
				e.blk.urgent[fmt.Sprintf("%d|%s", g.ID, d)] = true
				e.blk.mu.Unlock()
			}
			if pick == 0 {
				continue
			}
			nat = badX
			if ov[g.ID] == nil {
				ov[g.ID] = map[string]int64{}
			}
			ov[g.ID][d] = pick
			if prev[g.ID][d] != pick {
				msgs = append(msgs, fmt.Sprintf("Block-Prüfung „%s“: %s sperrt „%s“ (%s) – läuft jetzt über „%s“",
					g.Name, d, e.Exits.ExitName(nat), r.Detail, e.Exits.ExitName(pick)))
			}
		}
		for d, x := range prev[g.ID] {
			if _, still := ov[g.ID][d]; !still {
				msgs = append(msgs, fmt.Sprintf("Block-Prüfung „%s“: %s läuft wieder normal (Ausnahme über „%s“ aufgehoben)",
					g.Name, d, e.Exits.ExitName(x)))
			}
		}
	}
	e.blk.mu.Lock()
	e.blk.ov = ov
	e.blk.mu.Unlock()
	env := e.exitEnv()
	e.Exits.SetOverrides(env, ov)
	if !e.Sys.DryRun() {
		go e.resolveOverrides(env, ov)
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		e.Log("info", m)
	}
}

// pickOverride: Braucht ein Ziel eine Ausnahme, und über welchen Ausgang? nat = Ausgang, über den es
// sonst liefe (bei „je Ziel“ zählt jeder Ausgang der Verteilung). Ausgewichen wird nur auf einen
// Ausgang mit bestätigtem „ok“ (Gegenprobe); gibt es den noch nicht, check = andere Ausgänge prüfen.
// Eine bestehende Ausnahme (prev) bleibt, solange ihr Ausgang in Ordnung ist.
func pickOverride(dest bool, fails int, usable []int64, nat int64, rs map[int64]store.BlockResult, prev int64) (pick, bad int64, r store.BlockResult, check bool) {
	cands := []int64{nat}
	if dest {
		cands = usable
	}
	for _, c := range cands {
		if x, ok := rs[c]; ok && blockBad(x, fails) {
			r, bad = x, c
			break
		}
	}
	if bad == 0 {
		return 0, 0, r, false
	}
	for _, c := range usable {
		o, ok := rs[c]
		if c == bad || !ok || o.Status != "ok" || o.Fails > 0 || o.Checked == 0 {
			continue
		}
		if pick == 0 || c == prev {
			pick = c
		}
	}
	return pick, bad, r, pick == 0
}

// BlockFail: Fehlschlag aus dem Verkehr (Proxy konnte das Ziel über den Ausgang nicht erreichen).
// Zählt als Fehlversuch; an der Grenze werden alle Ausgänge für das Ziel sofort geprüft.
func (e *Engine) BlockFail(gid int64, host string, exitID int64, detail string) {
	host = exits.NormDomain(host)
	if host == "" || exitID == 0 {
		return
	}
	o, err := e.St.Object("group", gid)
	if err != nil {
		return
	}
	b := exits.GroupFrom(o).Block
	if !b.On {
		return
	}
	k := fmt.Sprintf("%s|%d", host, exitID)
	now := time.Now()
	e.blk.mu.Lock()
	e.blk.init()
	if now.Sub(e.blk.lastErr[k]) < blockFailRepeat {
		e.blk.mu.Unlock()
		return
	}
	e.blk.lastErr[k] = now
	if len(e.blk.lastErr) > 5000 {
		e.blk.lastErr = map[string]time.Time{k: now}
	}
	e.blk.mu.Unlock()
	r, err := e.St.AddBlockFail(host, exitID, detail, now.Unix())
	if err == nil && r.Fails >= b.Fails {
		e.blk.mu.Lock()
		e.blk.urgent[fmt.Sprintf("%d|%s", gid, host)] = true
		e.blk.mu.Unlock()
		e.blockKick()
	}
}

// BlockCheckNow: alle Ziele einer Gruppe (bzw. eines Ziels) sofort prüfen.
func (e *Engine) BlockCheckNow(gid int64, domain string) {
	now := time.Now()
	for _, g := range e.blockGroups() {
		if g.ID != gid {
			continue
		}
		ts := e.blockTargets(g, now)
		if domain != "" {
			ts = []string{exits.NormDomain(domain)}
		}
		e.blk.mu.Lock()
		e.blk.init()
		for _, d := range ts {
			e.blk.urgent[fmt.Sprintf("%d|%s", gid, d)] = true
		}
		e.blk.mu.Unlock()
	}
	e.blockKick()
}

// BlockRow: Zeile der Ergebnis-Übersicht einer Gruppe.
type BlockRow struct {
	Domain  string                      `json:"domain"`
	Manual  bool                        `json:"manual"`
	Via     int64                       `json:"via"`  // Ausgang, über den das Ziel gerade läuft
	Over    bool                        `json:"over"` // Ausnahme aus der Block-Prüfung
	Results map[int64]store.BlockResult `json:"results"`
}

// BlockReport: Ziele und Ergebnisse einer Gruppe.
func (e *Engine) BlockReport(gid int64) ([]BlockRow, time.Time, error) {
	o, err := e.St.Object("group", gid)
	if err != nil {
		return nil, time.Time{}, err
	}
	g := exits.GroupFrom(o)
	res, err := e.St.BlockResults()
	if err != nil {
		return nil, time.Time{}, err
	}
	manual := map[string]bool{}
	for _, d := range g.Block.Domains {
		manual[d] = true
	}
	ts := e.blockTargets(g, time.Now())
	for d, byExit := range res {
		for _, x := range g.Exits {
			if r, ok := byExit[x]; ok && (r.Status != "ok" || r.Fails > 0) {
				ts = append(ts, d)
				break
			}
		}
	}
	ts = uniq(ts)
	ov := e.Exits.Overrides()[gid]
	out := []BlockRow{}
	for _, d := range ts {
		row := BlockRow{Domain: d, Manual: manual[d], Results: map[int64]store.BlockResult{}}
		for _, x := range g.Exits {
			if r, ok := res[d][x]; ok {
				row.Results[x] = r
			}
		}
		if x, ok := ov[d]; ok {
			row.Via, row.Over = x, true
		} else {
			row.Via = e.Exits.Natural(gid, d)
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Over != out[j].Over {
			return out[i].Over
		}
		if out[i].Manual != out[j].Manual {
			return out[i].Manual
		}
		return strings.Compare(out[i].Domain, out[j].Domain) < 0
	})
	e.blk.mu.Lock()
	last := e.blk.last
	e.blk.mu.Unlock()
	return out, last, nil
}

// resolveOverrides: Adressen der Ziele mit Ausnahme selbst auflösen – Geräte, die den Namen noch
// im Zwischenspeicher haben, fragen das Panel-DNS erst nach Ablauf erneut.
func (e *Engine) resolveOverrides(env *exits.Env, ov map[int64]map[string]int64) {
	for gid, m := range ov {
		for d := range m {
			for _, n := range []string{d, "www." + d} {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", n)
				cancel()
				if err == nil {
					e.Exits.LearnOverride(env, gid, n, ips)
				}
			}
		}
	}
}

// proxyRoute: Ausgänge für eine Proxy-Verbindung (nil = wie bisher über die Gruppen-Markierung).
func (e *Engine) proxyRoute(gid int64, host string) []exits.RouteChoice {
	e.blk.mu.Lock()
	rt, on := e.blk.on[gid]
	e.blk.mu.Unlock()
	if !on {
		return nil
	}
	r := e.Exits.Route(gid, host)
	if !rt && len(r) > 1 {
		r = r[:1] // nur Ausnahmen, kein Ausweichen
	}
	return r
}

// BlockKick: Block-Prüfung sofort neu bewerten (nach dem Speichern einer Gruppe).
func (e *Engine) BlockKick() { e.blockKick() }
