package engine

import (
	"net/netip"
	"strconv"
	"time"

	"vpnpanel/internal/exits"
)

// Passive Erkennung für die Block-Prüfung: Hängt der Verbindungsaufbau zu einem Ziel über einen
// Ausgang (conntrack: SYN_SENT über mindestens zwei Abfragen), zählt das als Fehlversuch für dieses
// Ziel und diesen Ausgang. Den Namen zur Zieladresse liefern die DNS-Antworten der Gruppe.

const (
	passiveEvery = 15 * time.Second
	passiveHang  = 12 * time.Second // so lange muss ein Aufbau hängen
	nameKeep     = 2 * time.Hour    // Zuordnung Adresse → Name aus DNS-Antworten
	nameMax      = 20000            // je Gruppe
)

type nameRec struct {
	name string
	exp  time.Time
}

type synRec struct {
	first    time.Time
	reported bool
}

// noteNames: Adressen einer DNS-Antwort merken (nur Gruppen mit Block-Prüfung).
func (e *Engine) noteNames(gid int64, name string, addrs []netip.Addr) {
	name = exits.NormDomain(name)
	if name == "" || len(addrs) == 0 {
		return
	}
	now := time.Now()
	e.blk.mu.Lock()
	defer e.blk.mu.Unlock()
	if _, on := e.blk.on[gid]; !on {
		return
	}
	if e.blk.names == nil {
		e.blk.names = map[int64]map[netip.Addr]nameRec{}
	}
	m := e.blk.names[gid]
	if m == nil || len(m) > nameMax {
		m = map[netip.Addr]nameRec{}
		e.blk.names[gid] = m
	}
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			m[a] = nameRec{name, now.Add(nameKeep)}
		}
	}
}

func (e *Engine) nameOf(gid int64, a netip.Addr, now time.Time) string {
	e.blk.mu.Lock()
	defer e.blk.mu.Unlock()
	if r, ok := e.blk.names[gid][a]; ok && now.Before(r.exp) {
		return r.name
	}
	return ""
}

// passiveTick: hängende Verbindungen je Ausgang der Gruppen mit Block-Prüfung auswerten.
func (e *Engine) passiveTick() {
	if e.Sys.DryRun() {
		return
	}
	now := time.Now()
	e.blk.mu.Lock()
	var gids []int64
	for g := range e.blk.on {
		gids = append(gids, g)
	}
	if e.blk.syn == nil {
		e.blk.syn = map[string]*synRec{}
	}
	e.blk.mu.Unlock()
	if len(gids) == 0 {
		return
	}
	env := e.exitEnv()
	exitGroups := map[int64][]int64{} // Ausgang → Gruppen
	for _, g := range gids {
		for _, c := range e.Exits.Usable(g) {
			exitGroups[c.Exit] = append(exitGroups[c.Exit], g)
		}
	}
	seen := map[string]bool{}
	type hit struct {
		gid, exit int64
		name      string
	}
	var hits []hit
	for x, groups := range exitGroups {
		conns, err := e.Exits.PendingConns(env, x)
		if err != nil {
			continue
		}
		for _, c := range conns {
			k := strconv.FormatInt(x, 10) + "|" + c.Key()
			seen[k] = true
			e.blk.mu.Lock()
			r := e.blk.syn[k]
			if r == nil {
				r = &synRec{first: now}
				e.blk.syn[k] = r
			}
			due := !r.reported && now.Sub(r.first) >= passiveHang
			if due {
				r.reported = true
			}
			e.blk.mu.Unlock()
			if !due {
				continue
			}
			for _, g := range groups {
				if n := e.nameOf(g, c.Dst, now); n != "" {
					hits = append(hits, hit{g, x, n})
					break
				}
			}
		}
	}
	e.blk.mu.Lock()
	for k := range e.blk.syn {
		if !seen[k] {
			delete(e.blk.syn, k)
		}
	}
	e.blk.mu.Unlock()
	for _, h := range hits {
		e.BlockFail(h.gid, h.name, h.exit, "Passiv: Verbindungsaufbau ohne Antwort (SYN)")
	}
}
