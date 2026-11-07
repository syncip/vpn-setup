package engine

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"vpnpanel/internal/proto"
)

// Live-Anzeige: Die Engine fragt die Zähler aller Protokolle regelmäßig ab (ohne sie
// zurückzusetzen) und berechnet daraus die aktuelle Geschwindigkeit pro Zugang.
// Schaut jemand zu, alle 2 Sekunden, sonst alle 10 Sekunden. Der Verlauf der letzten
// 30 Minuten bleibt im Speicher.

const (
	liveFast    = 2 * time.Second
	liveSlow    = 10 * time.Second
	liveHistory = 30 * time.Minute
	liveIdle    = 60 * time.Second // so lange gilt ein Zugang nach letzter Aktivität als verbunden
)

type LivePoint struct {
	TS   int64   `json:"ts"`   // Unix-Zeit in Millisekunden
	Up   float64 `json:"up"`   // Bytes pro Sekunde
	Down float64 `json:"down"` // Bytes pro Sekunde
}

type LivePeer struct {
	ID       int64   `json:"id"`
	Up       float64 `json:"up"`
	Down     float64 `json:"down"`
	Online   bool    `json:"online"`
	Endpoint string  `json:"endpoint,omitempty"`
	Since    int64   `json:"since"` // verbunden seit (Unix), 0 = unbekannt
}

type LiveData struct {
	TS       int64                 `json:"ts"`
	Interval float64               `json:"interval"`
	Peers    map[int64]*LivePeer   `json:"-"`
	History  []LivePoint           `json:"history"`
	PeerHist map[int64][]LivePoint `json:"-"`
	Errors   map[string]string     `json:"errors,omitempty"`
}

type liveState struct {
	mu       sync.Mutex
	watched  time.Time
	prev     map[int64]proto.LiveSample
	prevAt   time.Time
	active   map[int64]time.Time // letzte Aktivität
	since    map[int64]int64
	cur      map[int64]*LivePeer
	hist     []LivePoint
	peerHist map[int64][]LivePoint
	errs     map[string]string
	snap     *Snapshot
	snapAt   time.Time
	demo     map[int64]float64
	demoAt   time.Time
}

// WatchLive: Die Oberfläche schaut zu → schneller messen.
func (e *Engine) WatchLive() {
	e.live.mu.Lock()
	first := time.Since(e.live.watched) > liveSlow*2
	e.live.watched = time.Now()
	e.live.mu.Unlock()
	if first {
		select {
		case e.liveKick <- struct{}{}:
		default:
		}
	}
}

// RunLive: Messschleife (läuft neben Run).
func (e *Engine) RunLive(stop <-chan struct{}) {
	t := time.NewTimer(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-e.liveKick:
		case <-t.C:
		}
		e.sampleLive()
		e.live.mu.Lock()
		d := liveSlow
		if time.Since(e.live.watched) < 30*time.Second {
			d = liveFast
		}
		e.live.mu.Unlock()
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(d)
	}
}

func (e *Engine) sampleLive() {
	ls := &e.live
	ls.mu.Lock()
	snap := ls.snap
	if snap == nil || time.Since(ls.snapAt) > 15*time.Second {
		ls.mu.Unlock()
		s, err := e.Snapshot()
		if err != nil {
			return
		}
		ls.mu.Lock()
		ls.snap, ls.snapAt, snap = s, time.Now(), s
	}
	ls.mu.Unlock()

	env := e.Env()
	samples := map[int64]proto.LiveSample{}
	errs := map[string]string{}
	if e.Sys.DryRun() {
		samples = e.demoSamples(snap)
	} else {
		for _, d := range proto.All() {
			lr, ok := d.(proto.LiveReader)
			bundles := snap.ByProto[d.Info().ID]
			if !ok || len(bundles) == 0 {
				continue
			}
			m, err := lr.Live(env, bundles)
			if err != nil {
				errs[d.Info().ID] = err.Error()
			}
			for id, s := range m {
				samples[id] = s
			}
		}
	}
	now := time.Now()

	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.errs = errs
	if ls.active == nil {
		ls.active, ls.since, ls.peerHist = map[int64]time.Time{}, map[int64]int64{}, map[int64][]LivePoint{}
	}
	dt := now.Sub(ls.prevAt).Seconds()
	first := ls.prev == nil || dt > 120
	cur := map[int64]*LivePeer{}
	var tu, td float64
	for id, s := range samples {
		p := &LivePeer{ID: id, Endpoint: s.Endpoint}
		if old, ok := ls.prev[id]; ok && !first && dt > 0 {
			du, dd := s.Up-old.Up, s.Down-old.Down
			if du < 0 { // Zähler wurde zurückgesetzt (Einsammeln)
				du = s.Up
			}
			if dd < 0 {
				dd = s.Down
			}
			p.Up, p.Down = float64(du)/dt, float64(dd)/dt
		}
		if p.Up+p.Down > 64 { // mehr als Keepalive-Rauschen
			ls.active[id] = now
		}
		p.Online = s.Online || now.Sub(ls.active[id]) < liveIdle
		if p.Online {
			if ls.since[id] == 0 {
				ls.since[id] = now.Unix()
			}
			p.Since = ls.since[id]
		} else {
			delete(ls.since, id)
		}
		tu += p.Up
		td += p.Down
		cur[id] = p
	}
	for id := range ls.since {
		if cur[id] == nil {
			delete(ls.since, id)
		}
	}
	ls.prev, ls.prevAt, ls.cur = samples, now, cur
	if first {
		return
	}
	ms := now.UnixMilli()
	cut := now.Add(-liveHistory).UnixMilli()
	ls.hist = appendPoint(ls.hist, LivePoint{ms, tu, td}, cut)
	for id, p := range cur {
		if p.Online || len(ls.peerHist[id]) > 0 {
			ls.peerHist[id] = appendPoint(ls.peerHist[id], LivePoint{ms, p.Up, p.Down}, cut)
		}
	}
	for id, h := range ls.peerHist {
		if cur[id] == nil {
			h = appendPoint(h, LivePoint{ms, 0, 0}, cut)
		}
		if len(h) == 0 || h[len(h)-1].TS < cut {
			delete(ls.peerHist, id)
		} else {
			ls.peerHist[id] = h
		}
	}
}

func appendPoint(h []LivePoint, p LivePoint, cut int64) []LivePoint {
	h = append(h, p)
	i := 0
	for i < len(h) && h[i].TS < cut {
		i++
	}
	if i > 0 {
		h = append(h[:0:0], h[i:]...)
	}
	return h
}

// Live liefert den aktuellen Stand (Kopie).
func (e *Engine) Live() *LiveData {
	e.WatchLive()
	ls := &e.live
	ls.mu.Lock()
	defer ls.mu.Unlock()
	d := &LiveData{TS: time.Now().Unix(), Interval: liveFast.Seconds(), Peers: map[int64]*LivePeer{},
		History: append([]LivePoint(nil), ls.hist...), PeerHist: map[int64][]LivePoint{}, Errors: map[string]string{}}
	for id, p := range ls.cur {
		c := *p
		d.Peers[id] = &c
	}
	for id, h := range ls.peerHist {
		d.PeerHist[id] = append([]LivePoint(nil), h...)
	}
	for k, v := range ls.errs {
		d.Errors[k] = v
	}
	return d
}

// demoSamples: erfundene, gleichmäßig wachsende Zähler für den Testmodus.
func (e *Engine) demoSamples(snap *Snapshot) map[int64]proto.LiveSample {
	ls := &e.live
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.demo == nil {
		ls.demo = map[int64]float64{}
	}
	out := map[int64]proto.LiveSample{}
	ids := make([]int64, 0, len(snap.Peers))
	for id, pb := range snap.Peers {
		if pb.Active && pb.Peer.Enabled {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	t := float64(time.Now().UnixMilli()) / 1000
	dt := time.Since(ls.demoAt).Seconds()
	if ls.demoAt.IsZero() || dt > 60 {
		dt = 2
	}
	ls.demoAt = time.Now()
	for i, id := range ids {
		if i%3 == 2 { // jeder dritte ist offline
			continue
		}
		base := float64(1+i%4) * 400_000 * (1.2 + math.Sin(t/(20+float64(i)*7)))
		ls.demo[id] += base * (0.6 + rand.Float64()*0.8) * dt
		prev := out[id]
		prev.Down = int64(ls.demo[id])
		prev.Up = int64(ls.demo[id] / 8)
		prev.Online = true
		out[id] = prev
	}
	return out
}

// PeerLiveSince: verbunden seit (Unix-Zeit) laut Live-Messung, 0 = nicht verbunden oder unbekannt.
// Zählt ab dem ersten Messpunkt, an dem der Zugang aktiv war (spätestens seit dem Panel-Start).
func (e *Engine) PeerLiveSince(id int64) int64 {
	e.live.mu.Lock()
	defer e.live.mu.Unlock()
	if p := e.live.cur[id]; p != nil && p.Online {
		return p.Since
	}
	return 0
}

// PeerLiveOnline: laut Live-Messung gerade verbunden (ohne die Messung zu beschleunigen).
func (e *Engine) PeerLiveOnline(id int64) bool {
	e.live.mu.Lock()
	defer e.live.mu.Unlock()
	p := e.live.cur[id]
	return p != nil && p.Online
}
