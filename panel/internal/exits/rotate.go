package exits

import (
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Wechsel (Rotation) innerhalb einer Gruppe, damit der Verkehr nicht dauerhaft über dieselbe Adresse
// läuft:
//   - group: die ganze Gruppe wechselt nach einer zufälligen Zeit und/oder Datenmenge auf einen
//     zufällig gewählten anderen gesunden Ausgang.
//   - dest:  je Ziel – neue Verbindungen werden nach Zieladresse auf alle gesunden Ausgänge verteilt;
//     beim Wechsel wird die Verteilung neu gemischt.
//
// Immer weich: laufende Verbindungen bleiben auf ihrem Ausgang (siehe pins.go). Ein Ausgang, den die
// Gruppe verlässt, bleibt verbunden, bis seine Verbindungen enden (höchstens DrainMin Minuten).
// Ausgänge in Bereitschaft werden rechtzeitig vorher verbunden und geprüft (WarmSec bzw. ab 85 %
// der Datenmenge), damit beim Wechsel nichts hakt.

// Rotation: Einstellungen einer Gruppe (Data["rotate"]).
type Rotation struct {
	Mode     string  `json:"mode"`      // "" = aus | group | dest
	MinMin   int     `json:"min_min"`   // nach Zeit: zufällig zwischen MinMin und MaxMin Minuten (0 = aus)
	MaxMin   int     `json:"max_min"`   //
	MinGB    float64 `json:"min_gb"`    // nach Datenmenge: zufällig zwischen MinGB und MaxGB (0 = aus)
	MaxGB    float64 `json:"max_gb"`    //
	DrainMin int     `json:"drain_min"` // alte Verbindungen höchstens so lange halten
	WarmSec  int     `json:"warm_sec"`  // Bereitschaft: so lange vorher verbinden
	FlushDNS bool    `json:"flush_dns"` // DNS-Zwischenspeicher der Gruppe beim Wechsel leeren
}

const (
	maxRotateMin = 7 * 24 * 60
	maxRotateGB  = 100000
	defDrainMin  = 30
	defWarmSec   = 90
	minWarm      = 45 * time.Second // mindestens eine Prüfrunde Vorlauf
	warmShare    = 0.85             // ab diesem Anteil der Datenmenge vorbereiten
)

// On: Wechsel eingeschaltet?
func (r Rotation) On() bool { return r.Mode == "group" || r.Mode == "dest" }

// RotationFrom liest die Einstellungen (fehlende Werte → Vorgaben).
func RotationFrom(v any) Rotation {
	r := Rotation{DrainMin: defDrainMin, WarmSec: defWarmSec, FlushDNS: true}
	mm, ok := v.(map[string]any)
	if !ok {
		return r
	}
	if s, _ := mm["mode"].(string); s == "group" || s == "dest" {
		r.Mode = s
	}
	f := func(k string, def float64) float64 {
		if x, ok := mm[k].(float64); ok {
			return x
		}
		return def
	}
	r.MinMin, r.MaxMin = int(f("min_min", 0)), int(f("max_min", 0))
	r.MinGB, r.MaxGB = f("min_gb", 0), f("max_gb", 0)
	r.DrainMin, r.WarmSec = int(f("drain_min", defDrainMin)), int(f("warm_sec", defWarmSec))
	if b, ok := mm["flush_dns"].(bool); ok {
		r.FlushDNS = b
	}
	if r.MaxMin < r.MinMin {
		r.MaxMin = r.MinMin
	}
	if r.MinMin <= 0 {
		r.MinMin, r.MaxMin = 0, 0
	}
	if r.MaxGB < r.MinGB {
		r.MaxGB = r.MinGB
	}
	if r.MinGB <= 0 {
		r.MinGB, r.MaxGB = 0, 0
	}
	return r
}

// Check: Fehlertext für ungültige Einstellungen ("" = in Ordnung).
func (r Rotation) Check() string {
	switch r.Mode {
	case "", "group", "dest":
	default:
		return "Wechsel: Art ungültig"
	}
	if r.MinMin < 0 || r.MaxMin < 0 || r.MaxMin > maxRotateMin || (r.MinMin > 0 && r.MinMin < 1) {
		return "Wechsel nach Zeit: 1 Minute bis 7 Tage"
	}
	if r.MinMin > 0 && r.MaxMin < r.MinMin {
		return "Wechsel nach Zeit: „bis“ muss mindestens „von“ sein"
	}
	if r.MinGB < 0 || r.MaxGB < 0 || r.MaxGB > maxRotateGB || (r.MinGB > 0 && r.MinGB < 0.01) {
		return "Wechsel nach Datenmenge: 0,01 bis 100000 GB"
	}
	if r.MinGB > 0 && r.MaxGB < r.MinGB {
		return "Wechsel nach Datenmenge: „bis“ muss mindestens „von“ sein"
	}
	if r.DrainMin < 1 || r.DrainMin > 24*60 {
		return "Alte Verbindungen halten: 1 Minute bis 24 Stunden"
	}
	if r.WarmSec < 0 || r.WarmSec > 3600 {
		return "Vorlauf: 0 bis 3600 Sekunden"
	}
	if r.Mode == "group" && r.MinMin == 0 && r.MinGB == 0 {
		return "Wechsel der ganzen Gruppe: Zeit oder Datenmenge angeben"
	}
	return ""
}

// rotState: Laufzeit-Zustand des Wechsels einer Gruppe.
type rotState struct {
	cfg   Rotation
	next  time.Time        // nächster Wechsel nach Zeit (leer = keiner)
	gbAt  float64          // nächster Wechsel nach Datenmenge (Bytes, 0 = keiner)
	bytes float64          // seit dem letzten Wechsel
	ctr   map[int64]uint64 // letzte Zählerstände (rx+tx) der Ausgänge
	cand  int64            // vorbereiteter nächster Ausgang (ganze Gruppe)
	seed  uint32           // Verteilung je Ziel
	pool  []int64          // je Ziel: gesunde Ausgänge der Verteilung
	last  time.Time        // letzter Wechsel
	now   bool             // „Jetzt wechseln“
}

type drainState struct {
	from, until time.Time
}

func (m *Manager) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *Manager) randf() float64 {
	m.rngMu.Lock()
	defer m.rngMu.Unlock()
	return m.rng.Float64()
}

func (m *Manager) randn(n int) int {
	m.rngMu.Lock()
	defer m.rngMu.Unlock()
	return m.rng.Intn(n)
}

// schedule legt den nächsten Wechsel fest (Zeit und Datenmenge zufällig im Bereich).
func (m *Manager) schedule(rs *rotState, now time.Time) {
	r := rs.cfg
	rs.next, rs.gbAt, rs.bytes, rs.cand, rs.now = time.Time{}, 0, 0, 0, false
	if r.MinMin > 0 {
		span := float64(r.MaxMin-r.MinMin) * 60
		rs.next = now.Add(time.Duration((float64(r.MinMin)*60 + m.randf()*span) * float64(time.Second)))
	}
	if r.MinGB > 0 {
		rs.gbAt = (r.MinGB + m.randf()*(r.MaxGB-r.MinGB)) * 1e9
	}
}

// counter: Bytes (rx+tx) einer Ausgangs-Schnittstelle.
func counter(env *Env, id int64) (uint64, bool) {
	var sum uint64
	for _, n := range []string{"rx_bytes", "tx_bytes"} {
		b, err := env.Sys.ReadFile("/sys/class/net/" + IfName(id) + "/statistics/" + n)
		if err != nil {
			return 0, false
		}
		v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, false
		}
		sum += v
	}
	return sum, true
}

// usesLocked: Ausgänge, über die gerade Verkehr der Gruppe läuft (aktiver, Verteilung, auslaufende).
// m.mu gesperrt.
func (m *Manager) usesLocked(gid int64) []int64 {
	seen := map[int64]bool{}
	var out []int64
	add := func(id int64) {
		if id != 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if gs := m.groups[gid]; gs != nil {
		add(gs.Active)
	}
	if rs := m.rot[gid]; rs != nil {
		for _, id := range rs.pool {
			add(id)
		}
	}
	for id, d := range m.drainBy[gid] {
		if d {
			add(id)
		}
	}
	return out
}

// rotate: Wechsel und auslaufende Ausgänge bearbeiten (nach dem Bewerten der Gruppen, in Check).
// probe misst einen Ausgang (verbindet ihn vorher nicht).
func (m *Manager) rotate(env *Env, groups []*Group, byID map[int64]*Exit, probe func(*Exit)) {
	now := m.clock()
	for _, g := range groups {
		if !g.Enabled || g.Slot < 1 {
			continue
		}
		m.mu.Lock()
		rs := m.rot[g.ID]
		if !g.Rotate.On() || g.Blocked != "" {
			if rs != nil && !g.Rotate.On() {
				delete(m.rot, g.ID)
			}
			m.mu.Unlock()
			continue
		}
		if rs == nil || rs.cfg != g.Rotate {
			prevSeed := uint32(0)
			if rs != nil {
				prevSeed = rs.seed
			}
			rs = &rotState{cfg: g.Rotate, ctr: map[int64]uint64{}, seed: prevSeed}
			if rs.seed == 0 {
				rs.seed = m.rng32()
			}
			m.schedule(rs, now)
			m.rot[g.ID] = rs
		}
		uses := m.usesLocked(g.ID)
		m.mu.Unlock()

		// Datenmenge seit dem letzten Wechsel
		var add float64
		cur := map[int64]uint64{}
		for _, id := range uses {
			if v, ok := counter(env, id); ok {
				cur[id] = v
			}
		}
		m.mu.Lock()
		for id, v := range cur {
			if p, ok := rs.ctr[id]; ok {
				if v >= p {
					add += float64(v - p)
				} else {
					add += float64(v) // neu verbunden – Zähler begann bei 0
				}
			}
		}
		rs.ctr = cur
		rs.bytes += add
		due := rs.now || (!rs.next.IsZero() && !now.Before(rs.next)) || (rs.gbAt > 0 && rs.bytes >= rs.gbAt)
		warm := due || (!rs.next.IsZero() && !now.Before(rs.next.Add(-warmLead(g.Rotate)))) || (rs.gbAt > 0 && rs.bytes >= rs.gbAt*warmShare)
		m.mu.Unlock()

		if g.Rotate.Mode == "dest" {
			m.rotateDest(env, g, byID, due, now)
			continue
		}
		m.rotateGroup(env, g, byID, probe, warm, due, now)
	}
	m.drainTick(env, byID, now)
}

func warmLead(r Rotation) time.Duration {
	d := time.Duration(r.WarmSec) * time.Second
	if d < minWarm {
		d = minWarm
	}
	return d
}

func (m *Manager) rng32() uint32 {
	m.rngMu.Lock()
	defer m.rngMu.Unlock()
	return m.rng.Uint32() | 1
}

// rotateGroup: ganze Gruppe – Kandidat vorbereiten, beim Fälligwerden weich umschalten.
func (m *Manager) rotateGroup(env *Env, g *Group, byID map[int64]*Exit, probe func(*Exit), warm, due bool, now time.Time) {
	m.mu.Lock()
	rs, gs := m.rot[g.ID], m.groups[g.ID]
	cur := gs.Active
	if cur == 0 || !warm {
		if cur == 0 && due {
			m.schedule(rs, now) // kein Ausgang – die Ausfall-Logik ist dran
		}
		m.mu.Unlock()
		return
	}
	// Kandidat wählen: zufällig unter den anderen Ausgängen, gesunde zuerst
	pick := func(exclude map[int64]bool) int64 {
		var healthy, other []int64
		for _, id := range g.Exits {
			x := byID[id]
			if id == cur || exclude[id] || x == nil || !x.Enabled || x.Slot < 1 {
				continue
			}
			if ok, _ := m.isHealthy(g, x); ok {
				healthy = append(healthy, id)
			} else {
				other = append(other, id)
			}
		}
		if len(healthy) > 0 {
			return healthy[m.randn(len(healthy))]
		}
		if len(other) > 0 {
			return other[m.randn(len(other))]
		}
		return 0
	}
	tried := map[int64]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		if rs.cand == 0 || byID[rs.cand] == nil || !byID[rs.cand].Enabled || rs.cand == cur {
			rs.cand = pick(tried)
		}
		cand := rs.cand
		if cand == 0 {
			break
		}
		x := byID[cand]
		ok, _ := m.isHealthy(g, x)
		m.mu.Unlock()
		if !ok || (x.Standby() && !m.isConn(cand)) {
			// vorbereiten: verbinden (Bereitschaft) und prüfen
			if x.Standby() && !m.isConn(cand) {
				if err := m.connect(env, x); err != nil {
					env.Log("warn", fmt.Sprintf("Gruppe „%s“: nächster Ausgang „%s“ ließ sich nicht verbinden: %v", g.Name, x.Name, err))
					m.disconnect(env, x)
				}
				m.ensureRoutesLast(env)
			}
			if m.isConn(cand) || !x.Standby() {
				probe(x)
			}
		}
		m.mu.Lock()
		if ok, _ = m.isHealthy(g, x); ok {
			break
		}
		tried[cand] = true
		rs.cand = 0
		if !due {
			break // bis zum Wechsel ist noch Zeit – nächste Runde neu versuchen
		}
	}
	if !due {
		m.mu.Unlock()
		return
	}
	cand := rs.cand
	if cand == 0 {
		reason := "kein anderer gesunder Ausgang"
		m.schedule(rs, now)
		m.mu.Unlock()
		env.Log("info", fmt.Sprintf("Gruppe „%s“: Wechsel verschoben – %s", g.Name, reason))
		return
	}
	why := "Wechsel nach Zeit"
	if rs.now {
		why = "Wechsel von Hand"
	} else if rs.gbAt > 0 && rs.bytes >= rs.gbAt {
		why = fmt.Sprintf("Wechsel nach %.1f GB", rs.bytes/1e9)
	}
	m.schedule(rs, now)
	rs.last = now
	m.mu.Unlock()
	m.softSwitch(env, g, byID, cand, why, true)
}

// rotateDest: je Ziel – Verteilung auf alle gesunden Ausgänge, beim Fälligwerden neu mischen.
func (m *Manager) rotateDest(env *Env, g *Group, byID map[int64]*Exit, due bool, now time.Time) {
	m.mu.Lock()
	rs := m.rot[g.ID]
	var pool []int64
	for _, id := range g.Exits {
		if x := byID[id]; x != nil && x.Enabled && x.Slot > 0 {
			if ok, _ := m.isHealthy(g, x); ok {
				pool = append(pool, id)
			}
		}
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i] < pool[j] })
	changed := fmt.Sprint(pool) != fmt.Sprint(rs.pool)
	// Ausgänge, die aus der Verteilung fallen, laufen aus (ihre Verbindungen bleiben bis zum Ende)
	for _, id := range rs.pool {
		found := false
		for _, p := range pool {
			found = found || p == id
		}
		if !found {
			m.startDrainLocked(g, id, now)
		}
	}
	rs.pool = pool
	why := ""
	if due {
		why = "Verteilung neu gemischt (Zeit)"
		if rs.now {
			why = "Verteilung von Hand neu gemischt"
		} else if rs.gbAt > 0 && rs.bytes >= rs.gbAt {
			why = fmt.Sprintf("Verteilung neu gemischt (nach %.1f GB)", rs.bytes/1e9)
		}
		rs.seed = m.rng32()
		m.schedule(rs, now)
		rs.last = now
		changed = true
	}
	hooks := append([]func(SwitchEvent){}, m.hooks...)
	m.mu.Unlock()
	if !changed {
		return
	}
	m.syncPins(env)
	if why != "" {
		names := make([]string, 0, len(pool))
		for _, id := range pool {
			names = append(names, "„"+byID[id].Name+"“")
		}
		env.Log("info", fmt.Sprintf("Gruppe „%s“: %s – %d Ausgänge (%s)", g.Name, why, len(pool), strings.Join(names, ", ")))
		for _, f := range hooks {
			f(SwitchEvent{Group: g.ID, Rotation: true})
		}
	}
}

// softSwitch: Gruppe auf einen gesunden Ausgang umschalten, laufende Verbindungen bleiben auf dem
// alten Ausgang (er läuft aus). rotation = durch den Wechsel ausgelöst.
func (m *Manager) softSwitch(env *Env, g *Group, byID map[int64]*Exit, next int64, reason string, rotation bool) {
	m.mu.Lock()
	gs := m.groups[g.ID]
	cur := gs.Active
	now := m.clock()
	if cur != 0 && cur != next {
		m.startDrainLocked(g, cur, now)
	}
	gs.Active, gs.Since, gs.Reason, gs.State = next, now.Unix(), reason, "ok"
	hooks := append([]func(SwitchEvent){}, m.hooks...)
	m.mu.Unlock()
	m.syncPins(env)
	m.routeGroup(env, g, next)
	env.Set(fmt.Sprintf("exits:active:%d", g.ID), strconv.FormatInt(next, 10))
	from, to := "–", "–"
	if x := byID[cur]; x != nil {
		from = "„" + x.Name + "“"
	}
	if x := byID[next]; x != nil {
		to = "„" + x.Name + "“"
	}
	env.Log("info", fmt.Sprintf("Gruppe „%s“: %s → %s – %s (laufende Verbindungen bleiben)", g.Name, from, to, reason))
	for _, f := range hooks {
		f(SwitchEvent{Group: g.ID, Rotation: rotation})
	}
}

// startDrainLocked: Ausgang läuft für die Gruppe aus (bleibt verbunden, bis seine Verbindungen
// enden, höchstens DrainMin). m.mu gesperrt.
func (m *Manager) startDrainLocked(g *Group, id int64, now time.Time) {
	mins := g.Rotate.DrainMin
	if mins <= 0 {
		mins = defDrainMin
	}
	until := now.Add(time.Duration(mins) * time.Minute)
	if d, ok := m.drain[id]; !ok || d.until.Before(until) {
		m.drain[id] = drainState{from: now, until: until}
	}
	if m.drainBy[g.ID] == nil {
		m.drainBy[g.ID] = map[int64]bool{}
	}
	m.drainBy[g.ID][id] = true
}

// drainTick beendet das Auslaufen: Zeit um oder keine Verbindungen mehr (conntrack, falls vorhanden).
func (m *Manager) drainTick(env *Env, byID map[int64]*Exit, now time.Time) {
	m.mu.Lock()
	type item struct {
		id   int64
		from time.Time
		slot int
	}
	var check []item
	for id, d := range m.drain {
		x := byID[id]
		if x == nil || !x.Enabled || !now.Before(d.until) {
			m.endDrainLocked(id)
			continue
		}
		if now.Sub(d.from) >= time.Minute {
			check = append(check, item{id, d.from, x.Slot})
		}
	}
	m.mu.Unlock()
	for _, it := range check {
		if n, ok := pinnedConns(env, it.slot); ok && n == 0 {
			m.mu.Lock()
			m.endDrainLocked(it.id)
			m.mu.Unlock()
		}
	}
}

func (m *Manager) endDrainLocked(id int64) {
	delete(m.drain, id)
	for gid, set := range m.drainBy {
		delete(set, id)
		if len(set) == 0 {
			delete(m.drainBy, gid)
		}
	}
}

// pinnedConns zählt Verbindungen, die auf einen Ausgang festgelegt sind (conntrack). ok = false,
// wenn sich das nicht feststellen lässt (Programm fehlt, Testmodus).
func pinnedConns(env *Env, slot int) (int, bool) {
	if env.Sys.DryRun() {
		return 0, false
	}
	out, err := env.Sys.Run("conntrack", "-L", "-m", fmt.Sprintf("0x%x/0x%x", probeMark(slot), MarkMask))
	if err != nil {
		return 0, false
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "src=") {
			n++
		}
	}
	return n, true
}

// RotateNow: Wechsel einer Gruppe sofort auslösen (Knopf „Jetzt wechseln“).
func (m *Manager) RotateNow(g *Group) error {
	if !g.Rotate.On() {
		return fmt.Errorf("für diese Gruppe ist kein Wechsel eingestellt")
	}
	m.mu.Lock()
	rs := m.rot[g.ID]
	if rs == nil {
		m.mu.Unlock()
		return fmt.Errorf("Gruppe wird gerade eingerichtet – bitte gleich noch einmal")
	}
	rs.now = true
	m.mu.Unlock()
	m.Wake()
	return nil
}

// rotStatusLocked trägt den Stand des Wechsels in den Gruppen-Status ein. m.mu gesperrt.
func (m *Manager) rotStatusLocked(gid int64, gs *GroupStatus) {
	gs.Uses = m.usesLocked(gid)
	gs.Rotate, gs.NextRotate, gs.RotateBytes, gs.RotateAt, gs.Rotated, gs.Pool = "", 0, 0, 0, 0, nil
	rs := m.rot[gid]
	if rs == nil {
		return
	}
	gs.Rotate = rs.cfg.Mode
	if !rs.next.IsZero() {
		gs.NextRotate = rs.next.Unix()
	}
	gs.RotateBytes, gs.RotateAt = rs.bytes, rs.gbAt
	if !rs.last.IsZero() {
		gs.Rotated = rs.last.Unix()
	}
	gs.Pool = append([]int64(nil), rs.pool...)
	gs.Next = rs.cand
}

// ensureRoutesLast: Routen mit dem letzten bekannten Stand setzen (nach dem Verbinden eines Ausgangs).
func (m *Manager) ensureRoutesLast(env *Env) {
	m.mu.Lock()
	exits, groups := m.lastExits, m.lastGroups
	m.mu.Unlock()
	m.ensureRoutes(env, exits, groups)
}

// newRand: Zufallsquelle des Managers.
func newRand() *rand.Rand { return rand.New(rand.NewSource(time.Now().UnixNano())) }
