package exits

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	checkEvery   = 30 * time.Second
	window       = 4                // Messungen für den Durchschnitt (~2 Minuten)
	backAfter    = 10 * time.Minute // so lange muss ein bevorzugter Ausgang stabil sein
	keepSamples  = 40
	speedBytes   = 5_000_000
	dialTimeout  = 8 * time.Second
	speedTimeout = 60 * time.Second
)

// Prüfziele (für Labortests änderbar, siehe SetProbeTargets)
var (
	pingTarget = "1.1.1.1"
	traceURL   = "https://1.1.1.1/cdn-cgi/trace"
	speedURL   = "https://speed.cloudflare.com/__down?bytes=5000000"
)

// errNoTunnel: Schnittstelle des Ausgangs fehlt (OpenVPN nicht verbunden).
var errNoTunnel = errors.New("Tunnel nicht verbunden")

// SetProbeTargets ersetzt die Prüfziele – nur für Tests in einer Laborumgebung.
func SetProbeTargets(ping, trace, speed string) { pingTarget, traceURL, speedURL = ping, trace, speed }

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:8]) }

func failState(g *Group) string {
	if g.OnFail == "direct" {
		return "direct"
	}
	return "blocked"
}

// Dialer: Verbindungen über eine Gruppe (Markierung) bzw. direkt (mark 0).
func Dialer(mark uint32) *net.Dialer {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if mark != 0 {
		d.Control = markControl(mark)
	}
	return d
}

// Resolver: Namensauflösung über die angegebenen DNS-Server; die Anfragen laufen ebenfalls
// über die Gruppe (sonst sähen Dienste am DNS-Server den echten Standort).
func Resolver(mark uint32, servers []string) *net.Resolver {
	d := Dialer(mark)
	var mu sync.Mutex
	n := 0
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		mu.Lock()
		srv := servers[n%len(servers)]
		n++
		mu.Unlock()
		return d.DialContext(ctx, network, net.JoinHostPort(srv, "53"))
	}}
}

func httpClient(mark uint32, timeout time.Duration) *http.Client {
	d := Dialer(mark)
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: dialTimeout, DisableKeepAlives: true,
	}}
}

var (
	lossRe = regexp.MustCompile(`([0-9.]+)% packet loss`)
	rttRe  = regexp.MustCompile(`= [0-9.]+/([0-9.]+)/`)
)

// probe misst einen Ausgang: Ping (Verlust, Antwortzeit), HTTPS-Abruf (öffentliche IP, Land)
// und auf Wunsch einen kurzen Geschwindigkeitstest.
func (m *Manager) probe(env *Env, e *Exit, speed bool) (Sample, string, string, float64, error) {
	s := Sample{TS: time.Now().Unix(), Loss: 100}
	n := IfName(e.ID)
	if env.Sys.DryRun() { // Testmodus: gleichmäßige Beispielwerte
		r := rand.New(rand.NewSource(e.ID*7919 + s.TS/30))
		s.Loss, s.RTT, s.OK = 0, 20+float64(e.ID%5)*15+r.Float64()*8, true
		mb := 0.0
		if speed {
			mb = 80 + r.Float64()*40
		}
		return s, fmt.Sprintf("203.0.113.%d", 10+e.ID%200), []string{"US", "DE", "GB", "NL", "JP"}[e.ID%5], mb, nil
	}
	if _, err := env.Sys.Run("ip", "link", "show", "dev", n); err != nil {
		return s, "", "", 0, errNoTunnel
	}
	mark := strconv.FormatUint(uint64(probeMark(e.Slot)), 10)
	out, _ := env.Sys.Run("ping", "-n", "-q", "-c", "5", "-i", "0.3", "-W", "2", "-m", mark, "-I", n, pingTarget)
	if r := lossRe.FindStringSubmatch(out); r != nil {
		s.Loss, _ = strconv.ParseFloat(r[1], 64)
	}
	if r := rttRe.FindStringSubmatch(out); r != nil {
		s.RTT, _ = strconv.ParseFloat(r[1], 64)
	}
	ip, loc := "", ""
	var perr error
	resp, err := httpClient(probeMark(e.Slot), 15*time.Second).Get(traceURL)
	if err == nil {
		sc := bufio.NewScanner(io.LimitReader(resp.Body, 8192))
		for sc.Scan() {
			k, v, _ := strings.Cut(sc.Text(), "=")
			switch k {
			case "ip":
				ip = v
			case "loc":
				loc = v
			}
		}
		resp.Body.Close()
		s.OK = resp.StatusCode == 200 && net.ParseIP(ip) != nil
	} else {
		perr = fmt.Errorf("kein Internet über den Tunnel")
	}
	mb := 0.0
	if speed && s.OK {
		t0 := time.Now()
		if resp, err := httpClient(probeMark(e.Slot), speedTimeout).Get(speedURL); err == nil {
			nb, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, speedBytes+1024))
			resp.Body.Close()
			if d := time.Since(t0).Seconds(); nb > speedBytes/2 && d > 0 {
				mb = float64(nb) * 8 / d / 1e6
			}
		}
	}
	return s, ip, loc, mb, perr
}

// Run: Prüfschleife. load liefert jeweils den aktuellen Stand aus der Datenbank.
func (m *Manager) Run(stop <-chan struct{}, envFn func() *Env, load func() ([]*Exit, []*Group), speedEvery func() time.Duration) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		exits, groups := load()
		if len(exits) > 0 {
			m.Check(envFn(), exits, groups, speedEvery())
		}
		t.Reset(checkEvery)
	}
}

// Check prüft alle Ausgänge (parallel) und bewertet danach die Gruppen. Ausgänge in Bereitschaft
// werden nur geprüft, wenn eine Gruppe sie nutzt oder ihre Prüfung fällig ist (dafür kurz verbunden).
func (m *Manager) Check(env *Env, exits []*Exit, groups []*Group, speedEvery time.Duration) {
	m.probeMu.Lock()
	defer m.probeMu.Unlock()
	m.mu.Lock()
	force := m.force
	m.force = false
	m.mu.Unlock()
	now := time.Now()
	byID := map[int64]*Exit{}
	for _, e := range exits {
		byID[e.ID] = e
	}
	for _, g := range groups {
		if g.Enabled && g.Slot > 0 {
			m.active(env, g, byID)
		}
	}
	needed := m.neededSet()

	// 1. Welche Ausgänge werden geprüft? Bereitschaft: genutzt, verbunden oder Prüfung fällig.
	var todo []*Exit
	for _, e := range exits {
		if !e.Enabled || e.Slot < 1 {
			continue
		}
		m.mu.Lock()
		st := m.status[e.ID]
		if st == nil {
			st = &ExitStatus{ID: e.ID}
			m.status[e.ID] = st
		}
		st.Standby = e.Standby()
		st.Connected = !e.Standby() || m.conn[e.ID]
		due := force || st.Checked == 0 || now.Sub(time.Unix(st.Checked, 0)) >= time.Duration(e.CheckMin)*time.Minute
		m.mu.Unlock()
		if e.Standby() && !needed[e.ID] && !m.isConn(e.ID) {
			if !due {
				m.mu.Lock()
				st.NextCheck = st.Checked + int64(e.CheckMin)*60
				m.mu.Unlock()
				continue
			}
			if err := m.connect(env, e); err != nil {
				m.record(e, Sample{TS: now.Unix(), Loss: 100}, "", "", 0, false, fmt.Errorf("%w: %v", errNoTunnel, err))
				m.disconnect(env, e)
				continue
			}
		} else if e.Standby() && !m.isConn(e.ID) {
			// genutzt, aber (noch) nicht verbunden – z. B. nach dem Start
			if err := m.connect(env, e); err != nil {
				env.Log("warn", fmt.Sprintf("Ausgang „%s“: %v", e.Name, err))
			}
		}
		todo = append(todo, e)
	}
	if len(todo) > 0 {
		m.ensureRoutes(env, exits, groups)
	}

	// 2. Messen (parallel)
	probe := func(e *Exit) {
		m.mu.Lock()
		st := m.status[e.ID]
		speed := st != nil && speedEvery > 0 && now.Sub(time.Unix(st.MbitAt, 0)) >= speedEvery
		m.mu.Unlock()
		s, ip, loc, mb, err := m.probe(env, e, speed)
		m.record(e, s, ip, loc, mb, speed, err)
	}
	var wg sync.WaitGroup
	for _, e := range todo {
		wg.Add(1)
		go func(e *Exit) {
			defer wg.Done()
			probe(e)
		}(e)
	}
	wg.Wait()

	// 3. Aktiver Ausgang gestört? Dann Ausgänge in Bereitschaft verbinden und prüfen.
	m.failoverCandidates(env, groups, byID, probe)
	m.ensureRoutes(env, exits, groups)

	// 4. Gruppen bewerten (ggf. umschalten)
	for _, g := range groups {
		if g.Enabled && g.Slot > 0 {
			m.evaluate(env, g, byID)
		}
	}

	// 5. Nicht mehr benötigte Ausgänge in Bereitschaft wieder trennen
	needed = m.neededSet()
	for _, e := range exits {
		if e.Standby() && e.Enabled && !needed[e.ID] && m.isConn(e.ID) {
			m.disconnect(env, e)
		}
		m.mu.Lock()
		if st := m.status[e.ID]; st != nil && e.Standby() {
			st.Connected = m.conn[e.ID]
			st.NextCheck = st.Checked + int64(e.CheckMin)*60
			if needed[e.ID] {
				st.NextCheck = 0 // genutzt → laufend geprüft
			}
		}
		m.mu.Unlock()
	}
}

// record trägt eine Messung ein.
func (m *Manager) record(e *Exit, s Sample, ip, loc string, mb float64, speed bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.status[e.ID]
	if st == nil {
		return
	}
	// Up = Schnittstelle da; ob Verkehr durchgeht, bewertet isHealthy anhand der Messungen
	st.Checked, st.Up = s.TS, err == nil || !errors.Is(err, errNoTunnel)
	st.Samples = append(st.Samples, s)
	if len(st.Samples) > keepSamples {
		st.Samples = st.Samples[len(st.Samples)-keepSamples:]
	}
	st.Loss, st.RTT = avg(st.Samples)
	if ip != "" {
		st.IP, st.Loc = ip, loc
	}
	if mb > 0 {
		st.Mbit, st.MbitAt = mb, s.TS
	} else if speed {
		st.MbitAt = s.TS // nicht sofort wieder versuchen
	}
	st.Error = ""
	if err != nil {
		st.Error = err.Error()
	}
}

func avg(ss []Sample) (loss, rtt float64) {
	n := min(window, len(ss))
	if n == 0 {
		return 0, 0
	}
	cnt := 0
	for _, s := range ss[len(ss)-n:] {
		loss += s.Loss
		if s.RTT > 0 {
			rtt += s.RTT
			cnt++
		}
	}
	loss /= float64(n)
	if cnt > 0 {
		rtt /= float64(cnt)
	}
	return
}

// isHealthy: erfüllt ein Ausgang die Grenzen der Gruppe? (m.mu gesperrt)
func (m *Manager) isHealthy(g *Group, e *Exit) (bool, string) {
	if e == nil || !e.Enabled {
		return false, "deaktiviert"
	}
	st := m.status[e.ID]
	if st == nil || len(st.Samples) == 0 {
		return false, "noch nicht geprüft"
	}
	n := len(st.Samples)
	last := st.Samples[n-1]
	// Ein einzelner Aussetzer (eine Prüfung ohne Antwort, eine verlorene Ping-Runde) schaltet nicht
	// um: gestört erst, wenn auch die vorige Prüfung schlecht war. Antwortet HTTPS, aber kein Ping,
	// blockiert der Anbieter ICMP – dann zählt der Verlust nicht.
	lossOf := func(s Sample) float64 {
		if s.OK && s.Loss >= 100 {
			return 0
		}
		return s.Loss
	}
	bad := func(s Sample) bool { return !s.OK || lossOf(s) > g.MaxLoss }
	again := n == 1 || bad(st.Samples[n-2])
	switch {
	case !st.Up:
		return false, "Tunnel nicht verbunden"
	case !last.OK && again:
		return false, "kein Internet über den Tunnel"
	case lossOf(last) > g.MaxLoss && again:
		return false, fmt.Sprintf("Paketverlust %.0f %%", lossOf(last))
	case g.MaxRTT > 0 && st.RTT > g.MaxRTT && last.RTT > g.MaxRTT:
		return false, fmt.Sprintf("Antwortzeit %.0f ms", st.RTT)
	case g.MinMbit > 0 && st.Mbit > 0 && st.Mbit < g.MinMbit:
		return false, fmt.Sprintf("nur %.1f Mbit/s", st.Mbit)
	}
	return true, ""
}

// order: Reihenfolge der Ausgänge – ein von Hand gewählter Ausgang steht vorn. (m.mu gesperrt)
func (m *Manager) order(g *Group) []int64 {
	pin := int64(0)
	if gs := m.groups[g.ID]; gs != nil {
		pin = gs.Pinned
	}
	found := false
	for _, id := range g.Exits {
		found = found || id == pin
	}
	if pin == 0 || !found {
		return g.Exits
	}
	out := []int64{pin}
	for _, id := range g.Exits {
		if id != pin {
			out = append(out, id)
		}
	}
	return out
}

func (m *Manager) evaluate(env *Env, g *Group, exits map[int64]*Exit) {
	cur := m.active(env, g, exits)
	m.mu.Lock()
	now := time.Now()
	order := m.order(g)
	ok := map[int64]bool{}
	why := map[int64]string{}
	for _, id := range order {
		k := fmt.Sprintf("%d/%d", g.ID, id)
		h, r := m.isHealthy(g, exits[id])
		ok[id], why[id] = h, r
		if h {
			if _, seen := m.healthy[k]; !seen {
				m.healthy[k] = now
			}
		} else {
			delete(m.healthy, k)
		}
	}
	next, reason := cur, ""
	inGroup := false
	for _, id := range order {
		inGroup = inGroup || id == cur
	}
	if cur != 0 && inGroup && ok[cur] {
		// bevorzugter Ausgang wieder stabil? → zurück
		for _, id := range order {
			if id == cur {
				break
			}
			if ok[id] && now.Sub(m.healthy[fmt.Sprintf("%d/%d", g.ID, id)]) >= backAfter {
				next, reason = id, "bevorzugter Ausgang wieder stabil"
				break
			}
		}
	} else {
		next = 0
		for _, id := range order {
			if ok[id] {
				next = id
				break
			}
		}
		if cur != 0 {
			name := "Ausgang"
			if e := exits[cur]; e != nil {
				name = "„" + e.Name + "“"
			}
			reason = name + " gestört"
			if why[cur] != "" {
				reason += ": " + why[cur]
			}
		} else if next != 0 {
			reason = "Ausgang wieder verfügbar"
		}
	}
	gs := m.groups[g.ID]
	changed := next != cur
	if changed {
		gs.Active, gs.Since, gs.Reason = next, now.Unix(), reason
	}
	switch {
	case next == 0:
		gs.State = failState(g)
		if gs.Reason == "" {
			gs.Reason = "kein Ausgang erreichbar"
		}
	case len(order) > 0 && next != order[0]:
		gs.State = "failover"
	default:
		gs.State = "ok"
	}
	hooks := append([]func(int64){}, m.hooks...)
	m.mu.Unlock()
	if !changed {
		return
	}
	// Ausgang in Bereitschaft (z. B. Rückkehr zum bevorzugten): erst verbinden
	if x := exits[next]; x.Standby() && !m.isConn(next) {
		if err := m.connect(env, x); err != nil {
			m.disconnect(env, x)
			m.mu.Lock()
			gs.Active, gs.Reason = cur, fmt.Sprintf("„%s“ (Bereitschaft) ließ sich nicht verbinden: %v", x.Name, err)
			m.mu.Unlock()
			env.Log("warn", fmt.Sprintf("Gruppe „%s“: %s", g.Name, gs.Reason))
			return
		}
	}
	m.routeGroup(env, g, next)
	env.Set(fmt.Sprintf("exits:active:%d", g.ID), strconv.FormatInt(next, 10))
	to := "keiner (" + map[string]string{"block": "gesperrt", "direct": "direkt über den Server"}[g.OnFail] + ")"
	if e := exits[next]; e != nil {
		to = "„" + e.Name + "“"
	}
	env.Log("warn", fmt.Sprintf("Gruppe „%s“: Ausgang jetzt %s – %s", g.Name, to, reason))
	for _, f := range hooks {
		f(g.ID)
	}
}

// Switch: von Hand auf einen Ausgang der Gruppe umschalten (bis die Prüfung anders entscheidet).
func (m *Manager) Switch(env *Env, g *Group, exitID int64, exits map[int64]*Exit) error {
	found := false
	for _, id := range g.Exits {
		found = found || id == exitID
	}
	if !found || exits[exitID] == nil || !exits[exitID].Enabled {
		return fmt.Errorf("Ausgang gehört nicht zur Gruppe oder ist deaktiviert")
	}
	m.active(env, g, exits)
	if x := exits[exitID]; x.Standby() && !m.isConn(exitID) {
		if err := m.connect(env, x); err != nil {
			m.disconnect(env, x)
			return fmt.Errorf("„%s“ ließ sich nicht verbinden: %v", x.Name, err)
		}
	}
	m.mu.Lock()
	gs := m.groups[g.ID]
	gs.Active, gs.Since, gs.Reason = exitID, time.Now().Unix(), "von Hand umgeschaltet"
	// Der gewählte Ausgang wird bevorzugt (fällt er aus, übernimmt der nächste; ist er wieder
	// stabil, geht es zu ihm zurück). Wahl des ersten Ausgangs = wieder normale Reihenfolge.
	gs.Pinned = exitID
	if exitID == g.Exits[0] {
		gs.Pinned = 0
	}
	gs.State = "ok"
	hooks := append([]func(int64){}, m.hooks...)
	m.mu.Unlock()
	m.routeGroup(env, g, exitID)
	env.Set(fmt.Sprintf("exits:active:%d", g.ID), strconv.FormatInt(exitID, 10))
	pin := ""
	if gs.Pinned != 0 {
		pin = strconv.FormatInt(gs.Pinned, 10)
	}
	env.Set(fmt.Sprintf("exits:pin:%d", g.ID), pin)
	env.Log("info", fmt.Sprintf("Gruppe „%s“: von Hand auf „%s“ umgeschaltet", g.Name, exits[exitID].Name))
	for _, f := range hooks {
		f(g.ID)
	}
	return nil
}
