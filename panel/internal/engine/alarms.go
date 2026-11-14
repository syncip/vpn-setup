package engine

// Alarme: frei einstellbare Regeln (Schwellen, Limits, Probleme), die per E-Mail melden.
// Gespeichert als Objekte „alarm“; geprüft jede Minute in der Überwachung (RunNotify).
//
//   - Schwelle + Dauer: gemeldet wird erst, wenn der Wert so viele Minuten ohne Unterbrechung
//     schlecht ist (gegen kurze Spitzen).
//   - Wiederholen: solange der Alarm besteht, alle N Stunden erneut (0 = nur einmal).
//   - Entwarnung: Mail, wenn der Alarm vorbei ist.
//   - Empfänger: eigene Adressen oder – leer – die Administratoren mit Benachrichtigungen.
//
// Unabhängig von den Anlässen unter „Benachrichtigungen“ – nur der Mailserver muss eingerichtet sein.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/store"
)

// AlarmType beschreibt eine Art von Alarm für die Oberfläche.
type AlarmType struct {
	Key     string  `json:"key"`
	Group   string  `json:"group"`  // Abschnitt in der Auswahl
	Label   string  `json:"label"`  // „CPU-Auslastung über …“
	Unit    string  `json:"unit"`   // %, GB, Mbit/s, Tage, Anzahl – leer = keine Schwelle
	Target  string  `json:"target"` // exit | group | user – leer = ganzer Server
	Def     float64 `json:"def"`    // Vorgabe der Schwelle
	Minutes int     `json:"minutes"`
	Help    string  `json:"help"`
}

var AlarmTypes = []AlarmType{
	{"cpu", "Server", "CPU-Auslastung", "%", "", 90, 15, "Mittel über alle Kerne, je Minute gemessen."},
	{"mem", "Server", "Arbeitsspeicher belegt", "%", "", 90, 10, "Ohne Cache und Puffer."},
	{"disk", "Server", "Speicherplatz belegt", "%", "", 90, 0, "Datenträger mit den Daten des Panels."},
	{"rate", "Server", "Durchsatz", "Mbit/s", "", 500, 10, "Größere Richtung (rein oder raus) auf der Internet-Schnittstelle, Mittel je Minute."},
	{"errors", "Server", "Fehler beim Anwenden oder Prüfen", "", "", 0, 5, "Alles, was unter „Braucht Aufmerksamkeit“ als Fehler steht (Dienste, Konfiguration)."},
	{"updates", "Server", "Sicherheitsupdates verfügbar", "Anzahl", "", 1, 0, "Debian-Pakete mit Sicherheitsupdates (Zustand → Updates)."},
	{"unbound", "Server", "Unbound antwortet nicht", "", "", 0, 2, "Eigener DNS-Resolver, falls gewählt."},
	{"cert", "Server", "Zertifikat für DoH/DoT läuft ab", "Tage", "", 14, 0, "Meldet, wenn das Let's-Encrypt-Zertifikat in weniger Tagen abläuft."},
	{"login_lock", "Server", "Adressen durch die Login-Sperre gesperrt", "Anzahl", "", 1, 0, "Automatische Sperren nach Fehlversuchen (ohne von Hand gesperrte)."},
	{"exit_usage", "Ausgänge", "Ausgang: Verbrauch vom Datenlimit", "%", "exit", 80, 0, "Nur für Ausgänge mit Datenlimit, im laufenden Zeitraum."},
	{"exit_gb", "Ausgänge", "Ausgang: Verbrauch im Zeitraum", "GB", "exit", 500, 0, "Zeitraum des Limits, ohne Limit der laufende Kalendermonat. Hoch und runter zusammen."},
	{"exit_limit", "Ausgänge", "Ausgang: Limit erreicht (abgeschaltet oder gedrosselt)", "", "exit", 0, 0, "Sobald ein Limit greift."},
	{"exit_down", "Ausgänge", "Ausgang gestört", "", "exit", 0, 5, "Tunnel nicht verbunden oder kein Internet über den Ausgang."},
	{"group_down", "Ausgänge", "Ausgangsgruppe ohne Ausgang", "", "group", 0, 2, "Alle Ausgänge der Gruppe gestört – Verkehr gesperrt oder direkt."},
	{"user_usage", "Nutzer", "Nutzer: Verbrauch vom Datenlimit", "%", "user", 90, 0, "Nur Nutzer mit Datenlimit (eigenes oder Tarif)."},
	{"user_limit", "Nutzer", "Nutzer: Limit erreicht (gesperrt oder gedrosselt)", "", "user", 0, 0, "Datenlimit oder Drosselstufe greift."},
}

func alarmType(key string) *AlarmType {
	for i := range AlarmTypes {
		if AlarmTypes[i].Key == key {
			return &AlarmTypes[i]
		}
	}
	return nil
}

// Alarm: eine Regel.
type Alarm struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Type      string   `json:"type"`
	Target    int64    `json:"target"` // 0 = alle
	Threshold float64  `json:"threshold"`
	Minutes   int      `json:"minutes"` // so lange schlecht, bevor gemeldet wird
	Repeat    int      `json:"repeat"`  // Stunden, 0 = nur einmal
	Recover   bool     `json:"recover"` // Entwarnung schicken
	To        []string `json:"to"`      // leer = Administratoren mit Benachrichtigungen
}

func AlarmFrom(o *store.Object) *Alarm {
	a := &Alarm{ID: o.ID, Name: o.Name, Enabled: o.Enabled, To: []string{}}
	a.Type, _ = o.Data["type"].(string)
	a.Target = int64(num(o.Data, "target"))
	a.Threshold = num(o.Data, "threshold")
	a.Minutes = int(num(o.Data, "minutes"))
	a.Repeat = int(num(o.Data, "repeat"))
	a.Recover, _ = o.Data["recover"].(bool)
	if l, ok := o.Data["to"].([]any); ok {
		for _, v := range l {
			if s, ok := v.(string); ok {
				a.To = append(a.To, s)
			}
		}
	}
	return a
}

func num(m store.M, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}

// ValidateAlarm prüft und vervollständigt eine Regel; schreibt sie in o.
func ValidateAlarm(a *Alarm, o *store.Object) error {
	t := alarmType(a.Type)
	if t == nil {
		return fmt.Errorf("unbekannte Art %q", a.Type)
	}
	a.Name = strings.TrimSpace(a.Name)
	if len([]rune(a.Name)) > 80 || strings.ContainsAny(a.Name, "\r\n") {
		return errors.New("Name zu lang")
	}
	if a.Name == "" {
		a.Name = t.Label
	}
	if t.Unit != "" {
		if a.Threshold <= 0 {
			return errors.New("Schwelle muss größer als 0 sein")
		}
		if t.Unit == "%" && a.Threshold > 100 {
			return errors.New("Schwelle: höchstens 100 %")
		}
		if a.Threshold > 1e7 {
			return errors.New("Schwelle zu groß")
		}
	} else {
		a.Threshold = 0
	}
	if t.Target == "" || a.Target < 0 {
		a.Target = 0
	}
	if a.Minutes < 0 || a.Minutes > 24*60 {
		return errors.New("Dauer: 0 bis 1440 Minuten")
	}
	if a.Repeat < 0 || a.Repeat > 24*30 {
		return errors.New("Wiederholen: 0 bis 720 Stunden")
	}
	var to []string
	for _, s := range a.To {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ad, err := mail.ParseAddress(s)
		if err != nil || ad.Name != "" || len(s) > 200 {
			return fmt.Errorf("E-Mail-Adresse %q ungültig", s)
		}
		to = append(to, ad.Address)
	}
	if len(to) > 10 {
		return errors.New("höchstens 10 Empfänger")
	}
	if to == nil {
		to = []string{}
	}
	a.To = to
	o.Name, o.Enabled = a.Name, a.Enabled
	if o.Data == nil {
		o.Data = store.M{}
	}
	o.Data["type"], o.Data["target"], o.Data["threshold"] = a.Type, a.Target, a.Threshold
	o.Data["minutes"], o.Data["repeat"], o.Data["recover"], o.Data["to"] = a.Minutes, a.Repeat, a.Recover, a.To
	return nil
}

// ---------- Zustand ----------

// alarmTrack: Zustand eines Prüfpunkts („<Alarm>:<Ziel>“).
type alarmTrack struct {
	Type   string `json:"type"`
	Since  int64  `json:"since"`  // schlecht seit
	Active bool   `json:"active"` // Alarm besteht (Dauer erreicht)
	Sent   int64  `json:"sent"`   // zuletzt gemeldet
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Value  string `json:"value,omitempty"`
}

type alarmState struct {
	mu      sync.Mutex
	loaded  bool
	track   map[string]*alarmTrack
	cpu     [2]uint64 // busy, all der vorigen Messung
	net     [3]uint64 // rx, tx, Zeitpunkt
	netIf   string
	lastRun time.Time
}

// ActiveAlarm: bestehender Alarm (Oberfläche, „Braucht Aufmerksamkeit“).
type ActiveAlarm struct {
	Key     string `json:"key"`
	Type    string `json:"type"`
	AlarmID int64  `json:"alarm_id"`
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
	Value   string `json:"value,omitempty"`
	Since   int64  `json:"since"`
	Active  bool   `json:"active"` // false = schlecht, aber Dauer noch nicht erreicht
	Sent    int64  `json:"sent"`
}

func (e *Engine) alarmLoad() {
	s := &e.alarm
	if s.loaded {
		return
	}
	s.loaded = true
	s.track = map[string]*alarmTrack{}
	_ = json.Unmarshal([]byte(e.St.GetSetting("state:alarms", "")), &s.track)
	if s.track == nil {
		s.track = map[string]*alarmTrack{}
	}
}

// alarmOwnAttention: Arten, die „Braucht Aufmerksamkeit“ ohnehin schon zeigt (nicht doppelt).
var alarmOwnAttention = map[string]bool{"disk": true, "mem": true, "errors": true, "updates": true, "unbound": true, "cert": true,
	"exit_limit": true, "exit_down": true, "group_down": true}

// ActiveAlarms: alle Prüfpunkte, die gerade schlecht sind.
func (e *Engine) ActiveAlarms() []ActiveAlarm {
	s := &e.alarm
	s.mu.Lock()
	defer s.mu.Unlock()
	e.alarmLoad()
	out := []ActiveAlarm{}
	for k, t := range s.track {
		id, _ := strconv.ParseInt(strings.SplitN(k, ":", 2)[0], 10, 64)
		out = append(out, ActiveAlarm{Key: k, Type: t.Type, AlarmID: id, Title: t.Title, Detail: t.Detail, Value: t.Value, Since: t.Since, Active: t.Active, Sent: t.Sent})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// ---------- Prüfen ----------

// alarmHit: Ergebnis einer Prüfung für ein Ziel.
type alarmHit struct {
	Key    string // Ziel innerhalb des Alarms („exit:3“, „-“)
	Bad    bool
	Title  string // „Ausgang „USA 1“: 85 % vom Datenlimit“
	Detail string
	Value  string
}

// alarmCtx: einmal je Runde gelesene Daten.
type alarmCtx struct {
	now     time.Time
	cpu     float64 // -1 = unbekannt
	mem     float64
	disk    float64
	mbit    float64 // -1 = unbekannt
	exitLim map[int64]ExitLimitState
	exits   []*store.Object
	snap    *Snapshot
}

func (e *Engine) alarmContext(now time.Time) *alarmCtx {
	c := &alarmCtx{now: now, cpu: -1, mbit: -1}
	s := &e.alarm
	if e.Sys.DryRun() {
		h := dryHostStats(now)
		c.cpu, c.mbit = h.CPU, max(h.RX, h.TX)*8/1e6
		c.mem = 100 * float64(h.MemUsed) / float64(h.MemTotal)
		c.disk = 100 * float64(h.DiskUsed) / float64(h.DiskSize)
	} else {
		busy, all, _ := readCPU()
		if s.cpu[1] > 0 && all > s.cpu[1] && busy >= s.cpu[0] {
			c.cpu = 100 * float64(busy-s.cpu[0]) / float64(all-s.cpu[1])
		}
		s.cpu = [2]uint64{busy, all}
		if used, total := readMem(); total > 0 {
			c.mem = 100 * float64(used) / float64(total)
		}
		if used, size := diskUsage(e.Cfg.DataDir); size > 0 {
			c.disk = 100 * float64(used) / float64(size)
		}
		iface := e.Setting("out_interface")
		if iface == "" {
			iface = "eth0"
		}
		rx, tx := readIfaceBytes(iface)
		ts := uint64(now.Unix())
		if s.netIf == iface && s.net[2] > 0 && ts > s.net[2] && rx >= s.net[0] && tx >= s.net[1] {
			dt := float64(ts - s.net[2])
			c.mbit = float64(max(rx-s.net[0], tx-s.net[1])) * 8 / dt / 1e6
		}
		s.net, s.netIf = [3]uint64{rx, tx, ts}, iface
	}
	c.exitLim = e.ExitLimitStates()
	c.exits, _ = e.St.Objects("exit")
	c.snap, _ = e.Snapshot()
	return c
}

func pct(v float64) string { return strconv.Itoa(int(v+0.5)) + " %" }

func gbStr(b int64) string {
	g := float64(b) / GB
	if g < 10 {
		return strings.Replace(strconv.FormatFloat(g, 'f', 1, 64), ".", ",", 1) + " GB"
	}
	return strconv.FormatFloat(g, 'f', 0, 64) + " GB"
}

func fmtNum(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	return strings.Replace(s, ".", ",", 1)
}

// evalAlarm prüft eine Regel und liefert je Ziel ein Ergebnis.
func (e *Engine) evalAlarm(a *Alarm, c *alarmCtx) []alarmHit {
	th := a.Threshold
	one := func(bad bool, title, detail, value string) []alarmHit {
		return []alarmHit{{Key: "-", Bad: bad, Title: title, Detail: detail, Value: value}}
	}
	switch a.Type {
	case "cpu":
		if c.cpu < 0 {
			return nil
		}
		return one(c.cpu >= th, "CPU-Auslastung "+pct(c.cpu), "Schwelle: "+fmtNum(th)+" %", pct(c.cpu))
	case "mem":
		return one(c.mem >= th, "Arbeitsspeicher zu "+pct(c.mem)+" belegt", "Schwelle: "+fmtNum(th)+" %", pct(c.mem))
	case "disk":
		return one(c.disk >= th, "Speicherplatz zu "+pct(c.disk)+" belegt", "Schwelle: "+fmtNum(th)+" %", pct(c.disk))
	case "rate":
		if c.mbit < 0 {
			return nil
		}
		v := fmt.Sprintf("%.0f Mbit/s", c.mbit)
		return one(c.mbit >= th, "Durchsatz "+v, "Schwelle: "+fmtNum(th)+" Mbit/s", v)
	case "errors":
		errs := e.Errors()
		keys := make([]string, 0, len(errs))
		for k := range errs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var lines []string
		for _, k := range keys {
			first, _, _ := strings.Cut(errs[k], "\n")
			lines = append(lines, "• "+clip(first, 200))
		}
		title := "Fehler im Panel"
		if len(lines) > 0 {
			title = fmt.Sprintf("%d Fehler im Panel", len(lines))
		}
		return one(len(lines) > 0, title, strings.Join(lines, "\n"), strconv.Itoa(len(lines)))
	case "updates":
		e.pkg.mu.Lock()
		pk := e.pkg.state
		e.pkg.mu.Unlock()
		return one(pk.Security > 0 && float64(pk.Security) >= th, fmt.Sprintf("%d Sicherheitsupdates für Debian-Pakete", pk.Security),
			fmt.Sprintf("Insgesamt %d Paket-Updates – einspielen mit „apt full-upgrade“ im Container.", pk.Debian), strconv.Itoa(pk.Security))
	case "unbound":
		h := e.UnboundHealth()
		if !h.On || h.Checked == 0 {
			return one(false, "Unbound", "", "")
		}
		return one(!h.OK, "Unbound antwortet nicht", h.Why, "")
	case "cert":
		if !e.encDNSOn() {
			return one(false, "Zertifikat", "", "")
		}
		st := e.EncDNSState()
		if !st.HasCert || st.Cert.SelfSigned || st.Cert.NotAfter == 0 {
			return one(false, "Zertifikat", "", "")
		}
		days := int(time.Until(time.Unix(st.Cert.NotAfter, 0)).Hours() / 24)
		return one(float64(days) < th, fmt.Sprintf("Zertifikat für %s läuft in %d Tagen ab", st.Host, days), "Letzter Fehler: "+orDash(st.Error), fmt.Sprintf("%d Tage", days))
	case "login_lock":
		locks, _ := e.St.LoginLocks()
		n := 0
		var nets []string
		for _, l := range locks {
			if !l.Manual && (l.Until == 0 || l.Until > c.now.Unix()) {
				n++
				if len(nets) < 20 {
					nets = append(nets, "• "+l.Net+" – "+l.Reason)
				}
			}
		}
		return one(n > 0 && float64(n) >= th, fmt.Sprintf("%d Adressen durch die Login-Sperre gesperrt", n), strings.Join(nets, "\n"), strconv.Itoa(n))
	case "exit_usage", "exit_gb", "exit_limit", "exit_down":
		return e.evalExitAlarm(a, c)
	case "group_down":
		var out []alarmHit
		_, gs := e.Exits.Status()
		groups, _ := e.St.Objects("group")
		for _, g := range groups {
			if !g.Enabled || (a.Target != 0 && a.Target != g.ID) {
				continue
			}
			st, ok := gs[g.ID]
			bad := ok && (st.State == "blocked" || st.State == "direct")
			what := map[string]string{"blocked": "Verkehr gesperrt", "direct": "Verkehr läuft direkt über den Server"}[st.State]
			out = append(out, alarmHit{Key: "group:" + strconv.FormatInt(g.ID, 10), Bad: bad, Title: "Ausgangsgruppe „" + g.Name + "“ ohne Ausgang",
				Detail: strings.TrimSpace(what + "\n" + st.Reason)})
		}
		return out
	case "user_usage", "user_limit":
		if c.snap == nil {
			return nil
		}
		var out []alarmHit
		for id, u := range c.snap.Users {
			if a.Target != 0 && a.Target != id {
				continue
			}
			key := "user:" + strconv.FormatInt(id, 10)
			if a.Type == "user_limit" {
				v := c.snap.Verdict[id]
				out = append(out, alarmHit{Key: key, Bad: u.Enabled && (v.Status == "blocked" || v.Status == "throttled"),
					Title: "Nutzer „" + u.Name + "“: " + v.Reason, Detail: "Verbrauch im Zeitraum: " + gbStr(u.PeriodUp+u.PeriodDown)})
				continue
			}
			l := EffectiveLimits(u, c.snap.Plans)
			if l == nil || l.TrafficGB <= 0 {
				continue
			}
			p := 100 * float64(u.PeriodUp+u.PeriodDown) / (l.TrafficGB * GB)
			out = append(out, alarmHit{Key: key, Bad: u.Enabled && p >= th, Title: "Nutzer „" + u.Name + "“: " + pct(p) + " vom Datenlimit",
				Detail: fmt.Sprintf("%s von %s GB im laufenden Zeitraum.", gbStr(u.PeriodUp+u.PeriodDown), fmtNum(l.TrafficGB)), Value: pct(p)})
		}
		return out
	}
	return nil
}

func (e *Engine) evalExitAlarm(a *Alarm, c *alarmCtx) []alarmHit {
	var out []alarmHit
	var es map[int64]exitStatusView
	if a.Type == "exit_down" {
		es = e.exitStatusViews()
	}
	var month map[int64]store.ExitTotals
	for _, o := range c.exits {
		if a.Target != 0 && a.Target != o.ID {
			continue
		}
		key := "exit:" + strconv.FormatInt(o.ID, 10)
		name := "Ausgang „" + o.Name + "“"
		lim, hasLim := c.exitLim[o.ID]
		switch a.Type {
		case "exit_usage":
			if !hasLim || lim.Limits.TrafficGB <= 0 {
				continue
			}
			out = append(out, alarmHit{Key: key, Bad: lim.Percent >= a.Threshold, Title: name + ": " + pct(lim.Percent) + " vom Datenlimit",
				Detail: fmt.Sprintf("%s von %s GB im laufenden Zeitraum.%s", gbStr(lim.Used), fmtNum(lim.Limits.TrafficGB), resetText(lim.NextReset)), Value: pct(lim.Percent)})
		case "exit_gb":
			used := int64(0)
			what := "im laufenden Zeitraum"
			if hasLim && lim.Limits.Period != "none" {
				used = lim.Used
			} else {
				if month == nil {
					ms := time.Date(c.now.Year(), c.now.Month(), 1, 0, 0, 0, 0, c.now.Location()).Unix()
					month, _ = e.St.ExitTraffic(ms)
				}
				used = month[o.ID].Up + month[o.ID].Down
				what = "in diesem Monat"
			}
			out = append(out, alarmHit{Key: key, Bad: float64(used) >= a.Threshold*GB, Title: name + ": " + gbStr(used) + " " + what,
				Detail: "Schwelle: " + fmtNum(a.Threshold) + " GB", Value: gbStr(used)})
		case "exit_limit":
			if !hasLim {
				continue
			}
			out = append(out, alarmHit{Key: key, Bad: lim.Status == "blocked" || lim.Status == "throttled", Title: name + ": " + lim.Reason,
				Detail: fmt.Sprintf("Verbrauch: %s.%s", gbStr(lim.Used), resetText(lim.NextReset))})
		case "exit_down":
			if !o.Enabled {
				continue
			}
			v, ok := es[o.ID]
			out = append(out, alarmHit{Key: key, Bad: ok && v.bad, Title: name + " gestört", Detail: v.why})
		}
	}
	return out
}

func resetText(ts int64) string {
	if ts == 0 {
		return ""
	}
	return " Nächster Zeitraum ab " + time.Unix(ts, 0).Format("02.01.2006 15:04") + "."
}

type exitStatusView struct {
	bad bool
	why string
}

func (e *Engine) exitStatusViews() map[int64]exitStatusView {
	out := map[int64]exitStatusView{}
	if e.Exits == nil {
		return out
	}
	es, _ := e.Exits.Status()
	for id, s := range es {
		if s.Standby && !s.Connected {
			out[id] = exitStatusView{bad: s.Error != "", why: s.Error}
			continue
		}
		if s.Checked == 0 {
			continue
		}
		out[id] = exitStatusView{bad: s.Error != "" || !s.Up, why: orDash(s.Error)}
	}
	return out
}

// alarmMailOK: Mailversand eingerichtet?
func (e *Engine) alarmMailOK() bool {
	return e.Setting("mail_enabled") == "1" && e.Setting("smtp_host") != "" && e.Setting("mail_from") != ""
}

func (e *Engine) alarmRecipients(a *Alarm) []string {
	if len(a.To) > 0 {
		return a.To
	}
	return e.NotifyRecipients()
}

// alarmSend: Mail in die Warteschlange (ohne Drosselung – die übernimmt „Wiederholen“).
func (e *Engine) alarmSend(a *Alarm, subject, body string) bool {
	if !e.alarmMailOK() {
		return false
	}
	to := e.alarmRecipients(a)
	if len(to) == 0 {
		return false
	}
	e.notif.init()
	select {
	case e.notif.ch <- notifyMail{to: to, subject: subject, body: body}:
		return true
	default:
		e.logQuiet("warn", "Alarm-Mail verworfen (Warteschlange voll): "+subject)
		return false
	}
}

// runAlarms: eine Runde (jede Minute aus der Überwachung).
func (e *Engine) runAlarms() {
	objs, err := e.St.Objects("alarm")
	if err != nil {
		return
	}
	s := &e.alarm
	s.mu.Lock()
	e.alarmLoad()
	now := time.Now()
	s.lastRun = now
	var c *alarmCtx
	seen := map[string]bool{}
	changed := false
	type mailOut struct {
		a          *Alarm
		subj, body string
	}
	var mails []mailOut
	for _, o := range objs {
		a := AlarmFrom(o)
		if !a.Enabled || alarmType(a.Type) == nil {
			continue
		}
		if c == nil {
			c = e.alarmContext(now)
		}
		for _, h := range e.evalAlarm(a, c) {
			k := strconv.FormatInt(a.ID, 10) + ":" + h.Key
			t := s.track[k]
			if !h.Bad {
				if t != nil {
					if t.Active && a.Recover && t.Sent > 0 {
						mails = append(mails, mailOut{a, "Entwarnung: " + h.Title, "Der Alarm „" + a.Name + "“ ist vorbei.\n\nAktuell: " + h.Title +
							"\nBestand seit " + time.Unix(t.Since, 0).Format("02.01.2006 15:04") + "."})
					}
					delete(s.track, k)
					changed = true
				}
				continue
			}
			seen[k] = true
			if t == nil {
				t = &alarmTrack{Type: a.Type, Since: now.Unix()}
				s.track[k] = t
				changed = true
			}
			if t.Title != h.Title || t.Detail != h.Detail || t.Value != h.Value {
				t.Title, t.Detail, t.Value = h.Title, h.Detail, h.Value
				changed = true
			}
			if now.Unix()-t.Since < int64(a.Minutes)*60-10 {
				continue // noch nicht lange genug
			}
			if !t.Active {
				t.Active, changed = true, true
				e.Log("warn", "Alarm „"+a.Name+"“: "+h.Title)
			}
			if t.Sent == 0 || (a.Repeat > 0 && now.Unix()-t.Sent >= int64(a.Repeat)*3600) {
				subj := "Alarm: " + h.Title
				if t.Sent > 0 {
					subj = "Alarm besteht weiter: " + h.Title
				}
				body := "Alarm „" + a.Name + "“\n\n" + h.Title
				if h.Detail != "" {
					body += "\n\n" + h.Detail
				}
				body += "\n\nBesteht seit " + time.Unix(t.Since, 0).Format("02.01.2006 15:04") + "."
				if a.Repeat > 0 {
					body += fmt.Sprintf(" Wiederholung alle %d Stunden, solange der Alarm besteht.", a.Repeat)
				}
				mails = append(mails, mailOut{a, subj, body})
				t.Sent, changed = now.Unix(), true
			}
		}
	}
	// Prüfpunkte gelöschter/ausgeschalteter Alarme bzw. Ziele vergessen
	for k := range s.track {
		if !seen[k] {
			delete(s.track, k)
			changed = true
		}
	}
	if changed {
		b, _ := json.Marshal(s.track)
		_ = e.St.SetSetting("state:alarms", string(b))
	}
	s.mu.Unlock()
	for _, m := range mails {
		e.alarmSend(m.a, m.subj, m.body)
	}
}

// TestAlarm: Testmail an die Empfänger eines Alarms.
func (e *Engine) TestAlarm(id int64) ([]string, error) {
	o, err := e.St.Object("alarm", id)
	if err != nil {
		return nil, err
	}
	a := AlarmFrom(o)
	if !e.alarmMailOK() {
		return nil, errors.New("Mailversand ist nicht eingerichtet (Einstellungen → Benachrichtigungen)")
	}
	to := e.alarmRecipients(a)
	if len(to) == 0 {
		return nil, errors.New("keine Empfänger – Adressen eintragen oder in „Mein Konto“ Benachrichtigungen einschalten")
	}
	if _, err := e.sendMail(to, "Test: Alarm „"+a.Name+"“", "So kommt eine Meldung des Alarms „"+a.Name+"“ an.\n\nDies ist nur ein Test."); err != nil {
		return nil, err
	}
	return to, nil
}

// SeedAlarms legt beim ersten Start sinnvolle Alarme an (einmalig, auch wenn später alle gelöscht werden).
func (e *Engine) SeedAlarms() {
	if e.St.GetSetting("state:alarms:seeded", "") == "1" {
		return
	}
	if objs, _ := e.St.Objects("alarm"); len(objs) == 0 {
		for _, d := range []Alarm{
			{Type: "disk", Threshold: 90, Minutes: 0, Repeat: 24, Recover: true, Enabled: true},
			{Type: "mem", Threshold: 90, Minutes: 10, Repeat: 0, Recover: true, Enabled: true},
			{Type: "cpu", Threshold: 90, Minutes: 15, Repeat: 0, Recover: true, Enabled: true},
			{Type: "exit_usage", Threshold: 80, Repeat: 0, Enabled: true},
			{Type: "exit_limit", Repeat: 0, Recover: true, Enabled: true},
			{Type: "exit_down", Minutes: 10, Repeat: 0, Recover: true, Enabled: false},
			{Type: "updates", Threshold: 1, Repeat: 0, Enabled: false},
		} {
			a := d
			o := &store.Object{Kind: "alarm", Data: store.M{}, Secrets: store.M{}}
			if ValidateAlarm(&a, o) == nil {
				_ = e.St.SaveObject(o)
			}
		}
	}
	_ = e.St.SetSetting("state:alarms:seeded", "1")
}
