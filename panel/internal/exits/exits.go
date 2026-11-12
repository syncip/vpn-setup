// Package exits: Ausgänge über externe VPNs (WireGuard- oder OpenVPN-Konfigurationen eines
// Anbieters) und Ausgangsgruppen mit Prüfung und automatischem Umschalten.
//
//   - Jeder Ausgang bekommt eine eigene Schnittstelle ex<ID>, aber KEINE Route in der
//     Haupttabelle – der Server selbst bleibt unverändert erreichbar.
//   - Jede Gruppe hat eine Markierung (fwmark, Bits 0x7f000000) und eine eigene Routing-Tabelle
//     mit „default dev ex<aktiver Ausgang>“. Wer die Gruppe nutzt (Proxy, später VPN-Server),
//     markiert seine Verbindungen; Umschalten = eine Route in dieser Tabelle ersetzen.
//   - Fallen alle Ausgänge aus: „block“ (Tabelle mit blackhole, nichts geht raus) oder
//     „direct“ (Tabelle leer → Haupttabelle, also direkt über den Server).
//   - Nur IPv4.
package exits

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

const (
	MarkMask   = 0x7f000000
	maxSlots   = 63
	confDir    = "/etc/vpn/exits"
	exitUnit   = "/etc/systemd/system/vpn-exit@.service"
	probeTable = 2000 // + Slot des Ausgangs
	groupTable = 3000 // + Slot der Gruppe
	probePrio  = 6100
	bindPrio   = 6200
	groupPrio  = 6000
)

const exitUnitFile = `# Vom VPN-Panel erzeugt – OpenVPN-Ausgang (Client) /etc/vpn/exits/<name>.ovpn
[Unit]
Description=VPN-Ausgang (OpenVPN) %i
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
WorkingDirectory=/etc/vpn/exits
ExecStart=/usr/sbin/openvpn --suppress-timestamps --config /etc/vpn/exits/%i.ovpn
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`

// GroupMark: Markierung, mit der Verbindungen über eine Gruppe laufen.
func GroupMark(slot int) uint32 { return uint32(slot) << 24 }

// GroupTable: Routing-Tabelle einer Gruppe (Weg über den aktiven Ausgang bzw. Sperre).
func GroupTable(slot int) int   { return groupTable + slot }
func probeMark(slot int) uint32 { return uint32(64+slot) << 24 }

// IfName: Schnittstelle eines Ausgangs.
func IfName(id int64) string { return fmt.Sprintf("ex%d", id) }

// ---------- Modelle ----------

type Exit struct {
	ID      int64
	Name    string
	Enabled bool
	Type    string // wireguard | openvpn
	Slot    int
	WG      *WG
	OVPN    *OVPN
	User    string
	Pass    string
	// Verbindung: always = ständig verbunden (alle 30 s geprüft); standby = nur verbunden, solange
	// eine Gruppe ihn nutzt – sonst alle CheckMin Minuten kurz verbinden und prüfen.
	Mode     string
	CheckMin int
}

// Standby: nur bei Bedarf verbunden.
func (e *Exit) Standby() bool { return e != nil && e.Mode == "standby" }

type Group struct {
	ID      int64
	Name    string
	Enabled bool
	Slot    int
	Exits   []int64 // Reihenfolge = Priorität
	OnFail  string  // block | direct
	MaxLoss float64 // Prozent
	MaxRTT  float64 // ms
	MinMbit float64 // 0 = nicht prüfen
	DNS     []string
}

func num(m store.M, k string, def float64) float64 {
	if v, ok := m[k].(float64); ok {
		return v
	}
	return def
}

// ExitFrom liest einen Ausgang aus der Datenbank.
func ExitFrom(o *store.Object) (*Exit, error) {
	e := &Exit{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Slot: int(num(o.Data, "slot", 0)), CheckMin: int(num(o.Data, "check_min", 30))}
	e.Type, _ = o.Data["type"].(string)
	if mode, _ := o.Data["mode"].(string); mode == "standby" {
		e.Mode = "standby"
	} else {
		e.Mode = "always"
	}
	if e.CheckMin < 5 {
		e.CheckMin = 5
	}
	cfg, _ := o.Secrets["config"].(string)
	var err error
	switch e.Type {
	case "wireguard":
		e.WG, err = ParseWG(cfg)
	case "openvpn":
		e.OVPN, err = ParseOVPN(cfg)
		e.User, _ = o.Secrets["username"].(string)
		e.Pass, _ = o.Secrets["password"].(string)
	default:
		err = fmt.Errorf("Typ %q unbekannt", e.Type)
	}
	return e, err
}

// GroupFrom liest eine Gruppe aus der Datenbank.
func GroupFrom(o *store.Object) *Group {
	g := &Group{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Slot: int(num(o.Data, "slot", 0)),
		MaxLoss: num(o.Data, "max_loss", 20), MaxRTT: num(o.Data, "max_rtt", 400), MinMbit: num(o.Data, "min_mbit", 0)}
	g.OnFail, _ = o.Data["on_fail"].(string)
	if g.OnFail != "direct" {
		g.OnFail = "block"
	}
	if l, ok := o.Data["exits"].([]any); ok {
		for _, v := range l {
			if f, ok := v.(float64); ok {
				g.Exits = append(g.Exits, int64(f))
			}
		}
	}
	dns, _ := o.Data["dns"].(string)
	for _, d := range strings.Split(dns, ",") {
		if ip := net.ParseIP(strings.TrimSpace(d)); ip != nil && ip.To4() != nil {
			g.DNS = append(g.DNS, ip.String())
		}
	}
	if len(g.DNS) == 0 {
		g.DNS = []string{"1.1.1.1", "9.9.9.9"}
	}
	return g
}

// FreeSlot: kleinster freier Platz (1–63) für eine neue Gruppe bzw. einen neuen Ausgang.
func FreeSlot(objs []*store.Object) (int, error) {
	used := map[int]bool{}
	for _, o := range objs {
		used[int(num(o.Data, "slot", 0))] = true
	}
	for i := 1; i <= maxSlots; i++ {
		if !used[i] {
			return i, nil
		}
	}
	return 0, fmt.Errorf("höchstens %d Einträge möglich", maxSlots)
}

// ---------- Zustand ----------

type Sample struct {
	TS   int64   `json:"ts"`
	Loss float64 `json:"loss"` // Prozent
	RTT  float64 `json:"rtt"`  // ms, 0 = keine Antwort
	OK   bool    `json:"ok"`   // HTTPS-Abruf durch den Tunnel geklappt
}

type ExitStatus struct {
	ID      int64    `json:"id"`
	Up      bool     `json:"up"` // Schnittstelle vorhanden
	Loss    float64  `json:"loss"`
	RTT     float64  `json:"rtt"`
	Mbit    float64  `json:"mbit"`
	MbitAt  int64    `json:"mbit_at"`
	IP      string   `json:"ip"`
	Loc     string   `json:"loc"`
	Error   string   `json:"error,omitempty"`
	Checked int64    `json:"checked"`
	Samples []Sample `json:"samples"`
	// Bereitschaft: nicht ständig verbunden
	Standby   bool  `json:"standby"`
	Connected bool  `json:"connected"`  // gerade verbunden
	NextCheck int64 `json:"next_check"` // nächste Prüfung (nur Bereitschaft)
}

type GroupStatus struct {
	ID     int64  `json:"id"`
	Active int64  `json:"active"` // 0 = kein Ausgang (gesperrt bzw. direkt)
	Since  int64  `json:"since"`
	State  string `json:"state"` // ok | failover | blocked | direct | waiting
	Reason string `json:"reason,omitempty"`
	Pinned int64  `json:"pinned,omitempty"` // von Hand gewählter Ausgang (bevorzugt statt des ersten)
}

// Env: was der Manager vom Panel braucht.
type Env struct {
	Sys system.Runner
	Get func(string) string
	Set func(string, string)
	Log func(level, msg string)
	Out string // Internet-Schnittstelle (eth0)
}

type Manager struct {
	mu      sync.Mutex
	status  map[int64]*ExitStatus
	groups  map[int64]*GroupStatus
	healthy map[string]time.Time // „Gruppe/Ausgang“ → gesund seit
	hooks   []func(groupID int64)
	probeMu sync.Mutex
	conn    map[int64]bool // Ausgänge in Bereitschaft, die gerade verbunden sind
	force   bool           // nächste Prüfung: auch Ausgänge in Bereitschaft (Knopf „Jetzt prüfen“)
}

func New() *Manager {
	return &Manager{status: map[int64]*ExitStatus{}, groups: map[int64]*GroupStatus{}, healthy: map[string]time.Time{}, conn: map[int64]bool{}}
}

// OnSwitch: wird nach jedem Umschalten einer Gruppe aufgerufen (z. B. Proxy trennt Verbindungen).
func (m *Manager) OnSwitch(f func(groupID int64)) {
	m.mu.Lock()
	m.hooks = append(m.hooks, f)
	m.mu.Unlock()
}

func (m *Manager) Status() (map[int64]ExitStatus, map[int64]GroupStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	es, gs := map[int64]ExitStatus{}, map[int64]GroupStatus{}
	for id, s := range m.status {
		c := *s
		c.Samples = append([]Sample(nil), s.Samples...)
		es[id] = c
	}
	for id, s := range m.groups {
		gs[id] = *s
	}
	return es, gs
}

// active: aktueller Ausgang einer Gruppe (beim ersten Mal: gespeicherter bzw. erster Ausgang).
func (m *Manager) active(env *Env, g *Group, exits map[int64]*Exit) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.groups[g.ID]; ok {
		return s.Active
	}
	var first int64
	saved, _ := strconv.ParseInt(env.Get(fmt.Sprintf("exits:active:%d", g.ID)), 10, 64)
	for _, id := range g.Exits {
		if e := exits[id]; e != nil && e.Enabled {
			if first == 0 {
				first = id
			}
			if id == saved {
				first = id
				break
			}
		}
	}
	st := "waiting"
	if first == 0 {
		st = failState(g)
	}
	pin, _ := strconv.ParseInt(env.Get(fmt.Sprintf("exits:pin:%d", g.ID)), 10, 64)
	m.groups[g.ID] = &GroupStatus{ID: g.ID, Active: first, Since: time.Now().Unix(), State: st, Pinned: pin}
	return first
}

// ---------- Anwenden ----------

type rule struct {
	Prio  int    `json:"p"`
	Mark  uint32 `json:"m"`
	Table int    `json:"t"`
	Oif   string `json:"o,omitempty"` // statt Markierung: Sockets, die an diese Schnittstelle gebunden sind
}

// Apply richtet Ausgänge, Routing-Regeln und Gruppen-Tabellen ein.
func (m *Manager) Apply(env *Env, exits []*Exit, groups []*Group) error {
	sys := env.Sys
	byID := map[int64]*Exit{}
	var errs []string
	want := map[string]string{} // Schnittstelle → Typ
	for _, e := range exits {
		byID[e.ID] = e
	}
	for _, g := range groups {
		if g.Enabled && g.Slot > 0 {
			m.active(env, g, byID) // aktuellen Ausgang festlegen – ihn braucht es verbunden
		}
	}
	needed := m.neededSet()
	for _, e := range exits {
		if !e.Enabled || e.Slot < 1 {
			continue
		}
		n := IfName(e.ID)
		want[n] = e.Type
		if e.Standby() && !needed[e.ID] && !m.isConn(e.ID) {
			m.disconnect(env, e) // Bereitschaft: nur zum Prüfen bzw. bei Bedarf verbinden
			continue
		}
		if err := m.applyExit(env, e); err != nil {
			errs = append(errs, e.Name+": "+err.Error())
		} else if e.Standby() {
			m.setConn(e.ID, true)
		}
	}
	// Nicht mehr benötigte Ausgänge abbauen
	var prev map[string]string
	_ = json.Unmarshal([]byte(env.Get("exits:ifaces")), &prev)
	for n, typ := range prev {
		if want[n] == typ {
			continue
		}
		if typ == "openvpn" {
			_, _ = sys.Run("systemctl", "disable", "--now", "vpn-exit@"+n)
			_ = sys.Remove(confDir + "/" + n + ".ovpn")
			_ = sys.Remove(confDir + "/" + n + ".auth")
		} else {
			_, _ = sys.Run("ip", "link", "del", "dev", n)
			_ = sys.Remove(confDir + "/" + n + ".conf")
		}
		env.Set("exits:cfg:"+n, "")
		env.Log("info", "Ausgang "+n+" entfernt")
	}
	b, _ := json.Marshal(want)
	env.Set("exits:ifaces", string(b))

	// Routing-Regeln: Prüf-Tabelle pro Ausgang, Tabelle pro Gruppe
	var rules []rule
	for _, e := range exits {
		if e.Enabled && e.Slot > 0 {
			rules = append(rules, rule{Prio: probePrio + e.Slot, Mark: probeMark(e.Slot), Table: probeTable + e.Slot})
			// Dienste, die sich an den Ausgang binden (SO_BINDTODEVICE, z. B. Hysteria2), finden ihre
			// Route nur über eine eigene Regel – in der Haupttabelle hat der Ausgang keine Route.
			rules = append(rules, rule{Prio: bindPrio + e.Slot, Table: probeTable + e.Slot, Oif: IfName(e.ID)})
		}
	}
	for _, g := range groups {
		if g.Enabled && g.Slot > 0 {
			rules = append(rules, rule{Prio: groupPrio + g.Slot, Mark: GroupMark(g.Slot), Table: groupTable + g.Slot})
		}
	}
	if err := syncRules(env, rules); err != nil {
		errs = append(errs, "Routing-Regeln: "+err.Error())
	}
	m.ensureRoutes(env, exits, groups)
	if err := firewall(env, want); err != nil {
		errs = append(errs, "Firewall: "+err.Error())
	}
	// Status entfernter Gruppen/Ausgänge vergessen
	m.mu.Lock()
	keepG := map[int64]bool{}
	for _, g := range groups {
		keepG[g.ID] = g.Enabled
	}
	for id := range m.groups {
		if !keepG[id] {
			delete(m.groups, id)
		}
	}
	for id := range m.status {
		if e := byID[id]; e == nil || !e.Enabled {
			delete(m.status, id)
		}
	}
	for id := range m.conn {
		if e := byID[id]; e == nil || !e.Enabled || !e.Standby() {
			delete(m.conn, id)
		}
	}
	m.mu.Unlock()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (m *Manager) applyExit(env *Env, e *Exit) error {
	sys := env.Sys
	n := IfName(e.ID)
	switch e.Type {
	case "wireguard":
		ep, err := ResolveEndpoint(e.WG.Endpoint, net.LookupIP)
		if err != nil {
			if sys.DryRun() {
				ep = e.WG.Endpoint
			} else {
				return err
			}
		}
		conf := e.WG.SetConf(ep)
		sig := fmt.Sprintf("%s|%s|%d", conf, e.WG.Address, e.WG.MTU)
		exists := sys.DryRun()
		if !exists {
			_, err := sys.Run("ip", "link", "show", "dev", n)
			exists = err == nil
		}
		if exists && env.Get("exits:cfg:"+n) == hash(sig) {
			return nil
		}
		if _, err := sys.WriteFile(confDir+"/"+n+".conf", []byte(conf), 0o600); err != nil {
			return err
		}
		if !exists {
			if _, err := sys.Run("ip", "link", "add", "dev", n, "type", "wireguard"); err != nil {
				return fmt.Errorf("WireGuard-Schnittstelle anlegen: %w", err)
			}
		}
		steps := [][]string{
			{"wg", "setconf", n, confDir + "/" + n + ".conf"},
			{"ip", "-4", "address", "flush", "dev", n},
			{"ip", "-4", "address", "add", e.WG.Address.String(), "dev", n, "noprefixroute"},
			{"ip", "link", "set", "dev", n, "mtu", strconv.Itoa(e.WG.MTU), "up"},
			{"sysctl", "-qw", "net.ipv4.conf." + n + ".rp_filter=2"},
		}
		for _, s := range steps {
			if _, err := sys.Run(s[0], s[1:]...); err != nil {
				return err
			}
		}
		env.Set("exits:cfg:"+n, hash(sig))
		env.Log("info", "Ausgang „"+e.Name+"“ (WireGuard) eingerichtet")
	case "openvpn":
		if e.OVPN.NeedAuth && (e.User == "" || e.Pass == "") {
			return fmt.Errorf("die Konfiguration verlangt Benutzername und Passwort")
		}
		if !sys.DryRun() && !sys.Exists("/dev/net/tun") {
			return fmt.Errorf("/dev/net/tun fehlt (siehe README, Abschnitt OpenVPN)")
		}
		if ch, err := sys.WriteFile(exitUnit, []byte(exitUnitFile), 0o644); err != nil {
			return err
		} else if ch {
			_, _ = sys.Run("systemctl", "daemon-reload")
		}
		auth := confDir + "/" + n + ".auth"
		changed := false
		if e.OVPN.NeedAuth {
			ch, err := sys.WriteFile(auth, []byte(e.User+"\n"+e.Pass+"\n"), 0o600)
			if err != nil {
				return err
			}
			changed = ch
		}
		ch, err := sys.WriteFile(confDir+"/"+n+".ovpn", []byte(e.OVPN.Full(n, auth)), 0o600)
		if err != nil {
			return err
		}
		changed = changed || ch
		unit := "vpn-exit@" + n
		if changed {
			_, _ = sys.Run("systemctl", "enable", unit)
			if _, err := sys.Run("systemctl", "restart", unit); err != nil {
				return fmt.Errorf("OpenVPN-Ausgang starten: %w", err)
			}
			env.Log("info", "Ausgang „"+e.Name+"“ (OpenVPN) eingerichtet")
		} else if _, err := sys.Run("systemctl", "is-active", "--quiet", unit); err != nil {
			_, _ = sys.Run("systemctl", "enable", unit)
			_, _ = sys.Run("systemctl", "restart", unit)
		}
		_, _ = sys.Run("sysctl", "-qw", "net.ipv4.conf."+n+".rp_filter=2")
	}
	return nil
}

// ensureRoutes: Prüf-Routen der Ausgänge und Routen der Gruppen setzen. OpenVPN legt seine
// Schnittstelle bei jedem Neuverbinden neu an – deshalb regelmäßig (bei jeder Prüfung) aufrufen.
func (m *Manager) ensureRoutes(env *Env, exits []*Exit, groups []*Group) {
	sys := env.Sys
	byID := map[int64]*Exit{}
	for _, e := range exits {
		byID[e.ID] = e
		if e.Enabled && e.Slot > 0 {
			n := IfName(e.ID)
			// Keine Routen über den Ausgang in der Haupttabelle: OpenVPN vergibt die Adresse samt
			// Netz (z. B. 10.8.0.2/24) – die automatische Netzroute könnte sonst eigene Netze überdecken.
			if !sys.DryRun() {
				if out, err := sys.Run("ip", "-4", "route", "show", "table", "main", "dev", n); err == nil && strings.TrimSpace(out) != "" {
					_, _ = sys.Run("ip", "-4", "route", "flush", "table", "main", "dev", n)
				}
			}
			_, _ = sys.Run("ip", "-4", "route", "replace", "default", "dev", n, "table", strconv.Itoa(probeTable+e.Slot))
		}
	}
	for _, g := range groups {
		if !g.Enabled || g.Slot < 1 {
			continue
		}
		m.routeGroup(env, g, m.active(env, g, byID))
	}
}

func (m *Manager) routeGroup(env *Env, g *Group, active int64) {
	t := strconv.Itoa(groupTable + g.Slot)
	sys := env.Sys
	// Sicherung: Verschwindet die Schnittstelle (OpenVPN verbindet neu), wäre die Tabelle leer und
	// der Verkehr liefe bis zur nächsten Prüfung direkt mit der Adresse des Servers. Die Sperr-Route
	// mit hoher Metrik greift nur dann. Bei „direkt“ ist der direkte Weg gewollt.
	if g.OnFail == "direct" {
		_, _ = sys.Run("ip", "-4", "route", "del", "blackhole", "default", "metric", safetyMetric, "table", t)
	} else {
		_, _ = sys.Run("ip", "-4", "route", "replace", "blackhole", "default", "metric", safetyMetric, "table", t)
	}
	switch {
	case active != 0:
		if _, err := sys.Run("ip", "-4", "route", "replace", "default", "dev", IfName(active), "table", t); err != nil {
			// Schnittstelle (noch) nicht da (OpenVPN verbindet gerade) → lieber sperren
			_, _ = sys.Run("ip", "-4", "route", "replace", "blackhole", "default", "table", t)
		}
	case g.OnFail == "direct":
		_, _ = sys.Run("ip", "-4", "route", "flush", "table", t)
	default:
		_, _ = sys.Run("ip", "-4", "route", "replace", "blackhole", "default", "table", t)
	}
}

const safetyMetric = "10000"

func syncRules(env *Env, want []rule) error {
	sys := env.Sys
	var prev []rule
	_ = json.Unmarshal([]byte(env.Get("exits:rules")), &prev)
	has := map[rule]bool{}
	for _, r := range prev {
		has[r] = true
	}
	need := map[rule]bool{}
	for _, r := range want {
		need[r] = true
	}
	for _, r := range prev {
		if !need[r] {
			_, _ = sys.Run("ip", "-4", "rule", "del", "priority", strconv.Itoa(r.Prio))
		}
	}
	var errs []string
	for _, r := range want {
		if has[r] && !sys.DryRun() {
			if out, err := sys.Run("ip", "-4", "rule", "show", "priority", strconv.Itoa(r.Prio)); err == nil && strings.Contains(out, "lookup") {
				continue
			}
		}
		_, _ = sys.Run("ip", "-4", "rule", "del", "priority", strconv.Itoa(r.Prio))
		sel := []string{"fwmark", fmt.Sprintf("0x%x/0x%x", r.Mark, MarkMask)}
		if r.Oif != "" {
			sel = []string{"oif", r.Oif}
		}
		args := append(append([]string{"-4", "rule", "add", "priority", strconv.Itoa(r.Prio)}, sel...), "lookup", strconv.Itoa(r.Table))
		if _, err := sys.Run("ip", args...); err != nil {
			errs = append(errs, err.Error())
		}
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Prio < want[j].Prio })
	b, _ := json.Marshal(want)
	env.Set("exits:rules", string(b))
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// firewall: Ausgänge sind nach innen dicht (der Anbieter kann keine Dienste des Servers
// erreichen), Verkehr hinaus wird maskiert, TCP-MSS an die kleinere MTU angepasst.
func firewall(env *Env, ifaces map[string]string) error {
	sys := env.Sys
	if len(ifaces) == 0 {
		if env.Get("exits:fw") == "" {
			return nil
		}
		_, _ = sys.Run("iptables", "-D", "INPUT", "-j", "VPNEX-IN")
		_, _ = sys.Run("iptables", "-F", "VPNEX-IN")
		_, _ = sys.Run("iptables", "-X", "VPNEX-IN")
		_, _ = sys.Run("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "VPNEX-NAT")
		_, _ = sys.Run("iptables", "-t", "nat", "-F", "VPNEX-NAT")
		_, _ = sys.Run("iptables", "-t", "nat", "-X", "VPNEX-NAT")
		_, _ = sys.Run("iptables", "-t", "mangle", "-D", "FORWARD", "-j", "VPNEX-MSS")
		_, _ = sys.Run("iptables", "-t", "mangle", "-F", "VPNEX-MSS")
		_, _ = sys.Run("iptables", "-t", "mangle", "-X", "VPNEX-MSS")
		env.Set("exits:fw", "")
		return nil
	}
	names := make([]string, 0, len(ifaces))
	for n := range ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("*filter\n:VPNEX-IN - [0:0]\n-F VPNEX-IN\n")
	for _, n := range names {
		fmt.Fprintf(&b, "-A VPNEX-IN -i %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A VPNEX-IN -i %s -j DROP\n", n, n)
	}
	b.WriteString("COMMIT\n*nat\n:VPNEX-NAT - [0:0]\n-F VPNEX-NAT\n")
	for _, n := range names {
		fmt.Fprintf(&b, "-A VPNEX-NAT -o %s -j MASQUERADE\n", n)
	}
	b.WriteString("COMMIT\n*mangle\n:VPNEX-MSS - [0:0]\n-F VPNEX-MSS\n")
	for _, n := range names {
		fmt.Fprintf(&b, "-A VPNEX-MSS -o %s -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", n)
	}
	b.WriteString("COMMIT\n")
	if _, err := sys.RunInput(b.String(), "iptables-restore", "-n"); err != nil {
		return err
	}
	for _, j := range [][]string{{"filter", "INPUT", "VPNEX-IN", "-I"}, {"nat", "POSTROUTING", "VPNEX-NAT", "-A"}, {"mangle", "FORWARD", "VPNEX-MSS", "-A"}} {
		if _, err := sys.Run("iptables", "-t", j[0], "-C", j[1], "-j", j[2]); err != nil {
			if _, err := sys.Run("iptables", "-t", j[0], j[3], j[1], "-j", j[2]); err != nil {
				return err
			}
		}
	}
	env.Set("exits:fw", "1")
	return nil
}
