package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/exits"
)

// Unbound je Ausgangsgruppe: Mit „Unbound (selbst auflösen)“ bekommt jede aktive Gruppe eine eigene
// kleine Unbound-Instanz (127.0.0.1:5400+Platz der Gruppe). Sie läuft unter einem eigenen
// Systembenutzer; eine Routing-Regel für diesen Benutzer (ip rule uidrange) schickt alle Anfragen
// nach außen über die Tabelle der Gruppe, also über ihren Ausgang (samt Failover). Der Weg steht so
// schon beim Senden fest (Absender = Adresse am Tunnel), wie beim SO_MARK des Panel-DNS – eine
// nachträgliche Umleitung per Markierung verlor auf sys1 die Adressumschreibung. Ein Kill-Switch verwirft
// alles, was sonst hinaus wollte (anderer Weg, IPv6) – kein DNS-Leck, auch nicht bei Fehlern im
// Routing. Für Geräte mit Ausgangsgruppe fragt der Panel-DNS zuerst die Instanz, dann die
// DNS-Server der Gruppe (ebenfalls über den Ausgang).

const (
	ubgPortBase = 5400
	ubgUnitPath = "/etc/systemd/system/vpn-unbound@.service"
	ubgDataDir  = "/var/lib/vpnpanel-unbound"
	ubgStateKey = "state:unbound_groups"
	ubgDryUID   = 64000 // Trockenlauf: ausgedachte Benutzer-IDs ab hier
	ubgRulePrio = 6300  // + Platz der Gruppe: ip rule uidrange → Tabelle der Gruppe
)

// Die Instanzen startet nur das Panel – erst nachdem die nftables-Regeln (Weg über den Ausgang,
// Kill-Switch) geladen sind; nach einem Neustart des Servers also nicht vor dem Panel. Zusätzlich
// verweigert der Dienst den Start, solange die Kill-Switch-Kette fehlt.
const ubgUnit = `# Vom VPN-Panel geschrieben – Unbound für eine Ausgangsgruppe (%i). Wird nur vom Panel gestartet.
[Unit]
Description=Unbound für Ausgangsgruppe %i (VPN-Panel)
After=network-online.target vpnpanel.service

[Service]
Type=simple
ExecStartPre=/usr/sbin/nft list chain inet ` + nftTable + ` vp_ubguard
ExecStart=/usr/sbin/unbound -d -p -c /etc/unbound/vpnpanel-%i.conf
Restart=always
RestartSec=5
LimitNOFILE=65536
`

// ubInstance: eine Instanz für eine Gruppe.
type ubInstance struct {
	GID  int64
	Name string // Name der Gruppe
	Mark uint32
	Slot int
	User string
	UID  int
	Addr string
	// restart: Konfiguration geändert → beim Starten neu starten
	restart bool
}

func (in ubInstance) unit() string { return "vpn-unbound@g" + strconv.FormatInt(in.GID, 10) }
func (in ubInstance) conf() string {
	return "/etc/unbound/vpnpanel-g" + strconv.FormatInt(in.GID, 10) + ".conf"
}
func (in ubInstance) dir() string { return ubgDataDir + "/g" + strconv.FormatInt(in.GID, 10) }
func ubUser(gid int64) string     { return "vpnub" + strconv.FormatInt(gid, 10) }

// rule: Auswahl und Ziel der Routing-Regel (ohne „ip -4 rule add priority N“).
func (in ubInstance) rule() string {
	return fmt.Sprintf("uidrange %d-%d lookup %d", in.UID, in.UID, exits.GroupTable(in.Slot))
}
func (in ubInstance) prio() int { return ubgRulePrio + in.Slot }

type ubGroupState struct {
	apply   sync.Mutex // Anwenden (aus Apply und aus der Selbstprüfung)
	mu      sync.Mutex
	pending []ubInstance // eingerichtet; nftScript schreibt dafür den Kill-Switch
	list    []ubInstance // gestartet
}

// ubInstances: laufende Instanzen (Kopie).
func (e *Engine) ubInstances() []ubInstance {
	e.ubg.mu.Lock()
	defer e.ubg.mu.Unlock()
	return append([]ubInstance(nil), e.ubg.list...)
}

// ubPending: eingerichtete Instanzen (Kopie).
func (e *Engine) ubPending() []ubInstance {
	e.ubg.mu.Lock()
	defer e.ubg.mu.Unlock()
	return append([]ubInstance(nil), e.ubg.pending...)
}

// ubNames: Anzeigenamen der Instanzen (Adresse → „Unbound · Gruppe“) für DNSServerName.
var ubNames sync.Map

func (e *Engine) unboundGroupConfig(in ubInstance) string {
	return fmt.Sprintf(`# Vom VPN-Panel geschrieben – Unbound für die Ausgangsgruppe „%s“.
# Alle Anfragen nach außen laufen über den Ausgang der Gruppe (Routing-Regel für den Benutzer %s);
# Änderungen gehen beim nächsten Anwenden verloren.
server:
    interface: %s
    port: %s
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    username: "%s"
    chroot: ""
    directory: "%s"
    use-syslog: no
    auto-trust-anchor-file: "%s/root.key"
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    use-caps-for-id: no
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 3600
    edns-buffer-size: 1232
    msg-cache-size: 8m
    rrset-cache-size: 16m
    num-threads: 1
    verbosity: 0

remote-control:
    control-enable: no
`, strings.NewReplacer("\n", " ", "\"", "").Replace(in.Name), in.User, strings.Replace(in.Addr, ":", "@", 1),
		in.Addr[strings.LastIndex(in.Addr, ":")+1:], in.User, in.dir(), in.dir())
}

// applyUnboundGroups richtet die Instanzen ein (ohne sie zu starten) bzw. entfernt sie (want=false:
// alle entfernen). Gestartet werden sie mit startUBInstances, nachdem nftables geladen ist.
func (e *Engine) applyUnboundGroups(want bool) {
	var insts []ubInstance
	var errs []string
	if want {
		groups := e.groupRoutes()
		ids := make([]int64, 0, len(groups))
		for id := range groups {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		unitChanged := false
		if len(ids) > 0 {
			ch, err := e.Sys.WriteFile(ubgUnitPath, []byte(ubgUnit), 0o644)
			if err != nil {
				errs = append(errs, err.Error())
			}
			unitChanged = ch
			if ch {
				_, _ = e.Sys.Run("systemctl", "daemon-reload")
			}
		}
		for _, id := range ids {
			gr := groups[id]
			slot := int(gr.Mark >> 24)
			if !gr.Enabled || slot <= 0 {
				continue
			}
			in := ubInstance{GID: id, Name: gr.Name, Mark: gr.Mark, Slot: slot, User: ubUser(id), Addr: fmt.Sprintf("127.0.0.1:%d", ubgPortBase+slot)}
			if err := e.setupUBInstance(&in, unitChanged); err != nil {
				errs = append(errs, "„"+gr.Name+"“: "+err.Error())
				continue
			}
			insts = append(insts, in)
		}
	}
	// nicht mehr gebrauchte Instanzen entfernen
	var prev []int64
	_ = json.Unmarshal([]byte(e.St.GetSetting(ubgStateKey, "")), &prev)
	keep := map[int64]bool{}
	ids := []int64{}
	for _, in := range insts {
		keep[in.GID] = true
		ids = append(ids, in.GID)
	}
	for _, gid := range prev {
		if !keep[gid] {
			e.removeUBInstance(ubInstance{GID: gid, User: ubUser(gid)})
		}
	}
	b, _ := json.Marshal(ids)
	_ = e.St.SetSetting(ubgStateKey, string(b))

	e.ubg.mu.Lock()
	e.ubg.pending = insts
	if len(insts) == 0 {
		e.ubg.list = nil
	}
	e.ubg.mu.Unlock()
	if len(insts) == 0 {
		e.dns.mu.Lock()
		e.dns.ubg = nil
		e.dns.mu.Unlock()
		if err := e.syncUBRules(nil); err != nil {
			errs = append(errs, err.Error())
		}
	}
	e.setErr("unbound_groups", strings.Join(errs, "; "))
	if len(errs) > 0 {
		e.Log("warn", "Unbound je Ausgangsgruppe: "+strings.Join(errs, "; "))
	}
}

// startUBInstances startet die eingerichteten Instanzen (nftables ist geladen) und gibt sie für den
// Panel-DNS frei.
func (e *Engine) startUBInstances() {
	e.ubg.apply.Lock()
	defer e.ubg.apply.Unlock()
	var insts []ubInstance
	var errs []string
	// Routing-Regeln vor dem Start: ohne Regel verwirft der Kill-Switch alles (kein Leck)
	if err := e.syncUBRules(e.ubPending()); err != nil {
		errs = append(errs, err.Error())
	}
	for _, in := range e.ubPending() {
		act := "start"
		if in.restart {
			act = "restart"
		}
		if out, err := e.Sys.Run("systemctl", act, in.unit()); err != nil {
			errs = append(errs, "„"+in.Name+"“ startet nicht: "+strings.TrimSpace(out))
			continue
		}
		in.restart = false
		insts = append(insts, in)
	}
	e.ubg.mu.Lock()
	e.ubg.list = insts
	for i := range e.ubg.pending {
		e.ubg.pending[i].restart = false
	}
	e.ubg.mu.Unlock()
	addrs := map[int64]string{}
	ubNames.Range(func(k, _ any) bool { ubNames.Delete(k); return true })
	for _, in := range insts {
		addrs[in.GID] = in.Addr
		ubNames.Store(in.Addr, "Unbound · "+in.Name)
		if _, ok := e.dns.ubgState.Load(in.Addr); !ok {
			st := &unboundState{}
			st.down.Store(true) // erst nach der ersten erfolgreichen Prüfung fragen
			e.dns.ubgState.Store(in.Addr, st)
		}
	}
	e.dns.mu.Lock()
	e.dns.ubg = addrs
	e.dns.mu.Unlock()
	if len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		if prev := e.Errors()["unbound_groups"]; prev != "" {
			msg = prev + "; " + msg
		}
		e.setErr("unbound_groups", msg)
		e.Log("warn", "Unbound je Ausgangsgruppe: "+strings.Join(errs, "; "))
	}
}

// stopUBInstances: nftables ließ sich nicht laden – ohne Kill-Switch dürfen die
// Instanzen nicht laufen (ihre Anfragen gingen sonst direkt hinaus).
func (e *Engine) stopUBInstances(reason string) {
	e.ubg.apply.Lock()
	defer e.ubg.apply.Unlock()
	all := append(e.ubPending(), e.ubInstances()...)
	if len(all) == 0 {
		return
	}
	seen := map[int64]bool{}
	for _, in := range all {
		if !seen[in.GID] {
			seen[in.GID] = true
			_, _ = e.Sys.Run("systemctl", "stop", in.unit())
		}
	}
	e.ubg.mu.Lock()
	e.ubg.list = nil
	e.ubg.mu.Unlock()
	e.dns.mu.Lock()
	e.dns.ubg = nil
	e.dns.mu.Unlock()
	e.setErr("unbound_groups", "Unbound je Ausgangsgruppe angehalten: "+reason)
	e.Log("error", "Unbound je Ausgangsgruppe angehalten (Firewall-Regeln fehlen): "+reason)
}

// setupUBInstance: Benutzer, Verzeichnis, Vertrauensanker, Konfiguration, Dienst.
func (e *Engine) setupUBInstance(in *ubInstance, unitChanged bool) error {
	uid, err := e.ensureUBUser(in.User, in.GID)
	if err != nil {
		return err
	}
	in.UID = uid
	if !e.Sys.DryRun() {
		if _, err := e.Sys.Run("install", "-d", "-m", "755", ubgDataDir); err != nil {
			return fmt.Errorf("Verzeichnis %s: %v", ubgDataDir, err)
		}
		if _, err := e.Sys.Run("install", "-d", "-o", in.User, "-g", in.User, "-m", "750", in.dir()); err != nil {
			return fmt.Errorf("Verzeichnis %s: %v", in.dir(), err)
		}
		key := in.dir() + "/root.key"
		if !e.Sys.Exists(key) {
			src := unboundKey
			if !e.Sys.Exists(src) {
				src = dnsRootKey
			}
			if !e.Sys.Exists(src) {
				return fmt.Errorf("DNSSEC-Vertrauensanker fehlt (Paket „dns-root-data“ installieren)")
			}
			if _, err := e.Sys.Run("install", "-o", in.User, "-g", in.User, "-m", "644", src, key); err != nil {
				return fmt.Errorf("Vertrauensanker: %v", err)
			}
		}
	}
	changed, err := e.Sys.WriteFile(in.conf(), []byte(e.unboundGroupConfig(*in)), 0o644)
	if err != nil {
		return err
	}
	if out, err := e.Sys.Run("unbound-checkconf", in.conf()); err != nil {
		return fmt.Errorf("Konfiguration fehlerhaft: %s", strings.TrimSpace(out))
	}
	in.restart = changed || unitChanged
	return nil
}

func (e *Engine) removeUBInstance(in ubInstance) {
	_, _ = e.Sys.Run("systemctl", "disable", "--now", in.unit())
	_ = e.Sys.Remove(in.conf())
	if !e.Sys.DryRun() {
		_, _ = e.Sys.Run("rm", "-rf", "--", in.dir())
		_, _ = e.Sys.Run("userdel", in.User)
	}
}

// ensureUBUser legt den Systembenutzer der Instanz an und liefert seine ID.
func (e *Engine) ensureUBUser(user string, gid int64) (int, error) {
	if e.Sys.DryRun() {
		return ubgDryUID + int(gid), nil
	}
	if out, err := e.Sys.Run("id", "-u", user); err == nil {
		if uid, err := strconv.Atoi(strings.TrimSpace(out)); err == nil && uid > 0 {
			return uid, nil
		}
	}
	if out, err := e.Sys.Run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin", "--comment", "VPN-Panel Unbound", user); err != nil {
		return 0, fmt.Errorf("Benutzer %s: %s", user, strings.TrimSpace(out))
	}
	out, err := e.Sys.Run("id", "-u", user)
	if err != nil {
		return 0, fmt.Errorf("Benutzer %s: %v", user, err)
	}
	uid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || uid <= 0 {
		return 0, fmt.Errorf("Benutzer %s: unerwartete ID %q", user, strings.TrimSpace(out))
	}
	return uid, nil
}

// syncUBRules: Routing-Regeln (uidrange → Tabelle der Gruppe) für die Instanzen setzen, fremde
// Regeln im eigenen Bereich entfernen. Bestehende richtige Regeln bleiben unangetastet (kein Flattern).
func (e *Engine) syncUBRules(insts []ubInstance) error {
	have := map[int]string{}
	if !e.Sys.DryRun() {
		out, err := e.Sys.Run("ip", "-4", "rule", "show")
		if err != nil {
			return fmt.Errorf("Routing-Regeln lesen: %s", strings.TrimSpace(out))
		}
		for _, l := range strings.Split(out, "\n") {
			p, rest, ok := strings.Cut(strings.TrimSpace(l), ":")
			n, err := strconv.Atoi(p)
			if !ok || err != nil || n <= ubgRulePrio || n > ubgRulePrio+127 {
				continue
			}
			have[n] = strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(rest), "from all ")), " ")
		}
	}
	want := map[int]bool{}
	var errs []string
	for _, in := range insts {
		p := in.prio()
		want[p] = true
		if have[p] == in.rule() {
			continue
		}
		if _, ok := have[p]; ok {
			_, _ = e.Sys.Run("ip", "-4", "rule", "del", "priority", strconv.Itoa(p))
		}
		args := append([]string{"-4", "rule", "add", "priority", strconv.Itoa(p)}, strings.Fields(in.rule())...)
		if out, err := e.Sys.Run("ip", args...); err != nil {
			errs = append(errs, "Routing-Regel für „"+in.Name+"“: "+strings.TrimSpace(out))
		}
	}
	for p := range have {
		if !want[p] {
			_, _ = e.Sys.Run("ip", "-4", "rule", "del", "priority", strconv.Itoa(p))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// ubNftChains: Kill-Switch für die Instanzen. Der Weg über den Ausgang kommt aus der Routing-Regel
// (syncUBRules); fehlt sie oder zeigt die Tabelle woandershin, geht nichts hinaus.
func ubNftChains(insts []ubInstance) string {
	if len(insts) == 0 {
		return ""
	}
	var b strings.Builder
	// Wächter in postrouting: dort steht die endgültige Schnittstelle fest
	b.WriteString("\tchain vp_ubguard {\n\t\ttype filter hook postrouting priority filter; policy accept;\n")
	for _, in := range insts {
		// nur Loopback (Antworten an den Panel-DNS) und die Tunnel der Ausgänge; sonst nichts hinaus
		fmt.Fprintf(&b, "\t\tmeta skuid %d oifname \"lo\" accept\n\t\tmeta skuid %d meta nfproto ipv6 counter drop\n\t\tmeta skuid %d oifname != \"ex*\" counter drop\n",
			in.UID, in.UID, in.UID)
	}
	b.WriteString("\t}\n")
	return b.String()
}

// ---------- Selbstprüfung ----------

// UnboundGroupHealth: Zustand einer Instanz.
type UnboundGroupHealth struct {
	GID    int64  `json:"gid"`
	Name   string `json:"name"`
	Addr   string `json:"addr"`
	OK     bool   `json:"ok"`
	Why    string `json:"why,omitempty"`
	Detail string `json:"detail,omitempty"`
	MS     int    `json:"ms,omitempty"`
}

func (e *Engine) checkUnboundGroups() []UnboundGroupHealth {
	var out []UnboundGroupHealth
	for _, in := range e.ubInstances() {
		v, _ := e.dns.ubgState.LoadOrStore(in.Addr, &unboundState{})
		st := v.(*unboundState)
		h := UnboundGroupHealth{GID: in.GID, Name: in.Name, Addr: in.Addr}
		if e.Sys.DryRun() {
			h.OK, h.Why = true, "Testmodus – Instanz wird nicht gefragt"
			st.down.Store(false)
			out = append(out, h)
			continue
		}
		t := time.Now()
		resp := exchangeOne(probeRoot(), in.Addr, 0, false, 3*time.Second)
		if resp != nil && resp[3]&0x0f != 2 {
			h.OK, h.MS = true, int(time.Since(t).Milliseconds())
			st.fails.Store(0)
			st.down.Store(false)
			out = append(out, h)
			continue
		}
		st.down.Store(true)
		active := e.unitActive(in.unit())
		switch {
		case resp != nil:
			h.Why = "antwortet mit SERVFAIL – erreicht über den Ausgang keine DNS-Server (Ausgang gestört oder gesperrt?)"
		case !active:
			h.Why = "Dienst " + in.unit() + " läuft nicht"
		default:
			h.Why = "antwortet nicht (Zeitüberschreitung) – Ausgang der Gruppe gestört?"
		}
		st.mu.Lock()
		fix := time.Since(st.lastFix) > unboundFixGap
		if fix {
			st.lastFix = time.Now()
		}
		st.mu.Unlock()
		if fix && !active {
			_, _ = e.Sys.Run("systemctl", "restart", in.unit())
		}
		h.Why += ". Solange fragt der Panel-DNS die DNS-Server der Gruppe (ebenfalls über den Ausgang)."
		h.Detail = e.unitJournal(in.unit())
		out = append(out, h)
	}
	return out
}

func (e *Engine) unitActive(unit string) bool {
	out, _ := e.Sys.Run("systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

func (e *Engine) unitJournal(unit string) string {
	out, _ := e.Sys.Run("journalctl", "-u", unit, "-n", "8", "--no-pager", "-o", "cat")
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}
