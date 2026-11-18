package exits

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tor-Ausgang: Jeder Tor-Ausgang ist eine eigene Tor-Instanz (Dienst vpn-tor@exN, eigener
// Systembenutzer vpntor-exN, eigene Ports) plus eine TUN-Schnittstelle exN, die der Dienst
// vpn-t2s@exN („vpnpanel tun2socks“) an Tor weitergibt: TCP über den SOCKS-Port, DNS über den
// DNSPort, anderes UDP wird verworfen. Für den Rest des Panels ist exN ein Ausgang wie jeder andere
// – Gruppen, Prüfung, Limits (tc an exN), Block-Prüfung und Wechsel gelten unverändert.
//
// Kaskade (Tor über einen anderen Ausgang): Eine Routing-Regel für den Benutzer der Instanz
// (ip rule uidrange) schickt Tors Verbindungen über die Tabelle des Vorgängers; dahinter verwirft
// eine Sperr-Regel alles andere (IPv4 und IPv6). Der Dienst startet nur, wenn die Sperr-Regel steht.

const (
	torBin       = "/usr/bin/tor"
	torDir       = "/etc/vpn-tor" // außerhalb von /etc/vpn (0700): die Tor-Benutzer müssen ihre torrc lesen
	torOldDir    = "/etc/vpn/tor" // bis 0.25.0
	torStateDir  = "/var/lib/vpn-tor"
	torGeoIP     = "/usr/share/tor/geoip" // Paket tor-geoipdb: ohne die Datei kennt Tor keine Länder
	torUnitPath  = "/etc/systemd/system/vpn-tor@.service"
	t2sUnitPath  = "/etc/systemd/system/vpn-t2s@.service"
	torSocksBase = 19100 // + Platz
	torDNSBase   = 19200
	torCtlBase   = 19300
	torRulePrio  = 6600 // + Platz: uidrange → Tabelle des Vorgängers
	torBlockPrio = 6700 // + Platz: uidrange blackhole (Kill-Switch der Kaskade)
	torDryUID    = 65000
	torMTU       = 1500
)

const torUnitFile = `# Vom VPN-Panel geschrieben – Tor-Ausgang %i. Wird nur vom Panel gestartet.
[Unit]
Description=Tor-Ausgang %i (VPN-Panel)
After=network-online.target vpnpanel.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=vpntor-%i
# Kaskade: ohne Sperr-Regel für den Benutzer (Kill-Switch) startet Tor nicht – sonst ginge es direkt hinaus
# „+“: als root – der Dienstbenutzer sähe die Datei womöglich nicht, und die Prüfung fiele weg
ExecStartPre=+/bin/sh -c 'test ! -e /etc/vpn-tor/%i.via || { u=$$(id -u vpntor-%i) && ip -4 rule show | grep -q "uidrange $$u-$$u blackhole" && ip -6 rule show | grep -q "uidrange $$u-$$u blackhole"; }'
ExecStart=/usr/bin/tor -f /etc/vpn-tor/%i.torrc --RunAsDaemon 0
Restart=always
RestartSec=10
StateDirectory=vpn-tor/%i
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
`

const t2sUnitFile = `# Vom VPN-Panel geschrieben – Tor-Ausgang %i: Schnittstelle → Tor. Wird nur vom Panel gestartet.
[Unit]
Description=Tor-Ausgang %i – Schnittstelle (VPN-Panel)
After=vpn-tor@%i.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=vpntor-%i
EnvironmentFile=/etc/vpn-tor/%i.env
ExecStart=/usr/local/bin/vpnpanel tun2socks -dev %i -socks ${SOCKS} -dns ${DNS}
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
`

// TorCfg: Einstellungen eines Tor-Ausgangs.
type TorCfg struct {
	ExitCountries    []string `json:"exit_countries"`    // Ausgangsländer (ISO, klein), leer = beliebig
	EntryCountries   []string `json:"entry_countries"`   // Eingangsländer (Guard), leer = beliebig
	ExcludeCountries []string `json:"exclude_countries"` // nie benutzen
	Strict           bool     `json:"strict"`            // StrictNodes: Ausschlüsse auch dann, wenn Tor sonst nicht weiterkommt
	CircuitMin       int      `json:"circuit_min"`       // neue Verbindungen nach … Minuten über einen neuen Kreis (MaxCircuitDirtiness)
	Isolate          bool     `json:"isolate"`           // eigener Kreis je Zieladresse (IsolateDestAddr)
	Bridges          []string `json:"-"`                 // Brücken (geheim, aus Secrets)
}

// TorFrom liest die Einstellungen (Data["tor"], Secrets["bridges"]).
func TorFrom(v any, bridges string) *TorCfg {
	c := &TorCfg{CircuitMin: 10}
	if v != nil {
		b, _ := json.Marshal(v)
		_ = json.Unmarshal(b, c)
	}
	if c.CircuitMin <= 0 {
		c.CircuitMin = 10
	}
	for _, l := range strings.Split(strings.ReplaceAll(bridges, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "Bridge "))
		if l != "" && !strings.HasPrefix(l, "#") {
			c.Bridges = append(c.Bridges, l)
		}
	}
	return c
}

var (
	ccRe     = regexp.MustCompile(`^[a-z]{2}$`)
	bridgeRe = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]=,/+@%&?~-]+( [A-Za-z0-9_.:\[\]=,/+@%&?~-]+)*$`)
)

// torTransports: Brücken-Arten → mögliche Programme (das erste vorhandene wird benutzt).
var torTransports = map[string][]string{
	"obfs4": {"/usr/bin/lyrebird", "/usr/bin/obfs4proxy"}, "meek_lite": {"/usr/bin/lyrebird", "/usr/bin/obfs4proxy"},
	"webtunnel": {"/usr/bin/lyrebird"}, "scramblesuit": {"/usr/bin/lyrebird", "/usr/bin/obfs4proxy"},
	"snowflake": {"/usr/bin/snowflake-client"},
}

// NormCountries: „DE, ch at“ → [de ch at] (ohne Dubletten, sortiert).
func NormCountries(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '{' || r == '}' }) {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Check prüft die Einstellungen (Fehlertext oder "").
func (c *TorCfg) Check() string {
	for _, l := range [][]string{c.ExitCountries, c.EntryCountries, c.ExcludeCountries} {
		if len(l) > 60 {
			return "Zu viele Länder"
		}
		for _, cc := range l {
			if !ccRe.MatchString(cc) {
				return fmt.Sprintf("Ländercode %q ungültig (zwei Buchstaben, z. B. de, ch, nl)", cc)
			}
		}
	}
	for _, x := range c.ExcludeCountries {
		for _, y := range c.ExitCountries {
			if x == y {
				return "Land " + strings.ToUpper(x) + " ist zugleich Ausgangsland und ausgeschlossen"
			}
		}
	}
	if c.CircuitMin < 1 || c.CircuitMin > 24*60 {
		return "Neue Identität: 1 Minute bis 24 Stunden"
	}
	if len(c.Bridges) > 50 {
		return "Höchstens 50 Brücken"
	}
	for _, b := range c.Bridges {
		if len(b) > 1000 || !bridgeRe.MatchString(b) {
			return "Brücke ungültig: " + clip(b, 40)
		}
		if t := bridgeTransport(b); t != "" && torTransports[t] == nil {
			return "Brücken-Art „" + t + "“ wird nicht unterstützt (obfs4, webtunnel, snowflake, meek_lite)"
		}
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// bridgeTransport: Art einer Brücke („obfs4 1.2.3.4:443 …“ → obfs4, „1.2.3.4:443 FP“ → "").
func bridgeTransport(b string) string {
	f := strings.Fields(b)
	if len(f) == 0 || strings.Contains(f[0], ":") || net.ParseIP(f[0]) != nil {
		return ""
	}
	return strings.ToLower(f[0])
}

func torUser(n string) string { return "vpntor-" + n }

func torCC(l []string) string {
	out := make([]string, len(l))
	for i, c := range l {
		out[i] = "{" + c + "}"
	}
	return strings.Join(out, ",")
}

// torrc: Konfiguration der Instanz. plugins: Brücken-Art → Programm.
func torrc(e *Exit, plugins map[string]string) string {
	c, n, s := e.Tor, IfName(e.ID), e.Slot
	var b strings.Builder
	fmt.Fprintf(&b, "# Vom VPN-Panel erzeugt – Tor-Ausgang „%s“ (%s). Änderungen werden überschrieben.\n",
		strings.NewReplacer("\n", " ", "\r", " ").Replace(e.Name), n)
	iso := ""
	if c.Isolate {
		iso = " IsolateDestAddr"
	}
	fmt.Fprintf(&b, "SocksPort 127.0.0.1:%d%s\nDNSPort 127.0.0.1:%d\nControlPort 127.0.0.1:%d\nCookieAuthentication 1\n",
		torSocksBase+s, iso, torDNSBase+s, torCtlBase+s)
	fmt.Fprintf(&b, "DataDirectory %s/%s\nClientOnly 1\nAvoidDiskWrites 1\nLog notice stdout\nSafeLogging 1\n", torStateDir, n)
	// tun2socks gibt Tor nur IP-Adressen (DNS läuft getrennt über den DNSPort) – sonst eine Warnung je Verbindung
	b.WriteString("WarnUnsafeSocks 0\n")
	// nur IPv4 (der Kill-Switch der Kaskade gilt für beide, der Weg über den Vorgänger nur für IPv4)
	b.WriteString("ClientUseIPv4 1\nClientUseIPv6 0\nClientPreferIPv6ORPort 0\n")
	fmt.Fprintf(&b, "MaxCircuitDirtiness %d\n", c.CircuitMin*60)
	if len(c.ExitCountries) > 0 {
		fmt.Fprintf(&b, "ExitNodes %s\n", torCC(c.ExitCountries))
	}
	if len(c.EntryCountries) > 0 && len(c.Bridges) == 0 {
		fmt.Fprintf(&b, "EntryNodes %s\n", torCC(c.EntryCountries))
	}
	if len(c.ExcludeCountries) > 0 {
		fmt.Fprintf(&b, "ExcludeNodes %s\n", torCC(c.ExcludeCountries))
	}
	if c.Strict {
		b.WriteString("StrictNodes 1\n")
	}
	if len(c.Bridges) > 0 {
		b.WriteString("UseBridges 1\n")
		byProg := map[string][]string{}
		for t, p := range plugins {
			byProg[p] = append(byProg[p], t)
		}
		progs := make([]string, 0, len(byProg))
		for p := range byProg {
			progs = append(progs, p)
		}
		sort.Strings(progs)
		for _, p := range progs {
			ts := byProg[p]
			sort.Strings(ts)
			fmt.Fprintf(&b, "ClientTransportPlugin %s exec %s\n", strings.Join(ts, ","), p)
		}
		for _, br := range c.Bridges {
			fmt.Fprintf(&b, "Bridge %s\n", br)
		}
	}
	return b.String()
}

// torPlugins: Programme für die benutzten Brücken-Arten (Fehler, wenn eines fehlt).
func torPlugins(env *Env, c *TorCfg) (map[string]string, error) {
	out := map[string]string{}
	for _, br := range c.Bridges {
		t := bridgeTransport(br)
		if t == "" || out[t] != "" {
			continue
		}
		for _, p := range torTransports[t] {
			if env.Sys.DryRun() || env.Sys.Exists(p) {
				out[t] = p
				break
			}
		}
		if out[t] == "" {
			pkg := "obfs4proxy"
			if t == "snowflake" {
				pkg = "snowflake-client"
			}
			return nil, fmt.Errorf("für %s-Brücken fehlt das Paket „%s“ (apt install %s)", t, pkg, pkg)
		}
	}
	return out, nil
}

// ensureTorUser: Systembenutzer der Instanz, liefert die Benutzer-ID.
func ensureTorUser(env *Env, e *Exit) (int, error) {
	if env.Sys.DryRun() {
		return torDryUID + int(e.ID), nil
	}
	user := torUser(IfName(e.ID))
	id := func() (int, error) {
		out, err := env.Sys.Run("id", "-u", user)
		if err != nil {
			return 0, err
		}
		uid, err := strconv.Atoi(strings.TrimSpace(out))
		if err != nil || uid <= 0 {
			return 0, fmt.Errorf("unerwartete Benutzer-ID %q", strings.TrimSpace(out))
		}
		return uid, nil
	}
	if uid, err := id(); err == nil {
		return uid, nil
	}
	if out, err := env.Sys.Run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin", "--comment", "VPN-Panel Tor", user); err != nil {
		return 0, fmt.Errorf("Benutzer %s: %s", user, strings.TrimSpace(out))
	}
	return id()
}

// applyTor richtet einen Tor-Ausgang ein bzw. hält ihn am Laufen.
func (m *Manager) applyTor(env *Env, e *Exit) error {
	sys := env.Sys
	n := IfName(e.ID)
	if e.Tor == nil {
		e.Tor = TorFrom(nil, "")
	}
	if msg := e.Tor.Check(); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	if !sys.DryRun() && !sys.Exists(torBin) {
		return fmt.Errorf("Tor ist nicht installiert – vpn-setup.sh erneut ausführen (installiert das Paket „tor“)")
	}
	if !sys.DryRun() && !sys.Exists("/dev/net/tun") {
		return fmt.Errorf("/dev/net/tun fehlt (siehe README, Abschnitt OpenVPN)")
	}
	if c := e.Tor; !sys.DryRun() && len(c.ExitCountries)+len(c.EntryCountries)+len(c.ExcludeCountries) > 0 && !sys.Exists(torGeoIP) {
		return fmt.Errorf("für Länder braucht Tor das Paket „tor-geoipdb“ – vpn-setup.sh erneut ausführen (oder apt install tor-geoipdb)")
	}
	plugins, err := torPlugins(env, e.Tor)
	if err != nil {
		return err
	}
	user := torUser(n)
	if _, err := ensureTorUser(env, e); err != nil {
		return err
	}
	unitChanged := false
	for _, u := range [][2]string{{torUnitPath, torUnitFile}, {t2sUnitPath, t2sUnitFile}} {
		ch, err := sys.WriteFile(u[0], []byte(u[1]), 0o644)
		if err != nil {
			return err
		}
		unitChanged = unitChanged || ch
	}
	if unitChanged {
		_, _ = sys.Run("systemctl", "daemon-reload")
	}
	if !sys.DryRun() {
		if _, err := sys.Run("install", "-d", "-m", "755", torDir); err != nil {
			return fmt.Errorf("Verzeichnis %s: %v", torDir, err)
		}
	}
	for _, f := range []string{".torrc", ".env", ".via"} { // alter Ort (bis 0.25.0)
		_ = sys.Remove(torOldDir + "/" + n + f)
	}
	conf := torrc(e, plugins)
	if _, err := sys.WriteFile(torDir+"/"+n+".torrc", []byte(conf), 0o640); err != nil {
		return err
	}
	_, _ = sys.Run("chown", "root:"+user, torDir+"/"+n+".torrc") // Brücken: nur root und die Instanz lesen
	envf := fmt.Sprintf("SOCKS=127.0.0.1:%d\nDNS=127.0.0.1:%d\n", torSocksBase+e.Slot, torDNSBase+e.Slot)
	if _, err := sys.WriteFile(torDir+"/"+n+".env", []byte(envf), 0o644); err != nil {
		return err
	}
	if e.Via != 0 {
		if _, err := sys.WriteFile(torDir+"/"+n+".via", []byte(strconv.FormatInt(e.Via, 10)+"\n"), 0o644); err != nil {
			return err
		}
	} else {
		_ = sys.Remove(torDir + "/" + n + ".via")
	}
	// Kaskade: Weg und Sperre für den Benutzer, bevor Tor startet
	if err := m.syncTorRules(env); err != nil {
		return err
	}
	// Schnittstelle (dauerhaft – endet der Prozess, verwirft der Kernel die Pakete)
	exists := sys.DryRun() && env.Get("exits:cfg:"+n) != ""
	if !sys.DryRun() {
		out, err := sys.Run("ip", "-d", "link", "show", "dev", n)
		exists = err == nil && strings.Contains(out, "tun")
		if err == nil && !exists { // gleichnamige Schnittstelle anderer Art (früher WireGuard o. Ä.)
			_, _ = sys.Run("ip", "link", "del", "dev", n)
		}
	}
	if !exists {
		if _, err := sys.Run("ip", "tuntap", "add", "dev", n, "mode", "tun", "user", user); err != nil {
			return fmt.Errorf("Tor-Schnittstelle anlegen: %w", err)
		}
	}
	for _, s := range [][]string{
		{"ip", "-4", "address", "replace", fmt.Sprintf("10.254.%d.1/32", e.Slot), "dev", n, "noprefixroute"},
		{"ip", "link", "set", "dev", n, "mtu", strconv.Itoa(torMTU), "up"},
		{"sysctl", "-qw", "net.ipv4.conf." + n + ".rp_filter=2"},
	} {
		if _, err := sys.Run(s[0], s[1:]...); err != nil {
			return err
		}
	}
	sig := hash(fmt.Sprintf("%s|%s|%d|%s|%s", conf, envf, e.Via, torUnitFile, t2sUnitFile))
	if env.Get("exits:cfg:"+n) != sig {
		if _, err := sys.Run("systemctl", "restart", "vpn-tor@"+n); err != nil {
			return fmt.Errorf("Tor starten: %w", err)
		}
		if _, err := sys.Run("systemctl", "restart", "vpn-t2s@"+n); err != nil {
			return fmt.Errorf("Tor-Schnittstelle starten: %w", err)
		}
		env.Set("exits:cfg:"+n, sig)
		env.Log("info", "Ausgang „"+e.Name+"“ (Tor) eingerichtet")
		return nil
	}
	for _, u := range []string{"vpn-tor@" + n, "vpn-t2s@" + n} {
		if _, err := sys.Run("systemctl", "is-active", "--quiet", u); err != nil {
			_, _ = sys.Run("systemctl", "restart", u)
		}
	}
	return nil
}

// stopTor: Dienste anhalten und Schnittstelle entfernen (Einstellungen bleiben).
func stopTor(env *Env, n string) {
	_, _ = env.Sys.Run("systemctl", "stop", "vpn-t2s@"+n, "vpn-tor@"+n)
	_, _ = env.Sys.Run("ip", "link", "del", "dev", n)
}

// removeTor: Tor-Ausgang ganz entfernen.
func removeTor(env *Env, n string) {
	stopTor(env, n)
	for _, f := range []string{".torrc", ".env", ".via"} {
		_ = env.Sys.Remove(torDir + "/" + n + f)
		_ = env.Sys.Remove(torOldDir + "/" + n + f)
	}
	if !env.Sys.DryRun() {
		_, _ = env.Sys.Run("rm", "-rf", "--", torStateDir+"/"+n)
		_, _ = env.Sys.Run("userdel", torUser(n))
	}
}

// syncTorRules: Routing-Regeln der Tor-Kaskaden (Weg über den Vorgänger, dahinter die Sperre;
// IPv6 nur Sperre). Fremde Regeln im eigenen Bereich werden entfernt, richtige nicht angefasst.
func (m *Manager) syncTorRules(env *Env) error {
	m.mu.Lock()
	byID := map[int64]*Exit{}
	for _, x := range m.lastExits {
		byID[x.ID] = x
	}
	var list []*Exit
	for _, x := range m.lastExits {
		if x.Type == "tor" && x.Enabled && x.Slot > 0 && x.Via != 0 {
			list = append(list, x)
		}
	}
	m.mu.Unlock()
	sys := env.Sys
	var errs []string
	want4, want6 := map[int]string{}, map[int]string{}
	for _, x := range list {
		uid, err := ensureTorUser(env, x)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		block := fmt.Sprintf("uidrange %d-%d blackhole", uid, uid)
		want4[torBlockPrio+x.Slot], want6[torBlockPrio+x.Slot] = block, block
		if v := byID[x.Via]; v != nil && v.Enabled && v.Slot > 0 && v.Blocked == "" {
			want4[torRulePrio+x.Slot] = fmt.Sprintf("uidrange %d-%d lookup %d", uid, uid, probeTable+v.Slot)
		}
	}
	for _, fam := range []struct {
		f    string
		want map[int]string
	}{{"-4", want4}, {"-6", want6}} {
		have := map[int]string{}
		if !sys.DryRun() {
			out, err := sys.Run("ip", fam.f, "rule", "show")
			if err != nil {
				return fmt.Errorf("Routing-Regeln lesen: %s", strings.TrimSpace(out))
			}
			for _, l := range strings.Split(out, "\n") {
				p, rest, ok := strings.Cut(strings.TrimSpace(l), ":")
				n, err := strconv.Atoi(p)
				if !ok || err != nil || n < torRulePrio || n >= torBlockPrio+100 {
					continue
				}
				have[n] = strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(rest), "from all ")), " ")
			}
		}
		prios := make([]int, 0, len(fam.want))
		for p := range fam.want {
			prios = append(prios, p)
		}
		// Sperren zuerst (höhere Nummer): nie ein Augenblick mit Weg, aber ohne Sperre dahinter
		sort.Sort(sort.Reverse(sort.IntSlice(prios)))
		for _, p := range prios {
			if have[p] == fam.want[p] {
				continue
			}
			if _, ok := have[p]; ok {
				_, _ = sys.Run("ip", fam.f, "rule", "del", "priority", strconv.Itoa(p))
			}
			args := append([]string{fam.f, "rule", "add", "priority", strconv.Itoa(p)}, strings.Fields(fam.want[p])...)
			if out, err := sys.Run("ip", args...); err != nil {
				errs = append(errs, "Routing-Regel "+strconv.Itoa(p)+": "+strings.TrimSpace(out))
			}
		}
		for p := range have {
			if _, ok := fam.want[p]; !ok {
				_, _ = sys.Run("ip", fam.f, "rule", "del", "priority", strconv.Itoa(p))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Tor-Kaskade: %s", strings.Join(errs, "; "))
	}
	return nil
}

// torControl meldet sich an der Steuerung der Instanz an (Cookie) und schickt die Befehle der Reihe
// nach. Ergebnis: die Datenzeilen aller Antworten („250-…“ bzw. „250 …“ ohne „OK“).
func torControl(env *Env, e *Exit, cmds ...string) ([]string, error) {
	n := IfName(e.ID)
	cookie, err := env.Sys.ReadFile(torStateDir + "/" + n + "/control_auth_cookie")
	if err != nil {
		return nil, fmt.Errorf("Tor läuft nicht (Cookie fehlt)")
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", torCtlBase+e.Slot), 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("Tor-Steuerung nicht erreichbar")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	var data []string
	send := func(s string, keep bool) error {
		if _, err := fmt.Fprintf(c, "%s\r\n", s); err != nil {
			return err
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			line = strings.TrimRight(line, "\r\n")
			if !strings.HasPrefix(line, "250") || len(line) < 4 {
				return fmt.Errorf("Tor: %s", line)
			}
			if body := line[4:]; keep && body != "OK" {
				data = append(data, body)
			}
			if line[3] == ' ' { // letzte Zeile der Antwort
				return nil
			}
		}
	}
	if err := send("AUTHENTICATE "+hex.EncodeToString(cookie), false); err != nil {
		return nil, err
	}
	for _, cmd := range cmds {
		if err := send(cmd, true); err != nil {
			return data, err
		}
	}
	_, _ = fmt.Fprintf(c, "QUIT\r\n")
	return data, nil
}

// NewIdentity: Tor-Ausgang wechselt für neue Verbindungen auf neue Kreise (SIGNAL NEWNYM).
func (m *Manager) NewIdentity(env *Env, e *Exit) error {
	if e == nil || e.Type != "tor" {
		return fmt.Errorf("kein Tor-Ausgang")
	}
	if env.Sys.DryRun() {
		env.Log("info", "Ausgang „"+e.Name+"“: neue Tor-Identität (Testmodus)")
		return nil
	}
	if _, err := torControl(env, e, "SIGNAL NEWNYM"); err != nil {
		return err
	}
	env.Log("info", "Ausgang „"+e.Name+"“: neue Tor-Identität")
	return nil
}

// torCountry: Land einer Adresse laut Tors eigener GeoIP-Liste (Cloudflare meldet für
// Tor-Ausgänge nur „T1“). "" = unbekannt.
func torCountry(env *Env, e *Exit, ip string) string {
	if net.ParseIP(ip) == nil {
		return ""
	}
	data, err := torControl(env, e, "GETINFO ip-to-country/"+ip)
	if err != nil {
		return ""
	}
	for _, l := range data {
		if _, cc, ok := strings.Cut(l, "="); ok && len(cc) == 2 && cc != "??" {
			return strings.ToUpper(cc)
		}
	}
	return ""
}

// torDiag beschreibt, woran ein Tor-Ausgang hängt (Dienst aus, letzte Meldung, Bootstrap-Stand).
func torDiag(env *Env, n string) string {
	sys := env.Sys
	for _, u := range []struct{ unit, name string }{{"vpn-tor@" + n, "Tor"}, {"vpn-t2s@" + n, "Tor-Schnittstelle"}} {
		if _, err := sys.Run("systemctl", "is-active", "--quiet", u.unit); err != nil {
			out, _ := sys.Run("journalctl", "-u", u.unit, "-n", "30", "-o", "cat", "--no-pager")
			return u.name + " läuft nicht" + lastMsg(out, "")
		}
	}
	out, _ := sys.Run("journalctl", "-u", "vpn-tor@"+n, "-n", "200", "-o", "cat", "--no-pager")
	if m := lastMsg(out, "Bootstrapped "); m != "" {
		return "Tor" + m
	}
	return "Tor" + lastMsg(out, "")
}

// lastMsg: letzte (passende) Zeile eines Journals, gekürzt, als „: …“.
func lastMsg(out, want string) string {
	ls := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(ls) - 1; i >= 0; i-- {
		l := strings.TrimSpace(ls[i])
		if l == "" || (want != "" && !strings.Contains(l, want)) {
			continue
		}
		if want != "" {
			l = l[strings.Index(l, want):]
		} else if j := strings.Index(l, "] "); j >= 0 && j < 40 { // „… [notice] Text“
			l = l[j+2:]
		}
		if r := []rune(l); len(r) > 160 {
			l = string(r[:160]) + "…"
		}
		return ": " + l
	}
	return ""
}
