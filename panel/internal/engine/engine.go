// Package engine verbindet Datenbank und Protokolltreiber: Limits auswerten,
// Konfigurationen anwenden, Statistik einsammeln, nginx-SNI-Verteiler erzeugen.
package engine

import (
	"crypto/subtle"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

type Config struct {
	PanelBackend string // interne Adresse des Panels für nginx (z. B. 127.0.0.1:8480)
	DataDir      string
	LockPath     string
	HookAddr     string // interner HTTP-Listener für Dienste (z. B. 127.0.0.1:8479)
}

type Engine struct {
	St  *store.Store
	Sys system.Runner
	Cfg Config

	mu      sync.Mutex
	applyCh chan struct{}
	lastErr map[string]string
	errMu   sync.Mutex

	live     liveState
	upd      updateState
	Exits    *exits.Manager
	liveKick chan struct{}

	lists listState    // Online-Listen (lists.go)
	acl   aclState     // wirksame Sperr-/Freigabelisten (acl.go)
	rt    routeState   // Ziel-Regeln (routes.go)
	dns   dnsGate      // Panel-DNS bzw. DNS-Umleiter für Domain-Regeln (dns.go)
	dnsx  dnsExt       // DNS für Geräte ohne VPN (dnsext.go)
	smart smartProxy   // SmartDNS-Proxy (smartproxy.go)
	enc   encDNS       // DoH/DoT mit Zertifikat (encdns.go)
	geo   geoState     // Länder zu Absender-Adressen (geo.go)
	ubg   ubGroupState // Unbound je Ausgangsgruppe (unbound_groups.go)

	dnsLists dnsListState // Blocklisten des Panel-DNS (dnsfilter.go)

	exitRates exitRateState // Durchsatz der Ausgänge (exits.go)
	notif     notifyState   // E-Mail-Benachrichtigungen (notify.go)
	host      hostSampler   // CPU/RAM/Durchsatz für die Seitenleiste (hoststats.go)
}

func New(st *store.Store, sys system.Runner, cfg Config) *Engine {
	return &Engine{St: st, Sys: sys, Cfg: cfg, applyCh: make(chan struct{}, 1), lastErr: map[string]string{},
		liveKick: make(chan struct{}, 1), Exits: exits.New()}
}

// ---------- Einstellungen ----------

var settingDefaults = map[string]string{
	"server_host":         "", // Domain oder IP, die in allen Links und Configs steht (fragt vpn-setup.sh ab)
	"panel_host":          "", // leer = Webinterface nur direkt per IP:Port
	"sub_host":            "", // leer = Abo-Links über die Panel-Domain bzw. direkt per IP:Port
	"out_interface":       "eth0",
	"xray_api":            "127.0.0.1:10085",
	"collect_interval":    "60",
	"profile_title":       "VPN",
	"sub_update_interval": "12",
	"traffic_retention":   "180",
	"public_port":         "443",
	"trust_cloudflare":    "1",
	"session_hours":       "168",
	"update_check":        "1",   // 0 = nicht bei GitHub nach neuen Versionen fragen
	"exit_speedtest":      "360", // Minuten zwischen Geschwindigkeitstests der Ausgänge, 0 = aus
	"dns_enabled":         "1",   // Panel-DNS für WireGuard-/OpenVPN-Geräte
	"dns_upstream":        "1.1.1.1, 9.9.9.9",
	"dns_log_days":        "7",        // Aufbewahrung des DNS-Protokolls in Tagen, 0 = nicht protokollieren
	"private_block":       "1",        // VPN-Nutzer erreichen keine privaten Netze / den Server selbst
	"private_allow":       "",         // Ausnahmen (Netze, eins pro Zeile)
	"dns_cache_size":      "50000",    // Antworten im Zwischenspeicher, 0 = aus
	"dns_ttl_min":         "0",        // Antworten mindestens so lange merken (Sekunden)
	"dns_ttl_max":         "86400",    // höchstens so lange merken (Sekunden)
	"dns_nocache":         "",         // Domains, die nie zwischengespeichert werden
	"dns_strategy":        "order",    // order | fastest | roundrobin | parallel
	"dns_public":          "0",        // Port 53 von außen (nur freigegebene Absender)
	"dns_resolver":        "upstream", // upstream (öffentliche DNS-Server) | unbound (selbst auflösen)
	"dns_candidates":      "",         // Server für Speedtest/automatische Wahl, leer = eingebaute Liste
	"dns_auto":            "0",        // schnellste DNS-Server regelmäßig selbst wählen
	"dns_auto_hours":      "24",
	"dns_auto_count":      "2",
	"dns_tls":             "0",   // DoH/DoT für Geräte ohne VPN
	"dns_tls_host":        "",    // z. B. dns.example.org (Cloudflare „Nur DNS“), Kennungen als Unterdomains
	"dns_dot_port":        "853", // DoT
	"dns_acme_email":      "",    // optional: Kontakt bei Let's Encrypt
	"mail_enabled":        "0",   // Benachrichtigungen per E-Mail
	"smtp_host":           "",    // Mailserver, Passwort nur in secrets.env (SMTP_PASSWORD)
	"smtp_port":           "587",
	"smtp_security":       "starttls", // starttls | tls | none
	"smtp_user":           "",
	"mail_from":           "",
	"notify_events":       "exit,unbound,cert,update,error,lockout,backup",
}

func (e *Engine) Setting(k string) string { return e.St.GetSetting(k, settingDefaults[k]) }

func (e *Engine) Settings() map[string]string {
	m := map[string]string{}
	for k, v := range settingDefaults {
		m[k] = v
	}
	all, _ := e.St.AllSettings()
	for k, v := range all {
		if !strings.HasPrefix(k, "state:") {
			m[k] = v
		}
	}
	return m
}

func SettingKeys() []string {
	var k []string
	for key := range settingDefaults {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

func (e *Engine) Global() proto.Global {
	hook := ""
	if e.Cfg.HookAddr != "" {
		hook = "http://" + e.Cfg.HookAddr + "/hook"
	}
	rt := e.routing()
	return proto.Global{ServerHost: e.Setting("server_host"), OutIf: e.Setting("out_interface"), XrayAPI: e.Setting("xray_api"),
		DataDir: e.Cfg.DataDir, HookURL: hook, PublicPort: atoi(e.Setting("public_port"), 443), Groups: e.groupRoutes(), ACLs: e.acls(),
		Policies: rt.Policies, ServerPolicies: rt.ServerPolicies, TargetLists: rt.TargetLists, PanelDNS: e.Setting("dns_enabled") == "1", Net: rt.Net, Private: rt.Private}
}

func (e *Engine) Env() *proto.Env {
	return &proto.Env{
		Sys:      e.Sys,
		Global:   e.Global(),
		Log:      e.Log,
		GetState: func(k string) string { return e.St.GetSetting("state:"+k, "") },
		SetState: func(k, v string) { _ = e.St.SetSetting("state:"+k, v) },
		Shape:    &shaping.Plan{},
	}
}

func (e *Engine) Log(level, msg string) {
	log.Printf("[%s] %s", level, msg)
	e.St.AddEvent(level, msg)
	e.notifyLogged(level, msg)
}

// ---------- Zusammenstellen ----------

type Snapshot struct {
	Servers []*proto.ServerBundle
	Users   map[int64]*store.User
	Plans   map[int64]*store.Plan
	ByProto map[string][]*proto.ServerBundle
	Peers   map[int64]*proto.PeerBundle
	Verdict map[int64]Verdict
}

func (e *Engine) Snapshot() (*Snapshot, error) {
	servers, err := e.St.Servers()
	if err != nil {
		return nil, err
	}
	users, err := e.St.Users()
	if err != nil {
		return nil, err
	}
	plans, err := e.St.Plans()
	if err != nil {
		return nil, err
	}
	peers, err := e.St.Peers()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Users: map[int64]*store.User{}, Plans: map[int64]*store.Plan{}, ByProto: map[string][]*proto.ServerBundle{},
		Peers: map[int64]*proto.PeerBundle{}, Verdict: map[int64]Verdict{}}
	for _, p := range plans {
		s.Plans[p.ID] = p
	}
	now := time.Now()
	for _, u := range users {
		s.Users[u.ID] = u
		s.Verdict[u.ID] = Evaluate(u, EffectiveLimits(u, s.Plans), now)
	}
	sb := map[int64]*proto.ServerBundle{}
	for _, sv := range servers {
		b := &proto.ServerBundle{Server: sv}
		sb[sv.ID] = b
		s.Servers = append(s.Servers, b)
		s.ByProto[sv.Protocol] = append(s.ByProto[sv.Protocol], b)
	}
	for _, p := range peers {
		u := s.Users[p.UserID]
		b := sb[p.ServerID]
		if u == nil || b == nil {
			continue
		}
		v := s.Verdict[u.ID]
		pb := &proto.PeerBundle{Peer: p, User: u, Active: v.Active() && p.Enabled && b.Server.Enabled, RateDown: v.RateDown, RateUp: v.RateUp}
		b.Peers = append(b.Peers, pb)
		s.Peers[p.ID] = pb
	}
	return s, nil
}

// ---------- Anwenden ----------

// RequestApply plant ein Anwenden im Hintergrund (Änderungen aus der Oberfläche werden gebündelt).
func (e *Engine) RequestApply() {
	select {
	case e.applyCh <- struct{}{}:
	default:
	}
}

func (e *Engine) Apply() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	unlock, err := lockFile(e.Cfg.LockPath)
	if err != nil {
		return err
	}
	defer unlock()
	return e.applyLocked()
}

func (e *Engine) applyLocked() error {
	// vor dem Neuschreiben Zähler sichern (Xray-Neustart setzt sie zurück)
	if err := e.collectLocked(); err != nil {
		log.Printf("collect vor apply: %v", err)
	}
	snap, err := e.Snapshot()
	if err != nil {
		return err
	}
	e.saveVerdicts(snap)
	e.live.mu.Lock()
	e.live.snap = nil // Live-Anzeige: Namen/Zugänge neu laden
	e.live.mu.Unlock()
	var errs []string
	if err := e.applyExits(); err != nil {
		errs = append(errs, "Ausgänge: "+err.Error())
	}
	e.pruneRoutes(snap)
	rt := e.compileRoutes(snap)
	env := e.Env()
	for _, d := range proto.All() {
		id := d.Info().ID
		if err := d.Apply(env, snap.ByProto[id]); err != nil {
			errs = append(errs, d.Info().Label+": "+err.Error())
			e.setErr(id, err.Error())
		} else {
			e.setErr(id, "")
		}
	}
	e.applyUnbound()
	if err := e.applyNft(env, snap, rt, e.aclPlan()); err != nil {
		errs = append(errs, "Firewall (IP-Listen, Ziel-Regeln): "+err.Error())
		e.setErr("acl", err.Error())
		e.stopUBInstances(err.Error())
	} else {
		e.setErr("acl", "")
		e.startUBInstances()
	}
	if err := shaping.Apply(e.Sys, env.Global.OutIf, env.Shape, env.GetState, env.SetState, e.Log); err != nil {
		e.Log("warn", "Geschwindigkeitsbegrenzung: "+err.Error())
		e.setErr("shaping", err.Error())
	} else {
		e.setErr("shaping", "")
	}
	e.applySmart(e.SmartDomains())
	e.applyEncDNS()
	if err := e.applyNginx(snap); err != nil {
		errs = append(errs, "nginx: "+err.Error())
		e.setErr("nginx", err.Error())
	} else {
		e.setErr("nginx", "")
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		e.Log("error", "Anwenden fehlgeschlagen: "+msg)
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (e *Engine) setErr(k, v string) {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if v == "" {
		delete(e.lastErr, k)
	} else {
		e.lastErr[k] = v
	}
}

func (e *Engine) Errors() map[string]string {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	m := map[string]string{}
	for k, v := range e.lastErr {
		m[k] = v
	}
	return m
}

// saveVerdicts schreibt Status-Änderungen und protokolliert sie.
func (e *Engine) saveVerdicts(snap *Snapshot) bool {
	changed := false
	for id, v := range snap.Verdict {
		u := snap.Users[id]
		if u.Status != v.Status || u.RateDown != v.RateDown || u.RateUp != v.RateUp || u.StatusReason != v.Reason {
			if u.Status != v.Status {
				e.Log("info", fmt.Sprintf("Nutzer %s: %s → %s %s", u.Name, statusLabel(u.Status), statusLabel(v.Status), v.Reason))
			}
			u.Status, u.StatusReason, u.RateDown, u.RateUp = v.Status, v.Reason, v.RateDown, v.RateUp
			_ = e.St.SaveUser(u)
			changed = true
		}
	}
	return changed
}

func statusLabel(s string) string {
	return map[string]string{"ok": "aktiv", "throttled": "gedrosselt", "blocked": "gesperrt", "disabled": "deaktiviert", "expired": "abgelaufen"}[s]
}

// ---------- nginx SNI-Verteiler ----------

const nginxStream = "/etc/nginx/stream.d/vpn.conf"

func (e *Engine) applyNginx(snap *Snapshot) error {
	if !e.Sys.Exists("/etc/nginx/nginx.conf") && !e.Sys.DryRun() {
		return nil
	}
	routes := map[int][]proto.SNIRoute{}
	defaults := map[int]string{}
	pub := atoi(e.Setting("public_port"), 443)
	for _, h := range []string{e.Setting("panel_host"), e.Setting("sub_host")} {
		if h != "" {
			routes[pub] = append(routes[pub], proto.SNIRoute{Port: pub, SNI: h, Backend: e.Cfg.PanelBackend})
		}
	}
	for _, d := range proto.All() {
		r, ok := d.(proto.SNIRouter)
		if !ok {
			continue
		}
		for _, rt := range r.SNIRoutes(snap.ByProto[d.Info().ID]) {
			if rt.SNI == "" {
				if _, ok := defaults[rt.Port]; !ok {
					defaults[rt.Port] = rt.Backend
				}
				continue
			}
			routes[rt.Port] = append(routes[rt.Port], rt)
		}
	}
	if _, ok := defaults[pub]; !ok {
		defaults[pub] = e.Cfg.PanelBackend
	}
	// Verschlüsseltes DNS (DoH) und SmartDNS: Namen samt Unterdomains („.name“ in nginx)
	wild := map[int][]proto.SNIRoute{}
	if h := e.encDNSHost(); h != "" && e.encDNSOn() {
		wild[pub] = append(wild[pub], proto.SNIRoute{Port: pub, SNI: "." + h, Backend: dohAddr})
	}
	exact := map[string]bool{}
	for _, r := range routes[pub] {
		exact[r.SNI] = true
	}
	for _, d := range e.smartNginxNames() {
		if exact[d] || d == e.encDNSHost() {
			continue
		}
		wild[pub] = append(wild[pub], proto.SNIRoute{Port: pub, SNI: "." + d, Backend: smartAddr})
	}
	var ports []int
	for p := range defaults {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var b strings.Builder
	b.WriteString("# Vom VPN-Panel erzeugt – Änderungen werden überschrieben.\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "\nmap $ssl_preread_server_name $vpn_backend_%d {\n", p)
		if len(wild[p]) > 0 {
			b.WriteString("    hostnames;\n")
		}
		seen := map[string]bool{}
		for _, r := range routes[p] {
			if seen[r.SNI] {
				continue
			}
			seen[r.SNI] = true
			fmt.Fprintf(&b, "    %s %s;\n", r.SNI, r.Backend)
		}
		for _, r := range wild[p] {
			if seen[r.SNI] {
				continue
			}
			seen[r.SNI] = true
			fmt.Fprintf(&b, "    %s %s;\n", r.SNI, r.Backend)
		}
		fmt.Fprintf(&b, "    default %s;\n}\n\nserver {\n    listen %d;\n    listen [::]:%d;\n    ssl_preread on;\n    proxy_pass $vpn_backend_%d;\n    proxy_protocol on;\n    proxy_connect_timeout 5s;\n}\n", defaults[p], p, p, p)
	}
	data := []byte(b.String())
	old, _ := e.Sys.ReadFile(nginxStream)
	legacy := e.Sys.Exists("/etc/nginx/stream.d/vless.conf")
	if string(old) == string(data) && !legacy {
		return nil
	}
	if _, err := e.Sys.WriteFile(nginxStream, data, 0o644); err != nil {
		return err
	}
	_ = e.Sys.Remove("/etc/nginx/stream.d/vless.conf")
	if _, err := e.Sys.Run("nginx", "-t"); err != nil {
		if len(old) > 0 {
			_, _ = e.Sys.WriteFile(nginxStream, old, 0o644)
		}
		return err
	}
	if _, err := e.Sys.Run("systemctl", "reload-or-restart", "nginx"); err != nil {
		return err
	}
	e.Log("info", "nginx-SNI-Verteiler aktualisiert")
	return nil
}

func atoi(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def
	}
	return n
}

// ---------- Statistik ----------

func (e *Engine) Collect() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	unlock, err := lockFile(e.Cfg.LockPath)
	if err != nil {
		return err
	}
	defer unlock()
	if err := e.collectLocked(); err != nil {
		return err
	}
	// Hat sich durch den Verbrauch ein Status geändert (Limit, Drosselstufe, Ablauf)? → anwenden
	snap, err := e.Snapshot()
	if err != nil {
		return err
	}
	if e.saveVerdicts(snap) {
		return e.applyLocked()
	}
	return nil
}

func (e *Engine) collectLocked() error {
	snap, err := e.Snapshot()
	if err != nil {
		return err
	}
	env := e.Env()
	now := time.Now()
	ts := now.Unix()
	userDelta := map[int64][2]int64{}
	userSeen := map[int64]int64{}
	for _, d := range proto.All() {
		id := d.Info().ID
		bundles := snap.ByProto[id]
		if len(bundles) == 0 {
			continue
		}
		usage, err := d.Collect(env, bundles)
		if err != nil {
			e.setErr("collect:"+id, err.Error())
			continue
		}
		e.setErr("collect:"+id, "")
		for _, sb := range bundles {
			for _, pb := range sb.Peers {
				p := pb.Peer
				u, ok := usage[p.ID]
				if ok {
					p.TotalUp += u.Up
					p.TotalDown += u.Down
					if u.Seen > p.LastSeen {
						p.LastSeen = u.Seen
					}
					if u.Handshake > 0 {
						p.Handshake = u.Handshake
					}
					if u.Endpoint != "" {
						p.Endpoint = u.Endpoint
					}
					if u.Up+u.Down > 0 {
						_ = e.St.AddTraffic(p.ID, p.UserID, p.ServerID, ts, u.Up, u.Down)
						d := userDelta[p.UserID]
						userDelta[p.UserID] = [2]int64{d[0] + u.Up, d[1] + u.Down}
					}
					if p.LastSeen > userSeen[p.UserID] {
						userSeen[p.UserID] = p.LastSeen
					}
				}
				_ = e.St.SavePeer(p) // auch Rohzähler (LastRx/LastTx) sichern
			}
		}
	}
	e.collectExitTraffic(ts)
	// Nutzer: Zeitraum prüfen, Verbrauch addieren
	for id, u := range snap.Users {
		changed := false
		l := EffectiveLimits(u, snap.Plans)
		if ps := PeriodStart(l, now); ps > 0 && u.PeriodStart < ps {
			if u.PeriodUp+u.PeriodDown > 0 {
				e.Log("info", fmt.Sprintf("Nutzer %s: neuer Abrechnungszeitraum, Verbrauch zurückgesetzt", u.Name))
			}
			u.PeriodStart, u.PeriodUp, u.PeriodDown = ps, 0, 0
			changed = true
		}
		if d, ok := userDelta[id]; ok {
			u.PeriodUp += d[0]
			u.PeriodDown += d[1]
			u.TotalUp += d[0]
			u.TotalDown += d[1]
			changed = true
		}
		if s := userSeen[id]; s > u.LastSeen {
			u.LastSeen = s
			changed = true
		}
		if changed {
			_ = e.St.SaveUser(u)
		}
	}
	return nil
}

// Run: Hintergrundschleife für Statistik und gebündeltes Anwenden.
func (e *Engine) Run(stop <-chan struct{}) {
	interval := time.Duration(atoi(e.Setting("collect_interval"), 60)) * time.Second
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-stop:
			if err := e.Collect(); err != nil {
				log.Printf("collect beim Beenden: %v", err)
			}
			return
		case <-tick.C:
			if err := e.Collect(); err != nil {
				log.Printf("collect: %v", err)
			}
		case <-e.applyCh:
			time.Sleep(700 * time.Millisecond) // weitere Änderungen bündeln
			select {
			case <-e.applyCh:
			default:
			}
			_ = e.Apply()
		case <-prune.C:
			days := atoi(e.Setting("traffic_retention"), 180)
			_ = e.St.PruneTraffic(time.Now().AddDate(0, 0, -days).Unix())
			e.St.PruneSessions()
		}
	}
}

// ---------- Abfragen für Oberfläche und Abo ----------

func (e *Engine) ClientConfig(peerID int64) (*proto.ClientConfig, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return nil, err
	}
	pb := snap.Peers[peerID]
	if pb == nil {
		return nil, store.ErrNotFound
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID == pb.Peer.ServerID {
			d, ok := proto.Get(sb.Server.Protocol)
			if !ok {
				return nil, fmt.Errorf("Protokoll %s unbekannt", sb.Server.Protocol)
			}
			return d.ClientConfig(e.Env(), sb, pb)
		}
	}
	return nil, store.ErrNotFound
}

// OpenVPNProfile: .ovpn-Datei eines aktiven OpenVPN-Zugangs, der dem Nutzer gehört.
func (e *Engine) OpenVPNProfile(userID, peerID int64) (name, body string, err error) {
	snap, err := e.Snapshot()
	if err != nil {
		return "", "", err
	}
	pb := snap.Peers[peerID]
	if pb == nil || pb.User.ID != userID || !pb.Active {
		return "", "", store.ErrNotFound
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID == pb.Peer.ServerID && sb.Server.Protocol == "openvpn" {
			d, _ := proto.Get("openvpn")
			cc, err := d.ClientConfig(e.Env(), sb, pb)
			if err != nil || len(cc.Files) == 0 {
				return "", "", store.ErrNotFound
			}
			return cc.Files[0].Name, cc.Files[0].Content, nil
		}
	}
	return "", "", store.ErrNotFound
}

// SubLinks: alle Links eines Nutzers für das Abo.
func (e *Engine) SubLinks(userID int64) ([]string, error) { return e.SubLinksFor(userID, "") }

// SubLinksFor: Links für eine bestimmte App-Familie (siehe proto.Global.Client).
func (e *Engine) SubLinksFor(userID int64, client string) ([]string, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return nil, err
	}
	env := e.Env()
	env.Global.Client = client
	var out []string
	for _, sb := range snap.Servers {
		if !sb.Server.Enabled {
			continue
		}
		d, ok := proto.Get(sb.Server.Protocol)
		if !ok {
			continue
		}
		for _, pb := range sb.Peers {
			if pb.Peer.UserID == userID && pb.Peer.Enabled {
				out = append(out, d.ShareLinks(env, sb, pb)...)
			}
		}
	}
	return out, nil
}

// Hook beantwortet interne Anfragen eines Dienstes (z. B. Hysteria2-Anmeldung).
func (e *Engine) Hook(serverID int64, secret string, body []byte) (any, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return nil, err
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID != serverID {
			continue
		}
		want := proto.Str(sb.Server.State, "hook_secret")
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(secret)) != 1 {
			return nil, store.ErrNotFound
		}
		d, ok := proto.Get(sb.Server.Protocol)
		h, ok2 := d.(proto.Hooker)
		if !ok || !ok2 {
			return nil, store.ErrNotFound
		}
		resp, reshape, err := h.Hook(e.Env(), sb, body)
		if reshape {
			e.RequestApply()
		}
		return resp, err
	}
	return nil, store.ErrNotFound
}

// InitServer setzt Vorgaben über den Treiber.
func (e *Engine) InitServer(sv *store.Server) error {
	d, ok := proto.Get(sv.Protocol)
	if !ok {
		return fmt.Errorf("unbekanntes Protokoll %q", sv.Protocol)
	}
	all, err := e.St.Servers()
	if err != nil {
		return err
	}
	if sv.Settings == nil {
		sv.Settings = store.M{}
	}
	if sv.State == nil {
		sv.State = store.M{}
	}
	return d.InitServer(e.Env(), sv, all)
}

func (e *Engine) InitPeer(sv *store.Server, p *store.Peer) error {
	d, ok := proto.Get(sv.Protocol)
	if !ok {
		return fmt.Errorf("unbekanntes Protokoll %q", sv.Protocol)
	}
	others, err := e.St.PeersOfServer(sv.ID)
	if err != nil {
		return err
	}
	if p.Settings == nil {
		p.Settings = store.M{}
	}
	if p.Secrets == nil {
		p.Secrets = store.M{}
	}
	return d.InitPeer(e.Env(), sv, p, others)
}
