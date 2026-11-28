// Package engine verbindet Datenbank und Protokolltreiber: Limits auswerten,
// Konfigurationen anwenden, Statistik einsammeln, nginx-SNI-Verteiler erzeugen.
package engine

import (
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
	pkg      pkgState // Paket-Updates (pkgupdate.go)
	Exits    *exits.Manager
	liveKick chan struct{}

	lists     listState    // Online-Listen (lists.go)
	acl       aclState     // wirksame Sperr-/Freigabelisten (acl.go)
	rt        routeState   // Ziel-Regeln (routes.go)
	dns       dnsGate      // Panel-DNS bzw. DNS-Umleiter für Domain-Regeln (dns.go)
	dnsx      dnsExt       // DNS für Geräte ohne VPN (dnsext.go)
	smart     smartProxy   // SmartDNS-Proxy (smartproxy.go)
	dnsRate   extLimiter   // Begrenzung für DNS von außen über UDP (dnsrate.go)
	smartStat smartStats   // Statistik je SmartDNS-Profil (smartstats.go)
	enc       encDNS       // DoH/DoT mit Zertifikat (encdns.go)
	geo       geoState     // Länder zu Absender-Adressen (geo.go)
	ubg       ubGroupState // Unbound je Ausgangsgruppe (unbound_groups.go)
	blk       blockState   // Block-Prüfung je Ausgangsgruppe (blockcheck.go)

	dnsLists dnsListState // Blocklisten des Panel-DNS (dnsfilter.go)

	exitRates exitRateState // Durchsatz der Ausgänge (exits.go)
	notif     notifyState   // E-Mail-Benachrichtigungen (notify.go)
	host      hostSampler   // CPU/RAM/Durchsatz für die Seitenleiste (hoststats.go)
	alarm     alarmState    // Alarme (alarms.go)
	pts       pointState    // Wiederherstellungspunkte (points.go)
	self      selfUpdate    // Update aus dem Panel (selfupdate.go)
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
	"login_max_fails":     "8",   // Login-Sperre: Fehlversuche je Adresse …
	"login_window":        "15",  // … innerhalb dieser Minuten
	"login_lock":          "15",  // Sperrdauer in Minuten
	"login_lock_grow":     "1",   // Dauer bei Wiederholung innerhalb eines Tages verdoppeln (max. 24 h)
	"login_allow":         "",    // Adressen/Netze, die nie gesperrt werden
	"pkg_refresh":         "0",   // Paketlisten (apt-get update) täglich selbst aktualisieren
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
	"dns_ext_rate":        "20",       // DNS von außen über UDP: Anfragen je Sekunde und Absender, 0 = unbegrenzt
	"dns_ext_burst":       "60",       // … kurzzeitig bis zu so vielen
	"dns_ext_any":         "1",        // ANY-Anfragen von außen über UDP ablehnen
	"dns_smart_grant":     "1",        // SmartDNS-Proxy: wer per SmartDNS die Serveradresse bekam, darf ihn für diesen Namen nutzen
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
	"backup_auto":         "1", // täglich einen Wiederherstellungspunkt anlegen
	"backup_keep":         "7", // so viele tägliche Punkte behalten
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
