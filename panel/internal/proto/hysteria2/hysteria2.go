// Package hysteria2: Hysteria2 (QUIC über UDP). Pro Server läuft eine eigene Instanz
// (systemd-Vorlage vpn-hysteria@hy<ID>). Die Anmeldung fragt das Panel per HTTP – so kennt
// das Panel die Client-Adressen (für die Drosselung) und kann gesperrte Nutzer sofort abweisen.
// Verbrauch und Online-Status kommen über die trafficStats-API der Instanz.
package hysteria2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
)

const (
	confDir   = "/etc/hysteria"
	unitPath  = "/etc/systemd/system/vpn-hysteria@.service"
	statsBase = 25400 // trafficStats auf 127.0.0.1:25400+Server-ID
	binPath   = "/usr/local/bin/hysteria"
)

const unitFile = `# Vom VPN-Panel erzeugt – eine Hysteria2-Instanz pro Server (/etc/hysteria/<name>.yaml)
[Unit]
Description=Hysteria2 (VPN-Panel) %i
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/hysteria server --disable-update-check --config /etc/hysteria/%i.yaml
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/hysteria
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`

type serverCfg struct {
	Port                  int     `json:"port"`
	SNI                   string  `json:"sni"`
	Masquerade            string  `json:"masquerade"`
	Obfs                  bool    `json:"obfs"`
	BandwidthDown         float64 `json:"bandwidth_down"`
	BandwidthUp           float64 `json:"bandwidth_up"`
	IgnoreClientBandwidth bool    `json:"ignore_client_bandwidth"`
	Host                  string  `json:"host"`
	CertFile              string  `json:"cert_file"`
	KeyFile               string  `json:"key_file"`
	Shaping               bool    `json:"shaping"`
	IdleTimeout           int     `json:"idle_timeout"`
	DisableMTUDiscovery   bool    `json:"disable_mtu_discovery"`
	HopPorts              string  `json:"hop_ports"`    // z. B. „20000-50000“, leer = aus
	HopInterval           int     `json:"hop_interval"` // Sekunden, wie oft der Client den Port wechselt
}

func defaults() serverCfg {
	return serverCfg{Port: 443, Masquerade: "https://www.bing.com", IgnoreClientBandwidth: true, Shaping: true, IdleTimeout: 60, HopInterval: 30}
}

func load(srv *store.Server) serverCfg {
	c := defaults()
	_ = proto.Decode(srv.Settings, &c)
	return c
}

type Driver struct{}

func init() { proto.Register(Driver{}) }

func (Driver) Info() proto.Info {
	return proto.Info{
		ID:          "hysteria2",
		Label:       "Hysteria2",
		Description: "Schnelles Protokoll über QUIC/UDP – sieht aus wie HTTP/3. Sehr gut bei schlechten oder weit entfernten Verbindungen.",
		ServerFields: []proto.Field{
			{Key: "port", Label: "UDP-Port", Type: "number", Default: 443,
				Help: "Muss auf dem Proxmox-Host per UDP an den Container weitergeleitet werden. 443 sieht am unauffälligsten aus (HTTP/3)."},
			{Key: "sni", Label: "Servername (SNI)", Type: "text", Advanced: true, Placeholder: "Server-Domain aus den Einstellungen",
				Help: "Steht im selbst erzeugten Zertifikat und in den Links."},
			{Key: "masquerade", Label: "Tarnung (Webseite)", Type: "text", Default: "https://www.bing.com", Advanced: true,
				Help: "Wer den Server ohne Zugang per HTTP/3 aufruft, sieht diese Webseite. Leer = Fehlerseite."},
			{Key: "obfs", Label: "Verschleierung (Salamander)", Type: "bool", Default: false, Advanced: true,
				Help: "Verschleiert auch das QUIC selbst. Hilft gegen strenge Sperren, sieht dann aber nicht mehr wie HTTP/3 aus. Nicht jede App kann das."},
			{Key: "bandwidth_down", Label: "Max. Download pro Verbindung (Mbit/s)", Type: "number", Default: 0, Advanced: true, Help: "0 = unbegrenzt"},
			{Key: "bandwidth_up", Label: "Max. Upload pro Verbindung (Mbit/s)", Type: "number", Default: 0, Advanced: true, Help: "0 = unbegrenzt"},
			{Key: "ignore_client_bandwidth", Label: "Bandbreitenangabe der Clients ignorieren", Type: "bool", Default: true, Advanced: true,
				Help: "Nutzt BBR statt „Brutal“. Nötig, damit die Drosselung pro Nutzer sauber greift."},
			{Key: "shaping", Label: "Geschwindigkeitsbegrenzung", Type: "bool", Default: true, Advanced: true,
				Help: "Begrenzt Nutzer über ihre Client-Adresse und tc auf der ausgehenden Schnittstelle."},
			{Key: "hop_ports", Label: "Port-Hopping (UDP-Bereich)", Type: "text", Advanced: true, Placeholder: "aus – z. B. 20000-50000",
				Help: "Der Client wechselt regelmäßig den Zielport. Hilft, wenn Anbieter eine einzelne UDP-Verbindung drosseln oder kappen. Der Bereich muss auf dem Proxmox-Host per UDP an den Container weitergeleitet werden."},
			{Key: "hop_interval", Label: "Port-Wechsel alle (Sekunden)", Type: "number", Default: 30, Advanced: true,
				Help: "Nur für Clients, die das unterstützen (offizieller Client, sing-box/Hiddify)."},
			{Key: "idle_timeout", Label: "Leerlauf-Timeout (Sekunden)", Type: "number", Default: 60, Advanced: true,
				Help: "So lange hält der Server eine stille Verbindung offen (4–120). Höher = weniger Abbrüche bei Handys im Standby."},
			{Key: "disable_mtu_discovery", Label: "Paketgrößen-Erkennung aus", Type: "bool", Default: false, Advanced: true,
				Help: "Nur einschalten, wenn Verbindungen in manchen Mobilfunknetzen hängen bleiben (dann feste, kleine Pakete)."},
			{Key: "host", Label: "Adresse in den Links", Type: "text", Advanced: true, Placeholder: "Server-Domain aus den Einstellungen"},
			{Key: "cert_file", Label: "Eigenes Zertifikat (Pfad)", Type: "text", Advanced: true, Placeholder: "leer = selbst erzeugt",
				Help: "z. B. ein Let's-Encrypt-Zertifikat. Dann prüfen die Apps das Zertifikat normal (ohne „insecure“)."},
			{Key: "key_file", Label: "Eigener Schlüssel (Pfad)", Type: "text", Advanced: true},
		},
		Kinds: []proto.Kind{{ID: "access", Label: "Zugang", Icon: "key", Description: "Ein Hysteria2-Zugang (Passwort) mit Link für das Abo.", Defaults: store.M{}}},
	}
}

var (
	hostRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	pathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

func (Driver) InitServer(env *proto.Env, srv *store.Server, all []*store.Server) error {
	c := load(srv)
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("Port %d ungültig", c.Port)
	}
	for _, o := range all {
		if o.ID == srv.ID {
			continue
		}
		d, ok := proto.Get(o.Protocol)
		if !ok {
			continue
		}
		for _, p := range d.Ports(o) {
			if p.Proto != "udp" {
				continue
			}
			end := p.To
			if end == 0 {
				end = p.Port
			}
			if c.Port >= p.Port && c.Port <= end {
				return fmt.Errorf("UDP-Port %d wird schon von „%s“ verwendet", c.Port, o.Name)
			}
			if f, t, err := hopRange(c.HopPorts); err == nil && f > 0 && f <= end && t >= p.Port {
				return fmt.Errorf("Port-Hopping %d-%d überschneidet sich mit UDP %d von „%s“", f, t, p.Port, o.Name)
			}
		}
	}
	from, to, err := hopRange(c.HopPorts)
	if err != nil {
		return err
	}
	if from > 0 {
		c.HopPorts = fmt.Sprintf("%d-%d", from, to)
	} else {
		c.HopPorts = ""
	}
	if c.HopInterval == 0 {
		c.HopInterval = 30
	}
	if c.HopInterval < 5 || c.HopInterval > 3600 {
		return fmt.Errorf("Port-Wechsel %d ungültig (5–3600 Sekunden)", c.HopInterval)
	}
	c.SNI = strings.ToLower(strings.TrimSpace(c.SNI))
	c.Host = strings.TrimSpace(c.Host)
	for _, h := range []string{c.SNI, c.Host} {
		if h != "" && !hostRe.MatchString(h) {
			return fmt.Errorf("Name %q ungültig", h)
		}
	}
	c.Masquerade = strings.TrimSpace(c.Masquerade)
	if c.Masquerade != "" {
		u, err := url.Parse(c.Masquerade)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("Tarnung: bitte eine Adresse wie https://www.bing.com")
		}
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("eigenes Zertifikat: Zertifikat und Schlüssel angeben")
	}
	for _, p := range []string{c.CertFile, c.KeyFile} {
		if p != "" && !pathRe.MatchString(p) {
			return fmt.Errorf("Pfad %q ungültig", p)
		}
	}
	if c.BandwidthDown < 0 || c.BandwidthUp < 0 {
		return fmt.Errorf("Bandbreite darf nicht negativ sein")
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 60
	}
	if c.IdleTimeout < 4 || c.IdleTimeout > 120 {
		return fmt.Errorf("Leerlauf-Timeout %d ungültig (4–120 Sekunden)", c.IdleTimeout)
	}
	srv.Settings = proto.Encode(c)

	for _, k := range []string{"hook_secret", "stats_secret", "obfs_password"} {
		if proto.Str(srv.State, k) == "" {
			srv.State[k] = proto.RandHex(16)
		}
	}
	sni := sniOf(env, c)
	if proto.Str(srv.State, "cert_pem") == "" || proto.Str(srv.State, "cert_name") != sni {
		certPEM, keyPEM, pin, err := selfSigned(sni)
		if err != nil {
			return err
		}
		srv.State["cert_pem"], srv.State["key_pem"], srv.State["cert_sha256"], srv.State["cert_name"] = certPEM, keyPEM, pin, sni
	}
	return nil
}

func sniOf(env *proto.Env, c serverCfg) string {
	if c.SNI != "" {
		return c.SNI
	}
	return env.Global.ServerHost
}

func linkHost(env *proto.Env, c serverCfg) string {
	if c.Host != "" {
		return c.Host
	}
	return env.Global.ServerHost
}

// selfSigned erzeugt ein ECDSA-Zertifikat (10 Jahre) und liefert den SHA-256 für pinSHA256.
func selfSigned(name string) (certPEM, keyPEM, pin string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})),
		strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func (Driver) InitPeer(env *proto.Env, srv *store.Server, p *store.Peer, others []*store.Peer) error {
	p.Kind = "access"
	if proto.Str(p.Secrets, "password") == "" {
		p.Secrets["password"] = proto.RandHex(16)
	}
	return nil
}

func name(srv *store.Server) string { return fmt.Sprintf("hy%d", srv.ID) }
func peerID(p *store.Peer) string   { return fmt.Sprintf("p%d", p.ID) }
func statsAddr(srv *store.Server) string {
	return fmt.Sprintf("127.0.0.1:%d", statsBase+srv.ID)
}

// ---------- Client-Adressen aus der Anmeldung ----------

type seenAddr struct {
	addr netip.Addr
	at   time.Time
}

var (
	addrMu sync.Mutex
	addrs  = map[int64][]seenAddr{} // Peer-ID → Adressen
)

func rememberAddr(id int64, a netip.Addr) (isNew bool) {
	addrMu.Lock()
	defer addrMu.Unlock()
	for i, s := range addrs[id] {
		if s.addr == a {
			addrs[id][i].at = time.Now()
			return false
		}
	}
	addrs[id] = append(addrs[id], seenAddr{a, time.Now()})
	return true
}

// lastAddr: zuletzt bei der Anmeldung gesehene Client-Adresse („“ = unbekannt, z. B. nach Panel-Neustart
// bis zur nächsten Anmeldung).
func lastAddr(id int64) string {
	addrMu.Lock()
	defer addrMu.Unlock()
	var best seenAddr
	for _, s := range addrs[id] {
		if s.at.After(best.at) {
			best = s
		}
	}
	if !best.addr.IsValid() {
		return ""
	}
	return best.addr.Unmap().String()
}

func addrsOf(id int64) []netip.Addr {
	addrMu.Lock()
	defer addrMu.Unlock()
	var out []netip.Addr
	for _, s := range addrs[id] {
		out = append(out, s.addr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// forget entfernt Adressen von Zugängen, die nicht mehr online sind (mit Schonfrist).
func forget(online map[int64]bool, ids []int64) bool {
	addrMu.Lock()
	defer addrMu.Unlock()
	changed := false
	for _, id := range ids {
		if online[id] {
			continue
		}
		var keep []seenAddr
		for _, s := range addrs[id] {
			if time.Since(s.at) < 3*time.Minute {
				keep = append(keep, s)
			}
		}
		if len(keep) != len(addrs[id]) {
			changed = true
		}
		if len(keep) == 0 {
			delete(addrs, id)
		} else {
			addrs[id] = keep
		}
	}
	return changed
}

// Hook: Anmeldung einer Hysteria2-Instanz (auth type http).
func (Driver) Hook(env *proto.Env, sb *proto.ServerBundle, body []byte) (any, bool, error) {
	var req struct {
		Addr string `json:"addr"`
		Auth string `json:"auth"`
	}
	deny := map[string]any{"ok": false, "id": ""}
	if err := json.Unmarshal(body, &req); err != nil || req.Auth == "" {
		return deny, false, nil
	}
	if !sb.Server.Enabled {
		return deny, false, nil
	}
	for _, pb := range sb.Peers {
		pw := proto.Str(pb.Peer.Secrets, "password")
		if pw == "" || subtle.ConstantTimeCompare([]byte(pw), []byte(req.Auth)) != 1 {
			continue
		}
		if !pb.Active {
			return deny, false, nil
		}
		reshape := false
		if ap, err := netip.ParseAddrPort(req.Addr); err == nil {
			isNew := rememberAddr(pb.Peer.ID, ap.Addr().Unmap())
			reshape = isNew && load(sb.Server).Shaping && (pb.RateDown > 0 || pb.RateUp > 0)
		}
		return map[string]any{"ok": true, "id": peerID(pb.Peer)}, reshape, nil
	}
	return deny, false, nil
}

// ---------- Anwenden ----------

func (d Driver) Apply(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	want := map[string]bool{}
	var errs []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		want[name(sb.Server)] = true
		if err := applyServer(env, sb); err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
		}
	}
	if err := applyHopping(env, servers); err != nil {
		errs = append(errs, "Port-Hopping: "+err.Error())
	}
	// Entfernte/deaktivierte Instanzen abbauen
	var prev []string
	_ = json.Unmarshal([]byte(env.GetState("hy:instances")), &prev)
	for _, n := range prev {
		if want[n] {
			continue
		}
		_, _ = sys.Run("systemctl", "disable", "--now", "vpn-hysteria@"+n)
		for _, ext := range []string{".yaml", ".crt", ".key"} {
			_ = sys.Remove(confDir + "/" + n + ext)
		}
		env.Log("info", "Hysteria2-Instanz "+n+" entfernt")
	}
	var now []string
	for n := range want {
		now = append(now, n)
	}
	sort.Strings(now)
	b, _ := json.Marshal(now)
	env.SetState("hy:instances", string(b))
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func bw(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) + " mbps" }

func applyServer(env *proto.Env, sb *proto.ServerBundle) error {
	sys := env.Sys
	srv := sb.Server
	c := load(srv)
	n := name(srv)
	if !sys.DryRun() && !sys.Exists(binPath) {
		return fmt.Errorf("Hysteria ist nicht installiert (%s fehlt – Setup-Script erneut ausführen)", binPath)
	}
	if env.Global.HookURL == "" {
		return fmt.Errorf("interner Anmelde-Endpunkt des Panels fehlt (Option -hook)")
	}
	changed := false
	if ch, err := sys.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	} else if ch {
		_, _ = sys.Run("systemctl", "daemon-reload")
	}
	certFile, keyFile := c.CertFile, c.KeyFile
	if certFile == "" {
		certFile, keyFile = confDir+"/"+n+".crt", confDir+"/"+n+".key"
		ch1, err := sys.WriteFile(certFile, []byte(proto.Str(srv.State, "cert_pem")), 0o644)
		if err != nil {
			return err
		}
		ch2, err := sys.WriteFile(keyFile, []byte(proto.Str(srv.State, "key_pem")), 0o600)
		if err != nil {
			return err
		}
		changed = changed || ch1 || ch2
	}
	cfg := map[string]any{
		"listen": fmt.Sprintf(":%d", c.Port),
		"tls":    map[string]any{"cert": certFile, "key": keyFile},
		"auth": map[string]any{"type": "http", "http": map[string]any{
			"url": fmt.Sprintf("%s/%d/%s", env.Global.HookURL, srv.ID, proto.Str(srv.State, "hook_secret"))}},
		"trafficStats":          map[string]any{"listen": statsAddr(srv), "secret": proto.Str(srv.State, "stats_secret")},
		"ignoreClientBandwidth": c.IgnoreClientBandwidth,
		"quic": map[string]any{
			"maxIdleTimeout":          fmt.Sprintf("%ds", idle(c.IdleTimeout)),
			"disablePathMTUDiscovery": c.DisableMTUDiscovery,
		},
	}
	if c.Obfs {
		cfg["obfs"] = map[string]any{"type": "salamander", "salamander": map[string]any{"password": proto.Str(srv.State, "obfs_password")}}
	}
	if c.Masquerade != "" {
		cfg["masquerade"] = map[string]any{"type": "proxy", "proxy": map[string]any{"url": c.Masquerade, "rewriteHost": true}}
	}
	if c.BandwidthDown > 0 || c.BandwidthUp > 0 {
		// aus Sicht des Servers: „up“ = senden = Download der Nutzer
		b := map[string]any{}
		if c.BandwidthDown > 0 {
			b["up"] = bw(c.BandwidthDown)
		}
		if c.BandwidthUp > 0 {
			b["down"] = bw(c.BandwidthUp)
		}
		cfg["bandwidth"] = b
	}
	// JSON ist gültiges YAML – Hysteria liest die Datei mit einem YAML-Parser.
	data, _ := json.MarshalIndent(cfg, "", "  ")
	data = append([]byte("# Vom VPN-Panel erzeugt – Änderungen werden überschrieben.\n"), append(data, '\n')...)
	ch, err := sys.WriteFile(confDir+"/"+n+".yaml", data, 0o600)
	if err != nil {
		return err
	}
	changed = changed || ch
	unit := "vpn-hysteria@" + n
	if changed {
		_, _ = sys.Run("systemctl", "enable", unit)
		if _, err := sys.Run("systemctl", "restart", unit); err != nil {
			return fmt.Errorf("Hysteria2 neu starten: %w", err)
		}
		env.Log("info", "Hysteria2 „"+srv.Name+"“ konfiguriert und neu gestartet")
	} else if _, err := sys.Run("systemctl", "is-active", "--quiet", unit); err != nil {
		_, _ = sys.Run("systemctl", "enable", unit)
		if _, err := sys.Run("systemctl", "restart", unit); err != nil {
			return fmt.Errorf("Hysteria2 starten: %w", err)
		}
	}

	// Gesperrte Zugänge sofort trennen, Begrenzungen anmelden
	var kick []string
	for _, pb := range sb.Peers {
		if !pb.Active {
			kick = append(kick, peerID(pb.Peer))
			continue
		}
		if c.Shaping && (pb.RateDown > 0 || pb.RateUp > 0) {
			if as := addrsOf(pb.Peer.ID); len(as) > 0 {
				// ausgehend = Download des Nutzers, eingehend = Upload
				// Beim Port-Hopping kommen Pakete auf vielen Ports an (tc sieht sie vor der Umleitung) →
				// dann alles von/zu der Client-Adresse begrenzen.
				port := c.Port
				if f, _, _ := hopRange(c.HopPorts); f > 0 {
					port = 0
				}
				env.Shape.Add(shaping.Rule{Key: fmt.Sprintf("hy-p%d", pb.Peer.ID), Egress: pb.RateDown, Ingress: pb.RateUp, Addrs: as, Port: port})
			}
		}
	}
	if len(kick) > 0 && !sys.DryRun() && !changed {
		if err := statsCall(srv, "POST", "/kick", kick, nil); err != nil {
			env.Log("warn", "Hysteria2: Trennen gesperrter Zugänge: "+err.Error())
		}
	}
	return nil
}

var client = &http.Client{Timeout: 5 * time.Second}

func statsCall(srv *store.Server, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+statsAddr(srv)+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", proto.Str(srv.State, "stats_secret"))
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
	}
	return nil
}

// ---------- Statistik ----------

func (Driver) Collect(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.Usage, error) {
	if env.Sys.DryRun() {
		return nil, nil
	}
	res := map[int64]proto.Usage{}
	now := time.Now().Unix()
	var errs []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		// tx = vom Client gesendet (Upload), rx = an den Client (Download)
		var traffic map[string]struct{ Tx, Rx int64 }
		if err := statsCall(sb.Server, "GET", "/traffic?clear=1", nil, &traffic); err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
			continue
		}
		var online map[string]int
		_ = statsCall(sb.Server, "GET", "/online", nil, &online)
		on := map[int64]bool{}
		var ids []int64
		for _, pb := range sb.Peers {
			id := peerID(pb.Peer)
			ids = append(ids, pb.Peer.ID)
			u := proto.Usage{}
			if t, ok := traffic[id]; ok {
				u.Up, u.Down = t.Tx, t.Rx
			}
			if online[id] > 0 {
				on[pb.Peer.ID] = true
				u.Seen = now
			} else if u.Up+u.Down > 0 {
				u.Seen = now
			}
			if u.Up+u.Down > 0 || u.Seen > 0 {
				res[pb.Peer.ID] = u
			}
		}
		forget(on, ids)
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return res, nil
}

// ---------- Links und Konfiguration ----------

// link: hysteria2://-Link. singbox=true: Port-Hopping-Bereich im Host-Teil
// („host:443,20000-50000“, so liest es Hiddify/sing-box), sonst als mport-Parameter
// (v2rayN, NekoBox; Apps ohne Unterstützung nutzen einfach den normalen Port).
func link(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle, singbox bool) string {
	c := load(sb.Server)
	ports := strconv.Itoa(c.Port)
	q := url.Values{}
	q.Set("sni", sniOf(env, c))
	if c.CertFile == "" {
		q.Set("insecure", "1")
		q.Set("pinSHA256", proto.Str(sb.Server.State, "cert_sha256"))
	}
	if f, t, err := hopRange(c.HopPorts); err == nil && f > 0 {
		if singbox {
			ports = fmt.Sprintf("%d,%d-%d", c.Port, f, t)
		} else {
			q.Set("mport", fmt.Sprintf("%d-%d", f, t))
		}
	}
	if c.Obfs {
		q.Set("obfs", "salamander")
		q.Set("obfs-password", proto.Str(sb.Server.State, "obfs_password"))
	}
	label := sb.Server.Name + " - " + pb.Peer.Name
	return fmt.Sprintf("hysteria2://%s@%s:%s/?%s#%s", url.PathEscape(proto.Str(pb.Peer.Secrets, "password")),
		linkHost(env, c), ports, q.Encode(), url.PathEscape(oneLine(label)))
}

func (Driver) ClientConfig(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (*proto.ClientConfig, error) {
	c := load(sb.Server)
	host := fmt.Sprintf("%s:%d", linkHost(env, c), c.Port)
	hopFrom, hopTo, _ := hopRange(c.HopPorts)
	server := host
	if hopFrom > 0 {
		server = fmt.Sprintf("%s:%d-%d", linkHost(env, c), hopFrom, hopTo)
	}
	var y strings.Builder
	fmt.Fprintf(&y, "# Hysteria2 – %s (%s)\nserver: %s\nauth: %s\ntls:\n  sni: %s\n", oneLine(sb.Server.Name), oneLine(pb.User.Name), server,
		proto.Str(pb.Peer.Secrets, "password"), sniOf(env, c))
	if c.CertFile == "" {
		fmt.Fprintf(&y, "  insecure: true\n  pinSHA256: %s\n", proto.Str(sb.Server.State, "cert_sha256"))
	}
	if c.Obfs {
		fmt.Fprintf(&y, "obfs:\n  type: salamander\n  salamander:\n    password: %s\n", proto.Str(sb.Server.State, "obfs_password"))
	}
	if hopFrom > 0 {
		fmt.Fprintf(&y, "transport:\n  udp:\n    hopInterval: %ds\n", c.HopInterval)
	}
	y.WriteString("socks5:\n  listen: 127.0.0.1:1080\nhttp:\n  listen: 127.0.0.1:8080\n")
	links := []proto.Link{{Label: "Hysteria2", URL: link(env, sb, pb, false)}}
	if hopFrom > 0 {
		links = []proto.Link{
			// zuerst das Format, das (fast) jede App lesen kann; Hiddify nutzt dabei nur den Hauptport
			{Label: "v2rayNG, v2RayTun, NekoBox & Co.", URL: link(env, sb, pb, false)},
			{Label: "Hiddify / sing-box (mit Port-Hopping)", URL: link(env, sb, pb, true)},
		}
	}
	info := [][2]string{
		{"Server", server + " (UDP)"},
		{"Passwort", proto.Str(pb.Peer.Secrets, "password")},
		{"SNI", sniOf(env, c)},
	}
	if c.CertFile == "" {
		info = append(info, [2]string{"Zertifikat (SHA-256)", proto.Str(sb.Server.State, "cert_sha256")})
	}
	return &proto.ClientConfig{
		Title: "Hysteria2 – " + sb.Server.Name,
		Links: links,
		Files: []proto.File{{Name: "hysteria-" + safeName(pb.User.Name) + ".yaml", Content: y.String()}},
		Info:  info,
		Instructions: []string{
			"Am einfachsten: den Abo-Link des Nutzers importieren (v2RayTun, Hiddify, NekoBox, Streisand) – dann kommen Änderungen automatisch.",
			"Alternativ den hysteria2://-Link kopieren oder den QR-Code scannen.",
			"Die Datei ist für den offiziellen Hysteria-Client (hysteria client -c datei.yaml).",
			"Das Zertifikat ist selbst erzeugt; die Links prüfen es über den Fingerabdruck (pinSHA256).",
		},
	}, nil
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}

func safeName(s string) string {
	return regexp.MustCompile(`[^A-Za-z0-9_-]+`).ReplaceAllString(s, "_")
}

func (Driver) ShareLinks(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) []string {
	return []string{link(env, sb, pb, env.Global.Client == "singbox")}
}

// SingBox: hysteria2-Ausgang für das sing-box-Profil. Das selbst erzeugte Zertifikat wird
// mitgeliefert und damit richtig geprüft (kein „insecure“ nötig).
func (Driver) SingBox(env *proto.Env, sb *proto.ServerBundle, pb *proto.PeerBundle) (map[string]any, map[string]any) {
	if !pb.Active {
		return nil, nil
	}
	c := load(sb.Server)
	t := map[string]any{"enabled": true, "server_name": sniOf(env, c)}
	if c.CertFile == "" {
		pem := proto.Str(sb.Server.State, "cert_pem")
		if pem == "" {
			return nil, nil
		}
		t["certificate"] = strings.TrimSpace(pem)
	}
	o := map[string]any{"type": "hysteria2", "server": strings.Trim(linkHost(env, c), "[]"),
		"password": proto.Str(pb.Peer.Secrets, "password"), "tls": t}
	if f, to, err := hopRange(c.HopPorts); err == nil && f > 0 {
		// server_ports ersetzt server_port: Hauptport plus Hopping-Bereich
		iv := c.HopInterval
		if iv <= 0 {
			iv = 30
		}
		o["server_ports"] = []string{fmt.Sprintf("%d:%d", c.Port, c.Port), fmt.Sprintf("%d:%d", f, to)}
		o["hop_interval"] = fmt.Sprintf("%ds", iv)
	} else {
		o["server_port"] = c.Port
	}
	if c.Obfs {
		o["obfs"] = map[string]any{"type": "salamander", "password": proto.Str(sb.Server.State, "obfs_password")}
	}
	return o, nil
}

func (Driver) Ports(srv *store.Server) []proto.Port {
	c := load(srv)
	out := []proto.Port{{Port: c.Port, Proto: "udp", Note: "Hysteria2 " + srv.Name}}
	if f, t, err := hopRange(c.HopPorts); err == nil && f > 0 {
		out = append(out, proto.Port{Port: f, To: t, Proto: "udp", Note: "Hysteria2 Port-Hopping " + srv.Name})
	}
	return out
}

// hopRange: „20000-50000“ → 20000, 50000 (leer → 0, 0).
func hopRange(v string) (from, to int, err error) {
	v = strings.TrimSpace(strings.ReplaceAll(v, ":", "-"))
	if v == "" {
		return 0, 0, nil
	}
	a, b, ok := strings.Cut(v, "-")
	from, err1 := strconv.Atoi(strings.TrimSpace(a))
	to, err2 := strconv.Atoi(strings.TrimSpace(b))
	if !ok || err1 != nil || err2 != nil || from < 1024 || to > 65535 || to <= from {
		return 0, 0, fmt.Errorf("Port-Hopping: bitte einen Bereich wie 20000-50000 (1024–65535)")
	}
	return from, to, nil
}

func (Driver) Status(env *proto.Env, srv *store.Server) proto.Status {
	if !srv.Enabled {
		return proto.Status{Detail: "deaktiviert"}
	}
	if env.Sys.DryRun() {
		return proto.Status{Running: true, Detail: name(srv) + " (Testmodus)"}
	}
	if _, err := env.Sys.Run("systemctl", "is-active", "--quiet", "vpn-hysteria@"+name(srv)); err != nil {
		return proto.Status{Detail: "Hysteria2 läuft nicht"}
	}
	return proto.Status{Running: true, Detail: fmt.Sprintf("Hysteria2 auf UDP %d", load(srv).Port)}
}

func idle(s int) int {
	if s < 4 || s > 120 {
		return 60
	}
	return s
}

// Live: trafficStats ohne Zurücksetzen plus Liste der verbundenen Zugänge.
func (Driver) Live(env *proto.Env, servers []*proto.ServerBundle) (map[int64]proto.LiveSample, error) {
	if env.Sys.DryRun() {
		return nil, nil
	}
	res := map[int64]proto.LiveSample{}
	var errs []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		var traffic map[string]struct{ Tx, Rx int64 }
		if err := statsCall(sb.Server, "GET", "/traffic", nil, &traffic); err != nil {
			errs = append(errs, sb.Server.Name+": "+err.Error())
			continue
		}
		var online map[string]int
		_ = statsCall(sb.Server, "GET", "/online", nil, &online)
		for _, pb := range sb.Peers {
			id := peerID(pb.Peer)
			t, ok := traffic[id]
			if ok || online[id] > 0 {
				s := proto.LiveSample{Up: t.Tx, Down: t.Rx, Online: online[id] > 0}
				if s.Online {
					s.Endpoint = lastAddr(pb.Peer.ID)
				}
				res[pb.Peer.ID] = s
			}
		}
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return res, nil
}

// applyHopping: Port-Hopping – eingehende UDP-Pakete im Bereich auf den Port der Instanz
// umleiten (iptables/ip6tables REDIRECT, eigene Kette VPNHY in der nat-Tabelle).
func applyHopping(env *proto.Env, servers []*proto.ServerBundle) error {
	sys := env.Sys
	dev := env.Global.OutIf
	if dev == "" {
		dev = "eth0"
	}
	var rules []string
	for _, sb := range servers {
		if !sb.Server.Enabled {
			continue
		}
		c := load(sb.Server)
		if f, t, err := hopRange(c.HopPorts); err == nil && f > 0 {
			rules = append(rules, fmt.Sprintf("-A VPNHY -i %s -p udp -m udp --dport %d:%d -j REDIRECT --to-ports %d", dev, f, t, c.Port))
		}
	}
	sort.Strings(rules)
	// immer setzen (billig) – nach einem Neustart des Containers sind die Regeln weg
	sig := strings.Join(rules, "\n")
	changed := env.GetState("hy:hop") != sig
	if !changed && len(rules) == 0 {
		return nil
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if len(rules) == 0 {
			_, _ = sys.Run(bin, "-t", "nat", "-D", "PREROUTING", "-j", "VPNHY")
			_, _ = sys.Run(bin, "-t", "nat", "-F", "VPNHY")
			_, _ = sys.Run(bin, "-t", "nat", "-X", "VPNHY")
			continue
		}
		rs := "*nat\n:VPNHY - [0:0]\n-F VPNHY\n" + strings.Join(rules, "\n") + "\nCOMMIT\n"
		if _, err := sys.RunInput(rs, bin+"-restore", "-n"); err != nil {
			return fmt.Errorf("%s: %w", bin, err)
		}
		if _, err := sys.Run(bin, "-t", "nat", "-C", "PREROUTING", "-j", "VPNHY"); err != nil {
			if _, err := sys.Run(bin, "-t", "nat", "-I", "PREROUTING", "-j", "VPNHY"); err != nil {
				return fmt.Errorf("%s: %w", bin, err)
			}
		}
	}
	env.SetState("hy:hop", sig)
	if changed && len(rules) > 0 {
		env.Log("info", fmt.Sprintf("Hysteria2 Port-Hopping aktiv (%d Bereich(e))", len(rules)))
	}
	return nil
}
