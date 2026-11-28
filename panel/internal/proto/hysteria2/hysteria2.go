// Package hysteria2: Hysteria2 (QUIC über UDP). Pro Server läuft eine eigene Instanz
// (systemd-Vorlage vpn-hysteria@hy<ID>). Die Anmeldung fragt das Panel per HTTP – so kennt
// das Panel die Client-Adressen (für die Drosselung) und kann gesperrte Nutzer sofort abweisen.
// Verbrauch und Online-Status kommen über die trafficStats-API der Instanz.
package hysteria2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vpnpanel/internal/proto"
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
