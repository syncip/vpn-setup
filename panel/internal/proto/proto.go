// Package proto definiert die Schnittstelle für VPN-Protokolle. Ein neues Protokoll
// (z. B. Hysteria2) braucht nur einen weiteren Treiber, der Driver implementiert und
// sich per Register anmeldet. Die Oberfläche baut ihre Formulare aus den Field-Listen.
package proto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"golang.org/x/crypto/curve25519"

	"vpnpanel/internal/proto/shaping"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

// Field beschreibt ein Eingabefeld der Oberfläche.
type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"` // text | number | bool | select | cidr | cidrlist | textlist | targets | peers | secret
	Default  any      `json:"default,omitempty"`
	Options  []Option `json:"options,omitempty"`
	Help     string   `json:"help,omitempty"`
	Advanced bool     `json:"advanced,omitempty"`
	Kinds    []string `json:"kinds,omitempty"`    // nur für diese Zugangsarten anzeigen
	ReadOnly bool     `json:"readonly,omitempty"` // nur anzeigen (z. B. Schlüssel)
	Placeholder string `json:"placeholder,omitempty"`
}

type Option struct {
	Value any    `json:"value"`
	Label string `json:"label"`
}

// Kind ist eine Zugangsart mit Vorgaben (z. B. „Handy/Laptop“, „Netzwerk/Homelab“).
type Kind struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Defaults    store.M `json:"defaults"`
}

type Info struct {
	ID           string  `json:"id"`
	Label        string  `json:"label"`
	Description  string  `json:"description"`
	Mesh         bool    `json:"mesh"` // unterstützt Netzwerke/Geräte untereinander
	ServerFields []Field `json:"server_fields"`
	PeerFields   []Field `json:"peer_fields"`
	Kinds        []Kind  `json:"kinds"`
}

// Global sind serverweite Einstellungen, die jeder Treiber braucht.
type Global struct {
	ServerHost string
	OutIf      string
	XrayAPI    string
	DataDir    string
	PublicPort int    // TCP-Port von nginx (Panel, Abo, VLESS), 0 = 443
	HookURL    string // interner HTTP-Endpunkt des Panels (z. B. Hysteria2-Anmeldung), ohne Schrägstrich am Ende
	// Client: Art der App, die ein Abo abruft („singbox“ = Hiddify/sing-box, „v2raytun“ = v2RayTun), leer = unbekannt.
	// Treiber können Links daran anpassen (z. B. Port-Hopping im Host-Teil statt mport).
	Client string
	// Groups: Ausgangsgruppen (externe VPNs) – Verbindungen mit Mark laufen über den aktiven Ausgang.
	Groups map[int64]GroupRoute
	// ACLs: Sperr-/Freigabelisten je Server-ID (nil = keine Einschränkung). Die Engine setzt sie per
	// iptables auf den Ports aus Ports() durch; Treiber mit geteiltem Port (VLESS) über SelfACL selbst.
	ACLs map[int64]*ACL
	// Policies: Ziel-Regeln je Zugang (Peer-ID); ServerPolicies: nur Server- und globale Regeln je
	// Server-ID (für Dienste, die Nutzer nicht einzeln leiten können, z. B. Hysteria2).
	Policies       map[int64]*Policy
	ServerPolicies map[int64]*Policy
	// TargetLists: Inhalt der Ziellisten (nur IPv4), auf die Regeln verweisen.
	TargetLists map[int64][]netip.Prefix
}

// ACL: Wer darf sich mit einem Server verbinden?
type ACL struct {
	Deny      []netip.Prefix
	Allow     []netip.Prefix
	AllowOnly bool // es gibt eine Freigabeliste → nur deren Adressen
}

// Allowed: darf diese Client-Adresse verbinden?
func (a *ACL) Allowed(ip netip.Addr) bool {
	if a == nil {
		return true
	}
	ip = ip.Unmap()
	for _, p := range a.Deny {
		if p.Contains(ip) {
			return false
		}
	}
	if !a.AllowOnly {
		return true
	}
	for _, p := range a.Allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// SelfACL: Treiber setzt die Listen selbst durch (z. B. VLESS hinter dem gemeinsamen Port 443).
type SelfACL interface {
	SelfACL() bool
}

// GroupRoute: wie ein Treiber Verkehr über eine Ausgangsgruppe schickt.
type GroupRoute struct {
	ID      int64
	Name    string
	Enabled bool
	Mark    uint32   // SO_MARK für Sockets
	DNS     []string // DNS-Server, die über die Gruppe abgefragt werden
	// Dev: Schnittstelle des gerade aktiven Ausgangs ("" = keiner); State: ok | failover | blocked |
	// direct ("" = noch nicht bewertet). Für Dienste, die sich an die Schnittstelle binden (Hysteria2).
	Dev   string
	State string
}

// GroupSwitcher: optional – wird aufgerufen, wenn eine Gruppe den Ausgang wechselt
// (z. B. bestehende Proxy-Verbindungen trennen, damit sie über den neuen Ausgang aufgebaut werden).
type GroupSwitcher interface {
	GroupSwitched(groupID int64)
}

type Env struct {
	Sys    system.Runner
	Global Global
	Log    func(level, msg string)
	// Persist speichert interne Zustände (z. B. tc-Prüfsummen) dauerhaft.
	GetState func(key string) string
	SetState func(key, value string)
	// Shape sammelt Begrenzungen auf der Internet-Schnittstelle (eth0) aller Protokolle.
	Shape *shaping.Plan
}

// PeerBundle: ein Zugang mit Nutzer und aktuell wirksamen Limits.
type PeerBundle struct {
	Peer     *store.Peer
	User     *store.User
	Active   bool    // false = gesperrt/abgelaufen/deaktiviert → nicht in die Konfiguration
	RateDown float64 // Mbit/s, 0 = frei
	RateUp   float64
}

type ServerBundle struct {
	Server *store.Server
	Peers  []*PeerBundle
}

// Usage: Verbrauch seit dem letzten Einsammeln.
type Usage struct {
	Up, Down  int64
	Seen      int64 // Zeitpunkt letzter Aktivität (0 = unbekannt)
	Handshake int64
	Endpoint  string
}

// ClientConfig ist alles, was ein Nutzer zum Verbinden braucht.
type ClientConfig struct {
	Title        string     `json:"title"`
	Files        []File     `json:"files,omitempty"` // z. B. wg-Konfiguration
	Links        []Link     `json:"links,omitempty"` // z. B. vless://
	Instructions []string   `json:"instructions,omitempty"`
	Info         [][2]string `json:"info,omitempty"`
}

type File struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	QR      bool   `json:"qr"`
}

type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// SNIRoute: Weiterleitung im nginx-SNI-Verteiler (TCP-Protokolle auf gemeinsamem Port).
type SNIRoute struct {
	Port    int
	SNI     string // "" = Standard dieses Ports
	Backend string // host:port
}

// Port beschreibt einen Port, der auf dem Proxmox-Host weitergeleitet werden muss.
type Port struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // udp | tcp
	Note  string `json:"note"`
	To    int    `json:"to,omitempty"` // Ende eines Portbereichs (z. B. Port-Hopping), 0 = einzelner Port
}

type Status struct {
	Running bool   `json:"running"`
	Detail  string `json:"detail"`
}

type Driver interface {
	Info() Info
	// InitServer setzt Vorgaben und erzeugt Schlüssel (bei neuen und geänderten Servern).
	InitServer(env *Env, srv *store.Server, all []*store.Server) error
	// InitPeer setzt Vorgaben, Adressen und Schlüssel eines Zugangs.
	InitPeer(env *Env, srv *store.Server, p *store.Peer, others []*store.Peer) error
	// Apply schreibt die Konfiguration aller Server dieses Protokolls und lädt neu.
	Apply(env *Env, servers []*ServerBundle) error
	// Collect sammelt den Verbrauch pro Peer-ID ein.
	Collect(env *Env, servers []*ServerBundle) (map[int64]Usage, error)
	// ClientConfig erzeugt Konfiguration/Links für einen Zugang.
	ClientConfig(env *Env, sb *ServerBundle, pb *PeerBundle) (*ClientConfig, error)
	// ShareLinks liefert Links für das Abo (leer, wenn das Protokoll keine hat).
	ShareLinks(env *Env, sb *ServerBundle, pb *PeerBundle) []string
	Ports(srv *store.Server) []Port
	Status(env *Env, srv *store.Server) Status
}

// Hooker wird von Treibern implementiert, deren Dienst das Panel per HTTP fragt
// (z. B. Hysteria2-Anmeldung). reshape = Begrenzungen neu einspielen.
type Hooker interface {
	Hook(env *Env, sb *ServerBundle, body []byte) (resp any, reshape bool, err error)
}

// SNIRouter wird von Treibern implementiert, die über den gemeinsamen TCP-Port laufen.
type SNIRouter interface {
	SNIRoutes(servers []*ServerBundle) []SNIRoute
}

var drivers = map[string]Driver{}

func Register(d Driver) { drivers[d.Info().ID] = d }

func Get(id string) (Driver, bool) { d, ok := drivers[id]; return d, ok }

func All() []Driver {
	var out []Driver
	for _, d := range drivers {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().ID > out[j].Info().ID })
	return out
}

// ---------- Hilfen für Treiber ----------

// Decode überträgt eine Einstellungs-Map in eine typisierte Struktur.
func Decode(m store.M, v any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Encode überträgt eine Struktur zurück in eine Map.
func Encode(v any) store.M {
	b, _ := json.Marshal(v)
	m := store.M{}
	_ = json.Unmarshal(b, &m)
	return m
}

func Str(m store.M, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// X25519 erzeugt ein Schlüsselpaar.
func X25519() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return
}

func PubFromPriv(priv []byte) ([]byte, error) { return curve25519.X25519(priv, curve25519.Basepoint) }

func B64(b []byte) string    { return base64.StdEncoding.EncodeToString(b) }
func B64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func RandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func UUID() string {
	b := RandBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// LiveSample: aktueller Zählerstand eines Zugangs (beliebiger Nullpunkt – die Engine bildet
// Differenzen; fällt ein Zähler, wurde er zurückgesetzt).
type LiveSample struct {
	Up, Down int64
	Online   bool   // sicher verbunden (Handshake/Sitzung); sonst zählt Aktivität
	Endpoint string // öffentliche Adresse, wenn bekannt
	Since    int64  // verbunden seit (Unix), wenn der Dienst es kennt (OpenVPN); 0 = Engine schätzt
}

// SingBoxer: optional – Ausgang (outbound) bzw. Endpunkt (endpoint) eines Zugangs für das
// sing-box-Profil (offizielle sing-box-Apps lesen keine Link-Listen, nur fertige JSON-Konfigurationen).
// Beide nil = Zugang gehört nicht ins Profil. Das Feld "tag" setzt die Engine.
type SingBoxer interface {
	SingBox(env *Env, sb *ServerBundle, pb *PeerBundle) (outbound, endpoint map[string]any)
}

// LiveReader: optional – schnelle Zählerabfrage ohne Zurücksetzen (für die Live-Anzeige).
type LiveReader interface {
	Live(env *Env, servers []*ServerBundle) (map[int64]LiveSample, error)
}
