package store

// JSON-Map für protokollspezifische Einstellungen (vom Treiber typisiert ausgelesen).
type M = map[string]any

// Server ist eine VPN-Instanz eines Protokolls (z. B. wg0, wg1, VLESS-Reality).
type Server struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Enabled  bool   `json:"enabled"`
	Settings M      `json:"settings"`
	State    M      `json:"-"` // Schlüssel und interne Daten, nie an die Oberfläche
	Created  int64  `json:"created"`
}

// Peer ist ein Zugang eines Nutzers zu einem Server (WireGuard-Gerät, VLESS-UUID, …).
type Peer struct {
	ID       int64  `json:"id"`
	UserID   int64  `json:"user_id"`
	ServerID int64  `json:"server_id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"` // client | site | server (WireGuard), access (andere)
	Enabled  bool   `json:"enabled"`
	Settings M      `json:"settings"`
	Secrets  M      `json:"-"`

	// Traffic aus Sicht des Nutzers: Up = vom Gerät gesendet, Down = empfangen
	TotalUp   int64 `json:"total_up"`
	TotalDown int64 `json:"total_down"`
	LastRx    int64 `json:"-"` // letzter Rohzähler (WireGuard)
	LastTx    int64 `json:"-"`
	Handshake int64 `json:"handshake"`
	LastSeen  int64 `json:"last_seen"`
	Endpoint  string `json:"endpoint"` // zuletzt gesehene öffentliche Adresse
	Created   int64 `json:"created"`
}

// Tier: ab einem Verbrauch gilt eine geringere Geschwindigkeit.
type Tier struct {
	AfterGB  float64 `json:"after_gb"`
	DownMbit float64 `json:"down_mbit"`
	UpMbit   float64 `json:"up_mbit"`
}

// Limits gelten pro Nutzer, aus einem Tarif oder individuell.
type Limits struct {
	TrafficGB     float64 `json:"traffic_gb"`      // 0 = unbegrenzt
	Period        string  `json:"period"`          // none | daily | weekly | monthly
	ResetDay      int     `json:"reset_day"`       // Monatstag (1–28) bzw. Wochentag (1=Mo)
	OnLimit       string  `json:"on_limit"`        // block | throttle
	LimitDownMbit float64 `json:"limit_down_mbit"` // Geschwindigkeit nach Erreichen des Limits
	LimitUpMbit   float64 `json:"limit_up_mbit"`
	SpeedDownMbit float64 `json:"speed_down_mbit"` // Grundgeschwindigkeit, 0 = unbegrenzt
	SpeedUpMbit   float64 `json:"speed_up_mbit"`
	Tiers         []Tier  `json:"tiers"`
	MaxDevices    int     `json:"max_devices"` // 0 = unbegrenzt
}

// HasAny: ist überhaupt etwas begrenzt (Volumen, Geschwindigkeit, Drosselstufen)?
func (l *Limits) HasAny() bool {
	return l != nil && (l.TrafficGB > 0 || l.SpeedDownMbit > 0 || l.SpeedUpMbit > 0 || len(l.Tiers) > 0)
}

type Plan struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Limits      Limits `json:"limits"`
	Created     int64  `json:"created"`
}

type User struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	Note      string  `json:"note"`
	Enabled   bool    `json:"enabled"`
	PlanID    *int64  `json:"plan_id"`
	Limits    *Limits `json:"limits"` // individuelle Limits (wenn kein Tarif)
	ExpiresAt int64   `json:"expires_at"`
	SubToken  string  `json:"sub_token"`

	PeriodStart int64 `json:"period_start"`
	PeriodUp    int64 `json:"period_up"`
	PeriodDown  int64 `json:"period_down"`
	TotalUp     int64 `json:"total_up"`
	TotalDown   int64 `json:"total_down"`
	LastSeen    int64 `json:"last_seen"`

	Status       string  `json:"status"` // ok | throttled | blocked | disabled | expired
	StatusReason string  `json:"status_reason"`
	RateDown     float64 `json:"rate_down"` // aktuell wirksame Geschwindigkeit (Mbit/s), 0 = frei
	RateUp       float64 `json:"rate_up"`
	Created      int64   `json:"created"`
}

type Admin struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	PassHash    string `json:"-"`
	TOTPSecret  string `json:"-"`
	TOTPEnabled bool   `json:"totp_enabled"`
	Email       string `json:"email"`
	Notify      bool   `json:"notify"` // Benachrichtigungen per E-Mail an diese Adresse
	Created     int64  `json:"created"`
}

// LoginEntry: ein Anmeldeversuch am Panel.
type LoginEntry struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	Username string `json:"username"`
	AdminID  int64  `json:"admin_id"`
	IP       string `json:"ip"`
	Agent    string `json:"agent"`
	OK       bool   `json:"ok"`
	Reason   string `json:"reason"`
}

type Session struct {
	ID       string `json:"-"`
	AdminID  int64  `json:"admin_id"`
	Created  int64  `json:"created"`
	Expires  int64  `json:"expires"`
	LastUsed int64  `json:"last_used"`
	IP       string `json:"ip"`
	Agent    string `json:"agent"`
}

type Event struct {
	ID    int64  `json:"id"`
	TS    int64  `json:"ts"`
	Level string `json:"level"` // info | warn | error
	Msg   string `json:"msg"`
}

type TrafficPoint struct {
	TS   int64 `json:"ts"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}
