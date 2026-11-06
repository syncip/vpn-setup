package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/vless"
	"vpnpanel/internal/proto/wireguard"
	"vpnpanel/internal/store"
)

// Übernahme des bisherigen Bash-Setups (vpn-setup.sh): Schlüssel, Nutzer, Abo-Tokens
// und Statistik bleiben erhalten, bestehende Clients funktionieren unverändert weiter.

type legacyUser struct {
	UUID       string `json:"uuid"`
	N          int    `json:"n"`
	WGPriv     string `json:"wg_priv"`
	WGPub      string `json:"wg_pub"`
	PSK        string `json:"psk"`
	Created    string `json:"created"`
	VlessUp    int64  `json:"vless_up"`
	VlessDown  int64  `json:"vless_down"`
	WGRx       int64  `json:"wg_rx"`
	WGTx       int64  `json:"wg_tx"`
	WGLastRx   int64  `json:"wg_last_rx"`
	WGLastTx   int64  `json:"wg_last_tx"`
	WGHS       int64  `json:"wg_handshake"`
	VlessSeen  int64  `json:"vless_seen"`
	Sub        string `json:"sub"`
}

var (
	envLine  = regexp.MustCompile(`^([A-Z0-9_]+)=(.*)$`)
	arrayRe  = regexp.MustCompile(`\[\d+\]="((?:[^"\\]|\\.)*)"`)
	tokenRe  = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

func parseEnv(data string) (map[string]string, []string) {
	m := map[string]string{}
	var targets []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "declare") && strings.Contains(line, "REALITY_TARGETS") {
			for _, mm := range arrayRe.FindAllStringSubmatch(line, -1) {
				targets = append(targets, mm[1])
			}
			continue
		}
		if mm := envLine.FindStringSubmatch(line); mm != nil {
			m[mm[1]] = strings.Trim(mm[2], `"'`)
		}
	}
	return m, targets
}

// ImportLegacy läuft nur, wenn die Datenbank noch keine Server hat.
func (e *Engine) ImportLegacy(dir string) (bool, error) {
	servers, err := e.St.Servers()
	if err != nil || len(servers) > 0 {
		return false, err
	}
	sys := e.Sys
	usersRaw, err := sys.ReadFile(dir + "/users.json")
	if err != nil {
		return false, nil // nichts zu übernehmen
	}
	envRaw, _ := sys.ReadFile(dir + "/vpn.env")
	realRaw, _ := sys.ReadFile(dir + "/reality.env")
	env, targetsRaw := parseEnv(string(envRaw))
	renv, _ := parseEnv(string(realRaw))

	var db struct {
		Users map[string]legacyUser `json:"users"`
	}
	if err := json.Unmarshal(usersRaw, &db); err != nil {
		return false, fmt.Errorf("users.json lesen: %w", err)
	}

	if v := env["SERVER_HOST"]; v != "" {
		_ = e.St.SetSetting("server_host", v)
	}
	if v := env["SUB_HOST"]; v != "" {
		_ = e.St.SetSetting("sub_host", v)
	}
	if v := env["OUT_IF"]; v != "" {
		_ = e.St.SetSetting("out_interface", v)
	}
	if v := env["PUBLIC_PORT"]; v != "" {
		_ = e.St.SetSetting("public_port", v)
	}

	// WireGuard-Server
	net4 := env["WG_NET4"]
	if net4 == "" {
		net4 = "10.8.0"
	}
	net6 := env["WG_NET6"]
	if net6 == "" {
		net6 = "fd42:42:42::"
	}
	iface := env["WG_IF"]
	if iface == "" {
		iface = "wg0"
	}
	port, _ := strconv.Atoi(env["WG_PORT"])
	if port == 0 {
		port = 51820
	}
	wg := &store.Server{Name: "WireGuard", Protocol: "wireguard", Enabled: true, State: store.M{},
		Settings: store.M{"interface": iface, "port": port, "net4": net4 + ".0/24", "net6": net6 + "/64", "internet": true, "default_access": "all"}}
	if key, err := sys.ReadFile("/etc/wireguard/server.key"); err == nil {
		if err := wireguard.ImportKey(wg, string(key)); err != nil {
			return false, err
		}
	}
	if err := e.InitServer(wg); err != nil {
		return false, fmt.Errorf("WireGuard-Server: %w", err)
	}
	if err := e.St.SaveServer(wg); err != nil {
		return false, err
	}

	// VLESS-Server
	var targets []vless.Target
	for _, t := range targetsRaw {
		dest, names, _ := strings.Cut(t, "|")
		targets = append(targets, vless.Target{Dest: dest, ServerNames: strings.Fields(names)})
	}
	var vl *store.Server
	if renv["XR_PRIV"] != "" {
		vl = &store.Server{Name: "VLESS Reality", Protocol: "vless", Enabled: true, State: store.M{}, Settings: store.M{}}
		if len(targets) > 0 {
			vl.Settings["targets"] = targets
		}
		if p := env["PUBLIC_PORT"]; p != "" {
			vl.Settings["public_port"], _ = strconv.Atoi(p)
		}
		if err := vless.ImportKeys(vl, renv["XR_PRIV"], renv["XR_PUB"], renv["XR_SID"]); err != nil {
			return false, err
		}
		if err := e.InitServer(vl); err != nil {
			return false, fmt.Errorf("VLESS-Server: %w", err)
		}
		if err := e.St.SaveServer(vl); err != nil {
			return false, err
		}
	}

	names := make([]string, 0, len(db.Users))
	for n := range db.Users {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		lu := db.Users[name]
		created := time.Now()
		if t, err := time.ParseInLocation("2006-01-02 15:04", lu.Created, time.Local); err == nil {
			created = t
		}
		tok := lu.Sub
		if !tokenRe.MatchString(tok) {
			tok = proto.RandHex(16)
		}
		seen := lu.WGHS
		if lu.VlessSeen > seen {
			seen = lu.VlessSeen
		}
		u := &store.User{Name: name, Enabled: true, SubToken: tok, PeriodStart: created.Unix(), Created: created.Unix(),
			PeriodUp: lu.VlessUp + lu.WGRx, PeriodDown: lu.VlessDown + lu.WGTx,
			TotalUp: lu.VlessUp + lu.WGRx, TotalDown: lu.VlessDown + lu.WGTx, LastSeen: seen}
		if err := e.St.SaveUser(u); err != nil {
			return false, fmt.Errorf("Nutzer %s: %w", name, err)
		}
		if lu.WGPriv != "" && lu.N > 0 {
			p := &store.Peer{UserID: u.ID, ServerID: wg.ID, Name: name, Kind: "client", Enabled: true,
				Settings: store.M{"address4": fmt.Sprintf("%s.%d", net4, lu.N), "address6": fmt.Sprintf("%s%d", net6, lu.N), "tunnel": "full", "access": "default"},
				Secrets:  store.M{"private_key": lu.WGPriv, "public_key": lu.WGPub, "psk": lu.PSK},
				TotalUp:  lu.WGRx, TotalDown: lu.WGTx, LastRx: lu.WGLastRx, LastTx: lu.WGLastTx, Handshake: lu.WGHS, LastSeen: lu.WGHS}
			if err := e.InitPeer(wg, p); err != nil {
				return false, fmt.Errorf("WireGuard-Zugang %s: %w", name, err)
			}
			if err := e.St.SavePeer(p); err != nil {
				return false, err
			}
		}
		if vl != nil && lu.UUID != "" {
			p := &store.Peer{UserID: u.ID, ServerID: vl.ID, Name: name, Kind: "access", Enabled: true,
				Secrets: store.M{"uuid": lu.UUID}, TotalUp: lu.VlessUp, TotalDown: lu.VlessDown, LastSeen: lu.VlessSeen}
			if err := e.InitPeer(vl, p); err != nil {
				return false, err
			}
			if err := e.St.SavePeer(p); err != nil {
				return false, err
			}
		}
	}
	// Alte NAT-Regeln aus der PostUp-Zeile von wg0 entfernen (jetzt eigene Kette)
	out := e.Setting("out_interface")
	_, _ = sys.Run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", net4+".0/24", "-o", out, "-j", "MASQUERADE")
	_, _ = sys.Run("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", net6+"/64", "-o", out, "-j", "MASQUERADE")
	e.Log("info", fmt.Sprintf("Bisheriges Setup übernommen: %d Nutzer, Schlüssel und Statistik", len(names)))
	return true, nil
}
