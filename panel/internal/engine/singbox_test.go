package engine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

func TestSingBoxProfile(t *testing.T) {
	e, _ := newTest(t)
	e.Cfg.HookAddr = "127.0.0.1:8479"
	u := &store.User{Name: "martin", Enabled: true, SubToken: proto.RandHex(16)}
	_ = e.St.SaveUser(u)
	only := &store.User{Name: "nur-vless", Enabled: true, SubToken: proto.RandHex(16)}
	_ = e.St.SaveUser(only)
	servers := map[string]*store.Server{}
	add := func(pr string, user *store.User, kind string, enabled bool) {
		sv := servers[pr]
		if sv == nil {
			sv = &store.Server{Name: pr, Protocol: pr, Enabled: true, Settings: store.M{}}
			if pr == "hysteria2" {
				sv.Settings["hop_ports"] = "20000-40000"
			}
			if err := e.InitServer(sv); err != nil {
				t.Fatal(err)
			}
			_ = e.St.SaveServer(sv)
			servers[pr] = sv
		}
		p := &store.Peer{UserID: user.ID, ServerID: sv.ID, Name: "Handy", Kind: kind, Enabled: enabled, Settings: store.M{}}
		if err := e.InitPeer(sv, p); err != nil {
			t.Fatal(err)
		}
		_ = e.St.SavePeer(p)
	}
	add("wireguard", u, "client", true)
	add("wireguard", u, "site", true) // Netzwerk-Gerät: gehört nicht ins Profil
	add("hysteria2", u, "access", true)
	add("hysteria2", u, "access", false) // deaktiviert
	add("vless", u, "access", true)      // sing-box kann kein Reality mit Xray ≥ 26.9.9
	add("vless", only, "access", true)

	b, err := e.SingBoxProfile(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
		Route     map[string]any   `json:"route"`
		Exp       struct {
			Cache struct {
				Enabled bool `json:"enabled"`
			} `json:"cache_file"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	var sel map[string]any
	for _, o := range cfg.Outbounds {
		types[o["type"].(string)]++
		if o["tag"] == "VPN" {
			sel = o
		}
		if o["type"] == "hysteria2" {
			tls := o["tls"].(map[string]any)
			if !strings.HasPrefix(tls["certificate"].(string), "-----BEGIN CERTIFICATE") || tls["insecure"] != nil {
				t.Errorf("Hysteria2-Zertifikat fehlt: %v", tls)
			}
			if o["server_port"] != nil || len(o["server_ports"].([]any)) != 2 || o["hop_interval"] != "30s" {
				t.Errorf("Port-Hopping falsch: %v", o)
			}
		}
	}
	if types["hysteria2"] != 1 || types["vless"] != 0 || types["urltest"] != 1 || sel == nil {
		t.Errorf("Ausgänge falsch: %v", types)
	}
	if len(cfg.Endpoints) != 1 || cfg.Endpoints[0]["type"] != "wireguard" || cfg.Endpoints[0]["private_key"] == "" {
		t.Errorf("WireGuard-Endpunkt falsch: %v", cfg.Endpoints)
	}
	if n := len(sel["outbounds"].([]any)); n != 3 { // Automatisch + Hysteria2 + WireGuard
		t.Errorf("Auswahl hat %d Einträge", n)
	}
	if !cfg.Exp.Cache.Enabled || sel["interrupt_exist_connections"] != true {
		t.Errorf("Auswahl wird nicht gemerkt bzw. nicht sofort umgeschaltet")
	}
	if cfg.Route["final"] != "VPN" {
		t.Errorf("Route falsch: %v", cfg.Route)
	}
	if _, err := e.SingBoxProfile(only.ID); !errors.Is(err, ErrNoSingBox) {
		t.Errorf("nur VLESS: erwartet ErrNoSingBox, bekommen %v", err)
	}
}
