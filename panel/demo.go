package main

import (
	"math/rand"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// seedDemo legt Beispieldaten an (nur Testmodus), damit die Oberfläche gefüllt ist.
func seedDemo(e *engine.Engine) error {
	if s, _ := e.St.Servers(); len(s) > 0 {
		return nil
	}
	wg := &store.Server{Name: "WireGuard", Protocol: "wireguard", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(wg); err != nil {
		return err
	}
	_ = e.St.SaveServer(wg)
	lab := &store.Server{Name: "Homelab-Netz", Protocol: "wireguard", Enabled: true, Settings: store.M{"internet": false, "default_access": "own"}}
	if err := e.InitServer(lab); err != nil {
		return err
	}
	_ = e.St.SaveServer(lab)
	vl := &store.Server{Name: "VLESS Reality", Protocol: "vless", Enabled: true, Settings: store.M{}}
	vl.Settings["targets"] = []map[string]any{
		{"dest": "dl.google.com:443", "server_names": []string{"dl.google.com", "maps.google.com"}},
		{"dest": "web.whatsapp.com:443", "server_names": []string{"web.whatsapp.com"}},
		{"dest": "www.apple.com:443", "server_names": []string{"www.apple.com"}},
	}
	if err := e.InitServer(vl); err != nil {
		return err
	}
	_ = e.St.SaveServer(vl)

	std := &store.Plan{Name: "Standard", Description: "100 GB im Monat, danach 5 Mbit/s",
		Limits: store.Limits{TrafficGB: 100, Period: "monthly", ResetDay: 1, OnLimit: "throttle", LimitDownMbit: 5, LimitUpMbit: 2,
			Tiers: []store.Tier{{AfterGB: 50, DownMbit: 50, UpMbit: 20}}, MaxDevices: 5}}
	_ = e.St.SavePlan(std)
	gast := &store.Plan{Name: "Gast", Description: "10 GB, danach gesperrt", Limits: store.Limits{TrafficGB: 10, Period: "monthly", ResetDay: 1, OnLimit: "block", SpeedDownMbit: 20, SpeedUpMbit: 10, MaxDevices: 2}}
	_ = e.St.SavePlan(gast)

	now := time.Now()
	type dev struct {
		srv            *store.Server
		name, kind     string
		settings       store.M
		online         bool
	}
	users := []struct {
		name   string
		plan   *store.Plan
		gb     float64
		devs   []dev
		expire int64
	}{
		{"martin", nil, 230, []dev{
			{wg, "Pixel", "client", store.M{}, true},
			{wg, "Laptop", "client", store.M{}, false},
			{lab, "Homelab", "site", store.M{"routes": []string{"192.168.10.0/24"}}, true},
			{lab, "NAS", "server", store.M{}, true},
			{lab, "Arbeits-PC", "server", store.M{"routes": []string{"10.20.0.0/24"}}, false},
			{vl, "martin", "access", store.M{}, false},
		}, 0},
		{"anna", std, 62, []dev{{wg, "iPhone", "client", store.M{}, true}, {vl, "anna", "access", store.M{}, true}}, 0},
		{"papa", std, 104, []dev{{vl, "papa", "access", store.M{}, false}}, 0},
		{"gast-tom", gast, 3.2, []dev{{wg, "Handy", "client", store.M{}, false}}, now.AddDate(0, 0, 4).Unix()},
		{"lisa", gast, 10.5, []dev{{vl, "lisa", "access", store.M{}, false}}, 0},
	}
	r := rand.New(rand.NewSource(42))
	for _, uu := range users {
		u := &store.User{Name: uu.name, Enabled: true, SubToken: proto.RandHex(16), ExpiresAt: uu.expire, Created: now.AddDate(0, -2, 0).Unix()}
		if uu.plan != nil {
			id := uu.plan.ID
			u.PlanID = &id
		}
		u.PeriodStart = engine.PeriodStart(engine.EffectiveLimits(u, map[int64]*store.Plan{std.ID: std, gast.ID: gast}), now)
		bytes := int64(uu.gb * engine.GB)
		u.PeriodDown, u.PeriodUp = bytes*85/100, bytes*15/100
		u.TotalDown, u.TotalUp = u.PeriodDown*3, u.PeriodUp*3
		if err := e.St.SaveUser(u); err != nil {
			return err
		}
		for i, d := range uu.devs {
			p := &store.Peer{UserID: u.ID, ServerID: d.srv.ID, Name: d.name, Kind: d.kind, Enabled: true, Settings: d.settings}
			if info, ok := proto.Get(d.srv.Protocol); ok {
				for _, k := range info.Info().Kinds {
					if k.ID == d.kind {
						for key, v := range k.Defaults {
							if _, set := p.Settings[key]; !set {
								p.Settings[key] = v
							}
						}
					}
				}
			}
			if err := e.InitPeer(d.srv, p); err != nil {
				return err
			}
			share := u.TotalDown / int64(len(uu.devs))
			p.TotalDown, p.TotalUp = share, share/5
			if d.online {
				p.LastSeen = now.Add(-time.Duration(30+i*10) * time.Second).Unix()
				p.Handshake = p.LastSeen
			} else {
				p.LastSeen = now.Add(-time.Duration(2+r.Intn(70)) * time.Hour).Unix()
			}
			_ = e.St.SavePeer(p)
			if p.LastSeen > u.LastSeen {
				u.LastSeen = p.LastSeen
			}
			// Verlauf der letzten 30 Tage
			for h := 0; h < 30*24; h += 1 {
				ts := now.Add(-time.Duration(h) * time.Hour).Unix()
				hour := time.Unix(ts, 0).Hour()
				f := 0.2
				if hour >= 18 && hour <= 23 {
					f = 1.0
				} else if hour >= 8 && hour < 18 {
					f = 0.5
				}
				down := int64(float64(share) / 720 * f * (0.5 + r.Float64()) * 1.6)
				_ = e.St.AddTraffic(p.ID, u.ID, d.srv.ID, ts, down/6, down)
			}
		}
		_ = e.St.SaveUser(u)
	}
	e.Log("info", "Demo-Daten angelegt")
	return nil
}
