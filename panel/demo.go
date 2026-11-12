package main

import (
	"math/rand"
	"sort"
	"strconv"
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
	hy := &store.Server{Name: "Hysteria2", Protocol: "hysteria2", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(hy); err != nil {
		return err
	}
	_ = e.St.SaveServer(hy)
	ov := &store.Server{Name: "OpenVPN", Protocol: "openvpn", Enabled: true, Settings: store.M{}}
	if err := e.InitServer(ov); err != nil {
		return err
	}
	_ = e.St.SaveServer(ov)

	std := &store.Plan{Name: "Standard", Description: "100 GB im Monat, danach 5 Mbit/s",
		Limits: store.Limits{TrafficGB: 100, Period: "monthly", ResetDay: 1, OnLimit: "throttle", LimitDownMbit: 5, LimitUpMbit: 2,
			Tiers: []store.Tier{{AfterGB: 50, DownMbit: 50, UpMbit: 20}}, MaxDevices: 5}}
	_ = e.St.SavePlan(std)
	gast := &store.Plan{Name: "Gast", Description: "10 GB, danach gesperrt", Limits: store.Limits{TrafficGB: 10, Period: "monthly", ResetDay: 1, OnLimit: "block", SpeedDownMbit: 20, SpeedUpMbit: 10, MaxDevices: 2}}
	_ = e.St.SavePlan(gast)

	now := time.Now()
	type dev struct {
		srv        *store.Server
		name, kind string
		settings   store.M
		online     bool
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
			{hy, "martin", "access", store.M{}, true},
			{ov, "OPNsense", "access", store.M{}, true},
		}, 0},
		{"anna", std, 62, []dev{{wg, "iPhone", "client", store.M{}, true}, {vl, "anna", "access", store.M{}, true}, {hy, "anna", "access", store.M{}, true}}, 0},
		{"papa", std, 104, []dev{{vl, "papa", "access", store.M{}, false}, {ov, "Büro-PC", "access", store.M{}, false}}, 0},
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

// seedDemoMany: n weitere Nutzer mit 1–4 Geräten (Testmodus -demo-users), um die Oberfläche mit vielen
// Nutzern zu prüfen. Ohne Verlauf, nur Summen.
func seedDemoMany(e *engine.Engine, n int) error {
	if n <= 0 {
		return nil
	}
	users, _ := e.St.Users()
	if len(users) > 10 {
		return nil
	}
	servers, _ := e.St.Servers()
	byProto := map[string]*store.Server{}
	for _, s := range servers {
		if byProto[s.Protocol] == nil && s.Name != "Homelab-Netz" {
			byProto[s.Protocol] = s
		}
	}
	first := []string{"anna", "ben", "clara", "david", "emma", "felix", "greta", "hannah", "jonas", "lena", "max", "mia", "noah", "paul", "sophie", "tim", "lukas", "marie", "elias", "laura"}
	last := []string{"k", "m", "s", "w", "b", "h", "r", "f"}
	phones := []string{"Xiaomi15", "iPhone", "Pixel", "Galaxy", "Laptop", "Tablet", "Fernseher", "PC"}
	r := rand.New(rand.NewSource(99))
	now := time.Now()
	for i := 0; i < n; i++ {
		name := first[i%len(first)] + "." + last[(i/len(first))%len(last)]
		if i >= len(first)*len(last) {
			name += strconv.Itoa(i)
		}
		u := &store.User{Name: name, Enabled: r.Intn(15) != 0, SubToken: proto.RandHex(16), Created: now.AddDate(0, -1, 0).Unix()}
		gb := r.Float64() * 120
		u.PeriodStart = engine.PeriodStart(engine.EffectiveLimits(u, nil), now)
		u.PeriodDown = int64(gb * engine.GB * 0.85)
		u.PeriodUp = int64(gb * engine.GB * 0.15)
		u.TotalDown, u.TotalUp = u.PeriodDown*2, u.PeriodUp*2
		if err := e.St.SaveUser(u); err != nil {
			return err
		}
		type dv struct{ proto, name, kind string }
		var devs []dv
		for k := 0; k < 1+r.Intn(4); k++ {
			switch r.Intn(4) {
			case 0, 1:
				devs = append(devs, dv{"wireguard", phones[r.Intn(len(phones))], "client"})
			case 2:
				devs = append(devs, dv{"vless", name, "access"})
			default:
				devs = append(devs, []dv{{"hysteria2", name, "access"}, {"openvpn", phones[r.Intn(len(phones))], "access"}}[r.Intn(2)])
			}
		}
		for _, d := range devs {
			srv := byProto[d.proto]
			if srv == nil {
				continue
			}
			p := &store.Peer{UserID: u.ID, ServerID: srv.ID, Name: d.name, Kind: d.kind, Enabled: true, Settings: store.M{}}
			if info, ok := proto.Get(srv.Protocol); ok {
				for _, k := range info.Info().Kinds {
					if k.ID == d.kind {
						for key, v := range k.Defaults {
							p.Settings[key] = v
						}
					}
				}
			}
			if err := e.InitPeer(srv, p); err != nil {
				continue
			}
			p.TotalDown, p.TotalUp = u.TotalDown/int64(len(devs)), u.TotalUp/int64(len(devs))
			if r.Intn(3) == 0 {
				p.LastSeen = now.Add(-time.Duration(20+r.Intn(60)) * time.Second).Unix()
				p.Handshake = p.LastSeen
			} else {
				p.LastSeen = now.Add(-time.Duration(1+r.Intn(200)) * time.Hour).Unix()
			}
			_ = e.St.SavePeer(p)
			if p.LastSeen > u.LastSeen {
				u.LastSeen = p.LastSeen
			}
		}
		_ = e.St.SaveUser(u)
	}
	e.Log("info", "Demo: "+strconv.Itoa(n)+" weitere Nutzer angelegt")
	return nil
}

// seedDemoExits: Beispiel-Ausgänge, eine Gruppe, ein Proxy und eine IP-Liste (nur Testmodus).
func seedDemoExits(e *engine.Engine) error {
	if o, _ := e.St.Objects("exit"); len(o) > 0 {
		return nil
	}
	key := func() string { k, _, _ := proto.X25519(); return proto.B64(k) }
	pub := func() string { _, p, _ := proto.X25519(); return proto.B64(p) }
	var ids []int64
	for i, loc := range []string{"USA Ost", "USA West", "Niederlande"} {
		conf := "[Interface]\nPrivateKey = " + key() + "\nAddress = 100.64.0." + strconv.Itoa(i+2) + "/32\nDNS = 10.255.255.1\nPostUp = echo entfernt\n\n[Peer]\nPublicKey = " +
			pub() + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn" + strconv.Itoa(i+1) + ".example.net:443\n"
		o := &store.Object{Kind: "exit", Name: "Anbieter " + loc, Enabled: true, Data: store.M{"type": "wireguard", "slot": i + 1, "removed": []string{"DNS", "PostUp"}},
			Secrets: store.M{"config": conf}}
		if err := e.St.SaveObject(o); err != nil {
			return err
		}
		ids = append(ids, o.ID)
	}
	g := &store.Object{Kind: "group", Name: "USA", Enabled: true, Data: store.M{"slot": 1, "exits": ids[:2], "on_fail": "block", "max_loss": 20, "max_rtt": 400}}
	if err := e.St.SaveObject(g); err != nil {
		return err
	}
	px := &store.Server{Name: "Proxy USA", Protocol: "proxy", Enabled: true, Settings: store.M{"group": float64(g.ID), "socks_port": float64(11080), "http_port": float64(18080)}}
	if err := e.InitServer(px); err != nil {
		return err
	}
	if err := e.St.SaveServer(px); err != nil {
		return err
	}
	if users, _ := e.St.Users(); len(users) > 0 {
		p := &store.Peer{UserID: users[0].ID, ServerID: px.ID, Name: "Fernseher", Enabled: true, Settings: store.M{}, Secrets: store.M{}}
		if err := e.InitPeer(px, p); err == nil {
			_ = e.St.SavePeer(p)
		}
	}
	return e.St.SaveObject(&store.Object{Kind: "iplist", Name: "Gesperrt", Enabled: true,
		Data: store.M{"mode": "block", "all": true, "entries": []string{"192.0.2.0/24", "198.51.100.66/32"}}})
}

// seedDemoDNS: Blockliste, Filterprofil und ein Tag DNS-Protokoll (nur Testmodus).
func seedDemoDNS(e *engine.Engine) error {
	if o, _ := e.St.Objects("dnslist"); len(o) > 0 {
		return nil
	}
	bl := &store.Object{Kind: "dnslist", Name: "HaGeZi Multi PRO", Enabled: true,
		Data: store.M{"mode": "block", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", "refresh": 24}}
	if err := e.St.SaveObject(bl); err != nil {
		return err
	}
	own := &store.Object{Kind: "dnslist", Name: "Eigene Sperren", Enabled: true,
		Data: store.M{"mode": "block", "entries": []string{"tracking.example", "werbung.example"}}}
	if err := e.St.SaveObject(own); err != nil {
		return err
	}
	go func() { _, _ = e.FetchDNSList(bl.ID); e.RequestApply() }()
	if err := e.St.SaveObject(&store.Object{Kind: "dnsprofile", Name: "Standard", Enabled: true,
		Data: store.M{"lists": []int64{bl.ID, own.ID}, "assign": []string{"global"}, "block_doh": true,
			"rules": "nas.home = 192.168.1.10\nallow ok.example"}}); err != nil {
		return err
	}
	peers, _ := e.St.Peers()
	servers, _ := e.St.Servers()
	proto := map[int64]string{}
	for _, s := range servers {
		proto[s.ID] = s.Protocol
	}
	var devs []*store.Peer
	for _, p := range peers {
		if proto[p.ServerID] == "wireguard" && p.Kind == "client" {
			devs = append(devs, p)
		}
	}
	if len(devs) == 0 {
		return nil
	}
	ok := []string{"www.google.com", "api.github.com", "web.whatsapp.com", "i.ytimg.com", "www.spiegel.de", "connectivitycheck.gstatic.com",
		"graph.facebook.com", "time.android.com", "www.netflix.com", "cdn.jsdelivr.net", "mtalk.google.com", "play.googleapis.com"}
	bad := []string{"doubleclick.net", "googleads.g.doubleclick.net", "app-measurement.com", "graph.instagram.com.tracking.example",
		"pagead2.googlesyndication.com", "ads.tiktok.com", "werbung.example"}
	r := rand.New(rand.NewSource(7))
	now := time.Now().Unix()
	var es []store.DNSEntry
	for i := 0; i < 3000; i++ {
		p := devs[r.Intn(len(devs))]
		en := store.DNSEntry{TS: now - int64(r.Intn(24*3600)), PeerID: p.ID, UserID: p.UserID, Client: proto2addr(p), QType: []int{1, 1, 1, 28, 65}[r.Intn(5)]}
		switch x := r.Intn(10); {
		case x < 2:
			en.Name, en.Action, en.Detail = bad[r.Intn(len(bad))], "blocked", "Liste „HaGeZi Multi PRO“"
		case x < 5:
			en.Name, en.Action = ok[r.Intn(len(ok))], "cached"
		default:
			en.Name, en.Action, en.MS = ok[r.Intn(len(ok))], "ok", 8+r.Intn(60)
		}
		es = append(es, en)
	}
	sort.Slice(es, func(i, j int) bool { return es[i].TS < es[j].TS })
	return e.St.AddDNSLog(es)
}

func proto2addr(p *store.Peer) string {
	if a, ok := p.Settings["address4"].(string); ok {
		return a
	}
	return ""
}
