package api

// Gemeinsame Hilfen der Handler (Namen prüfen, Online-Zustand, leere Listen) sowie Meta und Übersicht.
// Weitere Handler liegen nach Thema in eigenen Dateien – siehe ARCHITEKTUR.md.

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// badLabel: Anzeigenamen (Geräte, Server, Tarife) – keine Steuerzeichen, denn sie landen
// als Kommentar in Konfigurationsdateien (wg0.conf, Client-Konfiguration).
func badLabel(n string) bool {
	if n == "" || len(n) > 48 || !utf8.ValidString(n) {
		return true
	}
	for _, r := range n {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}

const onlineWindow = 180 // Sekunden

func online(ts int64) bool { return ts > 0 && nowUnix()-ts < onlineWindow }

// liveOnline: Live-Messung der Engine (in New gesetzt).
var liveOnline = func(int64) bool { return false }

// liveSince: verbunden seit (Unix) laut Live-Messung, 0 = unbekannt (in New gesetzt).
var liveSince = func(int64) int64 { return 0 }

// peerOn: verbunden laut letzter Statistik oder Live-Messung.
func peerOn(p *store.Peer) bool { return online(p.LastSeen) || liveOnline(p.ID) }

// ---------- Meta & Übersicht ----------

// checkUpdate: „Jetzt prüfen“ im Dashboard.
func (a *API) checkUpdate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.E.CheckUpdate(a.Version))
}

func (a *API) meta(w http.ResponseWriter, r *http.Request) {
	var infos []proto.Info
	for _, d := range proto.All() {
		infos = append(infos, d.Info())
	}
	lan4, lan6 := lanAddrs(a.E.Setting("out_interface"))
	p4, p6 := a.E.PublicAddrs()
	pub4, pub6 := "", ""
	if p4.IsValid() {
		pub4 = p4.String()
	}
	if p6.IsValid() {
		pub6 = p6.String()
	}
	writeJSON(w, map[string]any{"protocols": infos, "version": a.Version, "update": a.E.Update(a.Version), "dry_run": a.E.Sys.DryRun(), "docker": engine.InDocker(),
		"server_host": a.E.Setting("server_host"), "sub_host": a.E.Setting("sub_host"), "lan4": lan4, "lan6": lan6, "pub4": pub4, "pub6": pub6})
}

// lanAddrs: Adressen des Containers auf der ausgehenden Schnittstelle – Ziel der Portweiterleitungen
// auf dem Host (für die Hilfe in der Oberfläche). Bei IPv6 gewinnt eine fest eingetragene Adresse
// (z. B. fd10:10:10::3) vor einer aus der MAC gebildeten (SLAAC, „…ff:fe…“).
func lanAddrs(dev string) (v4, v6 string) {
	if dev == "" {
		dev = "eth0"
	}
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		return "", ""
	}
	addrs, _ := ifc.Addrs()
	best := -1
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLoopback() {
			continue
		}
		if ipn.IP.To4() != nil {
			if v4 == "" {
				v4 = ipn.IP.String()
			}
			continue
		}
		if sc := v6Score(ipn.IP); sc > best {
			best, v6 = sc, ipn.IP.String()
		}
	}
	return v4, v6
}

// v6Score: feste Adressen vor SLAAC (EUI-64 mit ff:fe in der Mitte), private (ULA) vor öffentlichen –
// der Host leitet an die Adresse im internen Netz weiter.
func v6Score(ip net.IP) int {
	ip = ip.To16()
	sc := 0
	if !(ip[11] == 0xff && ip[12] == 0xfe) {
		sc += 2
	}
	if ip[0]&0xfe == 0xfc {
		sc++
	}
	return sc
}

type userRow struct {
	*store.User
	PlanName  string        `json:"plan_name"`
	Effective *store.Limits `json:"effective"`
	Devices   int           `json:"devices"`
	Online    bool          `json:"online"`
	// OnlineSince: seit wann (Unix) mindestens ein Zugang ununterbrochen verbunden ist, 0 = unbekannt
	OnlineSince int64    `json:"online_since,omitempty"`
	NextReset   int64    `json:"next_reset"`
	Protocols   []string `json:"protocols"`
	// Find: Gerätenamen, Server und Adressen für die Suche in der Nutzerliste
	Find string `json:"find"`
}

func (a *API) userRows(snap *engine.Snapshot) []*userRow {
	byUser := map[int64][]*proto.PeerBundle{}
	proto2 := map[int64]string{}
	srvName := map[int64]string{}
	for _, sb := range snap.Servers {
		proto2[sb.Server.ID] = sb.Server.Protocol
		srvName[sb.Server.ID] = sb.Server.Name
	}
	for _, pb := range snap.Peers {
		byUser[pb.Peer.UserID] = append(byUser[pb.Peer.UserID], pb)
	}
	now := time.Now()
	var out []*userRow
	for _, u := range snap.Users {
		l := engine.EffectiveLimits(u, snap.Plans)
		row := &userRow{User: u, Effective: l, NextReset: engine.NextReset(l, now)}
		if u.PlanID != nil {
			if p := snap.Plans[*u.PlanID]; p != nil {
				row.PlanName = p.Name
			}
		}
		seen := map[string]bool{}
		var find []string
		for _, pb := range byUser[u.ID] {
			row.Devices++
			find = append(find, pb.Peer.Name, srvName[pb.Peer.ServerID])
			if a4, ok := pb.Peer.Settings["address4"].(string); ok {
				find = append(find, a4)
			}
			if peerOn(pb.Peer) {
				row.Online = true
				if s := liveSince(pb.Peer.ID); s > 0 && (row.OnlineSince == 0 || s < row.OnlineSince) {
					row.OnlineSince = s
				}
			}
			if pr := proto2[pb.Peer.ServerID]; !seen[pr] {
				seen[pr] = true
				row.Protocols = append(row.Protocols, pr)
			}
		}
		sort.Strings(row.Protocols)
		row.Find = strings.Join(find, " ")
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	now := time.Now()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()
	tu, td, _ := a.St.TrafficSum(day)
	mu, md, _ := a.St.TrafficSum(month)
	// SmartDNS: Geräte ohne VPN über den Proxy kommen im Verkehr der Zugänge nicht vor → dazurechnen;
	// der VPN-Anteil ist schon enthalten und wird nur als „davon SmartDNS“ ausgewiesen.
	smart := map[string]int64{}
	for k, since := range map[string]int64{"today": day, "month": month} {
		pu, pd, _ := a.St.SmartTrafficSum(store.SmartProxy, since)
		vu, vd, _ := a.St.SmartTrafficSum(store.SmartVPN, since)
		smart[k] = pu + pd + vu + vd
		smart[k+"_proxy"] = pu + pd
		if k == "today" {
			tu, td = tu+pu, td+pd
		} else {
			mu, md = mu+pu, md+pd
		}
	}

	counts := map[string]int{}
	var totalUp, totalDown int64
	for _, u := range snap.Users {
		counts["users"]++
		counts["status_"+u.Status]++
		totalUp += u.TotalUp
		totalDown += u.TotalDown
	}
	usersOnline := map[int64]bool{}
	for _, pb := range snap.Peers {
		counts["peers"]++
		if peerOn(pb.Peer) {
			counts["peers_online"]++
			usersOnline[pb.Peer.UserID] = true
		}
	}
	counts["users_online"] = len(usersOnline)

	env := a.E.Env()
	var servers []map[string]any
	for _, sb := range snap.Servers {
		d, ok := proto.Get(sb.Server.Protocol)
		st := proto.Status{Detail: "Protokoll unbekannt"}
		if ok {
			st = d.Status(env, sb.Server)
		}
		on := 0
		for _, pb := range sb.Peers {
			if peerOn(pb.Peer) {
				on++
			}
		}
		servers = append(servers, map[string]any{"id": sb.Server.ID, "name": sb.Server.Name, "protocol": sb.Server.Protocol,
			"enabled": sb.Server.Enabled, "status": st, "peers": len(sb.Peers), "online": on})
		counts["servers"]++
	}

	// Top-Nutzer der letzten 30 Tage
	byUser, _ := a.St.TrafficByUser(now.AddDate(0, 0, -30).Unix())
	type top struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Up   int64  `json:"up"`
		Down int64  `json:"down"`
	}
	var tops []top
	for id, v := range byUser {
		if u := snap.Users[id]; u != nil {
			tops = append(tops, top{id, u.Name, v[0], v[1]})
		}
	}
	sort.Slice(tops, func(i, j int) bool { return tops[i].Up+tops[i].Down > tops[j].Up+tops[j].Down })
	if len(tops) > 6 {
		tops = tops[:6]
	}

	// Hinweise: fast am Limit, gedrosselt, gesperrt, bald abgelaufen
	type alert struct {
		UserID int64  `json:"user_id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Text   string `json:"text"`
	}
	var alerts []alert
	for _, u := range snap.Users {
		l := engine.EffectiveLimits(u, snap.Plans)
		switch u.Status {
		case "blocked", "expired", "throttled":
			alerts = append(alerts, alert{u.ID, u.Name, u.Status, u.StatusReason})
			continue
		}
		if l != nil && l.TrafficGB > 0 && u.Status == "ok" {
			pct := float64(u.PeriodUp+u.PeriodDown) / (l.TrafficGB * engine.GB) * 100
			if pct >= 80 {
				alerts = append(alerts, alert{u.ID, u.Name, "limit", fmt.Sprintf("%.0f %% des Datenlimits verbraucht", pct)})
			}
		}
		if u.ExpiresAt > 0 && u.Enabled && u.ExpiresAt > now.Unix() && u.ExpiresAt-now.Unix() < 7*86400 {
			alerts = append(alerts, alert{u.ID, u.Name, "expiring", "läuft am " + time.Unix(u.ExpiresAt, 0).Format("02.01.2006") + " ab"})
		}
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].Name < alerts[j].Name })
	events, _ := a.St.Events(8, "")

	writeJSON(w, map[string]any{
		"counts":  counts,
		"today":   map[string]int64{"up": tu, "down": td},
		"month":   map[string]int64{"up": mu, "down": md},
		"smart":   smart, // SmartDNS-Anteil (heute/Monat), davon ohne VPN
		"total":   map[string]int64{"up": totalUp, "down": totalDown},
		"servers": orEmptyM(servers), "top": orEmptyT(tops), "alerts": orEmptyA(alerts),
		"events": events, "errors": a.E.Errors(),
	})
}

// orEmptyT sorgt dafür, dass leere Listen als [] statt null ankommen.
func orEmptyT[T any](v []T) any {
	if v == nil {
		return []any{}
	}
	return v
}

func orEmptyM(v []map[string]any) any { return orEmptyT(v) }
func orEmptyA[T any](v []T) any       { return orEmptyT(v) }
