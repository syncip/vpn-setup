package api

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/wireguard"
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

func (a *API) meta(w http.ResponseWriter, r *http.Request) {
	var infos []proto.Info
	for _, d := range proto.All() {
		infos = append(infos, d.Info())
	}
	writeJSON(w, map[string]any{"protocols": infos, "version": a.Version, "dry_run": a.E.Sys.DryRun(),
		"server_host": a.E.Setting("server_host"), "sub_host": a.E.Setting("sub_host")})
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
}

func (a *API) userRows(snap *engine.Snapshot) []*userRow {
	byUser := map[int64][]*proto.PeerBundle{}
	proto2 := map[int64]string{}
	for _, sb := range snap.Servers {
		proto2[sb.Server.ID] = sb.Server.Protocol
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
		for _, pb := range byUser[u.ID] {
			row.Devices++
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

// ---------- Nutzer ----------

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, orEmptyT(a.userRows(snap)))
}

type userInput struct {
	Name      *string       `json:"name"`
	Note      *string       `json:"note"`
	Enabled   *bool         `json:"enabled"`
	PlanID    *int64        `json:"plan_id"`
	Limits    *store.Limits `json:"limits"`
	Custom    *bool         `json:"custom"` // true = individuelle Limits, false = Tarif/keine
	ExpiresAt *int64        `json:"expires_at"`
	Accesses  []struct {
		ServerID int64  `json:"server_id"`
		Kind     string `json:"kind"`
		Name     string `json:"name"`
	} `json:"accesses"`
}

func (a *API) applyUserInput(u *store.User, in *userInput) error {
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if !nameRe.MatchString(n) {
			return fmt.Errorf("Name ungültig (A-Z a-z 0-9 _ - ., max. 32 Zeichen)")
		}
		u.Name = n
	}
	if in.Note != nil {
		u.Note = *in.Note
	}
	if in.Enabled != nil {
		u.Enabled = *in.Enabled
	}
	if in.ExpiresAt != nil {
		u.ExpiresAt = *in.ExpiresAt
	}
	if in.Custom != nil {
		if *in.Custom {
			if in.Limits == nil {
				in.Limits = &store.Limits{}
			}
			if err := engine.ValidateLimits(in.Limits); err != nil {
				return err
			}
			u.Limits, u.PlanID = in.Limits, nil
		} else {
			u.Limits = nil
			if in.PlanID != nil && *in.PlanID > 0 {
				if _, err := a.St.Plan(*in.PlanID); err != nil {
					return fmt.Errorf("Tarif nicht gefunden")
				}
				id := *in.PlanID
				u.PlanID = &id
			} else {
				u.PlanID = nil
			}
		}
	}
	return nil
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var in userInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.Name == nil {
		errJSON(w, http.StatusBadRequest, "Name fehlt")
		return
	}
	u := &store.User{Enabled: true, SubToken: proto.RandHex(16)}
	if in.Custom == nil {
		f := false
		in.Custom = &f
	}
	if err := a.applyUserInput(u, &in); err != nil {
		fail(w, err)
		return
	}
	u.PeriodStart = engine.PeriodStart(engine.EffectiveLimits(u, a.planMap()), time.Now())
	if u.PeriodStart == 0 {
		u.PeriodStart = nowUnix()
	}
	if err := a.St.SaveUser(u); err != nil {
		fail(w, err)
		return
	}
	var errs []string
	for _, ac := range in.Accesses {
		name := ac.Name
		if name == "" {
			name = u.Name
		}
		if _, err := a.addPeer(u, ac.ServerID, name, ac.Kind, store.M{}, true); err != nil {
			errs = append(errs, err.Error())
		}
	}
	a.E.Log("info", "Nutzer "+u.Name+" angelegt")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": u.ID, "errors": errs})
}

func (a *API) planMap() map[int64]*store.Plan {
	m := map[int64]*store.Plan{}
	plans, _ := a.St.Plans()
	for _, p := range plans {
		m[p.ID] = p
	}
	return m
}

type peerRow struct {
	*store.Peer
	ServerName  string `json:"server_name"`
	Protocol    string `json:"protocol"`
	Online      bool   `json:"online"`
	OnlineSince int64  `json:"online_since,omitempty"`
	Active      bool   `json:"active"`
	UserName    string `json:"user_name"`
	PublicKey   string `json:"public_key,omitempty"`
}

func peerRowOf(pb *proto.PeerBundle, sv *store.Server) *peerRow {
	pr := &peerRow{Peer: pb.Peer, Online: peerOn(pb.Peer), Active: pb.Active, UserName: pb.User.Name}
	if pr.Online {
		pr.OnlineSince = liveSince(pb.Peer.ID)
	}
	if sv != nil {
		pr.ServerName, pr.Protocol = sv.Name, sv.Protocol
	}
	if k := proto.Str(pb.Peer.Secrets, "public_key"); k != "" {
		pr.PublicKey = k
	}
	return pr
}

func (a *API) getUser(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	u := snap.Users[id]
	if u == nil {
		fail(w, store.ErrNotFound)
		return
	}
	var row *userRow
	for _, ur := range a.userRows(snap) {
		if ur.ID == id {
			row = ur
		}
	}
	servers := map[int64]*store.Server{}
	for _, sb := range snap.Servers {
		servers[sb.Server.ID] = sb.Server
	}
	var peers []*peerRow
	for _, pb := range snap.Peers {
		if pb.Peer.UserID == id {
			peers = append(peers, peerRowOf(pb, servers[pb.Peer.ServerID]))
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	sub := a.subURL(r, u)
	writeJSON(w, map[string]any{"user": row, "peers": orEmptyT(peers), "sub_url": sub, "singbox_url": singBoxImport(sub, a.profileName(u)), "custom": u.Limits != nil})
}

func (a *API) subURL(r *http.Request, u *store.User) string {
	if h := a.E.Setting("sub_host"); h != "" {
		return "https://" + h + "/" + u.SubToken
	}
	if h := a.E.Setting("panel_host"); h != "" {
		return "https://" + h + "/sub/" + u.SubToken
	}
	return "https://" + r.Host + "/sub/" + u.SubToken // z. B. direkter Zugang per IP:Port
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.St.User(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	var in userInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	oldPeriod := engine.EffectiveLimits(u, a.planMap())
	if err := a.applyUserInput(u, &in); err != nil {
		fail(w, err)
		return
	}
	// Zeitraum geändert → aktuellen Zeitraum neu bestimmen (Verbrauch bleibt)
	if nl := engine.EffectiveLimits(u, a.planMap()); nl != nil && (oldPeriod == nil || oldPeriod.Period != nl.Period || oldPeriod.ResetDay != nl.ResetDay) {
		if ps := engine.PeriodStart(nl, time.Now()); ps > 0 {
			u.PeriodStart = ps
		}
	}
	if err := a.St.SaveUser(u); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.St.User(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteUser(u.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Nutzer "+u.Name+" gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) resetUser(w http.ResponseWriter, r *http.Request) {
	var in struct{ What string }
	_ = readJSON(r, &in)
	_ = a.E.Collect()
	u, err := a.St.User(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	u.PeriodUp, u.PeriodDown = 0, 0
	msg := "Verbrauch im Zeitraum"
	if in.What == "all" {
		u.TotalUp, u.TotalDown = 0, 0
		peers, _ := a.St.PeersOfUser(u.ID)
		for _, p := range peers {
			p.TotalUp, p.TotalDown = 0, 0
			_ = a.St.SavePeer(p)
		}
		msg = "Gesamte Statistik"
	}
	if err := a.St.SaveUser(u); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", fmt.Sprintf("Nutzer %s: %s zurückgesetzt", u.Name, msg))
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// profileName: Name des Profils in den Apps („VPN – Martin“).
func (a *API) profileName(u *store.User) string {
	t := a.E.Setting("profile_title")
	if t == "" {
		t = "VPN"
	}
	return t + " – " + u.Name
}

func (a *API) newToken(w http.ResponseWriter, r *http.Request) {
	u, err := a.St.User(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	u.SubToken = proto.RandHex(16)
	if err := a.St.SaveUser(u); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Nutzer "+u.Name+": neuer Abo-Link")
	writeJSON(w, map[string]string{"sub_url": a.subURL(r, u)})
}

// rangeParams: feste Zeiträume (range=24h|7d|30d|90d) oder ein Ausschnitt (from/to, Unix-Zeit)
// zum Hineinzoomen. Die Auflösung richtet sich nach der Länge (feinste Stufe: 1 Stunde).
func rangeParams(r *http.Request) (since, until, bucket int64) {
	now := time.Now()
	q := r.URL.Query()
	if f, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil && f > 0 {
		t, err := strconv.ParseInt(q.Get("to"), 10, 64)
		if err != nil || t <= f || t > now.Unix()+3600 {
			t = now.Unix()
		}
		if f < now.AddDate(-2, 0, 0).Unix() {
			f = now.AddDate(-2, 0, 0).Unix()
		}
		span := t - f
		switch {
		case span <= 4*86400:
			bucket = 3600
		case span <= 21*86400:
			bucket = 6 * 3600
		default:
			bucket = 86400
		}
		return f, t, bucket
	}
	until = now.Unix() + 3600
	switch q.Get("range") {
	case "7d":
		return now.AddDate(0, 0, -7).Unix(), until, 6 * 3600
	case "30d":
		return now.AddDate(0, 0, -30).Unix(), until, 86400
	case "90d":
		return now.AddDate(0, 0, -90).Unix(), until, 86400
	}
	return now.Add(-24 * time.Hour).Unix(), until, 3600
}

func (a *API) series(w http.ResponseWriter, r *http.Request, filter string, id int64) {
	since, until, bucket := rangeParams(r)
	s, err := a.St.TrafficSeries(since, until, bucket, filter, id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"bucket": bucket, "since": since, "until": until, "points": orEmptyT(s)})
}

func (a *API) userTraffic(w http.ResponseWriter, r *http.Request) { a.series(w, r, "user", pathID(r)) }
func (a *API) peerTraffic(w http.ResponseWriter, r *http.Request) { a.series(w, r, "peer", pathID(r)) }
func (a *API) serverTraffic(w http.ResponseWriter, r *http.Request) {
	a.series(w, r, "server", pathID(r))
}
func (a *API) traffic(w http.ResponseWriter, r *http.Request) { a.series(w, r, "", 0) }

// ---------- Zugänge ----------

func (a *API) addPeer(u *store.User, serverID int64, name, kind string, settings store.M, enabled bool) (*store.Peer, error) {
	sv, err := a.St.Server(serverID)
	if err != nil {
		return nil, fmt.Errorf("Server nicht gefunden")
	}
	d, ok := proto.Get(sv.Protocol)
	if !ok {
		return nil, fmt.Errorf("Protokoll unbekannt")
	}
	if l := engine.EffectiveLimits(u, a.planMap()); l != nil && l.MaxDevices > 0 {
		peers, _ := a.St.PeersOfUser(u.ID)
		if len(peers) >= l.MaxDevices {
			return nil, fmt.Errorf("%s: höchstens %d Zugänge erlaubt", u.Name, l.MaxDevices)
		}
	}
	name = strings.TrimSpace(name)
	if badLabel(name) {
		return nil, fmt.Errorf("Gerätename fehlt oder ist zu lang")
	}
	info := d.Info()
	if kind == "" && len(info.Kinds) > 0 {
		kind = info.Kinds[0].ID
	}
	// Vorgaben der Geräteart, überschrieben durch Eingaben
	s := store.M{}
	for _, k := range info.Kinds {
		if k.ID == kind {
			for key, v := range k.Defaults {
				s[key] = v
			}
		}
	}
	for key, v := range settings {
		s[key] = v
	}
	p := &store.Peer{UserID: u.ID, ServerID: sv.ID, Name: name, Kind: kind, Enabled: enabled, Settings: s}
	if err := a.E.InitPeer(sv, p); err != nil {
		return nil, fmt.Errorf("%s: %v", sv.Name, err)
	}
	if err := a.St.SavePeer(p); err != nil {
		return nil, err
	}
	a.E.Log("info", fmt.Sprintf("Zugang %s (%s) für %s angelegt", name, sv.Name, u.Name))
	return p, nil
}

func (a *API) createPeer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID   int64   `json:"user_id"`
		ServerID int64   `json:"server_id"`
		Name     string  `json:"name"`
		Kind     string  `json:"kind"`
		Enabled  *bool   `json:"enabled"`
		Settings store.M `json:"settings"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	u, err := a.St.User(in.UserID)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "Nutzer nicht gefunden")
		return
	}
	en := in.Enabled == nil || *in.Enabled
	p, err := a.addPeer(u, in.ServerID, in.Name, in.Kind, in.Settings, en)
	if err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": p.ID})
}

func (a *API) getPeer(w http.ResponseWriter, r *http.Request) {
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	pb := snap.Peers[pathID(r)]
	if pb == nil {
		fail(w, store.ErrNotFound)
		return
	}
	var sv *store.Server
	for _, sb := range snap.Servers {
		if sb.Server.ID == pb.Peer.ServerID {
			sv = sb.Server
		}
	}
	writeJSON(w, peerRowOf(pb, sv))
}

func (a *API) updatePeer(w http.ResponseWriter, r *http.Request) {
	p, err := a.St.Peer(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	var in struct {
		Name     *string `json:"name"`
		Kind     *string `json:"kind"`
		Enabled  *bool   `json:"enabled"`
		Settings store.M `json:"settings"`
		Regen    bool    `json:"regenerate_keys"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	sv, err := a.St.Server(p.ServerID)
	if err != nil {
		fail(w, err)
		return
	}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if badLabel(n) {
			errJSON(w, http.StatusBadRequest, "Gerätename fehlt oder ist zu lang")
			return
		}
		p.Name = n
	}
	if in.Kind != nil {
		p.Kind = *in.Kind
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.Settings != nil {
		p.Settings = in.Settings
	}
	if in.Regen {
		p.Secrets = store.M{}
		p.LastRx, p.LastTx = 0, 0
	}
	if err := a.E.InitPeer(sv, p); err != nil {
		fail(w, err)
		return
	}
	if err := a.St.SavePeer(p); err != nil {
		fail(w, err)
		return
	}
	if in.Regen {
		a.E.Log("warn", "Zugang "+p.Name+": neue Schlüssel erzeugt")
	}
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) deletePeer(w http.ResponseWriter, r *http.Request) {
	p, err := a.St.Peer(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeletePeer(p.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Zugang "+p.Name+" gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) peerConfig(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	cc, err := a.E.ClientConfig(id)
	if err != nil {
		fail(w, err)
		return
	}
	// Protokolle mit Links (VLESS …) kommen auch ins Abo – den Abo-Link mitliefern.
	resp := struct {
		*proto.ClientConfig
		SubURL     string `json:"sub_url,omitempty"`
		SingBoxURL string `json:"singbox_url,omitempty"`
		ProfileURL string `json:"profile_url,omitempty"` // OpenVPN: .ovpn zum Herunterladen (über den Abo-Token)
		ImportURL  string `json:"import_url,omitempty"`  // OpenVPN Connect: Profil per Link/QR übernehmen
	}{ClientConfig: cc}
	if p, err := a.St.Peer(id); err == nil {
		if sv, err := a.St.Server(p.ServerID); err == nil && sv.Protocol == "openvpn" {
			if u, err := a.St.User(p.UserID); err == nil {
				resp.ProfileURL = a.subURL(r, u) + "/openvpn/" + strconv.FormatInt(p.ID, 10)
				resp.ImportURL = "openvpn://import-profile/" + resp.ProfileURL
			}
		}
	}
	if len(cc.Links) > 0 {
		if p, err := a.St.Peer(id); err == nil {
			if u, err := a.St.User(p.UserID); err == nil {
				resp.SubURL = a.subURL(r, u)
				resp.SingBoxURL = singBoxImport(resp.SubURL, a.profileName(u))
			}
		}
	}
	writeJSON(w, resp)
}

// ---------- Server ----------

type serverRow struct {
	*store.Server
	Status    proto.Status `json:"status"`
	Peers     int          `json:"peers"`
	Online    int          `json:"online"`
	Ports     []proto.Port `json:"ports"`
	PublicKey string       `json:"public_key,omitempty"`
	Error     string       `json:"error,omitempty"`
	Up        int64        `json:"up"`
	Down      int64        `json:"down"`
}

func (a *API) serverRows(snap *engine.Snapshot) []*serverRow {
	env := a.E.Env()
	errs := a.E.Errors()
	var out []*serverRow
	for _, sb := range snap.Servers {
		row := &serverRow{Server: sb.Server, Peers: len(sb.Peers)}
		if d, ok := proto.Get(sb.Server.Protocol); ok {
			row.Status = d.Status(env, sb.Server)
			row.Ports = d.Ports(sb.Server)
		}
		row.PublicKey = proto.Str(sb.Server.State, "public_key")
		row.Error = errs[sb.Server.Protocol]
		for _, pb := range sb.Peers {
			if peerOn(pb.Peer) {
				row.Online++
			}
			row.Up += pb.Peer.TotalUp
			row.Down += pb.Peer.TotalDown
		}
		out = append(out, row)
	}
	return out
}

func (a *API) listServers(w http.ResponseWriter, r *http.Request) {
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, orEmptyT(a.serverRows(snap)))
}

func (a *API) getServer(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	for _, row := range a.serverRows(snap) {
		if row.ID == id {
			var peers []*peerRow
			for _, sb := range snap.Servers {
				if sb.Server.ID == id {
					for _, pb := range sb.Peers {
						peers = append(peers, peerRowOf(pb, sb.Server))
					}
				}
			}
			writeJSON(w, map[string]any{"server": row, "peers": orEmptyT(peers)})
			return
		}
	}
	fail(w, store.ErrNotFound)
}

func (a *API) createServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string  `json:"name"`
		Protocol string  `json:"protocol"`
		Enabled  *bool   `json:"enabled"`
		Settings store.M `json:"settings"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if badLabel(in.Name) {
		errJSON(w, http.StatusBadRequest, "Name fehlt oder ist zu lang")
		return
	}
	sv := &store.Server{Name: in.Name, Protocol: in.Protocol, Enabled: in.Enabled == nil || *in.Enabled, Settings: in.Settings, State: store.M{}}
	if sv.Settings == nil {
		sv.Settings = store.M{}
	}
	if err := a.E.InitServer(sv); err != nil {
		fail(w, err)
		return
	}
	if err := a.St.SaveServer(sv); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Server "+sv.Name+" ("+sv.Protocol+") angelegt")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": sv.ID})
}

func (a *API) updateServer(w http.ResponseWriter, r *http.Request) {
	sv, err := a.St.Server(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	var in struct {
		Name     *string `json:"name"`
		Enabled  *bool   `json:"enabled"`
		Settings store.M `json:"settings"`
		Regen    bool    `json:"regenerate_keys"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if badLabel(n) {
			errJSON(w, http.StatusBadRequest, "Name fehlt oder ist zu lang")
			return
		}
		sv.Name = n
	}
	if in.Enabled != nil {
		sv.Enabled = *in.Enabled
	}
	oldNets := []string{proto.Str(sv.Settings, "net4"), proto.Str(sv.Settings, "net6")}
	if in.Settings != nil {
		sv.Settings = in.Settings
	}
	if in.Regen {
		sv.State = store.M{}
	}
	if err := a.E.InitServer(sv); err != nil {
		fail(w, err)
		return
	}
	// Tunnelnetz geändert → Geräteadressen neu vergeben; neue OpenVPN-CA → neue Zertifikate
	tunnel := sv.Protocol == "wireguard" || sv.Protocol == "openvpn"
	netChanged := tunnel && (oldNets[0] != proto.Str(sv.Settings, "net4") || oldNets[1] != proto.Str(sv.Settings, "net6"))
	if netChanged || (in.Regen && sv.Protocol == "openvpn") {
		peers, _ := a.St.PeersOfServer(sv.ID)
		if netChanged {
			for _, p := range peers {
				delete(p.Settings, "address4")
				delete(p.Settings, "address6")
			}
		}
		var done []*store.Peer
		d, _ := proto.Get(sv.Protocol)
		for _, p := range peers {
			if err := d.InitPeer(a.E.Env(), sv, p, done); err != nil {
				fail(w, fmt.Errorf("Adressen neu vergeben: %w", err))
				return
			}
			done = append(done, p)
		}
		for _, p := range peers {
			_ = a.St.SavePeer(p)
		}
		if netChanged {
			a.E.Log("warn", "Server "+sv.Name+": Tunnelnetz geändert – Geräte brauchen eine neue Konfiguration")
		}
	}
	if err := a.St.SaveServer(sv); err != nil {
		fail(w, err)
		return
	}
	if in.Regen {
		a.E.Log("warn", "Server "+sv.Name+": neue Schlüssel – alle Geräte brauchen eine neue Konfiguration")
	}
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) deleteServer(w http.ResponseWriter, r *http.Request) {
	sv, err := a.St.Server(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteServer(sv.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("warn", "Server "+sv.Name+" mit allen Zugängen gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// network: Daten für die Netzwerk-Ansicht eines WireGuard-Servers.
func (a *API) network(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID != id {
			continue
		}
		if sb.Server.Protocol != "wireguard" {
			errJSON(w, http.StatusBadRequest, "nur für WireGuard-Server")
			return
		}
		reach := wireguard.Reachable(sb)
		type nodeOut struct {
			*peerRow
			Reach []int64 `json:"reach"`
		}
		var nodes []nodeOut
		for _, pb := range sb.Peers {
			rr := reach[pb.Peer.ID]
			if rr == nil {
				rr = []int64{}
			}
			nodes = append(nodes, nodeOut{peerRowOf(pb, sb.Server), rr})
		}
		writeJSON(w, map[string]any{"server": sb.Server, "nodes": orEmptyT(nodes), "public_key": proto.Str(sb.Server.State, "public_key")})
		return
	}
	fail(w, store.ErrNotFound)
}

// ---------- Tarife ----------

func (a *API) listPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := a.St.Plans()
	if err != nil {
		fail(w, err)
		return
	}
	users, _ := a.St.Users()
	count := map[int64]int{}
	for _, u := range users {
		if u.PlanID != nil && u.Limits == nil {
			count[*u.PlanID]++
		}
	}
	type row struct {
		*store.Plan
		Users int `json:"users"`
	}
	var out []row
	for _, p := range plans {
		out = append(out, row{p, count[p.ID]})
	}
	writeJSON(w, orEmptyT(out))
}

func (a *API) savePlan(w http.ResponseWriter, r *http.Request, p *store.Plan) {
	var in store.Plan
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if badLabel(in.Name) {
		errJSON(w, http.StatusBadRequest, "Name fehlt oder ist zu lang")
		return
	}
	if err := engine.ValidateLimits(&in.Limits); err != nil {
		fail(w, err)
		return
	}
	p.Name, p.Description, p.Limits = in.Name, in.Description, in.Limits
	if err := a.St.SavePlan(p); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	writeJSON(w, p)
}

func (a *API) createPlan(w http.ResponseWriter, r *http.Request) { a.savePlan(w, r, &store.Plan{}) }

func (a *API) updatePlan(w http.ResponseWriter, r *http.Request) {
	p, err := a.St.Plan(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.savePlan(w, r, p)
}

func (a *API) deletePlan(w http.ResponseWriter, r *http.Request) {
	if err := a.St.DeletePlan(pathID(r)); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- Einstellungen & System ----------

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.E.Settings()) }

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	for k, v := range in {
		v, err := engine.ValidateSetting(k, v)
		if err != nil {
			errJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		in[k] = v
	}
	for k, v := range in {
		if err := a.St.SetSetting(k, v); err != nil {
			fail(w, err)
			return
		}
	}
	a.E.Log("info", "Einstellungen geändert von "+adminOf(r).Username)
	a.E.RequestApply()
	writeJSON(w, a.E.Settings())
}

func (a *API) system(w http.ResponseWriter, r *http.Request) {
	type check struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	var checks []check
	if h := a.E.Setting("server_host"); h == "" {
		checks = append(checks, check{"Server-Adresse", false, "fehlt – unter Einstellungen eintragen (steht in allen Links und Configs)"})
	} else {
		checks = append(checks, check{"Server-Adresse", true, h})
	}
	for _, bin := range []struct{ name, label string }{{"wg", "WireGuard-Werkzeuge"}, {"xray", "Xray"}, {"hysteria", "Hysteria2"}, {"nginx", "nginx"}, {"tc", "tc (Geschwindigkeitsbegrenzung)"}, {"iptables", "iptables"}, {"ip6tables", "ip6tables"}} {
		_, err := exec.LookPath(bin.name)
		ok := err == nil || a.E.Sys.DryRun()
		d := "vorhanden"
		if !ok {
			d = "fehlt"
		}
		checks = append(checks, check{bin.label, ok, d})
	}
	for _, svc := range []string{"xray", "nginx"} {
		_, err := a.E.Sys.Run("systemctl", "is-active", "--quiet", svc)
		d := "läuft"
		if err != nil {
			d = "läuft nicht"
		}
		checks = append(checks, check{"Dienst " + svc, err == nil, d})
	}
	out, err := a.E.Sys.Run("sysctl", "-n", "net.ipv4.ip_forward")
	checks = append(checks, check{"IPv4-Weiterleitung", err == nil && (strings.TrimSpace(out) == "1" || a.E.Sys.DryRun()), strings.TrimSpace(out)})

	var ports []map[string]any
	servers, _ := a.St.Servers()
	for _, sv := range servers {
		if d, ok := proto.Get(sv.Protocol); ok && sv.Enabled {
			for _, p := range d.Ports(sv) {
				ports = append(ports, map[string]any{"server": sv.Name, "port": p.Port, "to": p.To, "proto": p.Proto, "note": p.Note})
			}
		}
	}
	writeJSON(w, map[string]any{"checks": checks, "errors": a.E.Errors(), "dry_run": a.E.Sys.DryRun(), "dry_log": a.E.Sys.Log(),
		"version": a.Version, "ports": orEmptyM(ports)})
}

func (a *API) applyNow(w http.ResponseWriter, r *http.Request) {
	if err := a.E.Apply(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) collectNow(w http.ResponseWriter, r *http.Request) {
	if err := a.E.Collect(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	ev, err := a.St.Events(limit, r.URL.Query().Get("level"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, orEmptyT(ev))
}
