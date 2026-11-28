package api

// Nutzer: Liste, Anlegen, Ändern, Löschen, Verlauf.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

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
	if filter == "" { // Gesamtverlauf: SmartDNS als eigene Reihe (VPN-Anteil und ohne VPN)
		if sm, err := a.St.SmartTrafficSeries(since, until, bucket); err == nil && len(sm) > 0 {
			at := map[int64]int{}
			for i, p := range s {
				at[p.TS] = i
			}
			for ts, v := range sm {
				i, ok := at[ts]
				if !ok {
					s = append(s, store.TrafficPoint{TS: ts})
					i = len(s) - 1
				}
				s[i].SVU, s[i].SVD, s[i].SPU, s[i].SPD = v.VUp, v.VDown, v.PUp, v.PDown
			}
			sort.Slice(s, func(i, j int) bool { return s[i].TS < s[j].TS })
		}
	}
	writeJSON(w, map[string]any{"bucket": bucket, "since": since, "until": until, "points": orEmptyT(s)})
}

func (a *API) userTraffic(w http.ResponseWriter, r *http.Request) { a.series(w, r, "user", pathID(r)) }
func (a *API) peerTraffic(w http.ResponseWriter, r *http.Request) { a.series(w, r, "peer", pathID(r)) }
func (a *API) serverTraffic(w http.ResponseWriter, r *http.Request) {
	a.series(w, r, "server", pathID(r))
}
func (a *API) traffic(w http.ResponseWriter, r *http.Request) { a.series(w, r, "", 0) }
