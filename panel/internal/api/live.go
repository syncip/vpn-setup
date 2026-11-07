package api

import (
	"net/http"
	"sort"
	"strconv"

	"vpnpanel/internal/engine"
)

// GET /api/live – aktuelle Geschwindigkeiten und Verbindungen.
// Optional ?user=<id> oder ?peer=<id> bzw. ?server=<id>: Verlauf nur dafür.
func (a *API) live(w http.ResponseWriter, r *http.Request) {
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	ld := a.E.Live()
	q := r.URL.Query()
	fUser, _ := strconv.ParseInt(q.Get("user"), 10, 64)
	fPeer, _ := strconv.ParseInt(q.Get("peer"), 10, 64)
	fServer, _ := strconv.ParseInt(q.Get("server"), 10, 64)

	type peerRow struct {
		ID       int64   `json:"id"`
		Name     string  `json:"name"`
		UserID   int64   `json:"user_id"`
		User     string  `json:"user"`
		ServerID int64   `json:"server_id"`
		Server   string  `json:"server"`
		Protocol string  `json:"protocol"`
		Up       float64 `json:"up"`
		Down     float64 `json:"down"`
		Online   bool    `json:"online"`
		Endpoint string  `json:"endpoint,omitempty"`
		Since    int64   `json:"since,omitempty"`
	}
	type agg struct {
		ID       int64   `json:"id"`
		Name     string  `json:"name"`
		Protocol string  `json:"protocol,omitempty"`
		Up       float64 `json:"up"`
		Down     float64 `json:"down"`
		Online   int     `json:"online"`
		Total    int     `json:"total"`
	}
	serverName := map[int64]*agg{}
	for _, sb := range snap.Servers {
		serverName[sb.Server.ID] = &agg{ID: sb.Server.ID, Name: sb.Server.Name, Protocol: sb.Server.Protocol, Total: len(sb.Peers)}
	}
	users := map[int64]*agg{}
	var peers []peerRow
	var totalUp, totalDown float64
	online := 0
	for id, pb := range snap.Peers {
		u := users[pb.Peer.UserID]
		if u == nil && pb.User != nil {
			u = &agg{ID: pb.User.ID, Name: pb.User.Name}
			users[pb.Peer.UserID] = u
		}
		if u != nil {
			u.Total++
		}
		lp := ld.Peers[id]
		if lp == nil {
			continue
		}
		sv := serverName[pb.Peer.ServerID]
		row := peerRow{ID: id, Name: pb.Peer.Name, UserID: pb.Peer.UserID, ServerID: pb.Peer.ServerID,
			Up: lp.Up, Down: lp.Down, Online: lp.Online, Endpoint: lp.Endpoint, Since: lp.Since}
		if u != nil {
			row.User = u.Name
			u.Up += lp.Up
			u.Down += lp.Down
			if lp.Online {
				u.Online++
			}
		}
		if sv != nil {
			row.Server, row.Protocol = sv.Name, sv.Protocol
			sv.Up += lp.Up
			sv.Down += lp.Down
			if lp.Online {
				sv.Online++
			}
		}
		totalUp += lp.Up
		totalDown += lp.Down
		if lp.Online {
			online++
			peers = append(peers, row)
		}
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Up+peers[i].Down != peers[j].Up+peers[j].Down {
			return peers[i].Up+peers[i].Down > peers[j].Up+peers[j].Down
		}
		return peers[i].ID < peers[j].ID
	})
	var userRows, serverRows []*agg
	usersOnline := 0
	for _, u := range users {
		if u.Online > 0 {
			usersOnline++
			userRows = append(userRows, u)
		}
	}
	sort.Slice(userRows, func(i, j int) bool {
		if userRows[i].Up+userRows[i].Down != userRows[j].Up+userRows[j].Down {
			return userRows[i].Up+userRows[i].Down > userRows[j].Up+userRows[j].Down
		}
		return userRows[i].ID < userRows[j].ID
	})
	for _, sb := range snap.Servers {
		serverRows = append(serverRows, serverName[sb.Server.ID])
	}

	// Verlauf: gesamt oder gefiltert (Summe der passenden Zugänge pro Messzeitpunkt)
	hist := ld.History
	if fUser > 0 || fPeer > 0 || fServer > 0 {
		sum := map[int64]*engine.LivePoint{}
		for id, h := range ld.PeerHist {
			pb := snap.Peers[id]
			if pb == nil || (fUser > 0 && pb.Peer.UserID != fUser) || (fPeer > 0 && id != fPeer) || (fServer > 0 && pb.Peer.ServerID != fServer) {
				continue
			}
			for _, p := range h {
				s := sum[p.TS]
				if s == nil {
					s = &engine.LivePoint{TS: p.TS}
					sum[p.TS] = s
				}
				s.Up += p.Up
				s.Down += p.Down
			}
		}
		// gleiche Zeitachse wie der Gesamtverlauf, fehlende Punkte = 0
		hist = make([]engine.LivePoint, 0, len(ld.History))
		for _, p := range ld.History {
			if s := sum[p.TS]; s != nil {
				hist = append(hist, *s)
			} else {
				hist = append(hist, engine.LivePoint{TS: p.TS})
			}
		}
	}
	writeJSON(w, map[string]any{
		"ts": ld.TS, "interval": ld.Interval, "history": orEmptyA(hist),
		"total":   map[string]any{"up": totalUp, "down": totalDown, "peers_online": online, "users_online": usersOnline, "peers": len(snap.Peers), "users": len(snap.Users)},
		"peers":   orEmptyA(peers),
		"users":   orEmptyA(userRows),
		"servers": orEmptyA(serverRows),
		"errors":  ld.Errors,
	})
}
