package api

// Server (WireGuard, VLESS, Hysteria2, OpenVPN, Proxy).

import (
	"fmt"
	"net/http"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/proto/wireguard"
	"vpnpanel/internal/store"
)

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

// serverTotals: Verkehr je Server heute, diese Woche, diesen Monat, dieses Jahr (Kalender in ?tz=) und 30 Tage.
func (a *API) serverTotals(w http.ResponseWriter, r *http.Request) {
	out := map[string]map[int64]store.ExitTotals{}
	for k, since := range calStarts(r) {
		t, err := a.St.TrafficByServer(since)
		if err != nil {
			fail(w, err)
			return
		}
		out[k] = t
	}
	writeJSON(w, map[string]any{"totals": out})
}
