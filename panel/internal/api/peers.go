package api

// Zugänge (Geräte/Peers) eines Nutzers.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

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
