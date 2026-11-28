package engine

// Statistik einsammeln (Collect) und Abfragen für Oberfläche und Abo.

import (
	"crypto/subtle"
	"fmt"
	"log"
	"time"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// ---------- Statistik ----------

func (e *Engine) Collect() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	unlock, err := lockFile(e.Cfg.LockPath)
	if err != nil {
		return err
	}
	defer unlock()
	if err := e.collectLocked(); err != nil {
		return err
	}
	// Hat sich durch den Verbrauch ein Status geändert (Limit, Drosselstufe, Ablauf)? → anwenden
	snap, err := e.Snapshot()
	if err != nil {
		return err
	}
	verdicts := e.saveVerdicts(snap)
	if e.checkExitLimits() || verdicts {
		return e.applyLocked()
	}
	e.shapeExits() // neu verbundene Ausgänge wieder drosseln
	return nil
}

func (e *Engine) collectLocked() error {
	snap, err := e.Snapshot()
	if err != nil {
		return err
	}
	env := e.Env()
	now := time.Now()
	ts := now.Unix()
	userDelta := map[int64][2]int64{}
	userSeen := map[int64]int64{}
	for _, d := range proto.All() {
		id := d.Info().ID
		bundles := snap.ByProto[id]
		if len(bundles) == 0 {
			continue
		}
		usage, err := d.Collect(env, bundles)
		if err != nil {
			e.setErr("collect:"+id, err.Error())
			continue
		}
		e.setErr("collect:"+id, "")
		for _, sb := range bundles {
			for _, pb := range sb.Peers {
				p := pb.Peer
				u, ok := usage[p.ID]
				if ok {
					p.TotalUp += u.Up
					p.TotalDown += u.Down
					if u.Seen > p.LastSeen {
						p.LastSeen = u.Seen
					}
					if u.Handshake > 0 {
						p.Handshake = u.Handshake
					}
					if u.Endpoint != "" {
						p.Endpoint = u.Endpoint
					}
					if u.Up+u.Down > 0 {
						_ = e.St.AddTraffic(p.ID, p.UserID, p.ServerID, ts, u.Up, u.Down)
						d := userDelta[p.UserID]
						userDelta[p.UserID] = [2]int64{d[0] + u.Up, d[1] + u.Down}
					}
					if p.LastSeen > userSeen[p.UserID] {
						userSeen[p.UserID] = p.LastSeen
					}
				}
				_ = e.St.SavePeer(p) // auch Rohzähler (LastRx/LastTx) sichern
			}
		}
	}
	e.collectExitTraffic(ts)
	e.collectSmart(now)
	// Nutzer: Zeitraum prüfen, Verbrauch addieren
	for id, u := range snap.Users {
		changed := false
		l := EffectiveLimits(u, snap.Plans)
		if ps := PeriodStart(l, now); ps > 0 && u.PeriodStart < ps {
			if u.PeriodUp+u.PeriodDown > 0 {
				e.Log("info", fmt.Sprintf("Nutzer %s: neuer Abrechnungszeitraum, Verbrauch zurückgesetzt", u.Name))
			}
			u.PeriodStart, u.PeriodUp, u.PeriodDown = ps, 0, 0
			changed = true
		}
		if d, ok := userDelta[id]; ok {
			u.PeriodUp += d[0]
			u.PeriodDown += d[1]
			u.TotalUp += d[0]
			u.TotalDown += d[1]
			changed = true
		}
		if s := userSeen[id]; s > u.LastSeen {
			u.LastSeen = s
			changed = true
		}
		if changed {
			_ = e.St.SaveUser(u)
		}
	}
	return nil
}

// Run: Hintergrundschleife für Statistik und gebündeltes Anwenden.
func (e *Engine) Run(stop <-chan struct{}) {
	interval := time.Duration(atoi(e.Setting("collect_interval"), 60)) * time.Second
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-stop:
			if err := e.Collect(); err != nil {
				log.Printf("collect beim Beenden: %v", err)
			}
			return
		case <-tick.C:
			if err := e.Collect(); err != nil {
				log.Printf("collect: %v", err)
			}
		case <-e.applyCh:
			time.Sleep(700 * time.Millisecond) // weitere Änderungen bündeln
			select {
			case <-e.applyCh:
			default:
			}
			_ = e.Apply()
		case <-prune.C:
			days := atoi(e.Setting("traffic_retention"), 180)
			_ = e.St.PruneTraffic(time.Now().AddDate(0, 0, -days).Unix())
			e.St.PruneSessions()
		}
	}
}

// ---------- Abfragen für Oberfläche und Abo ----------

func (e *Engine) ClientConfig(peerID int64) (*proto.ClientConfig, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return nil, err
	}
	pb := snap.Peers[peerID]
	if pb == nil {
		return nil, store.ErrNotFound
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID == pb.Peer.ServerID {
			d, ok := proto.Get(sb.Server.Protocol)
			if !ok {
				return nil, fmt.Errorf("Protokoll %s unbekannt", sb.Server.Protocol)
			}
			return d.ClientConfig(e.Env(), sb, pb)
		}
	}
	return nil, store.ErrNotFound
}

// OpenVPNProfile: .ovpn-Datei eines aktiven OpenVPN-Zugangs, der dem Nutzer gehört.
func (e *Engine) OpenVPNProfile(userID, peerID int64) (name, body string, err error) {
	snap, err := e.Snapshot()
	if err != nil {
		return "", "", err
	}
	pb := snap.Peers[peerID]
	if pb == nil || pb.User.ID != userID || !pb.Active {
		return "", "", store.ErrNotFound
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID == pb.Peer.ServerID && sb.Server.Protocol == "openvpn" {
			d, _ := proto.Get("openvpn")
			cc, err := d.ClientConfig(e.Env(), sb, pb)
			if err != nil || len(cc.Files) == 0 {
				return "", "", store.ErrNotFound
			}
			return cc.Files[0].Name, cc.Files[0].Content, nil
		}
	}
	return "", "", store.ErrNotFound
}

// SubLinks: alle Links eines Nutzers für das Abo.
func (e *Engine) SubLinks(userID int64) ([]string, error) { return e.SubLinksFor(userID, "") }

// SubLinksFor: Links für eine bestimmte App-Familie (siehe proto.Global.Client).
func (e *Engine) SubLinksFor(userID int64, client string) ([]string, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return nil, err
	}
	env := e.Env()
	env.Global.Client = client
	var out []string
	for _, sb := range snap.Servers {
		if !sb.Server.Enabled {
			continue
		}
		d, ok := proto.Get(sb.Server.Protocol)
		if !ok {
			continue
		}
		for _, pb := range sb.Peers {
			if pb.Peer.UserID == userID && pb.Peer.Enabled {
				out = append(out, d.ShareLinks(env, sb, pb)...)
			}
		}
	}
	return out, nil
}

// Hook beantwortet interne Anfragen eines Dienstes (z. B. Hysteria2-Anmeldung).
func (e *Engine) Hook(serverID int64, secret string, body []byte) (any, error) {
	snap, err := e.Snapshot()
	if err != nil {
		return nil, err
	}
	for _, sb := range snap.Servers {
		if sb.Server.ID != serverID {
			continue
		}
		want := proto.Str(sb.Server.State, "hook_secret")
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(secret)) != 1 {
			return nil, store.ErrNotFound
		}
		d, ok := proto.Get(sb.Server.Protocol)
		h, ok2 := d.(proto.Hooker)
		if !ok || !ok2 {
			return nil, store.ErrNotFound
		}
		resp, reshape, err := h.Hook(e.Env(), sb, body)
		if reshape {
			e.RequestApply()
		}
		return resp, err
	}
	return nil, store.ErrNotFound
}

// InitServer setzt Vorgaben über den Treiber.
func (e *Engine) InitServer(sv *store.Server) error {
	d, ok := proto.Get(sv.Protocol)
	if !ok {
		return fmt.Errorf("unbekanntes Protokoll %q", sv.Protocol)
	}
	all, err := e.St.Servers()
	if err != nil {
		return err
	}
	if sv.Settings == nil {
		sv.Settings = store.M{}
	}
	if sv.State == nil {
		sv.State = store.M{}
	}
	return d.InitServer(e.Env(), sv, all)
}

func (e *Engine) InitPeer(sv *store.Server, p *store.Peer) error {
	d, ok := proto.Get(sv.Protocol)
	if !ok {
		return fmt.Errorf("unbekanntes Protokoll %q", sv.Protocol)
	}
	others, err := e.St.PeersOfServer(sv.ID)
	if err != nil {
		return err
	}
	if p.Settings == nil {
		p.Settings = store.M{}
	}
	if p.Secrets == nil {
		p.Secrets = store.M{}
	}
	return d.InitPeer(e.Env(), sv, p, others)
}
