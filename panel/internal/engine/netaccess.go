package engine

import (
	"net/netip"
	"sort"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// Zugriff auf Netze (Objekte der Art „netaccess“, Netzwerk → Zugriff): Geräte bestimmter Nutzer,
// Tarife oder einzelne Geräte dürfen WireGuard-Netze erreichen – das Tunnelnetz eines Servers und
// die Netze hinter dessen Geräten (Homelab). Gilt für Geräte, deren Verkehr weitergeleitet wird
// (WireGuard, OpenVPN), auch von einem anderen Server aus. Die Treiber setzen daraus Firewall-Regeln,
// NAT und die Routen der Geräte (AllowedIPs bzw. „push route“).

// NetGrant: eine Freigabe.
type NetGrant struct {
	ID      int64   `json:"id"`
	Name    string  `json:"name"`
	Enabled bool    `json:"enabled"`
	Servers []int64 `json:"servers"` // Ziel-Netze (WireGuard-Server)
	All     bool    `json:"all"`     // alle Nutzer
	Users   []int64 `json:"users"`
	Plans   []int64 `json:"plans"`
	Peers   []int64 `json:"peers"`
	Note    string  `json:"note"`
}

func idList(v any) []int64 {
	if a, ok := v.([]int64); ok {
		return a
	}
	return ids(v)
}

// NetGrantFrom liest eine Freigabe aus dem gespeicherten Objekt.
func NetGrantFrom(o *store.Object) *NetGrant {
	g := &NetGrant{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Servers: idList(o.Data["servers"]), Users: idList(o.Data["users"]),
		Plans: idList(o.Data["plans"]), Peers: idList(o.Data["peers"])}
	g.All, _ = o.Data["all"].(bool)
	g.Note, _ = o.Data["note"].(string)
	return g
}

// Matches: gilt die Freigabe für diesen Zugang?
func (g *NetGrant) Matches(pb *proto.PeerBundle) bool {
	if g.All {
		return true
	}
	for _, id := range g.Peers {
		if id == pb.Peer.ID {
			return true
		}
	}
	for _, id := range g.Users {
		if id == pb.User.ID {
			return true
		}
	}
	if pb.User.PlanID != nil {
		for _, id := range g.Plans {
			if id == *pb.User.PlanID {
				return true
			}
		}
	}
	return false
}

type netInfo struct {
	name  string
	iface string
	nets  []netip.Prefix
}

// networks: alle aktiven Server, die ein Netz bilden (WireGuard), mit Schnittstelle und Netzen.
func networks(snap *Snapshot) map[int64]netInfo {
	out := map[int64]netInfo{}
	for _, sb := range snap.Servers {
		if !sb.Server.Enabled {
			continue
		}
		d, ok := proto.Get(sb.Server.Protocol)
		if !ok {
			continue
		}
		nw, ok := d.(proto.Networker)
		if !ok {
			continue
		}
		iface, nets := nw.Network(sb)
		if iface == "" || len(nets) == 0 {
			continue
		}
		out[sb.Server.ID] = netInfo{name: sb.Server.Name, iface: iface, nets: nets}
	}
	return out
}

// netLocal: Protokolle, deren Verkehr vom Server selbst ausgeht und die Nutzer einzeln leiten können
// (VLESS über Xray) – Freigaben wirken dort ohne NAT (Absender ist schon der Server).
var netLocal = map[string]bool{"vless": true}

// compileNetAccess: Freigaben → erreichbare Netze je Zugang und NAT je Ziel-Schnittstelle.
func (e *Engine) compileNetAccess(snap *Snapshot) *proto.NetAccess {
	objs, _ := e.St.Objects("netaccess")
	var grants []*NetGrant
	for _, o := range objs {
		if g := NetGrantFrom(o); g.Enabled && len(g.Servers) > 0 {
			grants = append(grants, g)
		}
	}
	if len(grants) == 0 {
		return nil
	}
	nets := networks(snap)
	na := &proto.NetAccess{Targets: map[int64][]proto.NetTarget{}, Masq: map[string][]netip.Prefix{}}
	masqSeen := map[string]map[netip.Prefix]bool{}
	env := &proto.Env{}
	for _, d := range proto.All() {
		f, fwd := d.(proto.Forwarder)
		if !fwd && !netLocal[d.Info().ID] {
			continue
		}
		for _, sb := range snap.ByProto[d.Info().ID] {
			if !sb.Server.Enabled {
				continue
			}
			var srcs map[int64][]netip.Prefix
			if fwd {
				srcs = f.Sources(env, sb)
			}
			for _, pb := range sb.Peers {
				if !pb.Active {
					continue
				}
				seen := map[int64]bool{}
				for _, g := range grants {
					if !g.Matches(pb) {
						continue
					}
					for _, sid := range g.Servers {
						n, ok := nets[sid]
						if !ok || seen[sid] {
							continue
						}
						seen[sid] = true
						na.Targets[pb.Peer.ID] = append(na.Targets[pb.Peer.ID], proto.NetTarget{Server: sid, Name: n.name, Iface: n.iface, Nets: n.nets})
						if sid == sb.Server.ID {
							continue // eigenes Netz: Geräte kennen den Rückweg
						}
						if masqSeen[n.iface] == nil {
							masqSeen[n.iface] = map[netip.Prefix]bool{}
						}
						for _, p := range srcs[pb.Peer.ID] {
							p = p.Masked()
							if !masqSeen[n.iface][p] {
								masqSeen[n.iface][p] = true
								na.Masq[n.iface] = append(na.Masq[n.iface], p)
							}
						}
					}
				}
				ts := na.Targets[pb.Peer.ID]
				sort.Slice(ts, func(i, j int) bool { return ts[i].Server < ts[j].Server })
			}
		}
	}
	for k, ps := range na.Masq {
		sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
		na.Masq[k] = ps
	}
	return na
}

// NetTargetsOf: Netze, die ein Zugang über Freigaben erreicht (für die Oberfläche).
func (e *Engine) NetTargetsOf(peer int64) []proto.NetTarget { return e.routing().Net.For(peer) }

// NetworkInfo: ein Netz für die Oberfläche (Netzwerk → Zugriff).
type NetworkInfo struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Iface   string   `json:"iface"`
	Nets    []string `json:"nets"`
	Devices int      `json:"devices"` // aktive Geräte im Netz
}

// Networks: alle aktiven WireGuard-Netze.
func (e *Engine) Networks() []NetworkInfo {
	snap, err := e.Snapshot()
	if err != nil {
		return nil
	}
	out := []NetworkInfo{}
	all := networks(snap)
	for _, sb := range snap.Servers {
		n, ok := all[sb.Server.ID]
		if !ok {
			continue
		}
		ni := NetworkInfo{ID: sb.Server.ID, Name: n.name, Iface: n.iface, Nets: []string{}}
		for _, p := range n.nets {
			ni.Nets = append(ni.Nets, p.String())
		}
		for _, pb := range sb.Peers {
			if pb.Active {
				ni.Devices++
			}
		}
		out = append(out, ni)
	}
	return out
}

// GrantReach: wie viele Geräte eine Freigabe betrifft. Devices = WireGuard/OpenVPN (wirkt),
// Other = Zugänge anderer Protokolle (Hysteria2, Proxy – dort wirkt sie nicht).
type GrantReach struct {
	Devices int      `json:"devices"`
	Other   int      `json:"other"`
	Users   int      `json:"users"`
	Names   []string `json:"names"` // die ersten Geräte („Nutzer · Gerät“)
}

func (e *Engine) GrantReach(gs []*NetGrant) map[int64]GrantReach {
	out := map[int64]GrantReach{}
	snap, err := e.Snapshot()
	if err != nil {
		return out
	}
	fwd := map[string]bool{}
	for _, d := range proto.All() {
		if _, ok := d.(proto.Forwarder); ok {
			fwd[d.Info().ID] = true
		}
	}
	for _, g := range gs {
		r := GrantReach{Names: []string{}}
		users := map[int64]bool{}
		for _, sb := range snap.Servers {
			for _, pb := range sb.Peers {
				if !pb.Peer.Enabled || !g.Matches(pb) {
					continue
				}
				if !fwd[sb.Server.Protocol] && !netLocal[sb.Server.Protocol] {
					r.Other++
					continue
				}
				r.Devices++
				users[pb.User.ID] = true
				if len(r.Names) < 6 {
					r.Names = append(r.Names, pb.User.Name+" · "+pb.Peer.Name)
				}
			}
		}
		r.Users = len(users)
		out[g.ID] = r
	}
	return out
}
