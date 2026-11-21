package api

import (
	"net/http"
	"sort"
	"time"

	"vpnpanel/internal/engine"
)

// Statistik je SmartDNS-Profil (DNS → SmartDNS → Statistik).

type smartHourOut struct {
	T     int64 `json:"t"` // Beginn der Stunde (Unix)
	Q     int64 `json:"q"`
	Bytes int64 `json:"bytes"`
}

type smartRouteOut struct {
	Idx     int    `json:"idx"`
	Group   int64  `json:"group"`
	Name    string `json:"name"`
	Domains int    `json:"domains"`
	Q       int64  `json:"q"`
	Bytes   int64  `json:"bytes"`
	Conns   int64  `json:"conns"`
	Last    int64  `json:"last"`
}

type smartDomOut struct {
	Domain string `json:"domain"`
	Route  int    `json:"route"`
	Q      int64  `json:"q"`
	Bytes  int64  `json:"bytes"`
	Conns  int64  `json:"conns"`
	Last   int64  `json:"last"`
	Err    string `json:"err,omitempty"`
}

type smartNameOut struct {
	Name string `json:"name"`
	Q    int64  `json:"q"`
	Last int64  `json:"last"`
}

type smartDevOut struct {
	Kind  string `json:"kind"` // peer | client
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Sub   string `json:"sub"`
	Q     int64  `json:"q"`
	Bytes int64  `json:"bytes"`
	Conns int64  `json:"conns"`
	Last  int64  `json:"last"`
}

type smartStatOut struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Enabled   bool            `json:"enabled"`
	Since     int64           `json:"since"`
	Last      int64           `json:"last"`
	Queries   int64           `json:"queries"`
	Q24       int64           `json:"q24"`
	Bytes24   int64           `json:"bytes24"`
	Up        int64           `json:"up"`
	Down      int64           `json:"down"`
	Proxy     int64           `json:"proxy"`
	Conns     int64           `json:"conns"`
	Devices24 int             `json:"devices24"` // Geräte, die in 24 h gefragt haben
	Hours     []smartHourOut  `json:"hours"`     // die letzten 7 Tage, jede Stunde
	Routes    []smartRouteOut `json:"routes"`
	Domains   []smartDomOut   `json:"domains"` // alle Einträge des Profils, meistgenutzte zuerst
	Names     []smartNameOut  `json:"names"`   // meistgefragte Namen
	Devices   []smartDevOut   `json:"devices"` // aktivste Geräte
	Unused    []string        `json:"unused"`  // Einträge, die noch nie gegriffen haben
	Errors    int             `json:"errors"`  // Einträge mit Fehler beim Proxy
}

func (a *API) smartStats(w http.ResponseWriter, r *http.Request) {
	stats := a.E.SmartStats()
	objs, err := a.St.Objects("smartdns")
	if err != nil {
		fail(w, err)
		return
	}
	groups := map[int64]string{}
	if gs, err := a.St.Objects("group"); err == nil {
		for _, o := range gs {
			groups[o.ID] = o.Name
		}
	}
	snap, err := a.E.Snapshot()
	if err != nil {
		fail(w, err)
		return
	}
	clients := map[int64]string{}
	if cs, err := a.St.Objects("dnsclient"); err == nil {
		for _, o := range cs {
			clients[o.ID] = o.Name
		}
	}
	srvName := map[int64]string{}
	for _, sb := range snap.Servers {
		srvName[sb.Server.ID] = sb.Server.Name
	}
	now := time.Now().Unix()
	nowH := now / 3600
	out := []smartStatOut{}
	for _, o := range objs {
		p := engine.SmartProfileFrom(o)
		st := stats[p.ID]
		if st == nil {
			st = &engine.SmartProfStat{Routes: map[int]*engine.SmartCount{}, Domains: map[string]*engine.SmartCount{},
				Names: map[string]*engine.SmartCount{}, Devices: map[int64]*engine.SmartCount{}, Hours: map[int64]*engine.SmartCount{}}
		}
		row := smartStatOut{ID: p.ID, Name: p.Name, Enabled: p.Enabled, Since: st.Since, Last: st.Last, Queries: st.Queries,
			Up: st.Up, Down: st.Down, Proxy: st.Proxy, Conns: st.Conns, Unused: []string{}}
		for h := nowH - 7*24 + 1; h <= nowH; h++ {
			pt := smartHourOut{T: h * 3600}
			if c := st.Hours[h]; c != nil {
				pt.Q, pt.Bytes = c.Q, c.Bytes
			}
			if h > nowH-24 {
				row.Q24 += pt.Q
				row.Bytes24 += pt.Bytes
			}
			row.Hours = append(row.Hours, pt)
		}
		// Weiterleitungen und Einträge laut Profil (auch ohne Treffer)
		seen := map[string]bool{}
		for i, rt := range p.Routes {
			ro := smartRouteOut{Idx: i, Group: rt.Group, Name: groups[rt.Group], Domains: len(rt.Domains)}
			if c := st.Routes[i]; c != nil {
				ro.Q, ro.Bytes, ro.Conns, ro.Last = c.Q, c.Bytes, c.Conns, c.Last
			}
			row.Routes = append(row.Routes, ro)
			for _, d := range rt.Domains {
				if seen[d] {
					continue
				}
				seen[d] = true
				do := smartDomOut{Domain: d, Route: i}
				if c := st.Domains[d]; c != nil {
					do.Q, do.Bytes, do.Conns, do.Last, do.Err = c.Q, c.Bytes, c.Conns, c.Last, c.Err
				}
				if do.Q == 0 && do.Conns == 0 {
					row.Unused = append(row.Unused, d)
				}
				if do.Err != "" {
					row.Errors++
				}
				row.Domains = append(row.Domains, do)
			}
		}
		sort.SliceStable(row.Domains, func(i, j int) bool {
			if row.Domains[i].Q != row.Domains[j].Q {
				return row.Domains[i].Q > row.Domains[j].Q
			}
			return row.Domains[i].Bytes > row.Domains[j].Bytes
		})
		for n, c := range st.Names {
			row.Names = append(row.Names, smartNameOut{Name: n, Q: c.Q, Last: c.Last})
		}
		sort.Slice(row.Names, func(i, j int) bool {
			if row.Names[i].Q != row.Names[j].Q {
				return row.Names[i].Q > row.Names[j].Q
			}
			return row.Names[i].Name < row.Names[j].Name
		})
		if len(row.Names) > 15 {
			row.Names = row.Names[:15]
		}
		for id, c := range st.Devices {
			if c.Last >= now-86400 {
				row.Devices24++
			}
			d := smartDevOut{ID: id, Q: c.Q, Bytes: c.Bytes, Conns: c.Conns, Last: c.Last}
			if id < 0 {
				d.Kind, d.ID, d.Name, d.Sub = "client", -id, clients[-id], "ohne VPN"
				if d.Name == "" {
					d.Name = "gelöschtes Gerät"
				}
			} else {
				d.Kind = "peer"
				if pb := snap.Peers[id]; pb != nil {
					d.Name, d.Sub = pb.Peer.Name, pb.User.Name+" · "+srvName[pb.Peer.ServerID]
				} else {
					d.Name = "gelöschtes Gerät"
				}
			}
			row.Devices = append(row.Devices, d)
		}
		sort.Slice(row.Devices, func(i, j int) bool {
			if row.Devices[i].Q != row.Devices[j].Q {
				return row.Devices[i].Q > row.Devices[j].Q
			}
			return row.Devices[i].Last > row.Devices[j].Last
		})
		if len(row.Devices) > 20 {
			row.Devices = row.Devices[:20]
		}
		if row.Names == nil {
			row.Names = []smartNameOut{}
		}
		if row.Devices == nil {
			row.Devices = []smartDevOut{}
		}
		if row.Routes == nil {
			row.Routes = []smartRouteOut{}
		}
		if row.Domains == nil {
			row.Domains = []smartDomOut{}
		}
		out = append(out, row)
	}
	writeJSON(w, out)
}

// POST /api/dns/smart/stats/reset {id} – 0 = alle Profile.
func (a *API) resetSmartStats(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID int64 `json:"id"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	a.E.ResetSmartStats(in.ID)
	writeJSON(w, map[string]bool{"ok": true})
}
