package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// Panel-DNS: Einstellungen, Filterprofile, Blocklisten, Protokoll und Auswertung.

type dnsProfileRow struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Lists    []int64  `json:"lists"`
	Rules    string   `json:"rules"`
	Assign   []string `json:"assign"`
	BlockDoH bool     `json:"block_doh"`
	NXDomain bool     `json:"nxdomain"`
	Error    string   `json:"error,omitempty"` // Fehler in den eigenen Regeln
}

type dnsListRow struct {
	ID      int64              `json:"id"`
	Name    string             `json:"name"`
	Enabled bool               `json:"enabled"`
	Mode    string             `json:"mode"`
	URL     string             `json:"url"`
	Refresh int                `json:"refresh"`
	Entries []string           `json:"entries"`
	Total   int                `json:"total"`
	Status  *engine.ListStatus `json:"status,omitempty"`
	UsedBy  []string           `json:"used_by"`
}

// dnsPresets: bekannte Blocklisten zum schnellen Hinzufügen.
var dnsPresets = []map[string]string{
	{"name": "HaGeZi Multi PRO", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", "note": "Werbung, Tracking, Schadseiten – ausgewogen"},
	{"name": "HaGeZi Multi NORMAL", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt", "note": "etwas weniger streng"},
	{"name": "HaGeZi Threat Intelligence", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt", "note": "Schadsoftware, Phishing, Betrug"},
	{"name": "OISD big", "url": "https://big.oisd.nl/", "note": "Werbung und Tracking, wenig Fehlalarme"},
	{"name": "AdGuard DNS filter", "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "note": "Liste des AdGuard-DNS"},
	{"name": "StevenBlack Unified", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "note": "Hosts-Datei: Werbung und Schadseiten"},
}

func (a *API) dnsOverview(w http.ResponseWriter, r *http.Request) {
	profiles := []*dnsProfileRow{}
	if objs, err := a.St.Objects("dnsprofile"); err == nil {
		for _, o := range objs {
			p := engine.DNSProfileFrom(o)
			row := &dnsProfileRow{ID: p.ID, Name: p.Name, Enabled: p.Enabled, Lists: orInts(p.Lists), Rules: p.Rules,
				Assign: orStrings(p.Assign), BlockDoH: p.BlockDoH, NXDomain: p.NXDomain}
			if _, err := engine.ParseDNSRules(p.Rules); err != nil {
				row.Error = err.Error()
			}
			profiles = append(profiles, row)
		}
	}
	lists := []*dnsListRow{}
	if objs, err := a.St.Objects("dnslist"); err == nil {
		for _, o := range objs {
			l := engine.DNSListFrom(o)
			row := &dnsListRow{ID: l.ID, Name: l.Name, Enabled: l.Enabled, Mode: l.Mode, URL: l.URL, Refresh: l.Refresh,
				Entries: orStrings(l.Entries), UsedBy: orStrings(a.E.ProfilesUsing(l.ID))}
			st, total := a.E.DNSListInfo(o)
			row.Total = total
			if l.URL != "" {
				row.Status = &st
			}
			lists = append(lists, row)
		}
	}
	info := a.E.DNSInfo()
	info.Rules = nil
	errs := a.E.Errors()
	writeJSON(w, map[string]any{
		"settings": map[string]string{"enabled": a.E.Setting("dns_enabled"), "upstream": a.E.Setting("dns_upstream"), "log_days": a.E.Setting("dns_log_days")},
		"info":     info, "profiles": profiles, "lists": lists, "presets": dnsPresets, "dry_run": a.E.Sys.DryRun(),
		"error": strings.TrimSpace(errs["dns"] + " " + errs["dnslog"]), "choices": a.scopeChoices(),
	})
}

// scopeChoices: Server, Nutzer und Geräte für Auswahlfelder.
func (a *API) scopeChoices() map[string]any {
	type opt struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol,omitempty"`
		UserID   int64  `json:"user_id,omitempty"`
		ServerID int64  `json:"server_id,omitempty"`
		Enabled  bool   `json:"enabled"`
	}
	servers, _ := a.St.Servers()
	users, _ := a.St.Users()
	peers, _ := a.St.Peers()
	sOpts, uOpts, pOpts := []opt{}, []opt{}, []opt{}
	proto := map[int64]string{}
	for _, s := range servers {
		proto[s.ID] = s.Protocol
		sOpts = append(sOpts, opt{ID: s.ID, Name: s.Name, Protocol: s.Protocol, Enabled: s.Enabled})
	}
	for _, u := range users {
		uOpts = append(uOpts, opt{ID: u.ID, Name: u.Name, Enabled: u.Enabled})
	}
	for _, p := range peers {
		pOpts = append(pOpts, opt{ID: p.ID, Name: p.Name, Protocol: proto[p.ServerID], UserID: p.UserID, ServerID: p.ServerID, Enabled: p.Enabled})
	}
	gOpts := []opt{}
	if gs, err := a.St.Objects("group"); err == nil {
		for _, o := range gs {
			gOpts = append(gOpts, opt{ID: o.ID, Name: o.Name, Enabled: o.Enabled})
		}
	}
	return map[string]any{"servers": sOpts, "users": uOpts, "peers": pOpts, "groups": gOpts}
}

func (a *API) dnsSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled  *bool   `json:"enabled"`
		Upstream *string `json:"upstream"`
		LogDays  *int    `json:"log_days"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	set := map[string]string{}
	if in.Enabled != nil {
		set["dns_enabled"] = map[bool]string{true: "1", false: "0"}[*in.Enabled]
	}
	if in.Upstream != nil {
		set["dns_upstream"] = *in.Upstream
	}
	if in.LogDays != nil {
		set["dns_log_days"] = strconv.Itoa(*in.LogDays)
	}
	for k, v := range set {
		v, err := engine.ValidateSetting(k, v)
		if err != nil {
			errJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		set[k] = v
	}
	for k, v := range set {
		if err := a.St.SetSetting(k, v); err != nil {
			fail(w, err)
			return
		}
	}
	if in.LogDays != nil && *in.LogDays == 0 {
		_, _ = a.St.PruneDNSLog(time.Now().Unix() + 1)
	}
	a.E.Log("info", "DNS-Einstellungen geändert von "+adminOf(r).Username)
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- Filterprofile ----------

func (a *API) saveDNSProfile(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name     *string  `json:"name"`
		Enabled  *bool    `json:"enabled"`
		Lists    []int64  `json:"lists"`
		Rules    *string  `json:"rules"`
		Assign   []string `json:"assign"`
		BlockDoH *bool    `json:"block_doh"`
		NXDomain *bool    `json:"nxdomain"`
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
		o.Name = n
	}
	if o.Name == "" {
		errJSON(w, http.StatusBadRequest, "Name fehlt")
		return
	}
	if in.Enabled != nil {
		o.Enabled = *in.Enabled
	}
	if in.Lists != nil {
		ids := []int64{}
		for _, id := range in.Lists {
			if _, err := a.St.Object("dnslist", id); err != nil {
				errJSON(w, http.StatusBadRequest, fmt.Sprintf("Blockliste %d gibt es nicht", id))
				return
			}
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		o.Data["lists"] = ids
	}
	if in.Rules != nil {
		if len(*in.Rules) > 200000 {
			errJSON(w, http.StatusBadRequest, "Regeln sind zu lang – für viele Einträge eine Blockliste anlegen")
			return
		}
		if _, err := engine.ParseDNSRules(*in.Rules); err != nil {
			fail(w, err)
			return
		}
		o.Data["rules"] = strings.TrimSpace(*in.Rules)
	}
	if in.Assign != nil {
		seen := map[string]bool{}
		out := []string{}
		for _, s := range in.Assign {
			s = strings.TrimSpace(s)
			if seen[s] {
				continue
			}
			kind, idText, _ := strings.Cut(s, ":")
			id, _ := strconv.ParseInt(idText, 10, 64)
			var err error
			switch kind {
			case "global":
				s = "global"
			case "server":
				_, err = a.St.Server(id)
			case "user":
				_, err = a.St.User(id)
			case "peer":
				_, err = a.St.Peer(id)
			default:
				err = fmt.Errorf("x")
			}
			if err != nil {
				errJSON(w, http.StatusBadRequest, "Zuordnung „"+s+"“ gibt es nicht")
				return
			}
			seen[s] = true
			out = append(out, s)
		}
		o.Data["assign"] = out
	}
	if in.BlockDoH != nil {
		o.Data["block_doh"] = *in.BlockDoH
	}
	if in.NXDomain != nil {
		o.Data["nxdomain"] = *in.NXDomain
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Filterprofil „"+o.Name+"“ gespeichert")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

func (a *API) createDNSProfile(w http.ResponseWriter, r *http.Request) {
	a.saveDNSProfile(w, r, &store.Object{Kind: "dnsprofile", Enabled: true, Data: store.M{"block_doh": true}, Secrets: store.M{}})
}

func (a *API) updateDNSProfile(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnsprofile", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveDNSProfile(w, r, o)
}

func (a *API) deleteDNSProfile(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnsprofile", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteObject("dnsprofile", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("warn", "Filterprofil „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- Blocklisten ----------

func (a *API) saveDNSList(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
		Mode    string  `json:"mode"`
		URL     *string `json:"url"`
		Refresh *int    `json:"refresh"`
		Entries *string `json:"entries"`
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
		o.Name = n
	}
	if o.Name == "" {
		errJSON(w, http.StatusBadRequest, "Name fehlt")
		return
	}
	if in.Enabled != nil {
		o.Enabled = *in.Enabled
	}
	switch in.Mode {
	case "":
	case "block", "allow":
		o.Data["mode"] = in.Mode
	default:
		errJSON(w, http.StatusBadRequest, "Art: sperren oder freigeben")
		return
	}
	oldURL, _ := o.Data["url"].(string)
	if in.URL != nil {
		u := strings.TrimSpace(*in.URL)
		if u != "" {
			if err := engine.CheckListURL(u); err != nil {
				fail(w, err)
				return
			}
		}
		o.Data["url"] = u
	}
	if in.Refresh != nil {
		if *in.Refresh < 0 || *in.Refresh > 24*90 {
			errJSON(w, http.StatusBadRequest, "Aktualisierung: 0 (nur von Hand) bis 2160 Stunden")
			return
		}
		o.Data["refresh"] = *in.Refresh
	}
	if in.Entries != nil {
		block, allow, skipped, err := engine.ParseDomainList(strings.NewReader(*in.Entries), 20000)
		if err != nil {
			fail(w, err)
			return
		}
		if skipped > 0 || len(allow) > 0 {
			errJSON(w, http.StatusBadRequest, "Eigene Einträge: bitte nur Domains, eine pro Zeile (Ausnahmen gehören in eine Liste der Art „freigeben“ oder in die Regeln eines Profils)")
			return
		}
		o.Data["entries"] = orStrings(block)
	}
	url, _ := o.Data["url"].(string)
	if url == "" && len(strs(o.Data["entries"])) == 0 {
		errJSON(w, http.StatusBadRequest, "Bitte eine Adresse (Online-Liste) oder eigene Einträge angeben")
		return
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Blockliste „"+o.Name+"“ gespeichert")
	if url != oldURL {
		a.E.DeleteDNSListData(o.ID)
		if url != "" {
			go func(id int64) {
				_, _ = a.E.FetchDNSList(id)
				a.E.RequestApply()
			}(o.ID)
		}
	}
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

// strs: Liste von Texten aus gespeicherten Daten ([]string oder []any).
func strs(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (a *API) createDNSList(w http.ResponseWriter, r *http.Request) {
	a.saveDNSList(w, r, &store.Object{Kind: "dnslist", Enabled: true, Data: store.M{"mode": "block", "refresh": 24}, Secrets: store.M{}})
}

func (a *API) updateDNSList(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnslist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveDNSList(w, r, o)
}

func (a *API) deleteDNSList(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnslist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if used := a.E.ProfilesUsing(o.ID); len(used) > 0 {
		errJSON(w, http.StatusBadRequest, "Die Liste wird noch von Filterprofilen verwendet: "+strings.Join(used, ", "))
		return
	}
	if err := a.St.DeleteObject("dnslist", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.DeleteDNSListData(o.ID)
	a.E.Log("warn", "Blockliste „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) refreshDNSList(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if _, err := a.E.FetchDNSList(id); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	st := a.E.DNSListStatus(id)
	writeJSON(w, map[string]any{"ok": true, "count": st.Count, "skipped": st.Skipped})
}

// ---------- Protokoll & Auswertung ----------

func qInt(r *http.Request, k string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(k), 10, 64)
	return n
}

func (a *API) dnsLog(w http.ResponseWriter, r *http.Request) {
	f := store.DNSLogFilter{Query: strings.TrimSpace(r.URL.Query().Get("q")), PeerID: qInt(r, "peer"), UserID: qInt(r, "user"),
		Action: r.URL.Query().Get("action"), Before: qInt(r, "before"), Limit: int(qInt(r, "limit"))}
	switch f.Action {
	case "", "ok", "blocked", "rewritten", "error", "cached":
	default:
		f.Action = ""
	}
	if len(f.Query) > 100 {
		f.Query = f.Query[:100]
	}
	rows, err := a.St.DNSLog(f)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"entries": rows})
}

func (a *API) dnsStats(w http.ResponseWriter, r *http.Request) {
	hours := qInt(r, "hours")
	if hours <= 0 || hours > 24*365 {
		hours = 24
	}
	st, err := a.St.DNSStats(time.Now().Add(-time.Duration(hours)*time.Hour).Unix(), qInt(r, "peer"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, st)
}

func (a *API) dnsCheck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Peer int64  `json:"peer"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	list, err := engine.ParseRouteDomains(in.Name)
	if err != nil || len(list) != 1 {
		errJSON(w, http.StatusBadRequest, "Bitte genau eine Domain angeben (z. B. werbung.de)")
		return
	}
	writeJSON(w, a.E.CheckDNS(in.Peer, list[0]))
}
