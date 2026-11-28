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
	ID       int64              `json:"id"`
	Name     string             `json:"name"`
	Enabled  bool               `json:"enabled"`
	Mode     string             `json:"mode"`
	URL      string             `json:"url"`
	Refresh  int                `json:"refresh"`
	Entries  []string           `json:"entries"`
	Total    int                `json:"total"`
	Excluded int                `json:"excluded"` // aus der Online-Liste herausgenommen
	Status   *engine.ListStatus `json:"status,omitempty"`
	UsedBy   []string           `json:"used_by"`
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
				Entries: orStrings(l.Entries), Excluded: len(l.Excluded), UsedBy: orStrings(a.E.ProfilesUsing(l.ID))}
			st, total := a.E.DNSListInfo(o)
			row.Total = total
			if l.URL != "" {
				row.Status = &st
			}
			lists = append(lists, row)
		}
	}
	ext := []map[string]any{}
	if objs, err := a.St.Objects("dnsclient"); err == nil {
		for _, o := range objs {
			ext = append(ext, map[string]any{"id": o.ID, "name": o.Name, "enabled": o.Enabled})
		}
	}
	info := a.E.DNSInfo()
	info.Rules = nil
	errs := a.E.Errors()
	writeJSON(w, map[string]any{
		"settings": map[string]string{"enabled": a.E.Setting("dns_enabled"), "upstream": a.E.Setting("dns_upstream"), "log_days": a.E.Setting("dns_log_days"),
			"cache_size": a.E.Setting("dns_cache_size"), "ttl_min": a.E.Setting("dns_ttl_min"), "ttl_max": a.E.Setting("dns_ttl_max"),
			"nocache": a.E.Setting("dns_nocache"), "strategy": a.E.Setting("dns_strategy"), "public": a.E.Setting("dns_public"),
			"resolver": a.E.Setting("dns_resolver"), "candidates": engine.CandidatesText(a.E.DNSCandidateList()), "candidates_custom": a.E.Setting("dns_candidates"),
			"auto": a.E.Setting("dns_auto"), "auto_hours": a.E.Setting("dns_auto_hours"), "auto_count": a.E.Setting("dns_auto_count"),
			"tls": a.E.Setting("dns_tls"), "tls_host": a.E.Setting("dns_tls_host"), "dot_port": a.E.Setting("dns_dot_port"), "acme_email": a.E.Setting("dns_acme_email"),
			"smart_grant": a.E.Setting("dns_smart_grant")},
		"smart_state": a.E.SmartState(), "tls_state": a.E.EncDNSState(),
		"unbound_installed": a.E.UnboundInstalled(), "unbound": a.E.UnboundHealth(), "auto_last": a.E.DNSAutoLast(),
		"upstreams": a.E.DNSServerStats(), "ext": ext,
		"info": info, "profiles": profiles, "smart": a.smartRows(), "lists": lists, "presets": dnsPresets, "dry_run": a.E.Sys.DryRun(),
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
		Cache    *int    `json:"cache_size"`
		TTLMin   *int    `json:"ttl_min"`
		TTLMax   *int    `json:"ttl_max"`
		NoCache  *string `json:"nocache"`
		Strategy *string `json:"strategy"`
		Public   *bool   `json:"public"`
		Resolver *string `json:"resolver"`
		Cands    *string `json:"candidates"`
		Auto     *bool   `json:"auto"`
		AutoH    *int    `json:"auto_hours"`
		AutoN    *int    `json:"auto_count"`
		TLS      *bool   `json:"tls"`
		TLSHost  *string `json:"tls_host"`
		DoTPort  *int    `json:"dot_port"`
		Email    *string `json:"acme_email"`
		ExtRate  *int    `json:"ext_rate"`
		ExtBurst *int    `json:"ext_burst"`
		ExtAny   *bool   `json:"ext_any"`
		Grant    *bool   `json:"smart_grant"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	set := map[string]string{}
	if in.Enabled != nil {
		set["dns_enabled"] = map[bool]string{true: "1", false: "0"}[*in.Enabled]
	}
	if in.Resolver != nil {
		set["dns_resolver"] = *in.Resolver
	}
	if in.Cands != nil {
		set["dns_candidates"] = *in.Cands
	}
	if in.Auto != nil {
		set["dns_auto"] = map[bool]string{true: "1", false: "0"}[*in.Auto]
	}
	if in.AutoH != nil {
		set["dns_auto_hours"] = strconv.Itoa(*in.AutoH)
	}
	if in.AutoN != nil {
		set["dns_auto_count"] = strconv.Itoa(*in.AutoN)
	}
	if in.Public != nil {
		set["dns_public"] = map[bool]string{true: "1", false: "0"}[*in.Public]
	}
	if in.TLS != nil {
		set["dns_tls"] = map[bool]string{true: "1", false: "0"}[*in.TLS]
	}
	if in.TLSHost != nil {
		set["dns_tls_host"] = *in.TLSHost
	}
	if in.DoTPort != nil {
		set["dns_dot_port"] = strconv.Itoa(*in.DoTPort)
	}
	if in.Email != nil {
		set["dns_acme_email"] = *in.Email
	}
	if in.ExtRate != nil {
		set["dns_ext_rate"] = strconv.Itoa(*in.ExtRate)
	}
	if in.ExtBurst != nil {
		set["dns_ext_burst"] = strconv.Itoa(*in.ExtBurst)
	}
	if in.ExtAny != nil {
		set["dns_ext_any"] = map[bool]string{true: "1", false: "0"}[*in.ExtAny]
	}
	if in.Grant != nil {
		set["dns_smart_grant"] = map[bool]string{true: "1", false: "0"}[*in.Grant]
	}
	if in.TLS != nil && *in.TLS {
		h := a.E.Setting("dns_tls_host")
		if in.TLSHost != nil {
			h = *in.TLSHost
		}
		if strings.TrimSpace(h) == "" {
			errJSON(w, http.StatusBadRequest, "Erst einen DNS-Namen eintragen (z. B. dns.example.org)")
			return
		}
	}
	if in.Upstream != nil {
		set["dns_upstream"] = *in.Upstream
	}
	if in.LogDays != nil {
		set["dns_log_days"] = strconv.Itoa(*in.LogDays)
	}
	for k, v := range map[string]*int{"dns_cache_size": in.Cache, "dns_ttl_min": in.TTLMin, "dns_ttl_max": in.TTLMax} {
		if v != nil {
			set[k] = strconv.Itoa(*v)
		}
	}
	if in.NoCache != nil {
		set["dns_nocache"] = *in.NoCache
	}
	if in.Strategy != nil {
		set["dns_strategy"] = *in.Strategy
	}
	if in.TTLMin != nil && in.TTLMax != nil && *in.TTLMax > 0 && *in.TTLMin > *in.TTLMax {
		errJSON(w, http.StatusBadRequest, "Mindestdauer ist größer als die Höchstdauer")
		return
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

// ---------- Blocklisten durchsuchen und anpassen ----------

// clipQ kürzt einen Suchtext.
func clipQ(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (a *API) dnsListEntries(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnslist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	q := r.URL.Query()
	src := q.Get("src")
	switch src {
	case "", "own", "url", "allow", "excluded":
	default:
		src = ""
	}
	writeJSON(w, a.E.DNSListEntries(o, clipQ(q.Get("q"), 100), src, int(qInt(r, "offset")), int(qInt(r, "limit"))))
}

func (a *API) editDNSListEntries(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnslist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	var in struct {
		Add     []string `json:"add"`
		Remove  []string `json:"remove"`
		Restore []string `json:"restore"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if len(in.Add)+len(in.Remove)+len(in.Restore) > 5000 {
		errJSON(w, http.StatusBadRequest, "Höchstens 5000 Domains auf einmal")
		return
	}
	msg, err := a.E.EditDNSList(o, in.Add, in.Remove, in.Restore)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "msg": msg})
}

func (a *API) searchDNSLists(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"lists": a.E.SearchDNSLists(clipQ(r.URL.Query().Get("q"), 100))})
}

// previewDNSPreset: bekannte Liste vor dem Hinzufügen ansehen (nur die Listen aus dnsPresets).
func (a *API) previewDNSPreset(w http.ResponseWriter, r *http.Request) {
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil || i < 0 || i >= len(dnsPresets) {
		errJSON(w, http.StatusNotFound, "Unbekannte Liste")
		return
	}
	p, err := a.E.PreviewDNSList(dnsPresets[i]["url"], clipQ(r.URL.Query().Get("q"), 100), int(qInt(r, "offset")), int(qInt(r, "limit")))
	if err != nil {
		errJSON(w, http.StatusBadGateway, "Liste nicht ladbar: "+err.Error())
		return
	}
	writeJSON(w, p)
}
