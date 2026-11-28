package api

// DNS: Blocklisten (auch durchsuchen/anpassen) sowie Protokoll und Auswertung.

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

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

// dnsSpeedTest misst die eingestellten und bekannte öffentliche DNS-Server (dauert einige Sekunden).
func (a *API) dnsSpeedTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Extra string `json:"extra"` // weitere Server, z. B. 127.0.0.1:5335 (Unbound)
	}
	_ = readJSON(r, &in)
	var extra []string
	if strings.TrimSpace(in.Extra) != "" {
		list, err := engine.ParseUpstream(in.Extra)
		if err != nil {
			fail(w, err)
			return
		}
		extra = list
	}
	writeJSON(w, map[string]any{"results": a.E.DNSSpeedTest(extra)})
}

// dnsAutoNow: automatische Wahl sofort ausführen (misst alle Server, übernimmt ggf. die schnellsten).
func (a *API) dnsAutoNow(w http.ResponseWriter, r *http.Request) {
	res := a.E.RunDNSAuto(true)
	a.E.Log("info", "DNS-Server-Wahl von Hand gestartet von "+adminOf(r).Username)
	writeJSON(w, res)
}

// dnsTLSRenew: Zertifikat für DoH/DoT jetzt holen.
func (a *API) dnsTLSRenew(w http.ResponseWriter, r *http.Request) {
	if err := a.E.RenewEncCert(true); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	a.E.Log("info", "Zertifikat für DoH/DoT angefordert von "+adminOf(r).Username)
	writeJSON(w, a.E.EncDNSState())
}

// dnsTLSState: Zustand von DoH/DoT und SmartDNS-Proxy.
func (a *API) dnsTLSState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"tls": a.E.EncDNSState(), "smart": a.E.SmartState()})
}

// dnsLive: Anfragen je Sekunde der letzten Minuten und die benutzten DNS-Server.
func (a *API) dnsLive(w http.ResponseWriter, r *http.Request) {
	secs, _ := strconv.Atoi(r.URL.Query().Get("secs"))
	writeJSON(w, a.E.DNSLiveData(secs))
}

// dnsCFToken: Cloudflare-API-Token setzen (landet nur in <data>/secrets.env, wird nie zurückgegeben).
func (a *API) dnsCFToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if r.Method != http.MethodDelete {
		if err := readJSON(r, &in); err != nil {
			fail(w, err)
			return
		}
		if strings.TrimSpace(in.Token) == "" {
			errJSON(w, http.StatusBadRequest, "Token fehlt")
			return
		}
	}
	if err := a.E.SetCFToken(in.Token); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Token == "" {
		a.E.Log("warn", "Cloudflare-API-Token entfernt von "+adminOf(r).Username)
		writeJSON(w, map[string]any{"tls": a.E.EncDNSState()})
		return
	}
	a.E.Log("info", "Cloudflare-API-Token hinterlegt von "+adminOf(r).Username)
	writeJSON(w, map[string]any{"tls": a.E.EncDNSState(), "check": a.E.VerifyCFToken()})
}

// dnsCFTokenVerify: Token bei Cloudflare prüfen.
func (a *API) dnsCFTokenVerify(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.E.VerifyCFToken())
}
