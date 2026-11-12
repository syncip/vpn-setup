package api

import (
	"fmt"
	"net/http"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// DNS für Geräte ohne VPN: Freigaben (Objekt „dnsclient“) und wer von außen fragt.

func (a *API) dnsExternal(w http.ResponseWriter, r *http.Request) {
	profiles := []map[string]any{}
	if objs, err := a.St.Objects("dnsprofile"); err == nil {
		for _, o := range objs {
			p := engine.DNSProfileFrom(o)
			global := false
			for _, s := range p.Assign {
				global = global || s == "global"
			}
			profiles = append(profiles, map[string]any{"id": p.ID, "name": p.Name, "enabled": p.Enabled, "global": global})
		}
	}
	writeJSON(w, map[string]any{"external": a.E.DNSExternal(), "profiles": profiles, "dns_enabled": a.E.Setting("dns_enabled") == "1",
		"out_interface": a.E.Setting("out_interface"), "dry_run": a.E.Sys.DryRun()})
}

func (a *API) saveDNSClient(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name    *string  `json:"name"`
		Enabled *bool    `json:"enabled"`
		Addrs   []string `json:"addrs"`
		Profile *int64   `json:"profile"`
		Note    *string  `json:"note"`
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
	if in.Addrs != nil || o.ID == 0 {
		list, err := engine.ParseClientAddrs(in.Addrs)
		if err != nil {
			errJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		o.Data["addrs"] = list
	}
	if in.Profile != nil {
		p := *in.Profile
		if p > 0 {
			if _, err := a.St.Object("dnsprofile", p); err != nil {
				errJSON(w, http.StatusBadRequest, fmt.Sprintf("Filterprofil %d gibt es nicht", p))
				return
			}
		} else if p < -1 {
			p = -1
		}
		o.Data["profile"] = p
	}
	if in.Note != nil {
		n := strings.TrimSpace(*in.Note)
		if len(n) > 300 {
			n = n[:300]
		}
		o.Data["note"] = n
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "DNS-Freigabe „"+o.Name+"“ gespeichert von "+adminOf(r).Username)
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

func (a *API) createDNSClient(w http.ResponseWriter, r *http.Request) {
	a.saveDNSClient(w, r, &store.Object{Kind: "dnsclient", Enabled: true, Data: store.M{"profile": int64(0)}, Secrets: store.M{}})
}

func (a *API) updateDNSClient(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnsclient", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveDNSClient(w, r, o)
}

func (a *API) deleteDNSClient(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("dnsclient", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteObject("dnsclient", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("warn", "DNS-Freigabe „"+o.Name+"“ gelöscht von "+adminOf(r).Username)
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// forgetDNSSeen leert die Liste der gesehenen Absender (?addr= für einen).
func (a *API) forgetDNSSeen(w http.ResponseWriter, r *http.Request) {
	a.E.ForgetExt(r.URL.Query().Get("addr"))
	writeJSON(w, map[string]bool{"ok": true})
}
