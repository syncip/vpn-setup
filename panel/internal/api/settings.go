package api

// Tarife sowie Einstellungen und System.

import (
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

// ---------- Tarife ----------

func (a *API) listPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := a.St.Plans()
	if err != nil {
		fail(w, err)
		return
	}
	users, _ := a.St.Users()
	count := map[int64]int{}
	for _, u := range users {
		if u.PlanID != nil && u.Limits == nil {
			count[*u.PlanID]++
		}
	}
	type row struct {
		*store.Plan
		Users int `json:"users"`
	}
	var out []row
	for _, p := range plans {
		out = append(out, row{p, count[p.ID]})
	}
	writeJSON(w, orEmptyT(out))
}

func (a *API) savePlan(w http.ResponseWriter, r *http.Request, p *store.Plan) {
	var in store.Plan
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if badLabel(in.Name) {
		errJSON(w, http.StatusBadRequest, "Name fehlt oder ist zu lang")
		return
	}
	if err := engine.ValidateLimits(&in.Limits); err != nil {
		fail(w, err)
		return
	}
	p.Name, p.Description, p.Limits = in.Name, in.Description, in.Limits
	if err := a.St.SavePlan(p); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	writeJSON(w, p)
}

func (a *API) createPlan(w http.ResponseWriter, r *http.Request) { a.savePlan(w, r, &store.Plan{}) }

func (a *API) updatePlan(w http.ResponseWriter, r *http.Request) {
	p, err := a.St.Plan(pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.savePlan(w, r, p)
}

func (a *API) deletePlan(w http.ResponseWriter, r *http.Request) {
	if err := a.St.DeletePlan(pathID(r)); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- Einstellungen & System ----------

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.E.Settings()) }

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	for k, v := range in {
		v, err := engine.ValidateSetting(k, v)
		if err != nil {
			errJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		in[k] = v
	}
	for k, v := range in {
		if err := a.St.SetSetting(k, v); err != nil {
			fail(w, err)
			return
		}
	}
	a.E.Log("info", "Einstellungen geändert von "+adminOf(r).Username)
	a.E.RequestApply()
	writeJSON(w, a.E.Settings())
}

func (a *API) system(w http.ResponseWriter, r *http.Request) {
	type check struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	var checks []check
	if h := a.E.Setting("server_host"); h == "" {
		checks = append(checks, check{"Server-Adresse", false, "fehlt – unter Einstellungen eintragen (steht in allen Links und Configs)"})
	} else {
		checks = append(checks, check{"Server-Adresse", true, h})
	}
	for _, bin := range []struct{ name, label string }{{"wg", "WireGuard-Werkzeuge"}, {"xray", "Xray"}, {"hysteria", "Hysteria2"}, {"nginx", "nginx"}, {"tc", "tc (Geschwindigkeitsbegrenzung)"}, {"iptables", "iptables"}, {"ip6tables", "ip6tables"}} {
		_, err := exec.LookPath(bin.name)
		ok := err == nil || a.E.Sys.DryRun()
		d := "vorhanden"
		if !ok {
			d = "fehlt"
		}
		checks = append(checks, check{bin.label, ok, d})
	}
	for _, svc := range []string{"xray", "nginx"} {
		_, err := a.E.Sys.Run("systemctl", "is-active", "--quiet", svc)
		d := "läuft"
		if err != nil {
			d = "läuft nicht"
		}
		checks = append(checks, check{"Dienst " + svc, err == nil, d})
	}
	out, err := a.E.Sys.Run("sysctl", "-n", "net.ipv4.ip_forward")
	checks = append(checks, check{"IPv4-Weiterleitung", err == nil && (strings.TrimSpace(out) == "1" || a.E.Sys.DryRun()), strings.TrimSpace(out)})

	var ports []map[string]any
	servers, _ := a.St.Servers()
	for _, sv := range servers {
		if d, ok := proto.Get(sv.Protocol); ok && sv.Enabled {
			for _, p := range d.Ports(sv) {
				ports = append(ports, map[string]any{"server": sv.Name, "port": p.Port, "to": p.To, "proto": p.Proto, "note": p.Note})
			}
		}
	}
	writeJSON(w, map[string]any{"checks": checks, "errors": a.E.Errors(), "dry_run": a.E.Sys.DryRun(), "dry_log": a.E.Sys.Log(),
		"version": a.Version, "ports": orEmptyM(ports)})
}

func (a *API) applyNow(w http.ResponseWriter, r *http.Request) {
	if err := a.E.Apply(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// portCheck: Portweiterleitungen von außen prüfen (über einen Ausgang, dauert einige Sekunden).
func (a *API) portCheck(w http.ResponseWriter, r *http.Request) {
	res, err := a.E.CheckPorts()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, res)
}

func (a *API) portCheckLast(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"last": engine.LastPortCheck()})
}

func (a *API) collectNow(w http.ResponseWriter, r *http.Request) {
	if err := a.E.Collect(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	ev, err := a.St.Events(limit, r.URL.Query().Get("level"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, orEmptyT(ev))
}
