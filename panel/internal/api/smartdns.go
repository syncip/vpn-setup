package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// SmartDNS-Profile (Objekte „smartdns“): Domains über eine Ausgangsgruppe, eigene Zuordnung
// (siehe engine/smartdns.go).

type smartRow struct {
	ID      int64               `json:"id"`
	Name    string              `json:"name"`
	Enabled bool                `json:"enabled"`
	Assign  []string            `json:"assign"`
	Routes  []engine.SmartRoute `json:"routes"`
}

func (a *API) smartRows() []smartRow {
	out := []smartRow{}
	objs, _ := a.St.Objects("smartdns")
	for _, o := range objs {
		p := engine.SmartProfileFrom(o)
		r := smartRow{ID: p.ID, Name: p.Name, Enabled: p.Enabled, Assign: orStrings(p.Assign), Routes: p.Routes}
		if r.Routes == nil {
			r.Routes = []engine.SmartRoute{}
		}
		out = append(out, r)
	}
	return out
}

func (a *API) saveSmartDNS(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name    *string  `json:"name"`
		Enabled *bool    `json:"enabled"`
		Assign  []string `json:"assign"`
		Routes  []struct {
			Group   int64  `json:"group"`
			Domains string `json:"domains"` // eine Domain je Zeile (oder durch Komma/Leerzeichen getrennt)
		} `json:"routes"`
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
			case "global", "vpn", "ext":
				s = kind
			case "server":
				_, err = a.St.Server(id)
			case "user":
				_, err = a.St.User(id)
			case "peer":
				_, err = a.St.Peer(id)
			case "client":
				_, err = a.St.Object("dnsclient", id)
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
	if in.Routes != nil {
		if len(in.Routes) > 20 {
			errJSON(w, http.StatusBadRequest, "höchstens 20 Einträge je SmartDNS-Profil")
			return
		}
		out := []any{}
		for _, sr := range in.Routes {
			g, err := a.St.Object("group", sr.Group)
			if err != nil {
				errJSON(w, http.StatusBadRequest, "Ausgangsgruppe auswählen")
				return
			}
			var doms []string
			seen := map[string]bool{}
			for _, d := range strings.FieldsFunc(sr.Domains, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == ';' || r == '\r' }) {
				d = strings.TrimSpace(d)
				if d == "" || strings.HasPrefix(d, "#") {
					continue
				}
				c := engine.CleanDomain(d)
				if c == "" {
					errJSON(w, http.StatusBadRequest, "„"+g.Name+"“: „"+d+"“ ist keine gültige Domain")
					return
				}
				if !seen[c] {
					seen[c] = true
					doms = append(doms, c)
				}
			}
			if len(doms) == 0 {
				continue
			}
			if len(doms) > 300 {
				errJSON(w, http.StatusBadRequest, "höchstens 300 Domains je Gruppe")
				return
			}
			out = append(out, map[string]any{"group": sr.Group, "domains": doms})
		}
		if len(out) == 0 {
			errJSON(w, http.StatusBadRequest, "Mindestens eine Domain mit Ausgangsgruppe eintragen")
			return
		}
		o.Data["routes"] = out
	}
	if _, ok := o.Data["routes"]; !ok {
		errJSON(w, http.StatusBadRequest, "Mindestens eine Domain mit Ausgangsgruppe eintragen")
		return
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "SmartDNS-Profil „"+o.Name+"“ gespeichert")
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

func (a *API) createSmartDNS(w http.ResponseWriter, r *http.Request) {
	a.saveSmartDNS(w, r, &store.Object{Kind: "smartdns", Enabled: true, Data: store.M{"assign": []string{}}, Secrets: store.M{}})
}

func (a *API) updateSmartDNS(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("smartdns", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveSmartDNS(w, r, o)
}

func (a *API) deleteSmartDNS(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("smartdns", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteObject("smartdns", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.ForgetSmartStats(o.ID)
	a.E.Log("warn", "SmartDNS-Profil „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}
