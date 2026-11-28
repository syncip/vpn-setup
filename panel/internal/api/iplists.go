package api

// IP-Listen (Sperr- und Freigabelisten je Server).

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// ---------- IP-Listen ----------

type ipListRow struct {
	ID      int64              `json:"id"`
	Name    string             `json:"name"`
	Enabled bool               `json:"enabled"`
	Mode    string             `json:"mode"`
	Entries []string           `json:"entries"`
	All     bool               `json:"all"`
	Servers []int64            `json:"servers"`
	URL     string             `json:"url"`
	Refresh int                `json:"refresh"` // Stunden, 0 = nur von Hand
	Total   int                `json:"total"`   // Einträge insgesamt (eigene + geladene)
	Status  *engine.ListStatus `json:"status,omitempty"`
	UsedBy  int                `json:"used_by"` // Ziel-Regeln, die die Liste verwenden
}

func (a *API) listIPLists(w http.ResponseWriter, r *http.Request) {
	objs, err := a.St.Objects("iplist")
	if err != nil {
		fail(w, err)
		return
	}
	rows := []*ipListRow{}
	for _, o := range objs {
		l := engine.IPListFrom(o)
		row := &ipListRow{ID: o.ID, Name: o.Name, Enabled: o.Enabled, Mode: l.Mode, Entries: orStrings(l.Entries),
			All: l.All, Servers: orInts(l.Servers), URL: l.URL, Refresh: l.Refresh, UsedBy: len(a.E.RoutesUsing("iplist", o.ID))}
		st, total := a.E.ListInfo(o)
		row.Total = total
		if l.URL != "" {
			row.Status = &st
		}
		rows = append(rows, row)
	}
	writeJSON(w, map[string]any{"lists": rows, "error": a.E.Errors()["acl"]})
}

func orStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func orInts(v []int64) []int64 {
	if v == nil {
		return []int64{}
	}
	return v
}

func (a *API) saveIPList(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
		Mode    string  `json:"mode"`
		Entries *string `json:"entries"` // eine Adresse/ein Netz pro Zeile, # = Kommentar
		All     *bool   `json:"all"`
		Servers []int64 `json:"servers"`
		URL     *string `json:"url"`     // Online-Liste: Adresse (leer = keine)
		Refresh *int    `json:"refresh"` // Stunden zwischen den Abrufen, 0 = nur von Hand
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
	oldMode, _ := o.Data["mode"].(string)
	switch in.Mode {
	case "":
		if o.Data["mode"] == nil {
			o.Data["mode"] = "block"
		}
	case "block", "allow", "targets":
		if oldMode == "targets" && in.Mode != "targets" && o.ID != 0 {
			if msg := a.usedByRoutes("iplist", o.ID); msg != "" {
				errJSON(w, http.StatusBadRequest, "Die Zielliste "+msg)
				return
			}
		}
		o.Data["mode"] = in.Mode
	default:
		errJSON(w, http.StatusBadRequest, "Art: Sperrliste, Freigabeliste oder Zielliste")
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
		list, err := engine.ParseIPEntries(*in.Entries)
		if err != nil {
			fail(w, err)
			return
		}
		o.Data["entries"] = orStrings(list)
	}
	if in.All != nil {
		o.Data["all"] = *in.All
	}
	if in.Servers != nil {
		ids := []int64{}
		for _, id := range in.Servers {
			if _, err := a.St.Server(id); err != nil {
				errJSON(w, http.StatusBadRequest, fmt.Sprintf("Server %d gibt es nicht", id))
				return
			}
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		o.Data["servers"] = ids
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "IP-Liste „"+o.Name+"“ gespeichert")
	if newURL, _ := o.Data["url"].(string); newURL != oldURL {
		a.E.DeleteListData(o.ID) // alter Inhalt gehört zur alten Adresse
		if newURL != "" {
			go func(id int64) { // erster Abruf im Hintergrund – die Liste kann groß sein
				_, _ = a.E.FetchList(id)
				a.E.RequestApply()
			}(o.ID)
		}
	}
	a.E.RequestApply()
	writeJSON(w, map[string]any{"id": o.ID})
}

// refreshIPList lädt eine Online-Liste sofort neu.
func (a *API) refreshIPList(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if _, err := a.E.FetchList(id); err != nil {
		fail(w, err)
		return
	}
	a.E.RequestApply()
	st := a.E.ListStatus(id)
	writeJSON(w, map[string]any{"ok": true, "count": st.Count, "skipped": st.Skipped})
}

func (a *API) createIPList(w http.ResponseWriter, r *http.Request) {
	a.saveIPList(w, r, &store.Object{Kind: "iplist", Enabled: true, Data: store.M{"mode": "block"}, Secrets: store.M{}})
}

func (a *API) updateIPList(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("iplist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveIPList(w, r, o)
}

func (a *API) deleteIPList(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("iplist", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if msg := a.usedByRoutes("iplist", o.ID); msg != "" {
		errJSON(w, http.StatusBadRequest, "Die Liste "+msg)
		return
	}
	if err := a.St.DeleteObject("iplist", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.DeleteListData(o.ID)
	a.E.Log("warn", "IP-Liste „"+o.Name+"“ gelöscht")
	a.E.RequestApply()
	writeJSON(w, map[string]bool{"ok": true})
}

func strOf(v any) string { s, _ := v.(string); return s }
