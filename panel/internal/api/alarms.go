package api

import (
	"net/http"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// GET /api/alarms – Regeln, Arten, bestehende Alarme und ob Mails rausgehen können.
func (a *API) listAlarms(w http.ResponseWriter, r *http.Request) {
	objs, err := a.St.Objects("alarm")
	if err != nil {
		fail(w, err)
		return
	}
	list := []*engine.Alarm{}
	for _, o := range objs {
		list = append(list, engine.AlarmFrom(o))
	}
	mailOK := a.E.Setting("mail_enabled") == "1" && a.E.Setting("smtp_host") != "" && a.E.Setting("mail_from") != ""
	rcpt := a.E.NotifyRecipients()
	if rcpt == nil {
		rcpt = []string{}
	}
	writeJSON(w, map[string]any{"alarms": list, "types": engine.AlarmTypes, "active": a.E.ActiveAlarms(),
		"mail_ok": mailOK, "recipients": rcpt})
}

func (a *API) saveAlarm(w http.ResponseWriter, r *http.Request, o *store.Object) {
	var in engine.Alarm
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := engine.ValidateAlarm(&in, o); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.St.SaveObject(o); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Alarm „"+o.Name+"“ gespeichert")
	writeJSON(w, engine.AlarmFrom(o))
}

func (a *API) createAlarm(w http.ResponseWriter, r *http.Request) {
	a.saveAlarm(w, r, &store.Object{Kind: "alarm", Data: store.M{}, Secrets: store.M{}})
}

func (a *API) updateAlarm(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("alarm", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	a.saveAlarm(w, r, o)
}

func (a *API) deleteAlarm(w http.ResponseWriter, r *http.Request) {
	o, err := a.St.Object("alarm", pathID(r))
	if err != nil {
		fail(w, err)
		return
	}
	if err := a.St.DeleteObject("alarm", o.ID); err != nil {
		fail(w, err)
		return
	}
	a.E.Log("info", "Alarm „"+o.Name+"“ gelöscht")
	writeJSON(w, map[string]bool{"ok": true})
}

// POST /api/alarms/{id}/test – Testmail an die Empfänger des Alarms.
func (a *API) testAlarm(w http.ResponseWriter, r *http.Request) {
	to, err := a.E.TestAlarm(pathID(r))
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "to": to})
}
