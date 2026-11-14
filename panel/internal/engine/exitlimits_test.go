package engine

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnpanel/internal/store"
)

func addLimitedExit(t *testing.T, e *Engine, l store.Limits) *store.Object {
	t.Helper()
	conf := "[Interface]\nPrivateKey = " + testKey('a') + "\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = " + testKey('b') +
		"\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	ex := &store.Object{Kind: "exit", Name: "USA", Enabled: true, Data: store.M{"type": "wireguard", "slot": 1, "limits": l}, Secrets: store.M{"config": conf}}
	if err := e.St.SaveObject(ex); err != nil {
		t.Fatal(err)
	}
	// nach dem Speichern wie aus der Datenbank gelesen (JSON)
	o, err := e.St.Object("exit", ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestEvaluateExit(t *testing.T) {
	now := time.Now()
	if v := EvaluateExit(nil, 1e12, now); v.Status != "ok" {
		t.Fatal(v)
	}
	l := &store.Limits{TrafficGB: 10, OnLimit: "block"}
	if v := EvaluateExit(l, 9*GB, now); v.Status != "ok" {
		t.Fatal(v)
	}
	if v := EvaluateExit(l, 10*GB, now); v.Status != "blocked" {
		t.Fatal(v)
	}
	l = &store.Limits{TrafficGB: 10, OnLimit: "throttle", LimitDownMbit: 5, LimitUpMbit: 2, SpeedDownMbit: 100}
	if v := EvaluateExit(l, 11*GB, now); v.Status != "throttled" || v.RateDown != 5 || v.RateUp != 2 {
		t.Fatal(v)
	}
	if v := EvaluateExit(l, GB, now); v.Status != "ok" || v.RateDown != 100 {
		t.Fatal(v)
	}
}

func TestExitLimitBlockAndReset(t *testing.T) {
	e, _ := newTest(t)
	o := addLimitedExit(t, e, store.Limits{TrafficGB: 1, Period: "monthly", ResetDay: 1, OnLimit: "block"})
	if l := ExitLimits(o); l == nil || l.TrafficGB != 1 {
		t.Fatalf("Limits nicht gelesen: %+v", l)
	}
	now := time.Now().Unix()
	_ = e.St.AddExitTraffic(o.ID, now, GB/4, GB/2)
	st := e.ExitLimitStates()[o.ID]
	if st.Status != "ok" || st.Used != GB/4+GB/2 || st.Percent != 75 {
		t.Fatalf("Zustand: %+v", st)
	}
	if e.checkExitLimits() {
		t.Fatal("ohne Limit-Überschreitung nichts zu tun")
	}
	_ = e.St.AddExitTraffic(o.ID, now, 0, GB/2)
	if !e.checkExitLimits() {
		t.Fatal("Überschreitung nicht erkannt")
	}
	xs, _ := e.LoadExits()
	if len(xs) != 1 || xs[0].Enabled {
		t.Fatal("Ausgang über dem Limit ist nicht abgeschaltet")
	}
	if e.checkExitLimits() {
		t.Fatal("unverändert → nichts anwenden")
	}
	// Zurücksetzen: Verbrauch ab jetzt, Ausgang wieder an
	if err := e.ResetExitUsage(o.ID); err != nil {
		t.Fatal(err)
	}
	if st := e.ExitLimitStates()[o.ID]; st.Used != 0 || st.Status != "ok" {
		t.Fatalf("nach Zurücksetzen: %+v", st)
	}
	if !e.checkExitLimits() {
		t.Fatal("Freigabe nicht erkannt")
	}
	if xs, _ := e.LoadExits(); !xs[0].Enabled {
		t.Fatal("Ausgang bleibt abgeschaltet")
	}
}

func TestExitLimitThrottleShaping(t *testing.T) {
	e, dry := newTest(t)
	o := addLimitedExit(t, e, store.Limits{TrafficGB: 1, Period: "daily", OnLimit: "throttle", LimitDownMbit: 8, LimitUpMbit: 2})
	_ = e.St.AddExitTraffic(o.ID, time.Now().Unix(), GB, GB)
	if !e.checkExitLimits() {
		t.Fatal("Drosselung nicht erkannt")
	}
	if xs, _ := e.LoadExits(); !xs[0].Enabled {
		t.Fatal("gedrosselter Ausgang darf nicht abgeschaltet sein")
	}
	e.shapeExits()
	log := strings.Join(dry.Log(), "\n")
	dev := "ex" + strconv.FormatInt(o.ID, 10)
	// ausgehend (Upload zum Anbieter) 2 Mbit, eingehend (Download) 8 Mbit
	if !strings.Contains(log, "tc class add dev "+dev+" parent 1: classid 1:11 htb rate 2000kbit ceil 2000kbit") ||
		!strings.Contains(log, "tc filter add dev "+dev+" parent ffff: protocol ip prio 1 u32 match ip src 0.0.0.0/0 police rate 8000kbit") {
		t.Fatalf("tc fehlt:\n%s", log)
	}
}

func TestAlarms(t *testing.T) {
	e, _ := newTest(t)
	e.notif.init()
	for k, v := range map[string]string{"mail_enabled": "1", "smtp_host": "mail.example.org", "mail_from": "panel@example.org"} {
		_ = e.St.SetSetting(k, v)
	}
	_ = e.St.SaveAdmin(&store.Admin{Username: "a", PassHash: "x", Email: "a@example.org", Notify: true})
	// Testmodus: Datenträger zu 16 % belegt
	a := &Alarm{Type: "disk", Threshold: 10, Recover: true, Enabled: true}
	o := &store.Object{Kind: "alarm", Data: store.M{}, Secrets: store.M{}}
	if err := ValidateAlarm(a, o); err != nil {
		t.Fatal(err)
	}
	if o.Name != "Speicherplatz belegt" {
		t.Fatalf("Name: %q", o.Name)
	}
	_ = e.St.SaveObject(o)
	e.runAlarms()
	e.runAlarms() // nur einmal melden (ohne Wiederholung)
	drain(e)
	if got := strings.Join(e.SentMails(), "\n"); got != "a@example.org | Alarm: Speicherplatz zu 16 % belegt" {
		t.Fatalf("Mails:\n%s", got)
	}
	if act := e.ActiveAlarms(); len(act) != 1 || !act[0].Active || act[0].Type != "disk" {
		t.Fatalf("aktiv: %+v", act)
	}
	// Schwelle hoch → Entwarnung an eigene Empfänger
	a.Threshold, a.To = 50, []string{"ops@example.org"}
	_ = ValidateAlarm(a, o)
	_ = e.St.SaveObject(o)
	e.runAlarms()
	drain(e)
	mails := e.SentMails()
	if len(mails) != 2 || !strings.HasPrefix(mails[1], "ops@example.org | Entwarnung:") {
		t.Fatalf("Mails: %v", mails)
	}
	if len(e.ActiveAlarms()) != 0 {
		t.Fatal("Alarm besteht noch")
	}

	// Dauer: erst nach N Minuten
	b := &Alarm{Type: "disk", Threshold: 5, Minutes: 10, Enabled: true}
	ob := &store.Object{Kind: "alarm", Data: store.M{}, Secrets: store.M{}}
	_ = ValidateAlarm(b, ob)
	_ = e.St.SaveObject(ob)
	e.runAlarms()
	drain(e)
	if len(e.SentMails()) != 2 {
		t.Fatal("vor Ablauf der Dauer gemeldet")
	}
	if act := e.ActiveAlarms(); len(act) != 1 || act[0].Active {
		t.Fatalf("wartend: %+v", act)
	}

	// Ausgang: Anteil vom Datenlimit
	ex := addLimitedExit(t, e, store.Limits{TrafficGB: 10, Period: "monthly", ResetDay: 1})
	_ = e.St.AddExitTraffic(ex.ID, time.Now().Unix(), 0, 9*GB)
	c := &Alarm{Type: "exit_usage", Threshold: 80, Enabled: true}
	oc := &store.Object{Kind: "alarm", Data: store.M{}, Secrets: store.M{}}
	_ = ValidateAlarm(c, oc)
	_ = e.St.SaveObject(oc)
	e.runAlarms()
	drain(e)
	mails = e.SentMails()
	if last := mails[len(mails)-1]; !strings.Contains(last, "Ausgang „USA“: 90 % vom Datenlimit") {
		t.Fatalf("Mails: %v", mails)
	}

	// ungültige Eingaben
	for _, bad := range []Alarm{{Type: "x"}, {Type: "cpu", Threshold: 0}, {Type: "cpu", Threshold: 120}, {Type: "cpu", Threshold: 50, To: []string{"kein mail"}}} {
		if err := ValidateAlarm(&bad, &store.Object{}); err == nil {
			t.Fatalf("angenommen: %+v", bad)
		}
	}
}

func TestSeedAlarms(t *testing.T) {
	e, _ := newTest(t)
	e.SeedAlarms()
	objs, _ := e.St.Objects("alarm")
	if len(objs) < 5 {
		t.Fatalf("%d Alarme", len(objs))
	}
	for _, o := range objs {
		_ = e.St.DeleteObject("alarm", o.ID)
	}
	e.SeedAlarms()
	if objs, _ := e.St.Objects("alarm"); len(objs) != 0 {
		t.Fatal("gelöschte Alarme kommen wieder")
	}
}
