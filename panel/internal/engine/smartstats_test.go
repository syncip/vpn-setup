package engine

import (
	"os"
	"testing"
	"time"
)

// TestSmartStatsCounters: nft-Zähler (Zuwachs, Neustart der Tabelle), Proxy-Verkehr, Speichern, Zurücksetzen.
func TestSmartStatsCounters(t *testing.T) {
	e, _ := newTest(t)
	rid := SmartRuleID(7, 1)
	now := time.Now().Unix()
	js := func(up, dn int64) string {
		return `{"nftables":[{"metainfo":{}},{"counter":{"name":"s` + itoa(rid) + `_up","bytes":` + itoa(up) + `}},` +
			`{"counter":{"name":"s` + itoa(rid) + `_dn","bytes":` + itoa(dn) + `}},{"counter":{"name":"andere","bytes":5}}]}`
	}
	e.smartCounters(js(100, 1000), now)
	e.smartCounters(js(150, 1600), now)
	e.smartCounters(js(10, 20), now) // Tabelle neu angelegt → zählt ganz
	e.smartProxied(rid, "netflix.com", -3, -1, "")
	e.smartProxied(rid, "netflix.com", -3, 5000, "")
	st := e.SmartStats()[7]
	if st == nil || st.Up != 160 || st.Down != 1620 || st.Proxy != 5000 || st.Conns != 1 || st.Routes[1].Bytes != 160+1620+5000 ||
		st.Devices[-3].Conns != 1 || st.Domains["netflix.com"].Bytes != 5000 {
		t.Fatalf("Zähler: %+v", st)
	}
	e.saveSmartStats(time.Now())
	if _, err := os.Stat(e.smartStatsPath()); err != nil {
		t.Fatal("nicht gespeichert")
	}
	// neu laden
	e2, _ := newTest(t)
	e2.Cfg.DataDir = e.Cfg.DataDir
	if st := e2.SmartStats()[7]; st == nil || st.Proxy != 5000 {
		t.Errorf("geladen: %+v", st)
	}
	e.ForgetSmartStats(7)
	if len(e.SmartStats()) != 0 {
		t.Error("nicht gelöscht")
	}
	if _, _, ok := splitSmartRule(42); ok {
		t.Error("normale Regel als SmartDNS erkannt")
	}
}
