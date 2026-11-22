package engine

import (
	"strings"
	"testing"
	"time"

	"vpnpanel/internal/backup"
)

func TestAssetCheck(t *testing.T) {
	sha := "sha256:" + strings.Repeat("ab", 32)
	bin := releaseAsset{Name: binaryAssetName(), Digest: sha, URL: releaseDownload + "v1.1.0/" + binaryAssetName()}
	setup := func(d string) releaseAsset { return releaseAsset{Name: "vpn-setup.sh", Digest: d} }
	old := fetchReleaseFn
	defer func() { fetchReleaseFn = old }()
	fetchReleaseFn = func(url, cur string) (*releaseInfo, error) {
		if !strings.HasSuffix(url, "/tags/v1.0.0") {
			t.Fatalf("Abfrage %s", url)
		}
		return &releaseInfo{Tag: "v1.0.0", Assets: []releaseAsset{setup("sha256:alt")}}, nil
	}

	ok, why, changed := installCheck(&releaseInfo{Assets: []releaseAsset{bin, setup("sha256:alt")}}, "1.0.0")
	if !ok || why != "" || changed {
		t.Fatalf("gleiches Setup: %v %q %v", ok, why, changed)
	}
	if _, _, changed := installCheck(&releaseInfo{Assets: []releaseAsset{bin, setup("sha256:neu")}}, "v1.0.0"); !changed {
		t.Fatal("geändertes Setup nicht erkannt")
	}
	for name, a := range map[string]releaseAsset{
		"ohne Prüfsumme": {Name: bin.Name, URL: bin.URL},
		"md5":            {Name: bin.Name, URL: bin.URL, Digest: "md5:abc"},
		"fremde Adresse": {Name: bin.Name, Digest: sha, URL: "https://example.org/x"},
		"andere Datei":   {Name: "vpnpanel-linux-mips", Digest: sha, URL: bin.URL},
	} {
		if ok, why, _ := installCheck(&releaseInfo{Assets: []releaseAsset{a}}, "1.0.0"); ok || why == "" {
			t.Fatalf("%s angenommen", name)
		}
	}
	if h, err := assetSHA(&bin); err != nil || h != strings.Repeat("ab", 32) {
		t.Fatal(h, err)
	}
}

func TestUpdateRunState(t *testing.T) {
	e, _ := newTest(t)
	dd := e.Cfg.DataDir
	if ReadUpdateRun(dd) != nil {
		t.Fatal("Zustand ohne Update")
	}
	// neues Programm meldet sich → ok, und erst dann gibt es den Rücksprung
	r := &UpdateRun{Mode: "update", State: "restart", From: "1.0.0", To: "v1.1.0", Started: time.Now().Unix(), Point: "p", Prev: "/x/vpnpanel.prev"}
	if err := WriteUpdateRun(dd, r); err != nil {
		t.Fatal(err)
	}
	e.ConfirmUpdate("1.0.0") // altes Programm: nichts tun
	if ReadUpdateRun(dd).State != "restart" {
		t.Fatal("altes Programm hat ok gemeldet")
	}
	e.ConfirmUpdate("1.1.0")
	got := ReadUpdateRun(dd)
	if got.State != "ok" || got.Finished == 0 || !got.Terminal() {
		t.Fatalf("nach Start: %+v", got)
	}
	st := e.UpdateStatus("1.1.0")
	if st["rollback"] == nil {
		t.Fatal("kein Rücksprung angeboten")
	}
	if e.UpdateStatus("1.0.0")["rollback"] != nil {
		t.Fatal("Rücksprung bei anderer Version angeboten")
	}
	// zurückgesetzt: nur einmal melden
	r.State, r.Error = "rolled_back", "kaputt"
	_ = WriteUpdateRun(dd, r)
	e.ConfirmUpdate("1.0.0")
	if !ReadUpdateRun(dd).Noted {
		t.Fatal("Rücksprung nicht vermerkt")
	}
	// ohne Rückmeldung → abgebrochen
	r = &UpdateRun{Mode: "update", State: "apply", Started: time.Now().Add(-time.Hour).Unix()}
	_ = WriteUpdateRun(dd, r)
	if run := e.UpdateStatus("1.0.0")["run"].(*UpdateRun); run.State != "failed" {
		t.Fatalf("alter Lauf: %s", run.State)
	}
	// läuft noch → kein zweites Update
	r.Started = time.Now().Unix()
	_ = WriteUpdateRun(dd, r)
	if err := e.StartUpdate("1.0.0", "t"); err == nil || !strings.Contains(err.Error(), "läuft") {
		t.Fatalf("zweites Update: %v", err)
	}
}

func TestUpdateDryRunAndPoints(t *testing.T) {
	e, _ := newTest(t)
	dd := e.Cfg.DataDir
	_ = WriteUpdateRun(dd, &UpdateRun{State: "ok"})
	if err := e.StartUpdate("dev", "tester"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	var r *UpdateRun
	for time.Now().Before(deadline) {
		if r = ReadUpdateRun(dd); r != nil && r.Terminal() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if r == nil || r.State != "ok" || r.Point == "" {
		t.Fatalf("Testmodus-Update: %+v", r)
	}
	p, err := backup.GetPoint(dd, r.Point)
	if err != nil || p.Kind != backup.KindUpdate {
		t.Fatalf("Punkt vor Update: %+v %v", p, err)
	}
	// täglicher Punkt: einmal, nicht doppelt; ausgeschaltet keiner
	now := time.Now()
	e.autoPoint("dev", now)
	e.autoPoint("dev", now.Add(time.Hour))
	count := func() int {
		n := 0
		list, _ := backup.ListPoints(dd)
		for _, p := range list {
			if p.Kind == backup.KindAuto {
				n++
			}
		}
		return n
	}
	if count() != 1 {
		t.Fatalf("tägliche Punkte: %d", count())
	}
	_ = e.St.SetSetting("backup_auto", "0")
	e.autoPoint("dev", now.Add(48*time.Hour))
	if count() != 1 {
		t.Fatal("trotz „aus“ angelegt")
	}
	if info := e.PointsInfo(); info["error"] != nil || len(info["points"].([]backup.Point)) != 2 {
		t.Fatalf("Übersicht: %+v", info)
	}
}
