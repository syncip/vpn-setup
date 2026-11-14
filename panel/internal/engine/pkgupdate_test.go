package engine

import "testing"

func TestParseAptSim(t *testing.T) {
	out := `NOTE: This is only a simulation!
Reading package lists...
Inst openssl [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])
Inst tzdata [2025b-4] (2025b-4+deb13u1 Debian:13.2/stable [all])
Inst libfoo1 (1.2-3 Debian:13.2/stable [amd64])
Conf openssl (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])
Remv oldpkg [1.0]`
	items := parseAptSim(out)
	if len(items) != 3 {
		t.Fatalf("%d Einträge, erwartet 3: %+v", len(items), items)
	}
	o := items[0]
	if o.Name != "openssl" || o.Installed != "3.5.1-1" || o.Latest != "3.5.1-1+deb13u1" || !o.Security || !o.Relevant {
		t.Errorf("openssl falsch: %+v", o)
	}
	if items[1].Security || items[1].Relevant || items[1].Source != "Debian:13.2/stable" {
		t.Errorf("tzdata falsch: %+v", items[1])
	}
	if items[2].Installed != "" || items[2].Latest != "1.2-3" {
		t.Errorf("neues Paket falsch: %+v", items[2])
	}
}

func TestParseBinaryVersions(t *testing.T) {
	if v := parseXrayVersion("Xray 25.10.15 (Xray, Penetrates Everything.) 4c9e9f4 (go1.25.3 linux/amd64)\nA unified platform"); v != "25.10.15" {
		t.Errorf("Xray: %q", v)
	}
	hy := "░█░█░█░█\nVersion:\tv2.6.4\nBuildDate:\t2025-09-01\n"
	if v := parseHysteriaVersion(hy); v != "v2.6.4" {
		t.Errorf("Hysteria2: %q", v)
	}
	if v := parseHysteriaVersion("Version: app/v2.7.0"); v != "v2.7.0" {
		t.Errorf("Hysteria2 app/: %q", v)
	}
	if !newerVersion("2.7.0", "2.6.4") || newerVersion("2.6.4", "2.6.4") {
		t.Errorf("Vergleich falsch")
	}
}

func TestDemoPkgCounts(t *testing.T) {
	st := demoPkgUpdates()
	sortPkg(st.Items)
	if st.Items[0].Kind != "binary" {
		t.Errorf("Programme nicht zuerst: %+v", st.Items[0])
	}
}
