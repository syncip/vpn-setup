package engine

import (
	"strings"
	"testing"

	"vpnpanel/internal/proto"
)

func TestParseMeminfo(t *testing.T) {
	used, total := parseMeminfo("MemTotal:        4000000 kB\nMemFree:          500000 kB\nMemAvailable:    2500000 kB\nCached: 100 kB\n")
	if total != 4000000*1024 || used != 1500000*1024 {
		t.Errorf("used=%d total=%d", used, total)
	}
	// ältere Kernel ohne MemAvailable
	used, total = parseMeminfo("MemTotal: 1000 kB\nMemFree: 200 kB\nBuffers: 100 kB\nCached: 300 kB\n")
	if total != 1000*1024 || used != 400*1024 {
		t.Errorf("ohne MemAvailable: used=%d total=%d", used, total)
	}
}

func TestParseNetDev(t *testing.T) {
	text := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth0: 123456789 1000    0    0    0     0          0         0 98765432  900    0    0    0     0       0          0
 eth01: 5 1 0 0 0 0 0 0 6 1 0 0 0 0 0 0`
	rx, tx := parseNetDev(text, "eth0")
	if rx != 123456789 || tx != 98765432 {
		t.Errorf("eth0: %d %d", rx, tx)
	}
	if rx, tx := parseNetDev(text, "wg9"); rx != 0 || tx != 0 {
		t.Error("unbekannte Schnittstelle")
	}
}

func TestAttention(t *testing.T) {
	e, _ := newTest(t)
	_ = e.St.SetSetting("server_host", "")
	e.setErr("exit:3", "Ausgang A: Verbindung fehlgeschlagen\nDetails …")
	rememberPortCheck(&PortCheckResult{Items: []PortCheckItem{
		{HostPort: HostPort{Server: "wg", Port: proto.Port{Port: 51820, Proto: "udp"}}, Family: "IPv4", State: "missing", Detail: "kommt nicht an"},
		{HostPort: HostPort{Server: "wg", Port: proto.Port{Port: 51820, Proto: "udp"}}, Family: "IPv6", State: "skipped"},
		{HostPort: HostPort{Server: "vless", Port: proto.Port{Port: 443, Proto: "tcp"}}, Family: "IPv4", State: "ok"},
	}})
	t.Cleanup(func() { rememberPortCheck(nil) })
	att := e.Attention("0.15.4")
	var keys []string
	for _, a := range att {
		keys = append(keys, a.Level+":"+a.Key)
	}
	got := strings.Join(keys, " ")
	if got != "error:err:exit:3 error:server_host warn:port:udp:51820" {
		t.Errorf("Einträge: %s", got)
	}
	if att[0].Title != "Ausgang A: Verbindung fehlgeschlagen" || att[0].Link != "#/proxy/exits" {
		t.Errorf("Fehler-Eintrag: %+v", att[0])
	}
	if att[2].Title != "UDP 51820 (wg) kommt von außen nicht an" || att[2].Link != "#/health" {
		t.Errorf("Port-Eintrag: %+v", att[2])
	}
}

func TestHostStatsDry(t *testing.T) {
	e, _ := newTest(t)
	h := e.HostStats()
	if h.MemTotal == 0 || h.Cores == 0 || h.Iface == "" {
		t.Errorf("Testmodus: %+v", h)
	}
}
