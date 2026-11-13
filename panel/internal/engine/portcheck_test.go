package engine

import (
	"net/netip"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

func TestPortCheckScript(t *testing.T) {
	ports := []HostPort{
		{Server: "wg", Port: proto.Port{Port: 51820, Proto: "udp"}},
		{Server: "vless", Port: proto.Port{Port: 443, Proto: "tcp"}},
	}
	s := pcScript(ports, netip.MustParseAddr("203.0.113.7"))
	for _, want := range []string{
		"table inet vpnpanel_portcheck\ndelete table inet vpnpanel_portcheck\n",
		"type filter hook prerouting priority -350; policy accept;",
		`ip saddr 203.0.113.7 udp dport 51820 udp length 985 counter comment "p0"`,
		`ip saddr 203.0.113.7 tcp dport 443 tcp flags & (syn|ack) == syn counter comment "p1"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Skript ohne %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "drop") || strings.Contains(s, "reject") {
		t.Errorf("Prüftabelle darf keinen Verkehr verändern:\n%s", s)
	}
	// ohne bekannte Adresse des Ausgangs: TCP nicht zählen (echte Clients würden mitgezählt)
	s = pcScript(ports, netip.Addr{})
	if !strings.Contains(s, `udp dport 51820 udp length 985 counter comment "p0"`) || strings.Contains(s, "tcp dport") || strings.Contains(s, "saddr") {
		t.Errorf("ohne Absender:\n%s", s)
	}
}

func TestParsePCCounters(t *testing.T) {
	out := `{"nftables": [{"metainfo": {"version": "1.1.3"}}, {"table": {"family": "inet", "name": "vpnpanel_portcheck"}},
	{"rule": {"family": "inet", "table": "vpnpanel_portcheck", "chain": "pre", "handle": 2, "comment": "p0",
	  "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 51820}},
	           {"counter": {"packets": 3, "bytes": 3015}}]}},
	{"rule": {"family": "inet", "table": "vpnpanel_portcheck", "chain": "pre", "handle": 3, "comment": "p1",
	  "expr": [{"counter": {"packets": 0, "bytes": 0}}]}}]}`
	m := parsePCCounters(out)
	if m["p0"] != 3 || m["p1"] != 0 || len(m) != 2 {
		t.Errorf("Zähler: %v", m)
	}
	if parsePCCounters("kaputt") != nil {
		t.Error("ungültige Ausgabe")
	}
}

// Im Testmodus liefert die Prüfung ein simuliertes Ergebnis (für die Oberfläche) und merkt es sich.
func TestPortCheckDry(t *testing.T) {
	e, _ := newTest(t)
	if _, err := e.CheckPorts(); err == nil {
		t.Error("ohne Server keine Prüfung")
	}
	s := &store.Server{Name: "wg", Protocol: "wireguard", Enabled: true, Settings: store.M{}, State: store.M{}}
	if err := e.InitServer(s); err != nil {
		t.Fatal(err)
	}
	if err := e.St.SaveServer(s); err != nil {
		t.Fatal(err)
	}
	r, err := e.CheckPorts()
	if err != nil {
		t.Fatal(err)
	}
	if !r.DryRun || len(r.Items) != 2 || r.Items[0].Family != "IPv4" || r.Items[1].State != "skipped" || LastPortCheck() != r {
		t.Errorf("Ergebnis: %+v", r)
	}
}
