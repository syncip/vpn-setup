package vless

import "testing"

func TestParseOnlineIPs(t *testing.T) {
	out := `{"users":[{"email":"p7@vpn","ips":[{"ip":"198.51.100.4","lastSeen":100},{"ip":"2001:db8::9","lastSeen":200}]},{"email":"p8@vpn","ips":[]}]}`
	m := parseOnlineIPs(out)
	if m["p7@vpn"] != "2001:db8::9" || m["p8@vpn"] != "" {
		t.Errorf("falsch: %v", m)
	}
	if len(parseOnlineIPs("{}")) != 0 || parseOnlineIPs("kaputt") != nil {
		t.Error("leere/kaputte Antwort")
	}
}
