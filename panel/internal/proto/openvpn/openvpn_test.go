package openvpn

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestParseStatus(t *testing.T) {
	// Ausgabe von „status 3“ (OpenVPN 2.6)
	lines := strings.Split(strings.Join([]string{
		"TITLE\tOpenVPN 2.6.14 x86_64-pc-linux-gnu",
		"TIME\t2026-11-08 12:00:00\t1794135600",
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher",
		"CLIENT_LIST\tp-0123456789abcdef\t[AF_INET6]::ffff:203.0.113.7:51234\t10.66.0.2\tfd66:66:66::2\t1234\t5678\t2026-11-08 11:00:00\t1794132000\tUNDEF\t3\t0\tAES-256-GCM",
		"CLIENT_LIST\tp-fedcba9876543210\t2001:db8::5:1194\t10.66.0.3\t\t10\t20\t2026-11-08 11:30:00\t1794133800\tUNDEF\t4\t1\tAES-256-GCM",
		"CLIENT_LIST\tUNDEF\t198.51.100.1:5000\t\t\t0\t0\t2026-11-08 11:59:00\t1794135540\tUNDEF\t5\t2\tnone",
		"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)",
		"ROUTING_TABLE\t10.66.0.2\tp-0123456789abcdef\t203.0.113.7:51234\t2026-11-08 12:00:00\t1794135600",
		"GLOBAL_STATS\tMax bcast/mcast queue length\t0",
	}, "\n"), "\n")
	ss := parseStatus(lines)
	if len(ss) != 2 {
		t.Fatalf("%d Sitzungen: %+v", len(ss), ss)
	}
	if s := ss[0]; s.CN != "p-0123456789abcdef" || s.Real != "203.0.113.7" || s.Rx != 1234 || s.Tx != 5678 || s.Since != 1794132000 || s.ClientID != "3" {
		t.Errorf("erste Sitzung: %+v", s)
	}
	if ss[1].Real != "2001:db8::5" {
		t.Errorf("IPv6-Adresse: %q", ss[1].Real)
	}
}

func TestRealAddr(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4:5555":                       "1.2.3.4",
		"[2001:db8::1]:5555":                 "2001:db8::1",
		"::ffff:1.2.3.4":                     "1.2.3.4",
		"[AF_INET]1.2.3.4:1194":              "1.2.3.4",
		"[AF_INET6]2001:db8::9:1":            "2001:db8::9",
		"udp6:[2001:db8::1]:5555":            "2001:db8::1",
		"[AF_INET6]::ffff:203.0.113.7:51234": "203.0.113.7",
		"tcp4-server:198.51.100.2:40000":     "198.51.100.2",
	} {
		if got := realAddr(in); got != want {
			t.Errorf("%s → %s, erwartet %s", in, got, want)
		}
	}
}

func TestAddr(t *testing.T) {
	p := netip.MustParsePrefix("10.66.0.0/29")
	if l := lastHost(p); l.String() != "10.66.0.6" {
		t.Errorf("letzte Adresse %s", l)
	}
	if _, err := addrAt(p, 8); err == nil {
		t.Errorf("Adresse außerhalb des Netzes")
	}
	if m := mask4(netip.MustParsePrefix("10.0.0.0/16")); m != "255.255.0.0" {
		t.Errorf("Maske %s", m)
	}
	if n := nextNet(netip.MustParsePrefix("fd66:66:66::/64")); n.String() != "fd66:66:67::/64" {
		t.Errorf("nächstes Netz %s", n)
	}
	k := tlsCryptKey()
	if strings.Count(k, "\n") != 18 || !strings.HasPrefix(k, "-----BEGIN OpenVPN Static key V1-----\n") {
		t.Errorf("tls-crypt-Schlüssel:\n%s", k)
	}
}

// Nur auf echtem Linux: OVPN_SOCK=<socket> [OVPN_KILL=<cn>] fragt die laufende Instanz ab.
func TestLiveMgmt(t *testing.T) {
	sock := os.Getenv("OVPN_SOCK")
	if sock == "" {
		t.Skip("OVPN_SOCK nicht gesetzt")
	}
	if cn := os.Getenv("OVPN_KILL"); cn != "" {
		if err := kill(sock, cn); err != nil {
			t.Fatal(err)
		}
	}
	ss, err := sessions(sock)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range ss {
		t.Logf("%+v", s)
	}
}
