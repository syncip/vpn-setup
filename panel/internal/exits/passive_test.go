package exits

import "testing"

func TestParseSynSent(t *testing.T) {
	out := `tcp      6 118 SYN_SENT src=10.9.0.2 dst=192.0.2.13 sport=40100 dport=443 [UNREPLIED] src=192.0.2.13 dst=10.1.0.1 sport=443 dport=40100 mark=1090519040 use=1
tcp      6 431999 ESTABLISHED src=10.9.0.2 dst=192.0.2.10 sport=40000 dport=443 src=192.0.2.10 dst=10.1.0.1 sport=443 dport=40000 [ASSURED] mark=1090519040 use=1
tcp      6 100 SYN_SENT src=fd42::2 dst=2001:db8::1 sport=1 dport=443 [UNREPLIED] src=2001:db8::1 dst=fd42::2 sport=443 dport=1 mark=0 use=1
conntrack v1.4.8 (conntrack-tools): 3 flow entries have been shown.`
	c := parseSynSent(out)
	if len(c) != 1 || c[0].Dst.String() != "192.0.2.13" || c[0].SPort != 40100 || c[0].DPort != 443 || c[0].Src.String() != "10.9.0.2" {
		t.Fatalf("%+v", c)
	}
	if c[0].Key() != "10.9.0.2:40100>192.0.2.13:443" {
		t.Fatal(c[0].Key())
	}
}
