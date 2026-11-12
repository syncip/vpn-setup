package geo

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `2|ripencc|20261112|123|19830705|20261111|+0100
ripencc|*|ipv4|*|80000|summary
ripencc|DE|ipv4|2.160.0.0|1048576|20100512|allocated
ripencc|DE|ipv4|2.176.0.0|65536|20100512|allocated
ripencc|FR|ipv4|51.77.0.0|65536|20160219|allocated
ripencc|ZZ|ipv4|10.0.0.0|256|20160219|reserved
ripencc||ipv4|11.0.0.0|256|20160219|available
ripencc|DE|ipv6|2a02:8100::|24|20090211|allocated
ripencc|FR|ipv6|2001:41d0::|32|20020802|allocated
kaputt|zeile
ripencc|NL|ipv4|300.1.1.1|256|20160219|allocated
ripencc|NL|ipv4|255.255.255.0|512|20160219|allocated
`

func TestGeo(t *testing.T) {
	var b Builder
	if n, err := b.Add(strings.NewReader(sample)); err != nil || n != 5 {
		t.Fatalf("Add: %d %v", n, err)
	}
	d := b.Build(1)
	if len(d.V4) != 2 { // die beiden DE-Blöcke grenzen aneinander
		t.Errorf("zusammengefasst: %+v", d.V4)
	}
	for addr, want := range map[string]string{
		"2.160.0.1": "DE", "2.176.255.255": "DE", "2.177.0.0": "", "51.77.247.118": "FR",
		"10.0.0.1": "", "2a02:8100::1": "DE", "2001:41d0:203:4a76::10": "FR", "2001:41d1::1": "",
		"::ffff:51.77.247.118": "FR", "255.255.255.1": "",
	} {
		if got := d.Lookup(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %q, erwartet %q", addr, got, want)
		}
	}
	p := filepath.Join(t.TempDir(), "geo.gob")
	if err := d.Save(p); err != nil {
		t.Fatal(err)
	}
	d2, err := Load(p)
	if err != nil || d2.Lookup(netip.MustParseAddr("51.77.247.118")) != "FR" || d2.At != 1 {
		t.Fatalf("Load: %v", err)
	}
	if (*DB)(nil).Lookup(netip.MustParseAddr("1.1.1.1")) != "" {
		t.Error("leere Liste")
	}
}
