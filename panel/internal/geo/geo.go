// Package geo ordnet IP-Adressen einem Land zu – aus den Vergabelisten der fünf regionalen
// Registrierungsstellen (RIPE NCC, ARIN, APNIC, LACNIC, AFRINIC). Die Listen werden einmal
// heruntergeladen und lokal ausgewertet; keine Adresse verlässt den Server. Genauigkeit: das Land,
// in dem der Adressblock registriert ist (bei Endkunden-Anschlüssen fast immer das richtige).
package geo

import (
	"bufio"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Sources: Vergabelisten (Format „registry|cc|type|start|value|date|status“).
var Sources = []string{
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}

// MaxLine: längere Zeilen gelten als kaputt (die echten sind < 100 Zeichen).
const MaxLine = 512

type range4 struct {
	Lo, Hi uint32
	CC     [2]byte
}

type range6 struct {
	Lo, Hi [16]byte
	CC     [2]byte
}

// DB: sortierte Adressbereiche je Land.
type DB struct {
	At int64 // Zeitpunkt des Downloads (Unix)
	V4 []range4
	V6 []range6
}

// Builder sammelt Bereiche aus mehreren Listen.
type Builder struct {
	v4 []range4
	v6 []range6
}

// Add liest eine Vergabeliste; ungültige Zeilen werden übersprungen.
func (b *Builder) Add(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), MaxLine)
	n := 0
	for sc.Scan() {
		f := strings.Split(sc.Text(), "|")
		if len(f) < 7 || (f[6] != "allocated" && f[6] != "assigned") {
			continue
		}
		cc := strings.ToUpper(f[1])
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			continue
		}
		code := [2]byte{cc[0], cc[1]}
		start, err := netip.ParseAddr(f[3])
		if err != nil {
			continue
		}
		v, err := strconv.ParseUint(f[4], 10, 64)
		if err != nil || v == 0 {
			continue
		}
		switch {
		case f[2] == "ipv4" && start.Is4():
			lo := binary.BigEndian.Uint32(start.AsSlice())
			if v > uint64(^uint32(0)-lo)+1 {
				continue
			}
			b.v4 = append(b.v4, range4{lo, lo + uint32(v-1), code})
			n++
		case f[2] == "ipv6" && start.Is6() && v <= 128:
			p, err := start.Prefix(int(v))
			if err != nil {
				continue
			}
			lo := p.Addr().As16()
			hi := lo
			for i := int(v); i < 128; i++ {
				hi[i/8] |= 1 << (7 - i%8)
			}
			b.v6 = append(b.v6, range6{lo, hi, code})
			n++
		}
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}

// Build sortiert und fasst aneinandergrenzende Bereiche desselben Landes zusammen.
func (b *Builder) Build(at int64) *DB {
	sort.Slice(b.v4, func(i, j int) bool { return b.v4[i].Lo < b.v4[j].Lo })
	v4 := make([]range4, 0, len(b.v4))
	for _, r := range b.v4 {
		if k := len(v4) - 1; k >= 0 && v4[k].CC == r.CC && uint64(v4[k].Hi)+1 >= uint64(r.Lo) {
			v4[k].Hi = max(v4[k].Hi, r.Hi)
			continue
		}
		v4 = append(v4, r)
	}
	sort.Slice(b.v6, func(i, j int) bool { return less16(b.v6[i].Lo, b.v6[j].Lo) })
	v6 := make([]range6, 0, len(b.v6))
	for _, r := range b.v6 {
		if k := len(v6) - 1; k >= 0 && v6[k].CC == r.CC && !less16(r.Lo, v6[k].Lo) && !less16(v6[k].Hi, r.Lo) {
			if less16(v6[k].Hi, r.Hi) {
				v6[k].Hi = r.Hi
			}
			continue
		}
		v6 = append(v6, r)
	}
	return &DB{At: at, V4: v4, V6: v6}
}

func less16(a, b [16]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// Lookup liefert den Ländercode (z. B. „DE“) oder "".
func (d *DB) Lookup(a netip.Addr) string {
	if d == nil || !a.IsValid() {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		x := binary.BigEndian.Uint32(a.AsSlice())
		i := sort.Search(len(d.V4), func(i int) bool { return d.V4[i].Lo > x }) - 1
		if i >= 0 && x <= d.V4[i].Hi {
			return string(d.V4[i].CC[:])
		}
		return ""
	}
	x := a.As16()
	i := sort.Search(len(d.V6), func(i int) bool { return less16(x, d.V6[i].Lo) }) - 1
	if i >= 0 && !less16(d.V6[i].Hi, x) {
		return string(d.V6[i].CC[:])
	}
	return ""
}

// Save schreibt die ausgewertete Liste (gob, über eine temporäre Datei).
func (d *DB) Save(path string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(f).Encode(d); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Load liest eine mit Save geschriebene Liste.
func Load(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var d DB
	if err := gob.NewDecoder(io.LimitReader(f, 64<<20)).Decode(&d); err != nil {
		return nil, err
	}
	if !sort.SliceIsSorted(d.V4, func(i, j int) bool { return d.V4[i].Lo < d.V4[j].Lo }) ||
		!sort.SliceIsSorted(d.V6, func(i, j int) bool { return less16(d.V6[i].Lo, d.V6[j].Lo) }) {
		return nil, errors.New("Länderliste beschädigt")
	}
	return &d, nil
}
