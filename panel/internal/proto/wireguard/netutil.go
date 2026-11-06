package wireguard

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// addrAt liefert die Adresse base+i innerhalb des Präfixes.
func addrAt(p netip.Prefix, i uint64) (netip.Addr, error) {
	base := p.Masked().Addr()
	b := base.AsSlice()
	if base.Is4() {
		v := uint64(binary.BigEndian.Uint32(b)) + i
		if v > 0xffffffff {
			return netip.Addr{}, fmt.Errorf("Adressbereich erschöpft")
		}
		binary.BigEndian.PutUint32(b, uint32(v))
	} else {
		lo := binary.BigEndian.Uint64(b[8:]) + i
		binary.BigEndian.PutUint64(b[8:], lo)
	}
	a, _ := netip.AddrFromSlice(b)
	if base.Is4() {
		a = a.Unmap()
	}
	if !p.Contains(a) {
		return netip.Addr{}, fmt.Errorf("Adressbereich %s erschöpft", p)
	}
	return a, nil
}

// hostCount: Anzahl nutzbarer Adressen (begrenzt, damit Schleifen endlich bleiben).
func hostCount(p netip.Prefix) uint64 {
	bits := p.Addr().BitLen() - p.Bits()
	if bits >= 16 {
		return 65534
	}
	return (uint64(1) << bits) - 2
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("ungültiges Netz %q", s)
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("ungültiges Netz %q", s)
	}
	return p.Masked(), nil
}

func overlaps(a, b netip.Prefix) bool { return a.Overlaps(b) }

func hostPrefix(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

func split46(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

// nextNet erhöht ein Netz um eins (10.8.0.0/24 → 10.9.0.0/24 bzw. fd42:42:42::/64 → fd42:42:43::/64).
func nextNet(p netip.Prefix) netip.Prefix {
	b := p.Masked().Addr().AsSlice()
	if p.Addr().Is4() {
		// zweites Oktett hochzählen (10.8 → 10.9), so bleiben die Netze leicht lesbar
		b[1]++
	} else {
		v := binary.BigEndian.Uint16(b[4:6]) + 1
		binary.BigEndian.PutUint16(b[4:6], v)
	}
	a, _ := netip.AddrFromSlice(b)
	return netip.PrefixFrom(a.Unmap(), p.Bits())
}
