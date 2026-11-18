package tor2socks

import (
	"flag"
	"fmt"
	"net/netip"
	"regexp"
)

var devRe = regexp.MustCompile(`^ex[0-9]{1,9}$`)

func parseArgs(args []string) (dev, socks, dns string, err error) {
	fs := flag.NewFlagSet("tun2socks", flag.ContinueOnError)
	fs.StringVar(&dev, "dev", "", "Schnittstelle (exN)")
	fs.StringVar(&socks, "socks", "", "SOCKS-Port von Tor (127.0.0.1:Port)")
	fs.StringVar(&dns, "dns", "", "DNSPort von Tor (127.0.0.1:Port)")
	if err = fs.Parse(args); err != nil {
		return
	}
	if !devRe.MatchString(dev) {
		return "", "", "", fmt.Errorf("-dev exN fehlt")
	}
	for _, a := range []string{socks, dns} {
		ap, e := netip.ParseAddrPort(a)
		if e != nil || !ap.Addr().IsLoopback() {
			return "", "", "", fmt.Errorf("-socks/-dns: nur 127.0.0.1:Port erlaubt (%q)", a)
		}
	}
	return
}
