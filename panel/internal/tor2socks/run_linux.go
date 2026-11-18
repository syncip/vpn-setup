//go:build linux

package tor2socks

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
)

// Run hängt sich an die (vom Panel angelegte) TUN-Schnittstelle dev und leitet sie an Tor weiter,
// bis stop geschlossen wird.
func Run(dev string, h *Handler, stop <-chan struct{}) error {
	d, err := tun.Open(dev, 0)
	if err != nil {
		return fmt.Errorf("Schnittstelle %s: %w", dev, err)
	}
	st, err := core.CreateStack(&core.Config{LinkEndpoint: d, TransportHandler: h, ICMPHandler: h})
	if err != nil {
		d.Close()
		return fmt.Errorf("Netzwerk-Stack: %w", err)
	}
	<-stop
	st.Close()
	st.Wait()
	return nil
}

// Main: Unterbefehl „vpnpanel tun2socks -dev exN -socks 127.0.0.1:P -dns 127.0.0.1:Q“.
func Main(args []string) error {
	dev, socks, dns, err := parseArgs(args)
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; close(stop) }()
	h := &Handler{Socks: socks, DNS: dns, Log: func(s string) { fmt.Fprintln(os.Stderr, s) }}
	fmt.Fprintf(os.Stderr, "Tor-Ausgang %s → SOCKS %s, DNS %s\n", dev, socks, dns)
	return Run(dev, h, stop)
}
