package engine

import (
	"net/netip"
	"strings"
	"time"

	"vpnpanel/internal/geo"
	"vpnpanel/internal/store"
)

// DemoExtSeen: Beispiel-Absender außerhalb des VPN (nur Testmodus und nur, wenn die Liste leer ist).
func (e *Engine) DemoExtSeen() {
	if !e.Sys.DryRun() {
		return
	}
	// kleine Beispiel-Länderliste (im Testmodus wird nichts heruntergeladen)
	if e.geo.db.Load() == nil {
		var b geo.Builder
		_, _ = b.Add(strings.NewReader(strings.Join([]string{
			"demo|DE|ipv6|2a02:8100::|19|0|allocated",
			"demo|US|ipv4|93.184.0.0|65536|0|allocated",
			"demo|DE|ipv4|185.220.100.0|1024|0|allocated",
			"demo|NL|ipv4|45.83.64.0|1024|0|allocated",
		}, "\n")))
		e.geo.once.Do(func() {})
		e.geo.db.Store(b.Build(time.Now().Unix()))
	}
	x := &e.dnsx
	x.mu.Lock()
	e.loadExt()
	n := len(x.seen)
	x.mu.Unlock()
	if n > 0 {
		return
	}
	var cid int64
	if objs, _ := e.St.Objects("dnsclient"); len(objs) > 0 {
		cid = objs[0].ID
	}
	names := []string{"www.google.com", "i.ytimg.com", "www.netflix.com", "time.android.com", "doubleclick.net", "sync-v2.brave.com"}
	now := time.Now().Unix()
	var logs []store.DNSEntry
	add := func(addr string, client int64, via string, k int) {
		a := netip.MustParseAddr(addr)
		for i := 0; i < k; i++ {
			nm := names[i%len(names)]
			blocked := client != 0 && nm == "doubleclick.net"
			e.noteExt(a, client, nm, client == 0, blocked, via)
			if client == 0 {
				continue
			}
			en := store.DNSEntry{TS: now - int64(i*37), PeerID: -client, Client: addr, Name: nm, QType: 1, Action: "ok", MS: 6, Upstream: "208.67.222.222:53", Transport: via}
			if blocked {
				en.Action, en.Detail, en.Upstream, en.MS = "blocked", "Liste „HaGeZi Multi PRO“", "", 0
			}
			logs = append(logs, en)
		}
	}
	if cid != 0 {
		add("2a02:8109:1234:5600::17", cid, "doh", 40)
		add("93.184.12.34", cid, "dot", 25)
		add("93.184.12.34", cid, "dns", 10)
	}
	add("185.220.101.4", 0, "dns", 12)
	add("45.83.64.1", 0, "doh-addr", 3)
	_ = e.St.AddDNSLog(logs)
	e.saveExt()
}
