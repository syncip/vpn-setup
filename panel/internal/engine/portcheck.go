package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnpanel/internal/exits"
	"vpnpanel/internal/proto"
)

// Prüfung der Portweiterleitungen auf dem Host – von außen, ohne fremden Prüfdienst:
// Das Panel spricht die eigene öffentliche Adresse über einen Ausgang (externes VPN) an. Die Pakete
// laufen also wie bei einem echten Gerät über das Internet und die Weiterleitung auf dem Host.
// Ein vorübergehender nft-Zähler (Tabelle vpnpanel_portcheck) zeigt, ob sie im Container ankommen –
// so lassen sich auch UDP-Ports prüfen, auf die WireGuard und Hysteria2 nicht antworten.

const (
	pcTable    = "vpnpanel_portcheck"
	pcUDPLen   = 977 // ungewöhnliche Länge: so zählt nft nur die eigenen Prüfpakete
	pcTimeout  = 5 * time.Second
	pcUDPWait  = 2 * time.Second
	pcUDPTries = 3
)

// HostPort: Port eines Servers, den der Host weiterleiten muss.
type HostPort struct {
	Server string `json:"server"`
	proto.Port
}

// HostPorts: alle Ports der aktiven Server (wie in der Karte „Portweiterleitungen auf dem Host“).
func (e *Engine) HostPorts() []HostPort {
	var out []HostPort
	servers, _ := e.St.Servers()
	for _, sv := range servers {
		if d, ok := proto.Get(sv.Protocol); ok && sv.Enabled {
			for _, p := range d.Ports(sv) {
				out = append(out, HostPort{Server: sv.Name, Port: p})
			}
		}
	}
	return out
}

type PortCheckItem struct {
	HostPort
	Family string `json:"family"` // IPv4 | IPv6
	// ok = erreichbar · arrived = kommt an, aber kein Dienst antwortet · missing = kommt nicht an ·
	// skipped = nicht prüfbar
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type PortCheckResult struct {
	At     int64           `json:"at"`
	Via    string          `json:"via"`    // Name des Ausgangs
	ViaIP  string          `json:"via_ip"` // öffentliche Adresse des Ausgangs
	Addr4  string          `json:"addr4"`
	Addr6  string          `json:"addr6"`
	Items  []PortCheckItem `json:"items"`
	DryRun bool            `json:"dry_run,omitempty"`
}

var pcMu sync.Mutex // eine Prüfung zur Zeit (gemeinsame nft-Tabelle)

var (
	pcLastMu sync.Mutex
	pcLast   *PortCheckResult // letztes Ergebnis (bis zum Neustart)
)

// LastPortCheck: Ergebnis der letzten Prüfung (nil = noch keine).
func LastPortCheck() *PortCheckResult {
	pcLastMu.Lock()
	defer pcLastMu.Unlock()
	return pcLast
}

func rememberPortCheck(r *PortCheckResult) *PortCheckResult {
	pcLastMu.Lock()
	pcLast = r
	pcLastMu.Unlock()
	return r
}

// pickProbeExit: verbundener, fehlerfreier Ausgang mit dem geringsten Verlust.
func (e *Engine) pickProbeExit() (*exits.Exit, exits.ExitStatus, error) {
	if e.Exits == nil {
		return nil, exits.ExitStatus{}, errors.New("Ausgänge sind nicht aktiv")
	}
	xs, _ := e.LoadExits()
	st, _ := e.Exits.Status()
	var best *exits.Exit
	var bestSt exits.ExitStatus
	for _, x := range xs {
		s, ok := st[x.ID]
		if !x.Enabled || !ok || !s.Up || s.Error != "" || (s.Standby && !s.Connected) || s.Loss >= 50 {
			continue
		}
		if best == nil || s.Loss < bestSt.Loss || (s.Loss == bestSt.Loss && s.RTT < bestSt.RTT) {
			best, bestSt = x, s
		}
	}
	if best == nil {
		return nil, exits.ExitStatus{}, errors.New("Für die Prüfung von außen braucht es einen verbundenen Ausgang " +
			"(Netzwerk → Ausgänge) – über ihn spricht das Panel die eigene Adresse wie ein fremdes Gerät an")
	}
	return best, bestSt, nil
}

// CheckPorts prüft alle Portweiterleitungen (IPv4 über einen Ausgang; IPv6 können Ausgänge nicht).
func (e *Engine) CheckPorts() (*PortCheckResult, error) {
	if !pcMu.TryLock() {
		return nil, errors.New("Es läuft bereits eine Prüfung")
	}
	defer pcMu.Unlock()
	ports := e.HostPorts()
	res := &PortCheckResult{At: time.Now().Unix(), Items: []PortCheckItem{}}
	if len(ports) == 0 {
		return nil, errors.New("Keine aktiven Server – es gibt keine Ports zu prüfen")
	}
	pub4, pub6 := e.PublicAddrs()
	if pub6.IsValid() {
		res.Addr6 = pub6.String()
	}
	if e.Sys.DryRun() {
		return rememberPortCheck(e.dryPortCheck(res, ports, pub4)), nil
	}
	if !pub4.IsValid() {
		return nil, errors.New("Die Server-Adresse (Einstellungen → Allgemein) fehlt oder hat keine IPv4-Adresse")
	}
	res.Addr4 = pub4.String()
	x, xst, err := e.pickProbeExit()
	if err != nil {
		return nil, err
	}
	res.Via, res.ViaIP = x.Name, xst.IP
	src, _ := netip.ParseAddr(xst.IP)
	if !src.Is4() {
		src = netip.Addr{}
	}

	// Zähler je Port (Absender = Ausgang, falls bekannt; UDP zusätzlich an der Länge erkennbar)
	if err := e.pcSetup(ports, src); err != nil {
		return nil, fmt.Errorf("Zähler (nftables): %v", err)
	}
	defer func() { _, _ = e.Sys.Run("nft", "delete", "table", "inet", pcTable) }()

	mark := exits.ProbeMark(x.Slot)
	items := make([]PortCheckItem, len(ports))
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		go func(i int, p HostPort) {
			defer wg.Done()
			items[i] = e.pcProbe(p, pub4, mark, i)
		}(i, p)
	}
	wg.Wait()
	counts := e.pcCounters()
	for i := range items {
		it := &items[i]
		n := counts[pcComment(i)]
		switch {
		case it.State == "ok":
		case n > 0 && it.Proto == "udp":
			it.State, it.Detail = "ok", "Prüfpaket kam im Container an"
		case n > 0:
			it.State = "arrived"
			it.Detail = "kommt an, aber kein Dienst nimmt an – läuft der Dienst? (" + it.Detail + ")"
		case it.Proto != "udp" && !src.IsValid():
			// ohne bekannte Adresse des Ausgangs gibt es für TCP keinen Zähler
			it.State = "missing"
			it.Detail = "keine Verbindung (" + it.Detail + ") – Weiterleitung auf dem Host und Dienst prüfen"
		default:
			it.State = "missing"
			it.Detail = "kommt nicht an – Weiterleitung auf dem Host fehlt oder eine Firewall blockiert"
		}
	}
	res.Items = append(res.Items, items...)
	for _, p := range ports {
		it := PortCheckItem{HostPort: p, Family: "IPv6", State: "skipped",
			Detail: "nicht prüfbar – Ausgänge können nur IPv4"}
		if !pub6.IsValid() {
			it.Detail = "Server-Adresse hat keine IPv6-Adresse"
		}
		res.Items = append(res.Items, it)
	}
	e.Log("info", fmt.Sprintf("Portweiterleitungen über Ausgang „%s“ geprüft: %s", x.Name, pcSummary(res.Items)))
	return rememberPortCheck(res), nil
}

func pcComment(i int) string { return "p" + strconv.Itoa(i) }

func pcSummary(items []PortCheckItem) string {
	n := map[string]int{}
	for _, it := range items {
		if it.Family == "IPv4" {
			n[it.State]++
		}
	}
	return fmt.Sprintf("%d erreichbar, %d ohne Dienst, %d kommen nicht an", n["ok"], n["arrived"], n["missing"])
}

// pcScript: eigene Tabelle nur mit Zählern (policy accept) – verändert keinen Verkehr.
func pcScript(ports []HostPort, src netip.Addr) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", pcTable, pcTable, pcTable)
	b.WriteString("\tchain pre {\n\t\ttype filter hook prerouting priority -350; policy accept;\n")
	for i, p := range ports {
		match := ""
		if src.IsValid() {
			match = "ip saddr " + src.String() + " "
		}
		if p.Proto == "udp" {
			match += fmt.Sprintf("udp dport %d udp length %d", p.Port.Port, pcUDPLen+8)
		} else {
			match += fmt.Sprintf("tcp dport %d tcp flags & (syn|ack) == syn", p.Port.Port)
		}
		if !src.IsValid() && p.Proto != "udp" {
			continue // TCP ohne bekannten Absender: Zähler wäre durch echte Clients verfälscht
		}
		fmt.Fprintf(&b, "\t\t%s counter comment %q\n", match, pcComment(i))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func (e *Engine) pcSetup(ports []HostPort, src netip.Addr) error {
	if out, err := e.Sys.RunInput(pcScript(ports, src), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// pcCounters: Pakete je Kommentar.
func (e *Engine) pcCounters() map[string]int {
	out, err := e.Sys.Run("nft", "-j", "list", "table", "inet", pcTable)
	if err != nil {
		return nil
	}
	return parsePCCounters(out)
}

func parsePCCounters(out string) map[string]int {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return nil
	}
	m := map[string]int{}
	for _, it := range doc.Nftables {
		if it.Rule == nil {
			continue
		}
		for _, raw := range it.Rule.Expr {
			var c struct {
				Counter *struct {
					Packets int `json:"packets"`
				} `json:"counter"`
			}
			if json.Unmarshal(raw, &c) == nil && c.Counter != nil {
				m[it.Rule.Comment] += c.Counter.Packets
			}
		}
	}
	return m
}

// pcProbe: TCP – Verbindung über den Ausgang; UDP – Prüfpakete senden (Ergebnis über den Zähler).
func (e *Engine) pcProbe(p HostPort, pub4 netip.Addr, mark uint32, i int) PortCheckItem {
	it := PortCheckItem{HostPort: p, Family: "IPv4"}
	addr := net.JoinHostPort(pub4.String(), strconv.Itoa(p.Port.Port))
	d := exits.Dialer(mark)
	d.Timeout = pcTimeout
	ctx, cancel := context.WithTimeout(context.Background(), pcTimeout)
	defer cancel()
	if p.Proto != "udp" {
		c, err := d.DialContext(ctx, "tcp4", addr)
		if err != nil {
			it.Detail = pcErr(err)
			return it
		}
		_ = c.Close()
		it.State, it.Detail = "ok", "Verbindung angenommen"
		return it
	}
	c, err := d.DialContext(ctx, "udp4", addr)
	if err != nil {
		it.Detail = pcErr(err)
		return it
	}
	defer c.Close()
	payload := make([]byte, pcUDPLen)
	copy(payload, "vpnpanel-portcheck "+pcComment(i))
	for n := 0; n < pcUDPTries; n++ {
		_, _ = c.Write(payload)
		time.Sleep(pcUDPWait / pcUDPTries)
	}
	return it
}

func pcErr(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "Zeitüberschreitung"
	case strings.Contains(err.Error(), "refused"):
		return "abgewiesen"
	}
	return err.Error()
}

// dryPortCheck: Testmodus – Ergebnis ohne Netzwerk, damit sich die Oberfläche prüfen lässt.
func (e *Engine) dryPortCheck(res *PortCheckResult, ports []HostPort, pub4 netip.Addr) *PortCheckResult {
	res.DryRun = true
	res.Via, res.ViaIP = "Testmodus", "203.0.113.7"
	if pub4.IsValid() {
		res.Addr4 = pub4.String()
	} else {
		res.Addr4 = "198.51.100.10"
	}
	for i, p := range ports {
		it := PortCheckItem{HostPort: p, Family: "IPv4", State: "ok", Detail: "Verbindung angenommen"}
		if p.Proto == "udp" {
			it.Detail = "Prüfpaket kam im Container an"
		}
		if i == len(ports)-1 && len(ports) > 1 {
			it.State, it.Detail = "missing", "kommt nicht an – Weiterleitung auf dem Host fehlt oder eine Firewall blockiert"
		}
		res.Items = append(res.Items, it)
	}
	for _, p := range ports {
		res.Items = append(res.Items, PortCheckItem{HostPort: p, Family: "IPv6", State: "skipped", Detail: "nicht prüfbar – Ausgänge können nur IPv4"})
	}
	return res
}
