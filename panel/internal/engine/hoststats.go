package engine

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kennzahlen des Servers für die Seitenleiste: CPU, RAM, Datenträger, Durchsatz der ausgehenden
// Schnittstelle. Liest nur /proc (im LXC liefert lxcfs die Werte des Containers) – keine Befehle.

type HostStats struct {
	CPU      float64 `json:"cpu"`       // Prozent über alle Kerne seit der letzten Abfrage
	Cores    int     `json:"cores"`     //
	Load1    float64 `json:"load1"`     //
	MemUsed  uint64  `json:"mem_used"`  // Byte (ohne Cache)
	MemTotal uint64  `json:"mem_total"` //
	DiskUsed uint64  `json:"disk_used"` // Datenverzeichnis
	DiskSize uint64  `json:"disk_size"` //
	RX       float64 `json:"rx"`        // Byte/s auf der ausgehenden Schnittstelle
	TX       float64 `json:"tx"`        //
	Iface    string  `json:"iface"`     //
	Uptime   int64   `json:"uptime"`    // Sekunden
}

type hostSampler struct {
	mu        sync.Mutex
	at        time.Time
	busy, all uint64
	rx, tx    uint64
	iface     string
	last      HostStats
}

// HostStats: aktuelle Werte; CPU und Durchsatz als Mittel seit der vorigen Abfrage (mind. 1 s Abstand,
// häufigere Abfragen bekommen das letzte Ergebnis).
func (e *Engine) HostStats() HostStats {
	h := &e.host
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if now.Sub(h.at) < time.Second {
		return h.last
	}
	if e.Sys.DryRun() {
		h.last = dryHostStats(now)
		h.at = now
		return h.last
	}
	var s HostStats
	iface := e.Setting("out_interface")
	if iface == "" {
		iface = "eth0"
	}
	s.Iface = iface
	busy, all, cores := readCPU()
	rx, tx := readIfaceBytes(iface)
	if dt := now.Sub(h.at).Seconds(); !h.at.IsZero() && dt > 0 && iface == h.iface {
		if all > h.all {
			s.CPU = round1(100 * float64(busy-h.busy) / float64(all-h.all))
		}
		if rx >= h.rx && tx >= h.tx {
			s.RX, s.TX = float64(rx-h.rx)/dt, float64(tx-h.tx)/dt
		}
	}
	h.busy, h.all, h.rx, h.tx, h.iface = busy, all, rx, tx, iface
	s.Cores = cores
	s.MemUsed, s.MemTotal = readMem()
	s.Load1, s.Uptime = readLoadUptime()
	s.DiskUsed, s.DiskSize = diskUsage(e.Cfg.DataDir)
	h.at, h.last = now, s
	return s
}

// readCPU: Summe busy/all aus der ersten Zeile von /proc/stat und Anzahl der Kerne.
func readCPU() (busy, all uint64, cores int) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) == 0 || !strings.HasPrefix(fl[0], "cpu") {
			continue
		}
		if fl[0] != "cpu" {
			cores++
			continue
		}
		for i, v := range fl[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			all += n
			if i != 3 && i != 4 { // idle, iowait
				busy += n
			}
		}
	}
	return
}

func parseMeminfo(text string) (used, total uint64) {
	vals := map[string]uint64{}
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		fl := strings.Fields(v)
		if len(fl) > 0 {
			n, _ := strconv.ParseUint(fl[0], 10, 64)
			vals[k] = n * 1024
		}
	}
	total = vals["MemTotal"]
	avail, ok := vals["MemAvailable"]
	if !ok {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	if avail < total {
		used = total - avail
	}
	return
}

func readMem() (used, total uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	return parseMeminfo(string(b))
}

func readLoadUptime() (load float64, up int64) {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fl := strings.Fields(string(b)); len(fl) > 0 {
			load, _ = strconv.ParseFloat(fl[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if fl := strings.Fields(string(b)); len(fl) > 0 {
			f, _ := strconv.ParseFloat(fl[0], 64)
			up = int64(f)
		}
	}
	return
}

// parseNetDev: empfangene/gesendete Byte einer Schnittstelle aus /proc/net/dev.
func parseNetDev(text, iface string) (rx, tx uint64) {
	for _, l := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}
		fl := strings.Fields(rest)
		if len(fl) >= 9 {
			rx, _ = strconv.ParseUint(fl[0], 10, 64)
			tx, _ = strconv.ParseUint(fl[8], 10, 64)
		}
	}
	return
}

func readIfaceBytes(iface string) (rx, tx uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	return parseNetDev(string(b), iface)
}

// dryHostStats: Testmodus – ruhig schwankende Werte, damit sich die Oberfläche prüfen lässt.
func dryHostStats(now time.Time) HostStats {
	t := float64(now.Unix())
	return HostStats{CPU: round1(14 + 8*math.Sin(t/17)), Cores: 4, Load1: 0.42, MemUsed: 1_740_000_000, MemTotal: 4_000_000_000,
		DiskUsed: 3_200_000_000, DiskSize: 20_000_000_000, RX: 4_200_000 + 1_500_000*math.Sin(t/9), TX: 610_000 + 200_000*math.Cos(t/11),
		Iface: "eth0", Uptime: 864000}
}
