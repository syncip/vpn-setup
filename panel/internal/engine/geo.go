package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"vpnpanel/internal/geo"
)

// Länder zu Absender-Adressen (DNS von außen): Vergabelisten der Registrierungsstellen, einmal pro
// Woche geladen und lokal ausgewertet – keine Adresse wird an einen fremden Dienst geschickt.

const (
	geoEvery   = 7 * 24 * time.Hour
	geoRetry   = 6 * time.Hour
	geoMaxFile = 64 << 20 // je Liste (die größte hat ~10 MB)
	geoMinV4   = 50000    // weniger Bereiche → Download unvollständig, alte Liste behalten
)

type geoState struct {
	db      atomic.Pointer[geo.DB]
	once    sync.Once
	busy    atomic.Bool
	mu      sync.Mutex
	lastTry time.Time
	err     string
}

func (e *Engine) geoPath() string { return filepath.Join(e.Cfg.DataDir, "geo.gob") }

// countryOf: Ländercode einer Adresse ("" = unbekannt bzw. Liste noch nicht geladen).
func (e *Engine) countryOf(a netip.Addr) string {
	g := &e.geo
	g.once.Do(func() {
		if d, err := geo.Load(e.geoPath()); err == nil {
			g.db.Store(d)
		}
	})
	return g.db.Load().Lookup(a)
}

// refreshGeo lädt die Listen neu, wenn fällig (im Hintergrund, nur wenn DNS von außen genutzt wird).
func (e *Engine) refreshGeo() {
	if e.Sys.DryRun() || !(e.dnsPublic() || e.encDNSOn()) {
		return
	}
	g := &e.geo
	e.countryOf(netip.Addr{}) // gespeicherte Liste laden
	if d := g.db.Load(); d != nil && time.Since(time.Unix(d.At, 0)) < geoEvery {
		return
	}
	g.mu.Lock()
	due := time.Since(g.lastTry) > geoRetry
	if due {
		g.lastTry = time.Now()
	}
	g.mu.Unlock()
	if !due || !g.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.busy.Store(false)
		err := e.downloadGeo()
		g.mu.Lock()
		g.err = ""
		if err != nil {
			g.err = err.Error()
		}
		g.mu.Unlock()
		if err != nil {
			e.Log("warn", "Länderliste: "+err.Error())
		}
	}()
}

func (e *Engine) downloadGeo() error {
	var b geo.Builder
	cl := &http.Client{Timeout: 3 * time.Minute}
	ok := 0
	var last error
	for _, src := range geo.Sources {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		resp, err := cl.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				_, err = b.Add(io.LimitReader(resp.Body, geoMaxFile))
			} else {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			resp.Body.Close()
		}
		cancel()
		if err != nil {
			last = fmt.Errorf("%s: %w", src, err)
			continue
		}
		ok++
	}
	d := b.Build(time.Now().Unix())
	if ok < len(geo.Sources) || len(d.V4) < geoMinV4 {
		if last == nil {
			last = fmt.Errorf("nur %d Adressbereiche", len(d.V4))
		}
		return fmt.Errorf("unvollständig geladen (%d von %d Listen), alte Liste bleibt: %w", ok, len(geo.Sources), last)
	}
	if err := d.Save(e.geoPath()); err != nil {
		return err
	}
	e.geo.db.Store(d)
	e.Log("info", fmt.Sprintf("Länderliste geladen: %d IPv4- und %d IPv6-Bereiche", len(d.V4), len(d.V6)))
	return nil
}

// GeoState: Stand der Länderliste für die Oberfläche.
func (e *Engine) GeoState() map[string]any {
	g := &e.geo
	e.countryOf(netip.Addr{})
	g.mu.Lock()
	defer g.mu.Unlock()
	st := map[string]any{"err": g.err, "busy": g.busy.Load()}
	if d := g.db.Load(); d != nil {
		st["at"] = d.At
	}
	return st
}
