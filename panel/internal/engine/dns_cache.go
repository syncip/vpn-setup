package engine

// Panel-DNS: Zwischenspeicher und Protokoll (dns_log).

import (
	"encoding/binary"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"vpnpanel/internal/store"
)

// ---------- Zwischenspeicher ----------

// cached liefert eine gespeicherte Antwort mit der ID der Anfrage und heruntergezählten TTLs.
func (g *dnsGate) cached(key string, id uint16) ([]byte, bool) {
	g.mu.Lock()
	a := g.answers[key]
	g.mu.Unlock()
	if a == nil {
		return nil, false
	}
	now := time.Now()
	if now.After(a.exp) {
		return nil, false
	}
	out := append([]byte(nil), a.msg...)
	binary.BigEndian.PutUint16(out, id)
	adjustTTL(out, uint32(now.Sub(a.at).Seconds()))
	return out, true
}

// store merkt sich eine Antwort (nicht abgeschnittene, ohne Serverfehler) für ihre kleinste TTL.
func (g *dnsGate) store(key string, msg []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Truncated || (h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError) {
		return
	}
	ttl := uint32(3600)
	if p.SkipAllQuestions() != nil {
		return
	}
	n := 0
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		n++
		if rh.TTL < ttl {
			ttl = rh.TTL
		}
		if p.SkipAnswer() != nil {
			break
		}
	}
	if n == 0 { // leere Antworten / „gibt es nicht“: kurz merken
		ttl = 60
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cacheMax == 0 {
		return // Zwischenspeicher aus
	}
	if g.ttlMin > 0 && ttl < g.ttlMin {
		ttl = g.ttlMin
	}
	if g.ttlMax > 0 && ttl > g.ttlMax {
		ttl = g.ttlMax
	}
	if ttl < 5 {
		return
	}
	if g.answers == nil {
		g.answers = map[string]*dnsAnswer{}
	}
	if len(g.answers) >= g.cacheMax {
		i := 0
		for k, v := range g.answers { // abgelaufene und ein Zehntel zufällig entfernen
			if now.After(v.exp) || i%10 == 0 {
				delete(g.answers, k)
			}
			i++
		}
	}
	g.answers[key] = &dnsAnswer{msg: append([]byte(nil), msg...), at: now, exp: now.Add(time.Duration(ttl) * time.Second)}
}

// adjustTTL zieht von allen TTLs (außer OPT) die vergangene Zeit ab.
func adjustTTL(m []byte, sub uint32) {
	if sub == 0 || len(m) < 12 {
		return
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	rr := int(binary.BigEndian.Uint16(m[6:])) + int(binary.BigEndian.Uint16(m[8:])) + int(binary.BigEndian.Uint16(m[10:]))
	off := 12
	skipName := func() bool {
		for off < len(m) {
			l := int(m[off])
			switch {
			case l == 0:
				off++
				return true
			case l&0xC0 == 0xC0:
				off += 2
				return off <= len(m)
			default:
				off += l + 1
			}
		}
		return false
	}
	for i := 0; i < qd; i++ {
		if !skipName() {
			return
		}
		off += 4
	}
	for i := 0; i < rr; i++ {
		if !skipName() || off+10 > len(m) {
			return
		}
		typ := binary.BigEndian.Uint16(m[off:])
		if typ != 41 {
			ttl := binary.BigEndian.Uint32(m[off+4:])
			if ttl > sub {
				ttl -= sub
			} else {
				ttl = 1
			}
			binary.BigEndian.PutUint32(m[off+4:], ttl)
		}
		off += 10 + int(binary.BigEndian.Uint16(m[off+8:]))
	}
}

// ---------- Protokoll ----------

func (g *dnsGate) logEntry(en store.DNSEntry) {
	g.mu.Lock()
	on, ch := g.logOn, g.logCh
	g.mu.Unlock()
	if !on || ch == nil {
		return
	}
	select {
	case ch <- en:
	default: // Datenbank kommt nicht hinterher → Eintrag fällt weg
	}
}

// writeLog schreibt das Protokoll gesammelt (alle 2 Sekunden) und räumt stündlich auf.
func (g *dnsGate) writeLog(e *Engine, ch chan store.DNSEntry) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var buf []store.DNSEntry
	var pruned time.Time
	for {
		select {
		case en := <-ch:
			buf = append(buf, en)
			if len(buf) < 2000 {
				continue
			}
		case <-t.C:
		}
		if len(buf) > 0 {
			if err := e.St.AddDNSLog(buf); err != nil {
				e.setErr("dnslog", "DNS-Protokoll: "+err.Error())
			}
			buf = buf[:0]
		}
		if time.Since(pruned) > time.Hour {
			pruned = time.Now()
			days := atoi(e.Setting("dns_log_days"), 7)
			if days <= 0 {
				days = 0
			}
			_, _ = e.St.PruneDNSLog(time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix())
		}
	}
}
