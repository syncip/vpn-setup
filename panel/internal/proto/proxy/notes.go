package proxy

import (
	"sync"
	"time"
)

// Ereignisse zu abgelehnten Verbindungen und Anmeldungen. Gedrosselt: pro Schlüssel (Adresse + Grund)
// höchstens einmal in noteEvery, insgesamt höchstens noteMax pro Minute – Portscanner und
// Angreifer sollen das Ereignisprotokoll nicht fluten.
const (
	noteEvery = 10 * time.Minute
	noteMax   = 30
)

var notes = struct {
	sync.Mutex
	log   func(level, msg string)
	last  map[string]time.Time
	win   time.Time
	count int
}{last: map[string]time.Time{}}

func setLog(f func(level, msg string)) {
	notes.Lock()
	notes.log = f
	notes.Unlock()
}

// note meldet ein Ereignis (gedrosselt). Nie mit gehaltenem mgr-Lock aufrufen.
func note(level, key, msg string) {
	notes.Lock()
	f := notes.log
	now := time.Now()
	if f == nil {
		notes.Unlock()
		return
	}
	if t, ok := notes.last[key]; ok && now.Sub(t) < noteEvery {
		notes.Unlock()
		return
	}
	if now.Sub(notes.win) > time.Minute {
		notes.win, notes.count = now, 0
	}
	if notes.count >= noteMax {
		notes.Unlock()
		return
	}
	notes.count++
	notes.last[key] = now
	if len(notes.last) > 5000 {
		for k, t := range notes.last {
			if now.Sub(t) >= noteEvery {
				delete(notes.last, k)
			}
		}
	}
	notes.Unlock()
	f(level, msg)
}

// resetNotes: nur für Tests.
func resetNotes() {
	notes.Lock()
	notes.last = map[string]time.Time{}
	notes.win, notes.count = time.Time{}, 0
	notes.Unlock()
}
