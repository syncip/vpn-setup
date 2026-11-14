package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

func TestLockKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":            "203.0.113.7",
		"::ffff:203.0.113.7":     "203.0.113.7",
		"2001:db8:1:2:aaaa::1":   "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::fff": "2001:db8:1:2::/64",
	} {
		if got := lockKey(in); got != want {
			t.Errorf("%s → %s, erwartet %s", in, got, want)
		}
	}
}

func TestLoginLockByAddress(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := engine.New(st, &system.Dry{Root: filepath.Join(dir, "dryroot")}, engine.Config{PanelBackend: "127.0.0.1:8480", DataDir: dir})
	a := New(e, nil, false, "0.18.0")
	h, _ := HashPassword("geheimes-passwort-1")
	if err := st.SaveAdmin(&store.Admin{Username: "admin", PassHash: h}); err != nil {
		t.Fatal(err)
	}
	_ = st.SetSetting("login_max_fails", "3")
	handler := a.Handler()
	login := func(from, pw string) int {
		j, _ := json.Marshal(map[string]string{"username": "admin", "password": pw})
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(j))
		req.Header.Set("X-Requested-With", "vpnpanel")
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = from + ":40000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 3; i++ {
		if c := login("203.0.113.7", "falsch-falsch"); c != http.StatusUnauthorized {
			t.Fatalf("Fehlversuch %d: %d", i+1, c)
		}
	}
	// Angreifer-Adresse ist gesperrt – auch mit richtigem Passwort
	if c := login("203.0.113.7", "geheimes-passwort-1"); c != http.StatusTooManyRequests {
		t.Errorf("gesperrte Adresse: %d, erwartet 429", c)
	}
	// der echte Admin von einer anderen Adresse kommt weiter rein (Name wird nie gesperrt)
	if c := login("198.51.100.20", "geheimes-passwort-1"); c != http.StatusOK {
		t.Errorf("andere Adresse: %d, erwartet 200", c)
	}
	locks, _ := st.LoginLocks()
	if len(locks) != 1 || locks[0].Net != "203.0.113.7" || locks[0].Strikes != 1 || locks[0].Until == 0 {
		t.Fatalf("Sperre falsch: %+v", locks)
	}
	// IPv6: ganze /64 gesperrt
	for i := 0; i < 3; i++ {
		login("[2001:db8:1:2::"+string(rune('a'+i))+"]", "falsch-falsch")
	}
	if c := login("[2001:db8:1:2::ffff]", "geheimes-passwort-1"); c != http.StatusTooManyRequests {
		t.Errorf("IPv6 aus demselben /64: %d, erwartet 429", c)
	}
	// Ausnahmeliste: nie gesperrt
	_ = st.SetSetting("login_allow", "192.0.2.0/24")
	for i := 0; i < 5; i++ {
		login("192.0.2.9", "falsch-falsch")
	}
	if c := login("192.0.2.9", "geheimes-passwort-1"); c != http.StatusOK {
		t.Errorf("Adresse aus der Ausnahmeliste gesperrt: %d", c)
	}
	// Wiederholung verdoppelt die Dauer
	_ = st.DeleteLoginLock("203.0.113.7")
	prev := locks[0]
	_ = st.PutLoginLock(&store.LoginLock{Net: "203.0.113.7", Until: 1, Strikes: 1, Created: prev.Created})
	for i := 0; i < 3; i++ {
		login("203.0.113.7", "falsch-falsch")
	}
	locks, _ = st.LoginLocks()
	for _, l := range locks {
		if l.Net == "203.0.113.7" {
			if l.Strikes != 2 || l.Until-l.Created < 29*60 {
				t.Errorf("zweite Sperre: %+v (erwartet 2. Sperre, 30 Minuten)", l)
			}
		}
	}
	// Entsperren über die Sperrliste
	_ = st.DeleteLoginLock("203.0.113.7")
	if c := login("203.0.113.7", "geheimes-passwort-1"); c != http.StatusOK {
		t.Errorf("nach Entsperren: %d", c)
	}
}
