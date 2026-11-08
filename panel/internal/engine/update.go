package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Update-Prüfung: fragt alle 12 Stunden bei GitHub nach dem neuesten Release (abschaltbar
// mit der Einstellung update_check=0). Es werden keine Daten mitgeschickt.

const releaseAPI = "https://api.github.com/repos/syncip/vpn-setup/releases/latest"

type UpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"available"`
	URL       string `json:"url,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Checked   int64  `json:"checked,omitempty"`
	Error     string `json:"error,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
}

type updateState struct {
	mu   sync.Mutex
	info UpdateInfo
}

// Update liefert den letzten Stand der Prüfung.
func (e *Engine) Update(current string) UpdateInfo {
	e.upd.mu.Lock()
	defer e.upd.mu.Unlock()
	i := e.upd.info
	i.Current = current
	i.Disabled = e.Setting("update_check") == "0"
	i.Available = !i.Disabled && i.Latest != "" && newerVersion(i.Latest, current)
	return i
}

// RunUpdateCheck: Prüfschleife (kurz nach dem Start, dann alle 12 Stunden).
func (e *Engine) RunUpdateCheck(stop <-chan struct{}, current string) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if e.Setting("update_check") != "0" && !e.Sys.DryRun() {
			e.CheckUpdate(current)
		}
		t.Reset(12 * time.Hour)
	}
}

// CheckUpdate fragt GitHub jetzt.
func (e *Engine) CheckUpdate(current string) UpdateInfo {
	info := UpdateInfo{Checked: time.Now().Unix()}
	c := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", releaseAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vpnpanel/"+current)
	resp, err := c.Do(req)
	if err == nil {
		defer resp.Body.Close()
		var r struct {
			Tag  string `json:"tag_name"`
			URL  string `json:"html_url"`
			Body string `json:"body"`
		}
		if resp.StatusCode != 200 {
			err = fmt.Errorf("GitHub antwortet mit %d", resp.StatusCode)
		} else if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err == nil {
			info.Latest, info.URL = strings.TrimSpace(r.Tag), r.URL
			if len(r.Body) > 4000 {
				r.Body = r.Body[:4000] + " …"
			}
			info.Notes = r.Body
			if !strings.HasPrefix(info.URL, "https://github.com/") {
				info.URL = ""
			}
		}
	}
	if err != nil {
		info.Error = err.Error()
	}
	e.upd.mu.Lock()
	if err != nil && e.upd.info.Latest != "" { // alten Stand behalten
		e.upd.info.Error, e.upd.info.Checked = info.Error, info.Checked
	} else {
		e.upd.info = info
	}
	e.upd.mu.Unlock()
	if err == nil && newerVersion(info.Latest, current) {
		e.Log("info", "Update verfügbar: "+info.Latest+" (installiert: "+current+")")
	}
	return e.Update(current)
}

// newerVersion: ist a (z. B. „v0.7.1“) neuer als b? Unbekannte Formate → false.
func newerVersion(a, b string) bool {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
