package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Paket-Updates: zeigt neue Versionen von Xray, Hysteria2 und den Debian-Paketen an – installiert
// wird nichts. Xray/Hysteria2: installierte Version vom Programm, neueste von GitHub (nur mit
// update_check=1). Debian: Simulation „apt-get -s dist-upgrade“ (verändert nichts); sie sieht nur,
// was in den Paketlisten steht. Die Listen aktualisiert Debian meist selbst (apt-daily.timer),
// sonst der Knopf „Paketlisten aktualisieren“ oder pkg_refresh=1 (täglich apt-get update).

type PkgItem struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // panel | binary | debian
	Installed string `json:"installed"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Security  bool   `json:"security,omitempty"`
	Relevant  bool   `json:"relevant,omitempty"` // vom Panel genutztes Paket
	Source    string `json:"source,omitempty"`
	URL       string `json:"url,omitempty"`
}

type PkgUpdates struct {
	Checked    int64     `json:"checked"`
	ListsAt    int64     `json:"lists_at"` // Stand der Paketlisten (0 = unbekannt)
	Items      []PkgItem `json:"items"`
	Debian     int       `json:"debian"`   // Anzahl Debian-Updates
	Security   int       `json:"security"` // davon Sicherheitsupdates
	Binaries   int       `json:"binaries"` // Xray/Hysteria2 mit neuer Version
	Errors     []string  `json:"errors,omitempty"`
	Busy       string    `json:"busy,omitempty"` // „check“ oder „refresh“
	Disabled   bool      `json:"disabled,omitempty"`
	AutoLists  bool      `json:"auto_lists"`
	DryRun     bool      `json:"dry_run,omitempty"`
	RefreshErr string    `json:"refresh_error,omitempty"`
}

type pkgState struct {
	mu    sync.Mutex
	state PkgUpdates
	run   sync.Mutex // nur eine Prüfung gleichzeitig
}

// vom Panel genutzte Debian-Pakete (vpn-setup.sh)
var relevantPkgs = map[string]bool{
	"wireguard-tools": true, "iptables": true, "iproute2": true, "nginx": true, "libnginx-mod-stream": true,
	"nginx-common": true, "openvpn": true, "unbound": true, "unbound-anchor": true, "dns-root-data": true,
	"nftables": true, "conntrack": true, "openssl": true, "libssl3": true, "libssl3t64": true, "ca-certificates": true,
	"curl": true, "qrencode": true, "iputils-ping": true, "jq": true, "unzip": true,
}

var (
	aptInstRe = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) ([^\[\)]*)`)
	xrayVerRe = regexp.MustCompile(`^Xray (\S+)`)
)

// parseAptSim: Zeilen „Inst paket [alt] (neu Quelle [arch])“ aus apt-get -s
func parseAptSim(out string) []PkgItem {
	var items []PkgItem
	for _, line := range strings.Split(out, "\n") {
		m := aptInstRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		src := strings.TrimSpace(m[4])
		items = append(items, PkgItem{
			Name: m[1], Kind: "debian", Installed: m[2], Latest: m[3], Available: true, Source: src,
			Security: strings.Contains(strings.ToLower(src), "security"), Relevant: relevantPkgs[m[1]],
		})
	}
	return items
}

func parseXrayVersion(out string) string {
	if m := xrayVerRe.FindStringSubmatch(strings.TrimSpace(out)); m != nil {
		return m[1]
	}
	return ""
}

func parseHysteriaVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "version") {
			return strings.TrimPrefix(strings.TrimSpace(v), "app/")
		}
	}
	return ""
}

// ghLatest: neuestes Release eines GitHub-Projekts (Tag, Link)
func ghLatest(repo, ua string) (string, string, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vpnpanel/"+ua)
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub antwortet mit %d", resp.StatusCode)
	}
	var r struct {
		Tag string `json:"tag_name"`
		URL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(r.URL, "https://github.com/") {
		r.URL = ""
	}
	return strings.TrimPrefix(strings.TrimSpace(r.Tag), "app/"), r.URL, nil
}

// aptListsAt: jüngste Änderung der Paketlisten
func (e *Engine) aptListsAt() int64 {
	var newest int64
	files, _ := filepath.Glob("/var/lib/apt/lists/*Release")
	for _, f := range files {
		if st, err := os.Stat(f); err == nil && st.ModTime().Unix() > newest {
			newest = st.ModTime().Unix()
		}
	}
	return newest
}

// PkgUpdates: letzter Stand (mit Panel-Version aus der Update-Prüfung)
func (e *Engine) PkgUpdates(version string) PkgUpdates {
	e.pkg.mu.Lock()
	s := e.pkg.state
	s.Items = append([]PkgItem(nil), s.Items...)
	e.pkg.mu.Unlock()
	s.Disabled = e.Setting("update_check") == "0"
	s.AutoLists = e.Setting("pkg_refresh") == "1"
	s.DryRun = e.Sys.DryRun()
	u := e.Update(version)
	panel := PkgItem{Name: "VPN-Panel", Kind: "panel", Installed: version, Latest: u.Latest, Available: u.Available, URL: u.URL}
	s.Items = append([]PkgItem{panel}, s.Items...)
	return s
}

func (e *Engine) setPkgBusy(b string) {
	e.pkg.mu.Lock()
	e.pkg.state.Busy = b
	e.pkg.mu.Unlock()
}

// CheckPkgUpdates: installierte und neueste Versionen jetzt ermitteln.
func (e *Engine) CheckPkgUpdates(version string) PkgUpdates {
	e.pkg.run.Lock()
	defer e.pkg.run.Unlock()
	e.setPkgBusy("check")
	defer e.setPkgBusy("")
	st := PkgUpdates{Checked: time.Now().Unix()}
	if e.Sys.DryRun() {
		st = demoPkgUpdates()
	} else {
		online := e.Setting("update_check") != "0"
		bins := []struct {
			name, repo, bin string
			args            []string
			parse           func(string) string
		}{
			{"Xray", "XTLS/Xray-core", "xray", []string{"version"}, parseXrayVersion},
			{"Hysteria2", "apernet/hysteria", "/usr/local/bin/hysteria", []string{"version"}, parseHysteriaVersion},
		}
		for _, b := range bins {
			out, err := e.Sys.Run(b.bin, b.args...)
			inst := b.parse(out)
			if err != nil || inst == "" {
				continue // nicht installiert
			}
			it := PkgItem{Name: b.name, Kind: "binary", Installed: strings.TrimPrefix(inst, "v")}
			if online {
				latest, url, err := ghLatest(b.repo, version)
				if err != nil {
					st.Errors = append(st.Errors, b.name+": "+err.Error())
				} else {
					it.Latest, it.URL = strings.TrimPrefix(latest, "v"), url
					it.Available = newerVersion(it.Latest, it.Installed)
				}
			}
			st.Items = append(st.Items, it)
		}
		out, err := e.Sys.Run("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
		if err != nil {
			st.Errors = append(st.Errors, "Debian-Pakete: "+firstLine(err.Error()))
		} else {
			st.Items = append(st.Items, parseAptSim(out)...)
		}
		st.ListsAt = e.aptListsAt()
	}
	sortPkg(st.Items)
	for _, it := range st.Items {
		switch {
		case it.Kind == "debian":
			st.Debian++
			if it.Security {
				st.Security++
			}
		case it.Kind == "binary" && it.Available:
			st.Binaries++
		}
	}
	e.pkg.mu.Lock()
	refreshErr := e.pkg.state.RefreshErr
	e.pkg.state = st
	e.pkg.state.RefreshErr = refreshErr
	e.pkg.mu.Unlock()
	return e.PkgUpdates(version)
}

// RefreshPkgLists: apt-get update (lädt nur die Paketlisten, installiert nichts), danach prüfen.
func (e *Engine) RefreshPkgLists(version string) PkgUpdates {
	e.setPkgBusy("refresh")
	var msg string
	if !e.Sys.DryRun() {
		if _, err := e.Sys.Run("apt-get", "update", "-q"); err != nil {
			msg = firstLine(err.Error())
			e.Log("warn", "Paketlisten aktualisieren fehlgeschlagen: "+msg)
		}
	}
	e.pkg.mu.Lock()
	e.pkg.state.RefreshErr = msg
	e.pkg.mu.Unlock()
	return e.CheckPkgUpdates(version)
}

// maybeRefreshLists: bei pkg_refresh=1 einmal am Tag apt-get update
func (e *Engine) maybeRefreshLists(version string) bool {
	if e.Setting("pkg_refresh") != "1" || e.Sys.DryRun() {
		return false
	}
	if at := e.aptListsAt(); at > 0 && time.Since(time.Unix(at, 0)) < 20*time.Hour {
		return false
	}
	e.RefreshPkgLists(version)
	return true
}

func sortPkg(items []PkgItem) {
	rank := func(it PkgItem) int {
		switch {
		case it.Kind == "binary" && it.Available:
			return 0
		case it.Kind == "binary":
			return 1
		case it.Security:
			return 2
		case it.Relevant:
			return 3
		}
		return 4
	}
	sort.SliceStable(items, func(i, j int) bool {
		if rank(items[i]) != rank(items[j]) {
			return rank(items[i]) < rank(items[j])
		}
		return items[i].Name < items[j].Name
	})
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 300 {
		s = s[:300] + " …"
	}
	return s
}

// Testmodus: Beispielwerte, damit die Anzeige in der Vorschau etwas zeigt
func demoPkgUpdates() PkgUpdates {
	now := time.Now()
	st := PkgUpdates{Checked: now.Unix(), ListsAt: now.Add(-7 * time.Hour).Unix()}
	st.Items = []PkgItem{
		{Name: "Xray", Kind: "binary", Installed: "25.9.11", Latest: "25.10.15", Available: true, URL: "https://github.com/XTLS/Xray-core/releases"},
		{Name: "Hysteria2", Kind: "binary", Installed: "2.6.4", Latest: "2.6.4"},
	}
	st.Items = append(st.Items, parseAptSim(`Inst openssl [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])
Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])
Inst nginx [1.26.3-3] (1.26.3-3+deb13u1 Debian:13.2/stable [amd64])
Inst tzdata [2025b-4] (2025b-4+deb13u1 Debian:13.2/stable [all])
Conf openssl (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])`)...)
	return st
}
