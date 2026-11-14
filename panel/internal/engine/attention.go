package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// „Braucht Aufmerksamkeit“: alles, was gerade nicht stimmt, an einer Stelle – mit Link zur Stelle,
// an der es sich beheben lässt. Nur aus vorhandenem Zustand (keine Prüfungen, keine Befehle).

type AttentionItem struct {
	Key    string `json:"key"`
	Level  string `json:"level"` // error | warn | info
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Link   string `json:"link,omitempty"` // #/… oder https://…
}

var attentionRank = map[string]int{"error": 0, "warn": 1, "info": 2}

// errLink: wohin ein Eintrag aus Errors() führt (Schlüssel wie „exit:3“, „dnslog“).
func errLink(key string) string {
	switch k, _, _ := strings.Cut(key, ":"); k {
	case "exit", "group", "exits":
		return "#/proxy/exits"
	case "dns", "dnslog", "dnslist", "unbound", "encdns", "acme":
		return "#/dns/settings"
	}
	return "#/health/events"
}

func (e *Engine) Attention(version string) []AttentionItem {
	var out []AttentionItem
	add := func(key, level, title, detail, link string) {
		out = append(out, AttentionItem{Key: key, Level: level, Title: title, Detail: detail, Link: link})
	}
	if e.Setting("server_host") == "" {
		add("server_host", "error", "Server-Adresse fehlt", "Sie steht in allen Links und Konfigurationen.", "#/settings/general")
	}
	for k, v := range e.Errors() {
		first, rest, _ := strings.Cut(v, "\n")
		add("err:"+k, "error", clip(first, 110), clip(strings.TrimSpace(rest), 600), errLink(k))
	}

	// Ausgänge und Gruppen
	if e.Exits != nil {
		xs, _ := e.LoadExits()
		es, gs := e.Exits.Status()
		lim := e.savedExitLimits()
		for _, x := range xs {
			id := strconv.FormatInt(x.ID, 10)
			switch l := lim[x.ID]; l.Status {
			case "blocked":
				add("exitlimit:"+id, "warn", "Ausgang „"+x.Name+"“ abgeschaltet", l.Reason+" – bis zum nächsten Zeitraum. Limit erhöhen oder Verbrauch zurücksetzen.", "#/proxy/exits")
			case "throttled":
				add("exitlimit:"+id, "info", "Ausgang „"+x.Name+"“ gedrosselt", l.Reason, "#/proxy/exits")
			}
		}
		for _, x := range xs {
			s, ok := es[x.ID]
			if !x.Enabled || !ok || s.Error == "" || (s.Standby && !s.Connected) {
				continue
			}
			add("exit:"+strconv.FormatInt(x.ID, 10), "warn", "Ausgang „"+x.Name+"“ gestört", clip(s.Error, 160), "#/proxy/exits")
		}
		if groups, err := e.St.Objects("group"); err == nil {
			for _, g := range groups {
				st, ok := gs[g.ID]
				if !g.Enabled || !ok || (st.State != "blocked" && st.State != "direct") {
					continue
				}
				what := map[string]string{"blocked": "Verkehr gesperrt", "direct": "Verkehr läuft direkt über den Server"}[st.State]
				add("group:"+strconv.FormatInt(g.ID, 10), "warn", "Ausgangsgruppe „"+g.Name+"“ ohne Ausgang", what+" – "+clip(st.Reason, 140), "#/proxy/groups")
			}
		}
	}

	// DNS: Unbound und Zertifikat
	if h := e.UnboundHealth(); h.On && h.Checked > 0 {
		if !h.OK {
			add("unbound", "warn", "Unbound antwortet nicht", clip(h.Why, 160), "#/dns/settings")
		}
		for _, g := range h.Groups {
			if !g.OK {
				add("unbound:"+strconv.FormatInt(g.GID, 10), "warn", "Unbound · "+g.Name+" antwortet nicht", clip(g.Why, 160), "#/dns/settings")
			}
		}
	}
	if e.encDNSOn() && !e.Sys.DryRun() {
		st := e.EncDNSState()
		if st.Error != "" {
			add("cert:error", "warn", "Zertifikat für "+st.Host+" ließ sich nicht holen", clip(st.Error, 160), "#/dns/external")
		} else if st.HasCert && !st.Cert.SelfSigned && st.Cert.NotAfter > 0 {
			if days := int(time.Until(time.Unix(st.Cert.NotAfter, 0)).Hours() / 24); days < 14 {
				add("cert:expiry", "warn", fmt.Sprintf("Zertifikat für %s läuft in %d Tagen ab", st.Host, days), "", "#/dns/external")
			}
		}
	}

	// letzte Portprüfung
	if pc := LastPortCheck(); pc != nil {
		for _, it := range pc.Items {
			if it.Family != "IPv4" || (it.State != "missing" && it.State != "arrived") {
				continue
			}
			title := fmt.Sprintf("%s %d (%s) kommt von außen nicht an", strings.ToUpper(it.Proto), it.Port.Port, it.Server)
			if it.State == "arrived" {
				title = fmt.Sprintf("%s %d (%s): kein Dienst nimmt an", strings.ToUpper(it.Proto), it.Port.Port, it.Server)
			}
			add(fmt.Sprintf("port:%s:%d", it.Proto, it.Port.Port), "warn", title, it.Detail, "#/health")
		}
	}

	// Datenträger und Speicher (letzter Messwert, keine neue Messung)
	e.host.mu.Lock()
	hs := e.host.last
	e.host.mu.Unlock()
	if hs.DiskSize > 0 && float64(hs.DiskUsed) > 0.9*float64(hs.DiskSize) {
		add("disk", "warn", fmt.Sprintf("Datenträger zu %d %% belegt", int(100*float64(hs.DiskUsed)/float64(hs.DiskSize))), "Protokolle und Verlauf brauchen Platz – Aufbewahrung verkürzen oder Platz schaffen.", "#/health")
	}
	if hs.MemTotal > 0 && float64(hs.MemUsed) > 0.92*float64(hs.MemTotal) {
		add("mem", "warn", fmt.Sprintf("Arbeitsspeicher zu %d %% belegt", int(100*float64(hs.MemUsed)/float64(hs.MemTotal))), "", "#/health")
	}

	// bestehende Alarme (Einstellungen → Alarme)
	for _, a := range e.ActiveAlarms() {
		if a.Active && !alarmOwnAttention[a.Type] {
			add("alarm:"+a.Key, "warn", a.Title, clip(a.Detail, 300), "#/settings/alarms")
		}
	}

	if u := e.Update(version); u.Available {
		add("update", "info", "Update "+u.Latest+" verfügbar", "Installiert: "+version, u.URL)
	}
	e.pkg.mu.Lock()
	pk := e.pkg.state
	e.pkg.mu.Unlock()
	if pk.Security > 0 {
		add("pkg:security", "warn", fmt.Sprintf("%d Sicherheitsupdates für Debian-Pakete", pk.Security), fmt.Sprintf("Insgesamt %d Paket-Updates – einspielen mit „apt full-upgrade“ im Container.", pk.Debian), "#/health/updates")
	} else if pk.Debian > 0 {
		add("pkg:debian", "info", fmt.Sprintf("%d Debian-Pakete aktualisierbar", pk.Debian), "Einspielen mit „apt full-upgrade“ im Container.", "#/health/updates")
	}
	if pk.Binaries > 0 {
		var names []string
		for _, it := range pk.Items {
			if it.Kind == "binary" && it.Available {
				names = append(names, it.Name+" "+it.Latest)
			}
		}
		add("pkg:binary", "info", "Neue Version: "+strings.Join(names, ", "), "Einspielen mit „bash vpn-setup.sh“ im Container.", "#/health/updates")
	}
	sort.SliceStable(out, func(i, j int) bool {
		if attentionRank[out[i].Level] != attentionRank[out[j].Level] {
			return attentionRank[out[i].Level] < attentionRank[out[j].Level]
		}
		return out[i].Key < out[j].Key
	})
	return out
}
