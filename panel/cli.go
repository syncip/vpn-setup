package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"vpnpanel/internal/api"
	"vpnpanel/internal/engine"
	"vpnpanel/internal/proto"
	"vpnpanel/internal/store"
)

const usage = `vpn – Verwaltung (gleiche Daten wie das Webinterface)

  vpn list                 Alle Nutzer mit Verbrauch und Status
  vpn show <name>          Nutzer mit Zugängen und Abo-Link
  vpn add <name>           Nutzer mit Zugang auf allen aktiven Servern anlegen
  vpn del <name> [-y]      Nutzer löschen
  vpn wg <name> [gerät]    WireGuard-Konfiguration mit QR-Code
  vpn sub <name>           Abo-Link mit QR-Code (v2RayTun)
  vpn reset <name>         Verbrauch im aktuellen Zeitraum zurücksetzen
  vpn sync                 Konfigurationen neu schreiben und anwenden
  vpn collect              Statistik einsammeln
  vpn admin passwd <name>  Passwort eines Administrators neu setzen
  vpn admin 2fa-off <name> 2FA eines Administrators abschalten
  vpn admin add <name>     Administrator anlegen
  vpn serve                Dienst starten (macht systemd)
`

func cli(args []string) {
	o, rest := parseOpts(args)
	rest = trimArgs(rest)
	if len(rest) == 0 || rest[0] == "help" || rest[0] == "-h" {
		fmt.Print(usage)
		return
	}
	if os.Geteuid() != 0 && !o.dev {
		fatal("bitte als root ausführen")
	}
	e, err := open(o)
	if err != nil {
		fatal("%v", err)
	}
	defer e.St.Close()
	arg := func(i int) string {
		if len(rest) > i {
			return rest[i]
		}
		return ""
	}
	user := func() *store.User {
		n := arg(1)
		if n == "" {
			fatal("Name fehlt")
		}
		u, err := e.St.UserByName(n)
		if err != nil {
			fatal("Nutzer '%s' gibt es nicht", n)
		}
		return u
	}

	switch rest[0] {
	case "list", "ls":
		_ = e.Collect()
		cmdList(e)
	case "show":
		u := user()
		_ = e.Collect()
		cmdShow(e, u)
	case "add":
		cmdAdd(e, arg(1))
	case "del", "rm":
		u := user()
		if arg(2) != "-y" {
			fmt.Printf("Nutzer '%s' wirklich löschen? [j/N] ", u.Name)
			a, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if a = strings.TrimSpace(strings.ToLower(a)); a != "j" && a != "y" {
				fmt.Println("Abgebrochen.")
				return
			}
		}
		if err := e.St.DeleteUser(u.ID); err != nil {
			fatal("%v", err)
		}
		e.Log("info", "Nutzer "+u.Name+" gelöscht (Kommandozeile)")
		apply(e)
		fmt.Printf("Nutzer '%s' gelöscht.\n", u.Name)
	case "wg":
		cmdWG(e, user(), arg(2))
	case "sub":
		u := user()
		url := subURL(e, u)
		fmt.Printf("=== Abo für v2RayTun: %s ===\n", u.Name)
		qr(url)
		fmt.Println(url)
	case "reset":
		u := user()
		_ = e.Collect()
		u, _ = e.St.User(u.ID)
		u.PeriodUp, u.PeriodDown = 0, 0
		_ = e.St.SaveUser(u)
		apply(e)
		fmt.Printf("Verbrauch von '%s' zurückgesetzt.\n", u.Name)
	case "sync":
		apply(e)
		fmt.Println("Konfiguration neu erzeugt.")
	case "collect":
		if err := e.Collect(); err != nil {
			fatal("%v", err)
		}
	case "admin":
		cmdAdmin(e, arg(1), arg(2))
	case "import":
		ok, err := e.ImportLegacy(o.legacy)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Println(map[bool]string{true: "Übernommen.", false: "Nichts zu übernehmen (Datenbank hat schon Server oder kein altes Setup)."}[ok])
	default:
		fmt.Print(usage)
		os.Exit(1)
	}
}

func apply(e *engine.Engine) {
	if err := e.Apply(); err != nil {
		fatal("%v", err)
	}
}

func human(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func seen(ts int64) string {
	if ts == 0 {
		return "nie"
	}
	d := time.Since(time.Unix(ts, 0))
	switch {
	case d < 3*time.Minute:
		return "online"
	case d < time.Hour:
		return fmt.Sprintf("vor %d Min.", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("vor %d Std.", int(d.Hours()))
	}
	return time.Unix(ts, 0).Format("02.01.2006 15:04")
}

var statusDE = map[string]string{"ok": "aktiv", "throttled": "gedrosselt", "blocked": "gesperrt", "disabled": "deaktiviert", "expired": "abgelaufen"}

func cmdList(e *engine.Engine) {
	users, _ := e.St.Users()
	peers, _ := e.St.Peers()
	count := map[int64]int{}
	for _, p := range peers {
		count[p.UserID]++
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATUS\tZEITRAUM\tGESAMT\tZUGÄNGE\tZULETZT DA")
	var tot int64
	for _, u := range users {
		tot += u.TotalUp + u.TotalDown
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", u.Name, statusDE[u.Status], human(u.PeriodUp+u.PeriodDown), human(u.TotalUp+u.TotalDown), count[u.ID], seen(u.LastSeen))
	}
	tw.Flush()
	fmt.Printf("\n%d Nutzer – gesamt %s\n", len(users), human(tot))
}

func subURL(e *engine.Engine, u *store.User) string {
	if h := e.Setting("sub_host"); h != "" {
		return "https://" + h + "/" + u.SubToken
	}
	return "https://" + e.Setting("panel_host") + "/sub/" + u.SubToken
}

func cmdShow(e *engine.Engine, u *store.User) {
	u, _ = e.St.User(u.ID)
	fmt.Printf("==================== %s ====================\n", u.Name)
	fmt.Printf("Status:      %s %s\n", statusDE[u.Status], u.StatusReason)
	if u.RateDown > 0 || u.RateUp > 0 {
		fmt.Printf("Tempo:       ↓ %.0f / ↑ %.0f Mbit/s\n", u.RateDown, u.RateUp)
	}
	fmt.Printf("Zeitraum:    ↑ %s  ↓ %s\n", human(u.PeriodUp), human(u.PeriodDown))
	fmt.Printf("Gesamt:      ↑ %s  ↓ %s\n", human(u.TotalUp), human(u.TotalDown))
	fmt.Printf("Zuletzt da:  %s\n", seen(u.LastSeen))
	fmt.Printf("Abo-Link:    %s\n\n", subURL(e, u))
	peers, _ := e.St.PeersOfUser(u.ID)
	servers := map[int64]*store.Server{}
	all, _ := e.St.Servers()
	for _, s := range all {
		servers[s.ID] = s
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ZUGANG\tSERVER\tADRESSE\tVERBRAUCH\tZULETZT DA")
	for _, p := range peers {
		sv := servers[p.ServerID]
		addr := proto.Str(p.Settings, "address4")
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Name, sv.Name, addr, human(p.TotalUp+p.TotalDown), seen(p.LastSeen))
	}
	tw.Flush()
	fmt.Printf("\nQR-Codes:  vpn wg %s   |   vpn sub %s\n", u.Name, u.Name)
}

func cmdAdd(e *engine.Engine, name string) {
	if name == "" {
		fatal("Name fehlt")
	}
	u := &store.User{Name: name, Enabled: true, SubToken: proto.RandHex(16)}
	if err := e.St.SaveUser(u); err != nil {
		fatal("%v", err)
	}
	servers, _ := e.St.Servers()
	for _, sv := range servers {
		if !sv.Enabled {
			continue
		}
		d, ok := proto.Get(sv.Protocol)
		if !ok {
			continue
		}
		kind := d.Info().Kinds[0]
		s := store.M{}
		for k, v := range kind.Defaults {
			s[k] = v
		}
		p := &store.Peer{UserID: u.ID, ServerID: sv.ID, Name: name, Kind: kind.ID, Enabled: true, Settings: s}
		if err := e.InitPeer(sv, p); err != nil {
			fmt.Fprintf(os.Stderr, "Warnung: %s: %v\n", sv.Name, err)
			continue
		}
		_ = e.St.SavePeer(p)
	}
	e.Log("info", "Nutzer "+name+" angelegt (Kommandozeile)")
	apply(e)
	fmt.Printf("Nutzer '%s' angelegt.\n\n", name)
	cmdShow(e, u)
}

func cmdWG(e *engine.Engine, u *store.User, dev string) {
	peers, _ := e.St.PeersOfUser(u.ID)
	servers, _ := e.St.Servers()
	isWG := map[int64]bool{}
	for _, s := range servers {
		isWG[s.ID] = s.Protocol == "wireguard"
	}
	var cands []*store.Peer
	for _, p := range peers {
		if isWG[p.ServerID] && (dev == "" || strings.EqualFold(p.Name, dev)) {
			cands = append(cands, p)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })
	if len(cands) == 0 {
		fatal("kein passender WireGuard-Zugang")
	}
	cc, err := e.ClientConfig(cands[0].ID)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("=== %s ===\n", cc.Title)
	if len(cc.Files) > 0 {
		qr(cc.Files[0].Content)
		fmt.Println(cc.Files[0].Content)
	}
	if len(cands) > 1 {
		var n []string
		for _, c := range cands[1:] {
			n = append(n, c.Name)
		}
		fmt.Printf("Weitere Geräte: %s  (vpn wg %s <gerät>)\n", strings.Join(n, ", "), u.Name)
	}
}

func qr(s string) {
	cmd := exec.Command("qrencode", "-t", "ansiutf8")
	cmd.Stdin = strings.NewReader(s)
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}

func cmdAdmin(e *engine.Engine, action, name string) {
	if name == "" {
		fatal("Name fehlt")
	}
	switch action {
	case "add", "passwd":
		pw := api.RandomPassword()
		h, _ := api.HashPassword(pw)
		adm, err := e.St.AdminByName(name)
		if action == "add" {
			if err == nil {
				fatal("Administrator '%s' gibt es schon", name)
			}
			adm = &store.Admin{Username: name}
		} else if err != nil {
			fatal("Administrator '%s' gibt es nicht", name)
		}
		adm.PassHash = h
		if err := e.St.SaveAdmin(adm); err != nil {
			fatal("%v", err)
		}
		e.St.DeleteSessionsOf(adm.ID, "")
		e.Log("warn", "Passwort von "+name+" über die Kommandozeile gesetzt")
		fmt.Printf("Benutzer: %s\nPasswort: %s\n", name, pw)
	case "2fa-off":
		adm, err := e.St.AdminByName(name)
		if err != nil {
			fatal("Administrator '%s' gibt es nicht", name)
		}
		adm.TOTPEnabled, adm.TOTPSecret = false, ""
		_ = e.St.SaveAdmin(adm)
		e.Log("warn", "2FA von "+name+" über die Kommandozeile abgeschaltet")
		fmt.Println("2FA abgeschaltet.")
	default:
		fmt.Print(usage)
	}
}
