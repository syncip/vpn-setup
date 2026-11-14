package engine

// Benachrichtigungen per E-Mail: Mailserver (SMTP) im Dashboard einstellbar, Passwort nur in
// <data>/secrets.env. Empfänger sind die Administratoren mit E-Mail-Adresse und eingeschalteten
// Benachrichtigungen (Konto-Seite). Eine Überwachung prüft jede Minute Ausgangsgruppen, Unbound,
// das DoH/DoT-Zertifikat und Updates; Fehler aus dem Ereignisprotokoll und Anmeldungen kommen direkt.

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NotifyEvents: wählbare Anlässe (Schlüssel → Beschriftung), Reihenfolge für die Oberfläche.
var NotifyEvents = []struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}{
	{"exit", "Ausgangsgruppe ausgefallen bzw. wieder da"},
	{"unbound", "Unbound antwortet nicht bzw. wieder"},
	{"cert", "DoH/DoT-Zertifikat läuft bald ab oder ließ sich nicht erneuern"},
	{"update", "Neue Panel-Version verfügbar"},
	{"error", "Fehler im Ereignisprotokoll"},
	{"lockout", "Anmeldung gesperrt (zu viele Fehlversuche)"},
	{"login", "Jede erfolgreiche Anmeldung am Panel"},
	{"backup", "Sicherung erstellt oder eingespielt"},
}

const (
	notifyThrottle = 30 * time.Minute // gleiche Meldung höchstens so oft
	notifyEvery    = time.Minute      // Überwachung
	smtpTimeout    = 30 * time.Second
)

type notifyMail struct {
	to            []string
	subject, body string
}

type notifyState struct {
	mu    sync.Mutex
	last  map[string]time.Time  // Schlüssel → zuletzt gesendet
	track map[string]*watchItem // Überwachung: Zustand je Prüfpunkt
	ch    chan notifyMail
	once  sync.Once
	sent  []notifyMail // Testmodus: statt zu senden
	busy  bool         // Versand läuft (gegen Schleifen über e.Log)
}

type watchItem struct {
	bad   int  // Fehlschläge in Folge
	alert bool // Ausfall gemeldet
}

func (n *notifyState) init() {
	n.once.Do(func() {
		n.last = map[string]time.Time{}
		n.track = map[string]*watchItem{}
		n.ch = make(chan notifyMail, 32)
	})
}

// notifyOn: Mailversand eingerichtet und Anlass gewählt?
func (e *Engine) notifyOn(event string) bool {
	if e.Setting("mail_enabled") != "1" || e.Setting("smtp_host") == "" || e.Setting("mail_from") == "" {
		return false
	}
	for _, k := range strings.Split(e.Setting("notify_events"), ",") {
		if strings.TrimSpace(k) == event {
			return true
		}
	}
	return false
}

// NotifyRecipients: Adressen der Administratoren mit eingeschalteten Benachrichtigungen.
func (e *Engine) NotifyRecipients() []string {
	admins, _ := e.St.Admins()
	var out []string
	for _, a := range admins {
		if a.Notify && a.Email != "" {
			out = append(out, a.Email)
		}
	}
	sort.Strings(out)
	return out
}

// Notify meldet einen Anlass per E-Mail (im Hintergrund). key fasst gleiche Meldungen zusammen:
// dieselbe Meldung geht höchstens alle 30 Minuten hinaus.
func (e *Engine) Notify(event, key, subject, body string) {
	if !e.notifyOn(event) {
		return
	}
	to := e.NotifyRecipients()
	if len(to) == 0 {
		return
	}
	n := &e.notif
	n.init()
	n.mu.Lock()
	if t, ok := n.last[event+":"+key]; ok && time.Since(t) < notifyThrottle {
		n.mu.Unlock()
		return
	}
	n.last[event+":"+key] = time.Now()
	if len(n.last) > 2000 {
		for k, t := range n.last {
			if time.Since(t) > notifyThrottle {
				delete(n.last, k)
			}
		}
	}
	n.mu.Unlock()
	m := notifyMail{to: to, subject: subject, body: body}
	select {
	case n.ch <- m:
	default:
		e.logQuiet("warn", "E-Mail-Benachrichtigung verworfen (Warteschlange voll): "+subject)
	}
}

// logQuiet: Ereignis ohne erneute Benachrichtigung (Fehler beim Mailversand dürfen keine Mail auslösen).
func (e *Engine) logQuiet(level, msg string) {
	e.notif.mu.Lock()
	e.notif.busy = true
	e.notif.mu.Unlock()
	e.Log(level, msg)
	e.notif.mu.Lock()
	e.notif.busy = false
	e.notif.mu.Unlock()
}

// notifyLogged: Hook aus e.Log – Fehler im Ereignisprotokoll melden.
func (e *Engine) notifyLogged(level, msg string) {
	if level != "error" {
		return
	}
	e.notif.init()
	e.notif.mu.Lock()
	busy := e.notif.busy
	e.notif.mu.Unlock()
	if busy {
		return
	}
	key := msg
	if len(key) > 80 {
		key = key[:80]
	}
	first, _, _ := strings.Cut(msg, "\n")
	e.Notify("error", key, "Fehler: "+clip(first, 90), "Im Ereignisprotokoll des Panels steht ein Fehler:\n\n"+msg)
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + " …"
	}
	return s
}

// RunNotify: Versand und Überwachung (läuft im Dienst).
func (e *Engine) RunNotify(stop <-chan struct{}, version string) {
	n := &e.notif
	n.init()
	e.SeedAlarms()
	t := time.NewTicker(notifyEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case m := <-n.ch:
			if _, err := e.sendMail(m.to, m.subject, m.body); err != nil {
				e.logQuiet("warn", "E-Mail „"+m.subject+"“ nicht gesendet: "+err.Error())
			}
		case <-t.C:
			e.watch(version)
		}
	}
}

// watchState: Ausfall erst nach zwei Prüfungen in Folge melden, Wiederkehr nur nach gemeldetem Ausfall.
func (e *Engine) watchState(event, key string, bad bool, downSubj, downBody, upSubj, upBody string) {
	n := &e.notif
	n.init()
	n.mu.Lock()
	it := n.track[key]
	if it == nil {
		it = &watchItem{}
		n.track[key] = it
	}
	send, up := false, false
	if bad {
		it.bad++
		if it.bad >= 2 && !it.alert {
			it.alert, send = true, true
		}
	} else {
		if it.alert {
			send, up = true, true
		}
		it.bad, it.alert = 0, false
	}
	n.mu.Unlock()
	switch {
	case send && up:
		e.Notify(event, key+":up", upSubj, upBody)
	case send:
		e.Notify(event, key+":down", downSubj, downBody)
	}
}

// watch: eine Runde der Überwachung.
func (e *Engine) watch(version string) {
	// Ausgangsgruppen
	if e.Exits != nil {
		_, gs := e.Exits.Status()
		names := map[int64]string{}
		if groups, err := e.St.Objects("group"); err == nil {
			for _, g := range groups {
				if g.Enabled {
					names[g.ID] = g.Name
				}
			}
		}
		for id, g := range gs {
			name, ok := names[id]
			if !ok || g.State == "waiting" || g.State == "" {
				continue
			}
			bad := g.State == "blocked" || g.State == "direct"
			what := map[string]string{"blocked": "Verkehr gesperrt", "direct": "Verkehr läuft direkt über den Server"}[g.State]
			e.watchState("exit", "group:"+strconv.FormatInt(id, 10), bad,
				"Ausgangsgruppe „"+name+"“ ohne Ausgang", "Die Ausgangsgruppe „"+name+"“ hat keinen funktionierenden Ausgang mehr ("+what+").\n\nGrund: "+g.Reason,
				"Ausgangsgruppe „"+name+"“ wieder verbunden", "Die Ausgangsgruppe „"+name+"“ nutzt wieder einen Ausgang.")
		}
	}
	// Unbound
	if h := e.UnboundHealth(); h.On && h.Checked > 0 {
		e.watchState("unbound", "unbound", !h.OK, "Unbound antwortet nicht",
			"Der eigene Resolver (Unbound) antwortet nicht. Der Panel-DNS fragt solange die Ersatz-DNS-Server.\n\n"+h.Why,
			"Unbound antwortet wieder", "Der eigene Resolver (Unbound) antwortet wieder.")
		for _, g := range h.Groups {
			e.watchState("unbound", "unbound:"+strconv.FormatInt(g.GID, 10), !g.OK, "Unbound · "+g.Name+" antwortet nicht",
				"Die Unbound-Instanz der Ausgangsgruppe „"+g.Name+"“ antwortet nicht. Geräte der Gruppe nutzen solange die DNS-Server der Gruppe.\n\n"+g.Why,
				"Unbound · "+g.Name+" antwortet wieder", "Die Unbound-Instanz der Ausgangsgruppe „"+g.Name+"“ antwortet wieder.")
		}
	}
	// Zertifikat für DoH/DoT
	if e.encDNSOn() {
		st := e.EncDNSState()
		if st.HasCert && !st.Cert.SelfSigned && st.Cert.NotAfter > 0 {
			days := int(time.Until(time.Unix(st.Cert.NotAfter, 0)).Hours() / 24)
			e.watchState("cert", "cert:expiry", days < 14, fmt.Sprintf("Zertifikat für %s läuft in %d Tagen ab", st.Host, days),
				fmt.Sprintf("Das Let's-Encrypt-Zertifikat für DoH/DoT (%s) läuft in %d Tagen ab und wurde noch nicht erneuert.\n\nLetzter Fehler: %s", st.Host, days, orDash(st.Error)),
				"Zertifikat für "+st.Host+" erneuert", "Das Zertifikat für DoH/DoT wurde erneuert.")
		}
		e.watchState("cert", "cert:error", st.Error != "" && !e.Sys.DryRun(), "Zertifikat für "+st.Host+" ließ sich nicht holen",
			"Das Panel konnte das Let's-Encrypt-Zertifikat für DoH/DoT nicht holen:\n\n"+st.Error, "Zertifikat für "+st.Host+" wieder in Ordnung", "Das Zertifikat für DoH/DoT ließ sich wieder holen.")
	}
	// Update (je Version nur einmal, auch über Neustarts)
	if u := e.Update(version); u.Available && e.notifyOn("update") {
		if e.St.GetSetting("state:notify_update", "") != u.Latest {
			_ = e.St.SetSetting("state:notify_update", u.Latest)
			body := "Für das VPN-Panel gibt es die Version " + u.Latest + " (installiert: " + version + ")."
			if u.URL != "" {
				body += "\n\n" + u.URL
			}
			e.Notify("update", u.Latest, "Panel-Update "+u.Latest+" verfügbar", body)
		}
	}
	// eigene Alarme (Einstellungen → Alarme)
	e.runAlarms()
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

// ---------- Versand ----------

// smtpConfig: Einstellungen des Mailservers.
type smtpConfig struct {
	Host, Security, User, Pass, From, HeloName string
	Port                                       int
}

func (e *Engine) smtpConfig() smtpConfig {
	return smtpConfig{Host: e.Setting("smtp_host"), Port: atoi(e.Setting("smtp_port"), 587), Security: e.Setting("smtp_security"),
		User: e.Setting("smtp_user"), Pass: e.secret("SMTP_PASSWORD"), From: e.Setting("mail_from"), HeloName: e.Setting("server_host")}
}

// sendMail verschickt eine Mail an alle Empfänger (im Testmodus nur gemerkt). reply ist die Antwort
// des Mailservers auf die Nachricht (meist mit Queue-ID – damit lässt sie sich in dessen Protokoll finden).
func (e *Engine) sendMail(to []string, subject, body string) (reply string, err error) {
	if e.Sys.DryRun() {
		e.notif.init()
		e.notif.mu.Lock()
		e.notif.sent = append(e.notif.sent, notifyMail{to: to, subject: subject, body: body})
		e.notif.mu.Unlock()
		return "250 Testmodus – nicht verschickt", nil
	}
	host := e.Setting("server_host")
	if host == "" {
		host = "VPN-Panel"
	}
	return smtpSend(e.smtpConfig(), to, "[VPN-Panel "+host+"] "+subject, body+"\n\n– VPN-Panel auf "+host+"\nBenachrichtigungen ändern: Einstellungen → Benachrichtigungen bzw. Mein Konto.")
}

// SentMails: im Testmodus verschickte Mails (für Tests und die Vorschau).
func (e *Engine) SentMails() []string {
	e.notif.init()
	e.notif.mu.Lock()
	defer e.notif.mu.Unlock()
	var out []string
	for _, m := range e.notif.sent {
		out = append(out, strings.Join(m.to, ",")+" | "+m.subject)
	}
	return out
}

// SendTestMail schickt sofort eine Testmail (Fehler kommen direkt zurück) und trägt das Ergebnis samt
// Antwort des Mailservers ins Ereignisprotokoll ein.
func (e *Engine) SendTestMail(to string) (string, error) {
	if e.Setting("smtp_host") == "" || e.Setting("mail_from") == "" {
		return "", errors.New("Mailserver und Absender eintragen und speichern")
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return "", errors.New("Empfänger-Adresse ungültig – in „Mein Konto“ eine E-Mail-Adresse eintragen")
	}
	c := e.smtpConfig()
	srv := fmt.Sprintf("%s:%d (%s)", c.Host, c.Port, c.Security)
	reply, err := e.sendMail([]string{to}, "Testmail", "Diese Testmail zeigt: Der Mailversand des VPN-Panels funktioniert.")
	if err != nil {
		e.logQuiet("warn", fmt.Sprintf("Testmail an %s über %s fehlgeschlagen: %v", to, srv, err))
		return "", err
	}
	e.logQuiet("info", fmt.Sprintf("Testmail an %s vom Mailserver %s angenommen: %s", to, srv, clip(reply, 200)))
	return reply, nil
}

// SetSMTPPassword: Passwort des Mailservers (nur in secrets.env, leer = entfernen).
func (e *Engine) SetSMTPPassword(pw string) error {
	if strings.ContainsAny(pw, "\r\n") || len(pw) > 500 {
		return errors.New("Passwort ungültig")
	}
	return e.setSecret("SMTP_PASSWORD", pw, "Passwort des Mailservers für Benachrichtigungen")
}

// SMTPPasswordSet: ist ein Passwort hinterlegt (wird nie ausgegeben)?
func (e *Engine) SMTPPasswordSet() bool { return e.secret("SMTP_PASSWORD") != "" }

func headerSafe(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

// buildMail: Nachricht mit UTF-8-Betreff und Quoted-Printable-Text.
func buildMail(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := "vpnpanel.local"
	if a, err := mail.ParseAddress(from); err == nil {
		if _, d, ok := strings.Cut(a.Address, "@"); ok {
			domain = d
		}
		from = a.String() // Name mit Umlauten korrekt kodiert
	}
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(to, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", headerSafe(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), domain)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\nAuto-Submitted: auto-generated\r\n\r\n")
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")))
	_ = w.Close()
	b.WriteString("\r\n")
	return b.Bytes()
}

// smtpSend: Versand mit STARTTLS (587), TLS (465) oder ohne Verschlüsselung (nur ohne Anmeldung
// bzw. an einen lokalen Mailserver – net/smtp schickt Passwörter nie unverschlüsselt ins Netz).
func smtpSend(c smtpConfig, to []string, subject, body string) (string, error) {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return "", errors.New("Absender-Adresse ungültig")
	}
	if len(to) == 0 {
		return "", errors.New("keine Empfänger")
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	d := &net.Dialer{Timeout: 15 * time.Second}
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	if c.Security == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return "", fmt.Errorf("Verbindung zu %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("Mailserver: %w", err)
	}
	defer cl.Close()
	helo := c.HeloName
	if helo == "" || !hostSettingRe.MatchString(helo) {
		helo = "localhost"
	}
	if err := cl.Hello(helo); err != nil {
		return "", fmt.Errorf("HELO: %w", err)
	}
	if c.Security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return "", errors.New("der Mailserver bietet kein STARTTLS an – Port 465 mit „TLS“ versuchen")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return "", fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if c.User != "" {
		if c.Pass == "" {
			return "", errors.New("Benutzername ist eingetragen, aber kein Passwort hinterlegt")
		}
		if err := cl.Auth(smtp.PlainAuth("", c.User, c.Pass, c.Host)); err != nil {
			return "", fmt.Errorf("Anmeldung am Mailserver: %w", err)
		}
	}
	if err := cl.Mail(from.Address); err != nil {
		return "", fmt.Errorf("Absender abgelehnt: %w", err)
	}
	for _, t := range to {
		if err := cl.Rcpt(t); err != nil {
			return "", fmt.Errorf("Empfänger %s abgelehnt: %w", t, err)
		}
	}
	// DATA von Hand: net/smtp verwirft sonst die Antwort auf die Nachricht (mit Queue-ID)
	id, err := cl.Text.Cmd("DATA")
	if err != nil {
		return "", err
	}
	cl.Text.StartResponse(id)
	_, _, err = cl.Text.ReadResponse(354)
	cl.Text.EndResponse(id)
	if err != nil {
		return "", fmt.Errorf("DATA: %w", err)
	}
	dw := cl.Text.DotWriter()
	if _, err := dw.Write(buildMail(c.From, to, subject, body)); err != nil {
		return "", err
	}
	if err := dw.Close(); err != nil {
		return "", err
	}
	code, msg, err := cl.Text.ReadResponse(250)
	if err != nil {
		return "", fmt.Errorf("Mail abgelehnt: %w", err)
	}
	reply := strings.ReplaceAll(fmt.Sprintf("%d %s", code, msg), "\n", " · ")
	_ = cl.Quit() // angenommen ist angenommen – ein Fehler beim Abmelden ändert daran nichts
	return reply, nil
}
