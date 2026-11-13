package engine

import (
	"strings"
	"testing"

	"vpnpanel/internal/store"
)

// drain: Mails aus der Warteschlange „senden“ (Testmodus merkt sie nur).
func drain(e *Engine) {
	for {
		select {
		case m := <-e.notif.ch:
			_, _ = e.sendMail(m.to, m.subject, m.body)
		default:
			return
		}
	}
}

func TestNotifyWatchAndThrottle(t *testing.T) {
	e, _ := newTest(t)
	e.notif.init()
	// ohne Mailserver: nichts
	e.watchState("unbound", "u", true, "aus", "", "an", "")
	e.watchState("unbound", "u", true, "aus", "", "an", "")
	drain(e)
	if len(e.SentMails()) != 0 {
		t.Fatal("Mail ohne Einrichtung")
	}
	for k, v := range map[string]string{"mail_enabled": "1", "smtp_host": "mail.example.org", "mail_from": "panel@example.org", "notify_events": "unbound,error"} {
		_ = e.St.SetSetting(k, v)
	}
	// ohne Empfänger: nichts
	e.Notify("unbound", "x", "s", "b")
	drain(e)
	if len(e.SentMails()) != 0 {
		t.Fatal("Mail ohne Empfänger")
	}
	_ = e.St.SaveAdmin(&store.Admin{Username: "a", PassHash: "x", Email: "a@example.org", Notify: true})
	_ = e.St.SaveAdmin(&store.Admin{Username: "b", PassHash: "x", Email: "b@example.org"}) // ohne Benachrichtigung

	e.notif.track = map[string]*watchItem{}
	e.watchState("unbound", "g1", true, "Unbound aus", "", "Unbound an", "")
	drain(e)
	if len(e.SentMails()) != 0 {
		t.Fatal("schon nach einer Prüfung gemeldet")
	}
	e.watchState("unbound", "g1", true, "Unbound aus", "", "Unbound an", "")
	e.watchState("unbound", "g1", true, "Unbound aus", "", "Unbound an", "")
	e.watchState("unbound", "g1", false, "Unbound aus", "", "Unbound an", "")
	e.watchState("unbound", "g1", false, "Unbound aus", "", "Unbound an", "")
	drain(e)
	got := strings.Join(e.SentMails(), "\n")
	if got != "a@example.org | Unbound aus\na@example.org | Unbound an" {
		t.Fatalf("Mails:\n%s", got)
	}
	// gleiche Meldung innerhalb von 30 Minuten nicht noch einmal
	e.watchState("unbound", "g1", true, "Unbound aus", "", "Unbound an", "")
	e.watchState("unbound", "g1", true, "Unbound aus", "", "Unbound an", "")
	drain(e)
	if n := len(e.SentMails()); n != 2 {
		t.Fatalf("gedrosselt erwartet, %d Mails", n)
	}
	// Anlass abgewählt → nichts
	e.Notify("update", "v1", "Update", "")
	// Fehler im Ereignisprotokoll → Mail, Fehler beim Versand selbst nicht
	e.Log("error", "Anwenden fehlgeschlagen: kaputt")
	e.logQuiet("error", "E-Mail nicht gesendet")
	drain(e)
	got = strings.Join(e.SentMails(), "\n")
	if strings.Contains(got, "Update") || !strings.Contains(got, "Fehler: Anwenden fehlgeschlagen: kaputt") || strings.Contains(got, "nicht gesendet") {
		t.Fatalf("Mails:\n%s", got)
	}
}

func TestBuildMail(t *testing.T) {
	m := string(buildMail("VPN-Panel <panel@example.org>", []string{"a@example.org"}, "Ausfall\r\nBcc: boese@example.org", "Zeile 1\nÄnderung"))
	head, body, _ := strings.Cut(m, "\r\n\r\n")
	if strings.Contains(head, "\r\nBcc:") {
		t.Fatalf("Kopfzeile eingeschleust:\n%s", head)
	}
	if !strings.Contains(head, "Subject: Ausfall  Bcc: boese@example.org\r\n") || !strings.Contains(head, "Message-ID: <") || !strings.Contains(head, "@example.org>") {
		t.Errorf("Kopf:\n%s", head)
	}
	if u := string(buildMail("Panel Größe <panel@example.org>", []string{"a@example.org"}, "Ausgang „Schweiz“", "")); !strings.Contains(u, "Subject: =?utf-8?q?") ||
		!strings.Contains(u, "From: =?utf-8?q?Panel_Gr=C3=B6=C3=9Fe?= <panel@example.org>") {
		t.Errorf("Umlaute nicht kodiert:\n%s", u)
	}
	if v, err := ValidateSetting("mail_from", " VPN-Panel <panel@example.org> "); err != nil || v != "VPN-Panel <panel@example.org>" {
		t.Errorf("Absender umgeschrieben: %q %v", v, err)
	}
	if !strings.Contains(body, "Zeile 1\r\n=C3=84nderung") {
		t.Errorf("Text:\n%q", body)
	}
}

func TestSecretsFile(t *testing.T) {
	e, _ := newTest(t)
	if err := e.SetCFToken("abcdefghijklmnopqrstuvwxyz0123"); err != nil {
		t.Fatal(err)
	}
	if err := e.SetSMTPPassword("p w#1"); err != nil {
		t.Fatal(err)
	}
	if e.cfToken() != "abcdefghijklmnopqrstuvwxyz0123" || e.secret("SMTP_PASSWORD") != "p w#1" || !e.SMTPPasswordSet() {
		t.Fatal("lesen")
	}
	if err := e.SetSMTPPassword("a\nCF_API_TOKEN=x"); err == nil {
		t.Fatal("Zeilenumbruch im Passwort angenommen")
	}
	_ = e.SetSMTPPassword("")
	if e.SMTPPasswordSet() || e.cfToken() == "" {
		t.Fatal("Entfernen darf nur die eigene Zeile treffen")
	}
}
