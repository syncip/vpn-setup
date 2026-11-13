package engine

import (
	"net"
	"net/textproto"
	"strings"
	"testing"
)

// fakeSMTP: minimaler Mailserver ohne Verschlüsselung und Anmeldung; merkt sich Befehle und Nachricht.
func fakeSMTP(t *testing.T, dataReply string) (addr string, got chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tp := textproto.NewConn(c)
		var log strings.Builder
		_ = tp.PrintfLine("220 test ESMTP")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				got <- log.String()
				return
			}
			log.WriteString(line + "\n")
			cmd := strings.ToUpper(strings.Fields(line + " x")[0])
			switch cmd {
			case "EHLO":
				_ = tp.PrintfLine("250-test\r\n250 8BITMIME")
			case "DATA":
				_ = tp.PrintfLine("354 go")
				body, _ := readAll(tp)
				log.WriteString(body)
				_ = tp.PrintfLine("%s", dataReply)
			case "QUIT":
				_ = tp.PrintfLine("221 bye")
				got <- log.String()
				return
			default:
				_ = tp.PrintfLine("250 ok")
			}
		}
	}()
	return l.Addr().String(), got
}

func readAll(tp *textproto.Conn) (string, error) {
	lines, err := tp.ReadDotLines()
	return strings.Join(lines, "\n"), err
}

func TestSMTPSendReply(t *testing.T) {
	addr, got := fakeSMTP(t, "250 2.0.0 Ok: queued as 4D5353F536")
	host, port, _ := net.SplitHostPort(addr)
	c := smtpConfig{Host: host, Port: atoi(port, 0), Security: "none", From: "VPN <vpn@example.org>", HeloName: "vpn.example.org"}
	reply, err := smtpSend(c, []string{"admin@example.org"}, "Testmail", "Hallo")
	if err != nil {
		t.Fatal(err)
	}
	if reply != "250 2.0.0 Ok: queued as 4D5353F536" {
		t.Errorf("Antwort: %q", reply)
	}
	log := <-got
	for _, want := range []string{"EHLO vpn.example.org", "MAIL FROM:<vpn@example.org>", "RCPT TO:<admin@example.org>", "Subject: Testmail", "Hallo", "QUIT"} {
		if !strings.Contains(log, want) {
			t.Errorf("fehlt %q:\n%s", want, log)
		}
	}
}

func TestSMTPSendRejected(t *testing.T) {
	addr, _ := fakeSMTP(t, "554 5.7.1 Spam")
	host, port, _ := net.SplitHostPort(addr)
	c := smtpConfig{Host: host, Port: atoi(port, 0), Security: "none", From: "vpn@example.org"}
	if _, err := smtpSend(c, []string{"admin@example.org"}, "x", "y"); err == nil || !strings.Contains(err.Error(), "554") {
		t.Errorf("Ablehnung nicht erkannt: %v", err)
	}
	// Benutzername ohne Passwort: klare Meldung statt Anmeldefehler
	c.User = "vpn@example.org"
	addr2, _ := fakeSMTP(t, "250 ok")
	h2, p2, _ := net.SplitHostPort(addr2)
	c.Host, c.Port = h2, atoi(p2, 0)
	if _, err := smtpSend(c, []string{"admin@example.org"}, "x", "y"); err == nil || !strings.Contains(err.Error(), "kein Passwort") {
		t.Errorf("fehlendes Passwort: %v", err)
	}
}
