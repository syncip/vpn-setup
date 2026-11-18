package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"vpnpanel/internal/exits"
)

// Aktive Prüfung eines Ziels über einen Ausgang: wie ein Browser die Startseite abrufen (Namen über
// den Ausgang auflösen, TLS, Weiterleitungen folgen) und die Antwort einordnen.

var blockDNS = []string{"1.1.1.1", "9.9.9.9"}

// Merkmale von Captcha- bzw. Prüfseiten (Cloudflare, reCAPTCHA, hCaptcha, DataDome, PerimeterX,
// Akamai, Imperva) – im Inhalt der Seite, kleingeschrieben.
var captchaMarks = []string{
	"cf-chl-", "/cdn-cgi/challenge-platform", "challenges.cloudflare.com", "just a moment...",
	"attention required! | cloudflare", "g-recaptcha", "www.google.com/recaptcha", "hcaptcha.com/1/api",
	"h-captcha", "captcha-delivery.com", "geo.captcha-delivery", "px-captcha", "_incapsula_resource",
	"are you a robot", "unusual traffic from your computer", "verify you are human", "bist du ein mensch",
}

// Merkmale von Sperrseiten.
var blockMarks = []string{
	"access denied", "you don't have permission to access", "error 1020", "error 1006", "error 1009",
	"request blocked", "the request could not be satisfied", "not available in your country",
	"not available in your region", "nicht in deinem land verfügbar", "vpn or proxy", "proxy or vpn",
	"anonymous proxy", "your ip has been blocked", "ip address has been blocked",
}

// classifyBlock ordnet eine Antwort ein: ok | captcha | blocked | error.
func classifyBlock(code int, hdr http.Header, body string) (string, string) {
	b := strings.ToLower(body)
	if strings.EqualFold(hdr.Get("cf-mitigated"), "challenge") {
		return "captcha", "Cloudflare-Prüfung (Captcha)"
	}
	for _, m := range captchaMarks {
		if strings.Contains(b, m) && (code >= 400 || len(b) < 60000) {
			return "captcha", fmt.Sprintf("Captcha-Seite (HTTP %d)", code)
		}
	}
	switch {
	case code == 451:
		return "blocked", "HTTP 451 – aus rechtlichen Gründen gesperrt"
	case code == 429:
		return "blocked", "HTTP 429 – zu viele Anfragen (Adresse gedrosselt)"
	case code == 403 || code == 401 && hdr.Get("WWW-Authenticate") == "":
		for _, m := range blockMarks {
			if strings.Contains(b, m) {
				return "blocked", fmt.Sprintf("Sperrseite (HTTP %d: „%s“)", code, m)
			}
		}
		return "blocked", fmt.Sprintf("HTTP %d – Zugriff verweigert", code)
	case code >= 500:
		return "error", fmt.Sprintf("HTTP %d – Fehler des Ziels", code)
	}
	if code >= 200 && code < 400 {
		for _, m := range blockMarks {
			if strings.Contains(b, m) && len(b) < 20000 { // kurze Seite mit Sperrtext
				return "blocked", fmt.Sprintf("Sperrseite (HTTP %d: „%s“)", code, m)
			}
		}
	}
	return "ok", fmt.Sprintf("HTTP %d", code)
}

// probeTarget prüft domain über den Ausgang mit der Markierung mark.
func probeTarget(ctx context.Context, mark uint32, domain string) (string, string) {
	d := exits.Dialer(mark)
	d.Resolver = exits.Resolver(mark, blockDNS)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 12 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 25 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 6 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/", nil)
	if err != nil {
		return "error", err.Error()
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	resp, err := cl.Do(req)
	if err != nil {
		return "error", shortNetErr(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return classifyBlock(resp.StatusCode, resp.Header, string(body))
}

func shortNetErr(err error) string {
	s := err.Error()
	var de *net.DNSError
	switch {
	case errors.As(err, &de):
		return "Name nicht auflösbar: " + de.Err
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded"):
		return "Zeitüberschreitung"
	case strings.Contains(s, "connection refused"):
		return "Verbindung abgelehnt"
	case strings.Contains(s, "connection reset"):
		return "Verbindung zurückgesetzt"
	case strings.Contains(s, "tls:") || strings.Contains(s, "x509"):
		return "TLS-Fehler"
	}
	if len(s) > 160 {
		s = s[:160] + " …"
	}
	return s
}

// demoProbe: Trockenlauf – feste, nachvollziehbare Ergebnisse ohne Netz.
func demoProbe(domain string, exitID int64) (string, string) {
	h := fnv.New32a()
	fmt.Fprintf(h, "%s|%d", domain, exitID)
	switch h.Sum32() % 9 {
	case 0:
		return "captcha", "Cloudflare-Prüfung (Captcha) – Demo"
	case 1:
		return "blocked", "HTTP 403 – Zugriff verweigert – Demo"
	}
	return "ok", "HTTP 200 – Demo"
}
