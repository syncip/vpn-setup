package exits

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Hochgeladene Konfigurationen werden nie unverändert übernommen: Wir lesen nur, was wir
// brauchen, und schreiben eine eigene Konfiguration. Alles andere (Skripte, Routen, DNS-Umbauten,
// Dateiverweise) fällt weg und wird dem Nutzer als „entfernt“ angezeigt.

// WG: Ausgang über WireGuard.
type WG struct {
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	Endpoint     string // host:port
	Address      netip.Prefix
	DNS          []string
	MTU          int
	Keepalive    int
	Removed      []string
}

func validKey(k string) bool {
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32
}

var hostPortRe = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{1,253}):([0-9]{1,5})$`)

// ParseWG liest eine wg-quick-Konfiguration (wie sie Anbieter ausgeben).
func ParseWG(text string) (*WG, error) {
	w := &WG{MTU: 1420, Keepalive: 25}
	sec := ""
	peers := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	n := 0
	for sc.Scan() {
		n++
		if n > 500 {
			return nil, fmt.Errorf("Konfiguration zu lang")
		}
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if sec == "peer" {
				peers++
			} else if sec != "interface" {
				return nil, fmt.Errorf("unbekannter Abschnitt [%s]", sec)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("Zeile %d nicht lesbar", n)
		}
		orig := strings.TrimSpace(k)
		k, v = strings.ToLower(orig), strings.TrimSpace(v)
		if sec == "" {
			return nil, fmt.Errorf("Zeile %d steht außerhalb eines Abschnitts", n)
		}
		switch sec + "." + k {
		case "interface.privatekey":
			w.PrivateKey = v
		case "interface.address":
			for _, a := range strings.Split(v, ",") {
				a = strings.TrimSpace(a)
				if !strings.Contains(a, "/") {
					a += "/32"
				}
				if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is4() && !w.Address.IsValid() {
					w.Address = p
				}
			}
		case "interface.dns":
			for _, d := range strings.Split(v, ",") {
				if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil && a.Is4() {
					w.DNS = append(w.DNS, a.String())
				}
			}
		case "interface.mtu":
			if m, err := strconv.Atoi(v); err == nil && m >= 1280 && m <= 1500 {
				w.MTU = m
			}
		case "peer.publickey":
			w.PublicKey = v
		case "peer.presharedkey":
			w.PresharedKey = v
		case "peer.endpoint":
			w.Endpoint = v
		case "peer.persistentkeepalive":
			if m, err := strconv.Atoi(v); err == nil && m >= 0 && m <= 600 {
				w.Keepalive = m
			}
		case "peer.allowedips":
			if !strings.Contains(v, "0.0.0.0/0") {
				w.Removed = append(w.Removed, "AllowedIPs (der Ausgang leitet immer den gesamten IPv4-Verkehr)")
			}
		default:
			w.Removed = append(w.Removed, orig)
		}
	}
	switch {
	case !validKey(w.PrivateKey):
		return nil, fmt.Errorf("PrivateKey fehlt oder ist ungültig")
	case peers != 1:
		return nil, fmt.Errorf("genau ein [Peer] erwartet, gefunden: %d", peers)
	case !validKey(w.PublicKey):
		return nil, fmt.Errorf("PublicKey des Peers fehlt oder ist ungültig")
	case w.PresharedKey != "" && !validKey(w.PresharedKey):
		return nil, fmt.Errorf("PresharedKey ist ungültig")
	case !hostPortRe.MatchString(w.Endpoint):
		return nil, fmt.Errorf("Endpoint fehlt oder ist ungültig (host:port)")
	case !w.Address.IsValid():
		return nil, fmt.Errorf("keine IPv4-Adresse (Address) gefunden")
	}
	if p, _ := strconv.Atoi(hostPortRe.FindStringSubmatch(w.Endpoint)[2]); p < 1 || p > 65535 {
		return nil, fmt.Errorf("Port im Endpoint ungültig")
	}
	return w, nil
}

// SetConf: Datei für „wg setconf“ (nur Schlüssel und Gegenstelle; Endpoint schon aufgelöst).
func (w *WG) SetConf(endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\n", w.PrivateKey, w.PublicKey)
	if w.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", w.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\nAllowedIPs = 0.0.0.0/0\n", endpoint)
	if w.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", w.Keepalive)
	}
	return b.String()
}

// ResolveEndpoint: Hostnamen im Endpoint auflösen (wg setconf kann das nicht), IPv4 bevorzugt.
func ResolveEndpoint(ep string, lookup func(string) ([]net.IP, error)) (string, error) {
	m := hostPortRe.FindStringSubmatch(ep)
	if m == nil {
		return "", fmt.Errorf("Endpoint ungültig")
	}
	host := strings.Trim(m[1], "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, uint16(atoi(m[2]))).String(), nil
	}
	ips, err := lookup(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("%s lässt sich nicht auflösen", host)
	}
	pick := ips[0]
	for _, ip := range ips {
		if ip.To4() != nil {
			pick = ip
			break
		}
	}
	a, _ := netip.AddrFromSlice(pick)
	return netip.AddrPortFrom(a.Unmap(), uint16(atoi(m[2]))).String(), nil
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// ---------- OpenVPN ----------

// OVPN: bereinigte OpenVPN-Client-Konfiguration.
type OVPN struct {
	Config   string // ohne unsere Zusätze (dev, Skripte aus, …)
	Remote   string // erster remote-Eintrag (Anzeige)
	NeedAuth bool   // auth-user-pass → Benutzername/Passwort nötig
	Removed  []string
}

// Erlaubte Anweisungen (Argumente werden übernommen). Alles andere wird entfernt.
var ovpnAllowed = map[string]bool{
	"client": true, "tls-client": true, "pull": true, "nobind": true, "persist-key": true, "persist-tun": true,
	"resolv-retry": true, "remote": true, "remote-random": true, "remote-random-hostname": true, "proto": true, "port": true,
	"rport": true, "connect-retry": true, "connect-retry-max": true, "connect-timeout": true, "server-poll-timeout": true,
	"remote-cert-tls": true, "remote-cert-ku": true, "remote-cert-eku": true, "ns-cert-type": true, "verify-x509-name": true,
	"cipher": true, "data-ciphers": true, "data-ciphers-fallback": true, "ncp-ciphers": true, "ncp-disable": true, "auth": true,
	"tls-version-min": true, "tls-version-max": true, "tls-cipher": true, "tls-ciphersuites": true, "tls-groups": true,
	"key-direction": true, "comp-lzo": true, "compress": true, "allow-compression": true, "reneg-sec": true, "reneg-bytes": true,
	"ping": true, "ping-restart": true, "ping-timer-rem": true, "keepalive": true, "tun-mtu": true, "tun-mtu-extra": true,
	"link-mtu": true, "mssfix": true, "fragment": true, "sndbuf": true, "rcvbuf": true, "explicit-exit-notify": true,
	"auth-nocache": true, "float": true, "hand-window": true, "tls-timeout": true, "mute-replay-warnings": true,
	"replay-window": true, "ecdh-curve": true, "key-method": true, "push-peer-info": true, "peer-fingerprint": true,
	"fast-io": true, "dev-type": true,
}

// Eingebettete Blöcke, die übernommen werden.
var ovpnBlocks = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true, "extra-certs": true}

// Anweisungen, die nur eingebettet erlaubt sind (sonst Verweis auf eine fremde Datei).
var ovpnFileArgs = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"extra-certs": true, "pkcs12": true, "secret": true, "dh": true, "crl-verify": true}

var ovpnArgRe = regexp.MustCompile(`^[A-Za-z0-9._:/@+=,\[\]-]{0,200}$`)

// ParseOVPN bereinigt eine .ovpn-Datei.
func ParseOVPN(text string) (*OVPN, error) {
	o := &OVPN{}
	var out strings.Builder
	removed := map[string]bool{}
	rm := func(k string) {
		if !removed[k] {
			removed[k] = true
			o.Removed = append(o.Removed, k)
		}
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > 3000 {
		return nil, fmt.Errorf("Konfiguration zu lang")
	}
	hasCA, remotes := false, 0
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		// eingebetteter Block <tag> … </tag>
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			tag := strings.ToLower(line[1 : len(line)-1])
			var body []string
			closed := false
			for i++; i < len(lines); i++ {
				l := strings.TrimSpace(lines[i])
				if strings.EqualFold(l, "</"+tag+">") {
					closed = true
					break
				}
				if strings.HasPrefix(l, "<") {
					return nil, fmt.Errorf("Block <%s> ist nicht abgeschlossen", tag)
				}
				body = append(body, l)
			}
			if !closed {
				return nil, fmt.Errorf("Block <%s> ist nicht abgeschlossen", tag)
			}
			if !ovpnBlocks[tag] {
				rm("<" + tag + ">")
				continue
			}
			content := strings.Join(body, "\n")
			if !strings.Contains(content, "-----BEGIN ") || !strings.Contains(content, "-----END ") {
				return nil, fmt.Errorf("Block <%s> enthält keinen Schlüssel bzw. kein Zertifikat", tag)
			}
			if tag == "ca" {
				hasCA = true
			}
			fmt.Fprintf(&out, "<%s>\n%s\n</%s>\n", tag, content, tag)
			continue
		}
		f := strings.Fields(line)
		k := strings.ToLower(strings.TrimPrefix(f[0], "--"))
		args := f[1:]
		switch {
		case k == "auth-user-pass":
			o.NeedAuth = true // eigene Datei mit den eingetragenen Zugangsdaten
			continue
		case ovpnFileArgs[k]:
			return nil, fmt.Errorf("„%s“ verweist auf eine Datei – bitte eine Konfiguration mit eingebetteten Zertifikaten (<%s>…</%s>) hochladen", k, k, k)
		case k == "dev":
			continue // setzen wir selbst
		case !ovpnAllowed[k]:
			rm(k)
			continue
		}
		for _, a := range args {
			if !ovpnArgRe.MatchString(strings.Trim(a, `"`)) {
				return nil, fmt.Errorf("„%s“: ungültiges Argument %q", k, a)
			}
		}
		if k == "dev-type" && (len(args) != 1 || args[0] != "tun") {
			return nil, fmt.Errorf("nur Tunnel-Verbindungen (dev tun) werden unterstützt")
		}
		if k == "remote" {
			if len(args) < 1 {
				return nil, fmt.Errorf("remote ohne Adresse")
			}
			remotes++
			if o.Remote == "" {
				o.Remote = strings.Join(args, " ")
			}
		}
		out.WriteString(k)
		if len(args) > 0 {
			out.WriteString(" " + strings.Join(args, " "))
		}
		out.WriteByte('\n')
	}
	if remotes == 0 {
		return nil, fmt.Errorf("kein „remote“ (Server-Adresse) gefunden")
	}
	if !hasCA {
		return nil, fmt.Errorf("kein eingebettetes CA-Zertifikat (<ca>) gefunden")
	}
	o.Config = out.String()
	return o, nil
}

// Full: komplette Client-Konfiguration für unsere Instanz.
func (o *OVPN) Full(dev, authFile string) string {
	var b strings.Builder
	b.WriteString("# Vom VPN-Panel erzeugt (bereinigte Anbieter-Konfiguration) – Änderungen werden überschrieben.\n")
	b.WriteString(o.Config)
	fmt.Fprintf(&b, "dev %s\ndev-type tun\npersist-tun\n", dev)
	// Keine Routen, kein DNS-Umbau, keine Skripte: der Ausgang ist nur über die Routing-Tabelle
	// seiner Gruppe erreichbar, der Server selbst bleibt unberührt.
	b.WriteString("route-noexec\nscript-security 1\n")
	for _, f := range []string{"redirect-gateway", "route-ipv6", "ifconfig-ipv6", "tun-ipv6", "dhcp-option", "block-outside-dns", "dns", "register-dns"} {
		fmt.Fprintf(&b, "pull-filter ignore \"%s\"\n", f)
	}
	b.WriteString("ignore-unknown-option dns-updown\ndns-updown disable\n")
	if o.NeedAuth {
		fmt.Fprintf(&b, "auth-user-pass %s\nauth-nocache\nauth-retry nointeract\n", authFile)
	}
	b.WriteString("verb 3\nmute 20\n")
	return b.String()
}
