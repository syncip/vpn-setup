# vpn-setup

WireGuard-Netze (Stern, Geräte mit Netzen dahinter), VLESS/Reality, Hysteria2 und OpenVPN mit Webinterface:
Nutzer, Tarife, Datenvolumen, Drosselung und Login mit 2FA. Für Debian 13.

## Installation

Läuft auf jedem Server mit **Debian 13**: VPS, eigene Hardware oder Container (z. B. Proxmox-LXC).

```bash
curl -fsSLO https://raw.githubusercontent.com/syncip/vpn-setup/main/vpn-setup.sh
bash vpn-setup.sh
```

Beim ersten Start fragt das Script nach:

- **Server-Adresse** – Domain mit A-/AAAA-Eintrag auf den Server (ohne Cloudflare-Proxy) oder die
  öffentliche IP. Sie steht in allen Links und Konfigurationen.
- **Abo-Domain** (optional) – z. B. `sub.example.org` über Cloudflare-Proxy. Leer = Abo-Links über die
  Panel-Domain bzw. direkt über `https://<IP>:9443/sub/…`.
- **Panel-Domain** (optional) – z. B. `panel.example.org` über Cloudflare-Proxy.

Die ausgehende Netzwerkschnittstelle erkennt das Script selbst. Das Panel-Programm kommt aus dem
neuesten Release. Erneut ausführen aktualisiert alles; Daten und Einstellungen bleiben.

```bash
bash vpn-setup.sh --neu                                   # Domains neu abfragen
SERVER_HOST=vpn.example.org SUB_HOST=sub.example.org bash vpn-setup.sh   # ohne Rückfragen
vpn config                                                # Einstellungen anzeigen
vpn config server_host=vpn.example.org                    # ändern und anwenden
```

Danach läuft das Webinterface auf **https://<IP>:9443**, dazu der Befehl `vpn help`.
Die erste Anmeldung steht in `/etc/vpn/panel-admin.txt`.

**Offene Ports:** TCP 443 und 9443, UDP 51820 (WireGuard), UDP 443 (Hysteria2, bei Port-Hopping
zusätzlich der UDP-Bereich), UDP 1194 bzw. der eingestellte Port (OpenVPN).

**Cloudflare (optional):** Für Abo- und Panel-Domain hinter Cloudflare das Origin-Zertifikat als
`/etc/vpn/sub-cert.pem` und `/etc/vpn/sub-key.pem` ablegen (muss beide Domains abdecken) und
SSL auf „Vollständig (streng)“ stellen. Ohne Zertifikat nutzt das Panel ein selbstsigniertes.

## Server hinter NAT (z. B. Proxmox-Container)

Erkennt das Script einen Container, zeigt es am Ende die nötigen Befehle für den Host an. Der Host muss
die Ports an den Container weiterleiten (Beispiel Container 10.10.10.3):

```bash
iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 9443 -j DNAT --to-destination 10.10.10.3:9443
```

Genauso TCP 443, UDP 443 und UDP 51820. Dauerhaft z. B. als `post-up`/`post-down` in
`/etc/network/interfaces`. Außerdem lädt der Host die Kernelmodule (WireGuard, Drosselung) und setzt
größere UDP-Puffer für Hysteria2 – beides geht im unprivilegierten Container nicht.

## Hysteria2

Jeder Hysteria2-Server läuft als eigene Instanz (`vpn-hysteria@hy<ID>`), Vorgabe UDP 443.
Im Container: auf dem Host den UDP-Port weiterleiten und größere UDP-Puffer setzen
(auf normalen Servern erledigt das Script):

```bash
iptables -t nat -A PREROUTING -i vmbr0 -p udp --dport 443 -j DNAT --to-destination 10.10.10.3:443
printf '%s\n' net.core.rmem_max=16777216 net.core.wmem_max=16777216 > /etc/sysctl.d/90-hysteria.conf && sysctl --system
```

### Port-Hopping (optional)

Unter Server → Hysteria2 → Erweitert einen UDP-Bereich eintragen, z. B. `20000-50000`. Der Client
wechselt dann regelmäßig den Zielport (hilft, wenn Anbieter einzelne UDP-Verbindungen drosseln).
Das Panel leitet den Bereich auf den Hysteria-Port um. Läuft es in einem Container, muss der Host
den Bereich an den Container weiterleiten:

```bash
iptables  -t nat -A PREROUTING -i vmbr0 -p udp --dport 20000:50000 -j DNAT --to-destination 10.10.10.3
ip6tables -t nat -A PREROUTING -i vmbr0 -d 2001:41d0:203:4a76::10 -p udp --dport 20000:50000 -j DNAT --to-destination fd10:10:10::3
```

Links bekommen `mport=20000-50000` (NekoBox, v2rayN); Hiddify erhält im Abo automatisch die
Form `host:443,20000-50000`. Apps ohne Unterstützung nutzen weiter den normalen Port.

## OpenVPN

Für Geräte, die nur OpenVPN können (Router, Firewalls wie OPNsense/pfSense, Firmen-PCs mit
OpenVPN Connect). Jeder OpenVPN-Server läuft als eigene Instanz (`vpn-openvpn@ovpn<ID>`,
Konfiguration in `/etc/openvpn/vpn/`), Vorgabe UDP 1194, Tunnelnetz `10.66.0.0/24` und `fd66:66:66::/64`.

- Eigene CA pro Server (ECDSA P-256), ein Zertifikat pro Zugang, `tls-crypt`: ohne Profil antwortet
  der Server gar nicht.
- Gesperrte, deaktivierte oder gelöschte Zugänge weist der Server sofort ab (`ccd-exclusive`) und trennt
  laufende Verbindungen. „Neue Schlüssel“ beim Zugang macht das alte Profil ungültig, beim Server alle.
- Profil: unter Zugänge → Konfiguration als `.ovpn`-Datei, als Download-Link oder als QR-Code für
  OpenVPN Connect. OpenVPN steht nicht im Abo (die Abo-Apps können es nicht).
- Geschwindigkeitslimits gelten wie bei WireGuard (tc auf `ovpn<ID>`).

Im Container braucht OpenVPN `/dev/net/tun`. Auf dem Proxmox-Host in `/etc/pve/lxc/<ID>.conf`
ergänzen und den Container neu starten, außerdem den Port weiterleiten:

```
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```

```bash
iptables -t nat -A PREROUTING -i vmbr0 -p udp --dport 1194 -j DNAT --to-destination 10.10.10.3:1194
```

## Proxy und Ausgänge (externe VPNs)

Menü **Proxy & Ausgänge**: SOCKS5- und HTTP-Proxy mit Benutzername und Passwort, z. B. für Fernseher und Apps.
Der Verkehr läuft direkt über den Server oder über eine **Ausgangsgruppe** – also über externe
VPN-Verbindungen, deren WireGuard- oder OpenVPN-Konfiguration (z. B. vom VPN-Anbieter) hochgeladen wird.

- **Ausgänge:** Hochgeladene Konfigurationen werden bereinigt: übernommen werden nur Schlüssel, Adresse,
  Gegenstelle und Verschlüsselung. Skripte (`PostUp`, `up`/`down`), Routen, DNS-Änderungen,
  `redirect-gateway`, Plugins und Verweise auf fremde Dateien fallen weg (die Oberfläche zeigt, was
  entfernt wurde). Jeder Ausgang bekommt eine Schnittstelle `ex<ID>` ohne Route in der Haupttabelle –
  der Server selbst bleibt unverändert erreichbar. Eingehende Verbindungen über einen Ausgang werden
  verworfen, TCP-MSS wird angepasst. Nur IPv4.
- **Gruppen:** mehrere Ausgänge in fester Reihenfolge. Alle 30 Sekunden prüft der Server jeden Ausgang
  (Ping, HTTPS-Abruf über den Tunnel → öffentliche IP und Land; auf Wunsch ein Geschwindigkeitstest mit
  5 MB, Einstellung `exit_speedtest`). Überschreitet der aktive Ausgang die Grenzen (Verlust,
  Antwortzeit, Mindesttempo) in zwei Prüfungen hintereinander, übernimmt der nächste – ein einzelner
  Aussetzer schaltet nicht um. Antwortet nur der Ping nicht (manche Anbieter blockieren ICMP), zählt das
  nicht als Verlust. Zurück geht es, wenn der bevorzugte Ausgang 10 Minuten stabil war. Fallen alle aus:
  **sperren** (kein Verkehr) oder **direkt** über den Server. Bei „sperren“ greift die Sperre auch in der
  kurzen Zeit, in der ein OpenVPN-Ausgang neu verbindet (kein kurzes Durchrutschen mit der Server-Adresse).
  Von Hand umschalten macht den gewählten Ausgang zum bevorzugten; Ausgang 1 wählen = normale Reihenfolge.
- **DNS** der Proxy-Nutzer wird über den aktiven Ausgang aufgelöst (DNS-Server je Gruppe).
- **Proxy-Zugänge** hängen wie alle Zugänge am Nutzer (Limits, Drosselung, Statistik, Sperre).
  Geräte ohne Passwort-Unterstützung (viele Fernseher): beim Zugang „Anmeldung per IP“ mit der festen
  öffentlichen Adresse des Anschlusses.
- Über den Proxy sind lokale Ziele (Container, Proxmox-Host, private Netze, Tailscale), die öffentlichen
  Adressen des Servers selbst und Port 25 (Mailversand) gesperrt. Eine Sperre nach Fehlversuchen gibt es
  nicht (sie traf vor allem die eigenen Geräte); die zufälligen 24-stelligen Passwörter sind nicht zu erraten.
- Abgelehnte Verbindungen und Anmeldungen stehen mit Grund unter **Ereignisse** (Übersicht bzw.
  Einstellungen → Ereignisse): IP-Liste, falsches Passwort, Zugang gesperrt, Verbindungsgrenze, Ziel nicht
  erreichbar (mit Fehler, auch bei 502/SOCKS-Fehlern) … – je Adresse und Grund höchstens alle 10 Minuten.
  Der Grund steht auch im Text der Fehlerantwort (`curl -v`).
- Ziele: **direkt** über den Server IPv4 und IPv6, über eine **Ausgangsgruppe** nur IPv4. Die Zugangsdaten
  zeigen deshalb `socks5h://…` – damit löst der Proxy die Namen auf (DNS über den Ausgang). Test mit curl:
  `curl -x socks5h://BENUTZER:PASSWORT@HOST:1080 https://www.cloudflare.com/cdn-cgi/trace` bzw.
  `-x http://BENUTZER:PASSWORT@HOST:8080`.
- Die Proxy-Verbindung selbst ist **unverschlüsselt** (Benutzername/Passwort können mitgelesen werden;
  HTTPS-Inhalte bleiben verschlüsselt).

Ports auf dem Proxmox-Host weiterleiten (Vorgabe SOCKS5 1080, HTTP 8080, beide TCP):

```bash
iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 1080 -j DNAT --to-destination 10.10.10.3:1080
iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 8080 -j DNAT --to-destination 10.10.10.3:8080
```

OpenVPN-Ausgänge brauchen wie der OpenVPN-Server `/dev/net/tun` (siehe oben).

## Ziel-Regeln: Verkehr über Ausgänge leiten (alle Protokolle)

Auf der Seite **Proxy & Ausgänge** legen **Ziel-Regeln** fest, welcher Verkehr über welche
Ausgangsgruppe läuft – nicht nur beim Proxy, sondern auch bei WireGuard, OpenVPN, VLESS und Hysteria2.

- **Gilt für:** alle, einen Server, einen Nutzer (alle seine Zugänge) oder ein einzelnes Gerät.
- **Ziele:** alles – oder nur bestimmte Ziele: Domains (samt Unterdomains), IPv4-Netze und Ziellisten
  (IP-Listen der Art „Zielliste“, auch als Online-Liste).
- **Über:** eine Ausgangsgruppe – oder „direkt über den Server“ als Ausnahme (z. B. alles über Mullvad,
  nur die Bank direkt).
- **Rangfolge:** Gerät vor Nutzer vor Server vor „alle“; innerhalb einer Ebene Ziel-Regeln vor „alles“.
  Die erste passende Regel gilt. Regeln mit deaktivierter Gruppe wirken nicht (Verkehr geht direkt).

So wird es je Protokoll umgesetzt:

| Protokoll | Umsetzung | Hinweise |
|-----------|-----------|----------|
| WireGuard, OpenVPN | nftables markiert Pakete je Quelle und Ziel, die Markierung wählt die Routing-Tabelle der Gruppe | Domains über die DNS-Anfragen des Geräts (siehe unten) |
| VLESS | Xray-Routing je Zugang | Domains per Sniffing, sehr zuverlässig |
| Hysteria2 | Ausgang wird an die Schnittstelle des aktiven Ausgangs gebunden, Ziele per Hysteria-ACL | nur Regeln für Server und „alle“ (Hysteria kann Nutzer nicht einzeln leiten); wechselt die Gruppe den Ausgang, startet der Dienst kurz neu |
| Proxy | im Panel-Prozess je Zugang | die Server-Einstellung „Ausgang“ wirkt wie eine „alles“-Regel am Server |

- **Domains bei WireGuard/OpenVPN:** Der Kernel sieht nur Adressen. Für Geräte mit Domain-Regeln leitet
  der Server deshalb deren DNS-Anfragen (Port 53) an einen eingebauten Umleiter, der die Adressen der
  passenden Namen lernt (24 Stunden) – unabhängig davon, welcher DNS-Server im Gerät eingetragen ist.
  DNS über TLS (Port 853) wird für diese Geräte abgewiesen, damit sie auf normales DNS zurückfallen.
  Geräte bzw. Browser mit DNS über HTTPS (DoH) umgehen das – dort DoH ausschalten oder Netze/Listen verwenden.
- **IPv6:** Ausgänge können nur IPv4. Läuft bei einem Gerät *alles* über eine Gruppe, wird IPv6 ins
  Internet für dieses Gerät gesperrt (sonst ginge es am Ausgang vorbei); für Domains aus Regeln gibt es
  keine IPv6-Adressen. Ziellisten und Netze zählen nur mit ihren IPv4-Einträgen.
- **Private Ziele** (andere VPN-Geräte, Heimnetze hinter Geräten, der Server selbst) laufen nie über Ausgänge.
- **Drosselung:** Tempo-Limits von VLESS-Nutzern wirken nicht für Verkehr, der über Ausgänge läuft.
- Fällt die Gruppe aus, gilt ihre Einstellung „sperren“ oder „direkt“ wie beim Proxy.

## IP-Listen

Menü **IP-Listen**: Sperrlisten (diese Adressen nie) und Freigabelisten (nur diese Adressen), je Liste
für alle Dienste oder ausgewählte Server. Gibt es für einen Dienst eine Freigabeliste, kommen nur deren
Adressen hinein; Sperrlisten gelten zusätzlich. Dazu **Ziellisten** für Ziel-Regeln (siehe oben).

- **Online-Listen:** Jede Liste kann zusätzlich eine Adresse (http/https) haben, von der der Server
  regelmäßig eine Textdatei lädt (eine Adresse oder ein Netz pro Zeile, Kommentare mit `#` oder `;`) –
  z. B. Sperrlisten von FireHOL oder Spamhaus. Intervall: von Hand, stündlich bis wöchentlich. Bis
  300 000 Einträge; nicht lesbare Zeilen werden übersprungen und gezählt. Schlägt ein Abruf fehl oder
  ist die Antwort leer, bleibt der letzte Stand aktiv (neuer Versuch spätestens nach einer Stunde).
  Geladen wird nur von öffentlichen Adressen.
- **Durchsetzung:** eigene nftables-Tabelle `inet vpnpanel` (pro Liste ein Set – auch große Listen
  kosten pro Paket nur eine Suche), geprüft auf den Ports des Dienstes; bestehende Verbindungen
  gesperrter Adressen brechen sofort ab. VLESS teilt sich Port 443 mit Panel und Abo und regelt es
  deshalb in Xray. Webinterface und Abo-Links sind nie betroffen. Braucht das Paket `nftables`
  (installiert das Setup-Script; beim Update von 0.7 `vpn-setup.sh` erneut ausführen).

## Version und Updates

Die Seitenleiste und die Übersicht zeigen die Version. Das Panel fragt alle 12 Stunden bei GitHub nach
dem neuesten Release (ohne Daten mitzuschicken) und zeigt ein verfügbares Update an; abschaltbar in den
Einstellungen. Eingespielt wird ein Update wie die Installation (Programm und Script kopieren,
`bash vpn-setup.sh`).

## Abo (Hiddify, v2rayN, NekoBox)

Das Abo eines Nutzers enthält alle aktiven Zugänge: VLESS (ein Eintrag je Tarnziel), Hysteria2 und
WireGuard-Geräte vom Typ „Handy / Laptop“ als `wireguard://`-Link. Einträge heißen „Server - Gerät“.
v2RayTun liest keine `wireguard://`-Links; erkennt das Panel die App (User-Agent `v2raytun`), steht
WireGuard dort als einzeilige Xray-JSON-Konfiguration im Abo.
Denselben WireGuard-Zugang nicht gleichzeitig in zwei Apps (oder App + WireGuard-App) nutzen.

**sing-box-App:** Die offizielle sing-box-App liest keine Link-Listen. `<Abo-Link>?format=singbox` liefert
stattdessen ein fertiges Profil (Hysteria2 mit eingebettetem Zertifikat, WireGuard „Handy / Laptop“ mit
vollem Tunnel, automatische Serverwahl). Den passenden QR-Code (`sing-box://import-remote-profile?…`)
zeigt die Nutzerseite.

**VLESS und sing-box/Hiddify:** Xray ab v26.9.9 nimmt bei Reality nur noch Client Hellos mit
`X25519MLKEM768` an; sing-box (und damit Hiddify) wird abgelehnt (`reality verification failed`).
VLESS deshalb mit Xray-basierten Apps nutzen (v2RayTun, v2rayNG).

Die Anmeldung läuft über das Panel (interner Endpunkt `127.0.0.1:8479`). So werden gesperrte
Nutzer sofort abgewiesen, und gedrosselte Nutzer werden über ihre Client-Adresse begrenzt.

## Entwicklung

- `panel/` – Go-Backend (`internal/…`) und Svelte-Oberfläche (`panel/web`)
- Bauen: `bash panel/build.sh` → `panel/dist/vpnpanel-linux-amd64`
- Lokal testen (Trockenlauf mit Demo-Daten): `go run . serve -dev -demo -data devdata`
