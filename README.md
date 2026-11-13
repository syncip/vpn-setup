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

Die Seite **Proxy & Ausgänge** hat Reiter: **Übersicht** (Ziel-Regeln → Gruppen → Ausgänge mit Zahlen,
Störungen und dem aktiven Ausgang je Gruppe), **Ausgänge**, **Gruppen**, **Ziel-Regeln** und **Proxy-Server**.

Menü **Proxy & Ausgänge**: SOCKS5- und HTTP-Proxy mit Benutzername und Passwort, z. B. für Fernseher und Apps.
Der Verkehr läuft direkt über den Server oder über eine **Ausgangsgruppe** – also über externe
VPN-Verbindungen, deren WireGuard- oder OpenVPN-Konfiguration (z. B. vom VPN-Anbieter) hochgeladen wird.

- **Ausgänge:** Hochgeladene Konfigurationen werden bereinigt: übernommen werden nur Schlüssel, Adresse,
  Gegenstelle und Verschlüsselung. Skripte (`PostUp`, `up`/`down`), Routen, DNS-Änderungen,
  `redirect-gateway`, Plugins und Verweise auf fremde Dateien fallen weg (die Oberfläche zeigt, was
  entfernt wurde). Jeder Ausgang bekommt eine Schnittstelle `ex<ID>` ohne Route in der Haupttabelle –
  der Server selbst bleibt unverändert erreichbar. Eingehende Verbindungen über einen Ausgang werden
  verworfen, TCP-MSS wird angepasst. Nur IPv4.
- **Verbindung je Ausgang:** *Immer verbunden* (Vorgabe, Prüfung alle 30 Sekunden, Umschalten sofort)
  oder *Bereitschaft*: verbunden nur, solange eine Gruppe den Ausgang gerade nutzt. Sonst verbindet der
  Server ihn im gewählten Abstand (5 Minuten bis täglich) kurz, prüft ihn und trennt wieder – sinnvoll,
  wenn der Anbieter viele dauerhafte Verbindungen ungern sieht. Fällt der aktive Ausgang einer Gruppe aus,
  werden Ausgänge in Bereitschaft der Reihe nach verbunden und geprüft, bevor umgeschaltet wird (dauert
  einige Sekunden länger).
- **Ping und Speedtest von Hand:** Knöpfe je Ausgang; ein Ausgang in Bereitschaft wird dafür kurz verbunden.
- **Verkehr je Ausgang:** gezählt an der Schnittstelle `ex<ID>` (stündlich gespeichert), in der Tabelle
  24 Stunden / 30 Tage, darunter ein Diagramm über 24 h bis 90 Tage, gesamt oder je Ausgang.
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

- **Domains bei WireGuard/OpenVPN:** Der Kernel sieht nur Adressen. Die DNS-Anfragen der Geräte laufen
  deshalb über den Panel-DNS (siehe „DNS“), der die Adressen der passenden Namen lernt (24 Stunden) –
  unabhängig davon, welcher DNS-Server im Gerät eingetragen ist, auch bei DNS über IPv6. Für Namen aus
  Regeln gibt er keine IPv6-Adressen heraus, damit das Gerät IPv4 nimmt (nur das kann über Ausgänge laufen).
  DNS über TLS (Port 853) wird für diese Geräte abgewiesen, und die Namen bekannter DoH-Server
  (Cloudflare, Google, Quad9 …) gibt es für sie nicht – Browser, die DoH von selbst einschalten
  (Chrome, Firefox in der Standardeinstellung), fallen so auf normales DNS zurück. Wer DoH oder ein
  „Privates DNS“ mit festem Anbieter ausdrücklich erzwingt, muss es ausschalten oder Netze/Listen verwenden.
  Hat das Gerät den Namen schon vor dem Anlegen der Regel aufgelöst, greift sie erst, wenn dessen
  DNS-Zwischenspeicher abläuft (meist Minuten; VPN kurz trennen und neu verbinden hilft).
- **IPv6:** Ausgänge können nur IPv4. Läuft bei einem Gerät *alles* über eine Gruppe, wird IPv6 ins
  Internet für dieses Gerät gesperrt (sonst ginge es am Ausgang vorbei); für Domains aus Regeln gibt es
  keine IPv6-Adressen. Ziellisten und Netze zählen nur mit ihren IPv4-Einträgen.
- **Private Ziele** (andere VPN-Geräte, Heimnetze hinter Geräten, der Server selbst) laufen nie über Ausgänge.
- **Drosselung:** Tempo-Limits von VLESS-Nutzern wirken nicht für Verkehr, der über Ausgänge läuft.
- Fällt die Gruppe aus, gilt ihre Einstellung „sperren“ oder „direkt“ wie beim Proxy.

## Netzwerk-Übersicht

Menü **Netzwerk** → **Übersicht**: eine Karte über alle Server und Protokolle – links Nutzer und Geräte,
dann die Server, die Ausgänge („Direkt“ und die Ausgangsgruppen mit ihren Ausgängen) und das Internet.

- **Verkehr:** Linien zeigen, wer verbunden ist; fließt gerade Verkehr, bewegen sie sich und werden mit
  der Menge dicker (alle 2 Sekunden aktualisiert). An Geräten, Servern, Gruppen und Ausgängen steht die
  aktuelle Geschwindigkeit – bei Ausgängen aus den Zählern der Schnittstelle, also der tatsächliche Durchsatz.
- **Wo hakt es?** Über der Karte stehen Auffälligkeiten: Server, die nicht laufen, Fehler beim Anwenden,
  gestörte Ausgänge, Gruppen im Ausweich- oder Sperrzustand, Ziel-Regeln, die nicht wirken, fehlgeschlagene
  Online-Listen sowie gesperrte, abgelaufene und gedrosselte Nutzer.
- **Anklicken** eines Geräts, Nutzers, Servers oder einer Gruppe hebt dessen Weg hervor und zeigt Einzelheiten
  (Weg nach außen samt der Ebene der Regel, bei WireGuard auch, welche Geräte es erreichen darf).
- **Ziehen – Ausgang zuweisen:** Gerät, Nutzer oder Server auf eine Gruppe ziehen → der ganze Verkehr läuft
  darüber; auf „Direkt“ ziehen → wieder direkt über den Server. Dahinter steht eine „alles“-Ziel-Regel der
  jeweiligen Ebene (ersetzt die bisherige; Regeln für bestimmte Ziele bleiben). Erbt das Gerät sonst eine
  weiter gefasste Regel, entsteht beim Ziehen auf „Direkt“ eine Ausnahme. Alles lässt sich danach unter
  „Proxy & Ausgänge“ → Ziel-Regeln ansehen und ändern. Hysteria2-Geräte lassen sich nicht einzeln zuweisen
  (den Server ziehen).
- **Ziehen – Zugriff:** Ein WireGuard-Gerät auf ein anderes Gerät desselben Servers ziehen erlaubt den
  Zugriff bzw. entzieht ihn, wenn er schon besteht. Der Zugriff des Geräts wird dabei auf „Ausgewählte
  Geräte“ umgestellt (bisher erreichbare Geräte bleiben erreichbar). Vor jeder Änderung fragt die Seite nach.

Die Reiter daneben zeigen je WireGuard-Server die Geräte (nach Nutzer gruppiert, mit Filter und Suche),
die Sternkarte und die Zugriffsmatrix (bis 40 Geräte).

### Zugriff zwischen Netzen

**Netzwerk** → **Zugriff**: Die Netze der WireGuard-Server sind voneinander getrennt. Eine **Freigabe**
erlaubt Nutzern, Tarifen oder einzelnen Geräten (WireGuard, OpenVPN, VLESS) den Zugriff auf ein anderes
WireGuard-Netz samt der Netze hinter dessen Geräten (z. B. Homelab). Das Panel ergänzt dafür die
Firewall, NAT auf dem Ziel-Netz, bei Split-Tunnel die AllowedIPs bzw. die OpenVPN-Routen und bei VLESS
die Xray-Regeln. Hysteria2 und Proxy können Nutzer nicht einzeln leiten – für sie wirken Freigaben nicht.

### Lokale Netze für VPN-Nutzer gesperrt

**Einstellungen** → **Sicherheit**: VPN-Nutzer erreichen private Adressen (10/8, 172.16/12, 192.168/16,
100.64/10, Loopback, fc00::/7 …) und die eigene Server-Adresse nicht – weder über WireGuard/OpenVPN
(Firewall) noch über VLESS (Xray), Hysteria2 (ACL) oder den Proxy. So bleibt z. B. das interne Netz des
Proxmox-Hosts geschützt. Ausnahmen (Netze, eine pro Zeile) lassen sich eintragen; Freigaben unter
„Zugriff“ gehen vor. Abschalten geht, ist aber nicht empfohlen. **Loopback** (127.0.0.0/8, ::1) bleibt
für VLESS und Hysteria2 auch dann gesperrt und lässt sich nicht als Ausnahme eintragen – dort laufen die
internen Dienste des Servers (Panel, Xray-API, Anmelde-Endpunkt).

Weitere Schutzmaßnahmen: DNS über TCP und DoT begrenzen gleichzeitige Verbindungen (insgesamt und je
Adresse); ein Fehler in einer einzelnen DNS-, DoT-, SmartDNS- oder Proxy-Verbindung wird abgefangen und
im Ereignisprotokoll gemeldet, statt das Panel zu beenden. Der Test `inject_test.go` belegt jedes
Eingabefeld aller Protokolle mit präparierten Werten und prüft, dass nichts als eigene Zeile oder
Befehlsargument in erzeugte Konfigurationen gelangt.

## DNS (Panel-DNS, Werbefilter)

Menü **DNS**: Das Panel ist DNS-Server für alle WireGuard- und OpenVPN-Geräte. Die Firewall leitet ihre
DNS-Anfragen (Port 53, IPv4 und IPv6) an das Panel, egal welcher DNS-Server im Gerät steht. Neue Configs
nennen gleich die Tunneladresse des Servers (DNS-Einstellung „auto“, Vorgabe; die frühere Vorgabe
„1.1.1.1, 2606:4700:4700::1111“ gilt ebenso als „auto“). Wichtig: Steht im Gerät ein öffentlicher
DNS-Server wie 1.1.1.1 oder 8.8.8.8, schalten Chrome, Brave & Co. gern selbst auf verschlüsseltes DNS
um – deshalb nach dem Update die Config neu laden.

- **Filterprofile** fassen Blocklisten und eigene Regeln zusammen und gelten für alle Geräte, einen
  Server, einen Nutzer oder ein Gerät (Rangfolge wie bei Ziel-Regeln). Eigene Regeln, eine pro Zeile:
  `werbung.de` sperrt (samt Unterdomains), `allow cdn.beispiel.de` gibt frei (geht vor Listen),
  `nas.home = 192.168.1.10` liefert eine eigene Antwort. Gesperrte Namen bekommen 0.0.0.0 bzw. ::
  (oder wahlweise „gibt es nicht“).
- **Blocklisten:** eigene Domains und/oder Online-Listen mit Aktualisierung (Hosts-Dateien,
  Adblock-Format `||domain^` mit Ausnahmen `@@`, eine Domain pro Zeile; bis 1 Mio. Einträge). Bekannte
  Listen (HaGeZi, OISD, AdGuard, StevenBlack) lassen sich mit einem Klick hinzufügen.
- **Verschlüsseltes DNS sperren** (je Profil, für Geräte mit Domain-Regeln immer): DNS über TLS
  (Port 853), DoH per Adresse (1.1.1.1, 8.8.8.8, 9.9.9.9 …) und die Namen bekannter DoH-Server werden
  abgewiesen. Browser in der Einstellung „automatisch“ fallen auf normales DNS zurück; ist dagegen ein
  fester Anbieter erzwungen (z. B. Brave „Sicheres DNS: Cloudflare“, Android „Privates DNS“ mit
  Hostname), lädt keine Seite mehr – dort auf „automatisch“ bzw. „aus“ stellen.
- **Protokoll** (Aufbewahrung einstellbar, Vorgabe 7 Tage, 0 = aus): jede Anfrage mit Gerät, Domain,
  Ergebnis und Weg; Suche und Filter, Sperren/Freigeben mit einem Klick. Die **Übersicht** zeigt
  Anfragen je Stunde, Anteil gesperrt, häufigste und gesperrte Domains, Geräte und „Domain prüfen“.
- Die **Übersicht** zeigt außerdem: verschiedene Domains und Geräte, Antwortzeit (Median/95 %),
  Anteil „gibt es nicht“ und Fehler, Abfragetypen, Sperrgründe, Weg (direkt/Gruppe), häufige Namen ohne
  Antwort und die Geräte mit den meisten Sperren. Die Karte „So wird gefiltert“ zeigt, welches Profil für
  wen gilt und welche Listen in keinem Profil stecken (eine Liste wirkt nur in einem aktiven Profil).
- **Zwischenspeicher** (Einstellungen): Größe, Mindest- und Höchstdauer und Domains, die nie gespeichert
  werden. **Verteilung** auf die DNS-Server: Reihenfolge, schnellster (laufend gemessen), reihum oder
  parallel.
- **Auflösung:** über öffentliche DNS-Server oder **Unbound** (läuft im Container, löst selbst rekursiv
  auf, 127.0.0.1:5335; das Setup-Script installiert das Paket, das Panel schreibt die Konfiguration und
  startet den Dienst nur, wenn Unbound gewählt ist). Antwortet Unbound nicht, springen die eingestellten
  DNS-Server ein; eine Selbstprüfung überspringt einen ausgefallenen Unbound sofort und versucht alle
  5 Minuten, ihn zu reparieren.
- **Unbound je Ausgangsgruppe:** Mit Unbound bekommt jede aktive Ausgangsgruppe eine eigene Instanz
  (`vpn-unbound@g<ID>`, 127.0.0.1:5400+Slot, eigener Systembenutzer `vpnub<ID>`). Sie fragt die
  Nameserver **über den Ausgang der Gruppe** – Geräte mit Ausgangsgruppe (ganzer Verkehr oder Ziel-Regel/
  SmartDNS) bekommen so Antworten passend zum Land des Ausgangs, und kein DNS dieser Geräte verlässt den
  Server direkt. Eine Routing-Regel für den Instanz-Benutzer (`ip rule … uidrange … lookup <Gruppe>`)
  legt den Weg schon beim Senden fest (Absender = Adresse am Tunnel). Dahinter steht als **Kill-Switch**
  eine Sperr-Regel (`uidrange … blackhole`, IPv4 und IPv6): Fehlt die Regel der Gruppe oder ist ihre
  Tabelle leer, endet die Anfrage dort statt direkt im Internet; IPv6 ist immer gesperrt, Loopback bleibt
  frei. Bewusst keine Firewall-Regel nach Benutzer – WireGuard behält beim Verpacken den Benutzer der
  Instanz, eine solche Regel verwürfe auch die Tunnelpakete des Ausgangs (Fehler bis v0.14.2). Die Instanzen
  startet nur das Panel, nachdem diese Regeln geladen sind (der Dienst verweigert ohne sie den Start, kein
  Autostart beim Booten); lassen sich die Regeln nicht laden, hält das Panel sie an. Fällt eine Instanz aus,
  springen die DNS-Server der Gruppe ein (ebenfalls über den Ausgang). Geprüft im Labortest
  `unbound_lab_test.go` (Netzwerk-Namespaces, als root).
- **DNS-Speedtest:** misst die Server einer bearbeitbaren Liste (hinzufügen/entfernen, eingebaute Liste
  wiederherstellen) plus die eingestellten Server und Unbound – bekannte Namen und neue (zufällige)
  Namen getrennt. **Automatische Wahl** (abschaltbar): misst regelmäßig (stündlich bis wöchentlich) und
  übernimmt die schnellsten 1–4 Server; gewechselt wird nur bei mindestens 15 % Vorteil oder wenn ein
  Server nicht zuverlässig antwortet. Jeder Wechsel steht im Ereignisprotokoll.
- **Ohne VPN** (Fernseher, Konsole, Router zu Hause): „DNS von außen“ leitet Port 53 der
  Außenschnittstelle an den Panel-DNS. Antworten bekommen nur **freigegebene Geräte** (IP-Adressen,
  Netze oder DynDNS-Namen, die alle 5 Minuten neu aufgelöst werden), jeweils mit eigenem Filterprofil.
  Alle anderen Anfragen werden verworfen. **„Wer fragt von außen?“** listet jeden Absender als
  *freigegeben* oder *gesperrt* mit IP, Hostname (Rückwärtsauflösung), Land, Anzahl und Weg (Port 53 an
  die Server-IP, DoH oder DoT – mit oder ohne Kennung); ein Klick auf die Zeile zeigt alle angefragten
  Domains (bis 500 je freigegebenem, 50 je gesperrtem Absender) – so sieht man, ob das eigene Gerät
  ankommt oder Fremde es versuchen; mit einem Klick freigeben. Das Land kommt aus den öffentlichen
  Vergabelisten der fünf Regional-Registries (RIPE, ARIN, APNIC, LACNIC, AFRINIC), die das Panel wöchentlich
  lädt und lokal auswertet – keine IP geht an einen fremden Dienst. Im DNS-Protokoll steht bei Geräten ohne
  VPN die zugreifende IP und der Weg. Ein offener DNS-Server für alle wird bewusst nicht angeboten (DNS-Verstärkungsangriffe).
  Auf dem Proxmox-Host UDP und TCP 53 an den Container weiterleiten (die Seite zeigt die Befehle,
  mit der internen IPv6 des Containers und der öffentlichen IPv6 aus der Server-Adresse).
- **DoH und DoT** (Reiter „Ohne VPN“): Jedes freigegebene Gerät bekommt eine Kennung und damit eigene
  Adressen – `https://<kennung>.dns.example.org/dns-query` (Browser, iOS, Router) und
  `<kennung>.dns.example.org` (Android „Privates DNS“, Port 853). Das funktioniert von jedem Netz aus,
  ohne feste IP; feste Adressen sind dann optional. Mit **Adresse merken** darf die Adresse, von der ein
  Gerät per DoH/DoT fragt, 24 Stunden lang auch normales DNS nutzen (z. B. der Fernseher im selben
  Heimnetz). DoH läuft über nginx auf Port 443, DoT direkt am Panel (TCP 853 auf dem Host weiterleiten).
  Das **Zertifikat** für `dns.example.org` und `*.dns.example.org` holt das Panel bei Let's Encrypt über
  die DNS-Prüfung mit der Cloudflare-API und erneuert es 30 Tage vor Ablauf; fehlende A-/AAAA-Einträge
  (ohne Cloudflare-Proxy) legt es an. Das API-Token (Recht „Zone → DNS → Bearbeiten“) lässt sich direkt in
  der DoH/DoT-Karte eintragen, prüfen und entfernen. Es steht nur auf dem Server in `/etc/vpn/secrets.env`
  (`CF_API_TOKEN=…`, Rechte 600) – nicht in der Datenbank – und wird in der Oberfläche nie wieder angezeigt.
- **SmartDNS** (je Filterprofil): Domains wie `netflix.com` laufen über eine Ausgangsgruppe (Vorlagen für
  Netflix, Disney+, Prime Video, Max, BBC iPlayer u. a.). Für VPN-Geräte wirkt das wie eine Ziel-Regel.
  Geräte ohne VPN (Port 53, DoH, DoT) bekommen für diese Namen die Adresse des Servers; nginx reicht die
  HTTPS-Verbindungen anhand des Namens an das Panel, das sie über die Gruppe weiterleitet (Ende-zu-Ende
  verschlüsselt, nur Port 443 – HTTP und QUIC nicht). Die Seite zeigt Verbindungen und Fehler je Domain.
- **Live** (Übersicht): Anfragen je Sekunde der letzten 1–10 Minuten (beantwortet, Speicher, gesperrt),
  aktive Geräte, Antwortzeit und welcher DNS-Server bzw. Unbound wie oft geantwortet hat. Das Protokoll
  vermerkt den antwortenden Server je Anfrage; die Übersicht zeigt die Anteile je Zeitraum.
- VLESS, Hysteria2 und Proxy nutzen den Panel-DNS (noch) nicht.

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
