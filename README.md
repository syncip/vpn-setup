# vpn-setup

WireGuard-Netze (Stern, Geräte mit Netzen dahinter), VLESS/Reality und Hysteria2 mit Webinterface:
Nutzer, Tarife, Datenvolumen, Drosselung und Login mit 2FA. Für Debian 13.

## Installation

```bash
curl -fsSLO https://raw.githubusercontent.com/syncip/vpn-setup/main/vpn-setup.sh
bash vpn-setup.sh
```

Das Script lädt das Panel-Programm aus dem neuesten Release. Danach läuft das Webinterface
auf **https://<IP>:9443** (`PANEL_DIRECT` im Script), dazu der Befehl `vpn help`.

## Zugang zum Webinterface

Das Panel lauscht im Container auf Port 9443 (HTTPS). Hinter Proxmox-NAT muss der Host den Port
an den Container weiterleiten, genau wie 443 und 51820. Auf dem Host (Beispiel Container 10.10.10.3):

```bash
iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 9443 -j DNAT --to-destination 10.10.10.3:9443
```

Dauerhaft in `/etc/network/interfaces` beim Block von `vmbr1` neben den anderen Weiterleitungen:

```
post-up   iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 9443 -j DNAT --to-destination 10.10.10.3:9443
post-down iptables -t nat -D PREROUTING -i vmbr0 -p tcp --dport 9443 -j DNAT --to-destination 10.10.10.3:9443
```

Die Zertifikatswarnung im Browser ist normal (Origin- bzw. selbstsigniertes Zertifikat).
Optional geht das Panel zusätzlich über eine Domain auf Port 443 (Einstellung „Panel-Domain“).

## Hysteria2

Jeder Hysteria2-Server läuft als eigene Instanz (`vpn-hysteria@hy<ID>`), Vorgabe UDP 443.
Auf dem Proxmox-Host den UDP-Port weiterleiten und größere UDP-Puffer setzen:

```bash
iptables -t nat -A PREROUTING -i vmbr0 -p udp --dport 443 -j DNAT --to-destination 10.10.10.3:443
printf '%s\n' net.core.rmem_max=16777216 net.core.wmem_max=16777216 > /etc/sysctl.d/90-hysteria.conf && sysctl --system
```

### Port-Hopping (optional)

Unter Server → Hysteria2 → Erweitert einen UDP-Bereich eintragen, z. B. `20000-50000`. Der Client
wechselt dann regelmäßig den Zielport (hilft, wenn Anbieter einzelne UDP-Verbindungen drosseln).
Das Panel leitet den Bereich im Container auf den Hysteria-Port um; auf dem Proxmox-Host muss der
Bereich an den Container gehen:

```bash
iptables  -t nat -A PREROUTING -i vmbr0 -p udp --dport 20000:50000 -j DNAT --to-destination 10.10.10.3
ip6tables -t nat -A PREROUTING -i vmbr0 -d 2001:41d0:203:4a76::10 -p udp --dport 20000:50000 -j DNAT --to-destination fd10:10:10::3
```

Links bekommen `mport=20000-50000` (Hiddify, NekoBox, v2rayN). Apps ohne Unterstützung nutzen
weiter den normalen Port.

Die Anmeldung läuft über das Panel (interner Endpunkt `127.0.0.1:8479`). So werden gesperrte
Nutzer sofort abgewiesen, und gedrosselte Nutzer werden über ihre Client-Adresse begrenzt.

## Entwicklung

- `panel/` – Go-Backend (`internal/…`) und Svelte-Oberfläche (`panel/web`)
- Bauen: `bash panel/build.sh` → `panel/dist/vpnpanel-linux-amd64`
- Lokal testen (Trockenlauf mit Demo-Daten): `go run . serve -dev -demo -data devdata`
