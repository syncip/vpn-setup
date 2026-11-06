# vpn-setup

WireGuard-Netze (Stern, Geräte mit Netzen dahinter) und VLESS/Reality mit Webinterface:
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

## Entwicklung

- `panel/` – Go-Backend (`internal/…`) und Svelte-Oberfläche (`panel/web`)
- Bauen: `bash panel/build.sh` → `panel/dist/vpnpanel-linux-amd64`
- Lokal testen (Trockenlauf mit Demo-Daten): `go run . serve -dev -demo -data devdata`
