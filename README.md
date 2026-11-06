# vpn-setup

WireGuard-Netze (Stern, Geräte mit Netzen dahinter) und VLESS/Reality mit Webinterface:
Nutzer, Tarife, Datenvolumen, Drosselung und Login mit 2FA. Für Debian 13.

## Installation

```bash
curl -fsSLO https://raw.githubusercontent.com/syncip/vpn-setup/main/vpn-setup.sh
bash vpn-setup.sh
```

Das Script lädt das Panel-Programm aus dem neuesten Release. Danach gibt es das Webinterface
unter der eingestellten Panel-Domain und den Befehl `vpn help`.

## Entwicklung

- `panel/` – Go-Backend (`internal/…`) und Svelte-Oberfläche (`panel/web`)
- Bauen: `bash panel/build.sh` → `panel/dist/vpnpanel-linux-amd64`
- Lokal testen (Trockenlauf mit Demo-Daten): `go run . serve -dev -demo -data devdata`
