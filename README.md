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

## Zugang zum Webinterface

- Über die Panel-Domain (Cloudflare → nginx auf 443 → Panel)
- Direkt per IP auf Port **9443** (`PANEL_DIRECT` im Script). Der Port ist nur im Container offen.
  Von außen am sichersten per SSH-Tunnel über den Proxmox-Host:

  ```bash
  ssh -L 9443:10.10.10.3:9443 root@<host>
  ```

  Dann im Browser `https://localhost:9443` öffnen. Die Zertifikatswarnung ist normal
  (das Cloudflare-Origin-Zertifikat kennt der Browser nicht).

## Entwicklung

- `panel/` – Go-Backend (`internal/…`) und Svelte-Oberfläche (`panel/web`)
- Bauen: `bash panel/build.sh` → `panel/dist/vpnpanel-linux-amd64`
- Lokal testen (Trockenlauf mit Demo-Daten): `go run . serve -dev -demo -data devdata`
