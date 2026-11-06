#!/usr/bin/env bash
# =====================================================================
#  VPN-Panel: WireGuard-Netze + Xray (VLESS/Reality) mit Webinterface
#  Für Debian 13 im LXC-Container hinter Proxmox-NAT (vmbr1)
#
#  Aufruf:  bash vpn-setup.sh   (mehrfach ausführbar, Daten bleiben)
#           Das Panel-Programm wird genommen, wenn es daneben liegt
#           (./vpnpanel oder ./panel/dist/vpnpanel-linux-amd64, bauen mit
#           bash panel/build.sh), sonst aus dem neuesten GitHub-Release geladen.
#
#  Alles Weitere (Server, Nutzer, Limits, Netze) im Webinterface
#  oder per Befehl:  vpn help
# =====================================================================
set -euo pipefail

### ---------- ANPASSEN ----------------------------------------------
OUT_IF="eth0"
CERT="/etc/vpn/sub-cert.pem"     # Cloudflare-Origin-Zertifikat (deckt panel. und sub. ab)
KEY="/etc/vpn/sub-key.pem"
PANEL_LISTEN="127.0.0.1:8480"    # intern, nginx verteilt per SNI von Port 443
PANEL_DIRECT="0.0.0.0:9443"      # direkter Zugang per https://IP:9443 (leer = aus)
### ------------------------------------------------------------------

[[ $EUID -eq 0 ]] || { echo "Bitte als root ausführen."; exit 1; }
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BIN=""
for f in "$HERE/vpnpanel" "$HERE/vpnpanel-linux-amd64" "$HERE/panel/dist/vpnpanel-linux-amd64"; do
  [[ -f $f ]] && { BIN=$f; break; }
done
if [[ -z $BIN ]]; then
  ARCH=$(dpkg --print-architecture)   # amd64 / arm64
  echo ">> Panel-Programm aus dem neuesten GitHub-Release laden"
  BIN=$(mktemp /tmp/vpnpanel.XXXXXX)
  curl -fL --retry 3 -o "$BIN" "${PANEL_URL:-https://github.com/syncip/vpn-setup/releases/latest/download/vpnpanel-linux-${ARCH}}" \
    || { echo "Download fehlgeschlagen (oder vpnpanel neben das Script legen)."; exit 1; }
fi

mkdir -p /etc/vpn && chmod 700 /etc/vpn

echo ">> Statistik des bisherigen Setups sichern"
if [[ -x /usr/local/bin/vpn ]]; then /usr/local/bin/vpn collect || true; fi
systemctl stop vpnpanel 2>/dev/null || true

echo ">> Pakete installieren"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  wireguard-tools iptables iproute2 qrencode curl ca-certificates openssl unzip jq nginx
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libnginx-mod-stream || true

echo ">> Forwarding aktivieren"
cat > /etc/sysctl.d/99-vpn.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.${OUT_IF}.accept_ra=2
EOF
sysctl -p /etc/sysctl.d/99-vpn.conf >/dev/null
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard

echo ">> Xray installieren/aktualisieren"
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo ">> Altes Bash-Setup abbauen (Daten bleiben für die Übernahme liegen)"
systemctl disable --now vpn-collect.timer vpn-collect-shutdown.service 2>/dev/null || true
rm -f /etc/systemd/system/vpn-collect.service /etc/systemd/system/vpn-collect.timer \
      /etc/systemd/system/vpn-collect-shutdown.service
rm -f /etc/nginx/conf.d/vpn-sub-https.conf /etc/nginx/conf.d/vpn-sub-http.conf \
      /etc/nginx/conf.d/vpn-sub-userinfo.conf /etc/nginx/stream.d/vless.conf
rm -rf /var/www/sub
[[ -L /usr/local/bin/vpn ]] || rm -f /usr/local/bin/vpn   # altes Bash-Script

echo ">> Panel installieren"
install -m 755 "$BIN" /usr/local/bin/vpnpanel
ln -sf /usr/local/bin/vpnpanel /usr/local/bin/vpn

if [[ ! -s $CERT || ! -s $KEY ]]; then
  CERT=/etc/vpn/panel-selfsigned.pem
  KEY=/etc/vpn/panel-selfsigned.key
  if [[ ! -s $CERT ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=vpnpanel" -keyout "$KEY" -out "$CERT" 2>/dev/null
  fi
  echo "!! Kein Cloudflare-Origin-Zertifikat gefunden – nutze ein selbstsigniertes."
  echo "!! Das klappt nur mit Cloudflare-SSL „Vollständig“, nicht „streng“."
fi
chmod 600 "$KEY"

cat > /etc/vpn/panel.env <<EOF
VPNPANEL_DATA=/etc/vpn
VPNPANEL_LISTEN=${PANEL_LISTEN}
VPNPANEL_CERT=${CERT}
VPNPANEL_KEY=${KEY}
VPNPANEL_PROXY=1
VPNPANEL_DIRECT=${PANEL_DIRECT}
EOF
chmod 600 /etc/vpn/panel.env

cat > /etc/systemd/system/vpnpanel.service <<'EOF'
[Unit]
Description=VPN-Panel (WireGuard, VLESS, Webinterface)
After=network-online.target nginx.service
Wants=network-online.target

[Service]
EnvironmentFile=/etc/vpn/panel.env
ExecStart=/usr/local/bin/vpnpanel serve
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
# sammelt beim Beenden noch einmal die Statistik ein
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF

echo ">> nginx vorbereiten (SNI-Verteiler schreibt das Panel nach /etc/nginx/stream.d/vpn.conf)"
mkdir -p /etc/nginx/stream.d
grep -q 'stream.d' /etc/nginx/nginx.conf || \
  printf '\nstream {\n    include /etc/nginx/stream.d/*.conf;\n}\n' >> /etc/nginx/nginx.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

echo ">> Panel starten"
systemctl daemon-reload
systemctl enable vpnpanel
systemctl restart vpnpanel
sleep 3
systemctl is-active --quiet vpnpanel || { journalctl -u vpnpanel -n 30 --no-pager; exit 1; }

echo
/usr/local/bin/vpn list || true
echo
if [[ -f /etc/vpn/panel-admin.txt ]]; then
  echo "Erste Anmeldung: Zugangsdaten stehen in /etc/vpn/panel-admin.txt"
  echo "(nach dem Anmelden Passwort ändern, 2FA einrichten und die Datei löschen)"
fi
cat <<'EOF'

Fertig. Webinterface:  https://<panel_host>  (Einstellung im Panel, Vorgabe panel.1337733.xyz)
Befehle:               vpn help
Direkter Zugang:       https://10.10.10.3:9443 (Container-IP; von außen per SSH-Tunnel
                       oder Portweiterleitung auf dem Host, siehe README)

Für Geschwindigkeitslimits auf dem Proxmox-Host (nicht im Container) einmalig:
  printf '%s\n' ifb act_connmark act_mirred sch_htb sch_ingress cls_fw cls_u32 cls_matchall \
    > /etc/modules-load.d/vpn-shaping.conf
  systemctl restart systemd-modules-load
EOF
