#!/usr/bin/env bash
# =====================================================================
#  VPN-Panel: WireGuard, VLESS/Reality und Hysteria2 mit Webinterface
#  Für Debian 13 (Server, VPS oder Container)
#
#  Aufruf:  bash vpn-setup.sh          (mehrfach ausführbar, Daten bleiben)
#           bash vpn-setup.sh --neu    Domains erneut abfragen
#  Ohne Rückfragen:  SERVER_HOST=vpn.example.org SUB_HOST=sub.example.org #                    PANEL_HOST=panel.example.org bash vpn-setup.sh
#  Beim ersten Start fragt das Script nach den Domains; die ausgehende
#  Schnittstelle erkennt es selbst (überschreiben mit OUT_IF=…).
#           Das Panel-Programm wird genommen, wenn es daneben liegt
#           (./vpnpanel oder ./panel/dist/vpnpanel-linux-amd64, bauen mit
#           bash panel/build.sh), sonst aus dem neuesten GitHub-Release geladen.
#
#  Alles Weitere (Server, Nutzer, Limits, Netze) im Webinterface
#  oder per Befehl:  vpn help
# =====================================================================
set -euo pipefail

### ---------- ANPASSEN ----------------------------------------------
CERT="/etc/vpn/sub-cert.pem"     # Cloudflare-Origin-Zertifikat (deckt panel. und sub. ab)
KEY="/etc/vpn/sub-key.pem"
PANEL_DIRECT="0.0.0.0:9443"      # Webinterface: https://<IP>:9443
PANEL_LISTEN="127.0.0.1:8480"    # intern für nginx (Abo-Links über sub.-Domain, optional Panel-Domain)
### ------------------------------------------------------------------

[[ $EUID -eq 0 ]] || { echo "Bitte als root ausführen."; exit 1; }
RECONF=0
for a in "$@"; do
  case $a in
    --neu|--config|--reconfigure) RECONF=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $a"; exit 1 ;;
  esac
done
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
chmod 755 "$BIN"

### ---------- Domains und Schnittstelle --------------------------------
host_ok() { [[ $1 =~ ^[A-Za-z0-9.-]*$ ]]; }
ask() { # ask <variable> <frage> <vorgabe>
  local ans=""
  while :; do
    read -r -p "$2${3:+ [$3]}: " ans </dev/tty || ans=""
    ans=${ans:-$3}
    [[ $ans == "-" ]] && ans=""      # „-“ = Feld leeren
    host_ok "$ans" && break
    echo "   Nur Buchstaben, Ziffern, Punkt und Bindestrich (ohne https://)."
  done
  printf -v "$1" '%s' "$ans"
}
legacy_env() { [[ -f /etc/vpn/vpn.env ]] && sed -n "s/^$1=[\"']\{0,1\}\([^\"']*\).*/\1/p" /etc/vpn/vpn.env | head -1 || true; }

FIRST=1
CUR_SERVER=""; CUR_SUB=""; CUR_PANEL=""; CUR_IF=""
if [[ -s /etc/vpn/panel.db ]]; then
  FIRST=0
  CUR_SERVER=$("$BIN" config server_host 2>/dev/null || true)
  CUR_SUB=$("$BIN" config sub_host 2>/dev/null || true)
  CUR_PANEL=$("$BIN" config panel_host 2>/dev/null || true)
  CUR_IF=$("$BIN" config out_interface 2>/dev/null || true)
elif [[ -f /etc/vpn/users.json ]]; then   # altes Bash-Setup, wird beim ersten Start übernommen
  FIRST=0
  CUR_SERVER=$(legacy_env SERVER_HOST); CUR_SUB=$(legacy_env SUB_HOST); CUR_IF=$(legacy_env OUT_IF)
fi

# Ältere Panel-Versionen kennen „config“ nicht und geben dann den Hilfetext aus → verwerfen
host_ok "$CUR_SERVER" || CUR_SERVER=""; host_ok "$CUR_SUB" || CUR_SUB=""; host_ok "$CUR_PANEL" || CUR_PANEL=""
[[ $CUR_IF =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || CUR_IF=""

DETECTED_IF=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
OUT_IF=${OUT_IF:-${CUR_IF:-${DETECTED_IF:-eth0}}}
ip link show "$OUT_IF" >/dev/null 2>&1 || { echo "Schnittstelle $OUT_IF gibt es nicht (OUT_IF=… setzen)."; exit 1; }

SERVER_HOST=${SERVER_HOST-$CUR_SERVER}
SUB_HOST=${SUB_HOST-$CUR_SUB}
PANEL_HOST=${PANEL_HOST-$CUR_PANEL}

if (( RECONF || FIRST )) || [[ -z $SERVER_HOST ]]; then
  if ! { : </dev/tty; } 2>/dev/null; then
    [[ -n $SERVER_HOST ]] || { echo "Keine Eingabe möglich: SERVER_HOST=<domain oder IP> bash vpn-setup.sh"; exit 1; }
  else
    PUBIP=$(curl -4 -fsS --max-time 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' || true)
    cat <<EOF

==================== Einrichtung ====================
Server-Adresse: Domain mit A-/AAAA-Eintrag auf diesen Server (OHNE Cloudflare-Proxy,
                graue Wolke) oder die öffentliche IP. Steht in allen Links und Configs.
Abo-Domain:     optional, z. B. sub.example.org über Cloudflare-Proxy (orange Wolke).
                Leer = Abo-Links über die Panel-Domain bzw. https://<IP>:9443/sub/…
Panel-Domain:   optional, z. B. panel.example.org über Cloudflare-Proxy.
                Leer = Webinterface nur über https://<IP>:9443
Ausgehende Schnittstelle: ${OUT_IF} (erkannt)
„-“ leert ein Feld.

EOF
    while :; do
      ask SERVER_HOST "Server-Adresse" "${SERVER_HOST:-$PUBIP}"
      [[ -n $SERVER_HOST ]] || { echo "   Die Server-Adresse wird gebraucht."; continue; }
      ask SUB_HOST "Abo-Domain (optional)" "$SUB_HOST"
      ask PANEL_HOST "Panel-Domain (optional)" "$PANEL_HOST"
      printf '
  Server-Adresse: %s
  Abo-Domain:     %s
  Panel-Domain:   %s
  Schnittstelle:  %s
'         "$SERVER_HOST" "${SUB_HOST:-–}" "${PANEL_HOST:-–}" "$OUT_IF"
      read -r -p "Passt das? [J/n] " ok </dev/tty || ok=""
      [[ ${ok,,} == n* ]] || break
    done
  fi
fi
for h in "$SERVER_HOST" "$SUB_HOST" "$PANEL_HOST"; do
  host_ok "$h" || { echo "Ungültiger Hostname: $h"; exit 1; }
done
### ------------------------------------------------------------------

mkdir -p /etc/vpn && chmod 700 /etc/vpn

echo ">> Statistik des bisherigen Setups sichern"
if [[ -x /usr/local/bin/vpn ]]; then /usr/local/bin/vpn collect || true; fi
systemctl stop vpnpanel 2>/dev/null || true

echo ">> Pakete installieren"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  wireguard-tools iptables iproute2 qrencode curl ca-certificates openssl unzip jq nginx openvpn   iputils-ping conntrack nftables
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libnginx-mod-stream || true
# Unbound: wahlweise Auflösung für den Panel-DNS (DNS → Einstellungen). Das Panel schreibt die
# Konfiguration selbst (127.0.0.1:5335) und startet den Dienst nur, wenn Unbound gewählt ist.
# dns-root-data liefert den DNSSEC-Vertrauensanker (ohne ihn startet Unbound nicht).
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unbound dns-root-data || true
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unbound-anchor || true
if [[ -f /usr/share/dns/root.key && -d /var/lib/unbound && ! -f /var/lib/unbound/root.key ]]; then
  install -o unbound -g unbound -m 644 /usr/share/dns/root.key /var/lib/unbound/root.key
fi
if [[ ! -f /etc/unbound/unbound.conf.d/vpnpanel.conf ]]; then systemctl disable --now unbound 2>/dev/null || true; fi

echo ">> Forwarding aktivieren"
cat > /etc/sysctl.d/99-vpn.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.${OUT_IF}.accept_ra=2
EOF
sysctl -p /etc/sysctl.d/99-vpn.conf >/dev/null
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
# OpenVPN: eigene Instanzen des Panels (vpn-openvpn@ovpn<ID>), Debians Vorlagen bleiben ungenutzt
mkdir -p /etc/openvpn/vpn && chmod 755 /etc/openvpn/vpn  # OpenVPN liest das ccd-Verzeichnis als „nobody“
# Ausgänge (externe VPNs für Proxy/Gruppen): bereinigte Konfigurationen mit Zugangsdaten
mkdir -p /etc/vpn/exits && chmod 700 /etc/vpn/exits

# Installer erst herunterladen, dann ausführen – bei bash -c "$(curl …)" würde ein
# fehlgeschlagener Download trotz set -e unbemerkt durchrutschen.
run_installer() {
  local url=$1; shift
  local f; f=$(mktemp /tmp/vpn-installer.XXXXXX)
  curl -fsSL --retry 3 -o "$f" "$url" || { rm -f "$f"; echo "Download fehlgeschlagen: $url"; exit 1; }
  bash "$f" "$@"
  rm -f "$f"
}

echo ">> Xray installieren/aktualisieren"
run_installer https://github.com/XTLS/Xray-install/raw/main/install-release.sh install

echo ">> Hysteria2 installieren/aktualisieren"
# offizielles Installationsscript; die Instanzen startet das Panel selbst (vpn-hysteria@<name>)
run_installer https://get.hy2.sh/
[[ -x /usr/local/bin/hysteria ]] || { echo "Hysteria wurde nicht installiert."; exit 1; }
systemctl disable --now hysteria-server.service 2>/dev/null || true
mkdir -p /etc/hysteria
# laufende Instanzen auf die neue Version bringen
systemctl try-restart 'vpn-hysteria@*' 2>/dev/null || true

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

# Geheimnisse, die nicht in die Datenbank gehören (z. B. Cloudflare-API-Token für das DoH/DoT-Zertifikat).
# Wird nie überschrieben; das Panel liest die Datei bei Bedarf.
if [[ ! -f /etc/vpn/secrets.env ]]; then
  cat > /etc/vpn/secrets.env <<'EOF'
# Cloudflare-API-Token (Recht „Zone → DNS → Bearbeiten“) für das Let's-Encrypt-Zertifikat von DoH/DoT:
# CF_API_TOKEN=
EOF
fi
chmod 600 /etc/vpn/secrets.env

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

echo ">> Einstellungen speichern"
/usr/local/bin/vpn config -n "server_host=${SERVER_HOST}" "sub_host=${SUB_HOST}"   "panel_host=${PANEL_HOST}" "out_interface=${OUT_IF}" >/dev/null

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
IP4=$(ip -o -4 addr show dev "$OUT_IF" 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1)
echo
echo "Fertig. Webinterface:  https://${PANEL_HOST:-${SERVER_HOST}:9443}"
[[ -n $PANEL_HOST ]] && echo "                       https://${SERVER_HOST}:9443 (direkt)"
echo "Befehle:               vpn help   (Domains ändern: vpn config, oder bash vpn-setup.sh --neu)"
cat <<EOF

Nach außen offen sein müssen: TCP 443 und 9443, UDP 51820 (WireGuard) und UDP 443
(Hysteria2, bei Port-Hopping zusätzlich der eingestellte UDP-Bereich), für OpenVPN-Server
deren Port (Vorgabe UDP 1194). Die Liste je Server steht im Panel unter „Server“.
EOF
[[ -c /dev/net/tun ]] || echo "Hinweis: /dev/net/tun fehlt – OpenVPN-Server können so nicht starten (siehe unten)."
if systemd-detect-virt -c -q 2>/dev/null; then
cat <<EOF

Container erkannt (interne Adresse ${IP4:-?}). Auf dem Host (z. B. Proxmox) einmalig:
  - Ports per DNAT an ${IP4:-den Container} weiterleiten, z. B.:
      iptables -t nat -A PREROUTING -i vmbr0 -p udp --dport 443 -j DNAT --to-destination ${IP4:-<container-ip>}:443
    (genauso TCP 443, TCP 9443, UDP 51820)
  - Kernelmodule für WireGuard und Geschwindigkeitslimits:
      printf '%s\n' wireguard ifb act_connmark act_mirred sch_htb sch_ingress cls_fw cls_u32 cls_matchall \
        > /etc/modules-load.d/vpn.conf
      systemctl restart systemd-modules-load
  - für OpenVPN das Gerät /dev/net/tun freigeben (Proxmox: /etc/pve/lxc/<ID>.conf, danach Container neu starten):
      lxc.cgroup2.devices.allow: c 10:200 rwm
      lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
  - größere UDP-Puffer für Hysteria2 (im Container nicht einstellbar):
      printf '%s\n' net.core.rmem_max=16777216 net.core.wmem_max=16777216 > /etc/sysctl.d/90-hysteria.conf
      sysctl --system
EOF
else
  printf '%s\n' net.core.rmem_max=16777216 net.core.wmem_max=16777216 > /etc/sysctl.d/90-hysteria.conf
  sysctl --system >/dev/null 2>&1 || true
fi
