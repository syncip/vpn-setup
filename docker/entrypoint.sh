#!/bin/bash
# Start des Containers: Datenverzeichnis, Zertifikat und panel.env vorbereiten, Einstellungen aus den
# Umgebungsvariablen übernehmen, dann systemd starten (das startet nginx und vpnpanel).
set -euo pipefail

DATA=/etc/vpn
mkdir -p "$DATA" "$DATA/exits"
chmod 700 "$DATA" "$DATA/exits"
export VPNPANEL_DATA=$DATA VPNPANEL_DOCKER=1

# Zertifikat für Webinterface und Abo: eigenes (TLS_CERT/TLS_KEY), Cloudflare-Origin im Datenordner, sonst selbstsigniert
CERT=${TLS_CERT:-$DATA/sub-cert.pem}
KEY=${TLS_KEY:-$DATA/sub-key.pem}
if [[ ! -s $CERT || ! -s $KEY ]]; then
  CERT=$DATA/panel-selfsigned.pem
  KEY=$DATA/panel-selfsigned.key
  if [[ ! -s $CERT || ! -s $KEY ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=vpnpanel" -keyout "$KEY" -out "$CERT" 2>/dev/null
    echo "Kein eigenes Zertifikat gefunden – nutze ein selbstsigniertes ($CERT)."
  fi
fi
chmod 600 "$KEY"

cat > "$DATA/panel.env" <<EOT
VPNPANEL_DATA=$DATA
VPNPANEL_LISTEN=${PANEL_LISTEN:-127.0.0.1:8480}
VPNPANEL_CERT=$CERT
VPNPANEL_KEY=$KEY
VPNPANEL_PROXY=1
VPNPANEL_DIRECT=${PANEL_DIRECT:-0.0.0.0:9443}
VPNPANEL_DOCKER=1
EOT
chmod 600 "$DATA/panel.env"

# Geheimnisse, die nicht in die Datenbank gehören – wird nie überschrieben
if [[ ! -f $DATA/secrets.env ]]; then
  cat > "$DATA/secrets.env" <<'EOT'
# Cloudflare-API-Token (Recht „Zone → DNS → Bearbeiten“) für das Let's-Encrypt-Zertifikat von DoH/DoT:
# CF_API_TOKEN=
# Passwort für den Mailversand (SMTP):
# SMTP_PASSWORD=
EOT
fi
chmod 600 "$DATA/secrets.env"

# Zeitzone (systemd gibt TZ nicht an die Dienste weiter)
if [[ -n ${TZ:-} && -f /usr/share/zoneinfo/$TZ ]]; then
  ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
  echo "$TZ" > /etc/timezone
fi

# Weiterleiten und UDP-Puffer (Hysteria2). Gilt im Host-Netz für den ganzen Host.
sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 || echo "Hinweis: sysctl für Weiterleitung fehlgeschlagen"
sysctl -q -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# Kernelmodule (klappt, wenn /lib/modules vom Host eingebunden ist; sonst auf dem Host laden)
for m in wireguard ifb act_connmark act_mirred sch_htb sch_ingress cls_fw cls_u32 cls_matchall tun; do
  modprobe -q "$m" 2>/dev/null || true
done
[[ -c /dev/net/tun ]] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200 2>/dev/null && chmod 666 /dev/net/tun || true; }

# Unbound braucht den Vertrauensanker
if [[ -f /usr/share/dns/root.key && -d /var/lib/unbound && ! -f /var/lib/unbound/root.key ]]; then
  install -o unbound -g unbound -m 644 /usr/share/dns/root.key /var/lib/unbound/root.key
fi

# Einstellungen aus der Umgebung – nur was gesetzt ist und sich ändert (sonst bleibt, was im Panel steht)
OUT_IF=${OUT_IF:-$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')}
set_args=()
want() {  # want <einstellung> <wert>
  [[ -n $2 ]] || return 0
  local cur=""
  [[ -s $DATA/panel.db ]] && cur=$(/usr/local/bin/vpnpanel config "$1" 2>/dev/null || true)
  [[ $cur == "$2" ]] || set_args+=("$1=$2")
}
want server_host "${SERVER_HOST:-}"
want sub_host "${SUB_HOST:-}"
want panel_host "${PANEL_HOST:-}"
want out_interface "${OUT_IF:-}"
if ((${#set_args[@]})); then
  /usr/local/bin/vpnpanel config -n "${set_args[@]}" >/dev/null && echo "Einstellungen übernommen: ${set_args[*]%%=*}"
fi

exec /sbin/init
