# VPN-Panel als Docker-Image: Debian 13 mit systemd (das Panel steuert seine Dienste über systemd –
# WireGuard, Xray, Hysteria2, OpenVPN, nginx, Unbound, Tor). Läuft im Host-Netz und privilegiert,
# siehe docker-compose.yml und README („Docker“).
#
# Bauen (Kontext = Wurzel des Repos, Programm vorher nach panel/dist/vpnpanel-linux-amd64 bauen):
#   docker build -f docker/Dockerfile -t vpnpanel .
FROM debian:trixie-slim

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus kmod procps tzdata \
      wireguard-tools iptables iproute2 qrencode curl ca-certificates openssl unzip jq \
      nginx libnginx-mod-stream openvpn iputils-ping conntrack nftables \
      tor tor-geoipdb unbound dns-root-data unbound-anchor \
 && rm -rf /var/lib/apt/lists/*

# Xray und Hysteria2: offizielle Release-Dateien, gegen die veröffentlichten Prüfsummen geprüft.
# Version festlegen: --build-arg XRAY_VERSION=v26.1.1 bzw. HYSTERIA_VERSION=app/v2.6.5 (Vorgabe: neueste)
ARG XRAY_VERSION=latest
ARG HYSTERIA_VERSION=latest
RUN set -eu; \
    gh() { if [ "$2" = latest ]; then echo "https://github.com/$1/releases/latest/download"; else echo "https://github.com/$1/releases/download/$2"; fi; }; \
    cd /tmp; \
    x=$(gh XTLS/Xray-core "$XRAY_VERSION"); \
    curl -fsSL --retry 3 -o xray.zip "$x/Xray-linux-64.zip"; \
    curl -fsSL --retry 3 -o xray.dgst "$x/Xray-linux-64.zip.dgst"; \
    want=$(sed -n 's/^SHA2-256= *//p' xray.dgst | head -1); \
    echo "$want  xray.zip" | sha256sum -c -; \
    mkdir -p xray /usr/local/share/xray /usr/local/etc/xray; \
    unzip -q xray.zip -d xray; \
    install -m 755 xray/xray /usr/local/bin/xray; \
    install -m 644 xray/geoip.dat xray/geosite.dat /usr/local/share/xray/; \
    h=$(gh apernet/hysteria "$HYSTERIA_VERSION"); \
    curl -fsSL --retry 3 -o hysteria "$h/hysteria-linux-amd64"; \
    curl -fsSL --retry 3 -o hashes.txt "$h/hashes.txt"; \
    want=$(awk '/hysteria-linux-amd64$/ {print $1; exit}' hashes.txt); \
    [ -n "$want" ]; echo "$want  hysteria" | sha256sum -c -; \
    install -m 755 hysteria /usr/local/bin/hysteria; \
    rm -rf /tmp/*; \
    /usr/local/bin/xray version | head -1; /usr/local/bin/hysteria version | head -3

COPY docker/xray.service /etc/systemd/system/xray.service
COPY docker/vpnpanel.service /etc/systemd/system/vpnpanel.service
COPY docker/entrypoint.sh /usr/local/sbin/vpnpanel-entrypoint
COPY panel/dist/vpnpanel-linux-amd64 /usr/local/bin/vpnpanel

RUN set -eu; \
    chmod 755 /usr/local/sbin/vpnpanel-entrypoint /usr/local/bin/vpnpanel; \
    ln -sf /usr/local/bin/vpnpanel /usr/local/bin/vpn; \
    mkdir -p /etc/nginx/stream.d /etc/hysteria /etc/wireguard /etc/openvpn/vpn; \
    chmod 700 /etc/wireguard; chmod 755 /etc/openvpn/vpn; \
    grep -q 'stream.d' /etc/nginx/nginx.conf || printf '\nstream {\n    include /etc/nginx/stream.d/*.conf;\n}\n' >> /etc/nginx/nginx.conf; \
    rm -f /etc/nginx/sites-enabled/default; \
    # Dienste, die im Container nichts tun oder stören; Tor/Unbound startet das Panel bei Bedarf selbst
    systemctl mask getty.target console-getty.service systemd-udevd.service systemd-udevd-control.socket \
      systemd-udevd-kernel.socket systemd-firstboot.service systemd-remount-fs.service \
      apt-daily.timer apt-daily-upgrade.timer dev-hugepages.mount sys-fs-fuse-connections.mount; \
    systemctl disable tor.service unbound.service 2>/dev/null || true; \
    systemctl enable nginx.service vpnpanel.service

VOLUME ["/etc/vpn"]
STOPSIGNAL SIGRTMIN+3
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD systemctl is-active --quiet vpnpanel || exit 1

ENTRYPOINT ["/usr/local/sbin/vpnpanel-entrypoint"]
