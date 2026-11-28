# Code-Karte des VPN-Panels

Einstieg für Änderungen: **erst hier nachsehen, dann nur die betroffene Datei lesen** (bei großen Dateien per
`grep -n "// ----------"` die Abschnitte finden und nur den Bereich lesen). Benutzerdoku steht in `../README.md`.

## Ablauf in einem Satz

`main.go` startet `serve`: Datenbank öffnen (`store`) → `engine` erzeugt aus der DB alle Konfigurationen und spielt sie ein
(`Apply`, Treiber in `proto/*`), sammelt Statistik (`Collect`) und betreibt die eingebauten Dienste (DNS, SmartDNS-Proxy, Proxy);
`api` liefert die JSON-API, das Abo und die eingebettete Svelte-Oberfläche (`webui`, gebaut aus `web/`).

## Häufige Aufgaben – wo anfangen?

| Aufgabe | Stelle |
|---|---|
| neue Einstellung | Vorgabe in `settingDefaults` (`internal/engine/engine.go`), Prüfung in `internal/engine/settings.go` (`ValidateSetting`), Oberfläche meist `web/src/pages/Settings.svelte` |
| neuer API-Endpunkt | Route in `internal/api/api.go` (`Handler()`), Handler in der Themen-Datei unter `internal/api/` |
| neue Tabelle / Spalte | Migration ans Ende von `migrations` in `internal/store/store.go`, Zugriffe in der Themen-Datei unter `internal/store/` |
| neues Protokoll | Paket unter `internal/proto/<name>/` mit `proto.Driver` (`internal/proto/proto.go`), in `main.go` importieren |
| neue Seite / neuer Reiter | `web/src/App.svelte` (Menü `NAV`, Routen), Seite unter `web/src/pages/`; alte Adressen → `MOVED` in `web/src/lib/state.svelte.js` |
| Firewall (nftables) | `internal/engine/nft.go` (Tabelle `inet vpnpanel`), Regeln aus `routes.go`, `acl.go`, `private.go`, `netaccess.go`, `smartdns.go` |
| Systembefehle | immer über `system.Runner` (`e.Sys`) – im Testmodus (`-dev`) nur protokolliert |

## Go-Pakete (`internal/`)

### `store` – SQLite (modernc, ohne CGO)
- `store.go` Öffnen, **Migrationen** (`migrations`, `SchemaVersion`), Einstellungen · `models.go` Typen (Server, User, Peer, Plan, …)
- `users.go` Server, Tarife, Nutzer, Zugänge · `traffic.go` Verkehr je Stunde (Zugänge, Ausgänge) · `grouptraffic.go` je Gruppe
- `smarttraffic.go` SmartDNS-Verkehr je Stunde · `objects.go` freie Objekte (exit, group, iplist, route, dnsprofile, smartdns, alarm, …)
- `admins.go` Ereignisse, Admins, Sitzungen, Anmeldeprotokoll, DB-Kopie für Sicherungen · `loginlock.go` · `dnslog.go` · `blockcheck.go`

### `engine` – Logik, Anwenden, Hintergrunddienste
- **Kern:** `engine.go` (Engine-Typ, `settingDefaults`, `Apply`, Zusammenstellen) · `collect.go` (Statistik einsammeln, Abfragen für UI/Abo)
  · `nginx.go` (SNI-Verteiler 443) · `settings.go` (Prüfung) · `secrets.go` (`secrets.env`) · `limits.go` (Limits/Drosseln) · `live.go` (Live-Werte)
- **Firewall & Wege:** `nft.go` · `routes.go` (Ziel-Regeln) · `acl.go` (IP-Listen) · `lists.go` (Online-Listen) · `private.go` (private Ziele)
  · `netaccess.go` (Netzwerk → Zugriff) · `effective.go` (Hilfen für „Was gilt?“)
- **Ausgänge:** `exits.go` (DB ↔ `exits`-Manager) · `exitlimits.go` · `blockcheck.go`, `blockpassive.go`, `blockprobe.go` (Block-Prüfung)
- **Panel-DNS:** `dns.go` (Server, Anfragen) · `dns_cache.go` (Zwischenspeicher, Protokoll) · `dns_upstream.go` (Weiterreichen, Speedtest)
  · `dnsfilter.go` (Filterprofile, Blocklisten) · `dnslistedit.go` · `dnsauto.go` (Unbound/Auto-Wahl) · `dnslive.go` · `dnsrate.go`
  · `dnsext.go` (Geräte ohne VPN) · `encdns.go` (DoH/DoT) · `encdns_acme.go` (Let's Encrypt, Cloudflare) · `geo.go`
  · `unbound.go` (Selbstprüfung) · `unbound_groups.go` (Unbound je Gruppe)
- **SmartDNS:** `smartdns.go` (Profile, Zuordnung, nft) · `smartproxy.go` (SNI-Proxy für Geräte ohne VPN) · `smartstats.go` (Statistik, nft-Zähler)
- **Betrieb:** `notify.go` (Mail) · `alarms.go` · `attention.go` („Braucht Aufmerksamkeit“) · `hoststats.go` · `portcheck.go`
  · `update.go` (Update-Prüfung) · `selfupdate.go` (**Update aus dem Panel**, Wächter) · `points.go` (Wiederherstellungspunkte)
  · `pkgupdate.go` (Paket-Updates) · `legacy.go` (Übernahme Bash-Setup) · `singbox.go` · `connlimit.go` · `lock_*.go`, `disk_*.go`

### `api` – HTTP
- `api.go` **alle Routen**, Middleware, Sicherheitsheader · `auth.go` Anmeldung, Sitzungen, 2FA · `loginlock.go` · `account.go` Konto, Mail, Sicherung
- `handlers.go` Meta, Übersicht, gemeinsame Hilfen · `users.go` · `peers.go` · `servers.go` · `settings.go` (Tarife, Einstellungen, System)
- `objects.go` Ausgänge und Gruppen · `iplists.go` · `routes.go` Ziel-Regeln · `chains.go` Kaskade über Ziel-Regeln · `netaccess.go`
- `dns.go` (Einstellungen, Filterprofile) · `dns_lists.go` (Blocklisten, Protokoll) · `dnsext.go` · `smartdns.go` · `smartstats.go`
- `effective.go` + `effective_kinds.go` („Was gilt?“) · `topology.go` (Netzwerkkarte) · `live.go` · `status.go` · `search.go` · `layout.go`
- `alarms.go` · `points.go` (Update installieren/Rücksprung, Wiederherstellungspunkte) · `sub.go` (Abo-Auslieferung)

### `proto` – Protokolltreiber (`proto.Driver`)
- `proto.go` Schnittstelle, Registry, Felder · `routes.go` Domain-/Netz-Abgleich für Ziel-Regeln · `conflicts.go` Netze/Ports prüfen
- je Treiber: `<name>.go` (Felder, Vorgaben, Prüfung) · `apply.go` (Konfiguration/Dienste einspielen) · `client.go` (Statistik, Client-Config, Links)
  - `wireguard/` (+ `netutil.go`) · `openvpn/` (+ `pki.go`, `mgmt.go`) · `hysteria2/` · `vless/vless.go` (eine Datei)
  - `proxy/` im Panel-Prozess: `proxy.go` (Treiber) · `runtime.go` · `dial.go` · `protocols.go` (SOCKS5/HTTP) · `stats.go` · `notes.go`
- `shaping/` tc-Drosselung (eth0 + ifb) für alle Protokolle

### Weitere Pakete
- `exits/` externe VPNs: `exits.go` (Manager, Modelle) · `parse.go` (Configs bereinigen) · `health.go` (Prüfung) · `rotate.go` · `standby.go`
  · `cascade.go` · `pins.go` (weicher Wechsel) · `override.go` · `passive.go` · `blockcfg.go` · `tor.go` · `mark_*.go`
- `backup/` `backup.go` (Format, Einspielen beim Start) · `points.go` (Wiederherstellungspunkte)
- `system/` Befehle/Dateien, `Dry` für den Testmodus · `geo/` Länder aus RIR-Listen · `tor2socks/` TUN → Tor · `webui/` eingebettete Oberfläche
- Wurzel: `main.go` (`serve`, `version`, `update-apply`, `tun2socks`) · `cli.go`, `cli_backup.go` (Befehl `vpn`) · `demo.go` (Demo-Daten)

## Oberfläche (`web/src`, Svelte 5)

- `App.svelte` Rahmen, Menü (`NAV`), Routen · `lib/state.svelte.js` Anmeldung, Meta, Route, `MOVED` · `lib/api.js` `get/post/put/del/run/postFile/upload`
- `lib/format.js` (bytes, speed, date, ago …) · `lib/live.svelte.js` (`/api/live` alle 2 s) · `lib/layout.svelte.js` · `lib/pick.js` · `lib/exitstate.js`
- **Seiten:** `Overview` · `Users`, `UserDetail` · `Servers` · `Network` (Übersicht/Aufbau/Zugriff) · `Proxy` (Ausgänge, Limits, Gruppen, Proxy-Server)
  · `IPLists` · `DNS` · `Stats` · `Health` (Zustand, Updates, Ereignisse) · `Effective` · `Settings` · `Account` · `Plans` · `Login`
- **Große Seiten** haben Abschnittsmarken `// ---------- … ----------` im Skript und `{#if tab === '…'}` im Markup:
  - `DNS.svelte`: Übersicht, Protokoll, Filterprofile, SmartDNS, SmartDNS-Statistik, Blocklisten, Blocklisten durchsuchen, Einstellungen
  - `Proxy.svelte`: Übersicht, Prüfen, Ausgang Ping/Speedtest, Ausgänge, Limits, Gruppen, Proxy-Server
  - `Settings.svelte`: Allgemein, Sicherheit, Benachrichtigungen, Sicherung, Administratoren
- **Bausteine:** `Chart` (alle Grafiken) · `TrafficChart` · `Board` (anordenbare Fenster) · `Modal`, `Confirm`, `Info`, `Fold`, `Picker`
  · `TopologyMap`, `BuildMap` (Netzwerkkarten) · `RouteRules`, `PeerRoutes` · `DNSExternal`, `DNSLive`, `DNSListBrowser`
  · `SmartLive`, `SmartStats` · `ExitLive`, `ExitTraffic` · `PanelUpdate`, `UpdatesPanel`, `RestorePoints` · `AlarmsPanel` · `NetAccess`

## Bauen, Testen, Ausführen

- Oberfläche: `cd web && npm run build` (landet in `internal/webui/dist`, wird eingebettet) – danach Go neu bauen.
- Tests: `go test ./...` · `go vet ./...` · Labortests (Linux/WSL als root): Build-Tag `lab`.
- Testmodus: `vpnpanel serve -dev -demo -data devdata` (keine Systembefehle, Dateien unter `devdata/dryroot`).
- Release-Programm: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=X.Y.Z" -o dist/vpnpanel-linux-amd64 .`
- Docker: `../docker/` – `Dockerfile` (Debian 13 + systemd, Xray/Hysteria2 mit Prüfsumme), `entrypoint.sh` (panel.env,
  Zertifikat, Einstellungen aus der Umgebung, dann `/sbin/init`), `docker-compose.yml`, `xray.service`, `vpnpanel.service`.
  Image baut `.github/workflows/docker.yml` bei jedem Release aus dem Release-Programm. Im Container setzt das
  Start-Script `VPNPANEL_DOCKER=1` → `engine.InDocker()` schaltet das Update aus dem Panel ab.
- Versionswechsel: `main.pointBeforeUpgrade` (in `open`) legt vor den Migrationen einen Punkt an (`<data>/panel-version`).
