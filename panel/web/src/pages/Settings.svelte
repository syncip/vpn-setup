<script>
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import QR from '../components/QR.svelte';
  import Info from '../components/Info.svelte';
  import PortHelp from '../components/PortHelp.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { date } from '../lib/format.js';
  import { go, session, meta } from '../lib/state.svelte.js';

  let { tab = 'general' } = $props();
  const tabs = [
    ['general', 'Allgemein', 'settings'],
    ['security', 'Sicherheit', 'lock'],
    ['admins', 'Administratoren', 'users'],
    ['system', 'System', 'terminal'],
    ['events', 'Ereignisse', 'list'],
  ];

  // ---------- Allgemein ----------
  let s = $state(null);
  async function loadSettings() {
    s = await get('/settings');
  }
  async function saveSettings() {
    const r = await run(() => put('/settings', $state.snapshot(s)), 'Einstellungen gespeichert');
    if (r) {
      s = r;
      Object.assign(meta, await get('/meta'));
    }
  }

  // ---------- Sicherheit ----------
  let pw = $state({ current: '', new: '', again: '' });
  let totp = $state(null);
  let totpCode = $state('');
  let disablePw = $state('');
  let sessions = $state([]);
  let priv = $state(null);
  async function loadSecurity() {
    sessions = await get('/auth/sessions');
    const all = await get('/settings');
    priv = { block: all.private_block !== '0', allow: all.private_allow || '' };
  }
  async function savePrivate() {
    if (!priv.block && !(await confirmDialog({ title: 'Lokale Netze freigeben?', text: 'VPN-Nutzer können dann das interne Netz des Servers erreichen – auch den Proxmox-Host und dessen Weboberfläche.', ok: 'Freigeben', danger: true }))) return;
    const r = await run(() => put('/settings', { private_block: priv.block ? '1' : '0', private_allow: priv.allow }), 'Gespeichert');
    if (r) priv = { block: r.private_block !== '0', allow: r.private_allow || '' };
  }
  async function changePw() {
    if (pw.new !== pw.again) return run(() => Promise.reject(new Error('Die neuen Passwörter stimmen nicht überein')));
    if (await run(() => post('/auth/password', { current: pw.current, new: pw.new }), 'Passwort geändert')) pw = { current: '', new: '', again: '' };
  }
  async function startTotp() {
    totp = await run(() => post('/auth/totp/setup'));
  }
  async function enableTotp() {
    if (await run(() => post('/auth/totp/enable', { code: totpCode }), '2FA aktiviert')) {
      totp = null;
      totpCode = '';
      session.user = await get('/auth/me');
    }
  }
  async function disableTotp() {
    if (await run(() => post('/auth/totp/disable', { password: disablePw }), '2FA deaktiviert')) {
      disablePw = '';
      session.user = await get('/auth/me');
    }
  }
  async function logoutOthers() {
    if (await run(() => del('/auth/sessions'), 'Andere Sitzungen beendet')) loadSecurity();
  }

  // ---------- Administratoren ----------
  let admins = $state([]);
  let na = $state({ username: '', password: '' });
  async function loadAdmins() {
    admins = await get('/admins');
  }
  async function addAdmin() {
    if (await run(() => post('/admins', na), 'Administrator angelegt')) {
      na = { username: '', password: '' };
      loadAdmins();
    }
  }
  async function removeAdmin(a) {
    if (!(await confirmDialog({ title: `${a.username} löschen?`, text: 'Der Zugang zum Panel wird entfernt.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/admins/${a.id}`), 'Gelöscht')) loadAdmins();
  }

  // ---------- System ----------
  let sys = $state(null);
  async function loadSystem() {
    sys = await get('/system');
  }
  async function applyNow() {
    if (await run(() => post('/system/apply'), 'Konfiguration angewendet')) loadSystem();
  }
  async function collectNow() {
    if (await run(() => post('/system/collect'), 'Statistik eingesammelt')) loadSystem();
  }

  // ---------- Ereignisse ----------
  let events = $state([]);
  let level = $state('');
  async function loadEvents() {
    events = await get(`/events?limit=300${level ? `&level=${level}` : ''}`);
  }

  $effect(() => {
    const t = tab;
    if (t === 'general') loadSettings();
    if (t === 'security') loadSecurity();
    if (t === 'admins') loadAdmins();
    if (t === 'system') loadSystem();
    if (t === 'events') loadEvents();
  });

  const generalFields = [
    { key: 'server_host', label: 'Server-Adresse', help: 'Domain (A/AAAA auf den Server, ohne Cloudflare-Proxy) oder öffentliche IP. Steht in allen Links und Konfigurationen.' },
    { key: 'panel_host', label: 'Panel-Domain', help: 'Optional. Leer = Webinterface nur direkt per IP:Port. Mit Domain zusätzlich über nginx auf Port 443 (z. B. hinter Cloudflare).' },
    { key: 'sub_host', label: 'Abo-Domain', help: 'Für Abo-Links (https://<abo-domain>/<token>). Leer = über die Panel-Domain unter /sub/ bzw. direkt per IP:Port.' },
    { key: 'profile_title', label: 'Name in der App', help: 'Titel des Abos in v2RayTun & Co.' },
  ];
  const advFields = [
    { key: 'out_interface', label: 'Ausgehende Schnittstelle', help: 'Schnittstelle des Servers ins Internet (z. B. eth0, ens3). Das Setup-Script erkennt sie selbst.' },
    { key: 'public_port', label: 'Öffentlicher TCP-Port', help: 'Port des nginx-SNI-Verteilers (Panel, Abo, VLESS).', num: true },
    { key: 'xray_api', label: 'Xray-API', help: 'Interne Adresse der Xray-Statistik.' },
    { key: 'collect_interval', label: 'Statistik-Intervall (Sekunden)', num: true },
    { key: 'sub_update_interval', label: 'Abo-Aktualisierung (Stunden)', help: 'Wie oft die App das Abo neu lädt.', num: true },
    { key: 'traffic_retention', label: 'Verlauf aufbewahren (Tage)', num: true },
    { key: 'session_hours', label: 'Anmeldung gültig (Stunden)', num: true },
    { key: 'exit_speedtest', label: 'Geschwindigkeitstest der Ausgänge (Minuten)', help: '0 = aus. Jeder Test lädt 5 MB über den Ausgang (Menü Proxy).', num: true },
  ];
  let showAdv = $state(false);
</script>

<PageHead title="Einstellungen" />

<div class="tabs">
  {#each tabs as [id, label, icon]}
    <button class:active={tab === id} onclick={() => go(`/settings/${id}`)}><Icon name={icon} size={16} /> {label}</button>
  {/each}
</div>

{#if tab === 'general' && s}
  <div class="card card-pad" style="max-width:760px">
    <div class="stack">
      {#each generalFields as f}
        <div class="field"><label for="s-{f.key}">{f.label} {#if f.help}<Info title={f.label} text={f.help} />{/if}</label><input id="s-{f.key}" class="input" bind:value={s[f.key]} /></div>
      {/each}
      <label class="switch"><input type="checkbox" checked={s.trust_cloudflare === '1'} onchange={(e) => (s.trust_cloudflare = e.currentTarget.checked ? '1' : '0')} /><span class="track"></span> Echte Besucher-IP von Cloudflare übernehmen (CF-Connecting-IP)</label>
      <label class="switch"><input type="checkbox" checked={s.update_check !== '0'} onchange={(e) => (s.update_check = e.currentTarget.checked ? '1' : '0')} /><span class="track"></span> Nach neuen Versionen suchen (fragt alle 12 Stunden bei GitHub nach, ohne Daten mitzuschicken)</label>
      <button type="button" class="btn ghost sm" style="align-self:flex-start" onclick={() => (showAdv = !showAdv)}><Icon name={showAdv ? 'chevron-down' : 'chevron'} size={15} /> Erweitert</button>
      {#if showAdv}
        <div class="grid cols-2">
          {#each advFields as f}
            <div class="field"><label for="s-{f.key}">{f.label} {#if f.help}<Info title={f.label} text={f.help} />{/if}</label><input id="s-{f.key}" class="input" inputmode={f.num ? 'numeric' : 'text'} bind:value={s[f.key]} /></div>
          {/each}
        </div>
      {/if}
      <div><button class="btn primary" onclick={saveSettings}>Speichern</button></div>
    </div>
  </div>
{:else if tab === 'security'}
  <div class="grid cols-2" style="max-width:1100px">
    <div class="card">
      <div class="card-head"><h3><Icon name="key" size={16} /> Passwort ändern</h3></div>
      <div class="card-pad stack">
        <div class="field"><label for="pw1">Aktuelles Passwort</label><input id="pw1" type="password" class="input" bind:value={pw.current} autocomplete="current-password" /></div>
        <div class="field"><label for="pw2">Neues Passwort</label><input id="pw2" type="password" class="input" bind:value={pw.new} autocomplete="new-password" placeholder="mindestens 10 Zeichen" /></div>
        <div class="field"><label for="pw3">Wiederholen</label><input id="pw3" type="password" class="input" bind:value={pw.again} autocomplete="new-password" /></div>
        <div><button class="btn primary" onclick={changePw} disabled={!pw.current || !pw.new}>Ändern</button></div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h3><Icon name="shield" size={16} /> Zwei-Faktor-Anmeldung</h3>{#if session.user.totp_enabled}<span class="badge ok">aktiv</span>{:else}<span class="badge warn">aus</span>{/if}</div>
      <div class="card-pad stack">
        {#if session.user.totp_enabled}
          <p class="muted small" style="margin:0">Bei jeder Anmeldung wird ein Code aus deiner Authenticator-App abgefragt.</p>
          <div class="field"><label for="dpw">Zum Abschalten Passwort eingeben</label><input id="dpw" type="password" class="input" bind:value={disablePw} /></div>
          <div><button class="btn danger" onclick={disableTotp} disabled={!disablePw}>2FA abschalten</button></div>
        {:else if totp}
          <p class="small" style="margin:0">QR-Code mit einer Authenticator-App (z. B. Aegis, 2FAS, Google Authenticator) scannen und den angezeigten Code eingeben.</p>
          <div class="row" style="gap:18px;align-items:flex-start">
            <QR text={totp.url} size={170} />
            <div class="stack-sm grow">
              <span class="label">Oder Schlüssel eintippen</span>
              <code class="mono" style="word-break:break-all">{totp.secret}</code>
            </div>
          </div>
          <div class="row"><input class="input mono" style="max-width:160px" placeholder="123456" bind:value={totpCode} inputmode="numeric" /><button class="btn primary" onclick={enableTotp} disabled={totpCode.length < 6}>Aktivieren</button></div>
        {:else}
          <p class="muted small" style="margin:0">Schützt das Panel zusätzlich mit einem Code vom Handy. Dringend empfohlen, da das Panel aus dem Internet erreichbar ist.</p>
          <div><button class="btn primary" onclick={startTotp}>2FA einrichten</button></div>
        {/if}
      </div>
    </div>
    {#if priv}
      <div class="card" style="grid-column:1/-1">
        <div class="card-head">
          <h3>
            <Icon name="lock" size={16} /> Lokale Netze für VPN-Nutzer
            <Info title="Lokale Netze" wide>
              <p>Ohne Sperre könnten VPN-Nutzer über den Server private Adressen erreichen – das interne Netz des Containers (z. B. 10.10.10.0/24 mit dem Proxmox-Host und seiner Weboberfläche), andere VMs, Loopback-Dienste (Panel, Xray-API) und die öffentliche Adresse des Servers selbst.</p>
              <ul>
                <li>Gesperrt: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 (CGNAT/Tailscale), 127.0.0.0/8, 169.254.0.0/16, IPv6 fc00::/7, fe80::/10, ::1 – und die Adressen der Server-Domain.</li>
                <li>Gilt für WireGuard, OpenVPN, VLESS, Hysteria2 und Proxy.</li>
                <li>Netze zwischen VPN-Servern gibst du gezielt unter <a href="#/network/access">Netzwerk → Zugriff</a> frei. Geräte desselben WireGuard-Servers erreichen sich weiter nach dessen Einstellung.</li>
                <li>Ausnahmen unten gelten für alle VPN-Nutzer.</li>
              </ul>
            </Info>
          </h3>
          {#if priv.block}<span class="badge ok">gesperrt</span>{:else}<span class="badge bad">offen</span>{/if}
        </div>
        <div class="card-pad stack">
          <label class="switch"><input type="checkbox" bind:checked={priv.block} /><span class="track"></span> Private Netze, Proxmox-Host und den Server selbst für VPN-Nutzer sperren (empfohlen)</label>
          <div class="field">
            <label for="priv-allow">Ausnahmen für alle <span class="muted">(optional)</span></label>
            <textarea id="priv-allow" class="input mono" rows="3" bind:value={priv.allow} disabled={!priv.block} placeholder="192.168.50.0/24"></textarea>
          </div>
          <div><button class="btn primary" onclick={savePrivate}>Speichern</button></div>
        </div>
      </div>
    {/if}
    <div class="card" style="grid-column:1/-1">
      <div class="card-head"><h3><Icon name="eye" size={16} /> Angemeldete Sitzungen</h3><button class="btn sm" onclick={logoutOthers}>Alle anderen abmelden</button></div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Gerät</th><th>IP</th><th>Angemeldet</th><th>Zuletzt aktiv</th></tr></thead>
          <tbody>
            {#each sessions as se}
              <tr><td class="small ellipsis" style="max-width:420px">{se.agent} {#if se.current}<span class="badge accent">diese</span>{/if}</td><td class="mono small">{se.ip}</td><td class="small">{date(se.created, true)}</td><td class="small">{date(se.last_used, true)}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  </div>
{:else if tab === 'admins'}
  <div class="grid cols-2" style="max-width:1100px">
    <div class="card">
      <div class="card-head"><h3>Administratoren</h3></div>
      <div class="table-wrap">
        <table class="table">
          <tbody>
            {#each admins as a}
              <tr>
                <td class="strong">{a.username} {#if a.id === session.user.id}<span class="badge accent">du</span>{/if}</td>
                <td>{#if a.totp_enabled}<span class="badge ok">2FA</span>{:else}<span class="badge warn">ohne 2FA</span>{/if}</td>
                <td class="small muted">seit {date(a.created)}</td>
                <td class="right">{#if a.id !== session.user.id}<button class="btn sm icon ghost danger" title="Löschen" onclick={() => removeAdmin(a)}><Icon name="trash" size={15} /></button>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h3>Administrator hinzufügen</h3></div>
      <div class="card-pad stack">
        <div class="field"><label for="na-u">Benutzername</label><input id="na-u" class="input" bind:value={na.username} autocomplete="off" /></div>
        <div class="field"><label for="na-p">Passwort</label><input id="na-p" type="password" class="input" bind:value={na.password} autocomplete="new-password" placeholder="mindestens 10 Zeichen" /></div>
        <div><button class="btn primary" onclick={addAdmin} disabled={!na.username || !na.password}>Anlegen</button></div>
        <div class="row small muted" style="gap:6px">Passwort vergessen? <Info title="Passwort vergessen" wide><p>Auf dem Server als root:</p><pre>vpn admin passwd &lt;name&gt;</pre><p>2FA abschalten: <code>vpn admin 2fa-off &lt;name&gt;</code>. 2FA richtet jeder Administrator selbst ein.</p></Info></div>
      </div>
    </div>
  </div>
{:else if tab === 'system' && sys}
  <div class="stack" style="max-width:1100px">
    <div class="row">
      <button class="btn primary" onclick={applyNow}><Icon name="refresh" size={16} /> Konfiguration jetzt anwenden</button>
      <button class="btn" onclick={collectNow}><Icon name="activity" size={16} /> Statistik einsammeln</button>
      <span class="grow"></span>
      <span class="muted small">Version {sys.version}</span>
    </div>
    {#if Object.keys(sys.errors || {}).length}
      <div class="notice bad"><Icon name="alert" /><div>{#each Object.entries(sys.errors) as [k, v]}<div class="small"><b>{k}:</b> {v}</div>{/each}</div></div>
    {/if}
    <div class="grid cols-2">
      <div class="card">
        <div class="card-head"><h3>Komponenten</h3></div>
        <div class="table-wrap">
          <table class="table">
            <tbody>
              {#each sys.checks as c}
                <tr><td><span class="row"><span class="dot" class:on={c.ok} class:bad={!c.ok}></span>{c.name}</span></td><td class="small muted right">{c.detail}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Portweiterleitungen auf dem Host <Info title="Firewall-Regeln für den Proxmox-Host" wide><PortHelp ports={sys.ports} /></Info></h3></div>
        <div class="card-pad stack-sm">
          <table class="table">
            <tbody>
              {#each sys.ports as p}
                <tr><td><span class="badge">{p.proto.toUpperCase()} {p.port}{p.to ? `–${p.to}` : ''}</span></td><td class="small">{p.server}</td><td class="small muted">{p.note}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    {#if sys.dry_run}
      <div class="card">
        <div class="card-head"><h3>Testmodus – ausgeführte Befehle</h3><span class="badge warn">nicht wirklich ausgeführt</span></div>
        <pre class="code" style="border:none;border-radius:0 0 12px 12px;max-height:420px">{sys.dry_log.slice(-150).join('\n')}</pre>
      </div>
    {/if}
  </div>
{:else if tab === 'events'}
  <div class="card" style="max-width:1100px">
    <div class="card-head">
      <h3>Ereignisse</h3>
      <div class="segmented">
        {#each [['', 'Alle'], ['info', 'Info'], ['warn', 'Warnungen'], ['error', 'Fehler']] as [k, l]}
          <button class:active={level === k} onclick={() => { level = k; loadEvents(); }}>{l}</button>
        {/each}
      </div>
    </div>
    <div class="table-wrap">
      <table class="table">
        <tbody>
          {#each events as e}
            <tr>
              <td class="small muted nowrap" style="width:150px">{date(e.ts, true)}</td>
              <td style="width:90px"><span class="badge {e.level === 'error' ? 'bad' : e.level === 'warn' ? 'warn' : 'muted'}">{e.level}</span></td>
              <td class="small">{e.msg}</td>
            </tr>
          {:else}
            <tr><td class="empty">Keine Ereignisse</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}
