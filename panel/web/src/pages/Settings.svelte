<script>
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Info from '../components/Info.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run, postFile, upload } from '../lib/api.js';
  import { date } from '../lib/format.js';
  import { go, session, meta, toast } from '../lib/state.svelte.js';

  let { tab = 'general' } = $props();
  const tabs = [
    ['general', 'Allgemein', 'settings'],
    ['security', 'Sicherheit', 'lock'],
    ['notify', 'Benachrichtigungen', 'mail'],
    ['backup', 'Sicherung', 'archive'],
    ['admins', 'Administratoren', 'users'],
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
  let priv = $state(null);
  async function loadSecurity() {
    const all = await get('/settings');
    priv = { block: all.private_block !== '0', allow: all.private_allow || '' };
  }
  async function savePrivate() {
    if (!priv.block && !(await confirmDialog({ title: 'Lokale Netze freigeben?', text: 'VPN-Nutzer können dann das interne Netz des Servers erreichen – auch den Proxmox-Host und dessen Weboberfläche.', ok: 'Freigeben', danger: true }))) return;
    const r = await run(() => put('/settings', { private_block: priv.block ? '1' : '0', private_allow: priv.allow }), 'Gespeichert');
    if (r) priv = { block: r.private_block !== '0', allow: r.private_allow || '' };
  }

  // ---------- Benachrichtigungen ----------
  const mailKeys = ['mail_enabled', 'smtp_host', 'smtp_port', 'smtp_security', 'smtp_user', 'mail_from', 'notify_events'];
  let mail = $state(null);
  let nstate = $state(null);
  let smtpPw = $state('');
  let editPw = $state(false);
  async function loadNotify() {
    const [all, n] = await Promise.all([get('/settings'), get('/notify')]);
    mail = Object.fromEntries(mailKeys.map((k) => [k, all[k] ?? '']));
    nstate = n;
    editPw = !n.password_set;
  }
  const evOn = (k) => (mail?.notify_events || '').split(',').includes(k);
  function toggleEv(k, on) {
    const set = new Set((mail.notify_events || '').split(',').filter(Boolean));
    if (on) set.add(k);
    else set.delete(k);
    mail.notify_events = nstate.events.map((e) => e.key).filter((x) => set.has(x)).join(',');
  }
  function setSecurity(v) {
    mail.smtp_security = v;
    if (v === 'tls' && (mail.smtp_port === '587' || mail.smtp_port === '25')) mail.smtp_port = '465';
    if (v === 'starttls' && (mail.smtp_port === '465' || mail.smtp_port === '25')) mail.smtp_port = '587';
    if (v === 'none' && (mail.smtp_port === '465' || mail.smtp_port === '587')) mail.smtp_port = '25';
  }
  async function saveMail() {
    if (editPw && smtpPw) {
      if (!(await run(() => put('/notify/password', { password: smtpPw })))) return;
      smtpPw = '';
    }
    const r = await run(() => put('/settings', $state.snapshot(mail)), 'Benachrichtigungen gespeichert');
    if (r) loadNotify();
  }
  async function removeSmtpPw() {
    if (!(await confirmDialog({ title: 'Passwort entfernen?', text: 'Das Passwort des Mailservers wird aus secrets.env gelöscht.', ok: 'Entfernen', danger: true }))) return;
    if (await run(() => del('/notify/password'), 'Passwort entfernt')) loadNotify();
  }
  let testing = $state(false);
  async function testMail() {
    testing = true;
    const r = await run(() => post('/notify/test'));
    testing = false;
    if (r) {
      // Antwort des Mailservers (mit Queue-ID): ab hier ist die Mail beim Mailserver – kommt sie nicht an,
      // liegt es an Spamfilter oder Zustellung (Spam-Ordner, Protokoll des Mailanbieters)
      toast(`Testmail an ${r.to} vom Mailserver angenommen${r.reply ? ` (${r.reply})` : ''} – nicht angekommen? Spam-Ordner prüfen`);
      loadNotify();
    }
  }

  // ---------- Sicherung ----------
  let bk = $state(null);
  let ex = $state({ password: '', again: '', current: '', code: '', logs: false });
  let rs = $state({ file: null, password: '', current: '', code: '' });
  let busy = $state('');
  let restarting = $state(false);
  async function loadBackup() {
    bk = await get('/backup');
  }
  async function exportBackup() {
    if (ex.password !== ex.again) return run(() => Promise.reject(new Error('Die Passwörter der Sicherung stimmen nicht überein')));
    busy = 'export';
    const r = await run(() => postFile('/backup/export', { password: ex.password, current: ex.current, code: ex.code, logs: ex.logs }, 'vpnpanel.vpnbak'));
    busy = '';
    if (r) {
      toast(`Sicherung gespeichert: ${r.name}`);
      ex = { password: '', again: '', current: '', code: '', logs: ex.logs };
    }
  }
  async function restoreBackup() {
    if (!(await confirmDialog({ title: 'Sicherung einspielen?', text: 'Alle Nutzer, Server, Einstellungen und Zugangsdaten werden durch den Stand der Sicherung ersetzt. Das Panel startet dafür neu; die bisherigen Dateien bleiben auf dem Server in einem Ordner „restore-bak-…“ erhalten.', ok: 'Einspielen und neu starten', danger: true }))) return;
    const f = new FormData();
    f.append('password', rs.password);
    f.append('current', rs.current);
    f.append('code', rs.code);
    f.append('file', rs.file);
    busy = 'restore';
    const r = await run(() => upload('/backup/restore', f));
    busy = '';
    if (!r) return;
    rs = { file: null, password: '', current: '', code: '' };
    if (r.restart) {
      restarting = true;
      waitRestart();
    } else {
      toast('Sicherung abgelegt – wird beim nächsten Start des Dienstes eingespielt');
      loadBackup();
    }
  }
  // nach dem Neustart neu laden (die Anmeldung stammt dann aus der Sicherung)
  async function waitRestart() {
    await new Promise((r) => setTimeout(r, 4000));
    for (let i = 0; i < 60; i++) {
      try {
        const res = await fetch('/api/auth/me', { credentials: 'same-origin' });
        if (res.status === 200 || res.status === 401) {
          location.reload();
          return;
        }
      } catch {
        /* startet noch */
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
    restarting = false;
    toast('Das Panel ist nicht zurückgekommen – auf dem Server „systemctl status vpnpanel“ prüfen', 'error');
  }
  async function cancelRestore() {
    if (await run(() => del('/backup/restore'), 'Abgelegte Sicherung verworfen')) loadBackup();
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

  $effect(() => {
    const t = tab;
    if (t === 'general') loadSettings();
    if (t === 'security') loadSecurity();
    if (t === 'notify') loadNotify();
    if (t === 'backup') loadBackup();
    if (t === 'admins') loadAdmins();
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

<PageHead title="Einstellungen" subtitle="Server-Adresse, Sicherheit, Benachrichtigungen, Sicherung und Administratoren · System und Ereignisse stehen jetzt unter „Zustand“" />

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
    <div class="notice" style="grid-column:1/-1"><Icon name="user" /><div class="small">Passwort, Zwei-Faktor-Anmeldung, Sitzungen und das Anmeldeprotokoll findest du unter <a href="#/account">Mein Konto</a> (Klick auf deinen Namen unten links).</div></div>
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
  </div>
{:else if tab === 'notify' && mail && nstate}
  <div class="grid cols-2" style="max-width:1100px">
    <div class="card">
      <div class="card-head"><h3><Icon name="mail" size={16} /> Mailserver</h3>{#if mail.mail_enabled === '1'}<span class="badge ok">an</span>{:else}<span class="badge muted">aus</span>{/if}</div>
      <div class="card-pad stack">
        <label class="switch"><input type="checkbox" checked={mail.mail_enabled === '1'} onchange={(e) => (mail.mail_enabled = e.currentTarget.checked ? '1' : '0')} /><span class="track"></span> Benachrichtigungen per E-Mail verschicken</label>
        <div class="grid cols-2" style="grid-template-columns:minmax(0,3fr) minmax(0,1fr)">
          <div class="field"><label for="m-h">Mailserver (SMTP)</label><input id="m-h" class="input" bind:value={mail.smtp_host} placeholder="smtp.example.org" autocomplete="off" /></div>
          <div class="field"><label for="m-p">Port</label><input id="m-p" class="input" inputmode="numeric" bind:value={mail.smtp_port} /></div>
        </div>
        <div class="field">
          <span class="label">Verschlüsselung <Info title="Verschlüsselung" text="STARTTLS (meist Port 587) oder TLS (Port 465) – beides verschlüsselt. „Ohne“ nur für einen Mailserver im eigenen Netz ohne Anmeldung; ein Passwort wird nie unverschlüsselt gesendet." /></span>
          <div class="segmented" style="align-self:flex-start">
            {#each [['starttls', 'STARTTLS'], ['tls', 'TLS'], ['none', 'Ohne']] as [k, l]}
              <button class:active={mail.smtp_security === k} onclick={() => setSecurity(k)}>{l}</button>
            {/each}
          </div>
        </div>
        <div class="field"><label for="m-u">Benutzername <span class="muted">(leer = ohne Anmeldung)</span></label><input id="m-u" class="input" bind:value={mail.smtp_user} autocomplete="off" /></div>
        <div class="field">
          <label for="m-pw">Passwort <Info title="Passwort des Mailservers" text="Liegt nur in /etc/vpn/secrets.env auf dem Server (Rechte 600), nie in der Datenbank. Das Panel zeigt es nie wieder an." /></label>
          {#if editPw}
            <div class="row">
              <input id="m-pw" type="password" class="input grow" bind:value={smtpPw} autocomplete="new-password" placeholder={nstate.password_set ? 'neues Passwort' : 'Passwort des Postfachs'} />
              {#if nstate.password_set}<button class="btn ghost sm" onclick={() => { editPw = false; smtpPw = ''; }}>Abbrechen</button>{/if}
            </div>
          {:else}
            <div class="row"><span class="badge ok">hinterlegt</span><span class="grow"></span><button class="btn sm" onclick={() => (editPw = true)}>Ersetzen</button><button class="btn sm ghost danger" onclick={removeSmtpPw}>Entfernen</button></div>
          {/if}
        </div>
        <div class="field"><label for="m-f">Absender</label><input id="m-f" class="input" bind:value={mail.mail_from} placeholder="VPN-Panel <panel@example.org>" autocomplete="off" /></div>
        <div class="row">
          <button class="btn primary" onclick={saveMail}>Speichern</button>
          <button class="btn" onclick={testMail} disabled={testing || !session.user.email} title={session.user.email ? `an ${session.user.email}` : 'Erst in „Mein Konto“ eine E-Mail eintragen'}><Icon name="mail" size={15} /> {testing ? 'Sende …' : 'Testmail senden'}</button>
        </div>
        <p class="tiny muted" style="margin:0">Erst speichern, dann testen. Die Testmail geht an deine Adresse aus „Mein Konto“.</p>
      </div>
    </div>
    <div class="stack">
      <div class="card">
        <div class="card-head"><h3><Icon name="alert" size={16} /> Anlässe</h3></div>
        <div class="card-pad stack-sm">
          {#each nstate.events as ev}
            <label class="switch"><input type="checkbox" checked={evOn(ev.key)} onchange={(e) => toggleEv(ev.key, e.currentTarget.checked)} /><span class="track"></span> {ev.label}</label>
          {/each}
          <p class="tiny muted" style="margin:6px 0 0">Ausfälle werden nach zwei Prüfungen in Folge gemeldet (ca. 2 Minuten), die Wiederkehr nur nach einer Ausfallmeldung. Gleiche Meldungen höchstens alle 30 Minuten. Mit „Speichern“ links übernehmen.</p>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3><Icon name="users" size={16} /> Empfänger</h3></div>
        <div class="card-pad stack-sm">
          {#each nstate.recipients as r}
            <div class="row small"><Icon name="mail" size={14} /> {r}</div>
          {:else}
            <div class="notice warn"><Icon name="alert" /><div class="small">Noch kein Empfänger. Jeder Administrator trägt seine Adresse in <a href="#/account">Mein Konto</a> ein und schaltet Benachrichtigungen ein.</div></div>
          {/each}
          {#if nstate.sent?.length}
            <div class="tiny muted" style="margin-top:8px">Testmodus – nicht wirklich verschickt:</div>
            <pre class="code tiny" style="margin:0;max-height:160px">{nstate.sent.slice(-12).join('\n')}</pre>
          {/if}
        </div>
      </div>
    </div>
  </div>
{:else if tab === 'backup' && bk}
  <div class="grid cols-2" style="max-width:1100px">
    {#if bk.pending}
      <div class="notice warn" style="grid-column:1/-1">
        <Icon name="alert" />
        <div class="grow small">Eine Sicherung vom {date(bk.pending.created, true)} (Version {bk.pending.version}, {bk.pending.files} Dateien) liegt bereit und wird beim nächsten Start des Dienstes eingespielt.</div>
        <button class="btn sm" onclick={cancelRestore}>Verwerfen</button>
      </div>
    {/if}
    {#if restarting}
      <div class="notice" style="grid-column:1/-1"><Icon name="refresh" /><div class="small">Das Panel startet neu und spielt die Sicherung ein. Die Seite lädt danach von selbst neu – melde dich dann mit den Zugangsdaten aus der Sicherung an.</div></div>
    {/if}
    <div class="card">
      <div class="card-head"><h3><Icon name="download" size={16} /> Sicherung herunterladen</h3></div>
      <div class="card-pad stack">
        <p class="small muted" style="margin:0">Enthält Datenbank (Nutzer, Server, Schlüssel, Einstellungen, Statistik), <code>secrets.env</code> und die Zertifikate – verschlüsselt mit dem Passwort unten (AES-256, scrypt). Ohne dieses Passwort lässt sich die Datei nicht öffnen.</p>
        <div class="grid cols-2">
          <div class="field"><label for="b-p">Passwort der Sicherung</label><input id="b-p" type="password" class="input" bind:value={ex.password} autocomplete="new-password" placeholder="mind. {bk.min_password} Zeichen" /></div>
          <div class="field"><label for="b-a">Wiederholen</label><input id="b-a" type="password" class="input" bind:value={ex.again} autocomplete="new-password" /></div>
        </div>
        <label class="switch"><input type="checkbox" bind:checked={ex.logs} /><span class="track"></span> DNS- und Anmeldeprotokoll mitsichern (größer)</label>
        <div class="divider"></div>
        <div class="grid" class:cols-2={session.user.totp_enabled}>
          <div class="field"><label for="b-c">Dein Panel-Passwort</label><input id="b-c" type="password" class="input" bind:value={ex.current} autocomplete="current-password" /></div>
          {#if session.user.totp_enabled}<div class="field"><label for="b-t">2FA-Code</label><input id="b-t" class="input mono" bind:value={ex.code} inputmode="numeric" autocomplete="one-time-code" placeholder="123456" /></div>{/if}
        </div>
        <div><button class="btn primary" onclick={exportBackup} disabled={busy !== '' || ex.password.length < bk.min_password || !ex.current || (session.user.totp_enabled && ex.code.length < 6)}><Icon name="download" size={15} /> {busy === 'export' ? 'Erstelle …' : 'Sicherung herunterladen'}</button></div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h3><Icon name="upload" size={16} /> Sicherung einspielen</h3></div>
      <div class="card-pad stack">
        <p class="small muted" style="margin:0">Ersetzt den kompletten Stand des Panels. Die Datei wird zuerst geprüft (Passwort, Prüfsummen, Version); erst dann startet das Panel neu und spielt sie ein. Die bisherigen Dateien bleiben auf dem Server in <code>restore-bak-…</code>.</p>
        <div class="field"><label for="r-f">Datei (.vpnbak)</label><input id="r-f" type="file" class="input" accept=".vpnbak" onchange={(e) => (rs.file = e.currentTarget.files[0] || null)} /></div>
        <div class="field"><label for="r-p">Passwort der Sicherung</label><input id="r-p" type="password" class="input" bind:value={rs.password} autocomplete="off" /></div>
        <div class="divider"></div>
        <div class="grid" class:cols-2={session.user.totp_enabled}>
          <div class="field"><label for="r-c">Dein Panel-Passwort</label><input id="r-c" type="password" class="input" bind:value={rs.current} autocomplete="current-password" /></div>
          {#if session.user.totp_enabled}<div class="field"><label for="r-t">2FA-Code</label><input id="r-t" class="input mono" bind:value={rs.code} inputmode="numeric" autocomplete="one-time-code" placeholder="123456" /></div>{/if}
        </div>
        <div><button class="btn danger" onclick={restoreBackup} disabled={busy !== '' || restarting || !rs.file || !rs.password || !rs.current || (session.user.totp_enabled && rs.code.length < 6)}><Icon name="upload" size={15} /> {busy === 'restore' ? 'Prüfe …' : 'Prüfen und einspielen'}</button></div>
        {#if !bk.restart}<p class="tiny muted" style="margin:0">Ohne Dienstverwaltung wird die Sicherung erst beim nächsten Start eingespielt.</p>{/if}
      </div>
    </div>
    <div class="card card-pad" style="grid-column:1/-1">
      <div class="row small" style="gap:6px">
        <Icon name="terminal" size={15} /> Auf dem Server geht das auch per Kommandozeile, z. B. für eine nächtliche Sicherung:
        <Info title="Sicherung per Kommandozeile" wide>
          <pre>VPNPANEL_BACKUP_PASSWORD='…' vpn backup create /root/panel.vpnbak
vpn backup restore /root/panel.vpnbak
systemctl restart vpnpanel</pre>
          <p>Ohne Umgebungsvariable fragt <code>vpn backup</code> das Passwort ab. Mit <code>--ohne-protokolle</code> bleiben DNS- und Anmeldeprotokoll draußen.</p>
        </Info>
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
{/if}
