<script>
  import Icon from '../components/Icon.svelte';
  import Board from '../components/Board.svelte';
  import PageHead from '../components/PageHead.svelte';
  import QR from '../components/QR.svelte';
  import Info from '../components/Info.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { date, ago } from '../lib/format.js';
  import { session } from '../lib/state.svelte.js';
  import { confirmDialog } from '../components/Confirm.svelte';

  // ---------- Profil ----------
  let prof = $state({ username: session.user.username, email: session.user.email || '', notify: !!session.user.notify, current: '' });
  const needPw = $derived(prof.username.trim() !== session.user.username || prof.email.trim() !== (session.user.email || ''));
  async function saveProfile() {
    const r = await run(() => put('/auth/profile', { username: prof.username.trim(), email: prof.email.trim(), notify: prof.notify, current: prof.current }), 'Konto gespeichert');
    if (r) {
      session.user = r;
      prof = { username: r.username, email: r.email || '', notify: !!r.notify, current: '' };
    }
  }

  // ---------- Passwort ----------
  let pw = $state({ current: '', new: '', again: '' });
  async function changePw() {
    if (pw.new !== pw.again) return run(() => Promise.reject(new Error('Die neuen Passwörter stimmen nicht überein')));
    if (await run(() => post('/auth/password', { current: pw.current, new: pw.new }), 'Passwort geändert – andere Sitzungen wurden abgemeldet')) {
      pw = { current: '', new: '', again: '' };
      loadSessions();
    }
  }

  // ---------- 2FA ----------
  let totp = $state(null);
  let totpCode = $state('');
  let disablePw = $state('');
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

  // ---------- Sitzungen ----------
  let sessions = $state([]);
  async function loadSessions() {
    sessions = await get('/auth/sessions');
  }
  async function logoutOthers() {
    if (await run(() => del('/auth/sessions'), 'Andere Sitzungen beendet')) loadSessions();
  }

  // ---------- Anmeldungen ----------
  let logins = $state(null);
  let onlyFailed = $state(false);
  async function loadLogins() {
    logins = await get('/auth/logins?limit=100');
  }
  // Adresse eines Fehlversuchs von Hand sperren (Einstellungen → Sicherheit → Gesperrte Adressen)
  async function lockIP(ip) {
    if (!(await confirmDialog({ title: `${ip} sperren?`, text: 'Von dieser Adresse ist dann 7 Tage lang keine Anmeldung am Panel möglich. Entsperren unter Einstellungen → Sicherheit.', ok: 'Sperren', danger: true }))) return;
    await run(() => post('/security/locks', { net: ip, minutes: 10080, reason: 'aus dem Anmeldeprotokoll gesperrt' }), `${ip} gesperrt`);
  }
  const shown = $derived((logins?.entries || []).filter((l) => !onlyFailed || !l.ok).slice(0, 50));

  function device(agent) {
    if (!agent) return '–';
    const os = /Android/.test(agent) ? 'Android' : /iPhone|iPad/.test(agent) ? 'iOS' : /Windows/.test(agent) ? 'Windows' : /Mac OS/.test(agent) ? 'macOS' : /Linux/.test(agent) ? 'Linux' : '';
    const br = /Edg\//.test(agent) ? 'Edge' : /Firefox\//.test(agent) ? 'Firefox' : /Chrome\//.test(agent) ? 'Chrome' : /Safari\//.test(agent) ? 'Safari' : /curl|python|Go-http/i.test(agent) ? 'Skript' : '';
    return [br, os].filter(Boolean).join(' · ') || agent.slice(0, 40);
  }

  loadSessions();
  loadLogins();
</script>

<PageHead title="Mein Konto" subtitle="Name, E-Mail, Passwort, Zwei-Faktor-Anmeldung und Anmeldungen" />

{#snippet w_profile()}
  <div class="card">
    <div class="card-head"><h3><Icon name="user" size={16} /> Profil</h3><span class="muted small">seit {date(session.user.created)}</span></div>
    <div class="card-pad stack">
      <div class="field"><label for="p-u">Benutzername</label><input id="p-u" class="input" bind:value={prof.username} autocomplete="username" maxlength="32" /></div>
      <div class="field">
        <label for="p-e">E-Mail-Adresse <Info title="E-Mail" text="Für Benachrichtigungen bei Ausfällen. Den Mailserver stellst du unter Einstellungen → Benachrichtigungen ein." /></label>
        <input id="p-e" class="input" type="email" bind:value={prof.email} autocomplete="email" placeholder="name@example.org" />
      </div>
      <label class="switch"><input type="checkbox" bind:checked={prof.notify} disabled={!prof.email.trim()} /><span class="track"></span> Benachrichtigungen an diese Adresse schicken</label>
      {#if needPw}
        <div class="field"><label for="p-c">Aktuelles Passwort <span class="muted">(zum Ändern von Name oder E-Mail)</span></label><input id="p-c" type="password" class="input" bind:value={prof.current} autocomplete="current-password" /></div>
      {/if}
      <div><button class="btn primary" onclick={saveProfile} disabled={!prof.username.trim() || (needPw && !prof.current)}>Speichern</button></div>
    </div>
  </div>
{/snippet}
{#snippet w_password()}
  <div class="card">
    <div class="card-head"><h3><Icon name="key" size={16} /> Passwort ändern</h3></div>
    <div class="card-pad stack">
      <div class="field"><label for="pw1">Aktuelles Passwort</label><input id="pw1" type="password" class="input" bind:value={pw.current} autocomplete="current-password" /></div>
      <div class="field"><label for="pw2">Neues Passwort</label><input id="pw2" type="password" class="input" bind:value={pw.new} autocomplete="new-password" placeholder="mindestens 10 Zeichen" /></div>
      <div class="field"><label for="pw3">Wiederholen</label><input id="pw3" type="password" class="input" bind:value={pw.again} autocomplete="new-password" /></div>
      <div><button class="btn primary" onclick={changePw} disabled={!pw.current || !pw.new}>Ändern</button></div>
    </div>
  </div>
{/snippet}
{#snippet w_totp()}
  <div class="card">
    <div class="card-head"><h3><Icon name="shield" size={16} /> Zwei-Faktor-Anmeldung</h3>{#if session.user.totp_enabled}<span class="badge ok">aktiv</span>{:else}<span class="badge warn">aus</span>{/if}</div>
    <div class="card-pad stack">
      {#if session.user.totp_enabled}
        <p class="muted small" style="margin:0">Bei jeder Anmeldung wird ein Code aus deiner Authenticator-App abgefragt.</p>
        <div class="field"><label for="dpw">Zum Abschalten Passwort eingeben</label><input id="dpw" type="password" class="input" bind:value={disablePw} autocomplete="current-password" /></div>
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
        <div class="row"><input class="input mono" style="max-width:160px" placeholder="123456" bind:value={totpCode} inputmode="numeric" autocomplete="one-time-code" /><button class="btn primary" onclick={enableTotp} disabled={totpCode.length < 6}>Aktivieren</button></div>
      {:else}
        <p class="muted small" style="margin:0">Schützt das Panel zusätzlich mit einem Code vom Handy. Dringend empfohlen, da das Panel aus dem Internet erreichbar ist.</p>
        <div><button class="btn primary" onclick={startTotp}>2FA einrichten</button></div>
      {/if}
    </div>
  </div>
{/snippet}
{#snippet w_sessions()}
  <div class="card">
    <div class="card-head"><h3><Icon name="eye" size={16} /> Angemeldete Sitzungen</h3><button class="btn sm" onclick={logoutOthers} disabled={sessions.length < 2}>Alle anderen abmelden</button></div>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Gerät</th><th>IP</th><th>Zuletzt aktiv</th></tr></thead>
        <tbody>
          {#each sessions as se}
            <tr>
              <td class="small" title={se.agent}>{device(se.agent)} {#if se.current}<span class="badge accent">diese</span>{/if}<div class="tiny muted">seit {date(se.created, true)}</div></td>
              <td class="mono small">{se.ip}</td>
              <td class="small nowrap">{ago(se.last_used)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/snippet}
{#snippet w_logins()}
  <div class="card">
    <div class="card-head">
      <h3><Icon name="list" size={16} /> Anmeldungen am Panel <Info title="Anmeldungen" text="Alle Anmeldeversuche am Panel, auch mit unbekanntem Benutzernamen. Nach 8 Fehlversuchen in 15 Minuten wird eine Adresse bzw. ein Name für 15 Minuten gesperrt. Aufbewahrt werden 90 Tage." /></h3>
      <div class="row">
        <label class="switch small"><input type="checkbox" bind:checked={onlyFailed} /><span class="track"></span> nur fehlgeschlagene</label>
        <button class="btn sm icon ghost" title="Aktualisieren" onclick={loadLogins}><Icon name="refresh" size={15} /></button>
      </div>
    </div>
    {#if logins}
      <div class="tiles">
        <div class="tile"><span class="label">Erfolgreich · 24 h</span><b class="ok-text">{logins.day.ok}</b></div>
        <div class="tile"><span class="label">Fehlgeschlagen · 24 h</span><b class:bad-text={logins.day.failed > 0}>{logins.day.failed}</b></div>
        <div class="tile"><span class="label">Erfolgreich · 30 Tage</span><b>{logins.month.ok}</b></div>
        <div class="tile"><span class="label">Fehlgeschlagen · 30 Tage</span><b class:warn-text={logins.month.failed > 0}>{logins.month.failed}</b></div>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Zeit</th><th>Ergebnis</th><th>Benutzer</th><th>Adresse</th><th>Gerät</th></tr></thead>
          <tbody>
            {#each shown as l (l.id)}
              <tr>
                <td class="small nowrap">{date(l.ts, true)}</td>
                <td class="small">{#if l.ok}<span class="badge ok">erfolgreich</span>{:else}<span class="badge bad">fehlgeschlagen</span>{/if} <span class="muted">{l.reason}</span></td>
                <td class="small strong ellipsis" style="max-width:180px" title={l.username}>{l.username || '–'}</td>
                <td class="mono small nowrap">{l.ip}{#if !l.ok && l.ip}&nbsp;<button class="btn sm icon ghost" title="Diese Adresse sperren" onclick={() => lockIP(l.ip)}><Icon name="lock" size={13} /></button>{/if}</td>
                <td class="small muted" title={l.agent}>{device(l.agent)}</td>
              </tr>
            {:else}
              <tr><td class="empty" colspan="5">{onlyFailed ? 'Keine fehlgeschlagenen Anmeldungen' : 'Noch keine Anmeldungen protokolliert'}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/snippet}
<Board
  id="account"
  widgets={[
    { id: 'profile', title: 'Profil', w: 6, body: w_profile },
    { id: 'password', title: 'Passwort ändern', w: 6, body: w_password },
    { id: 'totp', title: 'Zwei-Faktor-Anmeldung', w: 6, body: w_totp },
    { id: 'sessions', title: 'Angemeldete Sitzungen', w: 6, body: w_sessions },
    { id: 'logins', title: 'Anmeldungen am Panel', w: 12, body: w_logins },
  ]}
/>

<style>
  .tiles {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }
  .tile {
    background: var(--panel);
    padding: 12px 18px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .tile b {
    font-size: 22px;
    font-weight: 650;
  }
  @media (max-width: 700px) {
    .tiles {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
</style>
