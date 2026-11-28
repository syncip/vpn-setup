<script>
  // Update des Panels aus dem Webinterface: neues Release laden (Prüfsumme von GitHub), vorher
  // Wiederherstellungspunkt, Austausch durch einen eigenen Wächter mit automatischem Rücksprung.
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import Modal from './Modal.svelte';
  import { get, post, run } from '../lib/api.js';
  import { date, bytes } from '../lib/format.js';
  import { session, meta, toast } from '../lib/state.svelte.js';

  let st = $state(null);
  let busy = $state('');
  let offline = $state(false); // Panel startet gerade neu
  let showLog = $state(false);
  let showNotes = $state(false);
  let dlg = $state({ open: false, mode: '', current: '', code: '' });
  let startedHere = false; // dieses Fenster hat das Update gestartet → danach neu laden

  const STATE = {
    download: 'Lädt und prüft das neue Programm …',
    backup: 'Wiederherstellungspunkt angelegt …',
    apply: 'Programm wird ausgetauscht …',
    restart: 'Panel startet neu …',
    rollback: 'Rücksprung läuft …',
    ok: 'Erfolgreich',
    failed: 'Abgebrochen',
    rolled_back: 'Zurückgesetzt',
  };
  const running = $derived(!!st?.run && !['ok', 'failed', 'rolled_back'].includes(st.run.state));
  const info = $derived(st?.info || {});

  async function load() {
    try {
      const r = await get('/update/status');
      const wasOffline = offline;
      offline = false;
      // nach dem Neustart: neue Version läuft → Seite neu laden (neue Oberfläche)
      if ((startedHere || wasOffline) && r.info?.current && st?.info?.current && r.info.current !== st.info.current) {
        toast(`Panel läuft jetzt mit ${r.info.current}`);
        setTimeout(() => location.reload(), 1500);
      }
      st = r;
    } catch {
      if (running || startedHere) offline = true;
    }
  }
  load();
  $effect(() => {
    const every = running || offline ? 2000 : 60000;
    const t = setInterval(load, every);
    return () => clearInterval(t);
  });

  async function check() {
    busy = 'check';
    await run(() => post('/update/check'));
    busy = '';
    load();
    try {
      Object.assign(meta, await get('/meta'));
    } catch {}
  }
  function open(mode) {
    dlg = { open: true, mode, current: '', code: '' };
  }
  const credsOk = $derived(!!dlg.current && (!session.user?.totp_enabled || dlg.code.replaceAll(' ', '').length >= 6));
  async function submit() {
    busy = dlg.mode;
    const r = await run(() => post(dlg.mode === 'install' ? '/update/install' : '/update/rollback', { current: dlg.current, code: dlg.code }));
    busy = '';
    if (!r) return;
    dlg.open = false;
    startedHere = true;
    st = r;
    showLog = true;
  }
</script>

<div class="card">
  <div class="card-head">
    <h3>
      <Icon name="shield" size={16} /> Panel aktualisieren
      <Info title="Update aus dem Panel" wide>
        <p>„Installieren“ lädt das Programm des neuesten Releases von GitHub und prüft es gegen die SHA-256-Prüfsumme, die GitHub zur Datei angibt. Vorher legt das Panel einen <b>Wiederherstellungspunkt</b> an und hebt das laufende Programm auf.</p>
        <p>Ein eigener Wächter tauscht das Programm aus und startet den Dienst neu. Meldet sich die neue Version nicht innerhalb von 2 Minuten oder stürzt sie danach ab, setzt er <b>automatisch</b> das alte Programm und den Wiederherstellungspunkt zurück.</p>
        <p>Nach einem Update kannst du auch selbst zur vorherigen Version zurück – Änderungen seit dem Update gehen dabei verloren (der Stand davor wird vorher gesichert).</p>
        <p><span class="mono">vpn-setup.sh</span> führt das Panel nicht aus (Pakete, Xray, Hysteria2). Ändert ein Release auch das Setup, steht hier ein Hinweis.</p>
      </Info>
    </h3>
    {#if st}
      {#if running || offline}<span class="badge warn">läuft</span>
      {:else if info.available}<span class="badge warn">{info.latest}</span>
      {:else if info.latest}<span class="badge ok">aktuell</span>{/if}
    {/if}
  </div>
  {#if !st}
    <div class="card-pad muted small">Lade …</div>
  {:else}
    <div class="card-pad stack-sm">
      <div class="row wrap" style="gap:16px">
        <div><div class="tiny muted">Installiert</div><div class="mono strong">{info.current}</div></div>
        <div><div class="tiny muted">Neueste</div><div class="mono strong">{info.latest || '–'}</div></div>
        <span class="grow"></span>
        <button class="btn" onclick={check} disabled={!!busy || running}><Icon name="refresh" size={15} /> {busy === 'check' ? 'Prüfe …' : 'Jetzt prüfen'}</button>
        {#if info.available && !st.docker}
          <button class="btn primary" onclick={() => open('install')} disabled={!!busy || running || !info.can_install} title={info.install_reason || ''}><Icon name="download" size={15} /> {info.latest} installieren</button>
        {/if}
      </div>
      {#if st.dry_run}<div class="notice warn small"><Icon name="alert" size={16} /><span>Testmodus – Beispiel-Release, der Ablauf wird nur gezeigt.</span></div>{/if}
      {#if info.disabled}<div class="notice small"><Icon name="info" size={16} /><span>Die Online-Prüfung ist ausgeschaltet (Einstellungen → Allgemein).</span></div>{/if}
      {#if info.error}<div class="notice bad small"><Icon name="alert" size={16} /><span>Prüfung: {info.error}</span></div>{/if}
      {#if st.docker}<div class="notice small"><Icon name="info" size={16} /><span>Läuft im Docker-Container: Updates kommen als neues Image – auf dem Host <code>docker compose pull &amp;&amp; docker compose up -d</code>. Vor dem Start einer neuen Version legt das Panel automatisch einen Wiederherstellungspunkt an.</span></div>{/if}
      {#if info.available && !info.can_install && info.install_reason && !st.docker}<div class="notice bad small"><Icon name="alert" size={16} /><span>Installieren nicht möglich: {info.install_reason}</span></div>{/if}
      {#if info.available && info.setup_changed}
        <div class="notice warn small">
          <Icon name="alert" size={16} />
          <span>Dieses Release ändert auch <span class="mono">vpn-setup.sh</span> (z. B. neue Pakete). Nach dem Update im Container zusätzlich <span class="mono">bash vpn-setup.sh</span> ausführen – oder das Update gleich so einspielen.</span>
        </div>
      {/if}
      {#if info.available && info.notes}
        <button class="btn ghost sm" style="align-self:flex-start" onclick={() => (showNotes = !showNotes)}><span class="chev" class:open={showNotes}><Icon name="chevron-down" size={14} /></span> Änderungen in {info.latest}{info.size ? ` · ${bytes(info.size)}` : ''}</button>
        {#if showNotes}<pre class="notes small">{info.notes}</pre>{/if}
        {#if info.url}<a class="tiny" href={info.url} target="_blank" rel="noopener noreferrer">Release auf GitHub</a>{/if}
      {/if}

      {#if offline}
        <div class="notice small"><Icon name="refresh" size={16} /><span>Das Panel startet neu … die Seite lädt danach von selbst neu.</span></div>
      {/if}
      {#if st.run}
        {@const r = st.run}
        <div class="run" class:bad={r.state === 'failed' || r.state === 'rolled_back'} class:ok={r.state === 'ok'}>
          <div class="row wrap" style="gap:8px">
            <Icon name={r.state === 'ok' ? 'check' : r.state === 'failed' || r.state === 'rolled_back' ? 'alert' : 'refresh'} size={16} />
            <span class="small strong">{r.mode === 'rollback' ? 'Rücksprung' : 'Update'} {r.from} → {r.to}: {STATE[r.state] || r.state}</span>
            <span class="grow"></span>
            <span class="tiny muted">{date(r.finished || r.started, true)}</span>
            {#if r.log?.length}<button class="btn ghost sm" onclick={() => (showLog = !showLog)}>{showLog ? 'Ablauf ausblenden' : 'Ablauf'}</button>{/if}
          </div>
          {#if r.error}<div class="small" style="margin-top:4px">{r.error}</div>{/if}
          {#if showLog && r.log?.length}<pre class="log tiny">{r.log.join('\n')}</pre>{/if}
        </div>
      {/if}
      {#if st.rollback && !running}
        <div class="row wrap small" style="gap:8px">
          <span class="muted">Probleme mit der neuen Version?</span>
          <button class="btn sm" onclick={() => open('rollback')} disabled={!!busy}><Icon name="refresh" size={14} /> Zurück zu {st.rollback.to}</button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<Modal bind:open={dlg.open} title={dlg.mode === 'install' ? `${info.latest} installieren?` : `Zurück zu ${st?.rollback?.to}?`} width={480}>
  <div class="stack">
    {#if dlg.mode === 'install'}
      <p class="small" style="margin:0">Das Panel legt einen Wiederherstellungspunkt an, tauscht das Programm aus und startet neu (meist unter einer Minute). VPN-Verbindungen bleiben bestehen; WireGuard läuft im Kernel weiter.</p>
      {#if info.setup_changed}<div class="notice warn small"><Icon name="alert" size={16} /><span>Danach zusätzlich <span class="mono">bash vpn-setup.sh</span> im Container ausführen.</span></div>{/if}
    {:else}
      <div class="notice warn small"><Icon name="alert" size={16} /><span>Programm und Daten gehen auf den Stand vor dem Update zurück – Änderungen seither gehen verloren (der aktuelle Stand wird vorher als Wiederherstellungspunkt gesichert).</span></div>
    {/if}
    <div class="grid cols-2">
      <div class="field"><label for="pu-c">Dein Panel-Passwort</label><input id="pu-c" type="password" class="input" bind:value={dlg.current} autocomplete="current-password" /></div>
      {#if session.user?.totp_enabled}<div class="field"><label for="pu-t">2FA-Code</label><input id="pu-t" class="input mono" bind:value={dlg.code} inputmode="numeric" autocomplete="one-time-code" placeholder="123456" /></div>{/if}
    </div>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (dlg.open = false)}>Abbrechen</button>
    <button class="btn {dlg.mode === 'install' ? 'primary' : 'danger'}" onclick={submit} disabled={!!busy || !credsOk}>
      {#if dlg.mode === 'install'}<Icon name="download" size={15} /> {busy === 'install' ? 'Startet …' : 'Installieren'}{:else}<Icon name="refresh" size={15} /> {busy === 'rollback' ? 'Startet …' : 'Zurückspringen'}{/if}
    </button>
  {/snippet}
</Modal>

<style>
  .chev {
    display: inline-flex;
    transition: transform 0.15s;
    transform: rotate(-90deg);
  }
  .chev.open {
    transform: none;
  }
  .run {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 12px;
  }
  .run.ok {
    border-color: var(--ok);
  }
  .run.bad {
    border-color: var(--warn);
  }
  .log,
  .notes {
    margin: 8px 0 0;
    max-height: 260px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
    background: var(--bg-soft, var(--surface-2, rgba(127, 127, 127, 0.08)));
    padding: 8px 10px;
    border-radius: 6px;
  }
</style>
