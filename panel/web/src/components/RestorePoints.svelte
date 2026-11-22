<script>
  // Wiederherstellungspunkte: Sicherungen, die das Panel selbst auf dem Server ablegt (täglich,
  // vor Updates, vor dem Einspielen und von Hand). Einspielen und Herunterladen nur mit Passwort/2FA.
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import Modal from './Modal.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run, postFile } from '../lib/api.js';
  import { date, bytes } from '../lib/format.js';
  import { session, toast } from '../lib/state.svelte.js';

  let { onrestart } = $props();

  let d = $state(null);
  let note = $state('');
  let busy = $state('');
  let keep = $state(7);
  // Dialog für Einspielen/Herunterladen
  let dlg = $state({ open: false, mode: '', point: null, password: '', again: '', current: '', code: '' });

  const KIND = {
    auto: ['täglich', ''],
    manual: ['von Hand', 'accent'],
    update: ['vor Update', 'warn'],
    restore: ['vor Wiederherstellung', 'muted'],
  };

  async function load() {
    try {
      d = await get('/backup/points');
      keep = d.keep;
    } catch {}
  }
  load();

  async function create() {
    busy = 'create';
    const r = await run(() => post('/backup/points', { note: note.trim() }), 'Wiederherstellungspunkt angelegt');
    busy = '';
    if (r) {
      note = '';
      load();
    }
  }
  async function setAuto(on) {
    if (await run(() => put('/settings', { backup_auto: on ? '1' : '0' }), on ? 'Tägliche Punkte an' : 'Tägliche Punkte aus')) load();
  }
  async function saveKeep() {
    if (keep === d.keep) return;
    if (await run(() => put('/settings', { backup_keep: String(keep) }), 'Gespeichert')) load();
    else keep = d.keep;
  }
  async function remove(p) {
    if (!(await confirmDialog({ title: 'Wiederherstellungspunkt löschen?', text: `Der Punkt vom ${date(p.created, true)} wird vom Server gelöscht.`, ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/backup/points/${p.id}`), 'Gelöscht')) load();
  }
  function open(mode, p) {
    dlg = { open: true, mode, point: p, password: '', again: '', current: '', code: '' };
  }
  const credsOk = $derived(!!dlg.current && (!session.user?.totp_enabled || dlg.code.replaceAll(' ', '').length >= 6));
  const pwOk = $derived(dlg.mode !== 'download' || (dlg.password.length >= (d?.min_password || 12) && dlg.password === dlg.again));

  async function submit() {
    const p = dlg.point;
    if (dlg.mode === 'download') {
      busy = 'download';
      const r = await run(() => postFile(`/backup/points/${p.id}/download`, { password: dlg.password, current: dlg.current, code: dlg.code }, 'vpnpanel.vpnbak'));
      busy = '';
      if (r) {
        dlg.open = false;
        toast(`Sicherung gespeichert: ${r.name}`);
      }
      return;
    }
    busy = 'restore';
    const r = await run(() => post(`/backup/points/${p.id}/restore`, { current: dlg.current, code: dlg.code }));
    busy = '';
    if (!r) return;
    dlg.open = false;
    if (r.restart) onrestart?.();
    else {
      toast('Abgelegt – wird beim nächsten Start des Dienstes eingespielt');
      load();
    }
  }
</script>

<div class="card" style="grid-column:1/-1">
  <div class="card-head">
    <h3>
      <Icon name="archive" size={16} /> Wiederherstellungspunkte
      <Info title="Wiederherstellungspunkte" wide>
        <p>Das Panel legt Sicherungen selbst auf dem Server ab (Datenordner, Unterordner <span class="mono">backups</span>):</p>
        <ul>
          <li><b>täglich</b> (abschaltbar, die letzten {d?.keep ?? 7} bleiben),</li>
          <li><b>vor jedem Update</b> aus dem Panel und <b>vor jeder Wiederherstellung</b> (je die letzten {d?.keep_update ?? 5}),</li>
          <li><b>von Hand</b> – diese löscht das Panel nie selbst.</li>
        </ul>
        <p>Gesichert werden Datenbank (ohne DNS- und Anmeldeprotokoll), Zugangsdaten und Zertifikate – wie bei „Sicherung herunterladen“. Die Punkte sind mit einem Schlüssel dieser Installation verschlüsselt; zum Herunterladen vergibst du ein eigenes Passwort, damit sich die Datei auch auf einem neuen Server einspielen lässt.</p>
        <p>Beim Einspielen sichert das Panel den aktuellen Stand vorher als eigenen Punkt – ein Fehlgriff lässt sich also rückgängig machen.</p>
      </Info>
    </h3>
    {#if d}<span class="muted small">{d.points.length} Punkte · {bytes(d.total)}</span>{/if}
  </div>
  {#if !d}
    <div class="card-pad muted small">Lade …</div>
  {:else}
    <div class="card-pad stack-sm">
      <div class="row wrap" style="gap:8px">
        <input class="input grow" style="min-width:200px" bind:value={note} maxlength="200" placeholder="Notiz (optional), z. B. „vor Umbau der Gruppen“" onkeydown={(e) => e.key === 'Enter' && create()} />
        <button class="btn primary" onclick={create} disabled={!!busy}><Icon name="plus" size={15} /> {busy === 'create' ? 'Sichere …' : 'Punkt anlegen'}</button>
      </div>
      <div class="row wrap" style="gap:14px">
        <label class="switch small"><input type="checkbox" checked={d.auto} onchange={(e) => setAuto(e.currentTarget.checked)} /><span class="track"></span> Täglich automatisch</label>
        <label class="small row" style="gap:6px">Behalten: <input class="input sm" type="number" min="1" max="90" style="width:70px" bind:value={keep} onchange={saveKeep} disabled={!d.auto} /> tägliche</label>
      </div>
      {#if d.error}<div class="notice bad small"><Icon name="alert" size={16} /><span>{d.error}</span></div>{/if}
    </div>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Zeitpunkt</th><th>Art</th><th>Version</th><th class="num">Größe</th><th></th></tr></thead>
        <tbody>
          {#each d.points as p (p.id)}
            <tr>
              <td>
                <div class="small strong nowrap">{date(p.created, true)}</div>
                {#if p.note}<div class="tiny muted">{p.note}</div>{/if}
              </td>
              <td><span class="badge {KIND[p.kind]?.[1] || ''}">{KIND[p.kind]?.[0] || p.kind}</span></td>
              <td class="mono small">{p.version}</td>
              <td class="num small nowrap">{bytes(p.size)}</td>
              <td class="actions nowrap">
                <button class="btn sm" onclick={() => open('restore', p)} title="Diesen Stand wiederherstellen"><Icon name="refresh" size={14} /> Einspielen</button>
                <button class="btn sm ghost icon" onclick={() => open('download', p)} title="Herunterladen (mit eigenem Passwort)" aria-label="Herunterladen"><Icon name="download" size={14} /></button>
                <button class="btn sm ghost icon" onclick={() => remove(p)} title="Löschen" aria-label="Löschen"><Icon name="trash" size={14} /></button>
              </td>
            </tr>
          {:else}
            <tr><td colspan="5" class="empty small">Noch keine Punkte. {d.auto ? 'Der erste tägliche entsteht wenige Minuten nach dem Start des Dienstes.' : ''}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal bind:open={dlg.open} title={dlg.mode === 'download' ? 'Punkt herunterladen' : 'Punkt einspielen?'} subtitle={dlg.point ? `${date(dlg.point.created, true)} · Version ${dlg.point.version}` : ''} width={480}>
  <div class="stack">
    {#if dlg.mode === 'restore'}
      <div class="notice warn small">
        <Icon name="alert" size={16} />
        <span>Nutzer, Server, Einstellungen und Zugangsdaten werden durch diesen Stand ersetzt; Änderungen danach gehen verloren. Der aktuelle Stand wird vorher als eigener Punkt gesichert. Das Panel startet dafür neu.</span>
      </div>
    {:else}
      <p class="small muted" style="margin:0">Die Datei wird mit diesem Passwort neu verschlüsselt. Ohne das Passwort lässt sie sich nicht einspielen.</p>
      <div class="grid cols-2">
        <div class="field"><label for="rp-p">Passwort der Sicherung</label><input id="rp-p" type="password" class="input" bind:value={dlg.password} autocomplete="new-password" placeholder="mind. {d?.min_password || 12} Zeichen" /></div>
        <div class="field"><label for="rp-a">Wiederholen</label><input id="rp-a" type="password" class="input" bind:value={dlg.again} autocomplete="new-password" /></div>
      </div>
    {/if}
    <div class="grid cols-2">
      <div class="field"><label for="rp-c">Dein Panel-Passwort</label><input id="rp-c" type="password" class="input" bind:value={dlg.current} autocomplete="current-password" /></div>
      {#if session.user?.totp_enabled}<div class="field"><label for="rp-t">2FA-Code</label><input id="rp-t" class="input mono" bind:value={dlg.code} inputmode="numeric" autocomplete="one-time-code" placeholder="123456" /></div>{/if}
    </div>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (dlg.open = false)}>Abbrechen</button>
    <button class="btn {dlg.mode === 'restore' ? 'danger' : 'primary'}" onclick={submit} disabled={!!busy || !credsOk || !pwOk}>
      {#if dlg.mode === 'restore'}<Icon name="refresh" size={15} /> {busy === 'restore' ? 'Prüfe …' : 'Einspielen und neu starten'}{:else}<Icon name="download" size={15} /> {busy === 'download' ? 'Erstelle …' : 'Herunterladen'}{/if}
    </button>
  {/snippet}
</Modal>

<style>
  .actions {
    text-align: right;
  }
  .actions .btn + .btn {
    margin-left: 4px;
  }
</style>
