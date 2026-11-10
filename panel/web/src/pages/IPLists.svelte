<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { PROTO_LABEL, ago, fmtNum } from '../lib/format.js';

  let lists = $state([]);
  let servers = $state([]);
  let error = $state('');
  let loaded = $state(false);

  async function load() {
    const [l, s] = await Promise.all([get('/iplists'), get('/servers')]);
    lists = l.lists;
    error = l.error || '';
    servers = s;
    loaded = true;
  }
  load();
  $effect(() => {
    // Online-Listen laden im Hintergrund – Stand nachziehen
    const t = setInterval(() => !open && load(), 15000);
    return () => clearInterval(t);
  });

  const MODE = {
    block: ['bad', 'lock', 'Sperrliste'],
    allow: ['ok', 'check', 'Freigabeliste'],
    targets: ['accent', 'route', 'Zielliste'],
  };
  const REFRESH = [
    [0, 'nur von Hand'],
    [1, 'stündlich'],
    [6, 'alle 6 Stunden'],
    [12, 'alle 12 Stunden'],
    [24, 'täglich'],
    [168, 'wöchentlich'],
  ];
  const when = (ts) => (ago(ts) === 'online' ? 'gerade eben' : ago(ts));
  const refreshText = (h) => REFRESH.find((r) => r[0] === h)?.[1] || `alle ${h} Stunden`;

  let busy = $state(0);
  async function refresh(l) {
    busy = l.id;
    await run(() => post(`/iplists/${l.id}/refresh`, {}), 'Liste neu geladen');
    busy = 0;
    load();
  }

  const srvById = $derived(Object.fromEntries(servers.map((s) => [s.id, s])));

  let open = $state(false);
  let cur = $state(null);
  let form = $state({});

  function openList(l = null) {
    cur = l;
    form = l
      ? { name: l.name, enabled: l.enabled, mode: l.mode, entries: l.entries.join('\n'), all: l.all, servers: [...l.servers], url: l.url || '', refresh: l.refresh || 0 }
      : { name: '', enabled: true, mode: 'block', entries: '', all: true, servers: [], url: '', refresh: 24 };
    open = true;
  }
  function toggleServer(id) {
    form.servers = form.servers.includes(id) ? form.servers.filter((x) => x !== id) : [...form.servers, id];
  }
  async function save() {
    const body = $state.snapshot(form);
    body.refresh = Number(body.refresh) || 0;
    body.url = (body.url || '').trim();
    const r = cur ? await run(() => put(`/iplists/${cur.id}`, body), 'Liste gespeichert') : await run(() => post('/iplists', body), 'Liste angelegt');
    if (r) {
      open = false;
      load();
    }
  }
  async function toggle(l) {
    if (await run(() => put(`/iplists/${l.id}`, { enabled: !l.enabled }), l.enabled ? 'Liste deaktiviert' : 'Liste aktiviert')) load();
  }
  async function remove(l) {
    if (!(await confirmDialog({ title: `Liste ${l.name} löschen?`, text: 'Die Regeln werden sofort entfernt.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/iplists/${l.id}`), 'Liste gelöscht')) load();
  }

  const entryCount = $derived((form.entries || '').split('\n').map((l) => l.replace(/#.*/, '').trim()).filter(Boolean).length);
</script>

<PageHead title="IP-Listen" subtitle="Sperr- und Freigabelisten für die Verbindung zu deinen Diensten, Ziellisten für Ziel-Regeln – auch als Online-Listen">
  <button class="btn primary" onclick={() => openList()}><Icon name="plus" size={16} /> Liste anlegen</button>
</PageHead>

{#if error}<div class="notice bad" style="margin-bottom:16px"><Icon name="alert" /><span>{error}</span></div>{/if}

<div class="grid cols-2">
  {#each lists as l}
    <div class="card lst" class:off={!l.enabled}>
      <div class="card-head">
        <div>
          <h3>{l.name}</h3>
          <div class="muted tiny">{fmtNum(l.total)} Einträge{#if l.url && l.entries.length}&nbsp;({fmtNum(l.entries.length)} eigene){/if}</div>
        </div>
        <span class="badge {MODE[l.mode][0]}"><Icon name={MODE[l.mode][1]} size={13} /> {MODE[l.mode][2]}</span>
      </div>
      <div class="card-pad stack" style="gap:10px">
        {#if l.url}
          <div class="online small">
            <div class="row" style="gap:6px"><Icon name="globe" size={14} /><span class="mono tiny url" title={l.url}>{l.url}</span></div>
            <div class="tiny" class:bad-text={l.status?.error}>
              {#if l.status?.error}
                <Icon name="alert" size={12} /> {l.status.error}{#if l.status.at}&nbsp;– Stand von {when(l.status.at)} bleibt aktiv{/if}
              {:else if l.status?.at}
                <span class="muted">Geladen {when(l.status.at)} · {fmtNum(l.status.count)} Einträge{l.status.skipped ? ` · ${fmtNum(l.status.skipped)} Zeilen nicht lesbar` : ''} · {refreshText(l.refresh)}</span>
              {:else}
                <span class="muted">Wird geladen …</span>
              {/if}
            </div>
          </div>
        {/if}
        <div class="small">
          {#if l.mode === 'targets'}
            <span class="muted">{l.used_by ? `In ${l.used_by} Ziel-Regel${l.used_by > 1 ? 'n' : ''} verwendet` : 'Noch in keiner Ziel-Regel verwendet (Proxy → Ziel-Regeln)'}</span>
          {:else if l.all}
            <span class="badge accent">Alle Dienste</span>
          {:else}
            <div class="row wrap" style="gap:6px">
              {#each l.servers as id}
                {@const s = srvById[id]}
                {#if s}<span class="badge"><ProtoLogo id={s.protocol} size={14} /> {s.name}</span>{/if}
              {:else}
                <span class="muted">Keinem Dienst zugeordnet</span>
              {/each}
            </div>
          {/if}
        </div>
        <div class="preview mono tiny">{l.entries.slice(0, 6).join('  ·  ')}{l.entries.length > 6 ? `  · … (+${l.entries.length - 6})` : ''}</div>
      </div>
      <div class="actions">
        <button class="btn sm" onclick={() => openList(l)}><Icon name="edit" size={15} /> Bearbeiten</button>
        <button class="btn sm ghost" onclick={() => toggle(l)}><Icon name="power" size={15} /> {l.enabled ? 'Deaktivieren' : 'Aktivieren'}</button>
        {#if l.url}<button class="btn sm ghost" onclick={() => refresh(l)} disabled={busy === l.id}><Icon name="refresh" size={15} /> {busy === l.id ? 'Lädt …' : 'Neu laden'}</button>{/if}
        <span class="grow"></span>
        <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(l)}><Icon name="trash" size={15} /></button>
      </div>
    </div>
  {/each}
</div>

{#if loaded && !lists.length}
  <div class="card empty"><h3>Noch keine IP-Listen</h3><p>Sperre einzelne Adressen oder Netze – oder erlaube einem Dienst nur bestimmte Adressen.</p><button class="btn primary" onclick={() => openList()}>Liste anlegen</button></div>
{/if}

<div class="notice" style="margin-top:18px">
  <Icon name="info" />
  <span>
    Gesperrte Adressen können sich nicht mehr verbinden; bestehende Verbindungen werden getrennt. Gibt es für einen Dienst eine Freigabeliste, dürfen nur deren
    Adressen verbinden – Sperrlisten gelten trotzdem. Das Webinterface und die Abo-Links sind davon nicht betroffen. Online-Listen lädt der Server regelmäßig
    neu (eine Adresse oder ein Netz pro Zeile, z. B. Sperrlisten von FireHOL oder Spamhaus); schlägt ein Abruf fehl, bleibt der letzte Stand aktiv.
  </span>
</div>

<Modal bind:open title={cur ? `Liste ${cur.name}` : 'IP-Liste anlegen'} width={680}>
  <div class="stack">
    <div class="grid cols-2">
      <div class="field"><label for="ipl-name">Name</label><input id="ipl-name" class="input" bind:value={form.name} /></div>
      <div class="field">
        <label for="ipl-mode">Art</label>
        <select id="ipl-mode" class="input" bind:value={form.mode}>
          <option value="block">Sperrliste – diese Adressen nie</option>
          <option value="allow">Freigabeliste – nur diese Adressen</option>
          <option value="targets">Zielliste – Ziele für Ziel-Regeln</option>
        </select>
      </div>
    </div>
    <div class="field">
      <label for="ipl-entries">Adressen und Netze <span class="muted">({entryCount})</span></label>
      <textarea id="ipl-entries" class="input mono" rows="9" bind:value={form.entries} placeholder={'203.0.113.7\n198.51.100.0/24\n2001:db8::/48   # Kommentar'}></textarea>
      <div class="help">Eine Adresse oder ein Netz (CIDR) pro Zeile, IPv4 und IPv6. „#“ leitet einen Kommentar ein.{#if form.mode === 'targets'}&nbsp;Für Ziel-Regeln zählen nur IPv4-Einträge.{/if}</div>
    </div>
    <div class="field">
      <label for="ipl-url">Online-Liste <span class="muted">(optional)</span></label>
      <div class="row" style="gap:8px">
        <input id="ipl-url" class="input mono grow" bind:value={form.url} placeholder="https://beispiel.de/liste.txt" />
        <select class="input" style="width:auto" bind:value={form.refresh} disabled={!form.url} title="Wie oft die Liste neu geladen wird">
          {#each REFRESH as [h, label]}<option value={h}>{label}</option>{/each}
          {#if !REFRESH.some((r) => r[0] === form.refresh)}<option value={form.refresh}>alle {form.refresh} Stunden</option>{/if}
        </select>
      </div>
      <div class="help">Adresse einer Textdatei mit einer Adresse oder einem Netz pro Zeile. Ihr Inhalt gilt zusätzlich zu den Einträgen oben (bis 300 000 Einträge).</div>
    </div>
    {#if form.mode !== 'targets'}
    <div class="field">
      <span class="label">Gilt für</span>
      <label class="switch"><input type="checkbox" bind:checked={form.all} /><span class="track"></span> Alle Dienste (auch künftige)</label>
      {#if !form.all}
        <div class="srvs">
          {#each servers as s}
            <label class="srv">
              <input type="checkbox" checked={form.servers.includes(s.id)} onchange={() => toggleServer(s.id)} />
              <ProtoLogo id={s.protocol} size={18} />
              <span class="grow">{s.name}</span>
              <span class="muted tiny">{PROTO_LABEL[s.protocol] || s.protocol}</span>
            </label>
          {:else}
            <span class="muted small">Noch keine Server.</span>
          {/each}
        </div>
      {/if}
    </div>
    {/if}
    {#if form.mode === 'allow'}
      <div class="notice warn small">
        <Icon name="alert" size={16} />
        <span>Achtung: Alle anderen Adressen werden für {form.all ? 'alle Dienste' : 'die gewählten Dienste'} abgewiesen{entryCount || form.url ? '' : ' – die Liste ist leer, damit käme niemand mehr hinein'}.</span>
      </div>
    {/if}
    <label class="switch"><input type="checkbox" bind:checked={form.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={!form.name}>{cur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
  .lst {
    display: flex;
    flex-direction: column;
  }
  .lst.off {
    opacity: 0.6;
  }
  .actions {
    display: flex;
    gap: 6px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    margin-top: auto;
  }
  .preview {
    color: var(--text-2);
    word-break: break-all;
  }
  .online {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .url {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .bad-text {
    color: var(--bad, #c0392b);
  }
  .label {
    font-weight: 600;
    font-size: 13px;
  }
  .srvs {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 240px;
    overflow: auto;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin-top: 8px;
  }
  .srv {
    display: flex;
    gap: 8px;
    align-items: center;
    cursor: pointer;
  }
  textarea.input {
    resize: vertical;
    font-size: 12px;
  }
</style>
