<script>
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import FieldForm from '../components/FieldForm.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { bytes, copy, clone } from '../lib/format.js';
  import { meta, protocol, toast } from '../lib/state.svelte.js';

  let servers = $state([]);
  let loaded = $state(false);
  async function load() {
    servers = await get('/servers');
    loaded = true;
  }
  load();

  // ---------- Bearbeiten / Anlegen ----------
  let open = $state(false);
  let cur = $state(null); // null = neu
  let form = $state({ name: '', protocol: '', enabled: true });
  let values = $state({});
  let busy = $state(false);
  const proto = $derived(protocol(form.protocol));

  function defaults(p) {
    const v = {};
    for (const f of p?.server_fields || []) if (f.default !== undefined) v[f.key] = clone(f.default);
    return v;
  }
  function openNew() {
    cur = null;
    const p = meta.protocols[0];
    form = { name: '', protocol: p?.id || '', enabled: true };
    values = defaults(p);
    open = true;
  }
  function pick(p) {
    form.protocol = p.id;
    values = defaults(p);
    if (!form.name) form.name = p.label;
  }
  function openEdit(s) {
    cur = s;
    form = { name: s.name, protocol: s.protocol, enabled: s.enabled };
    values = clone($state.snapshot(s.settings));
    open = true;
  }
  async function save() {
    busy = true;
    const body = { name: form.name, enabled: form.enabled, settings: $state.snapshot(values) };
    const ok = cur ? await run(() => put(`/servers/${cur.id}`, body), 'Server gespeichert') : await run(() => post('/servers', { ...body, protocol: form.protocol }), 'Server angelegt');
    busy = false;
    if (ok) {
      open = false;
      load();
    }
  }
  async function toggle(s) {
    if (await run(() => put(`/servers/${s.id}`, { enabled: !s.enabled }), s.enabled ? 'Server deaktiviert' : 'Server aktiviert')) load();
  }
  async function remove(s) {
    if (!(await confirmDialog({ title: `${s.name} löschen?`, text: `Alle ${s.peers} Zugänge auf diesem Server werden mit gelöscht. Das lässt sich nicht rückgängig machen.`, ok: 'Endgültig löschen', danger: true }))) return;
    if (await run(() => del(`/servers/${s.id}`), 'Server gelöscht')) load();
  }
  async function regen(s) {
    if (!(await confirmDialog({ title: 'Neue Server-Schlüssel?', text: 'Alle Geräte und Links dieses Servers funktionieren danach nicht mehr und müssen neu eingerichtet werden.', ok: 'Neu erzeugen', danger: true }))) return;
    if (await run(() => put(`/servers/${s.id}`, { regenerate_keys: true }), 'Neue Schlüssel erzeugt')) load();
  }
  const protoIcon = { wireguard: 'network', vless: 'shield' };
</script>

<PageHead title="Server" subtitle="VPN-Instanzen auf diesem System – mehrere pro Protokoll möglich">
  <button class="btn primary" onclick={openNew}><Icon name="plus" size={16} /> Server hinzufügen</button>
</PageHead>

<div class="grid cols-2">
  {#each servers as s}
    {@const p = protocol(s.protocol)}
    <div class="card srv" class:disabled={!s.enabled}>
      <div class="card-head">
        <div class="row grow">
          <span class="pill-icon"><Icon name={protoIcon[s.protocol] || 'server'} /></span>
          <div class="grow">
            <h3>{s.name}</h3>
            <div class="muted tiny">{p?.label || s.protocol}</div>
          </div>
        </div>
        <span class="badge {!s.enabled ? 'muted' : s.status?.running ? 'ok' : 'bad'}"><span class="dot" class:on={s.enabled && s.status?.running}></span>{s.enabled ? (s.status?.running ? 'läuft' : 'Fehler') : 'aus'}</span>
      </div>
      <div class="card-pad stack-sm">
        {#if s.error}<div class="notice bad small"><Icon name="alert" size={16} /> {s.error}</div>{/if}
        <dl class="kv">
          <dt>Status</dt><dd>{s.status?.detail}</dd>
          <dt>Zugänge</dt><dd>{s.online} online / {s.peers}</dd>
          <dt>Traffic</dt><dd>{bytes(s.up + s.down)}</dd>
          {#if s.protocol === 'wireguard'}
            <dt>Tunnelnetz</dt><dd class="mono">{s.settings.net4}{s.settings.net6 ? ` · ${s.settings.net6}` : ''}</dd>
            <dt>Internet</dt><dd>{s.settings.internet ? 'über diesen Server' : 'nein (nur Netzwerk)'}</dd>
          {:else if s.protocol === 'vless'}
            <dt>Tarnziele</dt><dd>{(s.settings.targets || []).flatMap((t) => t.server_names).join(', ')}</dd>
          {/if}
          {#if s.public_key}
            <dt>Public Key</dt>
            <dd class="row"><code class="ellipsis grow">{s.public_key}</code><button class="btn sm icon ghost" title="Kopieren" onclick={() => copy(s.public_key).then(() => toast('Kopiert'))}><Icon name="copy" size={14} /></button></dd>
          {/if}
          <dt>Port</dt>
          <dd>{#each s.ports || [] as pt}<span class="badge">{pt.proto.toUpperCase()} {pt.port}</span> {/each}</dd>
        </dl>
      </div>
      <div class="actions">
        {#if p?.mesh}<a class="btn sm" href="#/network/{s.id}"><Icon name="network" size={15} /> Netzwerk</a>{/if}
        <button class="btn sm" onclick={() => openEdit(s)}><Icon name="edit" size={15} /> Bearbeiten</button>
        <button class="btn sm" onclick={() => toggle(s)}><Icon name="power" size={15} /> {s.enabled ? 'Deaktivieren' : 'Aktivieren'}</button>
        <span class="grow"></span>
        <button class="btn sm icon ghost" title="Neue Schlüssel" onclick={() => regen(s)}><Icon name="key" size={15} /></button>
        <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(s)}><Icon name="trash" size={15} /></button>
      </div>
    </div>
  {/each}
</div>
{#if loaded && !servers.length}
  <div class="card empty"><h3>Noch keine Server</h3><p>Lege einen WireGuard- oder VLESS-Server an.</p><button class="btn primary" onclick={openNew}>Server hinzufügen</button></div>
{/if}

<div class="notice" style="margin-top:18px">
  <Icon name="info" />
  <span>Neue Ports (z. B. ein zweiter WireGuard-Server auf UDP 51821) müssen auf dem Proxmox-Host an den Container weitergeleitet werden. Die Liste findest du unter <a href="#/settings/system">Einstellungen → System</a>.</span>
</div>

<Modal bind:open title={cur ? `${cur.name} bearbeiten` : 'Server hinzufügen'} width={680}>
  <div class="stack">
    {#if !cur}
      <div class="grid cols-2" style="gap:10px">
        {#each meta.protocols as p}
          <button type="button" class="choice" class:active={form.protocol === p.id} onclick={() => pick(p)}>
            <span class="ic"><Icon name={protoIcon[p.id] || 'server'} /></span>
            <span><span class="strong">{p.label}</span><br /><span class="muted tiny">{p.description}</span></span>
          </button>
        {/each}
      </div>
    {/if}
    <div class="grid cols-2">
      <div class="field"><label for="sv-name">Name</label><input id="sv-name" class="input" bind:value={form.name} placeholder="z. B. Homelab-Netz" /></div>
      <div class="field"><span class="label">Status</span><label class="switch" style="height:36px"><input type="checkbox" bind:checked={form.enabled} /><span class="track"></span>{form.enabled ? 'Aktiv' : 'Deaktiviert'}</label></div>
    </div>
    {#if proto}
      {#key form.protocol + (cur?.id || 'new')}
        <FieldForm fields={proto.server_fields} bind:values />
      {/key}
    {/if}
    {#if cur?.protocol === 'wireguard'}
      <div class="notice warn small"><Icon name="alert" size={16} /> Änderungen an Tunnelnetz, Port oder Adresse erfordern neue Konfigurationen auf allen Geräten.</div>
    {/if}
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={busy || !form.name || !form.protocol}>{cur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
  .srv {
    display: flex;
    flex-direction: column;
  }
  .srv.disabled {
    opacity: 0.7;
  }
  .actions {
    display: flex;
    gap: 6px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    margin-top: auto;
    flex-wrap: wrap;
  }
</style>
