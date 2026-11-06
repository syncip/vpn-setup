<script>
  import { untrack } from 'svelte';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import FieldForm from './FieldForm.svelte';
  import { get, post, put, run } from '../lib/api.js';
  import { protocol } from '../lib/state.svelte.js';
  import { clone } from '../lib/format.js';

  // Gerät/Zugang anlegen oder bearbeiten.
  let { open = $bindable(false), peer = null, userId = 0, serverId = 0, users = [], servers = [], onsaved } = $props();

  let form = $state({ user_id: 0, server_id: 0, name: '', kind: '', enabled: true });
  let values = $state({});
  let others = $state([]);
  let busy = $state(false);

  const server = $derived(servers.find((s) => s.id === form.server_id));
  const proto = $derived(server ? protocol(server.protocol) : null);
  const kinds = $derived(proto?.kinds || []);
  const isNew = $derived(!peer);

  // beim Öffnen vorbelegen
  $effect(() => {
    if (!open) return;
    untrack(() => {
      if (peer) {
        form = { user_id: peer.user_id, server_id: peer.server_id, name: peer.name, kind: peer.kind, enabled: peer.enabled };
        values = clone($state.snapshot(peer.settings) || {});
      } else {
        const sid = serverId || servers.find((s) => s.enabled)?.id || servers[0]?.id || 0;
        form = { user_id: userId || users[0]?.id || 0, server_id: sid, name: '', kind: '', enabled: true };
        values = {};
      }
    });
  });

  // Geräteart-Vorgaben übernehmen (nur beim Anlegen)
  $effect(() => {
    if (!open || !isNew || !proto) return;
    if (!kinds.find((k) => k.id === form.kind)) form.kind = kinds[0]?.id || '';
  });
  function pickKind(k) {
    form.kind = k.id;
    values = { ...clone(k.defaults || {}) };
  }
  $effect(() => {
    if (open && isNew && form.kind && Object.keys(values).length === 0) {
      const k = kinds.find((x) => x.id === form.kind);
      if (k) values = { ...clone(k.defaults || {}) };
    }
  });

  // andere Geräte für „Ausgewählte Geräte“
  $effect(() => {
    const sid = form.server_id;
    if (!open || !sid || !proto?.mesh) {
      others = [];
      return;
    }
    get(`/servers/${sid}`).then((r) => (others = r.peers.filter((p) => !peer || p.id !== peer.id)));
  });

  async function save() {
    busy = true;
    const body = { name: form.name, kind: form.kind, enabled: form.enabled, settings: $state.snapshot(values) };
    const ok = isNew
      ? await run(() => post('/peers', { ...body, user_id: form.user_id, server_id: form.server_id }), 'Zugang angelegt')
      : await run(() => put(`/peers/${peer.id}`, body), 'Gespeichert');
    busy = false;
    if (ok) {
      open = false;
      onsaved?.(ok);
    }
  }
</script>

<Modal bind:open title={isNew ? 'Zugang hinzufügen' : `${peer?.name} bearbeiten`} subtitle={server ? `${server.name} · ${proto?.label || ''}` : ''} width={640}>
  <div class="stack">
    {#if isNew}
      {#if !userId}
        <div class="field">
          <label for="pe-user">Nutzer</label>
          <select id="pe-user" class="input" bind:value={form.user_id}>
            {#each users as u}<option value={u.id}>{u.name}</option>{/each}
          </select>
          <div class="help">Wem gehört das Gerät? Limits und Statistik laufen über den Nutzer.</div>
        </div>
      {/if}
      {#if !serverId}
        <div class="field">
          <label for="pe-srv">Server</label>
          <select id="pe-srv" class="input" bind:value={form.server_id} onchange={() => { form.kind = ''; values = {}; }}>
            {#each servers as s}<option value={s.id}>{s.name} ({protocol(s.protocol)?.label || s.protocol}){s.enabled ? '' : ' – deaktiviert'}</option>{/each}
          </select>
        </div>
      {/if}
      {#if kinds.length > 1}
        <div class="field">
          <span class="label">Art</span>
          <div class="grid cols-3" style="gap:10px">
            {#each kinds as k}
              <button type="button" class="choice" class:active={form.kind === k.id} onclick={() => pickKind(k)}>
                <span class="ic"><Icon name={k.icon === 'network' ? 'network' : k.icon} /></span>
                <span><span class="strong">{k.label}</span><br /><span class="muted tiny">{k.description}</span></span>
              </button>
            {/each}
          </div>
        </div>
      {/if}
    {/if}

    <div class="grid cols-2">
      <div class="field">
        <label for="pe-name">Name</label>
        <input id="pe-name" class="input" bind:value={form.name} placeholder={form.kind === 'site' ? 'z. B. Homelab' : form.kind === 'server' ? 'z. B. NAS' : 'z. B. Handy'} />
      </div>
      <div class="field">
        <span class="label">Status</span>
        <label class="switch" style="height:36px">
          <input type="checkbox" bind:checked={form.enabled} /><span class="track"></span>
          <span>{form.enabled ? 'Aktiv' : 'Deaktiviert'}</span>
        </label>
      </div>
    </div>

    {#if !isNew && kinds.length > 1}
      <div class="field">
        <label for="pe-kind">Art</label>
        <select id="pe-kind" class="input" bind:value={form.kind}>
          {#each kinds as k}<option value={k.id}>{k.label}</option>{/each}
        </select>
      </div>
    {/if}

    {#if proto}
      <FieldForm fields={proto.peer_fields || []} bind:values kind={form.kind} peers={others} />
    {/if}

    {#if form.kind === 'site'}
      <div class="notice">
        <Icon name="info" />
        <span>Das Gerät im Heimnetz (Router, Raspberry Pi, Proxmox-Host, …) baut die Verbindung auf und macht die eingetragenen Netze für andere VPN-Geräte erreichbar. Die fertige Konfiguration schaltet dort Weiterleitung und NAT ein.</span>
      </div>
    {/if}
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={busy || !form.name || !form.server_id || !form.user_id}>
      {isNew ? 'Anlegen' : 'Speichern'}
    </button>
  {/snippet}
</Modal>
