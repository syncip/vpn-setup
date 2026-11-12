<script>
  // Ziel-Regeln: welcher Verkehr über welche Ausgangsgruppe läuft (global, je Server, Nutzer oder Gerät).
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { PROTO_LABEL, ago, fmtNum } from '../lib/format.js';

  // reload: Zähler der Elternseite – ändert er sich (z. B. neue Gruppe), wird neu geladen
  let { reload = 0 } = $props();

  let d = $state({ routes: [], servers: [], users: [], peers: [], groups: [], lists: [], error: '', dns: null });
  const when = (ts) => (ago(ts) === 'online' ? 'gerade eben' : ago(ts));
  let loaded = $state(false);

  async function load() {
    try {
      d = await get('/routes');
      loaded = true;
    } catch {
      /* Seite zeigt den alten Stand */
    }
  }
  $effect(() => {
    reload;
    load();
  });
  $effect(() => {
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  });

  const by = (list) => Object.fromEntries(list.map((x) => [x.id, x]));
  const serverById = $derived(by(d.servers));
  const userById = $derived(by(d.users));
  const peerById = $derived(by(d.peers));
  const groupById = $derived(by(d.groups));
  const listById = $derived(by(d.lists));

  const SCOPE = { global: 'Alle', server: 'Server', user: 'Nutzer', peer: 'Gerät' };
  const ORDER = { peer: 0, user: 1, server: 2, global: 3 };

  function scopeText(r) {
    if (r.scope === 'server') return serverById[r.scope_id]?.name || '?';
    if (r.scope === 'user') return userById[r.scope_id]?.name || '?';
    if (r.scope === 'peer') {
      const p = peerById[r.scope_id];
      return p ? `${userById[p.user_id]?.name || '?'} · ${p.name}` : '?';
    }
    return 'alle Nutzer und Geräte';
  }
  function targetText(r) {
    if (r.match === 'all') return 'Alles';
    const parts = [];
    if (r.domains.length) parts.push(r.domains.slice(0, 3).join(', ') + (r.domains.length > 3 ? ` +${r.domains.length - 3}` : ''));
    if (r.nets.length) parts.push(r.nets.length === 1 ? r.nets[0] : `${r.nets.length} Netze`);
    for (const id of r.lists) parts.push(`Liste „${listById[id]?.name || id}“`);
    return parts.join(' · ') || '–';
  }
  // Anzeige in der Reihenfolge, in der die Regeln greifen
  const sorted = $derived(
    [...d.routes].sort((a, b) => ORDER[a.scope] - ORDER[b.scope] || a.scope_id - b.scope_id || (a.match === 'all') - (b.match === 'all') || a.id - b.id),
  );

  let open = $state(false);
  let cur = $state(null);
  let f = $state({});

  function openRule(r = null) {
    cur = r;
    f = r
      ? { name: r.name, enabled: r.enabled, scope: r.scope, scope_id: r.scope_id, match: r.match, nets: r.nets.join('\n'), domains: r.domains.join('\n'), lists: [...r.lists], group: r.group }
      : { name: '', enabled: true, scope: 'global', scope_id: 0, match: 'all', nets: '', domains: '', lists: [], group: d.groups.find((g) => g.enabled)?.id ?? 0 };
    open = true;
  }
  function setScope(s) {
    f.scope = s;
    f.scope_id = s === 'server' ? d.servers[0]?.id || 0 : s === 'user' ? d.users[0]?.id || 0 : s === 'peer' ? d.peers[0]?.id || 0 : 0;
  }
  function toggleList(id) {
    f.lists = f.lists.includes(id) ? f.lists.filter((x) => x !== id) : [...f.lists, id];
  }
  async function save() {
    const body = $state.snapshot(f);
    body.scope_id = Number(body.scope_id) || 0;
    body.group = Number(body.group) || 0;
    const r = cur ? await run(() => put(`/routes/${cur.id}`, body), 'Regel gespeichert') : await run(() => post('/routes', body), 'Regel angelegt');
    if (r) {
      open = false;
      load();
    }
  }
  async function toggle(r) {
    if (await run(() => put(`/routes/${r.id}`, { enabled: !r.enabled }), r.enabled ? 'Regel deaktiviert' : 'Regel aktiviert')) load();
  }
  async function remove(r) {
    if (!(await confirmDialog({ title: 'Regel löschen?', text: 'Der Verkehr läuft danach wieder nach den übrigen Regeln.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/routes/${r.id}`), 'Regel gelöscht')) load();
  }

  // Hinweise im Formular
  const hyOnly = $derived.by(() => {
    if (f.scope === 'server') return serverById[f.scope_id]?.protocol === 'hysteria2';
    if (f.scope === 'peer') return peerById[f.scope_id]?.protocol === 'hysteria2';
    return false;
  });
  const valid = $derived(
    (f.scope === 'global' || Number(f.scope_id) > 0) && (f.match === 'all' || (f.domains || '').trim() || (f.nets || '').trim() || (f.lists || []).length > 0),
  );
</script>

<div class="section-head">
  <div>
    <h2>Ziel-Regeln</h2>
    <div class="muted small">Welcher Verkehr über welche Ausgangsgruppe läuft – für WireGuard, OpenVPN, VLESS, Hysteria2 und Proxy</div>
  </div>
  <button class="btn sm primary" onclick={() => openRule()} disabled={!loaded}><Icon name="plus" size={15} /> Regel anlegen</button>
</div>
{#if d.error}<div class="notice bad" style="margin-bottom:12px"><Icon name="alert" /><span>{d.error}</span></div>{/if}
<div class="card">
  <div class="list">
    {#each sorted as r (r.id)}
      {@const g = groupById[r.group]}
      <div class="item" class:off={!r.enabled}>
        <span class="badge scope {r.scope}" title="Gilt für">{SCOPE[r.scope]}</span>
        <div class="grow">
          <div class="strong">
            {scopeText(r)}
            <span class="muted">·</span>
            <span class="what">{targetText(r)}</span>
            <Icon name="arrow-right" size={14} />
            {#if r.group === 0}<span class="via direct">direkt über den Server</span>{:else}<span class="via">{g?.name || 'Gruppe ?'}</span>{/if}
          </div>
          {#if r.name || r.note}
            <div class="tiny">
              {#if r.name}<span class="muted">{r.name}</span>{/if}
              {#if r.note && r.enabled}<span class="warn-text"><Icon name="alert" size={12} /> wirkt nicht: {r.note}</span>{/if}
            </div>
          {/if}
          {#if r.dns}
            <!-- Domain-Erkennung für WireGuard/OpenVPN: zeigt, ob DNS-Anfragen des Geräts ankommen -->
            <div class="tiny dnsline">
              {#if r.dns.error}
                <span class="warn-text"><Icon name="alert" size={12} /> {r.dns.error}</span>
              {:else if r.dns.queries}
                <span class="ok-text"><Icon name="check" size={12} /> Domains erkannt: {fmtNum(r.dns.addrs)} {r.dns.addrs === 1 ? 'Adresse' : 'Adressen'} gelernt, letzte DNS-Anfrage {when(r.dns.last)}</span>
              {:else if r.dns.addrs}
                <span class="muted">{fmtNum(r.dns.addrs)} {r.dns.addrs === 1 ? 'Adresse' : 'Adressen'} gelernt (seit dem Neustart noch keine neue DNS-Anfrage)</span>
              {:else}
                <span class="warn-text"
                  ><Icon name="alert" size={12} /> Noch keine DNS-Anfrage für diese Domains gesehen – am Gerät VPN trennen und neu verbinden, dann das Ziel aufrufen. Bleibt es dabei,
                  nutzt das Gerät verschlüsseltes DNS (Browser: „Sicheres DNS“, Android: „Privates DNS“).</span
                >
              {/if}
            </div>
          {/if}
        </div>
        <label class="switch" title={r.enabled ? 'Aktiv' : 'Aus'}><input type="checkbox" checked={r.enabled} onchange={() => toggle(r)} /><span class="track"></span></label>
        <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => openRule(r)}><Icon name="edit" size={15} /></button>
        <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(r)}><Icon name="trash" size={15} /></button>
      </div>
    {:else}
      <div class="empty small">
        Noch keine Regel – aller Verkehr geht direkt über den Server.{#if loaded && !d.groups.length}
          Lege zuerst unten einen Ausgang und eine Gruppe an.{/if}
      </div>
    {/each}
  </div>
  {#if sorted.length > 1 || d.dns?.running}
    <div class="foot muted tiny">
      {#if sorted.length > 1}Rangfolge: Gerät vor Nutzer vor Server vor „Alle“. Innerhalb einer Ebene greifen Regeln für bestimmte Ziele vor „Alles“. Die erste passende Regel gilt.{/if}
      {#if d.dns?.running}
        <div>
          DNS-Umleiter für Domain-Regeln (WireGuard/OpenVPN): {#if d.dns.queries}{fmtNum(d.dns.queries)} Anfragen von {d.dns.clients} {d.dns.clients === 1 ? 'Gerät' : 'Geräten'} seit dem
            Start, zuletzt {when(d.dns.last)}.{:else}läuft, hat aber noch keine DNS-Anfrage eines Geräts gesehen.{/if}
        </div>
      {/if}
    </div>
  {/if}
</div>

<Modal bind:open title={cur ? 'Regel bearbeiten' : 'Regel anlegen'} width={620}>
  <div class="stack">
    <div class="field">
      <span class="label">Gilt für</span>
      <div class="seg">
        {#each Object.entries(SCOPE) as [k, label]}
          <button class="btn sm" class:primary={f.scope === k} onclick={() => setScope(k)} disabled={k !== 'global' && !d[k + 's']?.length}>{label}</button>
        {/each}
      </div>
      {#if f.scope === 'server'}
        <select class="input" bind:value={f.scope_id}>
          {#each d.servers as s}<option value={s.id}>{s.name} ({PROTO_LABEL[s.protocol] || s.protocol})</option>{/each}
        </select>
      {:else if f.scope === 'user'}
        <select class="input" bind:value={f.scope_id}>
          {#each d.users as u}<option value={u.id}>{u.name}</option>{/each}
        </select>
      {:else if f.scope === 'peer'}
        <select class="input" bind:value={f.scope_id}>
          {#each d.peers as p}<option value={p.id}>{userById[p.user_id]?.name || '?'} · {p.name} ({PROTO_LABEL[p.protocol] || p.protocol})</option>{/each}
        </select>
      {:else}
        <div class="help">Für alle Nutzer und Geräte auf allen Servern, solange keine genauere Regel greift.</div>
      {/if}
      {#if f.scope === 'user'}<div class="help">Gilt für alle Zugänge des Nutzers. Hysteria2-Zugänge folgen nur Regeln für „Server“ und „Alle“.</div>{/if}
      {#if hyOnly && f.scope === 'peer'}<div class="help warn-text">Hysteria2 kann Geräte nicht einzeln leiten – für diesen Zugang bitte eine Regel für den Server anlegen.</div>{/if}
    </div>

    <div class="field">
      <span class="label">Ziele</span>
      <div class="seg">
        <button class="btn sm" class:primary={f.match === 'all'} onclick={() => (f.match = 'all')}>Alles</button>
        <button class="btn sm" class:primary={f.match === 'targets'} onclick={() => (f.match = 'targets')}>Nur bestimmte Ziele</button>
      </div>
    </div>
    {#if f.match === 'targets'}
      <div class="field">
        <label for="rt-dom">Domains</label>
        <textarea id="rt-dom" class="input mono" rows="3" bind:value={f.domains} placeholder={'netflix.com\nnflxvideo.net'}></textarea>
        <div class="help">
          Eine pro Zeile, Unterdomains sind eingeschlossen. Bei WireGuard und OpenVPN erkennt der Server die Ziele an den DNS-Anfragen des Geräts. Eine neue
          Regel greift, sobald das Gerät den Namen neu auflöst (VPN kurz trennen und verbinden hilft). Fest erzwungenes verschlüsseltes DNS (DoH, „Privates
          DNS“ mit Anbieter) umgeht das.
        </div>
      </div>
      <div class="field">
        <label for="rt-nets">IP-Netze (IPv4)</label>
        <textarea id="rt-nets" class="input mono" rows="2" bind:value={f.nets} placeholder={'203.0.113.0/24'}></textarea>
      </div>
      <div class="field">
        <span class="label">Ziellisten</span>
        {#if d.lists.length}
          <div class="row wrap" style="gap:6px">
            {#each d.lists as l}
              <button class="btn sm" class:primary={f.lists.includes(l.id)} onclick={() => toggleList(l.id)}>{l.name}{#if !l.enabled}&nbsp;(aus){/if}</button>
            {/each}
          </div>
        {:else}
          <div class="help">Noch keine – unter „IP-Listen“ eine Liste der Art „Zielliste“ anlegen (auch als Online-Liste).</div>
        {/if}
      </div>
    {/if}

    <div class="field">
      <label for="rt-via">Über</label>
      <select id="rt-via" class="input" bind:value={f.group}>
        {#each d.groups as g}<option value={g.id}>Ausgangsgruppe {g.name}{g.enabled ? '' : ' (deaktiviert)'}</option>{/each}
        <option value={0}>Direkt über den Server (Ausnahme)</option>
      </select>
      {#if f.group === 0}
        <div class="help">Nützlich als Ausnahme, z. B. „Alles über Mullvad, nur die Bank direkt“.</div>
      {:else if f.match === 'all'}
        <div class="help">Ausgänge können nur IPv4 – IPv6 ins Internet wird für diese Geräte gesperrt, damit nichts am Ausgang vorbeigeht.</div>
      {/if}
    </div>

    <div class="field"><label for="rt-name">Notiz (optional)</label><input id="rt-name" class="input" bind:value={f.name} placeholder="z. B. Streaming über USA" maxlength="60" /></div>
    <label class="switch"><input type="checkbox" bind:checked={f.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={!valid}>{cur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
  .section-head {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    justify-content: space-between;
    margin: 26px 0 12px;
  }
  .list {
    display: flex;
    flex-direction: column;
    padding: 6px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 9px 12px;
    border-radius: 8px;
  }
  .item.off .grow {
    opacity: 0.5;
  }
  .item .strong {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .what {
    font-weight: 500;
  }
  .via {
    color: var(--accent);
  }
  .via.direct {
    color: var(--muted);
  }
  .scope {
    min-width: 58px;
    text-align: center;
  }
  .foot {
    padding: 8px 18px 12px;
    border-top: 1px solid var(--border);
  }
  .seg {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 8px;
  }
  .ok-text {
    color: var(--ok);
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .dnsline {
    margin-top: 2px;
  }
  .warn-text {
    color: var(--warn, #b7791f);
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  textarea {
    resize: vertical;
  }
</style>
