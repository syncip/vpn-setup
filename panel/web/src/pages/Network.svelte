<script>
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import PeerEditor from '../components/PeerEditor.svelte';
  import ConfigView from '../components/ConfigView.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, put, del, run } from '../lib/api.js';
  import { ago, bytes } from '../lib/format.js';
  import { go, protocol } from '../lib/state.svelte.js';

  let { id = 0 } = $props();
  let servers = $state([]);
  let users = $state([]);
  let net = $state(null);
  let sel = $state(0);
  let view = $state('map');

  const mesh = $derived(servers.filter((s) => protocol(s.protocol)?.mesh));
  const sid = $derived(id || mesh[0]?.id || 0);

  async function loadBase() {
    [servers, users] = await Promise.all([get('/servers'), get('/users')]);
  }
  async function loadNet() {
    if (!sid) return;
    net = await get(`/servers/${sid}/network`);
  }
  loadBase();
  $effect(() => {
    sid;
    sel = 0;
    loadNet();
  });

  const st = $derived(net?.server?.settings || {});
  const nodes = $derived(net?.nodes || []);
  const kindIcon = { client: 'phone', server: 'server', site: 'network' };
  const kindLabel = { client: 'Handy / Laptop', server: 'Server / PC', site: 'Netzwerk' };

  // Positionen im Stern
  const W = 860, H = 470, CX = W / 2, CY = H / 2;
  const pos = $derived.by(() => {
    const m = new Map();
    const n = nodes.length;
    nodes.forEach((p, i) => {
      const a = -Math.PI / 2 + (i / Math.max(1, n)) * Math.PI * 2;
      m.set(p.id, { x: CX + Math.cos(a) * 330, y: CY + Math.sin(a) * 175 });
    });
    return m;
  });
  const selNode = $derived(nodes.find((n) => n.id === sel));
  const reachSet = $derived(new Set(selNode?.reach || []));
  const reachedBy = $derived(new Set(nodes.filter((n) => n.reach.includes(sel)).map((n) => n.id)));

  function accessText(n) {
    const a = n.settings?.access || 'default';
    const def = { all: 'alle', own: 'eigene', none: 'keine' }[st.default_access] || 'alle';
    return { default: `Standard (${def})`, all: 'Alle', own: 'Eigene Geräte', none: 'Keine', custom: `${n.settings?.access_peers?.length || 0} ausgewählte` }[a];
  }

  // ---------- Aktionen ----------
  let editorOpen = $state(false);
  let editPeer = $state(null);
  let cfgOpen = $state(false);
  let cfgPeer = $state(null);
  function add() {
    editPeer = null;
    editorOpen = true;
  }
  function edit(n) {
    editPeer = n;
    editorOpen = true;
  }
  function cfg(n) {
    cfgPeer = n;
    cfgOpen = true;
  }
  async function toggle(n) {
    if (await run(() => put(`/peers/${n.id}`, { enabled: !n.enabled }))) loadNet();
  }
  async function remove(n) {
    if (!(await confirmDialog({ title: `${n.name} löschen?`, text: 'Das Gerät und seine Netze sind danach nicht mehr erreichbar.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/peers/${n.id}`), 'Gerät gelöscht')) loadNet();
  }
</script>

<PageHead title="Netzwerk" subtitle="Geräte und Netze, die über WireGuard miteinander verbunden sind">
  {#if sid}<button class="btn primary" onclick={add}><Icon name="plus" size={16} /> Gerät hinzufügen</button>{/if}
</PageHead>

{#if !mesh.length && servers.length}
  <div class="card empty"><h3>Kein WireGuard-Server</h3><p>Lege unter „Server“ einen WireGuard-Server an, um Geräte zu vernetzen.</p><a class="btn primary" href="#/servers">Zu den Servern</a></div>
{:else if mesh.length}
  {#if mesh.length > 1}
    <div class="tabs">
      {#each mesh as s}
        <button class:active={s.id === sid} onclick={() => go(`/network/${s.id}`)}><span class="dot" class:on={s.status?.running}></span> {s.name}</button>
      {/each}
    </div>
  {/if}

  {#if net}
    <div class="grid cols-4 facts">
      <div class="card card-pad"><div class="muted small">Tunnelnetz</div><div class="mono strong">{st.net4}</div>{#if st.net6}<div class="mono tiny muted">{st.net6}</div>{/if}</div>
      <div class="card card-pad"><div class="muted small">Endpunkt</div><div class="mono strong">{st.endpoint || 'Server-Domain'}:{st.port}</div><div class="tiny muted">UDP · {st.interface}</div></div>
      <div class="card card-pad"><div class="muted small">Internet über Server</div><div class="strong">{st.internet ? 'Ja' : 'Nein'}</div><div class="tiny muted">Standard-Zugriff: {{ all: 'alle Geräte', own: 'eigene Geräte', none: 'keiner' }[st.default_access]}</div></div>
      <div class="card card-pad"><div class="muted small">Geräte</div><div class="strong">{nodes.filter((n) => n.online).length} online / {nodes.length}</div><div class="tiny muted">{nodes.reduce((s, n) => s + (n.settings?.routes?.length || 0), 0)} Netze dahinter</div></div>
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head">
        <h2>{view === 'map' ? 'Karte' : 'Zugriffsmatrix'}</h2>
        <div class="row">
          {#if selNode}<span class="small muted">Ausgewählt: <b>{selNode.name}</b> · erreicht {reachSet.size}, erreichbar von {reachedBy.size}</span><button class="btn sm ghost" onclick={() => (sel = 0)}>Auswahl aufheben</button>{/if}
          <div class="segmented">
            <button class:active={view === 'map'} onclick={() => (view = 'map')}>Karte</button>
            <button class:active={view === 'matrix'} onclick={() => (view = 'matrix')}>Matrix</button>
          </div>
        </div>
      </div>
      {#if view === 'map'}
        <div class="map">
          <svg viewBox="0 0 {W} {H}" role="img" aria-label="Netzwerkkarte">
            {#each nodes as n}
              {@const p = pos.get(n.id)}
              <line x1={CX} y1={CY} x2={p.x} y2={p.y} class="spoke" class:on={n.online && n.active} class:off={!n.active} />
            {/each}
            {#if selNode}
              {#each nodes.filter((n) => reachSet.has(n.id)) as n}
                {@const a = pos.get(sel)}
                {@const b = pos.get(n.id)}
                <path d="M{a.x},{a.y} Q{CX},{CY} {b.x},{b.y}" class="reach" />
              {/each}
            {/if}
            <g transform="translate({CX},{CY})">
              <circle r="44" class="hub" />
              <g transform="translate(-13,-24)" class="hub-ic"><Icon name="shield" size={26} /></g>
              <text y="16" text-anchor="middle" class="hub-t">Server</text>
              <text y="30" text-anchor="middle" class="hub-s">{st.net4}</text>
            </g>
            {#each nodes as n}
              {@const p = pos.get(n.id)}
              <g transform="translate({p.x},{p.y})" class="node" class:sel={sel === n.id} class:dim={sel && sel !== n.id && !reachSet.has(n.id) && !reachedBy.has(n.id)}
                onclick={() => (sel = sel === n.id ? 0 : n.id)} role="button" tabindex="0" onkeydown={(e) => e.key === 'Enter' && (sel = n.id)}>
                <circle r="25" class="nc" class:on={n.online} class:off={!n.active} />
                <g transform="translate(-10,-10)"><Icon name={kindIcon[n.kind] || 'phone'} size={20} /></g>
                <text y="42" text-anchor="middle" class="nt">{n.name}</text>
                <text y="56" text-anchor="middle" class="ns">{n.settings?.address4} · {n.user_name}</text>
                {#each n.settings?.routes || [] as r, i}
                  <g transform="translate(0,{70 + i * 18})">
                    <rect x="-52" y="-11" width="104" height="16" rx="5" class="route" />
                    <text y="1" text-anchor="middle" class="rt">{r}</text>
                  </g>
                {/each}
              </g>
            {/each}
          </svg>
          {#if !nodes.length}
            <div class="map-empty"><h3>Noch keine Geräte</h3><p class="muted">Füge dein Homelab, PCs oder Handys hinzu.</p><button class="btn primary" onclick={add}><Icon name="plus" size={16} /> Gerät hinzufügen</button></div>
          {/if}
        </div>
        <div class="legend tiny muted">
          <span><i class="dot on"></i> online</span><span><i class="dot"></i> offline</span><span><i class="ln"></i> erreichbar (Gerät anklicken)</span>
        </div>
      {:else}
        <div class="table-wrap">
          <table class="table matrix">
            <thead>
              <tr><th class="corner">von ↓ / nach →</th>{#each nodes as n}<th title={n.name}><span class="vert">{n.name}</span></th>{/each}<th>Internet</th></tr>
            </thead>
            <tbody>
              {#each nodes as a}
                <tr>
                  <td class="strong nowrap">{a.name}</td>
                  {#each nodes as b}
                    <td class="cell">{#if a.id === b.id}<span class="muted">–</span>{:else if a.reach.includes(b.id)}<span class="yes"><Icon name="check" size={14} /></span>{:else}<span class="no">·</span>{/if}</td>
                  {/each}
                  <td class="cell">{#if st.internet && a.settings?.tunnel === 'full'}<span class="yes"><Icon name="globe" size={14} /></span>{:else}<span class="no">·</span>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="legend tiny muted"><span>Antworten auf erlaubte Verbindungen kommen immer zurück. Regeln stellst du pro Gerät unter „Zugriff auf andere Geräte“ ein.</span></div>
      {/if}
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Geräte</h2><span class="muted small">{nodes.length}</span></div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Gerät</th><th>Adresse</th><th>Netze dahinter</th><th>Tunnel</th><th>Zugriff</th><th>Traffic</th><th>Zuletzt da</th><th></th></tr></thead>
          <tbody>
            {#each nodes as n}
              <tr class:selrow={sel === n.id}>
                <td>
                  <div class="row">
                    <span class="pill-icon"><Icon name={kindIcon[n.kind]} size={16} /></span>
                    <div>
                      <div class="strong">{n.name} {#if !n.enabled}<span class="badge muted">aus</span>{:else if !n.active}<span class="badge bad">gesperrt</span>{/if}</div>
                      <div class="muted tiny"><a href="#/users/{n.user_id}">{n.user_name}</a> · {kindLabel[n.kind]}</div>
                    </div>
                  </div>
                </td>
                <td class="mono small">{n.settings?.address4}{#if n.settings?.address6}<div class="muted tiny">{n.settings.address6}</div>{/if}</td>
                <td class="mono small">{(n.settings?.routes || []).join(', ') || '–'}</td>
                <td class="small">{n.settings?.tunnel === 'full' ? 'Voll' : 'Geteilt'}</td>
                <td class="small">{accessText(n)}</td>
                <td class="small nowrap">{bytes(n.total_up + n.total_down)}</td>
                <td class="small nowrap"><span class="row"><span class="dot" class:on={n.online}></span>{ago(n.last_seen)}</span>{#if n.endpoint}<div class="muted tiny mono">{n.endpoint}</div>{/if}</td>
                <td class="right nowrap">
                  <button class="btn sm" onclick={() => cfg(n)}><Icon name="qr" size={15} /> Konfiguration</button>
                  <button class="btn sm icon" title="Bearbeiten" onclick={() => edit(n)}><Icon name="edit" size={15} /></button>
                  <button class="btn sm icon" title={n.enabled ? 'Deaktivieren' : 'Aktivieren'} onclick={() => toggle(n)}><Icon name="power" size={15} /></button>
                  <button class="btn sm icon danger" title="Löschen" onclick={() => remove(n)}><Icon name="trash" size={15} /></button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}
{/if}

<PeerEditor bind:open={editorOpen} peer={editPeer} serverId={sid} {users} {servers} onsaved={loadNet} />
<Modal bind:open={cfgOpen} title={cfgPeer ? `${cfgPeer.name} – Konfiguration` : ''} subtitle={cfgPeer?.user_name} width={680}>
  {#if cfgPeer && cfgOpen}<ConfigView peerId={cfgPeer.id} />{/if}
</Modal>

<style>
  .map {
    position: relative;
    padding: 8px 12px 0;
  }
  svg {
    width: 100%;
    height: auto;
    display: block;
    max-height: 560px;
  }
  .spoke {
    stroke: var(--border-strong);
    stroke-width: 1.5;
    stroke-dasharray: 4 4;
  }
  .spoke.on {
    stroke: var(--ok);
    stroke-dasharray: none;
    stroke-width: 2;
  }
  .spoke.off {
    opacity: 0.35;
  }
  .reach {
    fill: none;
    stroke: var(--accent);
    stroke-width: 2.5;
    opacity: 0.75;
  }
  .hub {
    fill: var(--accent);
  }
  .hub-ic {
    color: #fff;
  }
  .hub-t {
    fill: #fff;
    font-weight: 700;
    font-size: 12px;
  }
  .hub-s {
    fill: #fff;
    opacity: 0.8;
    font-size: 9.5px;
    font-family: var(--mono);
  }
  .node {
    cursor: pointer;
    color: var(--text-2);
    transition: opacity 0.15s;
  }
  .node:focus {
    outline: none;
  }
  .node:focus-visible .nc {
    stroke: var(--accent);
  }
  .node.dim {
    opacity: 0.3;
  }
  .nc {
    fill: var(--panel);
    stroke: var(--border-strong);
    stroke-width: 2;
  }
  .nc.on {
    stroke: var(--ok);
  }
  .nc.off {
    stroke-dasharray: 3 3;
  }
  .node.sel .nc {
    stroke: var(--accent);
    stroke-width: 3;
    fill: var(--accent-soft);
  }
  .node.sel {
    color: var(--accent);
  }
  .nt {
    fill: var(--text);
    font-weight: 650;
    font-size: 12.5px;
  }
  .ns {
    fill: var(--muted);
    font-size: 10.5px;
    font-family: var(--mono);
  }
  .route {
    fill: var(--accent-soft);
  }
  .rt {
    fill: var(--accent);
    font-size: 10px;
    font-family: var(--mono);
    font-weight: 600;
  }
  .map-empty {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: color-mix(in srgb, var(--panel) 75%, transparent);
    gap: 4px;
  }
  .legend {
    display: flex;
    gap: 16px;
    padding: 8px 20px 14px;
    flex-wrap: wrap;
  }
  .legend i {
    display: inline-block;
    vertical-align: middle;
    margin-right: 4px;
  }
  .legend .ln {
    width: 16px;
    height: 3px;
    background: var(--accent);
    border-radius: 2px;
  }
  .matrix th,
  .matrix td {
    text-align: center;
    padding: 6px 8px;
  }
  .matrix td:first-child,
  .matrix th.corner {
    text-align: left;
  }
  .vert {
    writing-mode: vertical-rl;
    transform: rotate(180deg);
    white-space: nowrap;
    max-height: 120px;
    display: inline-block;
    text-transform: none;
    letter-spacing: 0;
    font-size: 12px;
  }
  .yes {
    display: inline-grid;
    place-items: center;
    width: 22px;
    height: 22px;
    border-radius: 6px;
    background: var(--ok-soft);
    color: var(--ok);
  }
  .no {
    color: var(--border-strong);
  }
  .selrow td {
    background: var(--accent-soft);
  }
</style>
