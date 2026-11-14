<script>
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Board from '../components/Board.svelte';
  import Modal from '../components/Modal.svelte';
  import PeerEditor from '../components/PeerEditor.svelte';
  import ConfigView from '../components/ConfigView.svelte';
  import TopologyMap from '../components/TopologyMap.svelte';
  import NetAccess from '../components/NetAccess.svelte';
  import SearchInput from '../components/SearchInput.svelte';
  import { tokens, matches } from '../lib/pick.js';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, put, del, run } from '../lib/api.js';
  import { ago, bytes } from '../lib/format.js';
  import { go, protocol } from '../lib/state.svelte.js';

  let { id = 0, view: viewParam = 'map', tab = '' } = $props();
  let servers = $state([]);
  let users = $state([]);
  let net = $state(null);
  let sel = $state(0);
  // Ansicht steht in der Adresse (#/network/<id>/matrix)
  const view = $derived(viewParam === 'matrix' ? 'matrix' : 'map');

  const mesh = $derived(servers.filter((s) => protocol(s.protocol)?.mesh));
  // ohne Server in der Adresse: Übersicht über alle Server (Karte mit Verkehr und Wegen)
  const sid = $derived(id);

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
    net = null;
    loadNet();
  });

  const st = $derived(net?.server?.settings || {});
  const nodes = $derived(net?.nodes || []);
  const kindIcon = { client: 'phone', server: 'server', site: 'network' };
  const kindLabel = { client: 'Handy / Laptop', server: 'Server / PC', site: 'Netzwerk' };

  // Suche: filtert Karte, Matrix und Liste (Name, Nutzer, Adresse, Netze, Art)
  let nq = $state('');
  const kindText = { client: 'handy laptop', server: 'server pc', site: 'netzwerk' };
  let nf = $state('all'); // all | online | offline | site | blocked
  const NF = [
    ['all', 'Alle'],
    ['online', 'Online'],
    ['offline', 'Offline'],
    ['site', 'Mit Netzen dahinter'],
    ['blocked', 'Gesperrt/aus'],
  ];
  const nfOk = (n, f) =>
    f === 'online' ? n.online : f === 'offline' ? !n.online : f === 'site' ? (n.settings?.routes || []).length > 0 : f === 'blocked' ? !n.enabled || !n.active : true;
  const nfCount = (f) => nodes.filter((n) => nfOk(n, f)).length;
  const shownNodes = $derived.by(() => {
    const t = tokens(nq);
    return nodes.filter(
      (n) =>
        nfOk(n, nf) &&
        matches(`${n.name} ${n.user_name} ${n.settings?.address4 || ''} ${n.settings?.address6 || ''} ${(n.settings?.routes || []).join(' ')} ${kindText[n.kind] || ''} ${n.online ? 'online' : 'offline'}`, t),
    );
  });
  const filtered = $derived(!!nq || nf !== 'all');

  // Geräteliste nach Nutzer gruppiert; bei vielen Geräten zugeklappt und seitenweise
  const MANY = 40;
  const MATRIX_MAX = 40;
  let openGroups = $state({});
  let glimit = $state(30);
  const groups = $derived.by(() => {
    const m = new Map();
    for (const n of shownNodes) {
      if (!m.has(n.user_id)) m.set(n.user_id, { uid: n.user_id, name: n.user_name, nodes: [] });
      m.get(n.user_id).nodes.push(n);
    }
    return [...m.values()].sort((a, b) => a.name.localeCompare(b.name));
  });
  const grouped = $derived(nodes.length > MANY);
  const isOpen = (g) => (openGroups[g.uid] ?? (filtered || !grouped));
  function toggleGroup(g) {
    openGroups = { ...openGroups, [g.uid]: !isOpen(g) };
  }
  function allGroups(open) {
    openGroups = Object.fromEntries(groups.map((g) => [g.uid, open]));
  }
  $effect(() => {
    nq;
    nf;
    glimit = 30;
  });

  // Positionen im Stern; bei vielen Geräten mehrere Ringe und kleinere Punkte
  const W = 860;
  const size = $derived(shownNodes.length <= 16 ? 'big' : shownNodes.length <= 36 ? 'mid' : 'small');
  const H = $derived(size === 'small' ? 640 : 470);
  const CX = W / 2;
  const CY = $derived(H / 2);
  const pos = $derived.by(() => {
    const m = new Map();
    const n = shownNodes.length;
    const k = n <= 24 ? 1 : n <= 60 ? 2 : n <= 130 ? 3 : 4;
    // Ringe von außen nach innen, Anzahl je Ring nach Umfang
    const f = Array.from({ length: k }, (_, j) => (k === 1 ? 1 : 1 - (j * 0.5) / (k - 1)));
    const fs = f.reduce((a, b) => a + b, 0);
    let i = 0;
    f.forEach((fj, j) => {
      const cnt = j === k - 1 ? n - i : Math.round((n * fj) / fs);
      for (let c = 0; c < cnt && i < n; c++, i++) {
        const a = -Math.PI / 2 + (c / Math.max(1, cnt)) * Math.PI * 2 + (j % 2 ? Math.PI / Math.max(1, cnt) : 0);
        m.set(shownNodes[i].id, { x: CX + Math.cos(a) * 345 * fj, y: CY + Math.sin(a) * (CY - 62) * fj });
      }
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

<PageHead title="Netzwerk" subtitle={sid ? 'Geräte und Netze dieses WireGuard-Servers' : 'Verbindungen, Verkehr und Störungen'} helpTitle="Netzwerk">
  {#snippet help()}
    <p><b>Übersicht:</b> Wer verbunden ist, wohin der Verkehr gerade fließt und wo es hakt. Bei vielen Nutzern ist die Karte kompakt – Nutzer aufklappen oder suchen.</p>
    <p><b>Zugriff:</b> Welche Nutzer, Tarife oder Geräte andere WireGuard-Netze erreichen dürfen (z. B. Anna auf WireGuard 1 und 2).</p>
    <p><b>WireGuard-Server:</b> Geräte und Netze, die über diesen Server miteinander verbunden sind, und wer wen erreichen darf (Karte, Matrix, Liste).</p>
  {/snippet}
  {#if sid}<button class="btn primary" onclick={add}><Icon name="plus" size={16} /> Gerät hinzufügen</button>{/if}
</PageHead>

{#if mesh.length}
  <div class="tabs">
    <button class:active={!sid && tab !== 'access'} onclick={() => go('/network')}><Icon name="network" size={14} /> Übersicht</button>
    <button class:active={tab === 'access'} onclick={() => go('/network/access')}><Icon name="lock" size={14} /> Zugriff</button>
    {#each mesh as s}
      <button class:active={s.id === sid} onclick={() => go(`/network/${s.id}${view === 'matrix' ? '/matrix' : ''}`)}><span class="dot" class:on={s.status?.running}></span> {s.name}</button>
    {/each}
  </div>
{/if}

{#if tab === 'access'}
  <NetAccess />
{:else if !sid}
  <TopologyMap />
{:else}

  {#if net}
    {#snippet w_net()}
      <div class="card card-pad"><div class="muted small">Tunnelnetz</div><div class="mono strong">{st.net4}</div>{#if st.net6}<div class="mono tiny muted">{st.net6}</div>{/if}</div>
    {/snippet}
    {#snippet w_endpoint()}
      <div class="card card-pad"><div class="muted small">Endpunkt</div><div class="mono strong">{st.endpoint || 'Server-Domain'}:{st.port}</div><div class="tiny muted">UDP · {st.interface}</div></div>
    {/snippet}
    {#snippet w_internet()}
      <div class="card card-pad"><div class="muted small">Internet über Server</div><div class="strong">{st.internet ? 'Ja' : 'Nein'}</div><div class="tiny muted">Standard-Zugriff: {{ all: 'alle Geräte', own: 'eigene Geräte', none: 'keiner' }[st.default_access]}</div></div>
    {/snippet}
    {#snippet w_devices()}
      <div class="card card-pad"><div class="muted small">Geräte</div><div class="strong">{nodes.filter((n) => n.online).length} online / {nodes.length}</div><div class="tiny muted">{nodes.reduce((s, n) => s + (n.settings?.routes?.length || 0), 0)} Netze dahinter</div></div>
    {/snippet}
    {#snippet w_map()}
    <div class="card">
      <div class="card-head">
        <h2>{view === 'map' ? 'Karte' : 'Zugriffsmatrix'}</h2>
        <div class="row wrap">
          {#if nodes.length > 6}<SearchInput bind:value={nq} placeholder="Gerät, Nutzer, Adresse, Netz …" width="240px" />{/if}
          {#if nodes.length > 6}
            <select class="input" style="width:auto;height:32px" bind:value={nf} aria-label="Filter">
              {#each NF as [k, l]}<option value={k}>{l} ({nfCount(k)})</option>{/each}
            </select>
          {/if}
          {#if selNode}<span class="small muted">Ausgewählt: <b>{selNode.name}</b> · erreicht {reachSet.size}, erreichbar von {reachedBy.size}</span><button class="btn sm ghost" onclick={() => (sel = 0)}>Auswahl aufheben</button>{/if}
          <div class="segmented">
            <button class:active={view === 'map'} onclick={() => go(`/network/${sid}`)}>Karte</button>
            <button class:active={view === 'matrix'} onclick={() => go(`/network/${sid}/matrix`)}>Matrix</button>
          </div>
        </div>
      </div>
      {#if view === 'map'}
        <div class="map">
          <svg viewBox="0 0 {W} {H}" role="img" aria-label="Netzwerkkarte" class={size}>
            {#each shownNodes as n}
              {@const p = pos.get(n.id)}
              <line x1={CX} y1={CY} x2={p.x} y2={p.y} class="spoke" class:on={n.online && n.active} class:off={!n.active} />
            {/each}
            {#if selNode}
              {#each shownNodes.filter((n) => reachSet.has(n.id) && pos.has(sel)) as n}
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
            {#each shownNodes as n}
              {@const p = pos.get(n.id)}
              {@const big = size === 'big'}
              {@const r = big ? 25 : size === 'mid' ? 17 : 10}
              <g transform="translate({p.x},{p.y})" class="node" class:sel={sel === n.id} class:dim={sel && sel !== n.id && !reachSet.has(n.id) && !reachedBy.has(n.id)}
                onclick={() => (sel = sel === n.id ? 0 : n.id)} role="button" tabindex="0" onkeydown={(e) => e.key === 'Enter' && (sel = n.id)}>
                <title>{n.name} · {n.user_name} · {n.settings?.address4}{(n.settings?.routes || []).length ? ' · ' + n.settings.routes.join(', ') : ''}</title>
                <circle {r} class="nc" class:on={n.online} class:off={!n.active} />
                {#if size !== 'small'}<g transform="translate({big ? -10 : -7},{big ? -10 : -7})"><Icon name={kindIcon[n.kind] || 'phone'} size={big ? 20 : 14} /></g>{/if}
                {#if big || size === 'mid' || sel === n.id}
                  <text y={r + 17} text-anchor="middle" class="nt" class:small={!big}>{n.name}</text>
                {/if}
                {#if big}
                  <text y="56" text-anchor="middle" class="ns">{n.settings?.address4} · {n.user_name}</text>
                  {#each n.settings?.routes || [] as rt, i}
                    <g transform="translate(0,{70 + i * 18})">
                      <rect x="-52" y="-11" width="104" height="16" rx="5" class="route" />
                      <text y="1" text-anchor="middle" class="rt">{rt}</text>
                    </g>
                  {/each}
                {/if}
              </g>
            {/each}
          </svg>
          {#if nodes.length && !shownNodes.length}
            <div class="map-empty"><h3>Keine Treffer</h3><p class="muted">Kein Gerät passt zu „{nq}“.</p></div>
          {:else if !nodes.length}
            <div class="map-empty"><h3>Noch keine Geräte</h3><p class="muted">Füge dein Homelab, PCs oder Handys hinzu.</p><button class="btn primary" onclick={add}><Icon name="plus" size={16} /> Gerät hinzufügen</button></div>
          {/if}
        </div>
        <div class="legend tiny muted">
          <span><i class="dot on"></i> online</span><span><i class="dot"></i> offline</span><span><i class="ln"></i> erreichbar (Gerät anklicken)</span>
          {#if size !== 'big'}<span>Viele Geräte: Name beim Zeigen auf einen Punkt, gezielt über die Suche</span>{/if}
        </div>
      {:else if shownNodes.length > MATRIX_MAX}
        <div class="empty small">
          <Icon name="filter" size={18} />
          <p>Die Matrix zeigt höchstens {MATRIX_MAX} Geräte – gerade sind es {shownNodes.length}. Grenze sie über Suche oder Filter oben ein (z. B. einen Nutzer oder „Mit Netzen dahinter“).</p>
        </div>
      {:else}
        <div class="table-wrap">
          <table class="table matrix">
            <thead>
              <tr><th class="corner">von ↓ / nach →</th>{#each shownNodes as n}<th title="{n.name} · {n.user_name}"><span class="vert">{n.name}</span></th>{/each}<th>Internet</th></tr>
            </thead>
            <tbody>
              {#each shownNodes as a}
                <tr>
                  <td class="strong nowrap">{a.name} <span class="muted tiny">{a.user_name}</span></td>
                  {#each shownNodes as b}
                    <td class="cell">{#if a.id === b.id}<span class="muted">–</span>{:else if a.reach.includes(b.id)}<span class="yes"><Icon name="check" size={14} /></span>{:else}<span class="no">·</span>{/if}</td>
                  {/each}
                  <td class="cell">{#if st.internet && a.settings?.tunnel === 'full'}<span class="yes"><Icon name="globe" size={14} /></span>{:else}<span class="no">·</span>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="legend tiny muted"><span>{#if nq}Die Suche filtert Zeilen und Spalten. {/if}Antworten auf erlaubte Verbindungen kommen immer zurück. Regeln stellst du pro Gerät unter „Zugriff auf andere Geräte“ ein.</span></div>
      {/if}
    </div>
    {/snippet}
    {#snippet w_list()}
    <div class="card">
      <div class="card-head">
        <h2>Geräte <span class="muted small">{filtered ? `${shownNodes.length} von ${nodes.length}` : nodes.length} · {groups.length} Nutzer</span></h2>
        {#if grouped}
          <div class="row" style="gap:6px">
            <button class="btn sm ghost" onclick={() => allGroups(true)}>Alle aufklappen</button>
            <button class="btn sm ghost" onclick={() => allGroups(false)}>Alle zuklappen</button>
          </div>
        {/if}
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Gerät</th><th>Adresse</th><th>Netze dahinter</th><th>Tunnel</th><th>Zugriff</th><th>Traffic</th><th>Zuletzt da</th><th></th></tr></thead>
          <tbody>
            {#each groups.slice(0, glimit) as g (g.uid)}
              {@const gon = g.nodes.filter((n) => n.online).length}
              <tr class="grow-row" onclick={() => toggleGroup(g)}>
                <td colspan="8">
                  <div class="row" style="gap:8px">
                    <span class="chev" class:open={isOpen(g)}><Icon name="chevron" size={14} /></span>
                    <Icon name="user" size={14} />
                    <a href="#/users/{g.uid}" class="strong" onclick={(e) => e.stopPropagation()}>{g.name}</a>
                    <span class="muted small">{g.nodes.length} {g.nodes.length === 1 ? 'Gerät' : 'Geräte'} · <span class:ok-t={gon}>{gon} online</span>{#if g.nodes.some((n) => (n.settings?.routes || []).length)}&nbsp;· mit Netzen{/if}</span>
                    <span class="grow"></span>
                    <span class="small muted">{bytes(g.nodes.reduce((a, n) => a + n.total_up + n.total_down, 0))}</span>
                  </div>
                </td>
              </tr>
              {#if isOpen(g)}
              {#each g.nodes as n (n.id)}
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
              {/if}
            {/each}
          </tbody>
        </table>
        {#if groups.length > glimit}
          <div class="more"><button class="btn sm" onclick={() => (glimit += 30)}><Icon name="plus" size={14} /> {Math.min(30, groups.length - glimit)} weitere Nutzer (von {groups.length - glimit})</button></div>
        {/if}
        {#if !shownNodes.length && nodes.length}<div class="empty small">Kein Gerät passt zu Suche und Filter.</div>{/if}
      </div>
    </div>
    {/snippet}
    <Board
      id="network"
      widgets={[
        { id: 'net', title: 'Tunnelnetz', w: 3, body: w_net },
        { id: 'endpoint', title: 'Endpunkt', w: 3, body: w_endpoint },
        { id: 'internet', title: 'Internet über Server', w: 3, body: w_internet },
        { id: 'devices', title: 'Geräte (Anzahl)', w: 3, body: w_devices },
        { id: 'map', title: 'Karte / Zugriffsmatrix', w: 12, body: w_map },
        { id: 'list', title: 'Geräte', w: 12, body: w_list },
      ]}
    />
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
  .nt.small {
    font-size: 10.5px;
    font-weight: 600;
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
  .grow-row {
    cursor: pointer;
  }
  .grow-row td {
    background: var(--panel-2);
    padding-top: 7px;
    padding-bottom: 7px;
  }
  .chev {
    display: grid;
    place-items: center;
    color: var(--muted);
    transition: transform 0.15s;
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .ok-t {
    color: var(--ok);
  }
  .more {
    padding: 10px 14px;
  }
</style>
