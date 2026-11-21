<script>
  // Gerade verbundene Geräte (Live, alle 2 s): Nutzer, Gerät, Server, Adresse, Dauer, Geschwindigkeit.
  // Sucht über alle Spalten, sortiert nach Geschwindigkeit und zeigt zunächst nur die ersten Zeilen.
  import Icon from './Icon.svelte';
  import ProtoLogo from './ProtoLogo.svelte';
  import SearchInput from './SearchInput.svelte';
  import { liveFeed } from '../lib/live.svelte.js';
  import { speed, duration, fmtNum, PROTO_LABEL } from '../lib/format.js';
  import { tokens, matches } from '../lib/pick.js';

  let { user = 0, connected = $bindable(0), limit = 10, title = 'Verbundene Geräte', bare = false } = $props();

  const lv = liveFeed(() => user);
  const now = $derived(lv.at || Date.now());
  const allPeers = $derived((lv.d?.peers || []).filter((p) => !user || p.user_id === Number(user)));
  $effect(() => {
    connected = allPeers.length;
  });

  let q = $state('');
  let sort = $state('speed'); // speed | user | since
  let more = $state(false);
  const peers = $derived.by(() => {
    const t = tokens(q);
    const list = allPeers.filter((p) => matches(`${p.user} ${p.name} ${PROTO_LABEL[p.protocol] || p.protocol} ${p.server} ${p.endpoint || ''}`, t));
    if (sort === 'speed') list.sort((a, b) => b.up + b.down - (a.up + a.down));
    else if (sort === 'user') list.sort((a, b) => `${a.user} ${a.name}`.localeCompare(`${b.user} ${b.name}`, 'de'));
    else list.sort((a, b) => (a.since || 9e12) - (b.since || 9e12));
    return list;
  });
  const visible = $derived(more || q ? peers : peers.slice(0, limit));
  const peak = $derived(Math.max(1, ...allPeers.map((p) => p.up + p.down)));
</script>

<div class:card={!bare} class="devs">
  <div class="dh">
    <h3 class="row" style="gap:8px"><span class="pulse"></span> {title} <span class="muted small" style="font-weight:400">{fmtNum(allPeers.length)}</span></h3>
    {#if allPeers.length > 6}
      <div class="row wrap" style="gap:8px">
        <SearchInput bind:value={q} placeholder="Gerät, Nutzer, Server …" width="200px" />
        <select class="input sm" bind:value={sort} aria-label="Sortierung">
          <option value="speed">nach Tempo</option>
          <option value="user">nach Name</option>
          <option value="since">am längsten da</option>
        </select>
      </div>
    {/if}
  </div>
  {#if lv.err}<div class="notice bad small" style="margin:0 14px 10px">{lv.err}</div>{/if}
  <div class="table-wrap">
    <table class="table">
      <thead>
        <tr>
          {#if !user}<th>Nutzer</th>{/if}
          <th>Gerät</th>
          <th class="hide-xs">Server</th>
          <th class="hide-sm">Adresse</th>
          <th class="hide-sm">Verbunden</th>
          <th style="width:28%">Geschwindigkeit</th>
        </tr>
      </thead>
      <tbody>
        {#each visible as p (p.id)}
          <tr>
            {#if !user}<td class="nowrap"><a href="#/users/{p.user_id}" class="strong">{p.user}</a></td>{/if}
            <td class="nowrap">{p.name}</td>
            <td class="small hide-xs"><span class="row" style="gap:6px;flex-wrap:nowrap"><ProtoLogo id={p.protocol} size={16} /><span class="muted">{p.server}</span></span></td>
            <td class="small muted hide-sm mono">{p.endpoint || '–'}</td>
            <td class="small muted hide-sm">{p.since ? duration(now / 1000 - p.since) : '–'}</td>
            <td>
              <div class="spd small"><span>↓ {speed(p.down)}</span><span class="muted">↑ {speed(p.up)}</span></div>
              <div class="bar"><div class="d" style="width:{(p.down / peak) * 100}%"></div><div class="u" style="width:{(p.up / peak) * 100}%"></div></div>
            </td>
          </tr>
        {:else}
          <tr><td colspan="6" class="empty small">{#if !lv.d}Lädt …{:else if allPeers.length}Keine Treffer für „{q}“{:else}<Icon name="moon" size={16} /> Gerade ist niemand verbunden{/if}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if !q && peers.length > limit}
    <button class="more small" onclick={() => (more = !more)}>{more ? 'Weniger zeigen' : `Alle ${fmtNum(peers.length)} zeigen`}</button>
  {/if}
  {#if lv.d && Object.keys(lv.d.errors || {}).length}
    <div class="tiny muted" style="padding:6px 14px 10px">Messung unvollständig: {Object.entries(lv.d.errors).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>
  {/if}
</div>

<style>
  .devs {
    min-width: 0;
  }
  .dh {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px 12px;
    flex-wrap: wrap;
    padding: 10px 14px 10px 16px;
  }
  .dh h3 {
    font-size: var(--fs-base);
  }
  .pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--ok);
    animation: blink 1.6s infinite;
  }
  @keyframes blink {
    50% {
      opacity: 0.35;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .pulse {
      animation: none;
    }
  }
  .table-wrap {
    overflow-x: auto;
    border-top: 1px solid var(--border);
  }
  .spd {
    display: flex;
    gap: 10px;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .bar {
    display: flex;
    height: 4px;
    border-radius: 4px;
    background: var(--panel-2);
    margin-top: 4px;
    overflow: hidden;
  }
  .bar .d {
    background: var(--down);
    transition: width 0.6s;
  }
  .bar .u {
    background: var(--up);
    transition: width 0.6s;
  }
  .nowrap {
    white-space: nowrap;
  }
  .mono {
    font-family: ui-monospace, monospace;
    font-size: var(--fs-sm);
  }
  .more {
    display: block;
    width: 100%;
    border: none;
    border-top: 1px solid var(--border);
    background: none;
    color: var(--accent);
    font: inherit;
    font-size: var(--fs-sm);
    font-weight: 550;
    padding: 9px;
    cursor: pointer;
  }
  .more:hover {
    background: var(--panel-2);
  }
  @media (max-width: 800px) {
    .hide-sm {
      display: none;
    }
  }
  @media (max-width: 520px) {
    .hide-xs {
      display: none;
    }
  }
</style>
