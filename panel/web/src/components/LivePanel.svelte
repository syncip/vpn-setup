<script>
  // Live-Anzeige: aktuelle Geschwindigkeit, Verlauf der letzten Minuten (zoombar) und
  // verbundene Geräte. Fragt alle 2 Sekunden ab, solange die Seite sichtbar ist.
  import Icon from './Icon.svelte';
  import ProtoLogo from './ProtoLogo.svelte';
  import TimeChart from './TimeChart.svelte';
  import { get } from '../lib/api.js';
  import { speed, duration } from '../lib/format.js';

  let { user = 0, compact = false, connected = $bindable(0) } = $props();

  const windows = [
    [120, '2 Min.'],
    [600, '10 Min.'],
    [1800, '30 Min.'],
  ];
  let win = $state(600);
  let d = $state(null);
  let err = $state('');
  let now = $state(Date.now());
  let busy = false;

  async function poll() {
    if (busy || document.hidden) return;
    busy = true;
    try {
      d = await get(user ? `/live?user=${user}` : '/live');
      now = Date.now();
      err = '';
    } catch (e) {
      err = e.message;
    } finally {
      busy = false;
    }
  }
  $effect(() => {
    user;
    poll();
    const t = setInterval(poll, 2000);
    const vis = () => !document.hidden && poll();
    document.addEventListener('visibilitychange', vis);
    return () => {
      clearInterval(t);
      document.removeEventListener('visibilitychange', vis);
    };
  });

  const hist = $derived(d?.history || []);
  const cur = $derived.by(() => {
    if (!d) return { up: 0, down: 0 };
    if (user) {
      const h = hist[hist.length - 1];
      return { up: h?.up || 0, down: h?.down || 0 };
    }
    return { up: d.total.up, down: d.total.down };
  });
  const peers = $derived((d?.peers || []).filter((p) => !user || p.user_id === Number(user)));
  $effect(() => {
    connected = peers.length;
  });
  const peak = $derived(Math.max(1, ...peers.map((p) => p.up + p.down)));
</script>

{#if err}<div class="notice bad" style="margin-bottom:12px">{err}</div>{/if}

<div class="card live">
  <div class="card-head">
    <h2 class="row" style="gap:8px"><span class="pulse"></span> Live</h2>
    <div class="segmented">
      {#each windows as [s, l]}<button class:active={win === s} onclick={() => (win = s)}>{l}</button>{/each}
    </div>
  </div>
  <div class="card-pad">
    <div class="kpis" class:compact>
      <div>
        <div class="muted tiny">Download</div>
        <div class="kpi down">{speed(cur.down)}</div>
      </div>
      <div>
        <div class="muted tiny">Upload</div>
        <div class="kpi up">{speed(cur.up)}</div>
      </div>
      {#if !user}
        <div>
          <div class="muted tiny">Nutzer online</div>
          <div class="kpi">{d?.total.users_online ?? '–'}<span class="muted">{' / '}{d?.total.users ?? '–'}</span></div>
        </div>
        <div>
          <div class="muted tiny">Geräte verbunden</div>
          <div class="kpi">{d?.total.peers_online ?? '–'}<span class="muted">{' / '}{d?.total.peers ?? '–'}</span></div>
        </div>
      {:else}
        <div>
          <div class="muted tiny">Verbunden</div>
          <div class="kpi">{peers.length}</div>
        </div>
      {/if}
    </div>
    <TimeChart mode="line" points={hist} from={now - win * 1000} to={now} format={speed} gap={25000} height={compact ? 160 : 200} legendNow />
  </div>

  {#if !compact || peers.length}
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            {#if !user}<th>Nutzer</th>{/if}
            <th>Gerät</th>
            <th class="hide-xs">Server</th>
            <th class="hide-sm">Adresse</th>
            <th class="hide-sm">Verbunden</th>
            <th style="width:30%">Geschwindigkeit</th>
          </tr>
        </thead>
        <tbody>
          {#each peers as p (p.id)}
            <tr>
              {#if !user}<td class="nowrap"><a href="#/users/{p.user_id}" class="strong">{p.user}</a></td>{/if}
              <td class="nowrap">{p.name}</td>
              <td class="small hide-xs"><span class="row" style="gap:6px;flex-wrap:nowrap"><ProtoLogo id={p.protocol} size={18} /><span class="muted">{p.server}</span></span></td>
              <td class="small muted hide-sm mono">{p.endpoint || '–'}</td>
              <td class="small muted hide-sm">{p.since ? duration(now / 1000 - p.since) : '–'}</td>
              <td>
                <div class="spd small"><span>↓ {speed(p.down)}</span><span class="muted">↑ {speed(p.up)}</span></div>
                <div class="bar"><div class="d" style="width:{(p.down / peak) * 100}%"></div><div class="u" style="width:{(p.up / peak) * 100}%"></div></div>
              </td>
            </tr>
          {:else}
            <tr><td colspan="6" class="empty small"><Icon name="moon" size={16} /> Gerade ist niemand verbunden</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if d && Object.keys(d.errors || {}).length}
    <div class="card-pad tiny muted">Messung unvollständig: {Object.entries(d.errors).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>
  {/if}
</div>

<style>
  .kpis {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 14px;
  }
  .kpis.compact {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  @media (max-width: 700px) {
    .kpis {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
  .kpi {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
  }
  .kpi .muted {
    font-size: 15px;
  }
  .kpi.down {
    color: var(--down);
  }
  .kpi.up {
    color: var(--up);
  }
  .pulse {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--ok, #22a06b);
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--ok, #22a06b) 60%, transparent);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    70% {
      box-shadow: 0 0 0 8px transparent;
    }
    100% {
      box-shadow: 0 0 0 0 transparent;
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
    height: 5px;
    border-radius: 5px;
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
    font-size: 12px;
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
