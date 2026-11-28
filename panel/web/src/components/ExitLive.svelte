<script>
  // Live-Anzeige der Ausgänge und Gruppen: aktueller Durchsatz alle 2 s, Verlauf der letzten 30 Minuten
  // (sammelt das Panel, solange eine Live-Anzeige offen ist; beim Öffnen wird er einmal geholt).
  //   exit: fest auf diesen Ausgang (Detailansicht, ohne Liste) · id: Speicherort der Grafik-Einstellungen
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import Chart from './Chart.svelte';
  import StateBadge from './StateBadge.svelte';
  import { get } from '../lib/api.js';
  import { speed } from '../lib/format.js';
  import { exitState } from '../lib/exitstate.js';

  let { exits = [], groups = [], exit = 0, id = 'exits-live', title = 'Ausgänge live', height = 170 } = $props();

  const KEEP = 30 * 60 * 1000;
  let win = $state('5'); // Minuten
  let selPick = $state('all'); // all | e<id> | g<id>
  const sel = $derived(exit ? 'e' + exit : selPick);
  let cur = $state(null); // letzte Antwort
  let hist = $state({}); // Schlüssel → [{ts, up, down}]

  function push(key, ts, r) {
    const list = hist[key] || [];
    list.push({ ts, up: r?.up || 0, down: r?.down || 0 });
    while (list.length && list[0].ts < ts - KEEP) list.shift();
    hist[key] = list;
  }
  let first = true;
  async function poll() {
    if (document.hidden) return;
    try {
      const r = await get(first ? '/exits/live?hist=1' : '/exits/live');
      if (first && r.history) {
        const h = {};
        for (const [k, l] of Object.entries(r.history)) h[k] = l.filter((p) => p.ts < r.ts - 500).map((p) => ({ ts: p.ts, up: p.up || 0, down: p.down || 0 }));
        hist = h;
      }
      first = false;
      cur = r;
      let up = 0,
        down = 0;
      for (const [id, v] of Object.entries(r.exits || {})) {
        push('e' + id, r.ts, v);
        up += v.up;
        down += v.down;
      }
      for (const [id, v] of Object.entries(r.groups || {})) push('g' + id, r.ts, v);
      push('all', r.ts, { up, down });
    } catch {}
  }
  poll();
  $effect(() => {
    const t = setInterval(poll, 2000);
    return () => clearInterval(t);
  });

  const now = $derived(cur?.ts || Date.now());
  const points = $derived(hist[sel] || []);
  const last = $derived(points[points.length - 1] || { up: 0, down: 0 });
  const rateOf = (key) => {
    const l = hist[key];
    return l?.length ? l[l.length - 1] : { up: 0, down: 0 };
  };
  const peak = $derived(Math.max(1, ...exits.map((e) => rateOf('e' + e.id).down + rateOf('e' + e.id).up), ...groups.map((g) => rateOf('g' + g.id).down + rateOf('g' + g.id).up)));
  const exitName = (id) => exits.find((e) => e.id === id)?.name || '–';
  const selName = $derived(sel === 'all' ? 'Alle Ausgänge' : sel[0] === 'e' ? exitName(+sel.slice(1)) : 'Gruppe ' + (groups.find((g) => g.id === +sel.slice(1))?.name || ''));
  const toggle = (k) => (selPick = selPick === k ? 'all' : k);
  const SERIES = [
    { key: 'down', label: 'Download', color: 'var(--down)' },
    { key: 'up', label: 'Upload', color: 'var(--up)' },
  ];
</script>

<Chart
  {id}
  {title}
  sub={exit ? '' : selName}
  series={SERIES}
  {points}
  unit="rate"
  kinds={['area', 'line']}
  from={now - +win * 60000}
  to={now}
  gap={8000}
  {height}
  ranges={[['2', '2 Min.'], ['5', '5 Min.'], ['15', '15 Min.'], ['30', '30 Min.']]}
  bind:range={win}
  live
>
  {#snippet tools()}<Info title="Live" text="Durchsatz der Ausgänge, alle 2 Sekunden gemessen an den Schnittstellen ex<ID>. Eine Gruppe zeigt den Durchsatz ihres aktiven Ausgangs. Den Verlauf der letzten 30 Minuten sammelt das Panel, solange eine Live-Anzeige offen ist – er bleibt beim Neuladen erhalten. Zeile anklicken = nur diesen Ausgang bzw. diese Gruppe im Diagramm." />{/snippet}
  {#snippet children()}
    <div class="kpis">
      <div><div class="muted tiny">Download</div><div class="kpi">{speed(last.down)}</div></div>
      <div><div class="muted tiny">Upload</div><div class="kpi up">{speed(last.up)}</div></div>
      {#if !exit}<div><div class="muted tiny">Ausgänge verbunden</div><div class="kpi other">{exits.filter((e) => exitState(e).tone === 'ok').length}<span class="muted"> / {exits.filter((e) => e.enabled).length}</span></div></div>{/if}
    </div>
  {/snippet}
  {#snippet footer()}
  {#if !exit}
  <div class="rows">
    {#if groups.length}<div class="sect tiny muted">Gruppen</div>{/if}
    {#each groups as g (g.id)}
      {@const r = rateOf('g' + g.id)}
      {@const act = cur?.active?.[g.id] || g.status?.active || 0}
      <button class="lrow" class:sel={sel === 'g' + g.id} onclick={() => toggle('g' + g.id)}>
        <span class="name"><Icon name="layers" size={14} /> <span class="strong small ellipsis">{g.name}</span></span>
        <span class="small muted ellipsis via">{#if !g.enabled}deaktiviert{:else if g.limit?.status === 'blocked'}gesperrt (Limit){:else if act}über {exitName(act)}{:else}{g.status?.state === 'direct' ? 'direkt' : 'gesperrt'}{/if}</span>
        <span class="spd small"><span>↓ {speed(r.down)}</span><span class="muted">↑ {speed(r.up)}</span></span>
        <span class="bar"><span class="d" style="width:{(r.down / peak) * 100}%"></span><span class="u" style="width:{(r.up / peak) * 100}%"></span></span>
      </button>
    {/each}
    <div class="sect tiny muted">Ausgänge</div>
    {#each exits as e (e.id)}
      {@const r = rateOf('e' + e.id)}
      {@const st = exitState(e)}
      <button class="lrow" class:sel={sel === 'e' + e.id} class:off={!e.enabled} onclick={() => toggle('e' + e.id)}>
        <span class="name"><span class="strong small ellipsis">{e.name}</span></span>
        <span class="via"><StateBadge small tone={st.tone} label={st.label} icon={st.icon} title={st.detail} />{#if e.limit?.status === 'throttled'}&nbsp;<StateBadge small tone="warn" icon="gauge" label="gedrosselt" title={e.limit.reason} />{/if}</span>
        <span class="spd small"><span>↓ {speed(r.down)}</span><span class="muted">↑ {speed(r.up)}</span></span>
        <span class="bar"><span class="d" style="width:{(r.down / peak) * 100}%"></span><span class="u" style="width:{(r.up / peak) * 100}%"></span></span>
      </button>
    {:else}
      <div class="small muted" style="padding:8px 12px">Noch keine Ausgänge.</div>
    {/each}
  </div>
  {/if}
  {/snippet}
</Chart>

<style>
  .kpis {
    display: flex;
    gap: 28px;
    flex-wrap: wrap;
  }
  .kpi {
    font-size: var(--fs-lg);
    font-weight: 700;
    color: var(--down);
  }
  .kpi.up {
    color: var(--up);
  }
  .kpi.other {
    color: var(--text);
  }
  .rows {
    display: flex;
    flex-direction: column;
    padding: 0 6px 8px;
    border-top: 1px solid var(--border);
  }
  .sect {
    padding: 8px 12px 2px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .lrow {
    display: grid;
    grid-template-columns: minmax(120px, 1.2fr) minmax(120px, 1.3fr) 190px minmax(80px, 1fr);
    gap: 12px;
    align-items: center;
    padding: 7px 12px;
    border: 0;
    border-radius: var(--radius-sm);
    background: none;
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .lrow:hover {
    background: var(--panel-2);
  }
  .lrow.sel {
    background: var(--accent-soft);
  }
  .lrow.off {
    opacity: 0.6;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .via {
    min-width: 0;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px;
  }
  .spd {
    display: flex;
    gap: 10px;
    white-space: nowrap;
  }
  .bar {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .bar span {
    height: 4px;
    border-radius: 4px;
    min-width: 2px;
    transition: width 0.4s;
  }
  .bar .d {
    background: var(--down);
  }
  .bar .u {
    background: var(--up);
  }
  @media (max-width: 760px) {
    .lrow {
      grid-template-columns: 1fr auto;
    }
    .bar {
      grid-column: 1 / -1;
    }
  }
</style>
