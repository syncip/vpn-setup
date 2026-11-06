<script>
  import { bytes } from '../lib/format.js';
  // points: [{ts, up, down}], bucket: Sekunden, since: Unix-Zeit
  let { points = [], bucket = 3600, since = 0, height = 180 } = $props();

  let hover = $state(-1);
  let el = $state();

  const data = $derived.by(() => {
    const now = Math.floor(Date.now() / 1000);
    const start = Math.floor((since || now - 24 * 3600) / bucket) * bucket;
    const map = new Map(points.map((p) => [p.ts, p]));
    const out = [];
    for (let t = start; t <= now; t += bucket) {
      const p = map.get(t);
      out.push({ ts: t, up: p?.up || 0, down: p?.down || 0 });
    }
    return out;
  });
  const maxV = $derived(Math.max(1, ...data.map((d) => d.up + d.down)));
  const total = $derived(data.reduce((s, d) => ({ up: s.up + d.up, down: s.down + d.down }), { up: 0, down: 0 }));

  function label(ts) {
    const d = new Date(ts * 1000);
    if (bucket < 86400) return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
  }
  function longLabel(ts) {
    const d = new Date(ts * 1000);
    if (bucket < 86400) return d.toLocaleString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    return d.toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' });
  }
  function move(e) {
    const r = el.getBoundingClientRect();
    const i = Math.floor(((e.clientX - r.left) / r.width) * data.length);
    hover = Math.max(0, Math.min(data.length - 1, i));
  }
  const ticks = $derived.by(() => {
    const n = data.length;
    const step = Math.max(1, Math.ceil(n / 6));
    const out = [];
    for (let i = 0; i < n; i += step) out.push(i);
    return out;
  });
</script>

<div class="chart">
  <div class="legend small">
    <span><i style="background:var(--down)"></i> Download {bytes(total.down)}</span>
    <span><i style="background:var(--up)"></i> Upload {bytes(total.up)}</span>
    <span class="muted">Spitze {bytes(maxV)}</span>
  </div>
  <div class="plot" style="height:{height}px" bind:this={el} onmousemove={move} onmouseleave={() => (hover = -1)} role="img" aria-label="Traffic-Verlauf">
    <div class="grid-lines"><span></span><span></span><span></span></div>
    <div class="bars">
      {#each data as d, i}
        <div class="bar" class:hl={hover === i}>
          <div class="seg up" style="height:{(d.up / maxV) * 100}%"></div>
          <div class="seg down" style="height:{(d.down / maxV) * 100}%"></div>
        </div>
      {/each}
    </div>
    {#if hover >= 0 && data[hover]}
      <div class="tip" style="left:{((hover + 0.5) / data.length) * 100}%">
        <div class="strong">{longLabel(data[hover].ts)}</div>
        <div>↓ {bytes(data[hover].down)}</div>
        <div>↑ {bytes(data[hover].up)}</div>
      </div>
    {/if}
  </div>
  <div class="axis tiny muted">
    {#each ticks as i}
      <span style="left:{((i + 0.5) / data.length) * 100}%">{label(data[i].ts)}</span>
    {/each}
  </div>
</div>

<style>
  .chart {
    width: 100%;
  }
  .legend {
    display: flex;
    gap: 16px;
    margin-bottom: 10px;
    flex-wrap: wrap;
  }
  .legend i {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 3px;
    margin-right: 4px;
  }
  .plot {
    position: relative;
  }
  .grid-lines {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    pointer-events: none;
  }
  .grid-lines span {
    border-top: 1px dashed var(--border);
  }
  .bars {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: flex-end;
    gap: 2px;
  }
  .bar {
    flex: 1;
    height: 100%;
    display: flex;
    flex-direction: column-reverse;
    border-radius: 3px 3px 0 0;
    min-width: 0;
  }
  .seg {
    width: 100%;
    transition: height 0.25s;
  }
  .seg.down {
    background: var(--down);
    border-radius: 3px 3px 0 0;
  }
  .seg.up {
    background: var(--up);
  }
  .bar.hl .seg {
    filter: brightness(1.15);
  }
  .bar.hl {
    background: var(--panel-2);
  }
  .tip {
    position: absolute;
    top: 4px;
    transform: translateX(-50%);
    background: var(--panel);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-lg);
    padding: 7px 10px;
    border-radius: 8px;
    font-size: 12px;
    pointer-events: none;
    white-space: nowrap;
    z-index: 2;
  }
  .axis {
    position: relative;
    height: 18px;
    margin-top: 4px;
  }
  .axis span {
    position: absolute;
    transform: translateX(-50%);
    white-space: nowrap;
  }
</style>
