<script>
  // Live-Ansicht des Panel-DNS: Anfragen je Sekunde und benutzte DNS-Server (seit dem Start).
  import Info from './Info.svelte';
  import Icon from './Icon.svelte';
  import { get } from '../lib/api.js';
  import { fmtNum } from '../lib/format.js';

  let secs = $state(300);
  let d = $state(null);
  let paused = $state(false);
  let hover = $state(null);
  let width = $state(600);
  const H = 120;

  async function load() {
    if (paused || document.hidden) return;
    d = await get(`/dns/live?secs=${secs}`).catch(() => d);
  }
  $effect(() => {
    secs;
    load();
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  });

  // auf 5-Sekunden-Schritte zusammenfassen, wenn es eng wird
  const step = $derived(secs > 300 ? 5 : secs > 120 ? 2 : 1);
  const pts = $derived.by(() => {
    if (!d) return [];
    const out = [];
    for (let i = 0; i < d.points.length; i += step) {
      const g = d.points.slice(i, i + step);
      const ok = g.reduce((a, p) => a + (p.n - p.bl - p.cached - p.err), 0);
      out.push({
        ts: g[0].ts,
        n: g.reduce((a, p) => a + p.n, 0) / g.length,
        bl: g.reduce((a, p) => a + p.bl, 0) / g.length,
        cached: g.reduce((a, p) => a + p.cached, 0) / g.length,
        ms: ok ? g.reduce((a, p) => a + p.ms * (p.n - p.bl - p.cached - p.err), 0) / ok : 0,
      });
    }
    return out;
  });
  const max = $derived(Math.max(5, ...pts.map((p) => p.n)) * 1.1);
  const x = (i) => (pts.length < 2 ? 0 : (i / (pts.length - 1)) * width);
  const y = (v) => H - (v / max) * H;
  function area(key) {
    if (!pts.length) return '';
    let s = `M0,${H}`;
    pts.forEach((p, i) => (s += ` L${x(i).toFixed(1)},${y(key(p)).toFixed(1)}`));
    return s + ` L${width},${H} Z`;
  }
  const avgMS = $derived.by(() => {
    if (!d) return 0;
    let w = 0,
      sum = 0;
    for (const p of d.points.slice(-60)) {
      const ok = p.n - p.bl - p.cached - p.err;
      w += ok;
      sum += p.ms * ok;
    }
    return w ? Math.round(sum / w) : 0;
  });
  const lastMin = $derived(d ? d.points.slice(-61, -1) : []);
  const blPct = $derived.by(() => {
    const n = lastMin.reduce((a, p) => a + p.n, 0);
    return n ? Math.round((lastMin.reduce((a, p) => a + p.bl, 0) / n) * 100) : 0;
  });
  function move(ev) {
    const r = ev.currentTarget.getBoundingClientRect();
    const i = Math.round(((ev.clientX - r.left) / r.width) * (pts.length - 1));
    hover = pts[Math.max(0, Math.min(pts.length - 1, i))] ? { i, p: pts[Math.max(0, Math.min(pts.length - 1, i))] } : null;
  }
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString('de-DE');
</script>

<div class="card livecard">
  <div class="card-head">
    <h3>
      <span class="pulse" class:paused></span> Live
      <Info title="Live" text="Anfragen je Sekunde am Panel-DNS (aus dem Speicher, unabhängig vom Protokoll). Grau = beantwortet, rot = gesperrt, hell = aus dem Zwischenspeicher. Wird alle 2 Sekunden aktualisiert." />
    </h3>
    <div class="row" style="gap:8px">
      <div class="segmented">
        {#each [[60, '1 Min.'], [300, '5 Min.'], [600, '10 Min.']] as [s, l]}<button class:active={secs === s} onclick={() => (secs = s)}>{l}</button>{/each}
      </div>
      <button class="btn sm" onclick={() => (paused = !paused)}>{paused ? 'Weiter' : 'Anhalten'}</button>
    </div>
  </div>
  <div class="card-pad" style="padding-top:0">
    <div class="lkpis">
      <div><div class="tiny muted">Anfragen/s</div><div class="lk">{d ? fmtNum(Math.round(d.qps * 10) / 10) : '–'}</div></div>
      <div><div class="tiny muted">Spitze</div><div class="lk">{d ? fmtNum(d.peak) : '–'}<span class="tiny muted"> /s</span></div></div>
      <div><div class="tiny muted">Gesperrt (1 Min.)</div><div class="lk bad-text">{blPct} %</div></div>
      <div><div class="tiny muted">Ø Antwort (1 Min.)</div><div class="lk">{avgMS ? `${avgMS} ms` : '–'}</div></div>
      <div><div class="tiny muted">Geräte aktiv</div><div class="lk">{d ? fmtNum(d.clients) : '–'}</div></div>
    </div>
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="chart" bind:clientWidth={width} onmousemove={move} onmouseleave={() => (hover = null)}>
      <svg {width} height={H} viewBox="0 0 {width} {H}" preserveAspectRatio="none">
        {#each [0.25, 0.5, 0.75] as f}<line x1="0" x2={width} y1={H * f} y2={H * f} class="grid" />{/each}
        <path d={area((p) => p.n)} class="a-all" />
        <path d={area((p) => p.cached + p.bl)} class="a-cache" />
        <path d={area((p) => p.bl)} class="a-bl" />
        {#if hover}<line x1={x(hover.i)} x2={x(hover.i)} y1="0" y2={H} class="cursor" />{/if}
      </svg>
      <div class="ymax tiny muted">{fmtNum(Math.round(max))}/s</div>
      {#if hover}
        <div class="tip tiny" style="left:{Math.min(width - 170, Math.max(0, x(hover.i) - 80))}px">
          <b>{clock(hover.p.ts)}</b><br />
          {fmtNum(Math.round(hover.p.n * 10) / 10)} Anfragen/s · {fmtNum(Math.round(hover.p.bl * 10) / 10)} gesperrt<br />
          {fmtNum(Math.round(hover.p.cached * 10) / 10)} aus dem Speicher{hover.p.ms ? ` · Ø ${Math.round(hover.p.ms)} ms` : ''}
        </div>
      {/if}
    </div>
    <div class="row tiny muted" style="justify-content:space-between;margin-top:2px">
      <span>vor {secs >= 120 ? `${secs / 60} Min.` : `${secs} s`}</span>
      <span><span class="sw all"></span> beantwortet <span class="sw cache"></span> Speicher <span class="sw bl"></span> gesperrt</span>
      <span>jetzt</span>
    </div>

    <div class="ups">
      <div class="row" style="gap:6px;margin-bottom:6px">
        <strong class="small">DNS-Server seit dem Start</strong>
        <Info title="DNS-Server" text="Welcher DNS-Server die Anfragen beantwortet hat, die nicht aus dem Speicher kamen – seit dem letzten Start des Dienstes. Mit Unbound als Resolver beantwortet Unbound fast alles; die anderen springen nur ein, wenn er nicht antwortet. Antwortzeit = gleitender Mittelwert." />
      </div>
      {#if d?.unbound?.on && !d.unbound.ok}
        <div class="notice bad small ubdown">
          <Icon name="alert" size={16} />
          <div>
            <b>Unbound ausgefallen – wird übersprungen.</b> {d.unbound.why}
            {#if d.unbound.detail}<details><summary>Meldungen von Unbound</summary><pre>{d.unbound.detail}</pre></details>{/if}
          </div>
        </div>
      {/if}
      {#each d?.upstreams || [] as u}
        <div class="up">
          <span class="small strong ellipsis" title={u.server}>{u.name}</span>
          <span class="mono tiny muted ellipsis">{u.server.replace(/:53$/, '')}</span>
          <span class="share"><span style="width:{u.share}%"></span></span>
          <span class="tiny num">{u.share} %</span>
          <span class="tiny muted num">{fmtNum(u.ok)}×</span>
          <span class="tiny num">{u.ms} ms</span>
          <span class="tiny num {u.fail ? 'warn-text' : 'muted'}">{u.fail ? `${fmtNum(u.fail)} Ausf.` : ''}</span>
        </div>
      {:else}
        <div class="muted small">Noch keine Anfrage an einen DNS-Server.</div>
      {/each}
    </div>
  </div>
</div>

<style>
  .ubdown {
    margin-bottom: 8px;
  }
  .ubdown details {
    margin-top: 4px;
  }
  .ubdown summary {
    cursor: pointer;
  }
  .ubdown pre {
    margin: 4px 0 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 11px;
  }
  .livecard {
    margin-bottom: 14px;
  }
  .pulse {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--ok, #16a34a);
    margin-right: 2px;
    animation: pulse 1.6s infinite;
  }
  .pulse.paused {
    background: var(--text-3, #999);
    animation: none;
  }
  @keyframes pulse {
    50% {
      opacity: 0.35;
    }
  }
  .lkpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
    gap: 10px;
    margin-bottom: 10px;
  }
  .lk {
    font-size: 20px;
    font-weight: 650;
    font-variant-numeric: tabular-nums;
  }
  .chart {
    position: relative;
    height: 120px;
    cursor: crosshair;
  }
  .chart svg {
    display: block;
  }
  .grid {
    stroke: var(--border);
    stroke-dasharray: 3 4;
  }
  .a-all {
    fill: var(--accent);
    opacity: 0.55;
  }
  .a-cache {
    fill: var(--accent);
    opacity: 0.25;
  }
  .a-bl {
    fill: var(--bad, #dc2626);
    opacity: 0.7;
  }
  .cursor {
    stroke: var(--text-2);
    stroke-width: 1;
  }
  .ymax {
    position: absolute;
    top: 0;
    left: 4px;
  }
  .tip {
    position: absolute;
    top: 6px;
    width: 160px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 7px;
    pointer-events: none;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12);
  }
  .sw {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 2px;
    margin: 0 2px 0 8px;
    vertical-align: -1px;
  }
  .sw.all {
    background: var(--accent);
    opacity: 0.55;
  }
  .sw.cache {
    background: var(--accent);
    opacity: 0.25;
  }
  .sw.bl {
    background: var(--bad, #dc2626);
    opacity: 0.7;
  }
  .ups {
    margin-top: 14px;
    border-top: 1px solid var(--border);
    padding-top: 10px;
  }
  .up {
    display: grid;
    grid-template-columns: minmax(80px, 140px) minmax(70px, 1fr) 90px 48px 64px 56px 64px;
    gap: 8px;
    align-items: center;
    padding: 3px 0;
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .share {
    height: 6px;
    border-radius: 3px;
    background: var(--border);
    overflow: hidden;
  }
  .share span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  @media (max-width: 640px) {
    .up {
      grid-template-columns: 1fr 70px 44px 56px;
    }
    .up > :nth-child(2),
    .up > :nth-child(5),
    .up > :nth-child(7) {
      display: none;
    }
  }
</style>
