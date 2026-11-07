<script>
  // Zoombares Zeitdiagramm (SVG).
  //   mode "bars": Traffic pro Zeitfenster (gestapelt Download/Upload), bucket in ms
  //   mode "line": Verlauf (z. B. Geschwindigkeit live), Lücken > gap ms werden nicht verbunden
  // Bedienung: Ziehen = Ausschnitt wählen, Umschalt+Ziehen = verschieben,
  //            Strg+Mausrad = zoomen, Doppelklick = zurücksetzen.
  // points: [{ts (ms), up, down}]
  let {
    points = [],
    mode = 'bars',
    bucket = 3600000,
    from = 0,
    to = 0,
    format = (v) => String(v),
    totalFormat = null,
    height = 200,
    gap = 0,
    onzoom = null,
    legendNow = false,
    binary = false, // Achse in 1024er-Schritten (Bytes)
  } = $props();

  let width = $state(600);
  let view = $state(null); // {from, to} oder null = alles
  let hover = $state(null); // {x, ts, up, down}
  let drag = $state(null); // {x0, x1, pan, vf, vt}
  let svgEl = $state();

  const PL = 64,
    PR = 10,
    PT = 10,
    PB = 22;
  const iw = $derived(Math.max(10, width - PL - PR));
  const ih = $derived(Math.max(10, height - PT - PB));

  const full = $derived.by(() => {
    let f = from,
      t = to;
    if (!f || !t) {
      const ts = points.map((p) => p.ts);
      f = f || Math.min(...ts, Date.now() - 3600000);
      t = t || Math.max(...ts, Date.now());
    }
    if (t <= f) t = f + 1000;
    return { from: f, to: t };
  });
  const vf = $derived(view ? view.from : full.from);
  const vt = $derived(view ? view.to : full.to);
  const X = (t) => PL + ((t - vf) / (vt - vf)) * iw;
  const T = (x) => vf + ((x - PL) / iw) * (vt - vf);

  // ---- Daten im Ausschnitt ----
  const bars = $derived.by(() => {
    if (mode !== 'bars') return [];
    const map = new Map(points.map((p) => [p.ts, p]));
    const out = [];
    let t = Math.floor(vf / bucket) * bucket;
    for (let n = 0; t < vt && n < 3000; t += bucket, n++) {
      const p = map.get(t);
      out.push({ ts: t, up: p?.up || 0, down: p?.down || 0 });
    }
    return out;
  });
  const visible = $derived.by(() => {
    if (mode !== 'line') return [];
    const s = points.findIndex((p) => p.ts >= vf);
    if (s < 0) return points.length ? [points[points.length - 1]] : [];
    let e = s;
    while (e < points.length && points[e].ts <= vt) e++;
    return points.slice(Math.max(0, s - 1), Math.min(points.length, e + 1));
  });

  function nice(v) {
    // Mindestskala, sonst zeigt ein leeres Diagramm Achsenwerte wie „1 B, 1 B, 0 B“
    if (binary && v < 1024) return 1024;
    if (v < 1000) return 1000;
    if (binary) {
      const b = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024)));
      return niceDec(v / b) * b;
    }
    return niceDec(v);
  }
  function niceDec(v) {
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }
  const yMax = $derived.by(() => {
    let m = 0;
    if (mode === 'bars') for (const b of bars) m = Math.max(m, b.up + b.down);
    else for (const p of visible) m = Math.max(m, p.up, p.down);
    return nice(m * 1.05);
  });
  const Y = (v) => PT + ih - (v / yMax) * ih;

  function path(key, area) {
    let d = '';
    let seg = [];
    const flush = () => {
      if (!seg.length) return;
      if (area) {
        d += `M${seg[0][0]},${PT + ih}` + seg.map(([x, y]) => `L${x},${y}`).join('') + `L${seg[seg.length - 1][0]},${PT + ih}Z`;
      } else {
        d += seg.map(([x, y], i) => `${i ? 'L' : 'M'}${x},${y}`).join('');
      }
      seg = [];
    };
    let prev = null;
    for (const p of visible) {
      if (gap && prev && p.ts - prev.ts > gap) flush();
      seg.push([X(p.ts).toFixed(1), Y(p[key]).toFixed(1)]);
      prev = p;
    }
    flush();
    return d;
  }

  // ---- Achsen ----
  const span = $derived(vt - vf);
  function tlabel(t) {
    const d = new Date(t);
    if (span <= 15 * 60000) return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (span <= 2 * 86400000) return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    if (span <= 10 * 86400000 && mode === 'bars' && bucket < 86400000)
      return d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit' });
    return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
  }
  function longLabel(t) {
    const d = new Date(t);
    if (mode === 'bars' && bucket >= 86400000) return d.toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' });
    const o = { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' };
    if (mode === 'line') o.second = '2-digit';
    let s = d.toLocaleString('de-DE', o);
    if (mode === 'bars' && bucket > 3600000) s += ' – ' + new Date(t + bucket).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    return s;
  }
  const xticks = $derived.by(() => {
    const n = Math.max(2, Math.floor(iw / 110));
    const steps = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800].map((s) => s * 1000);
    const step = steps.find((s) => span / s <= n) || span / n;
    const out = [];
    const off = new Date().getTimezoneOffset() * 60000;
    let t = Math.ceil((vf - off) / step) * step + off;
    if (step < 86400000) t = Math.ceil(vf / step) * step;
    for (; t <= vt; t += step) out.push(t);
    return out;
  });

  // ---- Summen für die Legende ----
  const sums = $derived.by(() => {
    if (mode === 'bars') return bars.reduce((s, b) => ({ up: s.up + b.up, down: s.down + b.down }), { up: 0, down: 0 });
    const last = points[points.length - 1];
    if (legendNow) return { up: last?.up || 0, down: last?.down || 0 };
    let up = 0,
      down = 0;
    for (const p of visible) {
      up = Math.max(up, p.up);
      down = Math.max(down, p.down);
    }
    return { up, down };
  });

  // ---- Bedienung ----
  function px(e) {
    const r = svgEl.getBoundingClientRect();
    return Math.max(PL, Math.min(PL + iw, ((e.clientX - r.left) / r.width) * width));
  }
  function setView(f, t, emit = true) {
    const minSpan = mode === 'bars' ? bucket * 2 : 10000;
    if (t - f < minSpan) {
      const c = (f + t) / 2;
      f = c - minSpan / 2;
      t = c + minSpan / 2;
    }
    if (mode === 'bars') {
      // nicht über den Datenbereich hinaus
      if (f < full.from) [f, t] = [full.from, Math.min(full.to, full.from + (t - f))];
      if (t > full.to) [f, t] = [Math.max(full.from, full.to - (t - f)), full.to];
    }
    if (f <= full.from + 1 && t >= full.to - 1) {
      reset();
      return;
    }
    view = { from: f, to: t };
    if (emit) onzoom?.(view.from, view.to);
  }
  export function reset() {
    const was = !!view;
    view = null;
    if (was) onzoom?.(null, null);
  }
  function down(e) {
    if (e.button !== 0) return;
    svgEl.setPointerCapture(e.pointerId);
    const x = px(e);
    drag = { x0: x, x1: x, pan: e.shiftKey && !!view, vf, vt };
    hover = null;
  }
  function move(e) {
    const x = px(e);
    if (drag) {
      if (drag.pan) {
        const dt = ((drag.x0 - x) / iw) * (drag.vt - drag.vf);
        view = { from: drag.vf + dt, to: drag.vt + dt };
      } else drag = { ...drag, x1: x };
      return;
    }
    const t = T(x);
    if (mode === 'bars') {
      const b = bars.find((b) => t >= b.ts && t < b.ts + bucket);
      hover = b ? { x: X(b.ts + bucket / 2), ...b } : null;
    } else {
      let best = null;
      for (const p of visible) if (!best || Math.abs(p.ts - t) < Math.abs(best.ts - t)) best = p;
      hover = best ? { x: X(best.ts), ...best } : null;
    }
  }
  function up() {
    if (!drag) return;
    const d = drag;
    drag = null;
    if (d.pan) {
      if (view) setView(view.from, view.to);
      return;
    }
    if (Math.abs(d.x1 - d.x0) > 6) {
      const a = T(Math.min(d.x0, d.x1)),
        b = T(Math.max(d.x0, d.x1));
      setView(a, b);
    }
  }
  $effect(() => {
    const el = svgEl;
    if (!el) return;
    const wheel = (e) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const c = T(px(e));
      const k = e.deltaY > 0 ? 1.3 : 1 / 1.3;
      setView(c - (c - vf) * k, c + (vt - c) * k);
    };
    el.addEventListener('wheel', wheel, { passive: false });
    return () => el.removeEventListener('wheel', wheel);
  });
  const sel = $derived(drag && !drag.pan && Math.abs(drag.x1 - drag.x0) > 2 ? { x: Math.min(drag.x0, drag.x1), w: Math.abs(drag.x1 - drag.x0) } : null);
  const tipLeft = $derived(hover ? Math.min(Math.max(hover.x / width, 0.12), 0.88) * 100 : 0);
</script>

<div class="tchart">
  <div class="legend small">
    <span><i style="background:var(--down)"></i> Download {(totalFormat || format)(sums.down)}</span>
    <span><i style="background:var(--up)"></i> Upload {(totalFormat || format)(sums.up)}</span>
    {#if mode === 'line' && !legendNow}<span class="muted">Spitzen im Ausschnitt</span>{/if}
    <span class="grow"></span>
    {#if view}
      <button class="btn sm" onclick={reset} title="Ganzen Zeitraum zeigen (Doppelklick)">Zoom zurücksetzen</button>
    {:else}
      <span class="tiny muted hint">Ziehen zum Zoomen · Strg+Mausrad</span>
    {/if}
  </div>
  <div class="wrap" bind:clientWidth={width} style="height:{height}px">
    <svg
      bind:this={svgEl}
      viewBox="0 0 {width} {height}"
      width={width}
      height={height}
      role="img"
      aria-label="Verlauf"
      onpointerdown={down}
      onpointermove={move}
      onpointerup={up}
      onpointercancel={() => (drag = null)}
      onpointerleave={() => (hover = null)}
      ondblclick={reset}
      class:panning={drag?.pan}
    >
      {#each [0, 0.5, 1] as f}
        <line x1={PL} x2={PL + iw} y1={PT + ih * (1 - f)} y2={PT + ih * (1 - f)} class="grid" />
        <text x={PL - 8} y={PT + ih * (1 - f) + 4} class="ylab">{format(yMax * f)}</text>
      {/each}
      {#each xticks as t}
        <text x={X(t)} y={height - 5} class="xlab">{tlabel(t)}</text>
      {/each}

      <clipPath id="clip-{PL}-{height}"><rect x={PL} y={0} width={iw} height={PT + ih} /></clipPath>
      <g clip-path="url(#clip-{PL}-{height})">
        {#if mode === 'bars'}
          {#each bars as b}
            {@const x0 = X(b.ts)}
            {@const w = Math.max(1, X(b.ts + bucket) - x0 - (iw / bars.length > 6 ? 2 : 0.5))}
            <rect x={x0} y={Y(b.down)} width={w} height={PT + ih - Y(b.down)} class="down" rx="2" class:hl={hover?.ts === b.ts} />
            <rect x={x0} y={Y(b.down + b.up)} width={w} height={Y(b.down) - Y(b.down + b.up)} class="up" class:hl={hover?.ts === b.ts} />
          {/each}
        {:else}
          <path d={path('down', true)} class="area-down" />
          <path d={path('down', false)} class="line-down" />
          <path d={path('up', false)} class="line-up" />
        {/if}
      </g>
      {#if hover && mode === 'line'}
        <line x1={hover.x} x2={hover.x} y1={PT} y2={PT + ih} class="cursor" />
        <circle cx={hover.x} cy={Y(hover.down)} r="3.5" class="dot-down" />
        <circle cx={hover.x} cy={Y(hover.up)} r="3" class="dot-up" />
      {/if}
      {#if sel}
        <rect x={sel.x} y={PT} width={sel.w} height={ih} class="sel" />
      {/if}
    </svg>
    {#if hover && !drag}
      <div class="tip" style="left:{tipLeft}%">
        <div class="strong">{longLabel(hover.ts)}</div>
        <div>↓ {format(hover.down)}</div>
        <div>↑ {format(hover.up)}</div>
      </div>
    {/if}
  </div>
</div>

<style>
  .tchart {
    width: 100%;
  }
  .legend {
    display: flex;
    gap: 16px;
    margin-bottom: 8px;
    flex-wrap: wrap;
    align-items: center;
    min-height: 28px;
  }
  .legend i {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 3px;
    margin-right: 4px;
  }
  .grow {
    flex: 1;
  }
  .btn.sm {
    padding: 3px 10px;
    font-size: 12px;
  }
  .wrap {
    position: relative;
    width: 100%;
  }
  svg {
    display: block;
    cursor: crosshair;
    user-select: none;
    touch-action: pan-y;
    overflow: visible;
  }
  svg.panning {
    cursor: grabbing;
  }
  .grid {
    stroke: var(--border);
    stroke-dasharray: 3 4;
  }
  .ylab {
    fill: var(--muted);
    font-size: 11px;
    text-anchor: end;
  }
  .xlab {
    fill: var(--muted);
    font-size: 11px;
    text-anchor: middle;
  }
  .down {
    fill: var(--down);
  }
  .up {
    fill: var(--up);
  }
  rect.hl {
    filter: brightness(1.18);
  }
  .area-down {
    fill: var(--down);
    opacity: 0.18;
  }
  .line-down {
    fill: none;
    stroke: var(--down);
    stroke-width: 2;
    stroke-linejoin: round;
  }
  .line-up {
    fill: none;
    stroke: var(--up);
    stroke-width: 1.6;
    stroke-linejoin: round;
  }
  .cursor {
    stroke: var(--muted);
    stroke-dasharray: 2 3;
  }
  .dot-down {
    fill: var(--down);
  }
  .dot-up {
    fill: var(--up);
  }
  .sel {
    fill: var(--accent);
    opacity: 0.15;
    stroke: var(--accent);
    stroke-width: 1;
  }
  .tip {
    position: absolute;
    top: 0;
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
  @media (max-width: 700px) {
    .hint {
      display: none;
    }
  }
</style>
