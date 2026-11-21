<script>
  // Einheitliche Grafik für alle Verläufe (Live, Verkehr, Ausgänge, DNS) – immer mit derselben Bedienung:
  //   Zeitraum-Knöpfe (ranges, range bindbar) · Zoom: Ziehen = Ausschnitt, Umschalt+Ziehen = verschieben,
  //   Strg+Mausrad oder −/+ = zoomen, Doppelklick = zurück · Legende anklicken = Reihe aus-/einblenden ·
  //   Anhalten (live) · Vergrößern · Menü „…“: Darstellung, Einheit, Höhe, Reihen, CSV, zurücksetzen.
  // Einstellungen (Darstellung, ausgeblendete Reihen, Einheit, Höhe, Zeitraum) werden je id pro Admin gespeichert.
  //   series: [{ key, label, color }]           points: [{ ts (ms), [key]: Zahl }]
  //   kinds: erlaubte Darstellungen ('line' | 'area' | 'bars'), kind: Vorgabe (sonst kinds[0])
  //   unit: 'rate' (Byte/s, umschaltbar bit/s ↔ Byte/s) | 'bytes' | 'count'; format: eigene Anzeige (überstimmt unit)
  //   bucket: Balkenbreite in ms (Verlauf mit festen Zeitfenstern), gap: Lücken > gap ms nicht verbinden
  //   stack: Reihen stapeln (Balken immer), legend: 'now' (letzter Wert) | 'sum' | 'peak'
  //   children: Kennzahlen über der Grafik, tools: eigene Bedienelemente im Kopf, footer: Inhalt unter der Grafik
  import Icon from './Icon.svelte';
  import { untrack } from 'svelte';
  import { layout, loadLayout, saveLayout } from '../lib/layout.svelte.js';
  import { speed, bytes, fmtNum, download } from '../lib/format.js';

  let {
    id = '',
    title = '',
    icon = '',
    series = [],
    points = [],
    kinds = ['line', 'area'],
    kind: kindDefault = '',
    unit = 'count',
    format = null,
    bucket = 0,
    from = 0,
    to = 0,
    gap = 0,
    height = 200,
    ranges = [],
    range = $bindable(''),
    live = false,
    stack = false,
    legend = 'now',
    onzoom = null,
    sub = '',
    children,
    tools,
    footer,
  } = $props();

  // ---------- gespeicherte Einstellungen ----------
  loadLayout();
  const skey = $derived(id ? `chart:${id}` : '');
  const saved = $derived((skey && layout.data[skey]) || {});
  function store(patch) {
    if (!skey) {
      local = { ...local, ...patch };
      return;
    }
    layout.data[skey] = { ...(layout.data[skey] || {}), ...patch };
    saveLayout();
  }
  let local = $state({}); // ohne id: nur bis zum Neuladen
  const opt = $derived(skey ? saved : local);
  const kindKey = $derived('kind_' + unit); // Darstellung je Einheit (Live-Linie vs. Verlauf-Balken)
  const kind = $derived(kinds.includes(opt[kindKey]) ? opt[kindKey] : kinds.includes(kindDefault) ? kindDefault : kinds[0]);
  const hidden = $derived(new Set(opt.hidden || []));
  const bits = $derived(opt.unit !== 'bytes');
  const SIZES = { s: 0.65, m: 1, l: 1.7 };
  const size = $derived(SIZES[opt.size] ? opt.size : 'm');
  const H = $derived(Math.round(height * SIZES[size]));

  // gespeicherten Zeitraum einmal übernehmen
  let rangeTaken = false;
  $effect(() => {
    if (rangeTaken || !layout.loaded) return;
    rangeTaken = true;
    const r = untrack(() => saved.range);
    if (r && ranges.some(([k]) => k === r) && r !== untrack(() => range)) range = r;
  });
  function pickRange(k) {
    range = k;
    reset();
    if (skey) store({ range: k });
  }

  // ---------- Anhalten ----------
  let frozen = $state(null);
  function togglePause() {
    frozen = frozen ? null : $state.snapshot({ points, from, to });
  }
  const P = $derived(frozen ? frozen.points : points);
  const F0 = $derived(frozen ? frozen.from : from);
  const T0 = $derived(frozen ? frozen.to : to);

  // ---------- Werte anzeigen ----------
  const fmt = $derived(
    format ||
      (unit === 'rate' ? (v) => (bits ? speed(v) : bytes(v) + '/s') : unit === 'bytes' ? bytes : (v) => fmtNum(Math.round(v * 10) / 10)),
  );
  const shown = $derived(series.filter((s) => !hidden.has(s.key)));

  // ---------- Geometrie ----------
  let width = $state(600);
  const PR = 10,
    PT = 8,
    PB = 22;
  const iw = $derived(Math.max(10, width - PL - PR));
  const ih = $derived(Math.max(10, H - PT - PB));

  const full = $derived.by(() => {
    let f = F0,
      t = T0;
    if (!f || !t) {
      const ts = P.map((p) => p.ts);
      f = f || Math.min(...ts, Date.now() - 3600000);
      t = t || Math.max(...ts, Date.now());
    }
    if (t <= f) t = f + 1000;
    return { from: f, to: t };
  });
  let view = $state(null); // {from, to} = gezoomt
  const vf = $derived(view ? view.from : full.from);
  const vt = $derived(view ? view.to : full.to);
  const X = (t) => PL + ((t - vf) / (vt - vf)) * iw;
  const TX = (x) => vf + ((x - PL) / iw) * (vt - vf);

  // Zeilen im Ausschnitt: feste Zeitfenster (bucket) werden lückenlos aufgefüllt
  const rows = $derived.by(() => {
    if (bucket) {
      const map = new Map(P.map((p) => [p.ts, p]));
      const out = [];
      let t = Math.floor(vf / bucket) * bucket;
      for (let n = 0; t < vt && n < 3000; t += bucket, n++) out.push(map.get(t) || { ts: t });
      return out;
    }
    const s = P.findIndex((p) => p.ts >= vf);
    if (s < 0) return P.length ? [P[P.length - 1]] : [];
    let e = s;
    while (e < P.length && P[e].ts <= vt) e++;
    return P.slice(Math.max(0, s - 1), Math.min(P.length, e + 1));
  });
  const val = (p, k) => Number(p?.[k]) || 0;
  const stacked = $derived(kind === 'bars' || stack);
  // Balkenbreite: Zeitfenster bzw. üblicher Abstand der Messpunkte
  const step = $derived.by(() => {
    if (bucket) return bucket;
    const d = [];
    for (let i = 1; i < rows.length && d.length < 50; i++) d.push(rows[i].ts - rows[i - 1].ts);
    d.sort((a, b) => a - b);
    return d[Math.floor(d.length / 2)] || 2000;
  });

  const binary = $derived(unit === 'bytes' || (unit === 'rate' && !bits));
  function niceDec(v) {
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }
  function nice(v) {
    if (unit === 'count') return v < 5 ? 5 : niceDec(v);
    if (binary) {
      if (v < 1024) return 1024;
      const b = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024)));
      return niceDec(v / b) * b;
    }
    // bit/s: Achse in Zehnerschritten der Bits
    const m = unit === 'rate' ? 8 : 1;
    return v * m < 1000 ? 1000 / m : niceDec(v * m) / m;
  }
  const yMax = $derived.by(() => {
    let m = 0;
    for (const p of rows) {
      if (stacked) m = Math.max(m, shown.reduce((a, s) => a + val(p, s.key), 0));
      else for (const s of shown) m = Math.max(m, val(p, s.key));
    }
    return nice(m * 1.05);
  });
  const Y = (v) => PT + ih - (v / yMax) * ih;
  // linker Rand passend zur längsten Achsenbeschriftung (sonst wird z. B. „40,0 Mbit/s“ abgeschnitten)
  const PL = $derived(Math.max(40, Math.ceil(Math.max(...[0, 0.5, 1].map((f) => String(fmt(yMax * f)).length)) * 6.6) + 14));

  // Pfade für Linie/Fläche (gestapelt: Bänder zwischen den Summen)
  function segments() {
    const segs = [];
    let cur = [];
    let prev = null;
    for (const p of rows) {
      if (gap && prev && p.ts - prev.ts > gap) {
        segs.push(cur);
        cur = [];
      }
      cur.push(p);
      prev = p;
    }
    if (cur.length) segs.push(cur);
    return segs;
  }
  const paths = $derived.by(() => {
    if (kind === 'bars') return [];
    const segs = segments();
    const out = [];
    const keys = shown.map((s) => s.key);
    for (let i = 0; i < shown.length; i++) {
      const s = shown[i];
      let line = '',
        area = '';
      for (const seg of segs) {
        const top = seg.map((p) => [X(p.ts), Y(stacked ? keys.slice(0, i + 1).reduce((a, k) => a + val(p, k), 0) : val(p, s.key))]);
        const base = stacked && i ? seg.map((p) => [X(p.ts), Y(keys.slice(0, i).reduce((a, k) => a + val(p, k), 0))]) : seg.map((p) => [X(p.ts), PT + ih]);
        line += top.map(([x, y], j) => `${j ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join('');
        if (kind === 'area' || stacked)
          area += top.map(([x, y], j) => `${j ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join('') + base.reverse().map(([x, y]) => `L${x.toFixed(1)},${y.toFixed(1)}`).join('') + 'Z';
      }
      out.push({ s, line, area });
    }
    return out;
  });
  const bars = $derived.by(() => {
    if (kind !== 'bars') return [];
    const w0 = X(vf + step) - X(vf);
    const pad = w0 > 6 ? 2 : 0.5;
    return rows.map((p) => {
      let acc = 0;
      const parts = shown.map((s) => {
        const v = val(p, s.key);
        const y1 = Y(acc),
          y2 = Y(acc + v);
        acc += v;
        return { color: s.color, y: y2, h: Math.max(0, y1 - y2) };
      });
      const x = bucket ? X(p.ts) : X(p.ts) - w0 / 2;
      return { ts: p.ts, x, w: Math.max(1, w0 - pad), parts };
    });
  });

  // ---------- Achsen ----------
  const span = $derived(vt - vf);
  function tlabel(t) {
    const d = new Date(t);
    if (span <= 15 * 60000) return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (span <= 2 * 86400000) return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    if (span <= 10 * 86400000 && bucket && bucket < 86400000) return d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit' });
    return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
  }
  function longLabel(t) {
    const d = new Date(t);
    if (bucket >= 86400000) return d.toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' });
    const o = { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' };
    if (!bucket) o.second = '2-digit';
    let s = d.toLocaleString('de-DE', o);
    if (bucket > 3600000) s += ' – ' + new Date(t + bucket).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    return s;
  }
  const xticks = $derived.by(() => {
    const n = Math.max(2, Math.floor(iw / 110));
    const steps = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800].map((s) => s * 1000);
    const st = steps.find((s) => span / s <= n) || span / n;
    const out = [];
    const off = new Date().getTimezoneOffset() * 60000;
    let t = st < 86400000 ? Math.ceil(vf / st) * st : Math.ceil((vf - off) / st) * st + off;
    for (; t <= vt && out.length < 40; t += st) out.push(t);
    return out;
  });

  // ---------- Legende ----------
  const legendVal = $derived.by(() => {
    const o = {};
    const last = P[P.length - 1];
    for (const s of series) {
      if (legend === 'now') o[s.key] = val(last, s.key);
      else if (legend === 'sum') o[s.key] = rows.reduce((a, p) => a + val(p, s.key), 0);
      else o[s.key] = rows.reduce((a, p) => Math.max(a, val(p, s.key)), 0);
    }
    return o;
  });
  function toggleSeries(k) {
    const h = new Set(hidden);
    if (h.has(k)) h.delete(k);
    else if (series.length - h.size > 1) h.add(k); // eine Reihe bleibt immer sichtbar
    store({ hidden: [...h] });
  }

  // ---------- Zoom und Zeiger ----------
  let svgEl = $state();
  let hover = $state(null);
  let drag = $state(null);
  function px(e) {
    const r = svgEl.getBoundingClientRect();
    return Math.max(PL, Math.min(PL + iw, ((e.clientX - r.left) / r.width) * width));
  }
  function setView(f, t) {
    const minSpan = bucket ? bucket * 2 : 10000;
    if (t - f < minSpan) {
      const c = (f + t) / 2;
      f = c - minSpan / 2;
      t = c + minSpan / 2;
    }
    if (f < full.from) [f, t] = [full.from, Math.min(full.to, full.from + (t - f))];
    if (t > full.to) [f, t] = [Math.max(full.from, full.to - (t - f)), full.to];
    if (f <= full.from + 1 && t >= full.to - 1) return reset();
    view = { from: f, to: t };
    onzoom?.(f, t);
  }
  export function reset() {
    const was = !!view;
    view = null;
    if (was) onzoom?.(null, null);
  }
  function zoomBy(k) {
    const c = (vf + vt) / 2;
    setView(c - ((vt - vf) / 2) * k, c + ((vt - vf) / 2) * k);
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
    const t = TX(x);
    let best = null;
    for (const p of rows) {
      const c = bucket ? p.ts + bucket / 2 : p.ts;
      if (!best || Math.abs(c - t) < Math.abs(best.c - t)) best = { c, p };
    }
    hover = best ? { x: X(best.c), p: best.p } : null;
  }
  function up() {
    if (!drag) return;
    const d = drag;
    drag = null;
    if (d.pan) {
      if (view) setView(view.from, view.to);
      return;
    }
    if (Math.abs(d.x1 - d.x0) > 6) setView(TX(Math.min(d.x0, d.x1)), TX(Math.max(d.x0, d.x1)));
  }
  $effect(() => {
    const el = svgEl;
    if (!el) return;
    const wheel = (e) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const c = TX(px(e));
      const k = e.deltaY > 0 ? 1.3 : 1 / 1.3;
      setView(c - (c - vf) * k, c + (vt - c) * k);
    };
    el.addEventListener('wheel', wheel, { passive: false });
    return () => el.removeEventListener('wheel', wheel);
  });
  const sel = $derived(drag && !drag.pan && Math.abs(drag.x1 - drag.x0) > 2 ? { x: Math.min(drag.x0, drag.x1), w: Math.abs(drag.x1 - drag.x0) } : null);
  const tipLeft = $derived(hover ? Math.min(Math.max(hover.x / width, 0.14), 0.86) * 100 : 0);

  // ---------- Menü ----------
  let menu = $state(false);
  let menuEl = $state();
  $effect(() => {
    if (!menu) return;
    const close = (e) => !menuEl?.contains(e.target) && (menu = false);
    const key = (e) => e.key === 'Escape' && (menu = false);
    setTimeout(() => document.addEventListener('pointerdown', close));
    document.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('pointerdown', close);
      document.removeEventListener('keydown', key);
    };
  });
  const KIND_LABEL = { line: 'Linie', area: 'Fläche', bars: 'Balken' };
  function csv() {
    const head = ['Zeit', ...series.map((s) => s.label + (unit === 'rate' ? ' (Byte/s)' : unit === 'bytes' ? ' (Byte)' : ''))];
    const lines = [head.join(';')];
    for (const p of bucket ? rows.filter((r) => series.some((s) => r[s.key] != null)) : rows) lines.push([new Date(p.ts).toISOString(), ...series.map((s) => val(p, s.key))].join(';'));
    download(`${id || 'grafik'}-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.csv`, lines.join('\n'));
    menu = false;
  }
  function resetOpts() {
    if (skey) {
      delete layout.data[skey];
      saveLayout();
    } else local = {};
    reset();
    menu = false;
  }
</script>

<div class="card chart">
  <div class="ch-head">
    <h3 class="ch-title">
      {#if live}<span class="pulse" class:paused={!!frozen} title={frozen ? 'Angehalten' : 'Live'}></span>{:else if icon}<Icon name={icon} size={16} />{/if}
      <span class="ellipsis">{title}</span>
      {#if sub}<span class="muted small ch-sub ellipsis">{sub}</span>{/if}
    </h3>
    {#if tools}<div class="ch-tools">{@render tools()}</div>{/if}
    <div class="ch-ctl">
      {#if ranges.length}
        <div class="chips" role="group" aria-label="Zeitraum">
          {#each ranges as [k, l]}
            {#if k === '|'}<span class="chip-sep"></span>{:else}<button class:active={range === k} onclick={() => pickRange(k)}>{l}</button>{/if}
          {/each}
        </div>
      {/if}
      <div class="ibtns">
        <button class="ib" onclick={() => zoomBy(1 / 1.6)} title="Hineinzoomen (oder in der Grafik ziehen)" aria-label="Hineinzoomen"><Icon name="zoom-in" size={15} /></button>
        <button class="ib" onclick={() => zoomBy(1.6)} disabled={!view} title="Herauszoomen" aria-label="Herauszoomen"><Icon name="zoom-out" size={15} /></button>
        {#if view}<button class="ib on" onclick={reset} title="Ganzen Zeitraum zeigen (Doppelklick)" aria-label="Zoom zurücksetzen"><Icon name="reset" size={15} /></button>{/if}
        {#if live}<button class="ib" class:on={!!frozen} onclick={togglePause} title={frozen ? 'Weiter' : 'Anhalten'} aria-label={frozen ? 'Weiter' : 'Anhalten'}><Icon name={frozen ? 'play' : 'pause'} size={14} /></button>{/if}
        <button class="ib" onclick={() => store({ size: size === 'l' ? 'm' : 'l' })} title={size === 'l' ? 'Kleiner' : 'Größer anzeigen'} aria-label="Größe"><Icon name={size === 'l' ? 'shrink' : 'expand'} size={14} /></button>
        <div class="menu-wrap" bind:this={menuEl}>
          <button class="ib" class:on={menu} onclick={() => (menu = !menu)} title="Darstellung, Einheit, Reihen, Export" aria-label="Menü" aria-expanded={menu}><Icon name="dots" size={16} stroke={3} /></button>
          {#if menu}
            <div class="menu" role="menu">
              {#if kinds.length > 1}
                <div class="m-label">Darstellung</div>
                <div class="segmented m-seg">
                  {#each kinds as k}<button class:active={kind === k} onclick={() => store({ [kindKey]: k })}>{KIND_LABEL[k]}</button>{/each}
                </div>
              {/if}
              {#if unit === 'rate'}
                <div class="m-label">Einheit</div>
                <div class="segmented m-seg">
                  <button class:active={bits} onclick={() => store({ unit: 'bits' })}>bit/s</button>
                  <button class:active={!bits} onclick={() => store({ unit: 'bytes' })}>Byte/s</button>
                </div>
              {/if}
              <div class="m-label">Höhe</div>
              <div class="segmented m-seg">
                {#each [['s', 'Klein'], ['m', 'Mittel'], ['l', 'Groß']] as [k, l]}<button class:active={size === k} onclick={() => store({ size: k })}>{l}</button>{/each}
              </div>
              {#if series.length > 1}
                <div class="m-label">Reihen</div>
                {#each series as s}
                  <label class="m-check"><input type="checkbox" checked={!hidden.has(s.key)} onchange={() => toggleSeries(s.key)} /> <i style="background:{s.color}"></i> {s.label}</label>
                {/each}
              {/if}
              <div class="m-sep"></div>
              <button class="m-item" onclick={csv}><Icon name="download" size={14} /> Als CSV speichern</button>
              <button class="m-item" onclick={resetOpts}><Icon name="reset" size={14} /> Grafik zurücksetzen</button>
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>

  {#if children}<div class="ch-kpis">{@render children()}</div>{/if}

  <div class="plot" bind:clientWidth={width} style="height:{H}px">
    <svg
      bind:this={svgEl}
      viewBox="0 0 {width} {H}"
      {width}
      height={H}
      role="img"
      aria-label={title || 'Verlauf'}
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
        <text x={PL - 8} y={PT + ih * (1 - f) + 4} class="ylab">{fmt(yMax * f)}</text>
      {/each}
      {#each xticks as t}<text x={X(t)} y={H - 5} class="xlab">{tlabel(t)}</text>{/each}
      <clipPath id="clip-{id || title}-{H}"><rect x={PL} y={0} width={iw} height={PT + ih} /></clipPath>
      <g clip-path="url(#clip-{id || title}-{H})">
        {#if kind === 'bars'}
          {#each bars as b (b.ts)}
            {#each b.parts as pt}<rect x={b.x} y={pt.y} width={b.w} height={pt.h} style:fill={pt.color} class:hl={hover?.p?.ts === b.ts} />{/each}
          {/each}
        {:else}
          {#each paths as pa (pa.s.key)}
            {#if pa.area}<path d={pa.area} style:fill={pa.s.color} class="area" class:solid={stacked} />{/if}
            <path d={pa.line} style:stroke={pa.s.color} class="line" />
          {/each}
        {/if}
      </g>
      {#if hover && kind !== 'bars'}
        <line x1={hover.x} x2={hover.x} y1={PT} y2={PT + ih} class="cursor" />
      {/if}
      {#if sel}<rect x={sel.x} y={PT} width={sel.w} height={ih} class="sel" />{/if}
    </svg>
    {#if hover && !drag}
      <div class="tip" style="left:{tipLeft}%">
        <div class="strong">{longLabel(hover.p.ts)}</div>
        {#each shown as s}<div class="trow"><i style="background:{s.color}"></i><span class="grow">{s.label}</span><b>{fmt(val(hover.p, s.key))}</b></div>{/each}
      </div>
    {/if}
  </div>

  <div class="legend">
    {#each series as s}
      <button class="lg" class:off={hidden.has(s.key)} onclick={() => toggleSeries(s.key)} title={hidden.has(s.key) ? 'Einblenden' : 'Ausblenden'}>
        <i style="background:{s.color}"></i>{s.label}
        <b>{fmt(legendVal[s.key] || 0)}</b>
      </button>
    {/each}
    <span class="grow"></span>
    <span class="tiny muted hint">{legend === 'sum' ? 'Summe im Ausschnitt' : legend === 'peak' ? 'Spitze im Ausschnitt' : ''}{frozen ? ' · angehalten' : ''}</span>
  </div>
  {#if footer}{@render footer()}{/if}
</div>

<style>
  .chart {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .ch-head {
    display: flex;
    align-items: center;
    gap: 8px 12px;
    flex-wrap: wrap;
    padding: 10px 12px 4px 16px;
  }
  .ch-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-base);
    min-width: 0;
    flex: 1 1 140px;
  }
  .ch-sub {
    font-weight: 400;
  }
  .ch-tools {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .ch-ctl {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    margin-left: auto;
  }
  .chips {
    display: inline-flex;
    gap: 1px;
    flex-wrap: wrap;
  }
  .chips button {
    border: none;
    background: none;
    color: var(--muted);
    font: inherit;
    font-size: var(--fs-sm);
    font-weight: 550;
    padding: 3px 8px;
    border-radius: 6px;
    cursor: pointer;
  }
  .chips button:hover {
    color: var(--text);
    background: var(--panel-2);
  }
  .chips button.active {
    color: var(--accent);
    background: var(--accent-soft);
  }
  .chip-sep {
    width: 1px;
    margin: 4px 4px;
    background: var(--border-strong);
  }
  .ibtns {
    display: inline-flex;
    gap: 1px;
  }
  .ib {
    width: 28px;
    height: 28px;
    display: grid;
    place-items: center;
    border: none;
    background: none;
    color: var(--muted);
    border-radius: 6px;
    cursor: pointer;
    padding: 0;
  }
  .ib:hover:not(:disabled) {
    color: var(--text);
    background: var(--panel-2);
  }
  .ib.on {
    color: var(--accent);
    background: var(--accent-soft);
  }
  .ib:disabled {
    opacity: 0.35;
    cursor: default;
  }
  .menu-wrap {
    position: relative;
  }
  .menu {
    position: absolute;
    right: 0;
    top: 32px;
    z-index: 20;
    width: 230px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    box-shadow: var(--shadow-lg);
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .m-label {
    font-size: var(--fs-xs);
    color: var(--muted);
    margin: 4px 2px 0;
  }
  .m-seg {
    display: flex;
  }
  .m-seg button {
    flex: 1;
  }
  .m-check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-sm);
    padding: 2px;
    cursor: pointer;
  }
  .m-check i,
  .lg i,
  .trow i {
    width: 9px;
    height: 9px;
    border-radius: 3px;
    display: inline-block;
    flex: none;
  }
  .m-sep {
    height: 1px;
    background: var(--border);
    margin: 4px 0;
  }
  .m-item {
    display: flex;
    align-items: center;
    gap: 8px;
    border: none;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--fs-sm);
    padding: 6px;
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
  }
  .m-item:hover {
    background: var(--panel-2);
  }
  .ch-kpis:empty {
    display: none;
  }
  .ch-kpis {
    padding: 4px 16px 6px;
  }
  .plot {
    position: relative;
    width: 100%;
    padding: 0 8px 0 0;
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
    font-size: var(--fs-xs);
    text-anchor: end;
  }
  .xlab {
    fill: var(--muted);
    font-size: var(--fs-xs);
    text-anchor: middle;
  }
  .line {
    fill: none;
    stroke-width: 1.8;
    stroke-linejoin: round;
  }
  .area {
    opacity: 0.16;
  }
  .area.solid {
    opacity: 0.55;
  }
  rect.hl {
    filter: brightness(1.18);
  }
  .cursor {
    stroke: var(--muted);
    stroke-dasharray: 2 3;
  }
  .sel {
    fill: var(--accent);
    opacity: 0.15;
    stroke: var(--accent);
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
    font-size: var(--fs-sm);
    pointer-events: none;
    white-space: nowrap;
    z-index: 3;
    min-width: 160px;
  }
  .trow {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .legend {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 2px 4px;
    padding: 4px 12px 10px;
  }
  .lg {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: none;
    background: none;
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-sm);
    padding: 3px 6px;
    border-radius: 6px;
    cursor: pointer;
  }
  .lg:hover {
    background: var(--panel-2);
  }
  .lg b {
    color: var(--text);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .lg.off {
    opacity: 0.45;
    text-decoration: line-through;
  }
  .pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--ok);
    flex: none;
    animation: blink 1.6s infinite;
  }
  .pulse.paused {
    background: var(--muted);
    animation: none;
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
  @media (max-width: 700px) {
    .hint {
      display: none;
    }
    .ch-ctl {
      margin-left: 0;
    }
  }
</style>
