<script>
  // Verkehr in einer Grafik: Live (2/10/30 Min., Geschwindigkeit alle 2 s) und Verlauf
  // (24 Std. bis 90 Tage, Datenmenge je Zeitfenster). Beim Hineinzoomen in den Verlauf werden
  // feinere Daten (bis 1 Stunde) vom Server nachgeladen.
  //   url:  Verlauf (/traffic bzw. /users/<id>/traffic), user: Nutzer für die Live-Daten
  //   kpis: Kennzahlen über der Grafik (nur Live)
  import { untrack } from 'svelte';
  import Chart from './Chart.svelte';
  import { get } from '../lib/api.js';
  import { liveFeed } from '../lib/live.svelte.js';
  import { speed, fmtNum } from '../lib/format.js';

  let { id = 'traffic', title = 'Verkehr', url = '/traffic', user = 0, height = 200, refresh = 0, kpis = false, live = true, start = '' } = $props();

  const LIVE = [
    ['2m', '2 Min.', 120],
    ['10m', '10 Min.', 600],
    ['30m', '30 Min.', 1800],
  ];
  const HIST = [
    ['24h', '24 Std.'],
    ['7d', '7 Tage'],
    ['30d', '30 Tage'],
    ['90d', '90 Tage'],
  ];
  const ranges = $derived(live ? [...LIVE.map(([k, l]) => [k, l]), ['|'], ...HIST] : HIST);
  let range = $state(untrack(() => start || (live ? '10m' : '24h')));
  const isLive = $derived(LIVE.some(([k]) => k === range));
  const win = $derived((LIVE.find(([k]) => k === range) || [0, 0, 600])[2] * 1000);

  const SERIES = [
    { key: 'down', label: 'Download', color: 'var(--down)' },
    { key: 'up', label: 'Upload', color: 'var(--up)' },
  ];

  // ---------- Live ----------
  const lv = liveFeed(
    () => user,
    () => isLive,
  );
  const now = $derived(lv.at || Date.now());
  const hist = $derived(lv.d?.history || []);
  const cur = $derived.by(() => {
    const d = lv.d;
    if (!d) return { up: 0, down: 0 };
    if (user) {
      const h = hist[hist.length - 1];
      return { up: h?.up || 0, down: h?.down || 0 };
    }
    return { up: d.total.up, down: d.total.down };
  });

  // ---------- Verlauf ----------
  let base = $state(null);
  let zoomed = $state(null);
  let err = $state('');
  let seq = 0;
  const conv = (t) => ({
    bucket: t.bucket * 1000,
    from: t.since * 1000,
    to: Math.min(t.until * 1000, Date.now() + 60000),
    points: (t.points || []).map((p) => ({ ts: p.ts * 1000, up: p.up, down: p.down })),
  });
  $effect(() => {
    if (isLive) return;
    const r = range;
    url;
    refresh;
    untrack(() => {
      zoomed = null;
      const my = ++seq;
      get(`${url}?range=${r}`)
        .then((t) => my === seq && ((base = conv(t)), (err = '')))
        .catch((e) => (err = e.message));
    });
  });
  async function zoom(f, t) {
    if (isLive) return;
    if (f == null) {
      zoomed = null;
      return;
    }
    const my = ++seq;
    try {
      const c = conv(await get(`${url}?from=${Math.floor(f / 1000)}&to=${Math.ceil(t / 1000)}`));
      if (my === seq && base) zoomed = { ...c, from: base.from, to: base.to }; // gleiche Achse, feinere Balken
    } catch {}
  }
  const data = $derived(zoomed || base);
  const sub = $derived(isLive ? '' : data ? `Datenmenge je ${data.bucket >= 86400000 ? 'Tag' : 'Stunde'}` : '');
</script>

{#if isLive}
  <Chart {id} {title} {sub} series={SERIES} points={hist} unit="rate" kinds={['area', 'line']} from={now - win} to={now} gap={25000} {height} {ranges} bind:range live legend="now">
    {#snippet children()}
      {#if kpis}
        <div class="kpis">
          <div><div class="muted tiny">Download</div><div class="kpi down">{speed(cur.down)}</div></div>
          <div><div class="muted tiny">Upload</div><div class="kpi up">{speed(cur.up)}</div></div>
          {#if !user && lv.d}
            <div><div class="muted tiny">Nutzer online</div><div class="kpi">{fmtNum(lv.d.total.users_online)}<span class="muted"> / {fmtNum(lv.d.total.users)}</span></div></div>
            <div><div class="muted tiny">Geräte verbunden</div><div class="kpi">{fmtNum(lv.d.total.peers_online)}<span class="muted"> / {fmtNum(lv.d.total.peers)}</span></div></div>
          {/if}
        </div>
      {/if}
      {#if lv.err}<div class="notice bad small">{lv.err}</div>{/if}
    {/snippet}
  </Chart>
{:else}
  <Chart
    {id}
    {title}
    {sub}
    series={SERIES}
    points={data?.points || []}
    unit="bytes"
    kinds={['bars', 'area', 'line']}
    bucket={data?.bucket || 3600000}
    from={data?.from || Date.now() - 86400000}
    to={data?.to || Date.now()}
    {height}
    {ranges}
    bind:range
    onzoom={zoom}
    legend="sum"
  >
    {#snippet children()}{#if err}<div class="notice bad small">{err}</div>{/if}{/snippet}
  </Chart>
{/if}

<style>
  .kpis {
    display: flex;
    gap: 8px 28px;
    flex-wrap: wrap;
  }
  .kpi {
    font-size: var(--fs-lg);
    font-weight: 700;
    letter-spacing: -0.01em;
    font-variant-numeric: tabular-nums;
  }
  .kpi .muted {
    font-size: var(--fs-base);
    font-weight: 500;
  }
  .kpi.down {
    color: var(--down);
  }
  .kpi.up {
    color: var(--up);
  }
</style>
