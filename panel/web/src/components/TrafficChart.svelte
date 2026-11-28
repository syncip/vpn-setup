<script>
  // Verkehr in einer Grafik: Live (2/10/30 Min., Geschwindigkeit alle 2 s) und Verlauf (Datenmenge je
  // Stunde/Tag/Woche/Monat, Zeitraum frei wählbar über PeriodPicker). Beim Hineinzoomen in den Verlauf werden
  // feinere Daten (bis 1 Stunde) vom Server nachgeladen.
  //   start: Vorgabe – Live-Fenster ('2m' | '10m' | '30m') oder Verlauf ('24h', '7d', '30d', 'month', 'year' …)
  //   url:  Verlauf (/traffic bzw. /users/<id>/traffic), user: Nutzer für die Live-Daten
  //   kpis: Kennzahlen über der Grafik (nur Live)
  import { untrack } from 'svelte';
  import Chart from './Chart.svelte';
  import { get } from '../lib/api.js';
  import { liveFeed } from '../lib/live.svelte.js';
  import { speed, fmtNum } from '../lib/format.js';
  import PeriodPicker from './PeriodPicker.svelte';
  import { resolve, query, GRAIN_WORD } from '../lib/period.js';

  let { id = 'traffic', title = 'Verkehr', url = '/traffic', user = 0, height = 200, refresh = 0, kpis = false, live = true, start = '' } = $props();

  const LIVE = [
    ['2m', '2 Min.', 120],
    ['10m', '10 Min.', 600],
    ['30m', '30 Min.', 1800],
  ];
  const ranges = $derived(live ? [...LIVE.map(([k, l]) => [k, l]), ['|'], ['hist', 'Verlauf']] : []);
  const startLive = untrack(() => LIVE.some(([k]) => k === start));
  let range = $state(untrack(() => (live && (startLive || !start) ? start || '10m' : 'hist')));
  let period = $state(null);
  const per = $derived(resolve(period || { mode: !startLive && start ? start : '24h' }));
  const isLive = $derived(LIVE.some(([k]) => k === range));
  const win = $derived((LIVE.find(([k]) => k === range) || [0, 0, 600])[2] * 1000);

  const BASE = [
    { key: 'down', label: 'Download', color: 'var(--down)' },
    { key: 'up', label: 'Upload', color: 'var(--up)' },
  ];
  // Gesamtansicht: SmartDNS als eigene Reihe. Der VPN-Anteil steckt im Verkehr der Zugänge und wird dort
  // abgezogen, Geräte ohne VPN (Proxy) kommen dazu – gestapelt ergibt das wieder den ganzen Verkehr.
  const overall = $derived(url === '/traffic' && !user);
  const SMART = { key: 'smart', label: 'SmartDNS', color: 'var(--ok)' };
  const withSmart = (p) => ({
    ts: p.ts,
    down: Math.max(0, (p.down || 0) - (p.svd || 0)),
    up: Math.max(0, (p.up || 0) - (p.svu || 0)),
    smart: (p.svu || 0) + (p.svd || 0) + (p.spu || 0) + (p.spd || 0),
  });

  // ---------- Live ----------
  const lv = liveFeed(
    () => user,
    () => isLive,
  );
  const now = $derived(lv.at || Date.now());
  const hist = $derived(overall ? (lv.d?.history || []).map(withSmart) : lv.d?.history || []);
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
    grain: t.grain || '',
    from: t.since * 1000,
    to: Math.min(t.until * 1000, Date.now() + 60000),
    points: (t.points || []).map((p) => (overall ? withSmart({ ...p, ts: p.ts * 1000 }) : { ts: p.ts * 1000, up: p.up, down: p.down })),
  });
  $effect(() => {
    if (isLive) return;
    const q = query(per);
    const f = per.from,
      t = per.to;
    url;
    refresh;
    untrack(() => {
      zoomed = null;
      const my = ++seq;
      get(`${url}?${q}`)
        .then((res) => my === seq && ((base = { ...conv(res), from: f, to: t }), (err = '')))
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
      const c = conv(await get(`${url}?${query({ from: f, to: t, grain: 'auto' }).replace('grain=auto', '')}`));
      if (my === seq && base) zoomed = { ...c, from: base.from, to: base.to }; // gleiche Achse, feinere Balken
    } catch {}
  }
  const data = $derived(zoomed || base);
  // SmartDNS-Reihe nur, wenn es SmartDNS-Verkehr gibt
  const hasSmart = $derived(overall && (isLive ? hist : data?.points || []).some((p) => p.smart > 0));
  const SERIES = $derived(hasSmart ? [...BASE, SMART] : BASE);
  const sub = $derived(
    [isLive ? '' : data ? `Datenmenge je ${GRAIN_WORD[data.grain] || 'Stunde'}` : '', hasSmart ? 'SmartDNS als eigene Reihe' : ''].filter(Boolean).join(' · '),
  );
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
    grain={data?.grain || ''}
    from={data?.from || per.from}
    to={data?.to || per.to}
    {height}
    {ranges}
    bind:range
    onzoom={zoom}
    legend="sum"
  >
    {#snippet children()}
      <PeriodPicker id={id} bind:value={period} start={!startLive && start ? start : '24h'} />
      {#if err}<div class="notice bad small">{err}</div>{/if}
    {/snippet}
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
