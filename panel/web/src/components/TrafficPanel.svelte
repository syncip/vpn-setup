<script>
  // Traffic-Verlauf mit Zeitraumwahl. Beim Hineinzoomen werden feinere Daten (bis 1 Stunde)
  // vom Server nachgeladen.
  import { untrack } from 'svelte';
  import TimeChart from './TimeChart.svelte';
  import { get } from '../lib/api.js';
  import { bytes } from '../lib/format.js';

  let { url = '/traffic', title = 'Traffic', height = 220, refresh = 0 } = $props();

  const ranges = [
    ['24h', '24 Std.'],
    ['7d', '7 Tage'],
    ['30d', '30 Tage'],
    ['90d', '90 Tage'],
  ];
  let range = $state('24h');
  let base = $state(null); // Daten des gewählten Zeitraums
  let zoomed = $state(null); // nachgeladene Daten für den Ausschnitt
  let chart = $state();
  let seq = 0;

  const conv = (t) => ({
    bucket: t.bucket * 1000,
    from: t.since * 1000,
    to: Math.min(t.until * 1000, Date.now() + 60000),
    points: (t.points || []).map((p) => ({ ts: p.ts * 1000, up: p.up, down: p.down })),
  });

  async function load() {
    const my = ++seq;
    const t = await get(`${url}?range=${range}`);
    if (my === seq) base = conv(t);
  }
  $effect(() => {
    range;
    url;
    refresh;
    untrack(() => {
      zoomed = null;
      chart?.reset();
      load().catch(() => {});
    });
  });

  async function zoom(f, t) {
    if (f == null) {
      zoomed = null;
      return;
    }
    const my = ++seq;
    try {
      const d = await get(`${url}?from=${Math.floor(f / 1000)}&to=${Math.ceil(t / 1000)}`);
      if (my !== seq) return;
      const c = conv(d);
      // gleiche Achse wie vorher, nur feinere Balken
      zoomed = { ...c, from: base.from, to: base.to };
    } catch {}
  }
  const data = $derived(zoomed || base);
</script>

<div class="card">
  <div class="card-head">
    <h2>{title}</h2>
    <div class="segmented">
      {#each ranges as [k, l]}<button class:active={range === k} onclick={() => (range = k)}>{l}</button>{/each}
    </div>
  </div>
  <div class="card-pad">
    {#if data}
      <TimeChart bind:this={chart} mode="bars" points={data.points} bucket={data.bucket} from={data.from} to={data.to} format={bytes} binary {height} onzoom={zoom} />
    {:else}
      <div style="height:{height + 36}px"></div>
    {/if}
  </div>
</div>
