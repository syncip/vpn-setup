<script>
  // Verkehr über die Ausgänge (GET /exits/traffic, Zeitraum und Gliederung per PeriodPicker): wahlweise Summe
  // (Download/Upload, optional nur ein Ausgang) oder je Ausgang gestapelt. Darunter der Anteil jedes Ausgangs
  // im gewählten Zeitraum.
  //   exit: fest auf diesen Ausgang (Detailansicht, ohne Umschalter und Liste)
  import Chart from './Chart.svelte';
  import Info from './Info.svelte';
  import { get } from '../lib/api.js';
  import PeriodPicker from './PeriodPicker.svelte';
  import { bytes } from '../lib/format.js';
  import { resolve, query, GRAIN_WORD } from '../lib/period.js';

  let { exits = [], id = 'exit-traffic', height = 180, list = true, exit = 0, start = '7d', title = 'Verkehr über die Ausgänge' } = $props();

  const COLORS = ['#4f7cff', '#22a374', '#f59e0b', '#e5484d', '#8e6cf0', '#0ea5b7', '#d9468f', '#7a8699', '#a3a31a', '#c46a2d'];
  let period = $state(null);
  const per = $derived(resolve(period || { mode: start }));
  let modeSel = $state('sum'); // sum | split
  let onlySel = $state(0); // nur dieser Ausgang (Summe)
  const mode = $derived(exit ? 'sum' : modeSel);
  const only = $derived(exit || onlySel);
  let tr = $state(null);
  let err = $state('');
  let seq = 0;
  $effect(() => {
    const q = query(per);
    const f = per.from,
      t = per.to;
    const my = ++seq;
    get(`/exits/traffic?${q}`)
      .then((r) => my === seq && ((tr = { ...r, from: f, to: t }), (err = '')))
      .catch((e) => (err = e.message));
  });

  const data = $derived.by(() => {
    if (!tr) return null;
    const by = new Map();
    for (const [b, eid, up, down] of tr.series || []) {
      if (mode === 'sum' && only && eid !== only) continue;
      const p = by.get(b) || { ts: b * 1000, up: 0, down: 0 };
      if (mode === 'sum') {
        p.up += up;
        p.down += down;
      } else p['e' + eid] = (p['e' + eid] || 0) + up + down;
      by.set(b, p);
    }
    return { points: [...by.values()], bucket: tr.bucket * 1000, grain: tr.grain, from: tr.from, to: tr.to };
  });
  const series = $derived(
    mode === 'sum'
      ? [
          { key: 'down', label: 'Download', color: 'var(--down)' },
          { key: 'up', label: 'Upload', color: 'var(--up)' },
        ]
      : exits.map((e, i) => ({ key: 'e' + e.id, label: e.name, color: COLORS[i % COLORS.length] })),
  );
  const month = (e) => (tr?.totals?.[e.id]?.up || 0) + (tr?.totals?.[e.id]?.down || 0);
  const all = $derived(exits.reduce((a, e) => a + month(e), 0));
  const sorted = $derived([...exits].sort((a, b) => month(b) - month(a)));
</script>

<Chart
  {id}
  {title}
  icon="route"
  sub={[!exit && mode === 'sum' && only ? exits.find((e) => e.id === only)?.name || '' : '', data ? `je ${GRAIN_WORD[data.grain] || 'Stunde'}` : ''].filter(Boolean).join(' · ')}
  {series}
  points={data?.points || []}
  unit="bytes"
  kinds={['bars', 'area', 'line']}
  bucket={data?.bucket || 3600000}
  grain={data?.grain || ''}
  from={data?.from || per.from}
  to={data?.to || per.to}
  {height}
  legend="sum"
>
  {#snippet tools()}
    <Info title="Verkehr" text="Gezählt an den Schnittstellen der Ausgänge: alles, was Nutzer über Gruppen ins Internet schicken bzw. von dort laden (inkl. Prüfungen). Download = vom Anbieter empfangen. „Je Ausgang“ stapelt die Datenmenge (Down + Up) der einzelnen Ausgänge." />
    {#if !exit}
      <div class="segmented sm">
        <button class:active={mode === 'sum'} onclick={() => (modeSel = 'sum')}>Summe</button>
        <button class:active={mode === 'split'} onclick={() => (modeSel = 'split')}>Je Ausgang</button>
      </div>
    {/if}
  {/snippet}
  {#snippet children()}
    <PeriodPicker {id} bind:value={period} {start} />
    {#if err}<div class="notice bad small">{err}</div>{/if}
  {/snippet}
  {#snippet footer()}
    {#if list && !exit && exits.length}
      <div class="trgrid">
        {#each sorted as e}
          {@const m = month(e)}
          <button class="trrow" class:sel={mode === 'sum' && only === e.id} onclick={() => ((modeSel = 'sum'), (onlySel = onlySel === e.id ? 0 : e.id))} title="Nur diesen Ausgang zeigen">
            <span class="small ellipsis grow">{e.name}</span>
            <span class="share"><span style="width:{all ? (m / all) * 100 : 0}%"></span></span>
            <span class="tiny muted nowrap">{bytes(m)}</span>
          </button>
        {/each}
      </div>
    {/if}
  {/snippet}
</Chart>

<style>
  .trgrid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 2px 14px;
    padding: 6px 12px 12px;
    border-top: 1px solid var(--border);
  }
  .trrow {
    display: flex;
    align-items: center;
    gap: 8px;
    border: 0;
    background: none;
    font: inherit;
    color: inherit;
    padding: 4px 6px;
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    min-width: 0;
  }
  .trrow:hover,
  .trrow.sel {
    background: var(--accent-soft);
  }
  .share {
    width: 70px;
    height: 6px;
    border-radius: 3px;
    background: var(--border);
    overflow: hidden;
    flex: none;
  }
  .share span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  .nowrap {
    white-space: nowrap;
  }
</style>
