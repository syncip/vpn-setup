<script>
  // Verkehr über die Ausgänge (GET /exits/traffic?days=): wahlweise Summe (Download/Upload, optional
  // nur ein Ausgang) oder je Ausgang gestapelt. Darunter der Anteil jedes Ausgangs in den letzten 30 Tagen.
  import Chart from './Chart.svelte';
  import Info from './Info.svelte';
  import { get } from '../lib/api.js';
  import { bytes } from '../lib/format.js';

  let { exits = [], id = 'exit-traffic', height = 180, list = true } = $props();

  const COLORS = ['#4f7cff', '#22a374', '#f59e0b', '#e5484d', '#8e6cf0', '#0ea5b7', '#d9468f', '#7a8699', '#a3a31a', '#c46a2d'];
  let range = $state('7');
  let mode = $state('sum'); // sum | split
  let only = $state(0); // nur dieser Ausgang (Summe)
  let tr = $state(null);
  let err = $state('');
  $effect(() => {
    const days = range;
    get(`/exits/traffic?days=${days}`)
      .then((r) => ((tr = r), (err = '')))
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
    const to = Date.now();
    return { points: [...by.values()], bucket: tr.bucket * 1000, from: to - tr.days * 86400000, to };
  });
  const series = $derived(
    mode === 'sum'
      ? [
          { key: 'down', label: 'Download', color: 'var(--down)' },
          { key: 'up', label: 'Upload', color: 'var(--up)' },
        ]
      : exits.map((e, i) => ({ key: 'e' + e.id, label: e.name, color: COLORS[i % COLORS.length] })),
  );
  const month = (e) => (e.traffic?.month?.up || 0) + (e.traffic?.month?.down || 0);
  const all = $derived(exits.reduce((a, e) => a + month(e), 0));
  const sorted = $derived([...exits].sort((a, b) => month(b) - month(a)));
</script>

<Chart
  {id}
  title="Verkehr über die Ausgänge"
  icon="route"
  sub={mode === 'sum' && only ? exits.find((e) => e.id === only)?.name || '' : ''}
  {series}
  points={data?.points || []}
  unit="bytes"
  kinds={['bars', 'area', 'line']}
  bucket={data?.bucket || 3600000}
  from={data?.from || Date.now() - 7 * 86400000}
  to={data?.to || Date.now()}
  {height}
  ranges={[['1', '24 Std.'], ['7', '7 Tage'], ['30', '30 Tage'], ['90', '90 Tage']]}
  bind:range
  legend="sum"
>
  {#snippet tools()}
    <Info title="Verkehr" text="Gezählt an den Schnittstellen der Ausgänge: alles, was Nutzer über Gruppen ins Internet schicken bzw. von dort laden (inkl. Prüfungen). Download = vom Anbieter empfangen. „Je Ausgang“ stapelt die Datenmenge (Down + Up) der einzelnen Ausgänge." />
    <div class="segmented sm">
      <button class:active={mode === 'sum'} onclick={() => (mode = 'sum')}>Summe</button>
      <button class:active={mode === 'split'} onclick={() => (mode = 'split')}>Je Ausgang</button>
    </div>
  {/snippet}
  {#snippet children()}{#if err}<div class="notice bad small">{err}</div>{/if}{/snippet}
  {#snippet footer()}
    {#if list && exits.length}
      <div class="trgrid">
        {#each sorted as e}
          {@const m = month(e)}
          <button class="trrow" class:sel={mode === 'sum' && only === e.id} onclick={() => ((mode = 'sum'), (only = only === e.id ? 0 : e.id))} title="Nur diesen Ausgang zeigen">
            <span class="small ellipsis grow">{e.name}</span>
            <span class="share"><span style="width:{all ? (m / all) * 100 : 0}%"></span></span>
            <span class="tiny muted nowrap">{bytes(m)} · 30 T.</span>
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
