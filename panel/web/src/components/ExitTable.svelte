<script>
  // Ausgänge im Vergleich: Verbrauch heute, Woche, Monat, Jahr und 30 Tage je Ausgang, sortierbar.
  // Klick auf eine Zeile wählt den Ausgang für die Detailansicht (onpick).
  import Icon from './Icon.svelte';
  import StateBadge from './StateBadge.svelte';
  import { bytes } from '../lib/format.js';
  import { exitState } from '../lib/exitstate.js';

  let { exits = [], totals = null, sel = 0, onpick = null } = $props();

  const COLS = [
    ['day', 'Heute'],
    ['week', 'Woche'],
    ['month', 'Monat'],
    ['year', 'Jahr'],
    ['30d', '30 Tage'],
  ];
  let sortBy = $state('month');
  let desc = $state(true);
  const val = (k, id) => {
    const t = totals?.totals?.[k]?.[id];
    return t ? t.up + t.down : 0;
  };
  const rows = $derived(
    [...exits].sort((a, b) => {
      const d = sortBy === 'name' ? a.name.localeCompare(b.name, 'de') : val(sortBy, a.id) - val(sortBy, b.id);
      return desc ? -d : d;
    }),
  );
  const sum = (k) => exits.reduce((a, e) => a + val(k, e.id), 0);
  function sortOn(k) {
    if (sortBy === k) desc = !desc;
    else {
      sortBy = k;
      desc = k !== 'name';
    }
  }
</script>

<div class="card">
  <div class="card-head"><h3><Icon name="stats" size={16} /> Ausgänge im Vergleich</h3><span class="muted small">Datenmenge (↓ + ↑), Kalender</span></div>
  <div class="tbl-wrap">
    <table class="tbl">
      <thead>
        <tr>
          <th><button class="th" onclick={() => sortOn('name')}>Ausgang{#if sortBy === 'name'} {desc ? '↓' : '↑'}{/if}</button></th>
          {#each COLS as [k, l]}<th class="num"><button class="th" onclick={() => sortOn(k)}>{l}{#if sortBy === k} {desc ? '↓' : '↑'}{/if}</button></th>{/each}
        </tr>
      </thead>
      <tbody>
        {#each rows as e (e.id)}
          {@const st = exitState(e)}
          <tr class:sel={sel === e.id} class:off={!e.enabled} onclick={() => onpick?.(e.id)} title="Statistik dieses Ausgangs zeigen">
            <td><span class="nm"><span class="strong small ellipsis">{e.name}</span><StateBadge small tone={st.tone} label={st.label} icon={st.icon} title={st.detail} /></span></td>
            {#each COLS as [k]}<td class="num small">{totals ? bytes(val(k, e.id)) : '–'}</td>{/each}
          </tr>
        {:else}
          <tr><td colspan={COLS.length + 1} class="muted small">Noch keine Ausgänge.</td></tr>
        {/each}
      </tbody>
      {#if exits.length > 1 && totals}
        <tfoot>
          <tr><td class="small strong">Summe</td>{#each COLS as [k]}<td class="num small strong">{bytes(sum(k))}</td>{/each}</tr>
        </tfoot>
      {/if}
    </table>
  </div>
</div>

<style>
  .tbl-wrap {
    overflow-x: auto;
  }
  .tbl {
    width: 100%;
    border-collapse: collapse;
  }
  .tbl th,
  .tbl td {
    padding: 7px 12px;
    border-top: 1px solid var(--border);
    text-align: left;
    white-space: nowrap;
  }
  .tbl .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .th {
    border: 0;
    background: none;
    font: inherit;
    font-size: var(--fs-xs, 12px);
    color: var(--muted);
    cursor: pointer;
    padding: 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  tbody tr {
    cursor: pointer;
  }
  tbody tr:hover {
    background: var(--panel-2);
  }
  tbody tr.sel {
    background: var(--accent-soft);
  }
  tr.off {
    opacity: 0.6;
  }
  .nm {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
</style>
