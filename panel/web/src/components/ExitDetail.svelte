<script>
  // Statistik eines Ausgangs: Auswahl, Verbrauch heute/Woche/Monat/Jahr, Geschwindigkeit live und
  // Verlauf mit frei wählbarem Zeitraum und Gliederung.
  //   exits, groups: aus GET /exits · totals: GET /exits/totals · sel (bindable): gewählter Ausgang
  import Icon from './Icon.svelte';
  import StateBadge from './StateBadge.svelte';
  import ExitLive from './ExitLive.svelte';
  import ExitTraffic from './ExitTraffic.svelte';
  import { bytes } from '../lib/format.js';
  import { exitState } from '../lib/exitstate.js';

  let { exits = [], groups = [], totals = null, sel = $bindable(0) } = $props();

  const cur = $derived(exits.find((e) => e.id === sel) || exits[0]);
  const st = $derived(cur ? exitState(cur) : null);
  const inGroups = $derived(cur ? groups.filter((g) => (g.exits || []).includes(cur.id)) : []);
  const tot = (k) => totals?.totals?.[k]?.[cur?.id] || { up: 0, down: 0 };
  const KPIS = [
    ['day', 'Heute'],
    ['week', 'Diese Woche'],
    ['month', 'Dieser Monat'],
    ['year', 'Dieses Jahr'],
  ];
</script>

{#if cur}
  <div class="card card-pad head">
    <div class="row wrap" style="gap:10px">
      <Icon name="route" size={18} />
      <select class="input pick" value={cur.id} onchange={(e) => (sel = +e.currentTarget.value)} aria-label="Ausgang">
        {#each exits as e (e.id)}<option value={e.id}>{e.name}{e.enabled ? '' : ' (aus)'}</option>{/each}
      </select>
      {#if st}<StateBadge tone={st.tone} label={st.label} icon={st.icon} title={st.detail} />{/if}
      {#if inGroups.length}<span class="small muted">in {inGroups.map((g) => g.name).join(', ')}</span>{/if}
      <span class="grow"></span>
      <a class="btn ghost sm" href="#/routing/exits">Ausgänge verwalten</a>
    </div>
    <div class="kpis">
      {#each KPIS as [k, l]}
        {@const t = tot(k)}
        <div class="kpi">
          <div class="muted tiny">{l}</div>
          <div class="big">{totals ? bytes(t.up + t.down) : '–'}</div>
          {#if totals}<div class="tiny muted">↓ {bytes(t.down)} · ↑ {bytes(t.up)}</div>{/if}
        </div>
      {/each}
    </div>
  </div>
  <div class="stack">
    <ExitLive {exits} {groups} exit={cur.id} id="exit-detail-live" title="Geschwindigkeit" height={190} />
    <ExitTraffic {exits} exit={cur.id} id="exit-detail-traffic" start="30d" title="Verkehr" height={200} />
  </div>
{:else}
  <div class="card card-pad muted small">Noch keine Ausgänge – anlegen unter <a href="#/routing/exits">Routing → Ausgänge</a>.</div>
{/if}

<style>
  .head {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-bottom: 12px;
  }
  .pick {
    width: auto;
    min-width: 180px;
    max-width: 100%;
    font-weight: 600;
  }
  .kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px 20px;
  }
  .big {
    font-size: var(--fs-lg);
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
</style>
