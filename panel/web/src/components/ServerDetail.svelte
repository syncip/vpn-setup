<script>
  // Statistik eines Servers: Auswahl, Zustand, Verbrauch heute/Woche/Monat/Jahr und eine Grafik mit
  // Geschwindigkeit live (Zugänge dieses Servers) und Verlauf mit frei wählbarem Zeitraum und Gliederung.
  //   servers: GET /servers · totals: GET /servers/totals · sel (bindable): gewählter Server
  import ProtoLogo from './ProtoLogo.svelte';
  import TrafficChart from './TrafficChart.svelte';
  import { bytes } from '../lib/format.js';
  import { protocol } from '../lib/state.svelte.js';

  let { servers = [], totals = null, sel = $bindable(0) } = $props();

  const cur = $derived(servers.find((s) => s.id === sel) || servers[0]);
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
      <ProtoLogo id={cur.protocol} size={30} />
      <select class="input pick" value={cur.id} onchange={(e) => (sel = +e.currentTarget.value)} aria-label="Server">
        {#each servers as s (s.id)}<option value={s.id}>{s.name}{s.enabled ? '' : ' (aus)'}</option>{/each}
      </select>
      <span class="badge {!cur.enabled ? 'muted' : cur.status?.running ? 'ok' : 'bad'}"><span class="dot" class:on={cur.enabled && cur.status?.running}></span>{cur.enabled ? (cur.status?.running ? 'läuft' : 'Fehler') : 'aus'}</span>
      <span class="small muted">{protocol(cur.protocol)?.label || cur.protocol} · {cur.online} online / {cur.peers} Zugänge · gesamt {bytes(cur.up + cur.down)}</span>
      <span class="grow"></span>
      <a class="btn ghost sm" href="#/servers">Server verwalten</a>
    </div>
    <div class="kpis">
      {#each KPIS as [k, l]}
        {@const t = tot(k)}
        <div>
          <div class="muted tiny">{l}</div>
          <div class="big">{totals ? bytes(t.up + t.down) : '–'}</div>
          {#if totals}<div class="tiny muted">↓ {bytes(t.down)} · ↑ {bytes(t.up)}</div>{/if}
        </div>
      {/each}
    </div>
  </div>
  <TrafficChart id="server-detail" title="Verkehr" url={`/servers/${cur.id}/traffic`} server={cur.id} kpis start="10m" height={220} />
{:else}
  <div class="card card-pad muted small">Noch keine Server – anlegen unter <a href="#/servers">Server</a>.</div>
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
</style>
