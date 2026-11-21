<script>
  // Statistik: alle Grafiken an einem Ort – Verkehr (Verlauf), Live (Tempo und Geräte), Ausgänge, DNS, SmartDNS.
  // Jede Seite ist anpassbar (Fenster verschieben, Breite, ausblenden, hinzufügen); jede Grafik merkt sich
  // Zeitraum, Darstellung, Einheit, Höhe und ausgeblendete Reihen.
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Board from '../components/Board.svelte';
  import TrafficChart from '../components/TrafficChart.svelte';
  import LiveDevices from '../components/LiveDevices.svelte';
  import ExitLive from '../components/ExitLive.svelte';
  import ExitTraffic from '../components/ExitTraffic.svelte';
  import DNSLive from '../components/DNSLive.svelte';
  import SmartLive from '../components/SmartLive.svelte';
  import { get } from '../lib/api.js';
  import { bytes, fmtNum, speed } from '../lib/format.js';
  import { go } from '../lib/state.svelte.js';
  import { liveFeed } from '../lib/live.svelte.js';

  let { tab = 'traffic' } = $props();
  const TABS = [
    ['traffic', 'Verkehr', 'stats'],
    ['live', 'Live', 'activity'],
    ['exits', 'Ausgänge', 'route'],
    ['dns', 'DNS', 'globe'],
    ['smart', 'SmartDNS', 'route'],
  ];
  $effect(() => {
    if (!TABS.some((t) => t[0] === tab)) go('/stats', true);
  });
  const label = $derived(TABS.find((t) => t[0] === tab)?.[1] || 'Verkehr');

  let ov = $state(null);
  let ex = $state(null);
  $effect(() => {
    if (tab === 'traffic' && !ov) get('/overview').then((d) => (ov = d)).catch(() => {});
    if (tab === 'exits' && !ex) get('/exits').then((d) => (ex = d)).catch(() => {});
  });
  const topMax = $derived(Math.max(1, ...(ov?.top || []).map((t) => t.up + t.down)));
  const lv = liveFeed(0, () => tab === 'live');
</script>

<PageHead title={tab === 'traffic' ? 'Statistik' : `Statistik · ${label}`} subtitle="Grafiken mit Zeitraum, Zoom (ziehen oder Strg+Mausrad), ausblendbaren Reihen und Export">
  {#snippet help()}
    <p><b>Bedienung aller Grafiken:</b> Zeitraum oben wählen · in der Grafik ziehen = hineinzoomen, Umschalt+Ziehen = verschieben, Strg+Mausrad = zoomen, Doppelklick = zurück · Legende anklicken = Reihe aus- oder einblenden · „…“ = Darstellung (Linie, Fläche, Balken), Einheit (bit/s oder Byte/s), Höhe, CSV-Export.</p>
    <p>Alle Einstellungen werden für dein Konto gespeichert. „Anpassen“ ordnet die Fenster dieser Seite.</p>
  {/snippet}
</PageHead>

<div class="tabs pagetabs">
  {#each TABS as [id, l, icon]}
    <button class:active={tab === id} onclick={() => go(id === 'traffic' ? '/stats' : `/stats/${id}`)}><Icon name={icon} size={14} /> {l}</button>
  {/each}
</div>

{#if tab === 'traffic'}
  {#snippet w_today()}
    <div class="card card-pad kpi"><div class="muted small">Heute</div><div class="big">{ov ? bytes(ov.today.up + ov.today.down) : '–'}</div>{#if ov}<div class="tiny muted">↓ {bytes(ov.today.down)} · ↑ {bytes(ov.today.up)}</div>{/if}</div>
  {/snippet}
  {#snippet w_month()}
    <div class="card card-pad kpi"><div class="muted small">Dieser Monat</div><div class="big">{ov ? bytes(ov.month.up + ov.month.down) : '–'}</div>{#if ov}<div class="tiny muted">↓ {bytes(ov.month.down)} · ↑ {bytes(ov.month.up)}</div>{/if}</div>
  {/snippet}
  {#snippet w_users()}
    <div class="card card-pad kpi"><div class="muted small">Nutzer</div><div class="big">{ov ? fmtNum(ov.counts.users || 0) : '–'}</div>{#if ov}<div class="tiny muted">{fmtNum(ov.counts.peers || 0)} Zugänge</div>{/if}</div>
  {/snippet}
  {#snippet w_servers()}
    <div class="card card-pad kpi"><div class="muted small">Server</div><div class="big">{ov ? fmtNum(ov.counts.servers || 0) : '–'}</div>{#if ov}<div class="tiny muted">{ov.servers.filter((s) => s.status.running).length} laufen</div>{/if}</div>
  {/snippet}
  {#snippet w_chart()}<TrafficChart id="stats-traffic" title="Verkehr gesamt" start="24h" height={240} />{/snippet}
  {#snippet w_top()}
    <div class="card">
      <div class="card-head"><h3>Top-Nutzer</h3><span class="muted small">30 Tage</span></div>
      <div class="list">
        {#each ov?.top || [] as t}
          <a class="item" href="#/users/{t.id}">
            <div class="grow">
              <div class="spread"><span class="strong small">{t.name}</span><span class="small">{bytes(t.up + t.down)}</span></div>
              <div class="bar"><div style="width:{((t.up + t.down) / topMax) * 100}%"></div></div>
            </div>
          </a>
        {:else}
          <div class="empty small">{ov ? 'Noch kein Verkehr' : 'Lädt …'}</div>
        {/each}
      </div>
    </div>
  {/snippet}
  <Board
    id="stats-traffic"
    widgets={[
      { id: 'today', title: 'Verkehr heute', w: 3, body: w_today },
      { id: 'month', title: 'Verkehr diesen Monat', w: 3, body: w_month },
      { id: 'users', title: 'Nutzer', w: 3, body: w_users },
      { id: 'servers', title: 'Server', w: 3, body: w_servers },
      { id: 'chart', title: 'Verkehr gesamt', w: 8, body: w_chart },
      { id: 'top', title: 'Top-Nutzer', w: 4, body: w_top },
    ]}
  />
{:else if tab === 'live'}
  {#snippet w_kpi_down()}
    <div class="card card-pad kpi"><div class="muted small">Download</div><div class="big down">{lv.d ? speed(lv.d.total.down) : '–'}</div></div>
  {/snippet}
  {#snippet w_kpi_up()}
    <div class="card card-pad kpi"><div class="muted small">Upload</div><div class="big up">{lv.d ? speed(lv.d.total.up) : '–'}</div></div>
  {/snippet}
  {#snippet w_kpi_users()}
    <div class="card card-pad kpi"><div class="muted small">Nutzer online</div><div class="big">{lv.d ? fmtNum(lv.d.total.users_online) : '–'}<span class="muted unit"> / {lv.d ? fmtNum(lv.d.total.users) : '–'}</span></div></div>
  {/snippet}
  {#snippet w_kpi_peers()}
    <div class="card card-pad kpi"><div class="muted small">Geräte verbunden</div><div class="big">{lv.d ? fmtNum(lv.d.total.peers_online) : '–'}<span class="muted unit"> / {lv.d ? fmtNum(lv.d.total.peers) : '–'}</span></div></div>
  {/snippet}
  {#snippet w_live()}<TrafficChart id="stats-live" title="Geschwindigkeit" start="10m" height={220} />{/snippet}
  {#snippet w_devices()}<LiveDevices limit={15} />{/snippet}
  <Board
    id="stats-live"
    widgets={[
      { id: 'down', title: 'Download jetzt', w: 3, body: w_kpi_down },
      { id: 'up', title: 'Upload jetzt', w: 3, body: w_kpi_up },
      { id: 'online', title: 'Nutzer online', w: 3, body: w_kpi_users },
      { id: 'peers', title: 'Geräte verbunden', w: 3, body: w_kpi_peers },
      { id: 'live', title: 'Geschwindigkeit', w: 12, body: w_live },
      { id: 'devices', title: 'Verbundene Geräte', w: 12, body: w_devices },
    ]}
  />
{:else if tab === 'exits'}
  {#if ex}
    {#snippet w_live()}<ExitLive exits={ex.exits} groups={ex.groups} />{/snippet}
    {#snippet w_traffic()}<ExitTraffic exits={ex.exits} />{/snippet}
    <Board
      id="stats-exits"
      widgets={[
        { id: 'live', title: 'Ausgänge live', w: 12, body: w_live },
        { id: 'traffic', title: 'Verkehr über die Ausgänge', w: 12, body: w_traffic },
      ]}
    />
  {:else}
    <div class="card card-pad muted small">Lädt …</div>
  {/if}
{:else if tab === 'dns'}
  {#snippet w_dns()}<DNSLive />{/snippet}
  <Board id="stats-dns" widgets={[{ id: 'live', title: 'DNS live', w: 12, body: w_dns }]} />
  <p class="muted small" style="margin-top:12px">Weitere DNS-Zahlen (Top-Domains, gesperrte Anfragen, Geräte) stehen unter <a href="#/dns">DNS → Übersicht</a>.</p>
{:else if tab === 'smart'}
  <SmartLive />
{/if}

<style>
  .kpi {
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 2px;
  }
  .big {
    font-size: var(--fs-xl);
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1.2;
    font-variant-numeric: tabular-nums;
  }
  .big.down {
    color: var(--down);
  }
  .big.up {
    color: var(--up);
  }
  .unit {
    font-size: var(--fs-base);
    font-weight: 500;
  }
  .list {
    display: flex;
    flex-direction: column;
    padding: 4px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 7px 10px;
    border-radius: 8px;
    color: inherit;
  }
  a.item:hover {
    background: var(--panel-2);
  }
  .bar {
    height: 4px;
    border-radius: 4px;
    background: var(--panel-2);
    margin-top: 4px;
    overflow: hidden;
  }
  .bar div {
    height: 100%;
    background: var(--accent);
    border-radius: 4px;
  }
</style>
