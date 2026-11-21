<script module>
  // Gemeinsame Bausteine für die SmartDNS-Statistik: Mini-Verlauf (Karte) und Detailansicht (Dialog).
  export function spark(hours, n = 24, key = 'q') {
    return (hours || []).slice(-n).map((h) => h[key] || 0);
  }
</script>

<script>
  // Statistik eines SmartDNS-Profils (Daten von GET /api/dns/smart/stats).
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import { fmtNum, bytes, ago, date } from '../lib/format.js';

  let { s, groupById = {}, onreset } = $props();

  let metric = $state('q'); // q | bytes
  let domSort = $state('q');
  let showAllDoms = $state(false);

  const traffic = $derived((s.up || 0) + (s.down || 0) + (s.proxy || 0));
  const maxOf = (a) => Math.max(1, ...a);

  // Verlauf 7 Tage (Stunden)
  const series = $derived((s.hours || []).map((h) => (metric === 'q' ? h.q : h.bytes)));
  const sMax = $derived(maxOf(series));
  // Wochentag × Stunde (Ortszeit) – wann wird der Dienst genutzt?
  const heat = $derived.by(() => {
    const m = Array.from({ length: 7 }, () => Array(24).fill(0));
    for (const h of s.hours || []) {
      const d = new Date(h.t * 1000);
      m[(d.getDay() + 6) % 7][d.getHours()] += metric === 'q' ? h.q : h.bytes;
    }
    return m;
  });
  const heatMax = $derived(maxOf(heat.flat()));
  const peak = $derived.by(() => {
    let best = [0, 0, 0];
    heat.forEach((row, d) => row.forEach((v, h) => v > best[2] && (best = [d, h, v])));
    return best[2] ? best : null;
  });
  const DAYS = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'];

  const routeMax = $derived(maxOf((s.routes || []).map((r) => r.q)));
  const doms = $derived.by(() => {
    const a = [...(s.domains || [])];
    if (domSort === 'bytes') a.sort((x, y) => y.bytes - x.bytes || y.q - x.q);
    else if (domSort === 'last') a.sort((x, y) => (y.last || 0) - (x.last || 0));
    else if (domSort === 'name') a.sort((x, y) => x.domain.localeCompare(y.domain));
    return a;
  });
  const domMax = $derived(maxOf((s.domains || []).map((x) => (domSort === 'bytes' ? x.bytes : x.q))));
  const nameMax = $derived(maxOf((s.names || []).map((x) => x.q)));
  const devMax = $derived(maxOf((s.devices || []).map((x) => x.q)));
  const hourLabel = (t) => new Date(t * 1000).toLocaleString('de-DE', { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  const fmtMetric = (v) => (metric === 'q' ? `${fmtNum(v)} Anfragen` : bytes(v));
</script>

<div class="kpis">
  <div class="kpi"><span class="k">{fmtNum(s.q24)}</span><span class="l">Anfragen in 24 h</span><span class="t">{fmtNum(s.queries)} seit {date(s.since)}</span></div>
  <div class="kpi">
    <span class="k">{bytes(traffic)}</span><span class="l">Verkehr gesamt <Info title="Wie wird gezählt?" text="VPN-Geräte (WireGuard, OpenVPN): Zähler der Firewall je Weiterleitung – zu den Zielen (↑) und Antworten von den Zieladressen (↓). Geräte ohne VPN: genau über den SmartDNS-Proxy. VLESS und Hysteria2 leiten selbst; dort zählen nur die Anfragen." /></span>
    <span class="t">VPN ↑ {bytes(s.up)} ↓ {bytes(s.down)} · ohne VPN {bytes(s.proxy)}</span>
  </div>
  <div class="kpi"><span class="k">{fmtNum(s.devices24)}</span><span class="l">Geräte in 24 h</span><span class="t">{fmtNum(s.devices.length)} insgesamt (Auswahl)</span></div>
  <div class="kpi">
    <span class="k">{s.last ? ago(s.last) : '–'}</span><span class="l">zuletzt gegriffen</span>
    <span class="t">{s.domains.length - s.unused.length} von {s.domains.length} Einträgen genutzt</span>
  </div>
</div>

<div class="sec">
  <div class="row" style="gap:8px;margin-bottom:6px">
    <h4 class="grow">Verlauf der letzten 7 Tage</h4>
    <div class="segmented sm">
      <button class:active={metric === 'q'} onclick={() => (metric = 'q')}>Anfragen</button>
      <button class:active={metric === 'bytes'} onclick={() => (metric = 'bytes')}>Verkehr</button>
    </div>
  </div>
  <div class="vchart">
    <div class="yax" aria-hidden="true"><span>{metric === 'q' ? fmtNum(sMax) : bytes(sMax)}</span><span>{metric === 'q' ? fmtNum(Math.round(sMax / 2)) : bytes(sMax / 2)}</span><span>0</span></div>
    <div style="min-width:0">
      <div class="bars" role="img" aria-label="Verlauf">
        {#each s.hours as h, i}
          <div class="bar" style="height:{Math.max(series[i] ? 3 : 0, (series[i] / sMax) * 100)}%" title="{hourLabel(h.t)}: {fmtMetric(series[i])}"></div>
        {/each}
      </div>
      <div class="xax" aria-hidden="true">
        {#each s.hours as h}<span>{new Date(h.t * 1000).getHours() === 0 ? new Date(h.t * 1000).toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit' }) : ''}</span>{/each}
      </div>
    </div>
  </div>
  <div class="tiny muted" style="margin-top:2px">{metric === 'q' ? 'Anfragen' : 'Verkehr'} je Stunde, die letzten 7 Tage bis jetzt</div>
</div>

<div class="sec">
  <h4>Wann wird es genutzt? {#if peak}<span class="muted tiny">– am meisten {DAYS[peak[0]]} {peak[1]}–{peak[1] + 1} Uhr</span>{/if}</h4>
  <div class="heat">
    <span></span>
    {#each Array(24) as _, h}<span class="hh">{h % 3 === 0 ? h : ''}</span>{/each}
    {#each heat as row, d}
      <span class="hd">{DAYS[d]}</span>
      {#each row as v, h}
        <span class="cell" style="opacity:{v ? 0.15 + 0.85 * (v / heatMax) : 1}" class:zero={!v} title="{DAYS[d]} {h}–{h + 1} Uhr: {fmtMetric(v)}"></span>
      {/each}
    {/each}
  </div>
</div>

{#if s.routes.length > 1}
  <div class="sec">
    <h4>Weiterleitungen</h4>
    {#each s.routes as r}
      <div class="hrow">
        <span class="badge accent"><Icon name="route" size={12} /> {r.name || groupById[r.group]?.name || `Gruppe #${r.group}`}</span>
        <span class="track"><span style="width:{(r.q / routeMax) * 100}%"></span></span>
        <span class="tiny nowrap">{fmtNum(r.q)} · {bytes(r.bytes)}</span>
      </div>
    {/each}
  </div>
{/if}

<div class="sec">
  <div class="row" style="gap:8px;margin-bottom:6px">
    <h4 class="grow">Domains im Profil</h4>
    <select class="input sm" style="width:auto" bind:value={domSort} aria-label="Sortierung">
      <option value="q">nach Anfragen</option>
      <option value="bytes">nach Verkehr</option>
      <option value="last">zuletzt genutzt</option>
      <option value="name">nach Name</option>
    </select>
  </div>
  {#each showAllDoms ? doms : doms.slice(0, 12) as x (x.domain)}
    <div class="hrow" class:unused={!x.q && !x.conns}>
      <span class="mono small ellipsis dn" title={x.domain}>{x.domain}{#if x.err}&nbsp;<span class="badge warn tiny" title={x.err}><Icon name="alert" size={11} /> Fehler</span>{/if}</span>
      <span class="track"><span style="width:{((domSort === 'bytes' ? x.bytes : x.q) / domMax) * 100}%"></span></span>
      <span class="tiny nowrap">
        {#if !x.q && !x.conns}nie angefragt{:else}{fmtNum(x.q)}{x.bytes ? ` · ${bytes(x.bytes)}` : ''}{x.last ? ` · ${ago(x.last)}` : ''}{/if}
      </span>
    </div>
  {/each}
  {#if doms.length > 12}
    <button class="btn sm ghost" onclick={() => (showAllDoms = !showAllDoms)}>{showAllDoms ? 'Weniger zeigen' : `Alle ${doms.length} zeigen`}</button>
  {/if}
  {#if s.unused.length && s.queries}
    <div class="tiny muted" style="margin-top:6px">
      <Icon name="info" size={12} />
      {s.unused.length === 1 ? '1 Eintrag hat' : `${s.unused.length} Einträge haben`} noch nie gegriffen – vielleicht ein Tippfehler, oder der Dienst nutzt andere Namen (siehe „Meistgefragte Namen“).
    </div>
  {/if}
</div>

<div class="two">
  <div class="sec">
    <h4>Meistgefragte Namen</h4>
    {#each s.names as n (n.name)}
      <div class="hrow">
        <span class="mono tiny ellipsis dn" title={n.name}>{n.name}</span>
        <span class="track"><span style="width:{(n.q / nameMax) * 100}%"></span></span>
        <span class="tiny nowrap">{fmtNum(n.q)}</span>
      </div>
    {:else}
      <div class="tiny muted">Noch keine Anfragen.</div>
    {/each}
  </div>
  <div class="sec">
    <h4>Aktivste Geräte</h4>
    {#each s.devices as dv (dv.kind + dv.id)}
      <div class="hrow">
        <a class="small ellipsis dn" href={`#/system/effective/${dv.kind}/${dv.id}`} title="Was gilt für dieses Gerät?">
          <Icon name={dv.kind === 'client' ? 'globe' : 'phone'} size={12} />
          {dv.name}
          <span class="muted tiny">{dv.sub}</span>
        </a>
        <span class="track"><span style="width:{(dv.q / devMax) * 100}%"></span></span>
        <span class="tiny nowrap" title="zuletzt {ago(dv.last)}">{fmtNum(dv.q)}{dv.bytes ? ` · ${bytes(dv.bytes)}` : ''}</span>
      </div>
    {:else}
      <div class="tiny muted">Noch kein Gerät.</div>
    {/each}
  </div>
</div>

{#if onreset}
  <div class="row" style="justify-content:flex-end;margin-top:6px">
    <button class="btn sm ghost danger" onclick={onreset}><Icon name="reset" size={14} /> Statistik zurücksetzen</button>
  </div>
{/if}

<style>
  .kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(46%, 150px), 1fr));
    gap: 10px;
    margin-bottom: 14px;
  }
  .kpi {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--panel-2);
    min-width: 0;
  }
  .kpi .k {
    font-size: var(--fs-xl);
    font-weight: 600;
  }
  .kpi .l {
    font-size: var(--fs-sm);
  }
  .kpi .t {
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .sec {
    margin-bottom: 16px;
    min-width: 0;
  }
  h4 {
    margin: 0 0 6px;
    font-size: var(--fs-md);
  }
  .vchart {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 6px;
  }
  .yax {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    align-items: flex-end;
    height: 98px;
    font-size: 10px;
    color: var(--muted);
    line-height: 1;
  }
  .xax {
    display: flex;
    font-size: 10px;
    color: var(--muted);
    padding-top: 3px;
    height: 16px;
  }
  .xax span {
    flex: 1;
    width: 0;
    min-width: 0;
    white-space: nowrap;
    overflow: visible;
    border-left: 1px solid transparent;
  }
  .xax span:not(:empty) {
    border-left-color: var(--border);
    padding-left: 2px;
  }
  .bars {
    display: flex;
    align-items: flex-end;
    gap: 1px;
    height: 90px;
    overflow: hidden;
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
  }
  .bar {
    flex: 1;
    background: var(--accent);
    border-radius: 1px 1px 0 0;
    min-width: 0;
  }
  .bar:hover {
    background: var(--accent-2);
  }
  .heat {
    display: grid;
    grid-template-columns: 26px repeat(24, minmax(0, 1fr));
    gap: 2px;
    font-size: 10px;
    color: var(--muted);
  }
  .hh {
    text-align: left;
  }
  .hd {
    line-height: 14px;
  }
  .cell {
    height: 14px;
    border-radius: 2px;
    background: var(--accent);
  }
  .cell.zero {
    background: var(--panel-2);
  }
  .hrow {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(40px, 2fr) 11.5em;
    align-items: center;
    gap: 8px;
    padding: 3px 0;
  }
  .hrow > :last-child {
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .two .hrow {
    grid-template-columns: minmax(0, 2fr) minmax(30px, 1.2fr) 7.5em;
  }
  .hrow.unused {
    color: var(--muted);
  }
  .dn {
    min-width: 0;
    color: inherit;
    text-decoration: none;
  }
  a.dn:hover {
    color: var(--accent);
  }
  .track {
    height: 6px;
    border-radius: 3px;
    background: var(--panel-2);
    overflow: hidden;
  }
  .track span {
    display: block;
    height: 100%;
    background: var(--accent);
    border-radius: 3px;
  }
  @media (max-width: 640px) {
    .bars {
      gap: 0;
    }
    .hrow,
    .two .hrow {
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 2px 8px;
    }
    .hrow .track {
      grid-column: 1 / -1;
      grid-row: 2;
    }
  }
  .two {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr));
    gap: 0 20px;
  }
</style>
