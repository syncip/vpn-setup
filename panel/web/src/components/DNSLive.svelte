<script>
  // Live-Ansicht des Panel-DNS: Anfragen je Sekunde und benutzte DNS-Server (seit dem Start).
  import Info from './Info.svelte';
  import Icon from './Icon.svelte';
  import { get } from '../lib/api.js';
  import Chart from './Chart.svelte';
  import { fmtNum } from '../lib/format.js';

  let range = $state('300');
  const secs = $derived(+range);
  let d = $state(null);

  async function load() {
    if (document.hidden) return;
    d = await get(`/dns/live?secs=${secs}`).catch(() => d);
  }
  $effect(() => {
    secs;
    load();
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  });

  // auf 5-Sekunden-Schritte zusammenfassen, wenn es eng wird
  const step = $derived(secs > 300 ? 5 : secs > 120 ? 2 : 1);
  const pts = $derived.by(() => {
    if (!d) return [];
    const out = [];
    for (let i = 0; i < d.points.length; i += step) {
      const g = d.points.slice(i, i + step);
      const ok = g.reduce((a, p) => a + (p.n - p.bl - p.cached - p.err), 0);
      out.push({
        ts: g[0].ts * 1000,
        ok: g.reduce((a, p) => a + Math.max(0, p.n - p.bl - p.cached), 0) / g.length,
        n: g.reduce((a, p) => a + p.n, 0) / g.length,
        bl: g.reduce((a, p) => a + p.bl, 0) / g.length,
        cached: g.reduce((a, p) => a + p.cached, 0) / g.length,
        ms: ok ? g.reduce((a, p) => a + p.ms * (p.n - p.bl - p.cached - p.err), 0) / ok : 0,
      });
    }
    return out;
  });
  const avgMS = $derived.by(() => {
    if (!d) return 0;
    let w = 0,
      sum = 0;
    for (const p of d.points.slice(-60)) {
      const ok = p.n - p.bl - p.cached - p.err;
      w += ok;
      sum += p.ms * ok;
    }
    return w ? Math.round(sum / w) : 0;
  });
  const lastMin = $derived(d ? d.points.slice(-61, -1) : []);
  const blPct = $derived.by(() => {
    const n = lastMin.reduce((a, p) => a + p.n, 0);
    return n ? Math.round((lastMin.reduce((a, p) => a + p.bl, 0) / n) * 100) : 0;
  });
  const SERIES = [
    { key: 'ok', label: 'Beantwortet', color: 'var(--accent)' },
    { key: 'cached', label: 'Aus dem Speicher', color: 'color-mix(in srgb, var(--accent) 40%, var(--panel))' },
    { key: 'bl', label: 'Gesperrt', color: 'var(--bad)' },
  ];
  const lastTs = $derived(d?.points?.length ? d.points[d.points.length - 1].ts * 1000 : Date.now());
  const perSec = (v) => fmtNum(Math.round(v * 10) / 10) + '/s';
</script>

<Chart
  id="dns-live"
  title="DNS live"
  series={SERIES}
  points={pts}
  unit="count"
  format={perSec}
  kinds={['area', 'bars', 'line']}
  stack
  from={lastTs - secs * 1000}
  to={lastTs}
  gap={15000}
  height={140}
  ranges={[['60', '1 Min.'], ['300', '5 Min.'], ['600', '10 Min.']]}
  bind:range
  live
>
  {#snippet tools()}<Info title="Live" text="Anfragen je Sekunde am Panel-DNS (aus dem Speicher, unabhängig vom Protokoll), gestapelt: beantwortet, aus dem Zwischenspeicher, gesperrt. Wird alle 2 Sekunden aktualisiert." />{/snippet}
  {#snippet children()}
    <div class="lkpis">
      <div><div class="tiny muted">Anfragen/s</div><div class="lk">{d ? fmtNum(Math.round(d.qps * 10) / 10) : '–'}</div></div>
      <div><div class="tiny muted">Spitze</div><div class="lk">{d ? fmtNum(d.peak) : '–'}<span class="tiny muted"> /s</span></div></div>
      <div><div class="tiny muted">Gesperrt (1 Min.)</div><div class="lk bad-text">{blPct} %</div></div>
      <div><div class="tiny muted">Ø Antwort (1 Min.)</div><div class="lk">{avgMS ? `${avgMS} ms` : '–'}</div></div>
      <div><div class="tiny muted">Geräte aktiv</div><div class="lk">{d ? fmtNum(d.clients) : '–'}</div></div>
    </div>
  {/snippet}
  {#snippet footer()}
  <div class="card-pad" style="padding-top:0">
    <div class="ups">
      <div class="row" style="gap:6px;margin-bottom:6px">
        <strong class="small">DNS-Server seit dem Start</strong>
        <Info title="DNS-Server" text="Welcher DNS-Server die Anfragen beantwortet hat, die nicht aus dem Speicher kamen – seit dem letzten Start des Dienstes. Mit Unbound als Resolver beantwortet Unbound fast alles; die anderen springen nur ein, wenn er nicht antwortet. Antwortzeit = gleitender Mittelwert." />
      </div>
      {#if d?.unbound?.on && !d.unbound.ok}
        <div class="notice bad small ubdown">
          <Icon name="alert" size={16} />
          <div>
            <b>Unbound ausgefallen – wird übersprungen.</b> {d.unbound.why}
            {#if d.unbound.detail}<details><summary>Meldungen von Unbound</summary><pre>{d.unbound.detail}</pre></details>{/if}
          </div>
        </div>
      {/if}
      {#each (d?.unbound?.groups || []).filter((g) => !g.ok) as g}
        <div class="notice warn small ubdown">
          <Icon name="alert" size={16} />
          <div>
            <b>Unbound „{g.name}“ wird übersprungen.</b> {g.why}
            {#if g.detail}<details><summary>Meldungen</summary><pre>{g.detail}</pre></details>{/if}
          </div>
        </div>
      {/each}
      {#each d?.upstreams || [] as u}
        <div class="up">
          <span class="small strong ellipsis" title={u.server}>{u.name}</span>
          <span class="mono tiny muted ellipsis">{u.server.replace(/:53$/, '')}</span>
          <span class="share"><span style="width:{u.share}%"></span></span>
          <span class="tiny num">{u.share} %</span>
          <span class="tiny muted num">{fmtNum(u.ok)}×</span>
          <span class="tiny num">{u.ms} ms</span>
          <span class="tiny num {u.fail ? 'warn-text' : 'muted'}">{u.fail ? `${fmtNum(u.fail)} Ausf.` : ''}</span>
        </div>
      {:else}
        <div class="muted small">Noch keine Anfrage an einen DNS-Server.</div>
      {/each}
    </div>
  </div>
  {/snippet}
</Chart>

<style>
  .ubdown {
    margin-bottom: 8px;
  }
  .ubdown details {
    margin-top: 4px;
  }
  .ubdown summary {
    cursor: pointer;
  }
  .ubdown pre {
    margin: 4px 0 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-size: var(--fs-xs);
  }
  .lkpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
    gap: 10px;
  }
  .lk {
    font-size: var(--fs-lg);
    font-weight: 650;
    font-variant-numeric: tabular-nums;
  }
  .ups {
    border-top: 1px solid var(--border);
    padding-top: 10px;
  }
  .up {
    display: grid;
    grid-template-columns: minmax(80px, 140px) minmax(70px, 1fr) 90px 48px 64px 56px 64px;
    gap: 8px;
    align-items: center;
    padding: 3px 0;
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .share {
    height: 6px;
    border-radius: 3px;
    background: var(--border);
    overflow: hidden;
  }
  .share span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  @media (max-width: 640px) {
    .up {
      grid-template-columns: 1fr 70px 44px 56px;
    }
    .up > :nth-child(2),
    .up > :nth-child(5),
    .up > :nth-child(7) {
      display: none;
    }
  }
</style>
