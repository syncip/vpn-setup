<script>
  // Statistik → SmartDNS: was gerade über SmartDNS läuft (live alle 5 Sekunden) – Tempo, Summen,
  // letzte Verbindungen über den Proxy und die Detailstatistik je Profil.
  import { untrack } from 'svelte';
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import SmartStats from './SmartStats.svelte';
  import { get } from '../lib/api.js';
  import { bytes, fmtNum, speed, ago } from '../lib/format.js';

  const EVERY = 5; // Sekunden – der Proxy zählt ebenfalls alle 5 Sekunden
  const KEEP = 60; // Messpunkte im Tempo-Verlauf (5 Minuten)

  let stats = $state(null);
  let proxy = $state({});
  let at = $state(0);
  let req = 0;
  let prev = null; // letzter Stand der Zähler (für das Tempo)
  let rate = $state({ vu: 0, vd: 0, pu: 0, pd: 0 });
  let hist = $state([]); // [{t, down, up}]
  let pick = $state(0);

  const sum = (k) => (stats || []).reduce((a, x) => a + (x[k] || 0), 0);
  const tot = $derived({
    q24: sum('q24'),
    b24: sum('bytes24'),
    up: sum('up'),
    down: sum('down'),
    pup: sum('proxy_up'),
    pdown: sum('proxy_down'),
    dev24: sum('devices24'),
  });
  const groupName = $derived(Object.fromEntries((stats || []).flatMap((p) => p.routes.map((r) => [r.group, r.name]))));
  const cur = $derived((stats || []).find((p) => p.id === pick) || (stats || [])[0]);

  async function load() {
    req = Date.now();
    const [st, tls] = await Promise.all([get('/dns/smart/stats').catch(() => null), get('/dns/tls').catch(() => null)]);
    if (tls?.smart) proxy = tls.smart;
    if (!st) return;
    const now = Date.now();
    const c = { t: now, vu: 0, vd: 0, pu: 0, pd: 0 };
    for (const p of st) {
      c.vu += p.up || 0;
      c.vd += p.down || 0;
      c.pu += p.proxy_up || 0;
      c.pd += p.proxy_down || 0;
    }
    if (prev && now > prev.t) {
      const s = (now - prev.t) / 1000;
      const d = (k) => Math.max(0, c[k] - prev[k]) / s; // zurückgesetzt → 0 statt negativ
      rate = { vu: d('vu'), vd: d('vd'), pu: d('pu'), pd: d('pd') };
      hist = [...hist, { t: now, down: rate.vd + rate.pd, up: rate.vu + rate.pu }].slice(-KEEP);
    }
    prev = c;
    stats = st;
    at = now;
  }
  $effect(() => {
    untrack(load);
    const t = setInterval(() => document.visibilityState === 'visible' && load(), EVERY * 1000);
    const onVis = () => document.visibilityState === 'visible' && Date.now() - req > 2000 && load();
    document.addEventListener('visibilitychange', onVis);
    return () => {
      clearInterval(t);
      document.removeEventListener('visibilitychange', onVis);
    };
  });

  // Tempo-Verlauf als Balken (↓ oben, ↑ darunter gestapelt)
  const hMax = $derived(Math.max(1, ...hist.map((h) => h.down + h.up)));
  const nice = (v) => {
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  };
  const yMax = $derived(nice(hMax));
</script>

{#if !stats}
  <div class="card card-pad muted small">Lädt …</div>
{:else if !stats.length}
  <div class="card empty">
    <h3>Noch kein SmartDNS-Profil</h3>
    <p>SmartDNS leitet einzelne Dienste (z. B. Netflix, Twitch) über eine Ausgangsgruppe. Profile legst du unter DNS → SmartDNS an.</p>
    <a class="btn primary" href="#/dns/smart">Zu SmartDNS</a>
  </div>
{:else}
  <div class="kpis">
    <div class="card card-pad kpi">
      <div class="muted small">SmartDNS jetzt <Info title="Tempo" text="Verkehr über SmartDNS seit der letzten Messung (alle {EVERY} Sekunden): VPN-Geräte über die Zähler der Firewall, Geräte ohne VPN über den Proxy. VLESS und Hysteria2 leiten selbst und zählen hier nicht." /></div>
      <div class="big"><span class="down">↓ {speed(rate.vd + rate.pd)}</span></div>
      <div class="tiny muted">↑ {speed(rate.vu + rate.pu)} · ohne VPN ↓ {speed(rate.pd)}</div>
    </div>
    <div class="card card-pad kpi">
      <div class="muted small">Verkehr in 24 h</div>
      <div class="big">{bytes(tot.b24)}</div>
      <div class="tiny muted">{fmtNum(tot.q24)} Anfragen · {fmtNum(tot.dev24)} Geräte</div>
    </div>
    <div class="card card-pad kpi">
      <div class="muted small">Verkehr gesamt</div>
      <div class="big">{bytes(tot.up + tot.down + sum('proxy'))}</div>
      <div class="tiny muted">VPN ↑ {bytes(tot.up)} ↓ {bytes(tot.down)}</div>
      <div class="tiny muted">ohne VPN ↑ {bytes(tot.pup)} ↓ {bytes(tot.pdown)}</div>
    </div>
    <div class="card card-pad kpi">
      <div class="muted small">Proxy (ohne VPN)</div>
      <div class="big">{fmtNum(proxy.active || 0)} <span class="unit muted">offen</span></div>
      <div class="tiny muted">{fmtNum(proxy.total || 0)} Verbindungen seit dem Start{proxy.denied ? ` · ${fmtNum(proxy.denied)} abgewiesen` : ''}</div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-head">
      <h3><Icon name="activity" size={15} /> Tempo über SmartDNS</h3>
      <span class="muted small">live, alle {EVERY} Sekunden{at ? ` · Stand ${new Date(at).toLocaleTimeString('de-DE')}` : ''}</span>
    </div>
    <div class="card-pad">
      {#if hist.length < 2}
        <div class="muted small">Der Verlauf füllt sich, solange die Seite offen ist (erste Werte nach {EVERY * 2} Sekunden).</div>
      {/if}
      <div class="rchart">
        <div class="yax"><span>{speed(yMax)}</span><span>{speed(yMax / 2)}</span><span>0</span></div>
        <div class="plot">
          <div class="gl" style="top:0"></div>
          <div class="gl" style="top:50%"></div>
          {#each hist as h (h.t)}
            <div class="col" title="{new Date(h.t).toLocaleTimeString('de-DE')} · ↓ {speed(h.down)} · ↑ {speed(h.up)}">
              <div class="b up" style="height:{(h.up / yMax) * 100}%"></div>
              <div class="b down" style="height:{(h.down / yMax) * 100}%"></div>
            </div>
          {/each}
        </div>
      </div>
      <div class="tiny muted legend"><span class="dot down"></span> Download <span class="dot up"></span> Upload · letzte 5 Minuten</div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-head">
      <h3><Icon name="laptop" size={15} /> Zuletzt über den Proxy</h3>
      <span class="muted small">Geräte ohne VPN, seit dem Start des Dienstes</span>
    </div>
    <div class="card-pad stack" style="gap:6px">
      {#each (proxy.hits || []).slice(0, 15) as h}
        <div class="row small hit">
          <span class="mono tiny grow ellipsis">{h.domain}</span>
          {#if groupName[h.group]}<span class="badge accent tiny">{groupName[h.group]}</span>{/if}
          <span class="tiny muted nowrap">{fmtNum(h.conns)}× · {bytes(h.bytes)} · {ago(h.last)}</span>
          {#if h.err}<span class="tiny warn-t ellipsis err" title={h.err}>{h.err}</span>{/if}
        </div>
      {:else}
        <div class="tiny muted">Noch keine Verbindungen über den Proxy.</div>
      {/each}
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-head">
      <h3><Icon name="globe" size={15} /> Je Profil</h3>
      <a class="small" href="#/dns/smart">Profile bearbeiten</a>
    </div>
    <div class="card-pad">
      {#if stats.length > 1}
        <div class="tabs" style="margin-bottom:12px">
          {#each stats as p}
            <button class:active={cur?.id === p.id} onclick={() => (pick = p.id)}>{p.name}{p.enabled ? '' : ' (aus)'}</button>
          {/each}
        </div>
      {/if}
      {#if cur}<SmartStats s={cur} />{/if}
    </div>
  </div>
{/if}

<style>
  .kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 14px;
  }
  .kpi {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .big {
    font-size: var(--fs-xl);
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1.2;
    font-variant-numeric: tabular-nums;
  }
  .big .down {
    color: var(--down);
  }
  .unit {
    font-size: var(--fs-base);
    font-weight: 500;
  }
  .rchart {
    display: flex;
    gap: 6px;
    height: 160px;
  }
  .yax {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    font-size: var(--fs-xs);
    color: var(--muted);
    text-align: right;
    white-space: nowrap;
    min-width: 64px;
  }
  .plot {
    position: relative;
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: flex-end;
    gap: 2px;
    border-bottom: 1px solid var(--border);
    overflow: hidden;
  }
  .gl {
    position: absolute;
    left: 0;
    right: 0;
    border-top: 1px dashed var(--border);
  }
  .col {
    flex: 1 1 0;
    max-width: 14px;
    height: 100%;
    display: flex;
    flex-direction: column-reverse;
  }
  .b {
    width: 100%;
    min-height: 0;
  }
  .b.down {
    background: var(--down);
    border-radius: 2px 2px 0 0;
  }
  .b.up {
    background: var(--up);
    opacity: 0.85;
  }
  .legend {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 6px;
  }
  .dot {
    width: 9px;
    height: 9px;
    border-radius: 2px;
    display: inline-block;
  }
  .dot.down {
    background: var(--down);
  }
  .dot.up {
    background: var(--up);
  }
  .hit {
    gap: 8px;
  }
  .err {
    max-width: 260px;
  }
  @media (max-width: 640px) {
    .err {
      max-width: 100%;
    }
    .hit {
      flex-wrap: wrap;
    }
  }
</style>
