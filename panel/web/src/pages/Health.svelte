<script>
  // Zustand: Kennzahlen, „Braucht Aufmerksamkeit“, Komponenten, Portweiterleitungen, Testmodus-Log und
  // Ereignisse. System und Ereignisse kommen unverändert aus den Einstellungen (alte Adressen leiten um).
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Info from '../components/Info.svelte';
  import PortHelp from '../components/PortHelp.svelte';
  import AttentionList from '../components/AttentionList.svelte';
  import Board from '../components/Board.svelte';
  import { get, post, run } from '../lib/api.js';
  import { date, bytes, speed, duration } from '../lib/format.js';
  import { go, status } from '../lib/state.svelte.js';

  let { tab = 'overview' } = $props();
  const tabs = [
    ['overview', 'Übersicht', 'activity'],
    ['events', 'Ereignisse', 'list'],
  ];

  // ---------- System ----------
  let sys = $state(null);
  async function loadSystem() {
    sys = await get('/system');
    if (!pc) pc = (await get('/system/portcheck').catch(() => ({}))).last || null;
  }
  // Portweiterleitungen von außen prüfen (über einen Ausgang)
  let pc = $state(null);
  let pcBusy = $state(false);
  let pcError = $state('');
  async function checkPorts() {
    pcBusy = true;
    pcError = '';
    try {
      pc = await post('/system/portcheck');
    } catch (e) {
      pcError = e.message;
    }
    pcBusy = false;
  }
  const pcKey = (p) => `${p.server}|${p.proto}|${p.port}`;
  const pcFor = (p, fam) => pc?.items?.find((i) => i.family === fam && pcKey(i) === pcKey(p));
  const pcLabel = { ok: 'erreichbar', arrived: 'kein Dienst', missing: 'kommt nicht an', skipped: 'nicht prüfbar' };
  const pcClass = { ok: 'ok', arrived: 'warn', missing: 'bad', skipped: 'muted' };
  async function applyNow() {
    if (await run(() => post('/system/apply'), 'Konfiguration angewendet')) loadSystem();
  }
  async function collectNow() {
    if (await run(() => post('/system/collect'), 'Statistik eingesammelt')) loadSystem();
  }

  // ---------- Ereignisse ----------
  let events = $state([]);
  let level = $state('');
  async function loadEvents() {
    events = await get(`/events?limit=300${level ? `&level=${level}` : ''}`);
  }

  $effect(() => {
    const t = tab;
    if (t === 'overview') loadSystem();
    if (t === 'events') loadEvents();
  });
  const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
</script>

<PageHead title="Zustand" subtitle="Was gerade läuft, was Aufmerksamkeit braucht, Komponenten, Ports und Ereignisse" />

<div class="tabs">
  {#each tabs as [id, label, icon]}
    <button class:active={tab === id} onclick={() => go(`/health${id === 'overview' ? '' : '/' + id}`)}><Icon name={icon} size={16} /> {label}</button>
  {/each}
</div>

{#if tab === 'overview'}
  {#if sys}
  <div class="stack" style="margin-bottom:16px">
  <div class="row">
    <button class="btn primary" onclick={applyNow}><Icon name="refresh" size={16} /> Konfiguration jetzt anwenden</button>
    <button class="btn" onclick={collectNow}><Icon name="activity" size={16} /> Statistik einsammeln</button>
    <span class="grow"></span>
    <span class="muted small">Version {sys.version}</span>
  </div>
  {#if Object.keys(sys.errors || {}).length}
    <div class="notice bad"><Icon name="alert" /><div>{#each Object.entries(sys.errors) as [k, v]}<div class="small"><b>{k}:</b> {v}</div>{/each}</div></div>
  {/if}
  </div>
  {/if}
  {#snippet w_attention()}
    <div class="card">
      <div class="card-head"><h3>Braucht Aufmerksamkeit</h3>{#if status.attention.length}<span class="badge warn">{status.attention.length}</span>{/if}</div>
      <AttentionList />
    </div>
  {/snippet}
  {#snippet w_host()}
    <div class="card">
      <div class="card-head"><h3>Server</h3>{#if status.host?.uptime}<span class="small muted">läuft seit {duration(status.host.uptime)}</span>{/if}</div>
      {#if status.host}
        {@const h = status.host}
        <div class="card-pad hs">
          <div><div class="muted small">CPU ({h.cores} Kerne · Last {h.load1.toLocaleString('de-DE')})</div><div class="big">{Math.round(h.cpu)} %</div><div class="hbar"><i style="width:{Math.min(100, h.cpu)}%"></i></div></div>
          <div><div class="muted small">Arbeitsspeicher</div><div class="big">{pct(h.mem_used, h.mem_total)} %</div><div class="hbar"><i style="width:{pct(h.mem_used, h.mem_total)}%"></i></div><div class="tiny muted">{bytes(h.mem_used)} von {bytes(h.mem_total)}</div></div>
          {#if h.disk_size}<div><div class="muted small">Datenträger</div><div class="big">{pct(h.disk_used, h.disk_size)} %</div><div class="hbar"><i style="width:{pct(h.disk_used, h.disk_size)}%"></i></div><div class="tiny muted">{bytes(h.disk_used)} von {bytes(h.disk_size)}</div></div>{/if}
          <div><div class="muted small">Durchsatz ({h.iface})</div><div class="big nowrap"><Icon name="down" size={14} /> {speed(h.rx)}</div><div class="small nowrap"><Icon name="up" size={13} /> {speed(h.tx)}</div></div>
          <div><div class="muted small">Geräte online</div><div class="big">{status.peers_online} / {status.peers}</div></div>
        </div>
      {:else}
        <div class="card-pad muted small">Lade …</div>
      {/if}
    </div>
  {/snippet}
  {#snippet w_components()}
    <div class="card">
      <div class="card-head"><h3>Komponenten</h3></div>
      <div class="table-wrap">
        <table class="table">
          <tbody>
            {#each sys.checks as c}
              <tr><td><span class="row"><span class="dot" class:on={c.ok} class:bad={!c.ok}></span>{c.name}</span></td><td class="small muted right">{c.detail}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/snippet}
  {#snippet w_ports()}
    <div class="card">
      <div class="card-head">
        <h3>Portweiterleitungen auf dem Host <Info title="Firewall-Regeln für den Proxmox-Host" wide><PortHelp ports={sys.ports} /></Info></h3>
        <span class="row" style="gap:6px">
          <button class="btn sm" onclick={checkPorts} disabled={pcBusy || !sys.ports.length} title="Von außen prüfen, ob die Ports ankommen"><Icon name="refresh" size={14} /> {pcBusy ? 'Prüfe …' : 'Prüfen'}</button>
        </span>
      </div>
      <div class="card-pad stack-sm">
        {#if pcError}<div class="notice bad small">{pcError}</div>{/if}
        {#if !pc && !pcError}
          <div class="small muted">„Prüfen“ spricht die öffentliche Adresse über einen verbundenen Ausgang (externes VPN) an – wie ein fremdes
            Gerät aus dem Internet, ohne fremden Prüfdienst. UDP gilt als erreichbar, wenn das Prüfpaket im Container ankommt.
            IPv6 lässt sich so nicht prüfen (Ausgänge nur IPv4), bei Portbereichen zählt der erste Port.</div>
        {/if}
        {#if pc}
          <div class="small muted">
            Geprüft {date(pc.at, true)} über Ausgang „{pc.via}“{pc.via_ip ? ` (${pc.via_ip})` : ''} an {pc.addr4}{#if pc.dry_run}{' · '}<span class="badge warn">Testmodus – nur simuliert</span>{/if}
          </div>
        {/if}
        <table class="table">
          <tbody>
            {#each sys.ports as p}
              {@const r4 = pcFor(p, 'IPv4')}
              {@const r6 = pcFor(p, 'IPv6')}
              <tr>
                <td>
                  <span class="badge">{p.proto.toUpperCase()} {p.port}{p.to ? `–${p.to}` : ''}</span>
                  {#if r4}<div class="row" style="gap:4px;margin-top:4px;flex-wrap:wrap"><span class="badge {pcClass[r4.state]}" title={r4.detail}>{pc.addr6 ? 'IPv4 ' : ''}{pcLabel[r4.state]}</span>{#if r6 && pc.addr6}<span class="badge {pcClass[r6.state]}" title={r6.detail}>IPv6 {pcLabel[r6.state]}</span>{/if}</div>{/if}
                </td>
                <td class="small">{p.server}</td><td class="small muted">{p.note}</td>
              </tr>
              {#if r4 && r4.state !== 'ok'}<tr><td colspan="3" class="small" style="padding-top:0;color:var(--{r4.state === 'missing' ? 'bad' : 'warn'})">{r4.detail}</td></tr>{/if}
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/snippet}
  {#snippet w_drylog()}
    <div class="card">
      <div class="card-head"><h3>Testmodus – ausgeführte Befehle</h3><span class="badge warn">nicht wirklich ausgeführt</span></div>
      <pre class="code" style="border:none;border-radius:0 0 12px 12px;max-height:420px">{sys.dry_log.slice(-150).join('\n')}</pre>
    </div>
  {/snippet}
  <Board
    id="health"
    widgets={[
      { id: 'attention', title: 'Braucht Aufmerksamkeit', w: 6, body: w_attention },
      { id: 'host', title: 'Server', w: 6, body: w_host },
      { id: 'components', title: 'Komponenten', w: 6, body: w_components, show: !!sys },
      { id: 'ports', title: 'Portweiterleitungen auf dem Host', w: 6, body: w_ports, show: !!sys },
      { id: 'drylog', title: 'Testmodus – ausgeführte Befehle', w: 12, body: w_drylog, show: !!sys?.dry_run },
    ]}
  />
{:else if tab === 'events'}
  <div class="card">
    <div class="card-head">
      <h3>Ereignisse</h3>
      <div class="segmented">
        {#each [['', 'Alle'], ['info', 'Info'], ['warn', 'Warnungen'], ['error', 'Fehler']] as [k, l]}
          <button class:active={level === k} onclick={() => { level = k; loadEvents(); }}>{l}</button>
        {/each}
      </div>
    </div>
    <div class="table-wrap">
      <table class="table">
        <tbody>
          {#each events as e}
            <tr>
              <td class="small muted nowrap" style="width:150px">{date(e.ts, true)}</td>
              <td style="width:90px"><span class="badge {e.level === 'error' ? 'bad' : e.level === 'warn' ? 'warn' : 'muted'}">{e.level}</span></td>
              <td class="small">{e.msg}</td>
            </tr>
          {:else}
            <tr><td class="empty">Keine Ereignisse</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}

<style>
  .hs {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
  }
  .hbar {
    height: 6px;
    border-radius: 3px;
    background: var(--border);
    margin-top: 6px;
    overflow: hidden;
  }
  .hbar i {
    display: block;
    height: 100%;
    background: var(--accent);
    border-radius: 3px;
    transition: width 0.6s;
  }
</style>
