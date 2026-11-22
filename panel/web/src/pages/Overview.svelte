<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import TrafficChart from '../components/TrafficChart.svelte';
  import LiveDevices from '../components/LiveDevices.svelte';
  import ExitLive from '../components/ExitLive.svelte';
  import DNSLive from '../components/DNSLive.svelte';
  import { liveFeed } from '../lib/live.svelte.js';
  import PageHead from '../components/PageHead.svelte';
  import { get, post, run } from '../lib/api.js';
  import { bytes, date, ago, speed, fmtNum } from '../lib/format.js';
  import { protocol, meta, status, intent, go } from '../lib/state.svelte.js';
  import AttentionList from '../components/AttentionList.svelte';
  import SearchInput from '../components/SearchInput.svelte';
  import Fold from '../components/Fold.svelte';
  import Board from '../components/Board.svelte';
  import UpdatesPanel from '../components/UpdatesPanel.svelte';
  import { tokens, matches } from '../lib/pick.js';

  let d = $state(null);
  let aq = $state('');
  let refresh = $state(0);
  let err = $state('');

  let ex = $state(null);
  async function load() {
    get('/exits').then((x) => (ex = x)).catch(() => {});
    try {
      d = await get('/overview');
      err = '';
    } catch (e) {
      err = e.message;
    }
  }
  load();
  $effect(() => {
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  });

  let upChecking = $state(false);
  async function checkUpdate() {
    upChecking = true;
    const r = await run(() => post('/update/check'));
    upChecking = false;
    if (r) meta.update = r;
  }
  const GSTATE = { ok: ['ok', 'OK'], failover: ['warn', 'Ausweich'], blocked: ['bad', 'gesperrt'], direct: ['warn', 'direkt'], waiting: ['muted', 'prüft'] };

  const lv = liveFeed();
  const topMax = $derived(Math.max(1, ...(d?.top || []).map((t) => t.up + t.down)));
  const alertTone = { blocked: 'bad', expired: 'bad', throttled: 'warn', limit: 'warn', expiring: 'warn' };
  const alertIcon = { blocked: 'lock', expired: 'clock', throttled: 'gauge', limit: 'alert', expiring: 'calendar' };
</script>

<PageHead title="Übersicht" subtitle="Alles auf einen Blick · „Anpassen“ ordnet die Fenster und fügt weitere hinzu">
  <button class="btn" onclick={() => (load(), refresh++)}><Icon name="refresh" size={16} /> Aktualisieren</button>
</PageHead>

{#if err}<div class="notice bad">{err}</div>{/if}

{#if d}
  {#snippet w_attention()}
    <div class="card">
      <div class="card-head">
        <h2>Braucht Aufmerksamkeit</h2>
        {#if status.attention.length}<span class="badge {status.attention.some((a) => a.level === 'error') ? 'bad' : 'warn'}">{status.attention.length}</span>{/if}
        <span class="grow"></span><a href="#/system" class="small">Zustand</a>
      </div>
      <AttentionList />
      {#if Object.keys(d.errors || {}).length}
        <div class="card-pad" style="padding-top:0">
          <Fold id="ov-errors" icon="alert" tone="bad" title="Fehler beim Anwenden – Rohdaten" count={Object.keys(d.errors).length}>
            {#each Object.entries(d.errors) as [k, v]}<div class="small"><b>{k}:</b> {v}</div>{/each}
          </Fold>
        </div>
      {/if}
    </div>
  {/snippet}
  {#snippet w_quick()}
    <div class="card">
      <div class="card-head"><h2>Schnellaktionen</h2></div>
      <div class="card-pad quick">
        <button class="btn" onclick={() => { intent.create = 'user'; go('/users'); }}><Icon name="plus" size={15} /> Nutzer anlegen</button>
        <a class="btn" href="#/routing/exits"><Icon name="globe" size={15} /> Ausgänge</a>
        <a class="btn" href="#/system"><Icon name="activity" size={15} /> Ports prüfen</a>
        <a class="btn" href="#/system/settings/backup"><Icon name="archive" size={15} /> Sicherung</a>
        <a class="btn" href="#/dns/log"><Icon name="list" size={15} /> DNS-Protokoll</a>
        <a class="btn" href="#/system/events"><Icon name="clock" size={15} /> Ereignisse</a>
      </div>
    </div>
  {/snippet}
  {#snippet w_now()}
    <a class="card card-pad stat link-card" href="#/stats/live">
      <div class="pill-icon"><Icon name="activity" /></div>
      <div>
        <div class="muted small">Jetzt</div>
        <div class="big"><span class="down-t">↓ {lv.d ? speed(lv.d.total.down) : '–'}</span></div>
        <div class="tiny muted">↑ {lv.d ? speed(lv.d.total.up) : '–'}</div>
      </div>
    </a>
  {/snippet}
  {#snippet w_online()}
    <a class="card card-pad stat link-card" href="#/stats/live">
      <div class="pill-icon"><Icon name="phone" /></div>
      <div>
        <div class="muted small">Online</div>
        <div class="big">{lv.d ? fmtNum(lv.d.total.users_online) : '–'}<span class="muted">{' '}Nutzer</span></div>
        <div class="tiny muted">{lv.d ? `${fmtNum(lv.d.total.peers_online)} von ${fmtNum(lv.d.total.peers)} Geräten verbunden` : ''}</div>
      </div>
    </a>
  {/snippet}
  {#snippet w_live()}
    <LiveDevices limit={8} />
  {/snippet}
  {#snippet w_exitlive()}
    {#if ex}<ExitLive exits={ex.exits} groups={ex.groups} />{/if}
  {/snippet}
  {#snippet w_dns()}
    <DNSLive />
  {/snippet}
  {#snippet w_version()}
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name={meta.update?.available ? 'download' : 'check'} /></div>
      <div class="grow">
        <div class="muted small">Version</div>
        <div class="big">v{meta.version}</div>
        <div class="tiny muted">
          {#if meta.update?.disabled}Update-Prüfung ausgeschaltet
          {:else if meta.update?.available}<a href={meta.update.url} target="_blank" rel="noopener noreferrer"><b>Neue Version {meta.update.latest} verfügbar</b></a> – Einspielen wie in der README beschrieben
          {:else if meta.update?.error}Prüfung fehlgeschlagen: {meta.update.error}
          {:else if meta.update?.checked}Aktuell (geprüft {ago(meta.update.checked)})
          {:else}Noch nicht geprüft{/if}
        </div>
      </div>
      {#if !meta.update?.disabled}<button class="btn sm" onclick={checkUpdate} disabled={upChecking}><Icon name="refresh" size={14} /> Jetzt prüfen</button>{/if}
    </div>
  {/snippet}
  {#snippet w_updates()}
    <UpdatesPanel compact />
  {/snippet}
  {#snippet w_groups()}
    <div class="card">
      <div class="card-head"><h2>Ausgangsgruppen</h2><a href="#/routing/groups" class="small">Alle</a></div>
      <div class="list">
        {#each ex?.groups || [] as g}
          {@const st = GSTATE[g.status?.state] || ['muted', g.enabled ? 'prüft' : 'aus']}
          {@const act = ex.exits.find((e) => e.id === g.status?.active)}
          <a class="item" href="#/routing/groups">
            <span class="pill-icon sm"><Icon name="layers" size={15} /></span>
            <div class="grow">
              <div class="strong ellipsis">{g.name}</div>
              <div class="muted tiny ellipsis">→ {act ? act.name : 'kein Ausgang'}{act?.status?.loc ? ` (${act.status.loc})` : ''}</div>
            </div>
            <span class="badge {st[0]}">{st[1]}</span>
          </a>
        {:else}
          <div class="empty small">{ex ? 'Keine Gruppen eingerichtet' : 'Lädt …'} <a href="#/routing/groups">Gruppen</a></div>
        {/each}
      </div>
    </div>
  {/snippet}
  {#snippet w_users()}
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="users" /></div>
      <div>
        <div class="muted small">Nutzer gesamt</div>
        <div class="big">{d.counts.users || 0}<span class="muted">{' · '}{d.counts.peers || 0} Zugänge</span></div>
      </div>
    </div>
  {/snippet}
  {#snippet w_servercount()}
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="server" /></div>
      <div>
        <div class="muted small">Server</div>
        <div class="big">{d.counts.servers || 0}</div>
      </div>
    </div>
  {/snippet}
  {#snippet w_today()}
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="activity" /></div>
      <div>
        <div class="muted small">Traffic heute</div>
        <div class="big">{bytes(d.today.up + d.today.down)}</div>
        {#if d.smart?.today}<div class="tiny muted">davon SmartDNS {bytes(d.smart.today)}</div>{/if}
      </div>
    </div>
  {/snippet}
  {#snippet w_month()}
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="calendar" /></div>
      <div>
        <div class="muted small">Traffic diesen Monat</div>
        <div class="big">{bytes(d.month.up + d.month.down)}</div>
        {#if d.smart?.month}<div class="tiny muted">davon SmartDNS {bytes(d.smart.month)}</div>{/if}
      </div>
    </div>
  {/snippet}
  {#snippet w_traffic()}
    <TrafficChart id="home-traffic" title="Verkehr" {refresh} />
  {/snippet}
  {#snippet w_servers()}
    <div class="card">
      <div class="card-head"><h2>Server</h2><a href="#/servers" class="small">Alle</a></div>
      <div class="list">
        {#each d.servers as s}
          <a class="item" href={s.protocol === 'wireguard' ? `#/servers/wg/${s.id}` : '#/servers'}>
            <span class="srvlogo"><ProtoLogo id={s.protocol} size={30} /><span class="dot" class:on={s.status.running} class:bad={s.enabled && !s.status.running}></span></span>
            <div class="grow">
              <div class="strong">{s.name}</div>
              <div class="muted tiny">{protocol(s.protocol)?.label || s.protocol} · {s.status.detail}</div>
            </div>
            <span class="badge">{s.online} / {s.peers}</span>
          </a>
        {:else}
          <div class="empty small">Noch keine Server. <a href="#/servers">Server anlegen</a></div>
        {/each}
      </div>
    </div>
  {/snippet}
  {#snippet w_alerts()}
    <Fold id="ov-alerts" icon="alert" tone={d.alerts.length ? 'warn' : ''} title="Hinweise" count={d.alerts.length}>
      {#if d.alerts.length > 6}<div style="padding:0 0 6px"><SearchInput bind:value={aq} placeholder="Hinweise durchsuchen …" width="100%" /></div>{/if}
      <div class="list" style="max-height:420px;overflow:auto;padding:0">
        {#each d.alerts.filter((a) => matches(`${a.name} ${a.text}`, tokens(aq))) as a}
          <a class="item" href="#/users/{a.user_id}">
            <span class="badge {alertTone[a.kind]}" style="width:28px;padding:0;justify-content:center"><Icon name={alertIcon[a.kind]} size={14} /></span>
            <div class="grow">
              <div class="strong">{a.name}</div>
              <div class="muted tiny">{a.text}</div>
            </div>
          </a>
        {:else}
          <div class="empty small"><Icon name="check" /> Alles in Ordnung</div>
        {/each}
      </div>
    </Fold>
  {/snippet}
  {#snippet w_top()}
    <div class="card">
      <div class="card-head"><h2>Top-Nutzer</h2><span class="muted small">30 Tage</span></div>
      <div class="list">
        {#each d.top as t}
          <a class="item" href="#/users/{t.id}">
            <div class="grow">
              <div class="spread"><span class="strong">{t.name}</span><span class="small">{bytes(t.up + t.down)}</span></div>
              <div class="bar"><div style="width:{((t.up + t.down) / topMax) * 100}%"></div></div>
            </div>
          </a>
        {:else}
          <div class="empty small">Noch kein Traffic</div>
        {/each}
      </div>
    </div>
  {/snippet}
  {#snippet w_events()}
    <div class="card">
      <div class="card-head"><h2>Ereignisse</h2><a href="#/system/events" class="small">Alle</a></div>
      <div class="list">
        {#each d.events as e}
          <div class="item ev">
            <span class="dot" class:warn={e.level === 'warn'} class:bad={e.level === 'error'}></span>
            <div class="grow">
              <div class="small">{e.msg}</div>
              <div class="muted tiny">{date(e.ts, true)}</div>
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/snippet}
  <Board
    id="home"
    widgets={[
      { id: 'now', title: 'Tempo jetzt', w: 3, body: w_now },
      { id: 'online', title: 'Online', w: 3, body: w_online },
      { id: 'today', title: 'Traffic heute', w: 3, body: w_today },
      { id: 'month', title: 'Traffic diesen Monat', w: 3, body: w_month },
      { id: 'traffic', title: 'Verkehr (live und Verlauf)', w: 8, body: w_traffic },
      { id: 'attention', title: 'Braucht Aufmerksamkeit', w: 4, body: w_attention },
      { id: 'servers', title: 'Server', w: 4, body: w_servers },
      { id: 'groups', title: 'Ausgangsgruppen', w: 4, body: w_groups },
      { id: 'top', title: 'Top-Nutzer', w: 4, body: w_top },
      { id: 'events', title: 'Ereignisse', w: 6, body: w_events },
      { id: 'alerts', title: 'Hinweise zu Nutzern', w: 6, body: w_alerts },
      { id: 'live', title: 'Verbundene Geräte', w: 12, body: w_live, off: true, desc: 'Wer gerade verbunden ist, mit Tempo – durchsuchbar' },
      { id: 'exitlive', title: 'Ausgänge live', w: 12, body: w_exitlive, off: true, desc: 'Durchsatz der Ausgänge und Gruppen' },
      { id: 'dns', title: 'DNS live', w: 12, body: w_dns, off: true, desc: 'Anfragen je Sekunde und benutzte DNS-Server' },
      { id: 'quick', title: 'Schnellaktionen', w: 4, body: w_quick, off: true, desc: 'Nutzer anlegen, Ausgänge, Ports, Sicherung …' },
      { id: 'version', title: 'Version', w: 6, body: w_version, off: true, desc: 'Panel-Version und Update-Prüfung' },
      { id: 'updates', title: 'Updates', w: 6, body: w_updates, off: true, desc: 'Paket- und Programm-Updates des Servers' },
      { id: 'users', title: 'Nutzer gesamt', w: 3, body: w_users, off: true, desc: 'Anzahl Nutzer und Zugänge' },
      { id: 'servercount', title: 'Anzahl Server', w: 3, body: w_servercount, off: true },
    ]}
  />

{/if}

<style>
  .link-card {
    color: inherit;
    text-decoration: none;
  }
  .stat {
    display: flex;
    gap: 14px;
    align-items: center;
  }
  .srvlogo { position: relative; display: inline-flex; flex: none; }
  .srvlogo .dot { position: absolute; right: -3px; bottom: -3px; box-shadow: 0 0 0 2px var(--panel); }
  .pill-icon.sm {
    width: 30px;
    height: 30px;
    border-radius: 8px;
  }
  .stat .pill-icon {
    width: 36px;
    height: 36px;
    border-radius: 10px;
  }
  .big {
    font-size: var(--fs-2xl);
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1.2;
  }
  .down-t {
    color: var(--down);
  }
  .big .muted {
    font-size: var(--fs-lg);
    font-weight: 600;
  }
  .list {
    display: flex;
    flex-direction: column;
    padding: 6px;
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
  .ev {
    align-items: flex-start;
  }
  .ev .dot {
    margin-top: 6px;
  }
  .bar {
    height: 5px;
    border-radius: 5px;
    background: var(--panel-2);
    margin-top: 5px;
    overflow: hidden;
  }
  .bar div {
    height: 100%;
    background: var(--accent);
    border-radius: 5px;
  }
  .quick {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 8px;
  }
  .quick .btn {
    justify-content: flex-start;
  }
</style>
