<script>
  import Icon from '../components/Icon.svelte';
  import Chart from '../components/Chart.svelte';
  import PageHead from '../components/PageHead.svelte';
  import { get } from '../lib/api.js';
  import { bytes, date } from '../lib/format.js';
  import { protocol } from '../lib/state.svelte.js';

  let d = $state(null);
  let range = $state('24h');
  let err = $state('');

  async function load() {
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

  const series = $derived(range === '24h' ? { points: d?.series24 || [], bucket: 3600, since: Date.now() / 1000 - 86400 } : { points: d?.series30 || [], bucket: 86400, since: Date.now() / 1000 - 30 * 86400 });
  const topMax = $derived(Math.max(1, ...(d?.top || []).map((t) => t.up + t.down)));
  const alertTone = { blocked: 'bad', expired: 'bad', throttled: 'warn', limit: 'warn', expiring: 'warn' };
  const alertIcon = { blocked: 'lock', expired: 'clock', throttled: 'gauge', limit: 'alert', expiring: 'calendar' };
</script>

<PageHead title="Übersicht" subtitle="Alles auf einen Blick">
  <button class="btn" onclick={load}><Icon name="refresh" size={16} /> Aktualisieren</button>
</PageHead>

{#if err}<div class="notice bad">{err}</div>{/if}

{#if d}
  {#if Object.keys(d.errors || {}).length}
    <div class="notice bad" style="margin-bottom:16px">
      <Icon name="alert" />
      <div>
        <div class="strong">Beim Anwenden ist ein Fehler aufgetreten</div>
        {#each Object.entries(d.errors) as [k, v]}<div class="small"><b>{k}:</b> {v}</div>{/each}
      </div>
    </div>
  {/if}

  <div class="grid cols-4">
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="users" /></div>
      <div>
        <div class="muted small">Nutzer online</div>
        <div class="big">{d.counts.users_online || 0}<span class="muted"> / {d.counts.users || 0}</span></div>
      </div>
    </div>
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="phone" /></div>
      <div>
        <div class="muted small">Zugänge verbunden</div>
        <div class="big">{d.counts.peers_online || 0}<span class="muted"> / {d.counts.peers || 0}</span></div>
      </div>
    </div>
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="activity" /></div>
      <div>
        <div class="muted small">Traffic heute</div>
        <div class="big">{bytes(d.today.up + d.today.down)}</div>
      </div>
    </div>
    <div class="card card-pad stat">
      <div class="pill-icon"><Icon name="calendar" /></div>
      <div>
        <div class="muted small">Traffic diesen Monat</div>
        <div class="big">{bytes(d.month.up + d.month.down)}</div>
      </div>
    </div>
  </div>

  <div class="grid main-grid" style="margin-top:16px">
    <div class="card">
      <div class="card-head">
        <h2>Traffic</h2>
        <div class="segmented">
          <button class:active={range === '24h'} onclick={() => (range = '24h')}>24 Stunden</button>
          <button class:active={range === '30d'} onclick={() => (range = '30d')}>30 Tage</button>
        </div>
      </div>
      <div class="card-pad"><Chart {...series} height={210} /></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>Server</h2><a href="#/servers" class="small">Alle</a></div>
      <div class="list">
        {#each d.servers as s}
          <a class="item" href={s.protocol === 'wireguard' ? `#/network/${s.id}` : '#/servers'}>
            <span class="dot" class:on={s.status.running} class:bad={s.enabled && !s.status.running}></span>
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
  </div>

  <div class="grid cols-3" style="margin-top:16px">
    <div class="card">
      <div class="card-head"><h2>Hinweise</h2><span class="badge">{d.alerts.length}</span></div>
      <div class="list">
        {#each d.alerts as a}
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
    </div>

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

    <div class="card">
      <div class="card-head"><h2>Ereignisse</h2><a href="#/settings/events" class="small">Alle</a></div>
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
  </div>
{/if}

<style>
  .stat {
    display: flex;
    gap: 14px;
    align-items: center;
  }
  .stat .pill-icon {
    width: 42px;
    height: 42px;
    border-radius: 12px;
  }
  .big {
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1.2;
  }
  .big .muted {
    font-size: 16px;
    font-weight: 600;
  }
  .main-grid {
    grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
  }
  @media (max-width: 1100px) {
    .main-grid {
      grid-template-columns: minmax(0, 1fr);
    }
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
    padding: 9px 12px;
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
</style>
