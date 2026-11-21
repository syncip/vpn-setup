<script>
  import Icon from './components/Icon.svelte';
  import Confirm from './components/Confirm.svelte';
  import Login from './pages/Login.svelte';
  import Overview from './pages/Overview.svelte';
  import Users from './pages/Users.svelte';
  import UserDetail from './pages/UserDetail.svelte';
  import Search, { search } from './components/Search.svelte';
  import Network from './pages/Network.svelte';
  import Servers from './pages/Servers.svelte';
  import Plans from './pages/Plans.svelte';
  import Settings from './pages/Settings.svelte';
  import Account from './pages/Account.svelte';
  import Proxy from './pages/Proxy.svelte';
  import IPLists from './pages/IPLists.svelte';
  import DNS from './pages/DNS.svelte';
  import Health from './pages/Health.svelte';
  import Stats from './pages/Stats.svelte';
  import { session, meta, toasts, route, go, moved, status } from './lib/state.svelte.js';
  import { get, post } from './lib/api.js';
  import { bytes, speed } from './lib/format.js';

  let navOpen = $state(false); // Handy: Menü offen
  let theme = $state(document.documentElement.dataset.theme || '');
  const pref = (k, d) => {
    try {
      return localStorage.getItem(k) || d;
    } catch {
      return d;
    }
  };
  const setPref = (k, v) => {
    try {
      localStorage.setItem(k, v);
    } catch {
      /* egal */
    }
  };
  let mini = $state(pref('sidebar', '') === 'mini'); // Seitenleiste nur mit Symbolen
  let density = $state(document.documentElement.dataset.density || '');

  async function boot() {
    try {
      session.user = await get('/auth/me');
      Object.assign(meta, await get('/meta'));
    } catch {
      session.user = null;
    }
    session.checked = true;
  }
  boot();

  $effect(() => {
    if (session.user && !meta.protocols.length) get('/meta').then((m) => Object.assign(meta, m));
  });

  // Menü: 7 Bereiche, Unterpunkte klappen beim aktiven Bereich auf.
  // keys: Schlüssel der Hinweise („Braucht Aufmerksamkeit“), die einen Punkt am Bereich zeigen.
  const NAV = [
    { path: '/', label: 'Übersicht', icon: 'home', count: true },
    {
      path: '/users',
      label: 'Nutzer',
      icon: 'users',
      subs: [
        ['/users', 'Alle Nutzer'],
        ['/users/plans', 'Tarife & Limits'],
      ],
    },
    {
      path: '/servers',
      label: 'Server',
      icon: 'server',
      subs: [
        ['/servers', 'Alle Server'],
        ['/servers/wg', 'WireGuard-Netz'],
        ['/servers/access', 'Zugriff'],
      ],
    },
    {
      path: '/routing',
      label: 'Routing',
      icon: 'route',
      keys: ['exit:', 'exitlimit:', 'group:', 'grouplimit:'],
      subs: [
        ['/routing', 'Übersicht'],
        ['/routing/map', 'Karte', ['/routing/live']],
        ['/routing/exits', 'Ausgänge'],
        ['/routing/groups', 'Gruppen'],
        ['/routing/rules', 'Ziel-Regeln'],
        ['/routing/iplists', 'IP-Listen'],
        ['/routing/proxy', 'Proxy-Server'],
      ],
    },
    {
      path: '/dns',
      label: 'DNS',
      icon: 'globe',
      keys: ['unbound', 'cert:'],
      subs: [
        ['/dns', 'Übersicht'],
        ['/dns/log', 'Protokoll'],
        ['/dns/profiles', 'Filterprofile'],
        ['/dns/lists', 'Blocklisten'],
        ['/dns/smart', 'SmartDNS'],
        ['/dns/external', 'Ohne VPN'],
        ['/dns/settings', 'Einstellungen'],
      ],
    },
    {
      path: '/stats',
      label: 'Statistik',
      icon: 'stats',
      subs: [
        ['/stats', 'Verkehr'],
        ['/stats/live', 'Live'],
        ['/stats/exits', 'Ausgänge'],
        ['/stats/dns', 'DNS'],
      ],
    },
    {
      path: '/system',
      label: 'System',
      icon: 'settings',
      keys: ['err:', 'port:', 'disk', 'mem', 'server_host', 'pkg:', 'alarm:'],
      subs: [
        ['/system', 'Zustand'],
        ['/system/updates', 'Updates'],
        ['/system/events', 'Ereignisse'],
        ['/system/settings', 'Einstellungen'],
        ['/system/account', 'Mein Konto'],
      ],
    },
  ];

  // Zustand alle 5 s (nur sichtbar und angemeldet)
  async function pollStatus() {
    if (!session.user || document.hidden) return;
    try {
      Object.assign(status, await get('/status'), { at: Date.now() });
    } catch {
      /* nächster Versuch */
    }
  }
  $effect(() => {
    if (!session.user) return;
    pollStatus();
    const t = setInterval(pollStatus, 5000);
    const vis = () => !document.hidden && pollStatus();
    document.addEventListener('visibilitychange', vis);
    return () => {
      clearInterval(t);
      document.removeEventListener('visibilitychange', vis);
    };
  });
  const issues = $derived(status.attention.filter((a) => a.level !== 'info'));
  // schlimmster Zustand je Bereich (Punkt rechts)
  function navTone(n) {
    if (!n.keys) return '';
    const hit = issues.filter((a) => n.keys.some((k) => a.key.startsWith(k)));
    return hit.some((a) => a.level === 'error') ? 'bad' : hit.length ? 'warn' : '';
  }
  const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
  const memPct = $derived(pct(status.host?.mem_used, status.host?.mem_total));
  const diskPct = $derived(pct(status.host?.disk_used, status.host?.disk_size));

  // alte Adressen → neue (Lesezeichen, Links in E-Mails)
  $effect(() => {
    const to = moved(route.path);
    if (to) go(to, true);
  });

  const parts = $derived(route.path.split('/').filter(Boolean));
  const section = $derived('/' + (parts[0] || ''));
  const cur = $derived(NAV.find((n) => n.path === section));
  // aktiver Unterpunkt: genauester Treffer (z. B. /servers/wg/3/matrix → WireGuard-Netz)
  const under = (path, p) => path === p || path.startsWith(p + '/');
  const curSub = $derived.by(() => {
    let best = null;
    for (const s of cur?.subs || []) {
      const hit = [s[0], ...(s[2] || [])].some((p) => under(route.path, p));
      if (hit && (!best || s[0].length > best[0].length)) best = s;
    }
    return best;
  });
  const pageLabel = $derived(cur ? (curSub && curSub[0] !== cur.path ? `${cur.label} · ${curSub[1]}` : cur.label) : 'VPN-Panel');
  $effect(() => {
    document.title = cur ? `${curSub && curSub[0] !== cur.path ? curSub[1] : cur.label} – VPN-Panel` : 'VPN-Panel';
  });

  async function logout() {
    await post('/auth/logout').catch(() => {});
    session.user = null;
  }

  function toggleTheme() {
    const dark = theme === 'dark' || (!theme && matchMedia('(prefers-color-scheme: dark)').matches);
    theme = dark ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    setPref('theme', theme);
  }
  function toggleDensity() {
    density = density === 'compact' ? '' : 'compact';
    if (density) document.documentElement.dataset.density = density;
    else delete document.documentElement.dataset.density;
    setPref('density', density);
  }
  function toggleMini() {
    mini = !mini;
    setPref('sidebar', mini ? 'mini' : '');
  }

  $effect(() => {
    route.path;
    navOpen = false;
  });
</script>

{#if !session.checked}
  <div class="boot"></div>
{:else if !session.user}
  <Login onlogin={boot} />
{:else}
  <Search />
  <div class="layout" class:mini>
    <aside class="sidebar" class:open={navOpen}>
      <div class="brand">
        <span class="logo"><Icon name="shield" size={18} /></span>
        <div class="brand-text">
          <div class="strong">VPN-Panel</div>
          <div class="tiny muted ellipsis">
            {meta.server_host} · v{meta.version}
            {#if meta.update?.available}<a class="upd" href={meta.update.url} target="_blank" rel="noopener noreferrer" title="Neue Version {meta.update.latest}">Update</a>{/if}
          </div>
        </div>
        <button class="ib collapse" onclick={toggleMini} title={mini ? 'Seitenleiste ausklappen' : 'Seitenleiste einklappen'} aria-label="Seitenleiste umschalten"><Icon name="sidebar" size={16} /></button>
      </div>

      <div class="side-scroll">
        <button class="sbtn" onclick={() => (search.open = true)} title="Schnellsuche (Strg+K)"><Icon name="search" size={15} /><span class="grow lbl">Suchen …</span><kbd class="lbl">Strg K</kbd></button>
        <nav>
          {#each NAV as n}
            {@const tone = navTone(n)}
            {@const on = n.path === section}
            <div class="sec" class:on>
              <a href="#{n.subs ? n.subs[0][0] : n.path}" class="top" class:active={on} title={mini ? n.label : ''}>
                <Icon name={n.icon} size={17} />
                <span class="grow lbl">{n.label}</span>
                {#if n.count && issues.length}<span class="nav-count" class:bad={issues.some((a) => a.level === 'error')} title="Braucht Aufmerksamkeit">{issues.length}</span>{/if}
                {#if tone}<span class="nav-dot {tone}" title="Braucht Aufmerksamkeit"></span>{/if}
                {#if n.subs && !mini}<span class="chev" class:open={on}><Icon name="chevron" size={13} /></span>{/if}
              </a>
              {#if n.subs}
                <div class="subs" class:fly={mini}>
                  {#if mini}<div class="fly-title">{n.label}</div>{/if}
                  {#each n.subs as s}
                    <a href="#{s[0]}" class:active={on && curSub?.[0] === s[0]}>{s[1]}</a>
                  {/each}
                </div>
              {/if}
            </div>
          {/each}
        </nav>
      </div>

      <a class="mini-stats" href="#/system" title="Zustand des Servers">
        {#if status.host}
          {@const h = status.host}
          <div class="gauges">
            <div title="CPU {Math.round(h.cpu)} %"><span class="lbl">CPU</span><b>{Math.round(h.cpu)}%</b><i class="bar"><i style="width:{Math.min(100, h.cpu)}%" class:hot={h.cpu > 85}></i></i></div>
            <div title="RAM: {bytes(h.mem_used)} von {bytes(h.mem_total)}"><span class="lbl">RAM</span><b>{memPct}%</b><i class="bar"><i style="width:{memPct}%" class:hot={memPct > 90}></i></i></div>
            {#if h.disk_size}<div title="Speicher: {bytes(h.disk_used)} von {bytes(h.disk_size)}"><span class="lbl">Disk</span><b>{diskPct}%</b><i class="bar"><i style="width:{diskPct}%" class:hot={diskPct > 90}></i></i></div>{/if}
          </div>
          <div class="mrow lbl" title="Durchsatz auf {h.iface}"><span><Icon name="down" size={11} />{speed(h.rx)} <Icon name="up" size={11} />{speed(h.tx)}</span><span>{status.peers_online}/{status.peers} online</span></div>
        {:else}
          <div class="mrow lbl"><span>Lade Zustand …</span></div>
        {/if}
      </a>

      <div class="side-foot">
        {#if meta.dry_run}<div class="badge warn dry lbl">Testmodus – keine Systemänderungen</div>{/if}
        <div class="me">
          <a class="me-link grow" href="#/system/account" title="Mein Konto">
            <span class="avatar">{session.user.username.slice(0, 1).toUpperCase()}</span>
            <span class="ellipsis lbl">{session.user.username}</span>
          </a>
          <button class="ib" onclick={toggleDensity} title={density ? 'Normale Abstände' : 'Kompakte Darstellung'} aria-label="Dichte umschalten" class:on={!!density}><Icon name="list" size={15} /></button>
          <button class="ib" onclick={toggleTheme} title="Hell/Dunkel" aria-label="Hell/Dunkel"><Icon name="moon" size={15} /></button>
          <button class="ib" onclick={logout} title="Abmelden" aria-label="Abmelden"><Icon name="logout" size={15} /></button>
        </div>
      </div>
    </aside>
    {#if navOpen}<div class="scrim" role="presentation" onclick={() => (navOpen = false)}></div>{/if}

    <main>
      <!-- Handy: Kopfzeile mit Menü, Seitenname und Warnungen -->
      <div class="topbar">
        <button class="btn icon ghost" onclick={() => (navOpen = true)} aria-label="Menü"><Icon name="menu" /></button>
        <span class="strong grow ellipsis">{pageLabel}</span>
        {#if issues.length}<a class="nav-count" class:bad={issues.some((a) => a.level === 'error')} href="#/" title="Braucht Aufmerksamkeit">{issues.length}</a>{/if}
        <button class="btn icon ghost" onclick={() => (search.open = true)} aria-label="Suchen"><Icon name="search" size={18} /></button>
      </div>
      {#if section === '/'}
        <Overview />
      {:else if section === '/users' && parts[1] === 'plans'}
        <Plans />
      {:else if section === '/users' && parts[1]}
        {#key parts[1]}<UserDetail id={Number(parts[1])} tab={parts[2] || 'overview'} />{/key}
      {:else if section === '/users'}
        <Users />
      {:else if section === '/servers' && parts[1] === 'access'}
        <Network tab="access" />
      {:else if section === '/servers' && parts[1] === 'wg'}
        <Network tab="wg" id={Number(parts[2]) || 0} view={parts[3] || 'map'} />
      {:else if section === '/servers'}
        <Servers />
      {:else if section === '/routing' && (parts[1] === 'map' || parts[1] === 'live')}
        <Network tab={parts[1] === 'live' ? 'live' : ''} />
      {:else if section === '/routing' && parts[1] === 'iplists'}
        <IPLists />
      {:else if section === '/routing'}
        <Proxy tab={parts[1] || 'overview'} />
      {:else if section === '/dns'}
        <DNS tab={parts[1] || 'overview'} />
      {:else if section === '/stats'}
        <Stats tab={parts[1] || 'traffic'} />
      {:else if section === '/system' && parts[1] === 'settings'}
        <Settings tab={parts[2] || 'general'} />
      {:else if section === '/system' && parts[1] === 'account'}
        <Account />
      {:else if section === '/system'}
        <Health tab={parts[1] || 'overview'} />
      {:else if moved(route.path)}
        <div class="boot"></div>
      {:else}
        <div class="empty"><h3>Seite nicht gefunden</h3><button class="btn" onclick={() => go('/')}>Zur Übersicht</button></div>
      {/if}
    </main>
  </div>
{/if}

<div class="toasts">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}"><Icon name={t.kind === 'error' ? 'alert' : 'check'} size={16} /> {t.msg}</div>
  {/each}
</div>
<Confirm />

<style>
  .boot {
    min-height: 100vh;
  }
  .layout {
    display: flex;
    min-height: 100vh;
  }
  /* ---------- Seitenleiste (folgt hell/dunkel) ---------- */
  .sidebar {
    width: 228px;
    flex: none;
    background: var(--panel);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    position: sticky;
    top: 0;
    height: 100vh;
    height: 100dvh;
    z-index: 30;
    transition: width 0.15s;
  }
  .mini .sidebar {
    width: 60px;
  }
  .mini .lbl,
  .mini .brand-text,
  .mini .chev,
  .mini .dry {
    display: none !important;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 10px 10px 14px;
    min-width: 0;
  }
  .mini .brand {
    flex-direction: column;
    padding: 12px 0 8px;
  }
  .brand-text {
    flex: 1;
    min-width: 0;
    line-height: 1.3;
  }
  .logo {
    width: 32px;
    height: 32px;
    flex: none;
    border-radius: 9px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, var(--brand-1), var(--brand-2));
    color: #fff;
  }
  .upd {
    background: var(--accent);
    color: #fff;
    border-radius: 999px;
    padding: 0 6px;
    font-weight: 600;
    margin-left: 2px;
  }
  .ib {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    width: 28px;
    height: 28px;
    flex: none;
    border-radius: 7px;
    display: grid;
    place-items: center;
    padding: 0;
  }
  .ib:hover {
    background: var(--panel-2);
    color: var(--text);
  }
  .ib.on {
    color: var(--accent);
  }
  .side-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    overflow-x: hidden;
    scrollbar-width: thin;
    padding-bottom: 8px;
  }
  .mini .side-scroll {
    overflow: visible;
  }
  .sbtn {
    display: flex;
    align-items: center;
    gap: 8px;
    width: calc(100% - 20px);
    margin: 2px 10px 10px;
    padding: 6px 9px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--panel-2);
    color: var(--muted);
    font: inherit;
    font-size: var(--fs-md);
    cursor: pointer;
    text-align: left;
  }
  .mini .sbtn {
    width: 40px;
    justify-content: center;
    padding: 7px 0;
  }
  .sbtn:hover {
    color: var(--text);
    border-color: var(--border-strong);
  }
  .sbtn kbd {
    font: inherit;
    font-size: var(--fs-xs);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0 4px;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 1px;
    padding: 0 8px;
  }
  .sec {
    position: relative;
  }
  nav a {
    display: flex;
    align-items: center;
    gap: 10px;
    border-radius: 7px;
    color: var(--text-2);
  }
  .top {
    padding: 7px 10px;
    font-weight: 550;
  }
  .mini .top {
    justify-content: center;
    padding: 9px 0;
  }
  .top:hover {
    background: var(--panel-2);
    color: var(--text);
  }
  .top.active {
    color: var(--text);
    font-weight: 650;
  }
  .top.active :global(svg) {
    color: var(--accent);
  }
  .mini .top.active {
    background: var(--accent-soft);
  }
  .chev {
    display: inline-flex;
    color: var(--muted);
    transition: transform 0.15s;
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .subs {
    display: none;
    flex-direction: column;
    gap: 1px;
    margin: 1px 0 6px 19px;
    padding-left: 10px;
    border-left: 1px solid var(--border);
  }
  .sec.on .subs:not(.fly) {
    display: flex;
  }
  .subs a {
    padding: 5px 10px;
    font-size: var(--fs-md);
    color: var(--muted);
  }
  .subs a:hover {
    color: var(--text);
    background: var(--panel-2);
  }
  .subs a.active {
    color: var(--accent);
    background: var(--accent-soft);
    font-weight: 600;
  }
  /* eingeklappt: Unterpunkte als Menü neben dem Symbol */
  .subs.fly {
    position: absolute;
    left: 48px;
    top: -4px;
    margin: 0;
    padding: 6px;
    min-width: 180px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    box-shadow: var(--shadow-lg);
    z-index: 40;
  }
  .sec:hover .subs.fly,
  .sec:focus-within .subs.fly {
    display: flex;
  }
  .fly-title {
    font-weight: 650;
    font-size: var(--fs-md);
    padding: 4px 10px 6px;
  }
  .nav-count {
    min-width: 20px;
    height: 18px;
    padding: 0 6px;
    border-radius: 9px;
    background: var(--warn);
    color: #fff;
    font-size: var(--fs-xs);
    font-weight: 650;
    display: grid;
    place-items: center;
  }
  .nav-count.bad {
    background: var(--bad);
  }
  .nav-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--warn);
    flex: none;
  }
  .nav-dot.bad {
    background: var(--bad);
  }
  .mini .nav-count,
  .mini .nav-dot {
    position: absolute;
    top: 4px;
    right: 8px;
  }
  .mini .nav-count {
    min-width: 16px;
    height: 14px;
    padding: 0 3px;
    font-size: 9px;
  }
  /* Server-Werte unten */
  .mini-stats {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 6px;
    min-width: 0;
    margin: 0 10px 8px;
    padding: 8px 10px;
    border-radius: 9px;
    border: 1px solid var(--border);
    background: var(--panel-2);
    color: var(--text-2);
    font-size: var(--fs-xs);
  }
  .mini-stats:hover {
    border-color: var(--border-strong);
  }
  .mini .mini-stats {
    margin: 0 6px 8px;
    padding: 6px 4px;
  }
  .gauges {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 8px;
  }
  .mini .gauges {
    grid-template-columns: 1fr;
    gap: 6px;
  }
  .gauges > div {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: baseline;
    gap: 0 4px;
  }
  .gauges b {
    color: var(--text);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .mini .gauges b {
    width: 100%;
    text-align: center;
  }
  i.bar {
    display: block;
    width: 100%;
    height: 3px;
    border-radius: 2px;
    background: var(--border);
    overflow: hidden;
    margin-top: 2px;
  }
  i.bar i {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 0.6s;
  }
  i.bar i.hot {
    background: var(--warn);
  }
  .mrow {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 2px 6px;
    min-width: 0;
    font-variant-numeric: tabular-nums;
  }
  .mrow span {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    white-space: nowrap;
  }
  .side-foot {
    flex: none;
    padding: 6px 8px 10px;
    border-top: 1px solid var(--border);
  }
  .dry {
    display: block;
    margin: 4px 2px 8px;
    height: auto;
    padding: 4px 8px;
    white-space: normal;
  }
  .me {
    display: flex;
    align-items: center;
    gap: 2px;
  }
  .mini .me {
    flex-direction: column;
    gap: 4px;
  }
  .me-link {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    color: var(--text);
    border-radius: 8px;
    padding: 4px 6px;
    font-weight: 550;
  }
  .mini .me-link {
    flex: none;
    padding: 2px;
  }
  .me-link:hover {
    background: var(--panel-2);
  }
  .avatar {
    width: 26px;
    height: 26px;
    flex: none;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 700;
    font-size: var(--fs-sm);
  }
  /* ---------- Inhalt ---------- */
  main {
    flex: 1;
    min-width: 0;
    padding: var(--main-pad, 22px 28px 48px);
  }
  .topbar {
    display: none;
  }
  .scrim {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.35);
    z-index: 25;
  }
  @media (max-width: 900px) {
    .sidebar,
    .mini .sidebar {
      position: fixed;
      left: 0;
      width: 260px;
      transform: translateX(-100%);
      transition: transform 0.2s;
      box-shadow: var(--shadow-lg);
    }
    .sidebar.open {
      transform: none;
    }
    .collapse {
      display: none;
    }
    /* auf dem Handy immer ausgeklappt */
    .mini .lbl,
    .mini .brand-text,
    .mini .chev {
      display: revert !important;
    }
    .mini .subs.fly {
      display: none;
    }
    .topbar {
      display: flex;
      align-items: center;
      gap: 8px;
      position: sticky;
      top: 0;
      z-index: 20;
      margin: -14px -14px 12px;
      padding: 6px 8px;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
    }
    .topbar .nav-count {
      text-decoration: none;
    }
    main {
      padding: 14px 14px 40px;
    }
  }
  .toasts {
    position: fixed;
    right: 18px;
    bottom: 18px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 100;
  }
  .toast {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-radius: 10px;
    background: var(--panel);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-lg);
    font-weight: 550;
    max-width: 420px;
    animation: slide 0.18s ease-out;
  }
  .toast.ok :global(svg) {
    color: var(--ok);
  }
  .toast.error {
    border-color: var(--bad);
  }
  .toast.error :global(svg) {
    color: var(--bad);
  }
  @keyframes slide {
    from {
      transform: translateY(10px);
      opacity: 0;
    }
  }
</style>
