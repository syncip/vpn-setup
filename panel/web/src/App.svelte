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
  import { session, meta, toasts, route, go, status } from './lib/state.svelte.js';
  import { get, post } from './lib/api.js';
  import { bytes, speed } from './lib/format.js';

  let navOpen = $state(false);
  let theme = $state(document.documentElement.dataset.theme || '');

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

  // Menü in Gruppen (gleiche Seiten und Adressen wie bisher; „Zustand“ bündelt System und Ereignisse)
  const nav = [
    { items: [{ path: '/', label: 'Übersicht', icon: 'home', count: true }] },
    { title: 'Verwalten', items: [
      { path: '/users', label: 'Nutzer', icon: 'users' },
      { path: '/servers', label: 'Server', icon: 'server' },
      { path: '/plans', label: 'Tarife & Limits', icon: 'tag' },
    ] },
    { title: 'Netz', items: [
      { path: '/network', label: 'Netzwerk', icon: 'network' },
      { path: '/proxy', label: 'Proxy & Ausgänge', icon: 'route', keys: ['exit:', 'exitlimit:', 'group:'] },
      { path: '/dns', label: 'DNS', icon: 'globe', keys: ['unbound', 'cert:'] },
      { path: '/iplists', label: 'IP-Listen', icon: 'filter' },
    ] },
    { title: 'System', items: [
      { path: '/health', label: 'Zustand', icon: 'activity', keys: ['err:', 'port:', 'disk', 'mem', 'server_host', 'pkg:'] },
      { path: '/settings', label: 'Einstellungen', icon: 'settings', keys: ['alarm:'] },
    ] },
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
  // schlimmster Zustand je Menüpunkt (Punkt rechts)
  function navTone(n) {
    if (!n.keys) return '';
    const hit = issues.filter((a) => n.keys.some((k) => a.key.startsWith(k)));
    return hit.some((a) => a.level === 'error') ? 'bad' : hit.length ? 'warn' : '';
  }
  const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
  const memPct = $derived(pct(status.host?.mem_used, status.host?.mem_total));
  const diskPct = $derived(pct(status.host?.disk_used, status.host?.disk_size));

  // alte Adressen von System und Ereignissen (jetzt unter „Zustand“)
  $effect(() => {
    if (route.path === '/settings/system') go('/health');
    else if (route.path === '/settings/events') go('/health/events');
  });

  const parts = $derived(route.path.split('/').filter(Boolean));
  const section = $derived('/' + (parts[0] || ''));

  function active(p) {
    return p === '/' ? section === '/' : section === p;
  }

  async function logout() {
    await post('/auth/logout').catch(() => {});
    session.user = null;
  }

  function toggleTheme() {
    const dark = theme === 'dark' || (!theme && matchMedia('(prefers-color-scheme: dark)').matches);
    theme = dark ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem('theme', theme);
    } catch {
      /* egal */
    }
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
  <div class="layout">
    <aside class="sidebar" class:open={navOpen}>
      <div class="brand">
        <span class="logo"><Icon name="shield" size={20} /></span>
        <div>
          <div class="strong">VPN-Panel</div>
          <div class="tiny host">{meta.server_host}</div>
          <div class="tiny ver">
            v{meta.version}
            {#if meta.update?.available}<a class="upd" href={meta.update.url} target="_blank" rel="noopener noreferrer" title="Neue Version {meta.update.latest}">Update {meta.update.latest}</a>{/if}
          </div>
        </div>
      </div>
      <a class="mini" href="#/health" title="Zustand des Servers – Details unter „Zustand“">
        {#if status.host}
          {@const h = status.host}
          <div class="mrow"><span>CPU</span><span>{Math.round(h.cpu)} %</span></div>
          <div class="bar"><i style="width:{Math.min(100, h.cpu)}%" class:hot={h.cpu > 85}></i></div>
          <div class="mrow"><span>RAM</span><span title="{bytes(h.mem_used)} von {bytes(h.mem_total)}">{memPct} %</span></div>
          <div class="bar"><i style="width:{memPct}%" class:hot={memPct > 90}></i></div>
          {#if h.disk_size}
            <div class="mrow"><span>Speicher</span><span title="{bytes(h.disk_used)} von {bytes(h.disk_size)}">{diskPct} %</span></div>
            <div class="bar"><i style="width:{diskPct}%" class:hot={diskPct > 90}></i></div>
          {/if}
          <div class="mrow" title="Durchsatz auf {h.iface}"><span>Traffic</span><span class="nowrap"><Icon name="down" size={11} />{speed(h.rx)} <Icon name="up" size={11} />{speed(h.tx)}</span></div>
          <div class="mrow"><span>Geräte online</span><span>{status.peers_online} / {status.peers}</span></div>
        {:else}
          <div class="mrow"><span>Lade Zustand …</span></div>
        {/if}
      </a>
      <button class="sbtn" onclick={() => (search.open = true)} title="Schnellsuche (Strg+K)"><Icon name="search" size={15} /><span class="grow">Suchen …</span><kbd>Strg K</kbd></button>
      <nav>
        {#each nav as g}
          {#if g.title}<div class="nav-title">{g.title}</div>{/if}
          {#each g.items as n}
            {@const tone = navTone(n)}
            <a href="#{n.path}" class:active={active(n.path)}>
              <Icon name={n.icon} /> <span class="grow">{n.label}</span>
              {#if n.count && issues.length}<span class="nav-count" class:bad={issues.some((a) => a.level === 'error')} title="Braucht Aufmerksamkeit">{issues.length}</span>{/if}
              {#if tone}<span class="nav-dot {tone}" title="Braucht Aufmerksamkeit"></span>{/if}
            </a>
          {/each}
        {/each}
      </nav>
      <div class="side-foot">
        {#if meta.dry_run}<div class="badge warn" style="margin:0 8px 10px;height:auto;padding:4px 8px;white-space:normal">Testmodus – keine Systemänderungen</div>{/if}
        <div class="me">
          <a class="me-link grow" href="#/account" class:active={section === '/account'} title="Mein Konto">
            <span class="avatar">{session.user.username.slice(0, 1).toUpperCase()}</span>
            <span class="ellipsis">{session.user.username}</span>
          </a>
          <button class="icon-btn" onclick={toggleTheme} title="Hell/Dunkel"><Icon name="moon" size={16} /></button>
          <button class="icon-btn" onclick={logout} title="Abmelden"><Icon name="logout" size={16} /></button>
        </div>
      </div>
    </aside>
    {#if navOpen}<div class="scrim" role="presentation" onclick={() => (navOpen = false)}></div>{/if}

    <main>
      <button class="btn icon menu-btn" onclick={() => (navOpen = true)} aria-label="Menü"><Icon name="menu" /></button>
      {#if section === '/'}
        <Overview />
      {:else if section === '/users' && parts[1]}
        {#key parts[1]}<UserDetail id={Number(parts[1])} tab={parts[2] || 'overview'} />{/key}
      {:else if section === '/users'}
        <Users />
      {:else if section === '/network'}
        <Network id={Number(parts[1]) || 0} view={parts[2] || 'map'} tab={parts[1] === 'access' ? 'access' : ''} />
      {:else if section === '/servers'}
        <Servers />
      {:else if section === '/proxy'}
        <Proxy tab={parts[1] || 'overview'} />
      {:else if section === '/dns'}
        <DNS tab={parts[1] || 'overview'} />
      {:else if section === '/iplists'}
        <IPLists />
      {:else if section === '/plans'}
        <Plans />
      {:else if section === '/health'}
        <Health tab={parts[1] || 'overview'} />
      {:else if section === '/settings'}
        <Settings tab={parts[1] || 'general'} />
      {:else if section === '/account'}
        <Account />
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
  .ver {
    opacity: 0.7;
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .upd {
    background: var(--accent);
    color: #fff;
    border-radius: 999px;
    padding: 0 7px;
    font-weight: 600;
    opacity: 1;
    text-decoration: none;
  }
  .layout {
    display: flex;
    min-height: 100vh;
  }
  .sidebar {
    width: 236px;
    flex: none;
    background: var(--sidebar);
    color: var(--sidebar-text);
    display: flex;
    flex-direction: column;
    position: sticky;
    top: 0;
    height: 100vh;
    z-index: 30;
    overflow-y: auto;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 18px 18px 14px;
    color: #fff;
  }
  .host {
    color: var(--sidebar-text);
    opacity: 0.8;
  }
  .logo {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, #5b77ff, #3b54d4);
    color: #fff;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 0 10px;
  }
  nav a {
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 9px 12px;
    border-radius: 8px;
    color: var(--sidebar-text);
    font-weight: 550;
  }
  nav a:hover {
    background: var(--sidebar-hover);
    color: #fff;
  }
  nav a.active {
    background: var(--sidebar-hover);
    color: var(--sidebar-active);
    box-shadow: inset 3px 0 0 #6f88ff;
  }
  .mini {
    display: grid;
    gap: 4px;
    margin: 0 12px 12px;
    padding: 10px 12px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.06);
    color: var(--sidebar-text);
    font-size: 12px;
  }
  .mini:hover {
    background: var(--sidebar-hover);
  }
  .mrow {
    display: flex;
    justify-content: space-between;
    gap: 8px;
  }
  .mrow span:last-child {
    color: #fff;
    font-variant-numeric: tabular-nums;
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }
  .bar {
    height: 4px;
    border-radius: 2px;
    background: rgba(255, 255, 255, 0.08);
    margin-bottom: 3px;
    overflow: hidden;
  }
  .bar i {
    display: block;
    height: 100%;
    border-radius: 2px;
    background: #6f88ff;
    transition: width 0.6s;
  }
  .bar i.hot {
    background: #f0a33a;
  }
  .nav-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--sidebar-text);
    opacity: 0.55;
    padding: 12px 12px 4px;
  }
  .nav-count {
    min-width: 20px;
    height: 18px;
    padding: 0 6px;
    border-radius: 9px;
    background: #f0a33a;
    color: #1b1f2a;
    font-size: 11px;
    font-weight: 650;
    display: grid;
    place-items: center;
  }
  .nav-count.bad {
    background: #f06a6a;
    color: #fff;
  }
  .nav-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #f0a33a;
  }
  .nav-dot.bad {
    background: #f06a6a;
  }
  .side-foot {
    margin-top: auto;
    padding: 12px 10px 14px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
  }
  .me {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 6px 8px;
    color: #fff;
  }
  .me-link {
    display: flex;
    align-items: center;
    gap: 9px;
    min-width: 0;
    color: #fff;
    border-radius: 8px;
    padding: 2px 4px;
    margin: -2px -4px;
  }
  .me-link:hover,
  .me-link.active {
    background: var(--sidebar-hover);
  }
  .avatar {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background: #2a3350;
    font-weight: 650;
    font-size: 13px;
  }
  .icon-btn {
    border: none;
    background: none;
    color: var(--sidebar-text);
    cursor: pointer;
    padding: 6px;
    border-radius: 7px;
    display: grid;
    place-items: center;
  }
  .icon-btn:hover {
    background: var(--sidebar-hover);
    color: #fff;
  }
  main {
    flex: 1;
    min-width: 0;
    padding: 28px 32px 48px;
    max-width: none;
  }
  .menu-btn {
    display: none;
    margin-bottom: 12px;
  }
  .scrim {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.4);
    z-index: 25;
  }
  @media (max-width: 900px) {
    .sidebar {
      position: fixed;
      left: 0;
      transform: translateX(-100%);
      transition: transform 0.2s;
    }
    .sidebar.open {
      transform: none;
    }
    .menu-btn {
      display: inline-flex;
    }
    main {
      padding: 16px 16px 40px;
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
  .sbtn {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0 12px 10px;
    padding: 7px 10px;
    border-radius: 8px;
    border: 1px solid var(--sidebar-hover);
    background: transparent;
    color: var(--sidebar-text);
    font: inherit;
    font-size: 13px;
    cursor: pointer;
    text-align: left;
  }
  .sbtn:hover {
    background: var(--sidebar-hover);
    color: #fff;
  }
  .sbtn kbd {
    font: inherit;
    font-size: 10px;
    border: 1px solid var(--sidebar-hover);
    border-radius: 4px;
    padding: 0 4px;
  }
</style>
