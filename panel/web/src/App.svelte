<script>
  import Icon from './components/Icon.svelte';
  import Confirm from './components/Confirm.svelte';
  import Login from './pages/Login.svelte';
  import Overview from './pages/Overview.svelte';
  import Users from './pages/Users.svelte';
  import UserDetail from './pages/UserDetail.svelte';
  import Network from './pages/Network.svelte';
  import Servers from './pages/Servers.svelte';
  import Plans from './pages/Plans.svelte';
  import Settings from './pages/Settings.svelte';
  import Proxy from './pages/Proxy.svelte';
  import IPLists from './pages/IPLists.svelte';
  import DNS from './pages/DNS.svelte';
  import { session, meta, toasts, route, go } from './lib/state.svelte.js';
  import { get, post } from './lib/api.js';

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

  const nav = [
    { path: '/', label: 'Übersicht', icon: 'home' },
    { path: '/users', label: 'Nutzer', icon: 'users' },
    { path: '/network', label: 'Netzwerk', icon: 'network' },
    { path: '/servers', label: 'Server', icon: 'server' },
    { path: '/proxy', label: 'Proxy & Ausgänge', icon: 'route' },
    { path: '/dns', label: 'DNS', icon: 'globe' },
    { path: '/iplists', label: 'IP-Listen', icon: 'filter' },
    { path: '/plans', label: 'Tarife & Limits', icon: 'tag' },
    { path: '/settings', label: 'Einstellungen', icon: 'settings' },
  ];

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
      <nav>
        {#each nav as n}
          <a href="#{n.path}" class:active={active(n.path)}><Icon name={n.icon} /> {n.label}</a>
        {/each}
      </nav>
      <div class="side-foot">
        {#if meta.dry_run}<div class="badge warn" style="margin:0 8px 10px;height:auto;padding:4px 8px;white-space:normal">Testmodus – keine Systemänderungen</div>{/if}
        <div class="me">
          <span class="avatar">{session.user.username.slice(0, 1).toUpperCase()}</span>
          <span class="grow ellipsis">{session.user.username}</span>
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
        <Network id={Number(parts[1]) || 0} view={parts[2] || 'map'} />
      {:else if section === '/servers'}
        <Servers />
      {:else if section === '/proxy'}
        <Proxy />
      {:else if section === '/dns'}
        <DNS tab={parts[1] || 'overview'} />
      {:else if section === '/iplists'}
        <IPLists />
      {:else if section === '/plans'}
        <Plans />
      {:else if section === '/settings'}
        <Settings tab={parts[1] || 'general'} />
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
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 20px 18px 22px;
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
    max-width: 1760px;
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
</style>
