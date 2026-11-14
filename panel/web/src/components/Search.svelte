<script module>
  // Schnellsuche (Strg+K / ⌘K): Seiten, Einstellungen, Nutzer, Geräte, Server, Ausgänge, Gruppen, Tarife.
  export const search = $state({ open: false });
</script>

<script>
  import Icon from './Icon.svelte';
  import { get } from '../lib/api.js';
  import { go, intent } from '../lib/state.svelte.js';
  import { tokens } from '../lib/pick.js';
  import { PROTO_LABEL } from '../lib/format.js';

  // Seiten, Reiter und Einstellungen (mit Stichwörtern, unter denen man sie sucht)
  const PAGES = [
    ['/', 'Übersicht', 'home', 'start dashboard live traffic aufmerksamkeit'],
    ['/users', 'Nutzer', 'users', 'benutzer konten kunden'],
    ['/servers', 'Server', 'server', 'wireguard vless hysteria openvpn protokolle'],
    ['/plans', 'Tarife & Limits', 'tag', 'volumen drosselung limit tarif kontingent'],
    ['/network', 'Netzwerk · Übersicht', 'network', 'topologie karte homelab'],
    ['/network/access', 'Netzwerk · Zugriff', 'lock', 'zugriff zwischen servern netze freigeben'],
    ['/proxy', 'Proxy & Ausgänge · Übersicht', 'route', 'ausgang externes vpn'],
    ['/proxy/exits', 'Ausgänge', 'globe', 'externes vpn anbieter wireguard openvpn hochladen speedtest'],
    ['/proxy/groups', 'Ausgangsgruppen', 'layers', 'failover ausweich gruppe'],
    ['/proxy/rules', 'Ziel-Regeln', 'route', 'routing domains länder regeln'],
    ['/proxy/proxy', 'Proxy-Server', 'server', 'socks5 http proxy fernseher'],
    ['/dns', 'DNS · Übersicht', 'globe', 'dns statistik anfragen gesperrt'],
    ['/dns/log', 'DNS-Protokoll', 'list', 'dns log anfragen protokoll'],
    ['/dns/profiles', 'DNS-Filterprofile', 'shield', 'filter profil kinder werbung smartdns'],
    ['/dns/lists', 'DNS-Blocklisten', 'filter', 'blocklisten werbeblocker tracker adblock'],
    ['/dns/external', 'DNS ohne VPN', 'globe', 'doh dot verschlüsselt freigabe zertifikat'],
    ['/dns/settings', 'DNS-Einstellungen', 'settings', 'unbound upstream zwischenspeicher cache ttl'],
    ['/iplists', 'IP-Listen', 'filter', 'sperrliste freigabe länder ip'],
    ['/health', 'Zustand', 'activity', 'system komponenten cpu ram anwenden einsammeln'],
    ['/health', 'Portweiterleitungen prüfen', 'activity', 'port weiterleitung proxmox erreichbar dnat'],
    ['/health/updates', 'Updates', 'download', 'paket update xray hysteria debian apt sicherheit version'],
    ['/health/events', 'Ereignisse', 'clock', 'log protokoll fehler warnungen'],
    ['/settings', 'Einstellungen · Allgemein', 'settings', 'domain server host abo port update-prüfung'],
    ['/settings/security', 'Einstellungen · Sicherheit', 'lock', 'lokale netze private'],
    ['/settings/security', 'Login-Sperre', 'shield', 'fehlversuche gesperrte adressen ip sperren entsperren brute force'],
    ['/settings/notify', 'Benachrichtigungen', 'mail', 'e-mail smtp mailserver testmail'],
    ['/settings/backup', 'Sicherung', 'archive', 'backup export einspielen wiederherstellen'],
    ['/settings/admins', 'Administratoren', 'users', 'admin konten zugänge panel'],
    ['/account', 'Mein Konto', 'user', 'passwort 2fa zwei-faktor totp sitzungen anmeldeprotokoll e-mail'],
  ];

  let q = $state('');
  let sel = $state(0);
  let idx = $state(null);
  let loadedAt = 0;
  let inputEl = $state();

  async function loadIndex() {
    if (idx && Date.now() - loadedAt < 60000) return;
    try {
      const [s, ex] = await Promise.all([get('/search'), get('/exits').catch(() => null)]);
      idx = { ...s, exits: ex?.exits || [], groups: ex?.groups || [] };
      loadedAt = Date.now();
    } catch {}
  }

  $effect(() => {
    if (search.open) {
      q = '';
      sel = 0;
      loadIndex();
      queueMicrotask(() => inputEl?.focus());
    }
  });

  const entries = $derived.by(() => {
    const out = [{ group: 'Aktionen', label: 'Nutzer anlegen', icon: 'plus', run: () => { intent.create = 'user'; go('/users'); }, text: 'nutzer anlegen neu hinzufügen' }];
    for (const [path, label, icon, kw] of PAGES) out.push({ group: 'Seiten', label, icon, path, text: `${label} ${kw}` });
    if (idx) {
      for (const u of idx.users) out.push({ group: 'Nutzer', label: u.name, sub: u.sub, icon: 'user', path: `/users/${u.id}`, off: u.off, text: `${u.name} ${u.sub || ''}` });
      for (const p of idx.peers) out.push({ group: 'Geräte und Zugänge', label: p.name, sub: p.sub, icon: 'phone', path: `/users/${p.user_id}/peers`, off: p.off, text: `${p.name} ${p.sub || ''} ${PROTO_LABEL[p.proto] || ''}` });
      for (const s of idx.servers) out.push({ group: 'Server', label: s.name, sub: PROTO_LABEL[s.proto] || s.proto, icon: 'server', path: s.proto === 'wireguard' ? `/network/${s.id}` : '/servers', off: s.off, text: `${s.name} ${PROTO_LABEL[s.proto] || s.proto} server` });
      for (const e of idx.exits) out.push({ group: 'Ausgänge', label: e.name, sub: e.status?.loc || '', icon: 'globe', path: '/proxy/exits', text: `${e.name} ausgang ${e.status?.loc || ''} ${e.status?.ip || ''}` });
      for (const g of idx.groups) out.push({ group: 'Ausgangsgruppen', label: g.name, icon: 'layers', path: '/proxy/groups', text: `${g.name} gruppe` });
      for (const p of idx.plans) out.push({ group: 'Tarife', label: p.name, sub: p.sub, icon: 'tag', path: '/plans', text: `${p.name} tarif ${p.sub || ''}` });
    }
    return out;
  });

  const results = $derived.by(() => {
    const toks = tokens(q);
    if (!toks.length) return entries.filter((e) => e.group === 'Aktionen' || e.group === 'Seiten').slice(0, 14);
    const scored = [];
    for (const e of entries) {
      const t = e.text.toLowerCase();
      if (!toks.every((w) => t.includes(w))) continue;
      const l = e.label.toLowerCase();
      let score = 0;
      if (l === toks.join(' ')) score += 100;
      if (l.startsWith(toks[0])) score += 40;
      if (l.includes(toks[0])) score += 20;
      if (e.group === 'Seiten' || e.group === 'Aktionen') score += 5;
      if (e.off) score -= 3;
      scored.push([score, e]);
    }
    scored.sort((a, b) => b[0] - a[0]);
    return scored.slice(0, 40).map((x) => x[1]);
  });
  // nach Gruppen ordnen, Reihenfolge der Gruppen nach bestem Treffer
  const grouped = $derived.by(() => {
    const m = new Map();
    for (const r of results) {
      if (!m.has(r.group)) m.set(r.group, []);
      m.get(r.group).push(r);
    }
    return [...m.entries()];
  });
  const flat = $derived(grouped.flatMap(([, l]) => l));

  $effect(() => {
    q;
    sel = 0;
  });

  function pick(e) {
    search.open = false;
    if (e.run) e.run();
    else go(e.path);
  }
  function onKey(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      sel = Math.min(flat.length - 1, sel + 1);
      scrollSel();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      sel = Math.max(0, sel - 1);
      scrollSel();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (flat[sel]) pick(flat[sel]);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      search.open = false;
    }
  }
  function scrollSel() {
    queueMicrotask(() => document.querySelector('.sr-item.sel')?.scrollIntoView({ block: 'nearest' }));
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      search.open = !search.open;
    }
  }}
/>

{#if search.open}
  <div class="sr-scrim" onclick={() => (search.open = false)} role="presentation"></div>
  <div class="sr" role="dialog" aria-modal="true" aria-label="Suche">
    <div class="sr-input">
      <Icon name="search" size={18} />
      <input bind:this={inputEl} bind:value={q} onkeydown={onKey} placeholder="Suchen: Nutzer, Gerät, Server, Ausgang, Einstellung …" autocomplete="off" spellcheck="false" />
      <kbd>Esc</kbd>
    </div>
    <div class="sr-list">
      {#each grouped as [g, list]}
        <div class="sr-group">{g}</div>
        {#each list as e}
          {@const i = flat.indexOf(e)}
          <button class="sr-item" class:sel={i === sel} class:off={e.off} onclick={() => pick(e)} onmousemove={() => (sel = i)}>
            <Icon name={e.icon} size={16} />
            <span class="grow ellipsis"><span class="strong">{e.label}</span>{#if e.sub}<span class="muted small"> · {e.sub}</span>{/if}</span>
            {#if e.off}<span class="badge muted">aus</span>{/if}
            {#if i === sel}<Icon name="arrow-right" size={14} />{/if}
          </button>
        {/each}
      {:else}
        <div class="sr-empty muted small">Nichts gefunden für „{q}“.</div>
      {/each}
    </div>
    <div class="sr-foot tiny muted"><span><kbd>↑</kbd> <kbd>↓</kbd> auswählen</span><span><kbd>Enter</kbd> öffnen</span><span><kbd>Strg</kbd> <kbd>K</kbd> öffnen/schließen</span></div>
  </div>
{/if}

<style>
  .sr-scrim {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.35);
    z-index: 90;
  }
  .sr {
    position: fixed;
    top: 12vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(640px, calc(100vw - 24px));
    max-height: 70vh;
    display: flex;
    flex-direction: column;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    z-index: 91;
    overflow: hidden;
  }
  .sr-input {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    color: var(--muted);
  }
  .sr-input input {
    flex: 1;
    border: none;
    outline: none;
    background: none;
    font: inherit;
    font-size: 16px;
    color: var(--text);
    min-width: 0;
  }
  .sr-list {
    overflow-y: auto;
    padding: 6px;
  }
  .sr-group {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    padding: 10px 10px 4px;
  }
  .sr-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 10px;
    border: none;
    background: none;
    border-radius: 8px;
    font: inherit;
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .sr-item.sel {
    background: var(--panel-2);
    outline: 1px solid var(--border);
  }
  .sr-item.off {
    opacity: 0.6;
  }
  .sr-empty {
    padding: 18px;
    text-align: center;
  }
  .sr-foot {
    display: flex;
    gap: 14px;
    padding: 8px 14px;
    border-top: 1px solid var(--border);
    flex-wrap: wrap;
  }
  kbd {
    font: inherit;
    font-size: 11px;
    border: 1px solid var(--border);
    border-bottom-width: 2px;
    border-radius: 4px;
    padding: 0 5px;
    background: var(--panel-2);
    color: var(--muted);
  }
</style>
