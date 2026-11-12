<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { ago, fmtNum } from '../lib/format.js';
  import { go } from '../lib/state.svelte.js';
  import Picker from '../components/Picker.svelte';
  import Info from '../components/Info.svelte';
  import { peerItems, userItems, serverItems } from '../lib/pick.js';
  import DNSExternal from '../components/DNSExternal.svelte';
  import DNSLive from '../components/DNSLive.svelte';

  let { tab = 'overview' } = $props();

  let d = $state({ settings: {}, info: {}, profiles: [], lists: [], presets: [], choices: { servers: [], users: [], peers: [], groups: [] }, error: '' });
  let loaded = $state(false);

  async function load() {
    d = await get('/dns');
    loaded = true;
  }
  load();

  const TABS = [
    ['overview', 'Übersicht', 'activity'],
    ['log', 'Protokoll', 'list'],
    ['profiles', 'Filterprofile', 'shield'],
    ['lists', 'Blocklisten', 'filter'],
    ['external', 'Ohne VPN', 'globe'],
    ['settings', 'Einstellungen', 'settings'],
  ];

  const peerById = $derived(Object.fromEntries(d.choices.peers.map((p) => [p.id, p])));
  const userById = $derived(Object.fromEntries(d.choices.users.map((u) => [u.id, u])));
  const srvById = $derived(Object.fromEntries(d.choices.servers.map((s) => [s.id, s])));
  const groupById = $derived(Object.fromEntries(d.choices.groups.map((g) => [g.id, g])));
  const dnsPeers = $derived(d.choices.peers.filter((p) => p.protocol === 'wireguard' || p.protocol === 'openvpn'));
  const extById = $derived(Object.fromEntries((d.ext || []).map((c) => [c.id, c])));
  const peerLabel = (id) => {
    if (id < 0) return `Ohne VPN · ${extById[-id]?.name || `#${-id}`}`;
    const p = peerById[id];
    if (!p) return id ? `Gerät #${id}` : 'unbekannt';
    return `${userById[p.user_id]?.name || '?'} · ${p.name}`;
  };
  // Auswahl mit Suche: Geräte mit Dienst und Server, gleichnamige Geräte unterscheidbar
  const dnsServers = $derived(d.choices.servers.filter((s) => s.protocol === 'wireguard' || s.protocol === 'openvpn'));
  const peerPick = $derived(peerItems(dnsPeers, d.choices.users, d.choices.servers));
  const peerSub = $derived(Object.fromEntries(peerPick.map((i) => [i.value, i])));
  const when = (ts) => (ago(ts) === 'online' ? 'gerade eben' : ago(ts));
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const day = (ts) => new Date(ts * 1000).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
  const QTYPE = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS' };
  const ACTION = {
    ok: ['', 'check', 'aufgelöst'],
    cached: ['', 'clock', 'aus Speicher'],
    blocked: ['bad', 'lock', 'gesperrt'],
    rewritten: ['accent', 'route', 'eigene Antwort'],
    error: ['warn', 'alert', 'Fehler'],
  };
  const REFRESH = [
    [0, 'nur von Hand'],
    [6, 'alle 6 Stunden'],
    [12, 'alle 12 Stunden'],
    [24, 'täglich'],
    [168, 'wöchentlich'],
  ];
  const refreshText = (h) => REFRESH.find((r) => r[0] === h)?.[1] || `alle ${h} Stunden`;

  // ---------- Übersicht ----------
  let hours = $state(24);
  let stats = $state(null);
  async function loadStats() {
    stats = await get(`/dns/stats?hours=${hours}`).catch(() => null);
  }
  $effect(() => {
    if (tab === 'overview') {
      hours;
      loadStats();
      const t = setInterval(() => {
        loadStats();
        load();
      }, 15000);
      return () => clearInterval(t);
    }
  });
  const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
  // Balken je Stunde: ganze Spanne, auch Stunden ohne Anfragen
  const bars = $derived.by(() => {
    if (!stats) return [];
    const now = Math.floor(Date.now() / 1000 / 3600) * 3600;
    const n = Math.min(hours, 24 * 7);
    const step = hours > 24 * 7 ? Math.ceil(hours / (24 * 7)) : 1;
    const by = Object.fromEntries(stats.hours.map((h) => [h[0], h]));
    const out = [];
    for (let i = n - 1; i >= 0; i -= 1) {
      let tot = 0,
        bl = 0;
      const t0 = now - i * step * 3600;
      for (let k = 0; k < step; k++) {
        const h = by[t0 - k * 3600];
        if (h) {
          tot += h[1];
          bl += h[2];
        }
      }
      out.push({ ts: t0, tot, bl });
    }
    return out;
  });
  const maxBar = $derived(Math.max(1, ...bars.map((b) => b.tot)));

  let check = $state({ peer: 0, name: '' });
  let checkRes = $state(null);
  async function runCheck() {
    checkRes = await run(() => post('/dns/check', { peer: Number(check.peer), name: check.name }));
  }

  // ---------- Protokoll ----------
  let filter = $state({ q: '', peer: 0, action: '' });
  let entries = $state([]);
  let more = $state(false);
  let live = $state(true);
  async function loadLog(append = false) {
    const p = new URLSearchParams({ limit: '200' });
    if (filter.q) p.set('q', filter.q);
    if (Number(filter.peer)) p.set('peer', filter.peer);
    if (filter.action) p.set('action', filter.action);
    if (append && entries.length) p.set('before', entries[entries.length - 1].id);
    const r = await get('/dns/log?' + p).catch(() => ({ entries: [] }));
    entries = append ? [...entries, ...r.entries] : r.entries;
    more = r.entries.length === 200;
  }
  let qTimer;
  $effect(() => {
    if (tab !== 'log') return;
    filter.q;
    filter.peer;
    filter.action;
    clearTimeout(qTimer);
    qTimer = setTimeout(() => loadLog(), 250);
  });
  $effect(() => {
    if (tab !== 'log' || !live) return;
    const t = setInterval(() => loadLog(), 5000);
    return () => clearInterval(t);
  });

  // Schnell sperren/freigeben: Regel in ein Profil schreiben
  let quick = $state(null); // {name, allow}
  let quickProfile = $state(0);
  function openQuick(name, allow) {
    quick = { name, allow };
    quickProfile = d.profiles[0]?.id || 0;
  }
  async function applyQuick() {
    const p = d.profiles.find((x) => x.id === Number(quickProfile));
    if (!p) return;
    const line = quick.allow ? `allow ${quick.name}` : quick.name;
    const rules = (p.rules ? p.rules + '\n' : '') + line;
    if (await run(() => put(`/dns/profiles/${p.id}`, { rules }), quick.allow ? `${quick.name} freigegeben` : `${quick.name} gesperrt`)) {
      quick = null;
      load();
    }
  }

  // ---------- Filterprofile ----------
  let pOpen = $state(false);
  let pCur = $state(null);
  let pf = $state({});
  function openProfile(p = null) {
    pCur = p;
    pf = p
      ? { name: p.name, enabled: p.enabled, lists: [...p.lists], rules: p.rules, assign: [...p.assign], block_doh: p.block_doh, nxdomain: p.nxdomain, smart: (p.smart || []).map((x) => ({ group: x.group, domains: x.domains.join('\n') })) }
      : { name: d.profiles.length ? '' : 'Standard', enabled: true, lists: d.lists.filter((l) => l.mode === 'block').map((l) => l.id), rules: '', assign: d.profiles.length ? [] : ['global'], block_doh: true, nxdomain: false, smart: [] };
    pOpen = true;
  }
  function toggleList(id) {
    pf.lists = pf.lists.includes(id) ? pf.lists.filter((x) => x !== id) : [...pf.lists, id];
  }
  // [Icon, Text, Protokoll, Zusatz]
  function assignLabel(a) {
    if (a === 'global') return ['globe', 'Alle Geräte', '', ''];
    const [k, idText] = a.split(':');
    const id = Number(idText);
    if (k === 'server') return ['server', srvById[id]?.name || `Server #${id}`, srvById[id]?.protocol || '', 'Server'];
    if (k === 'user') return ['user', userById[id]?.name || `Nutzer #${id}`, '', 'Nutzer'];
    const it = peerSub[id];
    return ['phone', peerLabel(id), it?.proto || '', it?.sub || ''];
  }
  // eine Suche über alle: Server, Nutzer, Geräte
  const assignPick = $derived(
    [
      { value: 'global', label: 'Alle Geräte', icon: 'globe', sub: 'alle WireGuard- und OpenVPN-Geräte', search: 'alle geräte global' },
      ...serverItems(dnsServers, 'server'),
      ...userItems(d.choices.users, 'user', dnsPeers),
      ...peerItems(dnsPeers, d.choices.users, d.choices.servers, 'peer'),
    ].filter((i) => !(pf.assign || []).includes(i.value)),
  );
  function addAssign(it) {
    if (!pf.assign.includes(it.value)) pf.assign = [...pf.assign, it.value];
  }
  // ---------- SmartDNS ----------
  const SMART_PRESETS = [
    ['Netflix', 'netflix.com\nnetflix.net\nnflxvideo.net\nnflximg.net\nnflximg.com\nnflxext.com\nnflxso.net\nfast.com'],
    ['Disney+', 'disneyplus.com\ndisney-plus.net\ndssott.com\nbamgrid.com\ndisneystreaming.com\ndisneynow.com'],
    ['Prime Video', 'primevideo.com\namazonvideo.com\naiv-cdn.net\naiv-delivery.net\npv-cdn.net\nmedia-amazon.com'],
    ['Hulu', 'hulu.com\nhulustream.com\nhuluim.com\nhulu.hb.omtrdc.net'],
    ['Max', 'max.com\nhbomax.com\nhbo.com\nhbomaxcdn.com\ndiscomax.com'],
    ['BBC iPlayer', 'bbc.co.uk\nbbc.com\nbbci.co.uk\nbbc.net.uk\nbidi.net.uk'],
    ['YouTube', 'youtube.com\ngooglevideo.com\nytimg.com\nyoutubei.googleapis.com\nyoutube-nocookie.com'],
    ['Spotify', 'spotify.com\nscdn.co\nspotifycdn.com\nspotilocal.com'],
    ['ChatGPT', 'openai.com\nchatgpt.com\noaistatic.com\noaiusercontent.com'],
  ];
  const groupOpts = $derived(d.choices.groups || []);
  function addSmart(preset) {
    const g = groupOpts.find((x) => x.enabled) || groupOpts[0];
    if (preset) {
      const row = pf.smart.find((r) => r.group === g?.id);
      if (row) {
        const have = new Set(row.domains.split(/\s+/).filter(Boolean));
        row.domains = [...have, ...preset[1].split('\n').filter((x) => !have.has(x))].join('\n');
        return;
      }
    }
    pf.smart = [...pf.smart, { group: g?.id || 0, domains: preset ? preset[1] : '' }];
  }
  const smartCount = (t) => (t || '').split(/[\s,;]+/).filter((x) => x && !x.startsWith('#')).length;

  async function saveProfile() {
    const body = $state.snapshot(pf);
    body.smart = body.smart.filter((r) => r.domains.trim()).map((r) => ({ group: Number(r.group), domains: r.domains }));
    const r = pCur ? await run(() => put(`/dns/profiles/${pCur.id}`, body), 'Profil gespeichert') : await run(() => post('/dns/profiles', body), 'Profil angelegt');
    if (r) {
      pOpen = false;
      load();
    }
  }
  async function toggleProfile(p) {
    if (await run(() => put(`/dns/profiles/${p.id}`, { enabled: !p.enabled }), p.enabled ? 'Profil deaktiviert' : 'Profil aktiviert')) load();
  }
  async function removeProfile(p) {
    if (!(await confirmDialog({ title: `Profil ${p.name} löschen?`, text: 'Geräte mit diesem Profil werden danach nicht mehr gefiltert (oder bekommen das nächste passende Profil).', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/dns/profiles/${p.id}`), 'Profil gelöscht')) load();
  }
  const ruleCount = (t) => (t || '').split('\n').map((l) => l.replace(/#.*/, '').trim()).filter(Boolean).length;

  // ---------- Blocklisten ----------
  let lOpen = $state(false);
  let lCur = $state(null);
  let lf = $state({});
  // Profile, in denen eine neue Liste gleich landet: die für alle Geräte, sonst das einzige Profil
  const globalProfiles = $derived(d.profiles.filter((p) => p.assign.includes('global')));
  function defaultProfiles() {
    if (globalProfiles.length) return globalProfiles.map((p) => p.id);
    return d.profiles.length === 1 ? [d.profiles[0].id] : [];
  }
  function openList(l = null, preset = null) {
    lCur = l;
    lf = l
      ? { name: l.name, enabled: l.enabled, mode: l.mode, url: l.url, refresh: l.refresh, entries: l.entries.join('\n'), profiles: d.profiles.filter((p) => p.lists.includes(l.id)).map((p) => p.id), mkStd: false }
      : { name: preset?.name || '', enabled: true, mode: 'block', url: preset?.url || '', refresh: 24, entries: '', profiles: defaultProfiles(), mkStd: !d.profiles.length };
    lOpen = true;
  }
  function toggleLP(id) {
    lf.profiles = lf.profiles.includes(id) ? lf.profiles.filter((x) => x !== id) : [...lf.profiles, id];
  }
  // Liste in die gewählten Profile eintragen bzw. austragen (oder Profil „Standard“ anlegen)
  async function syncProfiles(listId, want, mkStd) {
    if (mkStd && !d.profiles.length) {
      await run(() => post('/dns/profiles', { name: 'Standard', enabled: true, lists: [listId], rules: '', assign: ['global'], block_doh: true, nxdomain: false }), 'Profil „Standard“ für alle Geräte angelegt');
      return;
    }
    for (const p of d.profiles) {
      const has = p.lists.includes(listId);
      const on = want.includes(p.id);
      if (has === on) continue;
      const lists = on ? [...p.lists, listId] : p.lists.filter((x) => x !== listId);
      await run(() => put(`/dns/profiles/${p.id}`, { lists }));
    }
  }
  async function saveList() {
    const { profiles, mkStd, ...rest } = $state.snapshot(lf);
    const body = { ...rest, refresh: Number(rest.refresh) || 0 };
    const r = lCur ? await run(() => put(`/dns/lists/${lCur.id}`, body), 'Liste gespeichert') : await run(() => post('/dns/lists', body), 'Liste angelegt – wird geladen');
    if (r) {
      await syncProfiles(lCur ? lCur.id : r.id, profiles, mkStd);
      lOpen = false;
      load();
      setTimeout(load, 3000);
    }
  }
  // Übersicht „So wird gefiltert“: Listen ohne Profil wirken nicht
  const unusedLists = $derived(d.lists.filter((l) => l.enabled && !d.profiles.some((p) => p.enabled && p.lists.includes(l.id))));
  const activeProfiles = $derived(d.profiles.filter((p) => p.enabled));
  async function addUnusedTo(p) {
    if (await run(() => put(`/dns/profiles/${p.id}`, { lists: [...new Set([...p.lists, ...unusedLists.map((l) => l.id)])] }), `Listen in „${p.name}“ aufgenommen`)) load();
  }
  const listDomains = (p) => p.lists.reduce((a, id) => a + (d.lists.find((l) => l.id === id && l.enabled)?.total || 0), 0);
  let busy = $state(0);
  async function refreshList(l) {
    busy = l.id;
    await run(() => post(`/dns/lists/${l.id}/refresh`, {}), 'Liste neu geladen');
    busy = 0;
    load();
  }
  async function toggleDNSList(l) {
    if (await run(() => put(`/dns/lists/${l.id}`, { enabled: !l.enabled }), l.enabled ? 'Liste deaktiviert' : 'Liste aktiviert')) load();
  }
  async function removeList(l) {
    if (!(await confirmDialog({ title: `Liste ${l.name} löschen?`, ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/dns/lists/${l.id}`), 'Liste gelöscht')) load();
  }
  const usedPresets = $derived(new Set(d.lists.map((l) => l.url)));
  $effect(() => {
    if (tab !== 'lists') return;
    const t = setInterval(() => !lOpen && load(), 15000);
    return () => clearInterval(t);
  });

  // ---------- Einstellungen ----------
  let sf = $state(null);
  $effect(() => {
    if (loaded && !sf)
      sf = {
        enabled: d.settings.enabled === '1',
        upstream: d.settings.upstream,
        log_days: Number(d.settings.log_days),
        cache_size: Number(d.settings.cache_size ?? 50000),
        ttl_min: Number(d.settings.ttl_min || 0),
        ttl_max: Number(d.settings.ttl_max || 86400),
        nocache: d.settings.nocache || '',
        strategy: d.settings.strategy || 'order',
        resolver: d.settings.resolver || 'upstream',
        auto: d.settings.auto === '1',
        auto_hours: Number(d.settings.auto_hours || 24),
        auto_count: Number(d.settings.auto_count || 2),
      };
  });
  const STRATEGY = [
    ['order', 'Reihenfolge', 'Der erste Server antwortet; die weiteren nur, wenn er ausfällt.'],
    ['fastest', 'Schnellster', 'Zuerst der Server mit der besten gemessenen Antwortzeit (wird laufend gemessen).'],
    ['roundrobin', 'Reihum (Round Robin)', 'Anfragen gleichmäßig verteilen – keiner der Anbieter sieht alles.'],
    ['parallel', 'Parallel', 'An bis zu drei Server gleichzeitig, die erste Antwort gilt – am schnellsten, mehr Last.'],
  ];
  const TTLS = [
    [0, 'wie vom Server'],
    [30, '30 Sekunden'],
    [60, '1 Minute'],
    [300, '5 Minuten'],
    [600, '10 Minuten'],
    [1800, '30 Minuten'],
    [3600, '1 Stunde'],
    [21600, '6 Stunden'],
    [86400, '1 Tag'],
  ];
  const CACHES = [
    [0, 'aus'],
    [5000, '5 000 Antworten'],
    [20000, '20 000 Antworten'],
    [50000, '50 000 Antworten'],
    [100000, '100 000 Antworten'],
    [250000, '250 000 Antworten'],
  ];
  // DNS-Speedtest
  let speed = $state(null);
  let speedBusy = $state(false);
  async function runSpeed() {
    speedBusy = true;
    const r = await run(() => post('/dns/speedtest', {}));
    speedBusy = false;
    if (r) speed = r.results;
  }
  // Liste der Server für Speedtest und automatische Wahl
  const cands = $derived(
    (d.settings.candidates || '')
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const i = l.indexOf(' ');
        return i < 0 ? { addr: l, name: l } : { addr: l.slice(0, i), name: l.slice(i + 1) };
      }),
  );
  const candSet = $derived(new Set(cands.map((c) => c.addr)));
  let newCand = $state({ addr: '', name: '' });
  async function saveCands(list, msg) {
    const text = list.map((c) => `${c.addr} ${c.name}`).join('\n');
    if (await run(() => put('/dns/settings', { candidates: text }), msg)) {
      await load();
      return true;
    }
    return false;
  }
  async function addCand() {
    const addr = newCand.addr.trim();
    if (!addr) return;
    if (await saveCands([...cands, { addr, name: newCand.name.trim() || addr }], 'Server hinzugefügt')) newCand = { addr: '', name: '' };
  }
  async function dropCand(addr) {
    if ((await saveCands(cands.filter((c) => c.addr !== addr), 'Server entfernt')) && speed) speed = speed.filter((x) => x.addr !== addr || x.current);
  }
  async function resetCands() {
    if (!(await confirmDialog({ title: 'Liste zurücksetzen?', text: 'Die eingebaute Liste bekannter DNS-Server wird wiederhergestellt.', ok: 'Zurücksetzen' }))) return;
    if (await run(() => put('/dns/settings', { candidates: '' }), 'Liste zurückgesetzt')) load();
  }
  const isLocal = (a) => a.startsWith('127.') || a.startsWith('[::1]');
  const KNOWN_DNS = { '127.0.0.1:5335': 'Unbound', '1.1.1.1': 'Cloudflare', '1.0.0.1': 'Cloudflare', '8.8.8.8': 'Google', '8.8.4.4': 'Google', '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9', '94.140.14.140': 'AdGuard', '208.67.222.222': 'OpenDNS', '76.76.2.0': 'Control D', '185.222.222.222': 'DNS.SB' };
  const srvHost = (a) => a.replace(/:53$/, '');
  const srvName = (a) => KNOWN_DNS[srvHost(a)] || srvHost(a);
  // automatische Wahl
  let autoBusy = $state(false);
  async function autoNow() {
    autoBusy = true;
    const r = await run(() => post('/dns/auto', {}));
    autoBusy = false;
    if (r) {
      await load();
      sf = null;
    }
  }
  const HOURS = [
    [1, 'stündlich'],
    [6, 'alle 6 Stunden'],
    [12, 'alle 12 Stunden'],
    [24, 'täglich'],
    [72, 'alle 3 Tage'],
    [168, 'wöchentlich'],
  ];
  function useServers(n) {
    sf.upstream = speed
      .filter((x) => x.ok)
      .slice(0, n)
      .map((x) => x.addr)
      .join(', ');
  }
  async function saveSettings() {
    const body = $state.snapshot(sf);
    body.log_days = Number(body.log_days) || 0;
    for (const k of ['cache_size', 'ttl_min', 'ttl_max']) body[k] = Number(body[k]) || 0;
    if (body.log_days === 0 && Number(d.settings.log_days) > 0) {
      if (!(await confirmDialog({ title: 'Protokoll abschalten?', text: 'Das vorhandene DNS-Protokoll wird gelöscht.', ok: 'Abschalten', danger: true }))) return;
    }
    if (await run(() => put('/dns/settings', body), 'DNS-Einstellungen gespeichert')) load();
  }
</script>

<PageHead title="DNS" subtitle="Eigener DNS für WireGuard- und OpenVPN-Geräte">
  {#if tab === 'profiles'}<button class="btn primary" onclick={() => openProfile()}><Icon name="plus" size={16} /> Profil anlegen</button>{/if}
  {#if tab === 'lists'}<button class="btn primary" onclick={() => openList()}><Icon name="plus" size={16} /> Liste anlegen</button>{/if}
</PageHead>

<div class="tabs">
  {#each TABS as [id, label, icon]}
    <button class:active={tab === id} onclick={() => go(id === 'overview' ? '/dns' : `/dns/${id}`)}><Icon name={icon} size={14} /> {label}</button>
  {/each}
</div>

{#if d.error}<div class="notice bad" style="margin-bottom:16px"><Icon name="alert" /><span>{d.error}</span></div>{/if}

{#if loaded && d.settings.enabled !== '1'}
  <div class="notice warn" style="margin-bottom:16px">
    <Icon name="alert" />
    <span>Der Panel-DNS ist ausgeschaltet – Geräte fragen ihre eingetragenen DNS-Server direkt (Filter und Protokoll wirken nicht). <a href="#/dns/settings">Einschalten</a></span>
  </div>
{/if}

{#if tab === 'overview'}
  <div class="row wrap" style="gap:10px;margin-bottom:14px">
    <span class="badge {d.info.running ? 'ok' : d.dry_run ? 'muted' : 'warn'}">
      <span class="dot" class:on={d.info.running}></span>
      {d.info.running ? 'Läuft' : d.dry_run ? 'Testmodus – läuft nicht' : 'Läuft nicht'}
    </span>
    <span class="muted small">{fmtNum(d.info.devices)} {d.info.devices === 1 ? 'Gerät nutzt' : 'Geräte nutzen'} den Panel-DNS · {fmtNum(d.info.cached)} Antworten im Speicher{#if d.info.last}&nbsp;· letzte Anfrage {when(d.info.last)}{/if}</span>
    <span class="grow"></span>
    <div class="segmented">
      {#each [[24, '24 h'], [168, '7 Tage'], [720, '30 Tage']] as [h, label]}
        <button class:active={hours === h} onclick={() => (hours = h)}>{label}</button>
      {/each}
    </div>
  </div>

  {#if d.settings.enabled === '1'}<DNSLive />{/if}

  <div class="card filtercard">
    <div class="card-head">
      <h3>
        So wird gefiltert
        <Info title="Blocklisten und Filterprofile" wide>
          <p><b>Blocklisten</b> sagen, <i>was</i> gesperrt wird – große Sammlungen von Domains (Werbung, Tracker, …), die der Server regelmäßig neu lädt.</p>
          <p><b>Filterprofile</b> sagen, <i>für wen</i> welche Listen gelten – plus eigene Regeln (sperren, freigeben, eigene Antworten). So bekommt z. B. ein Profil „Kinder“ strengere Listen als „Standard“.</p>
          <p>Eine Liste wirkt erst, wenn sie in einem aktiven Profil steckt. Beim Anlegen einer Liste kannst du die Profile gleich mit auswählen; gibt es noch keins, legt das Panel „Standard“ für alle Geräte an.</p>
          <p>Für jedes Gerät gilt genau ein Profil: Gerät vor Nutzer vor Server vor „Alle Geräte“.</p>
        </Info>
      </h3>
      <button class="btn sm" onclick={() => go('/dns/lists')}><Icon name="filter" size={14} /> Blocklisten</button>
    </div>
    <div class="card-pad stack" style="gap:8px;padding-top:0">
      {#if loaded && !activeProfiles.length}
        <div class="notice warn small">
          <Icon name="alert" size={16} />
          <span>Es wird noch nichts gefiltert – kein aktives Filterprofil.{#if d.lists.length}&nbsp;{d.lists.length} {d.lists.length === 1 ? 'Liste ist' : 'Listen sind'} angelegt, aber keinem Profil zugeordnet.{/if}</span>
          <button class="btn sm primary" onclick={() => openProfile()}>Profil „Standard“ anlegen</button>
        </div>
      {/if}
      {#each activeProfiles as p}
        <div class="fline">
          <Icon name="shield" size={15} />
          <button class="linkbtn strong" onclick={() => openProfile(p)}>{p.name}</button>
          <Icon name="arrow-right" size={13} />
          {#each p.assign.slice(0, 4) as a}
            {@const [ic, label] = assignLabel(a)}
            <span class="badge"><Icon name={ic} size={12} /> {label}</span>
          {:else}
            <span class="warn-t small">noch niemandem zugeordnet</span>
          {/each}
          {#if p.assign.length > 4}<span class="muted small">+{p.assign.length - 4}</span>{/if}
          <span class="muted small">· {p.lists.length} {p.lists.length === 1 ? 'Liste' : 'Listen'} ({fmtNum(listDomains(p))} Domains) · {ruleCount(p.rules)} eigene Regeln{p.block_doh ? ' · DoH gesperrt' : ''}{p.smart?.length ? ` · SmartDNS: ${p.smart.map((x) => groupById[x.group]?.name || x.group).join(', ')}` : ''}</span>
        </div>
      {/each}
      {#if unusedLists.length && activeProfiles.length}
        <div class="notice warn small">
          <Icon name="alert" size={16} />
          <span>{unusedLists.map((l) => l.name).join(', ')} {unusedLists.length === 1 ? 'steckt' : 'stecken'} in keinem aktiven Profil und {unusedLists.length === 1 ? 'wirkt' : 'wirken'} nicht.</span>
          {#each (globalProfiles.length ? globalProfiles : activeProfiles).filter((p) => p.enabled).slice(0, 2) as p}
            <button class="btn sm" onclick={() => addUnusedTo(p)}>In „{p.name}“ aufnehmen</button>
          {/each}
        </div>
      {/if}
    </div>
  </div>

  {#if stats}
    <div class="grid cols-4 kpis">
      <div class="card card-pad"><div class="muted tiny">Anfragen</div><div class="kpi">{fmtNum(stats.total)}</div></div>
      <div class="card card-pad"><div class="muted tiny">Gesperrt</div><div class="kpi bad-text">{fmtNum(stats.blocked)} <span class="tiny muted">{pct(stats.blocked, stats.total)} %</span></div></div>
      <div class="card card-pad"><div class="muted tiny">Aus dem Speicher</div><div class="kpi">{pct(stats.cached, stats.total)} %</div></div>
      <div class="card card-pad"><div class="muted tiny">Ø Antwortzeit (aufgelöst)</div><div class="kpi">{fmtNum(Math.round(stats.avg_ms))} ms</div></div>
    </div>

    <div class="card card-pad" style="margin-top:14px">
      <div class="row" style="gap:14px;margin-bottom:8px">
        <strong class="small">Anfragen je {hours > 24 * 7 ? `${Math.ceil(hours / 168)} Stunden` : 'Stunde'}</strong>
        <span class="tiny muted"><span class="sw"></span> aufgelöst <span class="sw bl"></span> gesperrt</span>
      </div>
      <div class="bars">
        {#each bars as b}
          <div class="bar" title="{day(b.ts)} {clock(b.ts).slice(0, 5)} – {fmtNum(b.tot)} Anfragen, {fmtNum(b.bl)} gesperrt">
            <div class="fill" style="height:{(b.tot / maxBar) * 100}%"><div class="blk" style="height:{b.tot ? (b.bl / b.tot) * 100 : 0}%"></div></div>
          </div>
        {/each}
      </div>
      {#if !stats.total}<div class="muted small" style="margin-top:8px">Im gewählten Zeitraum keine Anfragen protokolliert.</div>{/if}
    </div>

    <div class="grid cols-3" style="margin-top:14px">
      {#each [['Häufigste Domains', stats.top_domains, false], ['Am häufigsten gesperrt', stats.top_blocked, true]] as [title, rows, bl]}
        <div class="card">
          <div class="card-head"><h3>{title}</h3></div>
          <div class="toplist">
            {#each rows as r}
              <div class="toprow">
                <span class="mono tiny ellipsis grow" title={r.name}>{r.name}</span>
                <span class="tiny muted">{fmtNum(r.count)}</span>
                <button class="btn sm icon ghost" title={bl ? 'Freigeben' : 'Sperren'} onclick={() => openQuick(r.name, bl)}><Icon name={bl ? 'check' : 'lock'} size={13} /></button>
              </div>
            {:else}
              <div class="muted small" style="padding:12px 14px">Noch nichts.</div>
            {/each}
          </div>
        </div>
      {/each}
      <div class="card">
        <div class="card-head"><h3>Geräte</h3></div>
        <div class="toplist">
          {#each stats.top_clients as r}
            <button class="toprow linkrow" onclick={() => {
              filter = { q: '', peer: r.peer_id, action: '' };
              go('/dns/log');
            }}>
              <span class="small ellipsis grow">{peerLabel(r.peer_id)}</span>
              <span class="tiny muted">{fmtNum(r.count)}{#if r.blocked}&nbsp;· <span class="bad-text">{fmtNum(r.blocked)} gesperrt</span>{/if}</span>
            </button>
          {:else}
            <div class="muted small" style="padding:12px 14px">Noch nichts.</div>
          {/each}
        </div>
      </div>
    </div>

    <div class="grid cols-4 kpis" style="margin-top:14px">
      <div class="card card-pad"><div class="muted tiny">Verschiedene Domains</div><div class="kpi">{fmtNum(stats.domains || 0)}</div><div class="tiny muted">von {fmtNum(stats.clients || 0)} {stats.clients === 1 ? 'Gerät' : 'Geräten'}</div></div>
      <div class="card card-pad"><div class="muted tiny">Antwortzeit Median / 95 % <Info title="Antwortzeit" text="Nur Anfragen, die das Panel bei einem DNS-Server nachfragen musste. 95 % = so schnell waren 95 von 100 Antworten." /></div><div class="kpi">{fmtNum(stats.p50 || 0)} <span class="tiny muted">/ {fmtNum(stats.p95 || 0)} ms</span></div></div>
      <div class="card card-pad"><div class="muted tiny">„Gibt es nicht“ (NXDOMAIN) <Info title="NXDOMAIN" text="Namen, die es nicht gibt (Tippfehler, abgeschaltete Dienste, Suchanfragen von Geräten). Gesperrte Namen zählen hier nicht mit." /></div><div class="kpi">{pct(stats.nxdomain || 0, stats.total)} %</div><div class="tiny muted">{fmtNum(stats.nxdomain || 0)} Anfragen</div></div>
      <div class="card card-pad"><div class="muted tiny">Fehler (keine Antwort, SERVFAIL)</div><div class="kpi" class:bad-text={stats.errors + (stats.servfail || 0) > 0}>{pct(stats.errors + (stats.servfail || 0), stats.total)} %</div><div class="tiny muted">{fmtNum(stats.errors)} ohne Antwort · {fmtNum(stats.servfail || 0)} SERVFAIL</div></div>
    </div>

    <div class="grid cols-3" style="margin-top:14px">
      <div class="card">
        <div class="card-head"><h3>Abfragetypen <Info title="Abfragetypen" text="A = IPv4-Adresse, AAAA = IPv6-Adresse, HTTPS/SVCB = Verbindungshinweise für Browser, PTR = Rückwärtsauflösung, TXT/SRV = Dienstinfos." /></h3></div>
        <div class="toplist">
          {#each stats.qtypes || [] as r}
            <div class="toprow"><span class="small grow">{QTYPE[r.name] || `Typ ${r.name}`}</span><span class="share"><span style="width:{pct(r.count, stats.total)}%"></span></span><span class="tiny muted num">{pct(r.count, stats.total)} %</span></div>
          {:else}<div class="muted small" style="padding:12px 14px">Noch nichts.</div>{/each}
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Sperrgründe</h3></div>
        <div class="toplist">
          {#each stats.reasons || [] as r}
            <div class="toprow"><span class="small ellipsis grow" title={r.name}>{r.name || 'unbekannt'}</span><span class="tiny muted">{fmtNum(r.count)}</span></div>
          {:else}<div class="muted small" style="padding:12px 14px">Nichts gesperrt.</div>{/each}
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Weg der Anfragen <Info title="Weg" text="Direkt = über die DNS-Server des Panels (bzw. Unbound). Gruppe = Ziel-Regel: Der Name wurde über die Ausgangsgruppe aufgelöst." /></h3></div>
        <div class="toplist">
          {#each stats.via || [] as r}
            <div class="toprow"><span class="small ellipsis grow">{r.peer_id ? `Gruppe „${groupById[r.peer_id]?.name || r.peer_id}“` : 'direkt'}</span><span class="share"><span style="width:{pct(r.count, stats.total)}%"></span></span><span class="tiny muted num">{pct(r.count, stats.total)} %</span></div>
          {:else}<div class="muted small" style="padding:12px 14px">Noch nichts.</div>{/each}
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>DNS-Server <Info title="DNS-Server im Zeitraum" text="Welcher DNS-Server die nicht zwischengespeicherten Anfragen beantwortet hat (aus dem Protokoll), mit mittlerer Antwortzeit. Gesperrte und gespeicherte Antworten fragen keinen Server." /></h3></div>
        <div class="toplist">
          {#each stats.upstreams || [] as r}
            {@const all = stats.upstreams.reduce((a, x) => a + x.count, 0)}
            <div class="toprow" title={r.name}><span class="small ellipsis grow">{srvName(r.name)}{#if srvName(r.name) !== srvHost(r.name)}&nbsp;<span class="mono tiny muted">{srvHost(r.name)}</span>{/if}</span><span class="share"><span style="width:{pct(r.count, all)}%"></span></span><span class="tiny muted num">{pct(r.count, all)} %</span><span class="tiny muted num">{r.ms} ms</span></div>
          {:else}<div class="muted small" style="padding:12px 14px">Noch nichts protokolliert.</div>{/each}
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Namen ohne Antwort <Info title="NXDOMAIN" text="Häufig gefragte Namen, die es nicht gibt – oft Geräte, die nach abgeschalteten Diensten suchen, oder Tippfehler in eigenen Regeln." /></h3></div>
        <div class="toplist">
          {#each stats.top_nx || [] as r}
            <div class="toprow"><span class="mono tiny ellipsis grow" title={r.name}>{r.name}</span><span class="tiny muted">{fmtNum(r.count)}</span></div>
          {:else}<div class="muted small" style="padding:12px 14px">Keine.</div>{/each}
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Meiste Sperren je Gerät</h3></div>
        <div class="toplist">
          {#each stats.blocked_by || [] as r}
            <button class="toprow linkrow" onclick={() => {
              filter = { q: '', peer: r.peer_id, action: 'blocked' };
              go('/dns/log');
            }}><span class="small ellipsis grow">{peerLabel(r.peer_id)}</span><span class="tiny bad-text">{fmtNum(r.count)}</span></button>
          {:else}<div class="muted small" style="padding:12px 14px">Nichts gesperrt.</div>{/each}
        </div>
      </div>
    </div>
  {/if}

  <div class="card card-pad" style="margin-top:14px">
    <div style="margin-bottom:8px"><strong class="small">Domain prüfen</strong> <Info title="Domain prüfen" text="Zeigt, was der Panel-DNS für ein Gerät mit einem Namen machen würde – ohne ihn aufzulösen: Profil, Sperre oder Freigabe und den Weg." /></div>
    <div class="row wrap" style="gap:8px">
      <Picker items={peerPick} bind:value={check.peer} placeholder="Gerät suchen …" width="300px" />
      <input class="input mono grow" style="min-width:200px" placeholder="werbung.de" bind:value={check.name} onkeydown={(e) => e.key === 'Enter' && runCheck()} />
      <button class="btn" onclick={runCheck} disabled={!Number(check.peer) || !check.name}><Icon name="search" size={15} /> Prüfen</button>
    </div>
    {#if checkRes}
      <div class="notice {checkRes.action === 'blocked' ? 'bad' : checkRes.action === 'rewritten' ? '' : 'okn'} small" style="margin-top:10px">
        <Icon name={ACTION[checkRes.action]?.[1] || 'info'} size={16} />
        <span>
          <strong>{checkRes.action === 'blocked' ? 'Gesperrt' : checkRes.action === 'rewritten' ? 'Eigene Antwort' : 'Wird aufgelöst'}</strong>
          {#if checkRes.detail}&nbsp;– {checkRes.detail}{/if}
          {#if checkRes.device}
            {#if checkRes.action === 'ok'}&nbsp;· Weg: {checkRes.via ? `Ausgangsgruppe „${groupById[checkRes.via]?.name || checkRes.via}“` : 'direkt über den Server'}{/if}
            <br /><span class="muted">Profil: {checkRes.profile || 'keins (nichts gefiltert)'} · verschlüsseltes DNS {checkRes.doh ? 'gesperrt' : 'erlaubt'}</span>
          {/if}
        </span>
      </div>
    {/if}
  </div>
{:else if tab === 'log'}
  <div class="row wrap" style="gap:8px;margin-bottom:12px">
    <input class="input grow" style="min-width:180px" placeholder="Domain suchen …" bind:value={filter.q} />
    <Picker items={peerPick} bind:value={filter.peer} none="Alle Geräte" width="280px" />
    <select class="input" style="width:auto" bind:value={filter.action}>
      <option value="">Alle Ergebnisse</option>
      <option value="ok">aufgelöst</option>
      <option value="blocked">gesperrt</option>
      <option value="rewritten">eigene Antwort</option>
      <option value="error">Fehler</option>
    </select>
    <label class="switch small"><input type="checkbox" bind:checked={live} /><span class="track"></span> Live</label>
  </div>
  {#if d.settings.log_days === '0'}
    <div class="notice small"><Icon name="info" size={16} /><span>Das Protokoll ist ausgeschaltet (Einstellungen).</span></div>
  {/if}
  <div class="card table-wrap">
    <table class="table log">
      <thead><tr><th>Zeit</th><th>Gerät</th><th>Domain</th><th>Typ</th><th>Ergebnis</th><th class="right">ms</th><th></th></tr></thead>
      <tbody>
        {#each entries as en (en.id)}
          {@const a = ACTION[en.action] || ACTION.ok}
          <tr>
            <td class="nowrap tiny muted" title={new Date(en.ts * 1000).toLocaleString('de-DE')}>{clock(en.ts)}</td>
            <td class="small nowrap ellipsis devcell" title={en.client}>{peerLabel(en.peer_id)}</td>
            <td class="mono tiny namecell" title={en.name}>{en.name}</td>
            <td class="tiny muted">{QTYPE[en.qtype] || en.qtype}</td>
            <td>
              <span class="badge {a[0]}" title={en.detail}><Icon name={a[1]} size={12} /> {a[2]}</span>
              {#if en.via}<span class="badge accent" title="über Ausgangsgruppe"><Icon name="route" size={12} /> {groupById[en.via]?.name || en.via}</span>{/if}
              {#if en.detail && en.action !== 'ok' && en.action !== 'cached'}<div class="tiny muted detail">{en.detail}</div>{/if}
            </td>
            <td class="right tiny muted nowrap" title={en.upstream ? `beantwortet von ${en.upstream}` : ''}>{en.action === 'cached' || en.action === 'blocked' ? '' : en.ms}{#if en.upstream}<div class="tiny muted">{srvName(en.upstream)}</div>{/if}</td>
            <td class="right nowrap">
              {#if en.action === 'blocked'}
                <button class="btn sm ghost" title="Freigeben" onclick={() => openQuick(en.name, true)}><Icon name="check" size={13} /></button>
              {:else}
                <button class="btn sm ghost" title="Sperren" onclick={() => openQuick(en.name, false)}><Icon name="lock" size={13} /></button>
              {/if}
            </td>
          </tr>
        {:else}
          <tr><td colspan="7" class="muted small" style="padding:20px">Keine Einträge.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if more}<div style="text-align:center;margin-top:10px"><button class="btn" onclick={() => loadLog(true)}>Ältere laden</button></div>{/if}
{:else if tab === 'external'}
  <DNSExternal onchange={load} />
{:else if tab === 'profiles'}
  <div class="grid cols-2">
    {#each d.profiles as p}
      <div class="card lst" class:off={!p.enabled}>
        <div class="card-head">
          <div>
            <h3>{p.name}</h3>
            <div class="muted tiny">{p.lists.length} {p.lists.length === 1 ? 'Liste' : 'Listen'} · {ruleCount(p.rules)} eigene Regeln{#if p.nxdomain}&nbsp;· Antwort „gibt es nicht“{/if}</div>
          </div>
          {#if p.block_doh}<span class="badge accent" title="Verschlüsseltes DNS (DoH/DoT) der Geräte wird gesperrt"><Icon name="lock" size={12} /> DoH gesperrt</span>{/if}
        </div>
        <div class="card-pad stack" style="gap:10px">
          {#if p.error}<div class="notice bad small"><Icon name="alert" size={16} /><span>{p.error}</span></div>{/if}
          <div class="row wrap" style="gap:6px">
            {#each p.assign as a}
              {@const [ic, label] = assignLabel(a)}
              <span class="badge"><Icon name={ic} size={12} /> {label}</span>
            {:else}
              <span class="muted small">Noch keinem Gerät zugeordnet</span>
            {/each}
          </div>
          {#if p.smart?.length}
            <div class="row wrap" style="gap:6px">
              {#each p.smart as sr}
                <span class="badge accent" title={sr.domains.join(', ')}><Icon name="route" size={12} /> {sr.domains.slice(0, 2).join(', ')}{sr.domains.length > 2 ? ` +${sr.domains.length - 2}` : ''} → {groupById[sr.group]?.name || `Gruppe #${sr.group}`}</span>
              {/each}
            </div>
          {/if}
          <div class="row wrap" style="gap:6px">
            {#each p.lists as id}
              {@const l = d.lists.find((x) => x.id === id)}
              {#if l}<span class="badge {l.mode === 'allow' ? 'ok' : 'bad'}"><Icon name={l.mode === 'allow' ? 'check' : 'filter'} size={12} /> {l.name}</span>{/if}
            {/each}
          </div>
        </div>
        <div class="actions">
          <button class="btn sm" onclick={() => openProfile(p)}><Icon name="edit" size={15} /> Bearbeiten</button>
          <button class="btn sm ghost" onclick={() => toggleProfile(p)}><Icon name="power" size={15} /> {p.enabled ? 'Deaktivieren' : 'Aktivieren'}</button>
          <span class="grow"></span>
          <button class="btn sm icon ghost danger" title="Löschen" onclick={() => removeProfile(p)}><Icon name="trash" size={15} /></button>
        </div>
      </div>
    {/each}
  </div>
  {#if loaded && !d.profiles.length}
    <div class="card empty">
      <h3>Noch kein Filterprofil</h3>
      <p>Ohne Profil löst der Panel-DNS nur auf und protokolliert. Lege ein Profil „Standard“ für alle Geräte an und wähle Blocklisten dazu.</p>
      <button class="btn primary" onclick={() => openProfile()}>Profil anlegen</button>
    </div>
  {/if}
  <div class="row infoline"><Info title="Welches Profil gilt?" text="Für jedes Gerät gilt genau ein Profil: das am Gerät, sonst das des Nutzers, sonst das des Servers, sonst das für alle Geräte. Gelten auf einer Ebene mehrere, gewinnt das ältere." label="Welches Profil gilt?" /></div>
{:else if tab === 'lists'}
  <div class="grid cols-2">
    {#each d.lists as l}
      <div class="card lst" class:off={!l.enabled}>
        <div class="card-head">
          <div>
            <h3>{l.name}</h3>
            <div class="muted tiny">{fmtNum(l.total)} Domains{#if l.url && l.entries.length}&nbsp;({fmtNum(l.entries.length)} eigene){/if}</div>
          </div>
          <span class="badge {l.mode === 'allow' ? 'ok' : 'bad'}"><Icon name={l.mode === 'allow' ? 'check' : 'lock'} size={13} /> {l.mode === 'allow' ? 'Freigaben' : 'Sperren'}</span>
        </div>
        <div class="card-pad stack" style="gap:8px">
          {#if l.url}
            <div class="row" style="gap:6px"><Icon name="globe" size={14} /><span class="mono tiny url" title={l.url}>{l.url}</span></div>
            <div class="tiny" class:bad-text={l.status?.error}>
              {#if l.status?.error}
                <Icon name="alert" size={12} /> {l.status.error}{#if l.status.at}&nbsp;– Stand von {when(l.status.at)} bleibt aktiv{/if}
              {:else if l.status?.at}
                <span class="muted">Geladen {when(l.status.at)} · {fmtNum(l.status.count)} Domains{l.status.skipped ? ` · ${fmtNum(l.status.skipped)} Zeilen übersprungen` : ''} · {refreshText(l.refresh)}</span>
              {:else}
                <span class="muted">Wird geladen …</span>
              {/if}
            </div>
          {/if}
          {#if l.used_by.length}
            <div class="tiny muted">In {l.used_by.join(', ')}</div>
          {:else}
            <div class="tiny warn-t row" style="gap:6px"><Icon name="alert" size={12} /> In keinem Filterprofil – wirkt nicht <button class="btn sm ghost" onclick={() => openList(l)}>Profil wählen</button></div>
          {/if}
        </div>
        <div class="actions">
          <button class="btn sm" onclick={() => openList(l)}><Icon name="edit" size={15} /> Bearbeiten</button>
          <button class="btn sm ghost" onclick={() => toggleDNSList(l)}><Icon name="power" size={15} /> {l.enabled ? 'Deaktivieren' : 'Aktivieren'}</button>
          {#if l.url}<button class="btn sm ghost" onclick={() => refreshList(l)} disabled={busy === l.id}><Icon name="refresh" size={15} /> {busy === l.id ? 'Lädt …' : 'Neu laden'}</button>{/if}
          <span class="grow"></span>
          <button class="btn sm icon ghost danger" title="Löschen" onclick={() => removeList(l)}><Icon name="trash" size={15} /></button>
        </div>
      </div>
    {/each}
  </div>
  <div class="card" style="margin-top:16px">
    <div class="card-head"><h3>Bekannte Listen <Info title="Blocklisten">
      <p>Listen lädt der Server regelmäßig neu – Hosts-Dateien, Adblock-Listen („||domain^“, Ausnahmen „@@“) oder eine Domain pro Zeile.</p>
      <p>Eine Domain sperrt auch alle Unterdomains. Schlägt ein Abruf fehl, bleibt der letzte Stand aktiv.</p>
      <p>Damit eine Liste wirkt, muss sie in einem Filterprofil gewählt sein.</p>
    </Info></h3></div>
    <div class="toplist">
      {#each d.presets as pr}
        <div class="toprow">
          <div class="grow">
            <div class="small strong">{pr.name}</div>
            <div class="tiny muted">{pr.note}</div>
          </div>
          {#if usedPresets.has(pr.url)}
            <span class="badge ok"><Icon name="check" size={12} /> hinzugefügt</span>
          {:else}
            <button class="btn sm" onclick={() => openList(null, pr)}><Icon name="plus" size={14} /> Hinzufügen</button>
          {/if}
        </div>
      {/each}
    </div>
  </div>
{:else if tab === 'settings' && sf}
  <div class="card card-pad stack" style="max-width:760px">
    <div class="row" style="gap:6px">
      <label class="switch"><input type="checkbox" bind:checked={sf.enabled} /><span class="track"></span> Panel-DNS für WireGuard- und OpenVPN-Geräte</label>
      <Info title="Panel-DNS">
        <p>DNS-Anfragen dieser Geräte gehen an das Panel – egal, welchen DNS-Server das Gerät eingetragen hat. Configs mit DNS „auto“ (Vorgabe) nennen die Tunneladresse des Servers.</p>
        <p>Bei bestehenden Geräten mit eigenem DNS-Eintrag (z. B. 1.1.1.1) schalten Browser gern auf verschlüsseltes DNS um – dann die Config neu herunterladen bzw. den DNS des Servers auf „auto“ stellen.</p>
      </Info>
    </div>
    <div class="field">
      <span class="label"
        >Auflösung <Info title="Wer löst die Namen auf?" wide>
          <p><b>Öffentliche DNS-Server</b> (z. B. Cloudflare, Quad9): schnell, weil sie fast alles schon im Speicher haben – der Anbieter sieht aber alle Namen, die der Server nachfragt.</p>
          <p><b>Unbound</b> läuft auf dem Server selbst und fragt die zuständigen Nameserver direkt (rekursiv, mit DNSSEC-Prüfung). Kein Anbieter sieht die Anfragen gesammelt; der erste Abruf eines Namens dauert etwas länger, danach antwortet der Speicher. Die DNS-Server unten springen ein, falls Unbound nicht antwortet.</p>
          <p>Für Ziel-Regeln gelten weiter die DNS-Server der Ausgangsgruppe.</p>
        </Info></span
      >
      <div class="segmented">
        <button class:active={sf.resolver === 'upstream'} onclick={() => (sf.resolver = 'upstream')}>Öffentliche DNS-Server</button>
        <button class:active={sf.resolver === 'unbound'} onclick={() => (sf.resolver = 'unbound')}>Unbound (selbst auflösen)</button>
      </div>
      {#if sf.resolver === 'unbound' && !d.unbound_installed}
        <div class="notice warn small" style="margin-top:6px"><Icon name="alert" size={16} /><span>Unbound ist auf dem Server nicht installiert. Das Setup-Script installiert das Paket „unbound“ – bis dahin fragt das Panel die DNS-Server unten.</span></div>
      {/if}
    </div>
    <div class="field">
      <label for="dns-up">{sf.resolver === 'unbound' ? 'Ersatz-DNS-Server (falls Unbound nicht antwortet)' : 'DNS-Server für die Auflösung'} <Info title="DNS-Server" text="Fragt das Panel für Namen ohne Ziel-Regel. Für Ziel-Regeln gelten die DNS-Server der Ausgangsgruppe. Die automatische Wahl (unten) kann diese Liste selbst anpassen." /></label>
      <input id="dns-up" class="input mono" bind:value={sf.upstream} placeholder="1.1.1.1, 9.9.9.9" />
    </div>
    <div class="field">
      <label for="dns-days">Protokoll aufbewahren <Info title="Protokoll" text="Jede Anfrage mit Gerät, Domain und Ergebnis. Ältere Einträge löscht der Server stündlich." /></label>
      <select id="dns-days" class="input" style="width:auto" bind:value={sf.log_days}>
        <option value={0}>nicht protokollieren</option>
        {#each [1, 3, 7, 14, 30, 90] as n}<option value={n}>{n} {n === 1 ? 'Tag' : 'Tage'}</option>{/each}
        {#if ![0, 1, 3, 7, 14, 30, 90].includes(Number(sf.log_days))}<option value={sf.log_days}>{sf.log_days} Tage</option>{/if}
      </select>
    </div>
    <div class="field">
      <span class="label"
        >Verteilung auf die DNS-Server <Info title="Verteilung" wide>
          <ul>{#each STRATEGY as [, l, t]}<li><b>{l}:</b> {t}</li>{/each}</ul>
          <p>Gilt auch für die DNS-Server der Ausgangsgruppen.</p>
        </Info></span
      >
      <div class="segmented">
        {#each STRATEGY as [k, l, t]}<button class:active={sf.strategy === k} title={t} onclick={() => (sf.strategy = k)}>{l}</button>{/each}
      </div>
      {#if d.upstreams?.length}
        <div class="tiny muted" style="margin-top:6px">
          Gemessen seit dem Start:
          {#each d.upstreams as u, i}{i ? ' · ' : ' '}<span class="mono">{srvName(u.server)}</span> {u.ms} ms{u.fail ? ` (${u.fail} Ausfälle)` : ''}{/each}
        </div>
      {/if}
    </div>
    <h4 class="sub-h">Zwischenspeicher</h4>
    <div class="grid cols-3">
      <div class="field">
        <label for="dns-cs">Größe <Info title="Größe" text="So viele Antworten merkt sich das Panel (eine Antwort ≈ 0,2–0,5 KB Arbeitsspeicher). 0 = aus – jede Anfrage geht an die DNS-Server." /></label>
        <select id="dns-cs" class="input" bind:value={sf.cache_size}>
          {#each CACHES as [v, l]}<option value={v}>{l}</option>{/each}
          {#if !CACHES.some((c) => c[0] === Number(sf.cache_size))}<option value={sf.cache_size}>{sf.cache_size} Antworten</option>{/if}
        </select>
      </div>
      <div class="field">
        <label for="dns-tmin">Mindestens merken <Info title="Mindestdauer" text="Manche Dienste geben sehr kurze Gültigkeiten an (z. B. 20 s). Eine Mindestdauer spart Anfragen, kann bei Umzügen aber kurz veraltete Adressen liefern." /></label>
        <select id="dns-tmin" class="input" bind:value={sf.ttl_min} disabled={!Number(sf.cache_size)}>
          {#each TTLS.slice(0, 6) as [v, l]}<option value={v}>{l}</option>{/each}
          {#if !TTLS.some((t) => t[0] === Number(sf.ttl_min))}<option value={sf.ttl_min}>{sf.ttl_min} s</option>{/if}
        </select>
      </div>
      <div class="field">
        <label for="dns-tmax">Höchstens merken <Info title="Höchstdauer" text="Auch wenn ein Server längere Gültigkeiten angibt, fragt das Panel spätestens nach dieser Zeit neu." /></label>
        <select id="dns-tmax" class="input" bind:value={sf.ttl_max} disabled={!Number(sf.cache_size)}>
          {#each TTLS.slice(2) as [v, l]}<option value={v}>{l}</option>{/each}
          {#if !TTLS.some((t) => t[0] === Number(sf.ttl_max))}<option value={sf.ttl_max}>{sf.ttl_max} s</option>{/if}
        </select>
      </div>
    </div>
    <div class="field">
      <label for="dns-nc">Nie zwischenspeichern <Info title="Ohne Zwischenspeicher" text="Diese Domains (mit Unterdomains) fragt das Panel jedes Mal neu – z. B. DynDNS-Namen oder Lastverteiler. Eine pro Zeile." /></label>
      <textarea id="dns-nc" class="input mono" rows="3" bind:value={sf.nocache} placeholder="meinname.ddns.net"></textarea>
    </div>
    <div><button class="btn primary" onclick={saveSettings}>Speichern</button></div>
  </div>

  <div class="card" style="max-width:760px;margin-top:14px">
    <div class="card-head">
      <h3>
        DNS-Speedtest
        <Info title="DNS-Speedtest" wide>
          <p>Misst vom Server aus (nicht über Ausgangsgruppen) die eingestellten und bekannte öffentliche DNS-Server:</p>
          <ul>
            <li><b>Bekannte Namen:</b> Median über 24 Anfragen nach beliebten Domains – meist aus dem Speicher des Anbieters, also vor allem die Wegzeit.</li>
            <li><b>Neue Namen:</b> zufällige Unterdomains, die der Anbieter erst selbst nachfragen muss.</li>
          </ul>
          <p>Das Panel speichert Antworten selbst zwischen – nach dem ersten Abruf zählt vor allem, wie schnell und zuverlässig neue Namen kommen.</p>
          <p><b>Unbound</b> (eigener rekursiver Resolver) fragt ohne Anbieter direkt die zuständigen Server: mehr Privatsphäre, aber der erste Abruf eines Namens dauert länger. Läuft Unbound z. B. auf 127.0.0.1:5335, rechts als weiteren Server eintragen, testen und oben als DNS-Server übernehmen.</p>
        </Info>
      </h3>
      <button class="btn" onclick={runSpeed} disabled={speedBusy}><Icon name="gauge" size={15} /> {speedBusy ? 'Misst … (bis ~20 s)' : 'Testen'}</button>
    </div>
    <div class="card-pad stack" style="gap:8px;padding-top:0">
      <div class="small"><strong>Getestete Server</strong> <span class="muted">({cands.length}{d.settings.candidates_custom ? ', eigene Liste' : ', eingebaute Liste'})</span> <Info title="Liste" text="Diese Server misst der Speedtest und aus ihnen wählt die Automatik. Die eingestellten DNS-Server und Unbound (falls installiert) werden immer mitgemessen." /></div>
      <div class="cands">
        {#each cands as c (c.addr)}
          <span class="chip" title={c.addr}>{c.name}{#if c.name !== c.addr}&nbsp;<span class="mono tiny muted">{c.addr}</span>{/if}<button type="button" title="Aus der Liste entfernen" onclick={() => dropCand(c.addr)} disabled={cands.length < 2}><Icon name="x" size={12} /></button></span>
        {/each}
      </div>
      <div class="row wrap" style="gap:8px">
        <input class="input mono" style="width:180px" bind:value={newCand.addr} placeholder="IP, z. B. 9.9.9.10" onkeydown={(e) => e.key === 'Enter' && addCand()} />
        <input class="input" style="width:180px" bind:value={newCand.name} placeholder="Name (optional)" onkeydown={(e) => e.key === 'Enter' && addCand()} />
        <button class="btn sm" onclick={addCand} disabled={!newCand.addr.trim()}><Icon name="plus" size={14} /> Hinzufügen</button>
        {#if d.settings.candidates_custom}<button class="btn sm ghost" onclick={resetCands}>Eingebaute Liste</button>{/if}
      </div>
    </div>
    {#if speed}
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Server</th><th class="right">Bekannte Namen</th><th class="right">Neue Namen</th><th class="right">Antworten</th><th></th></tr></thead>
          <tbody>
            {#each speed as x, i}
              <tr class:best={i < 2 && x.ok}>
                <td>
                  <span class="strong">{x.name}</span> <span class="mono tiny muted">{x.addr}</span>
                  {#if x.current}<span class="badge accent">eingestellt</span>{/if}
                  {#if x.note}<div class="tiny muted">{x.note}</div>{/if}
                </td>
                <td class="right">{x.ok ? `${x.median} ms` : '–'}</td>
                <td class="right">{x.ok ? `${x.uncached} ms` : '–'}</td>
                <td class="right" class:bad-text={x.ok < x.total}>{x.ok ? `${x.ok}/${x.total}` : 'keine'}</td>
                <td class="right">{#if candSet.has(x.addr) && !isLocal(x.addr)}<button class="btn sm icon ghost" title="Aus der Liste entfernen" onclick={() => dropCand(x.addr)}><Icon name="trash" size={13} /></button>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="row card-pad" style="gap:8px">
        <span class="small muted grow">Oben stehen die schnellsten. „Übernehmen“ trägt sie oben als DNS-Server ein – danach speichern.</span>
        <button class="btn sm" onclick={() => useServers(2)}>Die 2 schnellsten übernehmen</button>
        <button class="btn sm" onclick={() => useServers(3)}>Die 3 schnellsten</button>
      </div>
    {:else}
      <div class="card-pad muted small" style="padding-top:0">Noch nicht gemessen.</div>
    {/if}
  </div>

  <div class="card card-pad stack" style="max-width:760px;margin-top:14px">
    <div class="row" style="gap:6px">
      <label class="switch"><input type="checkbox" bind:checked={sf.auto} /><span class="track"></span> Schnellste DNS-Server automatisch wählen</label>
      <Info title="Automatische Wahl" wide>
        <p>Der Server misst regelmäßig alle Server der Liste (wie der Speedtest) und trägt die schnellsten als DNS-Server ein.</p>
        <p>Gewechselt wird nur, wenn die neue Auswahl mindestens 15 % schneller ist oder ein eingestellter Server nicht zuverlässig antwortet – kleine Messschwankungen führen nicht zu ständigem Umschalten. Jeder Wechsel steht im Ereignisprotokoll.</p>
        <p>Mit Unbound gilt die Wahl für die Ersatz-Server.</p>
      </Info>
    </div>
    <div class="row wrap" style="gap:10px">
      <select class="input" style="width:auto" bind:value={sf.auto_hours} disabled={!sf.auto}>
        {#each HOURS as [v, l]}<option value={v}>{l} prüfen</option>{/each}
      </select>
      <select class="input" style="width:auto" bind:value={sf.auto_count} disabled={!sf.auto}>
        {#each [1, 2, 3, 4] as n}<option value={n}>die {n === 1 ? 'schnellste' : `${n} schnellsten`} übernehmen</option>{/each}
      </select>
      <button class="btn" onclick={saveSettings}>Speichern</button>
      <button class="btn ghost" onclick={autoNow} disabled={autoBusy}><Icon name="refresh" size={14} /> {autoBusy ? 'Misst …' : 'Jetzt prüfen'}</button>
    </div>
    {#if d.auto_last}
      {@const a = d.auto_last}
      <div class="notice {a.changed ? 'okn' : ''} small">
        <Icon name={a.changed ? 'check' : 'info'} size={16} />
        <span
          >Zuletzt {when(a.at)}: {a.reason}{#if a.chosen?.length}&nbsp;– {a.changed ? 'jetzt' : 'beste'}: <span class="mono">{a.chosen.join(', ')}</span>{/if}{#if a.best_ms}&nbsp;(Ø {a.best_ms} ms{a.old_ms ? `, vorher ${a.old_ms} ms` : ''}){/if}</span
        >
      </div>
    {/if}
  </div>
{/if}

<Modal open={!!quick} onclose={() => (quick = null)} title={quick?.allow ? `${quick?.name} freigeben` : `${quick?.name} sperren`} width={480}>
  {#if quick}
    {#if d.profiles.length}
      <div class="field">
        <label for="q-prof">In Filterprofil <Info title="Regel" text="Fügt die Regel „{quick.allow ? 'allow ' : ''}{quick.name}“ hinzu (gilt auch für Unterdomains)." /></label>
        <select id="q-prof" class="input" bind:value={quickProfile}>
          {#each d.profiles as p}<option value={p.id}>{p.name}</option>{/each}
        </select>
      </div>
    {:else}
      <div class="notice warn small"><Icon name="alert" size={16} /><span>Es gibt noch kein Filterprofil – bitte zuerst eins anlegen.</span></div>
    {/if}
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (quick = null)}>Abbrechen</button>
    <button class="btn primary" onclick={applyQuick} disabled={!d.profiles.length}>{quick?.allow ? 'Freigeben' : 'Sperren'}</button>
  {/snippet}
</Modal>

<Modal bind:open={pOpen} title={pCur ? `Profil ${pCur.name}` : 'Filterprofil anlegen'} width={720}>
  <div class="stack">
    <div class="field"><label for="p-name">Name</label><input id="p-name" class="input" bind:value={pf.name} placeholder="z. B. Standard, Kinder, Ohne Filter" /></div>
    <div class="field">
      <span class="label">Gilt für <Info title="Suche" text="Suche nach Name, Gerät, Dienst (z. B. „WireGuard“), Server oder Adresse. Mehrere Wörter grenzen ein: „martin xiaomi wire“. Für jedes Gerät gilt genau ein Profil: Gerät vor Nutzer vor Server vor „Alle Geräte“." /></span>
      <div class="row wrap" style="gap:6px;margin:4px 0 8px">
        {#each pf.assign as a}
          {@const [ic, label, proto, sub] = assignLabel(a)}
          <span class="badge" title={sub}>
            {#if proto}<ProtoLogo id={proto} size={13} />{:else}<Icon name={ic} size={12} />{/if}
            {label}{#if sub && ic === 'phone'}<span class="muted">&nbsp;· {sub}</span>{/if}
            <button class="x" title="Entfernen" onclick={() => (pf.assign = pf.assign.filter((x) => x !== a))}><Icon name="x" size={11} /></button>
          </span>
        {:else}
          <span class="muted small">Noch niemandem – unten hinzufügen</span>
        {/each}
      </div>
      <Picker items={assignPick} keep={false} placeholder="Server, Nutzer oder Gerät suchen und hinzufügen …" onpick={addAssign} />
    </div>
    <div class="field">
      <span class="label">Blocklisten</span>
      <div class="srvs">
        {#each d.lists as l}
          <label class="srv">
            <input type="checkbox" checked={pf.lists.includes(l.id)} onchange={() => toggleList(l.id)} />
            <span class="grow">{l.name}</span>
            <span class="tiny muted">{fmtNum(l.total)} · {l.mode === 'allow' ? 'Freigaben' : 'Sperren'}</span>
          </label>
        {:else}
          <span class="muted small">Noch keine Blocklisten – unter „Blocklisten“ anlegen.</span>
        {/each}
      </div>
    </div>
    <div class="field">
      <label for="p-rules">Eigene Regeln <span class="muted">({ruleCount(pf.rules)})</span> <Info title="Eigene Regeln">
        <p>Eine Regel pro Zeile:</p>
        <ul><li><code>werbung.de</code> – sperren</li><li><code>allow cdn.beispiel.de</code> – freigeben (geht vor Listen)</li><li><code>nas.home = 192.168.1.10</code> – eigene Antwort</li></ul>
        <p>Unterdomains sind immer eingeschlossen. „#“ leitet einen Kommentar ein.</p>
      </Info></label>
      <textarea id="p-rules" class="input mono" rows="8" bind:value={pf.rules} placeholder={'werbung.de              # sperren\nallow cdn.beispiel.de   # freigeben (geht vor)\nnas.home = 192.168.1.10 # eigene Antwort'}></textarea>
    </div>
    <div class="field">
      <span class="label"
        >SmartDNS – Dienste über eine Ausgangsgruppe <Info title="SmartDNS" wide>
          <p>Die eingetragenen Domains (samt Unterdomains) laufen über die gewählte Ausgangsgruppe – z. B. Netflix über „USA“, der Rest bleibt direkt.</p>
          <p><b>VPN-Geräte</b> (WireGuard, OpenVPN, VLESS …): wirkt wie eine Ziel-Regel – der Verkehr zu diesen Zielen geht über den Ausgang der Gruppe, alle Ports.</p>
          <p><b>Geräte ohne VPN</b> (Fernseher, Konsole, DoH/DoT): Der Panel-DNS antwortet für diese Namen mit der Adresse des Servers; der Server reicht die HTTPS-Verbindung (Port 443) anhand des Namens über die Gruppe weiter. Die Verschlüsselung bleibt Ende-zu-Ende. Unverschlüsseltes HTTP (Port 80) und UDP/QUIC laufen so nicht – Apps weichen dann auf HTTPS aus.</p>
          <p>Damit Streamingdienste den Standort glauben, braucht es meist mehrere Domains (Anmeldung, Videoserver). Die Vorlagen enthalten die üblichen.</p>
        </Info></span
      >
      {#if !groupOpts.length}
        <div class="muted small">Noch keine Ausgangsgruppe – unter <a href="#/proxy/groups">Proxy & Ausgänge → Gruppen</a> anlegen.</div>
      {:else}
        {#each pf.smart as row, i}
          <div class="smartrow">
            <div class="row" style="gap:8px">
              <Icon name="route" size={15} />
              <select class="input" style="width:auto" bind:value={row.group}>
                {#each groupOpts as g}<option value={g.id}>{g.name}{g.enabled ? '' : ' (deaktiviert)'}</option>{/each}
              </select>
              <span class="tiny muted">{smartCount(row.domains)} Domains</span>
              <span class="grow"></span>
              <button class="btn sm icon ghost danger" title="Entfernen" onclick={() => (pf.smart = pf.smart.filter((_, j) => j !== i))}><Icon name="trash" size={14} /></button>
            </div>
            <textarea class="input mono" rows="3" bind:value={row.domains} placeholder={'netflix.com\nnflxvideo.net'}></textarea>
          </div>
        {/each}
        <div class="row wrap" style="gap:6px">
          <button class="btn sm" onclick={() => addSmart(null)}><Icon name="plus" size={13} /> Gruppe hinzufügen</button>
          <span class="tiny muted">Vorlage:</span>
          {#each SMART_PRESETS as pr}<button class="btn sm ghost" title={pr[1].replaceAll('\n', ', ')} onclick={() => addSmart(pr)}>{pr[0]}</button>{/each}
        </div>
      {/if}
    </div>
    <div class="row" style="gap:6px">
      <label class="switch"><input type="checkbox" bind:checked={pf.block_doh} /><span class="track"></span> Verschlüsseltes DNS der Geräte sperren (DoH/DoT)</label>
      <Info title="Verschlüsseltes DNS" text="Browser und Android („Privates DNS“) gehen sonst am Filter vorbei. Mit fest eingestelltem eigenem Anbieter (z. B. Brave „Sicheres DNS“ = Cloudflare) lädt dann keine Seite mehr – dort „automatisch“ oder „aus“ wählen." />
    </div>
    <label class="switch"><input type="checkbox" bind:checked={pf.nxdomain} /><span class="track"></span> Gesperrte Namen mit „gibt es nicht“ beantworten (statt 0.0.0.0)</label>
    <label class="switch"><input type="checkbox" bind:checked={pf.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (pOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveProfile} disabled={!pf.name}>{pCur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<Modal bind:open={lOpen} title={lCur ? `Liste ${lCur.name}` : 'Blockliste anlegen'} width={640}>
  <div class="stack">
    <div class="grid cols-2">
      <div class="field"><label for="l-name">Name</label><input id="l-name" class="input" bind:value={lf.name} /></div>
      <div class="field">
        <label for="l-mode">Art</label>
        <select id="l-mode" class="input" bind:value={lf.mode}>
          <option value="block">Sperren – diese Domains blockieren</option>
          <option value="allow">Freigeben – Ausnahmen für andere Listen</option>
        </select>
      </div>
    </div>
    <div class="field">
      <label for="l-url">Online-Liste <Info title="Online-Liste" text="Hosts-Datei, Adblock-Liste oder eine Domain pro Zeile, bis 1 000 000 Einträge. Der Server lädt sie im gewählten Abstand neu." /></label>
      <div class="row" style="gap:8px">
        <input id="l-url" class="input mono grow" bind:value={lf.url} placeholder="https://…/liste.txt" />
        <select class="input" style="width:auto" bind:value={lf.refresh} disabled={!lf.url}>
          {#each REFRESH as [h, label]}<option value={h}>{label}</option>{/each}
          {#if !REFRESH.some((r) => r[0] === lf.refresh)}<option value={lf.refresh}>alle {lf.refresh} Stunden</option>{/if}
        </select>
      </div>
    </div>
    <div class="field">
      <label for="l-entries">Eigene Einträge <span class="muted">(optional)</span></label>
      <textarea id="l-entries" class="input mono" rows="6" bind:value={lf.entries} placeholder={'werbung.example\ntracker.example'}></textarea>
    </div>
    <div class="field">
      <span class="label">Gilt in Filterprofil <Info title="Filterprofil" text="Eine Liste wirkt nur in einem Filterprofil. Das Profil bestimmt, für welche Geräte sie gilt (z. B. „Standard“ für alle Geräte)." /></span>
      {#if d.profiles.length}
        <div class="srvs">
          {#each d.profiles as p}
            <label class="srv">
              <input type="checkbox" checked={lf.profiles?.includes(p.id)} onchange={() => toggleLP(p.id)} />
              <span class="grow">{p.name}{p.enabled ? '' : ' (aus)'}</span>
              <span class="tiny muted">{p.assign.map((a) => assignLabel(a)[1]).slice(0, 3).join(', ') || 'niemandem zugeordnet'}</span>
            </label>
          {/each}
        </div>
        {#if !lf.profiles?.length}<div class="tiny warn-t" style="margin-top:6px">Ohne Profil wird die Liste nur geladen, sperrt aber nichts.</div>{/if}
      {:else}
        <label class="switch"><input type="checkbox" bind:checked={lf.mkStd} /><span class="track"></span> Profil „Standard“ für alle Geräte anlegen</label>
      {/if}
    </div>
    <label class="switch"><input type="checkbox" bind:checked={lf.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (lOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveList} disabled={!lf.name}>{lCur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
  .smartrow {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px;
    margin-bottom: 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .cands {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .cands .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 4px 1px 9px;
    font-size: 12px;
  }
  .cands .chip button {
    border: 0;
    background: none;
    cursor: pointer;
    color: var(--text-2);
    display: inline-flex;
    padding: 2px;
  }
  .cands .chip button:hover:not(:disabled) {
    color: var(--bad, #c33);
  }
  .infoline {
    margin-top: 14px;
  }
  .sub-h {
    margin: 6px 0 -4px;
    font-size: 14px;
  }
  tr.best td {
    background: var(--ok-soft);
  }
  .filtercard {
    margin-bottom: 14px;
  }
  .fline {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .linkbtn {
    border: none;
    background: none;
    padding: 0;
    font: inherit;
    color: var(--accent);
    cursor: pointer;
  }
  .warn-t {
    color: var(--warn, #b7791f);
  }
  .notice.okn {
    background: var(--ok-soft);
  }
  .kpi {
    font-size: 22px;
    font-weight: 650;
    margin-top: 2px;
  }
  .bad-text {
    color: var(--bad);
  }
  .bars {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 120px;
  }
  .bar {
    flex: 1;
    height: 100%;
    display: flex;
    align-items: flex-end;
    min-width: 2px;
  }
  .fill {
    width: 100%;
    background: var(--accent);
    opacity: 0.75;
    border-radius: 2px 2px 0 0;
    display: flex;
    flex-direction: column-reverse;
    overflow: hidden;
    min-height: 0;
  }
  .blk {
    background: var(--bad);
  }
  .sw {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 2px;
    background: var(--accent);
    margin: 0 3px 0 8px;
    vertical-align: -1px;
  }
  .sw.bl {
    background: var(--bad);
  }
  .toplist {
    display: flex;
    flex-direction: column;
  }
  .share {
    width: 80px;
    height: 6px;
    border-radius: 3px;
    background: var(--border);
    overflow: hidden;
    flex: none;
  }
  .share span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  .num {
    width: 44px;
    text-align: right;
  }
  .toprow {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-top: 1px solid var(--border);
    min-width: 0;
  }
  .linkrow {
    background: none;
    border-left: none;
    border-right: none;
    border-bottom: none;
    font: inherit;
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .linkrow:hover {
    background: var(--panel-2);
  }
  .log td {
    vertical-align: top;
  }
  .namecell {
    word-break: break-all;
    max-width: 380px;
  }
  .devcell {
    max-width: 200px;
  }
  .detail {
    margin-top: 2px;
    max-width: 320px;
  }
  .lst {
    display: flex;
    flex-direction: column;
  }
  .lst.off {
    opacity: 0.6;
  }
  .actions {
    display: flex;
    gap: 6px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    margin-top: auto;
  }
  .url {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .label {
    font-weight: 600;
    font-size: 13px;
  }
  .srvs {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 220px;
    overflow: auto;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin-top: 4px;
  }
  .srv {
    display: flex;
    gap: 8px;
    align-items: center;
    cursor: pointer;
  }
  .x {
    border: none;
    background: none;
    color: inherit;
    cursor: pointer;
    padding: 0;
    display: inline-flex;
    margin-left: 2px;
    opacity: 0.7;
  }
  .x:hover {
    opacity: 1;
  }
  textarea.input {
    resize: vertical;
    font-size: 12px;
  }
</style>
