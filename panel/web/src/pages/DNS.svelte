<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { ago, fmtNum } from '../lib/format.js';
  import { go } from '../lib/state.svelte.js';

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
    ['settings', 'Einstellungen', 'settings'],
  ];

  const peerById = $derived(Object.fromEntries(d.choices.peers.map((p) => [p.id, p])));
  const userById = $derived(Object.fromEntries(d.choices.users.map((u) => [u.id, u])));
  const srvById = $derived(Object.fromEntries(d.choices.servers.map((s) => [s.id, s])));
  const groupById = $derived(Object.fromEntries(d.choices.groups.map((g) => [g.id, g])));
  const dnsPeers = $derived(d.choices.peers.filter((p) => p.protocol === 'wireguard' || p.protocol === 'openvpn'));
  const peerLabel = (id) => {
    const p = peerById[id];
    if (!p) return id ? `Gerät #${id}` : 'unbekannt';
    return `${userById[p.user_id]?.name || '?'} · ${p.name}`;
  };
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
  let addKind = $state('user');
  let addId = $state(0);
  function openProfile(p = null) {
    pCur = p;
    pf = p
      ? { name: p.name, enabled: p.enabled, lists: [...p.lists], rules: p.rules, assign: [...p.assign], block_doh: p.block_doh, nxdomain: p.nxdomain }
      : { name: d.profiles.length ? '' : 'Standard', enabled: true, lists: d.lists.filter((l) => l.mode === 'block').map((l) => l.id), rules: '', assign: d.profiles.length ? [] : ['global'], block_doh: true, nxdomain: false };
    addKind = 'user';
    addId = 0;
    pOpen = true;
  }
  function toggleList(id) {
    pf.lists = pf.lists.includes(id) ? pf.lists.filter((x) => x !== id) : [...pf.lists, id];
  }
  function assignLabel(a) {
    if (a === 'global') return ['globe', 'Alle Geräte'];
    const [k, idText] = a.split(':');
    const id = Number(idText);
    if (k === 'server') return ['server', srvById[id]?.name || `Server #${id}`];
    if (k === 'user') return ['user', userById[id]?.name || `Nutzer #${id}`];
    return ['phone', peerLabel(id)];
  }
  const addOptions = $derived(addKind === 'server' ? d.choices.servers.filter((s) => s.protocol === 'wireguard' || s.protocol === 'openvpn') : addKind === 'user' ? d.choices.users : dnsPeers);
  function addAssign() {
    const v = addKind === 'global' ? 'global' : `${addKind}:${addId}`;
    if ((addKind === 'global' || Number(addId)) && !pf.assign.includes(v)) pf.assign = [...pf.assign, v];
    addId = 0;
  }
  async function saveProfile() {
    const body = $state.snapshot(pf);
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
  function openList(l = null, preset = null) {
    lCur = l;
    lf = l
      ? { name: l.name, enabled: l.enabled, mode: l.mode, url: l.url, refresh: l.refresh, entries: l.entries.join('\n') }
      : { name: preset?.name || '', enabled: true, mode: 'block', url: preset?.url || '', refresh: 24, entries: '' };
    lOpen = true;
  }
  async function saveList() {
    const body = $state.snapshot(lf);
    body.refresh = Number(body.refresh) || 0;
    const r = lCur ? await run(() => put(`/dns/lists/${lCur.id}`, body), 'Liste gespeichert') : await run(() => post('/dns/lists', body), 'Liste angelegt – wird geladen');
    if (r) {
      lOpen = false;
      load();
      setTimeout(load, 3000);
    }
  }
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
    if (loaded && !sf) sf = { enabled: d.settings.enabled === '1', upstream: d.settings.upstream, log_days: Number(d.settings.log_days) };
  });
  async function saveSettings() {
    const body = $state.snapshot(sf);
    body.log_days = Number(body.log_days) || 0;
    if (body.log_days === 0 && Number(d.settings.log_days) > 0) {
      if (!(await confirmDialog({ title: 'Protokoll abschalten?', text: 'Das vorhandene DNS-Protokoll wird gelöscht.', ok: 'Abschalten', danger: true }))) return;
    }
    if (await run(() => put('/dns/settings', body), 'DNS-Einstellungen gespeichert')) load();
  }
</script>

<PageHead title="DNS" subtitle="Eigener DNS für WireGuard- und OpenVPN-Geräte: Werbung und Tracker sperren, eigene Antworten, Protokoll">
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
  {/if}

  <div class="card card-pad" style="margin-top:14px">
    <strong class="small">Domain prüfen</strong>
    <div class="muted tiny" style="margin-bottom:8px">Was der Panel-DNS für ein Gerät mit einem Namen machen würde – ohne ihn aufzulösen.</div>
    <div class="row wrap" style="gap:8px">
      <select class="input" style="width:auto;min-width:200px" bind:value={check.peer}>
        <option value={0}>Gerät wählen …</option>
        {#each dnsPeers as p}<option value={p.id}>{peerLabel(p.id)}</option>{/each}
      </select>
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
    <select class="input" style="width:auto" bind:value={filter.peer}>
      <option value={0}>Alle Geräte</option>
      {#each dnsPeers as p}<option value={p.id}>{peerLabel(p.id)}</option>{/each}
    </select>
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
            <td class="right tiny muted">{en.action === 'cached' || en.action === 'blocked' ? '' : en.ms}</td>
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
  <div class="notice" style="margin-top:18px">
    <Icon name="info" />
    <span>Für jedes Gerät gilt genau ein Profil: das am Gerät, sonst das des Nutzers, sonst das des Servers, sonst das für alle Geräte. Gelten auf einer Ebene mehrere, gewinnt das ältere.</span>
  </div>
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
          <div class="tiny muted">{l.used_by.length ? `In ${l.used_by.join(', ')}` : 'In keinem Filterprofil'}</div>
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
    <div class="card-head"><h3>Bekannte Listen</h3></div>
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
  <div class="notice" style="margin-top:16px">
    <Icon name="info" />
    <span>Listen lädt der Server regelmäßig neu – Hosts-Dateien, Adblock-Listen („||domain^“, Ausnahmen „@@“) oder eine Domain pro Zeile. Eine Domain sperrt auch alle Unterdomains. Schlägt ein Abruf fehl, bleibt der letzte Stand aktiv. Damit eine Liste wirkt, muss sie in einem Filterprofil gewählt sein.</span>
  </div>
{:else if tab === 'settings' && sf}
  <div class="card card-pad stack" style="max-width:760px">
    <label class="switch"><input type="checkbox" bind:checked={sf.enabled} /><span class="track"></span> Panel-DNS für WireGuard- und OpenVPN-Geräte</label>
    <div class="help" style="margin-top:-6px">
      DNS-Anfragen dieser Geräte gehen an das Panel – egal, welchen DNS-Server das Gerät eingetragen hat. Configs mit DNS „auto“ (Vorgabe) nennen die Tunneladresse des Servers.
      Bei bestehenden Geräten mit eigenem DNS-Eintrag (z. B. 1.1.1.1) schalten Browser gern auf verschlüsseltes DNS um – dann die Config neu herunterladen bzw. den DNS des Servers auf „auto“ stellen.
    </div>
    <div class="field">
      <label for="dns-up">DNS-Server für die Auflösung</label>
      <input id="dns-up" class="input mono" bind:value={sf.upstream} placeholder="1.1.1.1, 9.9.9.9" />
      <div class="help">Fragt das Panel für Namen ohne Ziel-Regel. Für Ziel-Regeln gelten die DNS-Server der Ausgangsgruppe.</div>
    </div>
    <div class="field">
      <label for="dns-days">Protokoll aufbewahren</label>
      <select id="dns-days" class="input" style="width:auto" bind:value={sf.log_days}>
        <option value={0}>nicht protokollieren</option>
        {#each [1, 3, 7, 14, 30, 90] as n}<option value={n}>{n} {n === 1 ? 'Tag' : 'Tage'}</option>{/each}
        {#if ![0, 1, 3, 7, 14, 30, 90].includes(Number(sf.log_days))}<option value={sf.log_days}>{sf.log_days} Tage</option>{/if}
      </select>
      <div class="help">Jede Anfrage mit Gerät, Domain und Ergebnis. Ältere Einträge löscht der Server stündlich.</div>
    </div>
    <div><button class="btn primary" onclick={saveSettings}>Speichern</button></div>
  </div>
{/if}

<Modal open={!!quick} onclose={() => (quick = null)} title={quick?.allow ? `${quick?.name} freigeben` : `${quick?.name} sperren`} width={480}>
  {#if quick}
    {#if d.profiles.length}
      <div class="field">
        <label for="q-prof">In Filterprofil</label>
        <select id="q-prof" class="input" bind:value={quickProfile}>
          {#each d.profiles as p}<option value={p.id}>{p.name}</option>{/each}
        </select>
        <div class="help">Fügt die Regel „{quick.allow ? 'allow ' : ''}{quick.name}“ hinzu (gilt auch für Unterdomains).</div>
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
      <span class="label">Gilt für</span>
      <div class="row wrap" style="gap:6px;margin:4px 0 8px">
        {#each pf.assign as a}
          {@const [ic, label] = assignLabel(a)}
          <span class="badge"><Icon name={ic} size={12} /> {label}<button class="x" title="Entfernen" onclick={() => (pf.assign = pf.assign.filter((x) => x !== a))}><Icon name="x" size={11} /></button></span>
        {:else}
          <span class="muted small">Noch niemandem – unten hinzufügen</span>
        {/each}
      </div>
      <div class="row wrap" style="gap:6px">
        <select class="input" style="width:auto" bind:value={addKind}>
          <option value="global">Alle Geräte</option>
          <option value="server">Server</option>
          <option value="user">Nutzer</option>
          <option value="peer">Gerät</option>
        </select>
        {#if addKind !== 'global'}
          <select class="input grow" bind:value={addId}>
            <option value={0}>wählen …</option>
            {#each addOptions as o}<option value={o.id}>{addKind === 'peer' ? peerLabel(o.id) : o.name}</option>{/each}
          </select>
        {/if}
        <button class="btn" onclick={addAssign} disabled={addKind !== 'global' && !Number(addId)}><Icon name="plus" size={14} /> Hinzufügen</button>
      </div>
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
      <label for="p-rules">Eigene Regeln <span class="muted">({ruleCount(pf.rules)})</span></label>
      <textarea id="p-rules" class="input mono" rows="8" bind:value={pf.rules} placeholder={'werbung.de              # sperren\nallow cdn.beispiel.de   # freigeben (geht vor)\nnas.home = 192.168.1.10 # eigene Antwort'}></textarea>
      <div class="help">Eine Regel pro Zeile. Domain = sperren, „allow domain“ = freigeben (geht vor Listen), „domain = IP“ = eigene Antwort. Unterdomains sind immer eingeschlossen.</div>
    </div>
    <label class="switch"><input type="checkbox" bind:checked={pf.block_doh} /><span class="track"></span> Verschlüsseltes DNS der Geräte sperren (DoH/DoT)</label>
    <div class="help" style="margin-top:-8px">Browser und Android („Privates DNS“) gehen sonst am Filter vorbei. Mit fest eingestelltem eigenem Anbieter (z. B. Brave „Sicheres DNS“ = Cloudflare) lädt dann keine Seite mehr – dort „automatisch“ oder „aus“ wählen.</div>
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
      <label for="l-url">Online-Liste</label>
      <div class="row" style="gap:8px">
        <input id="l-url" class="input mono grow" bind:value={lf.url} placeholder="https://…/liste.txt" />
        <select class="input" style="width:auto" bind:value={lf.refresh} disabled={!lf.url}>
          {#each REFRESH as [h, label]}<option value={h}>{label}</option>{/each}
          {#if !REFRESH.some((r) => r[0] === lf.refresh)}<option value={lf.refresh}>alle {lf.refresh} Stunden</option>{/if}
        </select>
      </div>
      <div class="help">Hosts-Datei, Adblock-Liste oder eine Domain pro Zeile, bis 1 000 000 Einträge.</div>
    </div>
    <div class="field">
      <label for="l-entries">Eigene Einträge <span class="muted">(optional)</span></label>
      <textarea id="l-entries" class="input mono" rows="6" bind:value={lf.entries} placeholder={'werbung.example\ntracker.example'}></textarea>
    </div>
    <label class="switch"><input type="checkbox" bind:checked={lf.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (lOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveList} disabled={!lf.name}>{lCur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
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
