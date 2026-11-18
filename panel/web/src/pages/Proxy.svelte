<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Board from '../components/Board.svelte';
  import Modal from '../components/Modal.svelte';
  import FieldForm from '../components/FieldForm.svelte';
  import Info from '../components/Info.svelte';
  import PortHelp from '../components/PortHelp.svelte';
  import RouteRules from '../components/RouteRules.svelte';
  import TimeChart from '../components/TimeChart.svelte';
  import LimitsForm from '../components/LimitsForm.svelte';
  import Usage from '../components/Usage.svelte';
  import ExitLive from '../components/ExitLive.svelte';
  import StateBadge from '../components/StateBadge.svelte';
  import { exitState, toneClass } from '../lib/exitstate.js';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { ago, clone, date, fmtNum, bytes, limitsSummary } from '../lib/format.js';
  import { protocol, toast, go } from '../lib/state.svelte.js';

  let { tab = 'overview' } = $props();
  const TABS = [
    ['overview', 'Übersicht', 'activity'],
    ['exits', 'Ausgänge', 'globe'],
    ['groups', 'Gruppen', 'layers'],
    ['rules', 'Ziel-Regeln', 'route'],
    ['proxy', 'Proxy-Server', 'server'],
  ];

  let d = $state({ exits: [], groups: [], error: '' });
  let ruleCount = $state(null);
  let servers = $state([]);
  let loaded = $state(false);

  async function load() {
    try {
      const [x, s] = await Promise.all([get('/exits'), get('/servers')]);
      d = x;
      servers = s.filter((v) => v.protocol === 'proxy');
      loaded = true;
      if (tab === 'overview') get('/routes').then((r) => (ruleCount = { all: r.routes.length, on: r.routes.filter((x) => x.enabled).length })).catch(() => {});
    } catch (e) {
      toast(e.message, 'error');
    }
  }
  load();
  $effect(() => {
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  });

  const exitById = $derived(Object.fromEntries(d.exits.map((e) => [e.id, e])));
  const groupById = $derived(Object.fromEntries(d.groups.map((g) => [g.id, g])));

  const STATE = {
    ok: ['ok', 'Bevorzugter Ausgang'],
    failover: ['warn', 'Ausweich-Ausgang'],
    blocked: ['bad', 'Alle Ausgänge gestört – gesperrt'],
    direct: ['warn', 'Alle Ausgänge gestört – direkt'],
    waiting: ['muted', 'Wird geprüft …'],
  };

  // [Badge-Klasse, Text] – Grundlage ist exitState (lib/exitstate.js)
  function health(e) {
    const st = exitState(e);
    return [toneClass(st.tone), st.tone === 'bad' ? `${st.label}: ${st.detail}` : st.label];
  }
  // Zustand einer Gruppe (Datenlimit vor Ausfall)
  function groupState(g) {
    if (!g.enabled) return ['muted', 'deaktiviert'];
    if (g.limit?.status === 'blocked' || g.status?.limit) return ['warn', 'Gesperrt – Datenlimit'];
    if (g.rotate?.mode && g.status?.state === 'ok') return ['ok', g.rotate.mode === 'dest' ? 'Verteilt je Ziel' : 'Wechselt'];
    return STATE[g.status?.state || 'waiting'] || ['muted', 'wird geprüft'];
  }

  // ---------- Übersicht ----------
  const exitHealth = $derived.by(() => {
    const c = { ok: 0, warn: 0, bad: 0, muted: 0 };
    for (const e of d.exits) c[health(e)[0]]++;
    return c;
  });
  const groupIssues = $derived(d.groups.filter((g) => g.enabled && ['blocked', 'direct', 'failover'].includes(g.status?.state)));
  const badExits = $derived(d.exits.filter((e) => e.enabled && health(e)[0] === 'bad'));

  // ---------- Prüfen ----------
  let checking = $state(false);
  async function check(speed) {
    checking = true;
    await run(() => post('/exits/check', { speed }), speed ? 'Geschwindigkeitstest läuft (bis zu einer Minute)' : 'Prüfung läuft');
    setTimeout(load, speed ? 20000 : 6000);
    setTimeout(() => {
      checking = false;
      load();
    }, speed ? 60000 : 12000);
  }

  // ---------- einzelner Ausgang: Ping / Speedtest ----------
  let testing = $state({}); // id → 'ping' | 'speed'
  async function testExit(e, speed) {
    testing[e.id] = speed ? 'speed' : 'ping';
    try {
      const r = await post(`/exits/${e.id}/check`, { speed });
      const s = r.status || {};
      const i = d.exits.findIndex((x) => x.id === e.id);
      if (i >= 0) d.exits[i].status = s;
      if (!r.ok) toast(`${e.name}: ${r.error}`, 'error');
      else if (speed) toast(`${e.name}: ${fmtNum(Math.round(s.mbit))} Mbit/s, ${fmtNum(Math.round(s.rtt))} ms`);
      else {
        const last = s.samples?.[s.samples.length - 1];
        toast(`${e.name}: ${last?.rtt ? `${fmtNum(Math.round(last.rtt))} ms, ` : ''}${fmtNum(Math.round(last?.loss ?? 100))} % Verlust${last?.ok ? '' : ' – kein Internet über den Tunnel'}`, last?.ok ? 'ok' : 'error');
      }
    } catch (err) {
      toast(err.message, 'error');
    }
    delete testing[e.id];
  }

  // ---------- Ausgänge ----------
  let exOpen = $state(false);
  let exCur = $state(null);
  let ex = $state({ name: '', config: '', username: '', password: '', enabled: true, mode: 'always', check_min: 30 });
  const CHECKS = [
    [5, 'alle 5 Minuten'],
    [15, 'alle 15 Minuten'],
    [30, 'alle 30 Minuten'],
    [60, 'stündlich'],
    [180, 'alle 3 Stunden'],
    [360, 'alle 6 Stunden'],
    [720, 'alle 12 Stunden'],
    [1440, 'täglich'],
  ];
  const checkText = (m) => CHECKS.find((c) => c[0] === m)?.[1] || `alle ${m} Minuten`;
  const inMin = (ts) => {
    const m = Math.round((ts - Date.now() / 1000) / 60);
    if (m <= 0) return 'gleich';
    return m < 90 ? `in ${m} Min.` : `in ${Math.round(m / 60)} Std.`;
  };

  // ---------- Verkehr ----------
  let trDays = $state(7);
  let trExit = $state(0);
  let tr = $state(null);
  async function loadTraffic() {
    tr = await get(`/exits/traffic?days=${trDays}`).catch(() => null);
  }
  $effect(() => {
    if (tab !== 'exits') return;
    trDays;
    loadTraffic();
  });
  const trData = $derived.by(() => {
    if (!tr) return null;
    const by = new Map();
    for (const [b, id, up, down] of tr.series) {
      if (trExit && id !== trExit) continue;
      const p = by.get(b) || { ts: b * 1000, up: 0, down: 0 };
      p.up += up;
      p.down += down;
      by.set(b, p);
    }
    const to = Date.now();
    return { points: [...by.values()], bucket: tr.bucket * 1000, from: to - tr.days * 86400000, to };
  });
  const trSum = $derived((trData?.points || []).reduce((a, p) => a + p.up + p.down, 0));
  let exBusy = $state(false);
  let removedInfo = $state(null);
  const exType = $derived(ex.config.toLowerCase().includes('[interface]') ? 'wireguard' : ex.config.trim() ? 'openvpn' : exCur?.type || '');

  function openExit(e = null) {
    exCur = e;
    ex = { name: e?.name || '', config: '', username: e?.username || '', password: '', enabled: e ? e.enabled : true, mode: e?.mode || 'always', check_min: e?.check_min || 30 };
    exOpen = true;
  }
  async function readFile(ev) {
    const f = ev.currentTarget.files?.[0];
    if (!f) return;
    if (f.size > 256 * 1024) return toast('Datei zu groß', 'error');
    ex.config = await f.text();
    if (!ex.name) ex.name = f.name.replace(/\.(conf|ovpn)$/i, '').slice(0, 48);
  }
  async function saveExit() {
    exBusy = true;
    const body = { name: ex.name, enabled: ex.enabled, mode: ex.mode, check_min: Number(ex.check_min) };
    if (ex.config.trim()) body.config = ex.config;
    if (exType === 'openvpn') {
      body.username = ex.username;
      if (ex.password) body.password = ex.password;
    }
    const r = exCur ? await run(() => put(`/exits/${exCur.id}`, body), 'Ausgang gespeichert') : await run(() => post('/exits', body), 'Ausgang angelegt');
    exBusy = false;
    if (r) {
      exOpen = false;
      if (r.removed?.length) removedInfo = { name: ex.name, list: r.removed };
      ex.password = '';
      ex.config = '';
      load();
    }
  }
  async function toggleExit(e) {
    if (await run(() => put(`/exits/${e.id}`, { enabled: !e.enabled }), e.enabled ? 'Ausgang deaktiviert' : 'Ausgang aktiviert')) load();
  }
  async function removeExit(e) {
    const used = e.groups.map((id) => groupById[id]?.name).filter(Boolean);
    if (!(await confirmDialog({ title: `Ausgang ${e.name} löschen?`, text: used.length ? `Er wird auch aus ${used.join(', ')} entfernt.` : 'Der Tunnel wird abgebaut.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/exits/${e.id}`), 'Ausgang gelöscht')) load();
  }

  // ---------- Limits ----------
  let limOpen = $state(false);
  let limKind = $state('exit'); // exit | group
  let limCur = $state(null);
  let limOn = $state(false);
  let lim = $state(null);
  let limBusy = $state(false);
  function openLimit(e, kind = 'exit') {
    limKind = kind;
    limCur = e;
    limOn = !!e.limits;
    lim = e.limits ? clone(e.limits) : { traffic_gb: 0, period: 'monthly', reset_day: 1, on_limit: 'block', tiers: [] };
    limOpen = true;
  }
  async function saveLimit() {
    limBusy = true;
    const r = await run(() => put(`/${limKind === 'group' ? 'groups' : 'exits'}/${limCur.id}`, { limits: limOn ? lim : null }), limOn ? 'Limit gespeichert' : 'Limit entfernt');
    limBusy = false;
    if (r) {
      limOpen = false;
      load();
    }
  }
  async function resetUsage(e, kind = limKind) {
    const g = kind === 'group';
    if (!(await confirmDialog({ title: `Verbrauch von ${e.name} zurücksetzen?`, text: `Der Verbrauch im laufenden Zeitraum zählt wieder ab 0 – ${g ? 'eine gesperrte Gruppe nutzt wieder ihre Ausgänge' : 'ein abgeschalteter Ausgang verbindet sich wieder'}. Der Verlauf bleibt erhalten.`, ok: 'Zurücksetzen' }))) return;
    if (!(await run(() => post(`/${g ? 'groups' : 'exits'}/${e.id}/reset-usage`), 'Verbrauch zurückgesetzt'))) return;
    await load();
    if (limCur?.id === e.id) limCur = (g ? d.groups : d.exits).find((x) => x.id === e.id) || limCur;
  }
  const LIMIT_STATE = { blocked: ['bad', 'abgeschaltet'], throttled: ['warn', 'gedrosselt'] };

  // ---------- Gruppen ----------
  let grOpen = $state(false);
  let grCur = $state(null);
  let gr = $state({});
  // Wechsel innerhalb der Gruppe: Formularwerte (Zeit/Datenmenge einzeln ein- und ausschaltbar)
  function rotForm(r) {
    r = r || {};
    return {
      mode: r.mode || '',
      time: (r.min_min || 0) > 0,
      min_min: r.min_min || 30,
      max_min: r.max_min || 90,
      gb: (r.min_gb || 0) > 0,
      min_gb: r.min_gb || 2,
      max_gb: r.max_gb || 5,
      drain_min: r.drain_min || 30,
      warm_sec: r.warm_sec ?? 90,
      flush_dns: r.flush_dns ?? true,
    };
  }
  function rotBody(f) {
    return {
      mode: f.mode,
      min_min: f.time ? Number(f.min_min) || 0 : 0,
      max_min: f.time ? Number(f.max_min) || 0 : 0,
      min_gb: f.gb ? Number(f.min_gb) || 0 : 0,
      max_gb: f.gb ? Number(f.max_gb) || 0 : 0,
      drain_min: Number(f.drain_min) || 30,
      warm_sec: Number(f.warm_sec) || 0,
      flush_dns: !!f.flush_dns,
    };
  }
  function openGroup(g = null) {
    grCur = g;
    gr = g
      ? clone($state.snapshot({ name: g.name, enabled: g.enabled, exits: g.exits, on_fail: g.on_fail, max_loss: g.max_loss, max_rtt: g.max_rtt, min_mbit: g.min_mbit, dns: g.dns }))
      : { name: '', enabled: true, exits: d.exits.length === 1 ? [d.exits[0].id] : [], on_fail: 'block', max_loss: 20, max_rtt: 400, min_mbit: 0, dns: '1.1.1.1, 9.9.9.9' };
    gr.rot = rotForm(g?.rotate);
    gr.blk = blkForm(g?.block);
    grOpen = true;
  }
  function toggleMember(id) {
    gr.exits = gr.exits.includes(id) ? gr.exits.filter((x) => x !== id) : [...gr.exits, id];
  }
  function moveUp(i) {
    if (i < 1) return;
    const l = [...gr.exits];
    [l[i - 1], l[i]] = [l[i], l[i - 1]];
    gr.exits = l;
  }
  async function saveGroup() {
    const body = $state.snapshot(gr);
    for (const k of ['max_loss', 'max_rtt', 'min_mbit']) body[k] = Number(body[k]) || 0;
    body.rotate = rotBody(body.rot);
    delete body.rot;
    body.block = blkBody(body.blk);
    delete body.blk;
    const r = grCur ? await run(() => put(`/groups/${grCur.id}`, body), 'Gruppe gespeichert') : await run(() => post('/groups', body), 'Gruppe angelegt');
    if (r) {
      grOpen = false;
      load();
    }
  }
  async function removeGroup(g) {
    if (!(await confirmDialog({ title: `Gruppe ${g.name} löschen?`, text: 'Die Ausgänge selbst bleiben erhalten.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/groups/${g.id}`), 'Gruppe gelöscht')) load();
  }
  async function rotateNow(g) {
    if (await run(() => post(`/groups/${g.id}/rotate`), g.rotate?.mode === 'dest' ? 'Verteilung wird neu gemischt' : 'Wechsel wird vorbereitet')) setTimeout(load, 2500);
  }
  // „in 23 Min.“ / „in 2 Std.“
  function untilText(ts) {
    const s = Math.max(0, ts - Date.now() / 1000);
    if (s < 90) return 'gleich';
    if (s < 5400) return `in ${Math.round(s / 60)} Min.`;
    return `in ${fmtNum(Math.round(s / 360) / 10)} Std.`;
  }
  const ROT_MODE = { group: 'Ganze Gruppe wechselt', dest: 'Je Ziel verteilt' };
  // Block-Prüfung: Formularwerte (Ziele als Text, eins pro Zeile)
  function blkForm(b) {
    b = b || {};
    return {
      on: !!b.on,
      domains: (b.domains || []).join('\n'),
      auto: b.auto ?? true,
      top: b.top || 20,
      ok_hours: b.ok_hours || 24,
      bad_hours: b.bad_hours || 6,
      fails: b.fails || 4,
      realtime: b.realtime ?? true,
    };
  }
  function blkBody(f) {
    return {
      on: !!f.on,
      domains: String(f.domains || '')
        .split(/[\s,;]+/)
        .map((x) => x.trim())
        .filter(Boolean),
      auto: !!f.auto,
      top: Number(f.top) || 20,
      ok_hours: Number(f.ok_hours) || 24,
      bad_hours: Number(f.bad_hours) || 6,
      fails: Number(f.fails) || 4,
      realtime: !!f.realtime,
    };
  }
  // Ergebnis-Übersicht
  let bkOpen = $state(false);
  let bkGroup = $state(null);
  let bkData = $state(null);
  let bkAdd = $state('');
  async function openBlock(g) {
    bkGroup = g;
    bkData = null;
    bkAdd = '';
    bkOpen = true;
    await loadBlock();
  }
  async function loadBlock() {
    if (!bkGroup) return;
    const r = await run(() => get(`/groups/${bkGroup.id}/block`));
    if (r) bkData = r;
  }
  $effect(() => {
    if (!bkOpen) return;
    const t = setInterval(loadBlock, 5000);
    return () => clearInterval(t);
  });
  async function checkBlock(domain = '') {
    if (await run(() => post(`/groups/${bkGroup.id}/block/check`, { domain }), domain ? `${domain} wird geprüft` : 'Alle Ziele werden geprüft')) setTimeout(loadBlock, 2500);
  }
  async function resetBlock(domain) {
    if (await run(() => del(`/groups/${bkGroup.id}/block?domain=${encodeURIComponent(domain)}`), 'Ergebnisse verworfen – wird neu geprüft')) setTimeout(loadBlock, 2500);
  }
  async function addBlockTarget() {
    const g = groupById[bkGroup.id];
    const n = bkAdd.trim();
    if (!g || !n) return;
    const b = blkBody(blkForm(g.block));
    b.on = true;
    b.domains = [...b.domains, n];
    if (await run(() => put(`/groups/${g.id}`, { ...groupPayload(g), block: b }), `${n} wird geprüft`)) {
      bkAdd = '';
      await load();
      setTimeout(loadBlock, 2500);
    }
  }
  // unveränderte Felder einer Gruppe (zum Speichern nur der Block-Prüfung)
  function groupPayload(g) {
    return { name: g.name, enabled: g.enabled, exits: g.exits, on_fail: g.on_fail, max_loss: g.max_loss, max_rtt: g.max_rtt, min_mbit: g.min_mbit, dns: g.dns };
  }
  const BLK = {
    ok: ['ok', 'erreichbar'],
    captcha: ['bad', 'Captcha'],
    blocked: ['bad', 'gesperrt'],
    error: ['warn', 'Fehler'],
  };
  // „gerade eben“ / „vor 5 Min.“ (ago() sagt bei frischen Zeiten „online“)
  const sinceText = (ts) => (Date.now() / 1000 - ts < 90 ? 'gerade eben' : ago(ts));
  function blkCell(r, fails) {
    if (!r) return null;
    if (r.status === 'error' && r.fails >= fails) return ['bad', `${r.fails}× Fehler`];
    if (r.status === 'ok' && r.fails > 0) return ['warn', `${r.fails}× Fehler gemeldet`];
    if (r.status === 'error') return ['warn', `Fehler (${r.fails}×)`];
    return BLK[r.status] || ['', r.status];
  }
  async function switchTo(g, exitId) {
    if (!exitId || exitId === g.status?.active) return;
    if (await run(() => post(`/groups/${g.id}/switch`, { exit: exitId }), 'Umgeschaltet')) load();
  }

  // ---------- Proxy-Server ----------
  let svOpen = $state(false);
  let svCur = $state(null);
  let sv = $state({ name: '', enabled: true });
  let svValues = $state({});
  const pxProto = $derived(protocol('proxy'));
  function openServer(s = null) {
    svCur = s;
    sv = { name: s?.name || 'Proxy', enabled: s ? s.enabled : true };
    if (s) svValues = clone($state.snapshot(s.settings));
    else {
      const v = {};
      for (const f of pxProto?.server_fields || []) if (f.default !== undefined) v[f.key] = clone(f.default);
      if (d.groups.length) v.group = d.groups[0].id;
      svValues = v;
    }
    svOpen = true;
  }
  async function saveServer() {
    const body = { name: sv.name, enabled: sv.enabled, settings: $state.snapshot(svValues) };
    const ok = svCur ? await run(() => put(`/servers/${svCur.id}`, body), 'Proxy gespeichert') : await run(() => post('/servers', { ...body, protocol: 'proxy' }), 'Proxy angelegt');
    if (ok) {
      svOpen = false;
      load();
    }
  }
  function serverPorts(s) {
    return (s.ports || []).map((p) => `${p.note.startsWith('SOCKS') ? 'SOCKS5' : 'HTTP'} ${p.port}`).join(' · ') || 'keine Ports aktiv';
  }
</script>

<PageHead title="Proxy & Ausgänge" subtitle="Proxy, Ausgänge über externe VPNs und Ziel-Regeln" helpTitle="Proxy & Ausgänge">
  {#snippet help()}
    <p><b>Proxy:</b> SOCKS5/HTTP-Zugänge für Geräte ohne VPN-App (z. B. Fernseher). Zugänge legst du beim Nutzer an (Zugang hinzufügen → Proxy).</p>
    <p><b>Ausgänge:</b> WireGuard- oder OpenVPN-Konfigurationen externer Anbieter. Hochgeladene Konfigurationen werden bereinigt: Skripte (PostUp, up/down), Routen, DNS-Änderungen und Dateiverweise fallen weg.</p>
    <p><b>Gruppen:</b> Der Server prüft alle 30 Sekunden Antwortzeit und Verlust jedes Ausgangs (Ping und HTTPS über den Tunnel) und schaltet bei Störung auf den nächsten Ausgang der Gruppe; zurück geht es, wenn der bevorzugte Ausgang 10 Minuten stabil war. Nur IPv4.</p>
    <p><b>Ziel-Regeln:</b> legen fest, welcher Verkehr über welche Gruppe läuft.</p>
  {/snippet}
  {#if tab === 'overview' || tab === 'exits' || tab === 'groups'}
    <button class="btn" onclick={() => check(false)} disabled={checking || !d.exits.length}><Icon name="refresh" size={16} /> Jetzt prüfen</button>
    <button class="btn" onclick={() => check(true)} disabled={checking || !d.exits.length} title="Lädt 5 MB über jeden Ausgang"><Icon name="gauge" size={16} /> Geschwindigkeit messen</button>
  {/if}
  {#if tab === 'exits'}<button class="btn primary" onclick={() => openExit()}><Icon name="upload" size={16} /> Ausgang hochladen</button>{/if}
  {#if tab === 'groups'}<button class="btn primary" onclick={() => openGroup()} disabled={!d.exits.length}><Icon name="plus" size={16} /> Gruppe anlegen</button>{/if}
  {#if tab === 'proxy'}<button class="btn primary" onclick={() => openServer()}><Icon name="plus" size={16} /> Proxy anlegen</button>{/if}
</PageHead>

<div class="tabs">
  {#each TABS as [id, label, icon]}
    <button class:active={tab === id} onclick={() => go(id === 'overview' ? '/proxy' : `/proxy/${id}`)}><Icon name={icon} size={14} /> {label}</button>
  {/each}
</div>

{#if d.error}<div class="notice bad" style="margin-bottom:16px"><Icon name="alert" /><span>{d.error}</span></div>{/if}

{#if tab === 'overview'}
  {#snippet w_flow()}
    <div>
    <div class="flow">
      <button class="tile" onclick={() => go('/proxy/rules')}>
        <span class="tl"><Icon name="route" size={16} /> Ziel-Regeln</span>
        <span class="big">{ruleCount ? ruleCount.on : '…'}</span>
        <span class="tiny muted">{ruleCount ? `aktiv${ruleCount.all > ruleCount.on ? `, ${ruleCount.all - ruleCount.on} aus` : ''}` : ''} · welcher Verkehr über welche Gruppe läuft</span>
      </button>
      <span class="arrow"><Icon name="chevron" size={18} /></span>
      <button class="tile" onclick={() => go('/proxy/groups')}>
        <span class="tl"><Icon name="layers" size={16} /> Gruppen</span>
        <span class="big">{d.groups.length}</span>
        <span class="tiny muted">{groupIssues.length ? `${groupIssues.length} mit Störung` : 'alle auf dem bevorzugten Ausgang'} · Reihenfolge mit Ausweich-Ausgängen</span>
      </button>
      <span class="arrow"><Icon name="chevron" size={18} /></span>
      <button class="tile" onclick={() => go('/proxy/exits')}>
        <span class="tl"><Icon name="globe" size={16} /> Ausgänge</span>
        <span class="big">{d.exits.length}</span>
        <span class="tiny"><span class="ok-text">{exitHealth.ok} verbunden</span>{#if exitHealth.warn}&nbsp;· <span class="warn-text">{exitHealth.warn} instabil</span>{/if}{#if exitHealth.bad}&nbsp;· <span class="bad-text">{exitHealth.bad} gestört</span>{/if}</span>
      </button>
    </div>
    <div class="muted small" style="margin-top:6px">Daneben gibt es <button class="linkbtn" onclick={() => go('/proxy/proxy')}>{servers.length} Proxy-Server</button> (SOCKS5/HTTP) für Geräte ohne VPN-App – sie nutzen ebenfalls eine Gruppe als Ausgang.</div>

    {#if badExits.length || groupIssues.length}
      <div class="notice warn small" style="margin-top:10px">
        <Icon name="alert" size={16} />
        <span>
          {#each groupIssues as g}<span>Gruppe <b>{g.name}</b>: {STATE[g.status.state]?.[1]}. </span>{/each}
          {#each badExits as e}<span>Ausgang <b>{e.name}</b>: {health(e)[1]}. </span>{/each}
        </span>
      </div>
    {/if}
    </div>
  {/snippet}
  {#snippet w_groups()}
  <div class="card">
    <div class="card-head"><h3>Gruppen und aktiver Ausgang</h3></div>
    <div class="list">
      {#each d.groups as g}
        {@const st = groupState(g)}
        {@const act = exitById[g.status?.active]}
        <button class="item linkitem" onclick={() => go('/proxy/groups')}>
          <Icon name="layers" size={18} />
          <div class="grow">
            <div class="strong">{g.name}</div>
            <div class="muted tiny">{g.exits.length} Ausgänge · {g.users.length ? `genutzt von ${g.users.map((u) => u.name).slice(0, 4).join(', ')}${g.users.length > 4 ? ' …' : ''}` : 'von keiner Regel genutzt'}</div>
          </div>
          <span class="small">{act ? act.name : '–'}{#if act?.status?.loc}&nbsp;<span class="badge">{act.status.loc}</span>{/if}</span>
          <span class="badge {st[0]}">{st[1]}</span>
        </button>
      {:else}
        <div class="empty small">{d.exits.length ? 'Noch keine Gruppe.' : 'Noch keine Ausgänge – lade unter „Ausgänge“ die Konfiguration deines VPN-Anbieters hoch.'}</div>
      {/each}
    </div>
  </div>
  {/snippet}
  {#snippet w_live()}<ExitLive exits={d.exits} groups={d.groups} />{/snippet}
  <Board
    id="proxy"
    widgets={[
      { id: 'flow', title: 'Ziel-Regeln → Gruppen → Ausgänge', w: 12, body: w_flow },
      { id: 'live', title: 'Live', w: 12, body: w_live, show: d.exits.length > 0 },
      { id: 'groups', title: 'Gruppen und aktiver Ausgang', w: 12, body: w_groups },
    ]}
  />
{/if}

{#if tab === 'proxy'}
<div class="card">
  <div class="card-head">
    <div><h2>Proxy-Server <Info title="Proxy-Server" wide><p>Zugänge legst du beim Nutzer an (Zugang hinzufügen → Proxy).</p><PortHelp ports={servers.filter((s) => s.enabled).flatMap((s) => (s.ports || []).map((p) => ({ ...p, server: s.name })))} /></Info></h2></div>
  </div>
  <div class="list">
    {#each servers as s}
      {@const g = groupById[s.settings.group]}
      <div class="item">
        <span class="srvlogo"><ProtoLogo id="proxy" size={30} /><span class="dot" class:on={s.status.running} class:bad={s.enabled && !s.status.running}></span></span>
        <div class="grow">
          <div class="strong">{s.name} {#if !s.enabled}<span class="badge muted">aus</span>{/if}</div>
          <div class="muted tiny">{serverPorts(s)} · Ausgang: {g ? g.name : 'direkt über den Server'} · {s.status.detail}</div>
        </div>
        <span class="badge" title="online / Zugänge">{s.online} / {s.peers}</span>
        <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => openServer(s)}><Icon name="edit" size={15} /></button>
      </div>
    {:else}
      <div class="empty small">Noch kein Proxy-Server.</div>
    {/each}
  </div>
</div>

{/if}

{#if tab === 'rules'}
<RouteRules reload={d.groups.length + servers.length} />
{/if}

{#if tab === 'groups'}
<div class="muted small" style="margin-bottom:12px">Mehrere Ausgänge in fester Reihenfolge – fällt einer aus, übernimmt der nächste automatisch. Auf Wunsch wechselt die Gruppe zufällig nach Zeit oder Datenmenge bzw. verteilt je Ziel.</div>
<div class="grid cols-2">
  {#each d.groups as g}
    {@const st = groupState(g)}
    {@const act = exitById[g.status?.active]}
    <div class="card group">
      <div class="card-head">
        <div>
          <h3>{g.name}</h3>
          <div class="muted tiny">
            Bei Ausfall aller: {g.on_fail === 'direct' ? 'direkt über den Server' : 'sperren'} · Grenzen {fmtNum(g.max_loss)} % Verlust, {fmtNum(g.max_rtt)} ms{g.min_mbit ? `, ${fmtNum(g.min_mbit)} Mbit/s` : ''}
          </div>
        </div>
        <span class="badge {st[0]}">{st[1]}</span>
      </div>
      <div class="card-pad stack" style="gap:10px">
        {#if g.limit}
          {@const L = g.limit}
          <button class="linkish glim" onclick={() => openLimit(g, 'group')} title={limitsSummary(g.limits).replace('danach gesperrt', 'danach Gruppe gesperrt')}>
            <span class="spread tiny"><span class="strong"><Icon name="gauge" size={12} /> Limit</span><span class="muted">{#if L.next_reset}neu ab {date(L.next_reset)}{/if}</span></span>
            <Usage used={L.used} limitGb={L.limits.traffic_gb} tiers={L.limits.tiers || []} />
            {#if L.status !== 'ok' || L.rate_down || L.rate_up}
              <span class="row wrap tiny" style="gap:6px;margin-top:4px">
                {#if LIMIT_STATE[L.status]}<span class="badge {LIMIT_STATE[L.status][0]}">{L.status === 'blocked' ? 'gesperrt' : 'gedrosselt'}</span>{/if}
                {#if L.rate_down || L.rate_up}<span class="muted">↓ {fmtNum(L.rate_down) || '∞'} ↑ {fmtNum(L.rate_up) || '∞'} Mbit/s</span>{/if}
                {#if L.reason}<span class="muted">{L.reason}</span>{/if}
              </span>
            {/if}
          </button>
        {/if}
        {#if g.enabled && g.rotate?.mode}
          {@const R = g.status || {}}
          <div class="glim rot">
            <span class="spread tiny">
              <span class="strong"><Icon name="refresh" size={12} /> {ROT_MODE[g.rotate.mode]}</span>
              <button class="btn sm ghost" onclick={() => rotateNow(g)} title={g.rotate.mode === 'dest' ? 'Neue Verbindungen sofort neu auf die Ausgänge verteilen' : 'Jetzt auf einen anderen Ausgang wechseln (laufende Verbindungen bleiben)'}>{g.rotate.mode === 'dest' ? 'Neu mischen' : 'Jetzt wechseln'}</button>
            </span>
            <span class="tiny muted">
              {#if g.rotate.mode === 'dest'}{(R.pool || []).length} Ausgänge in der Verteilung{#if R.next_rotate || R.rotate_at}{' · '}{/if}{/if}
              {#if R.next_rotate}{g.rotate.mode === 'dest' ? 'neu gemischt' : 'nächster Wechsel'} {untilText(R.next_rotate)}{/if}
              {#if R.rotate_at}{R.next_rotate ? ' oder' : g.rotate.mode === 'dest' ? 'neu gemischt' : 'nächster Wechsel'} nach {bytes(R.rotate_at)} ({bytes(R.rotate_bytes || 0)} erreicht){/if}
              {#if R.next}{' · '}als Nächstes: {exitById[R.next]?.name || '–'} (bereit){/if}
              {#if R.rotated}{' · '}zuletzt {date(R.rotated, true)}{/if}
            </span>
          </div>
        {/if}
        {#if g.enabled && g.block?.on}
          <div class="glim rot">
            <span class="spread tiny">
              <span class="strong"><Icon name="shield" size={12} /> Block-Prüfung</span>
              <button class="btn sm ghost" onclick={() => openBlock(g)} title="Ergebnisse je Ziel und Ausgang">Ergebnisse</button>
            </span>
            <span class="tiny muted">
              {g.block.domains?.length || 0} feste Ziele{#if g.block.auto} + {g.block.top} meistbesuchte{/if}
              {#if g.avoid}{' · '}<span class="warn-text">{g.avoid} {g.avoid === 1 ? 'Ziel weicht' : 'Ziele weichen'} auf einen anderen Ausgang aus</span>{:else}{' · '}keine Ausnahmen{/if}
            </span>
          </div>
        {/if}
        {#if g.enabled}
          <div class="active-row">
            <Icon name="route" size={16} />
            <span class="grow">Aktiv: <b>{act ? act.name : 'keiner'}</b>
              {#if act?.status?.ip}<span class="muted small"> · {act.status.ip} {act.status.loc}</span>{/if}
              {#if g.status?.since}<span class="muted tiny"> · seit {date(g.status.since, true)}</span>{/if}
            </span>
          </div>
          {#if g.status?.reason}<div class="muted tiny">{g.status.reason}</div>{/if}
        {/if}
        <ol class="members">
          {#each g.exits as id, i}
            {@const e = exitById[id]}
            {#if e}
              {@const est = exitState(e)}
              <li class:cur={g.status?.active === id}>
                <StateBadge small tone={est.tone} label={est.label} icon={est.icon} title={est.detail} />
                <span class="grow">{i + 1}. {e.name} {#if g.status?.pinned === id}<span class="badge accent" title="Von Hand gewählt – wird statt des ersten Ausgangs bevorzugt. Ausgang 1 wählen = normale Reihenfolge.">gewählt</span>{/if}
                  {#if g.rotate?.mode === 'dest' && g.status?.pool?.includes(id)}<span class="badge ok" title="Neue Verbindungen werden nach Ziel auch über diesen Ausgang geleitet">verteilt</span>{/if}
                  {#if g.status?.next === id}<span class="badge accent" title="Ist verbunden und geprüft – übernimmt beim nächsten Wechsel">als Nächstes</span>{/if}
                  {#if g.status?.active !== id && !g.status?.pool?.includes(id) && g.status?.uses?.includes(id) && !e.status?.draining}<span class="badge muted" title="Laufende Verbindungen der Gruppe enden noch über diesen Ausgang">läuft aus</span>{/if}
                </span>
                <span class="muted tiny">{e.status?.rtt ? `${fmtNum(Math.round(e.status.rtt))} ms` : ''}</span>
                {#if g.enabled && e.enabled && g.status?.active !== id}
                  <button class="btn sm ghost" onclick={() => switchTo(g, id)} title="Von Hand auf diesen Ausgang umschalten">Umschalten</button>
                {/if}
              </li>
            {/if}
          {:else}
            <li class="muted small">Keine Ausgänge in der Gruppe</li>
          {/each}
        </ol>
        {#if g.users.length}
          <div class="muted tiny">Genutzt von: {g.users.map((u) => u.name).join(', ')}</div>
        {/if}
      </div>
      <div class="actions">
        <button class="btn sm" onclick={() => openGroup(g)}><Icon name="edit" size={15} /> Bearbeiten</button>
        <button class="btn sm" onclick={() => openLimit(g, 'group')}><Icon name="gauge" size={15} /> Limit</button>
        <span class="grow"></span>
        {#if g.traffic}<span class="tiny muted" title="Über die Gruppe gelaufen (Verkehr des jeweils aktiven Ausgangs)">{bytes((g.traffic.day?.up || 0) + (g.traffic.day?.down || 0))} heute · {bytes((g.traffic.month?.up || 0) + (g.traffic.month?.down || 0))} 30 T.</span>{/if}
        <button class="btn sm icon ghost danger" title="Löschen" onclick={() => removeGroup(g)}><Icon name="trash" size={15} /></button>
      </div>
    </div>
  {:else}
    {#if loaded}<div class="card empty small" style="grid-column:1/-1">{d.exits.length ? 'Noch keine Gruppe – lege eine an und wähle sie beim Proxy-Server als Ausgang.' : 'Lade zuerst einen Ausgang hoch.'}</div>{/if}
  {/each}
</div>

{/if}

{#if tab === 'exits'}
<div class="muted small" style="margin-bottom:12px">Externe VPN-Verbindungen – nur für Gruppen, der Server selbst nutzt sie nicht.</div>
  {#snippet w_exits()}
  <div class="card">
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Ausgang</th><th>Zustand</th><th>Messung</th><th>Öffentliche IP</th><th class="right">Verkehr <Info title="Verkehr" text="Oben: letzte 24 Stunden, unten: letzte 30 Tage (hoch + runter)." /></th><th>Limit <Info title="Limit" text="Datenvolumen je Zeitraum (hoch + runter, gezählt an der Schnittstelle des Ausgangs), Geschwindigkeit und Drosselstufen – wie bei Nutzern. Beim Erreichen wird der Ausgang gedrosselt oder abgeschaltet; Gruppen schalten dann auf den nächsten Ausgang um." /></th><th class="right">Prüfen</th><th></th></tr></thead>
        <tbody>
          {#each d.exits as e}
            {@const s = e.status}
            {@const st = exitState(e)}
            <tr class:off={!e.enabled}>
              <td>
                <div class="row" style="gap:8px">
                  <ProtoLogo id={e.type} size={22} />
                  <div style="min-width:0">
                    <div class="strong">{e.name}</div>
                    <div class="muted tiny mono ellipsis exsrv" title={e.server}>{e.server}{#if e.removed.length}&nbsp;<span class="badge muted" title={'Beim Hochladen entfernt: ' + e.removed.join(', ')}><Icon name="filter" size={11} /> {e.removed.length}</span>{/if}</div>
                  </div>
                </div>
              </td>
              <td>
                <div class="row wrap" style="gap:4px">
                  <StateBadge tone={st.tone} label={st.label} icon={st.icon} title={st.detail} />
                  {#if e.limit?.status === 'throttled'}<StateBadge small tone="warn" icon="gauge" label="gedrosselt" title={e.limit.reason} />{/if}
                </div>
                {#if st.tone !== 'ok' && st.tone !== 'muted'}<div class="tiny stdetail" class:bad-text={st.tone === 'bad'}>{st.detail}</div>{/if}
                <div class="tiny muted nowrap">
                  {#if e.mode === 'standby'}
                    <span title="Bereitschaft: nur verbunden, solange eine Gruppe den Ausgang nutzt">{s?.connected ? (s?.next_check ? 'Bereitschaft · gerade verbunden' : 'Bereitschaft · in Benutzung') : 'Bereitschaft · getrennt'}</span>
                    {#if !s?.connected && s?.next_check}<br />prüft {checkText(e.check_min)}, nächste {inMin(s.next_check)}{/if}
                  {:else}
                    immer verbunden · prüft alle 30 s
                  {/if}
                </div>
                {#if e.error}<div class="tiny bad-text">{e.error}</div>{/if}
                {#if e.need_auth && !e.has_auth}<div class="tiny bad-text">Benutzername/Passwort fehlen</div>{/if}
              </td>
              <td class="nowrap">
                {#if s?.checked}
                  <span class="small">{s.rtt ? `${fmtNum(Math.round(s.rtt))} ms` : '–'} · {fmtNum(Math.round(s.loss))} %</span>
                  <div class="tiny muted" title={s.mbit_at ? `Tempo gemessen ${ago(s.mbit_at)}` : ''}>{s.mbit ? `${fmtNum(Math.round(s.mbit))} Mbit/s` : 'Tempo –'}{#if e.mode === 'standby'}&nbsp;· {ago(s.checked) === 'online' ? 'gerade' : ago(s.checked)}{/if}</div>
                {:else}<span class="muted small">–</span>{/if}
              </td>
              <td class="nowrap">{#if s?.ip}<span class="mono small">{s.ip}</span> <span class="badge">{s.loc}</span>{:else}–{/if}</td>
              <td class="right nowrap small" title="30 Tage: hoch {bytes(e.traffic?.month?.up)}, runter {bytes(e.traffic?.month?.down)} · gesamt {bytes((e.traffic?.all?.up || 0) + (e.traffic?.all?.down || 0))}">
                {bytes((e.traffic?.day?.up || 0) + (e.traffic?.day?.down || 0))}
                <div class="tiny muted">{bytes((e.traffic?.month?.up || 0) + (e.traffic?.month?.down || 0))}</div>
              </td>
              <td class="limcell">
                {#if e.limit}
                  {@const L = e.limit}
                  <button class="linkish" title={limitsSummary(e.limits).replace('danach gesperrt', 'danach abgeschaltet')} onclick={() => openLimit(e)}>
                    <Usage used={L.used} limitGb={L.limits.traffic_gb} tiers={L.limits.tiers || []} compact />
                  </button>
                  <div class="tiny muted limline">
                    {#if LIMIT_STATE[L.status]}<span class="badge {LIMIT_STATE[L.status][0]}" title={L.reason}>{LIMIT_STATE[L.status][1]}</span>{/if}
                    {#if L.rate_down || L.rate_up}<span>↓ {fmtNum(L.rate_down) || '∞'} ↑ {fmtNum(L.rate_up) || '∞'} Mbit/s</span>{/if}
                    {#if L.next_reset}<span title="Nächster Zeitraum ab {date(L.next_reset, true)}">neu ab {date(L.next_reset)}</span>{/if}
                  </div>
                {:else}
                  <button class="btn sm ghost" onclick={() => openLimit(e)}><Icon name="gauge" size={13} /> Limit setzen</button>
                {/if}
              </td>
              <td class="right nowrap">
                <button class="btn sm" title="Ping-Prüfung jetzt (Antwortzeit, Verlust, HTTPS über den Tunnel){e.mode === 'standby' ? ' – verbindet kurz' : ''}" disabled={!e.enabled || !!testing[e.id]} onclick={() => testExit(e, false)}><Icon name="activity" size={13} /> {testing[e.id] === 'ping' ? '…' : 'Ping'}</button>
                <button class="btn sm" title="Speedtest jetzt (lädt 5 MB über den Ausgang){e.mode === 'standby' ? ' – verbindet kurz' : ''}" disabled={!e.enabled || !!testing[e.id]} onclick={() => testExit(e, true)}><Icon name="gauge" size={13} /> {testing[e.id] === 'speed' ? 'misst …' : 'Speed'}</button>
              </td>
              <td class="right nowrap">
                <button class="btn sm icon ghost" title={e.enabled ? 'Deaktivieren' : 'Aktivieren'} onclick={() => toggleExit(e)}><Icon name="power" size={15} /></button>
                <button class="btn sm icon ghost" title="Limit" onclick={() => openLimit(e)}><Icon name="gauge" size={15} /></button>
                <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => openExit(e)}><Icon name="edit" size={15} /></button>
                <button class="btn sm icon ghost danger" title="Löschen" onclick={() => removeExit(e)}><Icon name="trash" size={15} /></button>
              </td>
            </tr>
          {:else}
            <tr><td colspan="8" class="empty small">Noch keine Ausgänge. Lade die WireGuard- oder OpenVPN-Konfiguration deines Anbieters hoch.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
  {/snippet}
  {#snippet w_live()}<ExitLive exits={d.exits} groups={d.groups} />{/snippet}
  {#snippet w_traffic()}
  <div class="card">
    <div class="card-head">
      <h3>Verkehr über die Ausgänge <Info title="Verkehr" text="Gezählt an den Schnittstellen der Ausgänge: alles, was Nutzer über Gruppen ins Internet schicken bzw. von dort laden (inkl. Prüfungen). Runter = vom Anbieter empfangen." /> <span class="muted small">{bytes(trSum)}</span></h3>
      <div class="row wrap" style="gap:8px">
        <select class="input" style="width:auto" bind:value={trExit}>
          <option value={0}>Alle Ausgänge</option>
          {#each d.exits as e}<option value={e.id}>{e.name}</option>{/each}
        </select>
        <div class="segmented">
          {#each [[1, '24 h'], [7, '7 Tage'], [30, '30 Tage'], [90, '90 Tage']] as [n, l]}<button class:active={trDays === n} onclick={() => (trDays = n)}>{l}</button>{/each}
        </div>
      </div>
    </div>
    <div class="card-pad" style="padding-top:0">
      {#if trData}
        <TimeChart mode="bars" points={trData.points} bucket={trData.bucket} from={trData.from} to={trData.to} format={bytes} binary height={180} />
      {/if}
      <div class="trgrid">
        {#each [...d.exits].sort((a, b) => (b.traffic?.month?.down || 0) + (b.traffic?.month?.up || 0) - (a.traffic?.month?.down || 0) - (a.traffic?.month?.up || 0)) as e}
          {@const m = (e.traffic?.month?.up || 0) + (e.traffic?.month?.down || 0)}
          {@const all = d.exits.reduce((a, x) => a + (x.traffic?.month?.up || 0) + (x.traffic?.month?.down || 0), 0)}
          <button class="trrow" class:sel={trExit === e.id} onclick={() => (trExit = trExit === e.id ? 0 : e.id)}>
            <span class="small ellipsis grow">{e.name}</span>
            <span class="share"><span style="width:{all ? (m / all) * 100 : 0}%"></span></span>
            <span class="tiny muted nowrap">{bytes(m)} · 30 T.</span>
          </button>
        {/each}
      </div>
    </div>
  </div>
  {/snippet}
  <Board
    id="proxy-exits"
    widgets={[
      { id: 'exits', title: 'Ausgänge', w: 12, body: w_exits },
      { id: 'live', title: 'Live', w: 12, body: w_live, show: d.exits.length > 0 },
      { id: 'traffic', title: 'Verkehr über die Ausgänge', w: 12, body: w_traffic, show: d.exits.length > 0 },
    ]}
  />
{/if}

<Modal bind:open={exOpen} title={exCur ? `Ausgang ${exCur.name}` : 'Ausgang hochladen'} width={680}>
  <div class="stack">
    <div class="field"><label for="ex-name">Name</label><input id="ex-name" class="input" bind:value={ex.name} placeholder="z. B. Anbieter USA" /></div>
    <div class="field">
      <label for="ex-file">Konfiguration <Info title="Konfiguration" text="Eine .conf von WireGuard oder eine .ovpn von OpenVPN. Skripte (PostUp, up/down), Routen, DNS-Änderungen und Dateiverweise werden entfernt." />{#if exType}&nbsp;<span class="badge ok">erkannt: {exType === 'wireguard' ? 'WireGuard' : 'OpenVPN'}</span>{/if}</label>
      <input id="ex-file" type="file" accept=".conf,.ovpn,.txt" onchange={readFile} />
      <textarea class="input mono" rows="8" bind:value={ex.config} placeholder={exCur ? 'leer lassen = Konfiguration behalten' : '[Interface] … bzw. client / remote … <ca> …'}></textarea>
    </div>
    {#if exType === 'openvpn'}
      <div class="grid cols-2">
        <div class="field"><label for="ex-user">Benutzername <Info title="Zugangsdaten" text="Nur nötig, wenn die Konfiguration „auth-user-pass“ enthält (bei vielen Anbietern die OpenVPN-Zugangsdaten aus dem Kundenbereich, nicht das Login-Passwort)." /></label><input id="ex-user" class="input" bind:value={ex.username} autocomplete="off" /></div>
        <div class="field"><label for="ex-pw">Passwort</label><input id="ex-pw" class="input" type="password" bind:value={ex.password} autocomplete="new-password" placeholder={exCur?.has_auth ? 'gespeichert – leer = unverändert' : ''} /></div>
      </div>
    {/if}
    <div class="field">
      <span class="label"
        >Verbindung <Info title="Verbindung" wide>
          <p><b>Immer verbunden:</b> Der Tunnel steht ständig und wird alle 30 Sekunden geprüft – Umschalten geht sofort.</p>
          <p><b>Bereitschaft:</b> Verbunden nur, solange eine Gruppe den Ausgang gerade nutzt. Sonst verbindet der Server ihn im gewählten Abstand kurz, prüft ihn (Ping, HTTPS, ggf. Tempo) und trennt wieder. Fällt der aktive Ausgang einer Gruppe aus, werden Ausgänge in Bereitschaft der Reihe nach verbunden und geprüft, bevor umgeschaltet wird – das dauert einige Sekunden länger.</p>
          <p>Sinnvoll, wenn der Anbieter viele dauerhafte Verbindungen ungern sieht oder nur wenige gleichzeitige Verbindungen erlaubt.</p>
        </Info></span
      >
      <div class="row wrap" style="gap:10px">
        <div class="segmented">
          <button type="button" class:active={ex.mode === 'always'} onclick={() => (ex.mode = 'always')}>Immer verbunden</button>
          <button type="button" class:active={ex.mode === 'standby'} onclick={() => (ex.mode = 'standby')}>Bereitschaft</button>
        </div>
        {#if ex.mode === 'standby'}
          <select class="input" style="width:auto" bind:value={ex.check_min}>
            {#each CHECKS as [v, l]}<option value={v}>prüfen {l}</option>{/each}
          </select>
        {/if}
      </div>
    </div>
    <label class="switch"><input type="checkbox" bind:checked={ex.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (exOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveExit} disabled={exBusy || !ex.name || (!exCur && !ex.config.trim())}>{exCur ? 'Speichern' : 'Hochladen'}</button>
  {/snippet}
</Modal>

<Modal bind:open={limOpen} title={limCur ? `Limit für ${limKind === 'group' ? 'Gruppe ' : ''}${limCur.name}` : 'Limit'} width={680}>
  {#if limCur}
    <div class="stack">
      <label class="switch"><input type="checkbox" bind:checked={limOn} /><span class="track"></span> Limits für {limKind === 'group' ? 'diese Gruppe' : 'diesen Ausgang'}</label>
      {#if limCur.limit}
        <div class="card-pad limnow">
          <div class="spread small"><span class="strong">Im laufenden Zeitraum</span>{#if limCur.limit.next_reset}<span class="muted">neu ab {date(limCur.limit.next_reset, true)}</span>{/if}</div>
          <Usage used={limCur.limit.used} limitGb={limCur.limit.limits.traffic_gb} tiers={limCur.limit.limits.tiers || []} />
          <div class="row wrap tiny muted" style="gap:10px;margin-top:6px">
            <span>↓ {bytes(limCur.limit.down)} runter · ↑ {bytes(limCur.limit.up)} hoch</span>
            <span class="grow"></span>
            <button class="btn sm" onclick={() => resetUsage(limCur)}><Icon name="refresh" size={13} /> Verbrauch zurücksetzen</button>
          </div>
          {#if limCur.limit.reason}<div class="small" style="margin-top:6px">{limCur.limit.reason}</div>{/if}
        </div>
      {/if}
      {#if limOn}
        <LimitsForm bind:value={lim} exit={limKind} />
        {#if limKind === 'group'}
          <div class="notice small"><Icon name="info" size={16} /><span>Gezählt wird hoch + runter am jeweils aktiven Ausgang der Gruppe. <b>Drosseln</b> bremst den aktiven Ausgang (nutzen ihn weitere Gruppen, sind sie mitgebremst). <b>Sperren</b> lässt keinen Verkehr mehr über die Gruppe – auch nicht direkt, selbst wenn die Gruppe bei Ausfall „direkt“ weiterleiten würde. Im nächsten Zeitraum, bei höherem Limit oder nach „Verbrauch zurücksetzen“ geht es von selbst weiter.</span></div>
        {:else}
          <div class="notice small"><Icon name="info" size={16} /><span>Gezählt wird hoch + runter an der Schnittstelle des Ausgangs (auch Prüfungen und Speedtests). „Download“ ist, was vom Anbieter kommt. Ein abgeschalteter Ausgang wird sofort getrennt, Gruppen schalten auf den nächsten Ausgang um. Im nächsten Zeitraum, bei höherem Limit oder nach „Verbrauch zurücksetzen“ verbindet er sich von selbst wieder.</span></div>
        {/if}
      {:else}
        <p class="muted small">Ohne Limits wird {limKind === 'group' ? 'die Gruppe' : 'der Ausgang'} nie gedrosselt oder {limKind === 'group' ? 'gesperrt' : 'abgeschaltet'}. Der Verkehr wird trotzdem gezählt.</p>
      {/if}
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (limOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveLimit} disabled={limBusy}>Speichern</button>
  {/snippet}
</Modal>

<Modal open={!!removedInfo} onclose={() => (removedInfo = null)} title="Konfiguration bereinigt" width={520}>
  {#if removedInfo}
    <p class="small">Aus „{removedInfo.name}“ wurden diese Einträge entfernt, weil sie das System verändern könnten:</p>
    <ul class="removed">{#each removedInfo.list as r}<li class="mono small">{r}</li>{/each}</ul>
  {/if}
  {#snippet footer()}<button class="btn primary" onclick={() => (removedInfo = null)}>Verstanden</button>{/snippet}
</Modal>

<Modal bind:open={grOpen} title={grCur ? `Gruppe ${grCur.name}` : 'Gruppe anlegen'} width={640}>
  <div class="stack">
    <div class="field"><label for="gr-name">Name</label><input id="gr-name" class="input" bind:value={gr.name} placeholder="z. B. USA" /></div>
    <div class="field">
      <span class="label">Ausgänge (Reihenfolge = Vorrang)</span>
      <ol class="members edit">
        {#each gr.exits || [] as id, i}
          <li>
            <span class="grow">{i + 1}. {exitById[id]?.name || id}</span>
            <button class="btn sm icon ghost" title="Nach oben" disabled={i === 0} onclick={() => moveUp(i)}><Icon name="arrow-up" size={14} /></button>
            <button class="btn sm icon ghost" title="Entfernen" onclick={() => toggleMember(id)}><Icon name="x" size={14} /></button>
          </li>
        {/each}
      </ol>
      <div class="row wrap" style="gap:6px">
        {#each d.exits.filter((e) => !(gr.exits || []).includes(e.id)) as e}
          <button class="btn sm" onclick={() => toggleMember(e.id)}><Icon name="plus" size={13} /> {e.name}</button>
        {/each}
      </div>
    </div>
    <div class="field">
      <label for="gr-fail">Wenn alle Ausgänge gestört sind</label>
      <select id="gr-fail" class="input" bind:value={gr.on_fail}>
        <option value="block">Sperren – kein Verkehr (Standort bleibt sicher verborgen)</option>
        <option value="direct">Direkt über den Server weiterleiten</option>
      </select>
    </div>
    <div class="grid cols-3">
      <div class="field"><label for="gr-loss">Max. Verlust (%)</label><input id="gr-loss" class="input" type="number" bind:value={gr.max_loss} /></div>
      <div class="field"><label for="gr-rtt">Max. Antwortzeit (ms) <Info title="Max. Antwortzeit" text="Ist der Ausgang langsamer, gilt er als gestört. 0 = egal." /></label><input id="gr-rtt" class="input" type="number" bind:value={gr.max_rtt} placeholder="0 = egal" /></div>
      <div class="field"><label for="gr-mbit">Min. Tempo (Mbit/s) <Info title="Min. Tempo" text="Ist der Ausgang langsamer, gilt er als gestört. 0 = egal. Braucht den Geschwindigkeitstest („Geschwindigkeit messen“)." /></label><input id="gr-mbit" class="input" type="number" bind:value={gr.min_mbit} placeholder="0 = egal" /></div>
    </div>
    <div class="field"><label for="gr-dns">DNS-Server (über den Ausgang) <Info title="DNS über den Ausgang" text="Namen werden über den aktiven Ausgang aufgelöst, damit Dienste den passenden Standort sehen." /></label><input id="gr-dns" class="input mono" bind:value={gr.dns} /></div>
    <div class="field">
      <span class="label">Limit <Info title="Limit der Gruppe" text="Datenvolumen je Zeitraum, Geschwindigkeit und Drosselstufen für alles, was über die Gruppe läuft (gezählt am jeweils aktiven Ausgang). Beim Erreichen wird gedrosselt oder die Gruppe gesperrt." /></span>
      <div class="row wrap" style="gap:10px">
        <span class="small muted grow">{grCur?.limits ? limitsSummary(grCur.limits).replace('danach gesperrt', 'danach Gruppe gesperrt') : 'Keine Limits'}</span>
        {#if grCur}<button type="button" class="btn sm" onclick={() => openLimit(grCur, 'group')}><Icon name="gauge" size={14} /> Limit einstellen</button>{:else}<span class="tiny muted">nach dem Anlegen einstellbar</span>{/if}
      </div>
    </div>
    {#if gr.rot}
      <div class="field rotbox">
        <span class="label">Wechsel innerhalb der Gruppe <Info title="Wechsel" wide text="Damit der Verkehr nicht dauerhaft über dieselbe Adresse läuft. Ganze Gruppe: nach einer zufälligen Zeit bzw. Datenmenge wechselt die Gruppe auf einen zufällig gewählten anderen gesunden Ausgang. Je Ziel: neue Verbindungen werden nach Zieladresse auf alle gesunden Ausgänge verteilt – jede Website sieht eine andere Adresse; beim Wechsel wird neu gemischt. Immer weich: laufende Verbindungen (Downloads, Anrufe, Anmeldungen) bleiben auf ihrem Ausgang, bis sie enden. Ausgänge in Bereitschaft werden rechtzeitig vorher verbunden und geprüft. Hysteria2-Server, die die Gruppe nutzen, bauen beim Wechsel kurz neu auf." /></span>
        <div class="segmented">
          {#each [['', 'Aus'], ['group', 'Ganze Gruppe'], ['dest', 'Je Ziel']] as [v, l]}<button type="button" class:active={gr.rot.mode === v} onclick={() => (gr.rot.mode = v)}>{l}</button>{/each}
        </div>
        {#if gr.rot.mode}
          <div class="stack" style="gap:8px;margin-top:8px">
            <div class="row wrap rotline">
              <label class="check"><input type="checkbox" bind:checked={gr.rot.time} /> {gr.rot.mode === 'dest' ? 'Neu mischen nach Zeit' : 'Wechsel nach Zeit'}</label>
              {#if gr.rot.time}<span class="row small" style="gap:6px">zufällig <input class="input num" type="number" min="1" bind:value={gr.rot.min_min} /> bis <input class="input num" type="number" min="1" bind:value={gr.rot.max_min} /> Min.</span>{/if}
            </div>
            <div class="row wrap rotline">
              <label class="check"><input type="checkbox" bind:checked={gr.rot.gb} /> {gr.rot.mode === 'dest' ? 'Neu mischen nach Datenmenge' : 'Wechsel nach Datenmenge'}</label>
              {#if gr.rot.gb}<span class="row small" style="gap:6px">zufällig <input class="input num" type="number" min="0.01" step="0.1" bind:value={gr.rot.min_gb} /> bis <input class="input num" type="number" min="0.01" step="0.1" bind:value={gr.rot.max_gb} /> GB</span>{/if}
            </div>
            {#if gr.rot.mode === 'group' && !gr.rot.time && !gr.rot.gb}<div class="tiny" style="color:var(--warn)">Zeit oder Datenmenge wählen – sonst wechselt die Gruppe nie.</div>{/if}
            {#if gr.rot.mode === 'dest'}<div class="tiny muted">Alle Ausgänge der Gruppe bleiben dafür verbunden (auch die in Bereitschaft). Ohne Zeit/Datenmenge bleibt die Verteilung fest.</div>{/if}
            <div class="grid cols-2">
              <div class="field"><label for="gr-drain">Alte Verbindungen halten (Min.) <Info title="Auslaufen" text="So lange bleibt der bisherige Ausgang höchstens verbunden, damit laufende Verbindungen zu Ende laufen können. Enden sie früher, wird er früher frei." /></label><input id="gr-drain" class="input" type="number" min="1" bind:value={gr.rot.drain_min} /></div>
              <div class="field"><label for="gr-warm">Vorlauf (Sek.) <Info title="Vorlauf" text="So früh vor dem Wechsel wird der nächste Ausgang verbunden und geprüft, wenn er in Bereitschaft ist (mindestens 45 s). Beim Wechsel nach Datenmenge: ab 85 % der Menge." /></label><input id="gr-warm" class="input" type="number" min="0" bind:value={gr.rot.warm_sec} /></div>
            </div>
            <label class="check small"><input type="checkbox" bind:checked={gr.rot.flush_dns} /> DNS-Zwischenspeicher der Gruppe beim Wechsel leeren <Info title="DNS beim Wechsel" text="Der DNS-Server der Gruppe (Unbound über den Ausgang) startet kurz neu, damit Antworten zum Standort des neuen Ausgangs passen und alte Anfragen nicht verknüpft werden können." /></label>
          </div>
        {/if}
      </div>
    {/if}
    {#if gr.blk}
      <div class="field rotbox">
        <span class="label">Block-Prüfung <Info title="Block-Prüfung" wide text="Prüft Ziele (Websites) über jeden Ausgang der Gruppe – wie ein Browser. Kommt über einen Ausgang ein Captcha, eine Sperrseite oder scheitert das Ziel mehrmals in Folge, läuft dieses Ziel automatisch über einen anderen Ausgang der Gruppe, der nachweislich funktioniert (Gegenprobe). Die Ergebnisse werden gespeichert und nur in großen Abständen erneuert – bekannte Ziele werden nicht ständig neu geprüft. Fehlschläge aus dem Verkehr zählen mit – Verbindungsfehler des Proxys und Verbindungen der Geräte, deren Aufbau über einen Ausgang hängt (passiv erkannt, ohne eigene Anfragen) – und lösen bei Bedarf sofort eine Prüfung aus." /></span>
        <label class="check"><input type="checkbox" bind:checked={gr.blk.on} /> Ziele prüfen und bei Sperre ausweichen</label>
        {#if gr.blk.on}
          <div class="stack" style="gap:8px;margin-top:8px">
            <div class="field"><label for="gr-blkd">Feste Ziele <span class="muted tiny">(eins pro Zeile, z. B. example.org – gilt auch für Unterdomains)</span></label><textarea id="gr-blkd" class="input" rows="3" bind:value={gr.blk.domains} placeholder="shop.example.org"></textarea></div>
            <div class="row wrap rotline">
              <label class="check"><input type="checkbox" bind:checked={gr.blk.auto} /> dazu die meistbesuchten Ziele der Gruppe</label>
              {#if gr.blk.auto}<span class="row small" style="gap:6px">die <input class="input num" type="number" min="1" max="200" bind:value={gr.blk.top} /> häufigsten (DNS, 7 Tage)</span>{/if}
            </div>
            <div class="grid cols-3">
              <div class="field"><label for="gr-blkok">„Erreichbar“ erneut prüfen (Std.)</label><input id="gr-blkok" class="input" type="number" min="1" bind:value={gr.blk.ok_hours} /></div>
              <div class="field"><label for="gr-blkbad">„Gesperrt“ erneut prüfen (Std.)</label><input id="gr-blkbad" class="input" type="number" min="1" bind:value={gr.blk.bad_hours} /></div>
              <div class="field"><label for="gr-blkf">Gesperrt ab … Fehlern in Folge</label><input id="gr-blkf" class="input" type="number" min="1" max="20" bind:value={gr.blk.fails} /></div>
            </div>
            <label class="check small"><input type="checkbox" bind:checked={gr.blk.realtime} /> Proxy weicht sofort aus <Info title="Echtzeit" text="Kommt eine Verbindung des Proxys über den Ausgang nicht zustande, versucht der Proxy es ohne Wartezeit über den nächsten Ausgang der Gruppe. Der Fehlschlag zählt für die Block-Prüfung." /></label>
            {#if !gr.blk.auto && !String(gr.blk.domains || '').trim()}<div class="tiny" style="color:var(--warn)">Ziele eintragen oder die meistbesuchten Ziele einschalten.</div>{/if}
          </div>
        {/if}
      </div>
    {/if}
    <label class="switch"><input type="checkbox" bind:checked={gr.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (grOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveGroup} disabled={!gr.name || (gr.rot?.mode === 'group' && !gr.rot.time && !gr.rot.gb) || (gr.blk?.on && !gr.blk.auto && !String(gr.blk.domains || '').trim())}>{grCur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<Modal bind:open={bkOpen} title={bkGroup ? `Block-Prüfung ${bkGroup.name}` : 'Block-Prüfung'} width={860}>
  {@const G = bkGroup ? groupById[bkGroup.id] || bkGroup : null}
  {#if G}
    <div class="stack" style="gap:10px">
      <div class="row wrap" style="gap:8px">
        <span class="small muted grow">
          Ergebnisse je Ziel und Ausgang. Gesperrte Ziele laufen über einen Ausgang mit „erreichbar“.
          {#if bkData?.last}Letzter Durchlauf {sinceText(bkData.last)}.{/if}
        </span>
        <button class="btn sm" onclick={() => checkBlock()}><Icon name="refresh" size={14} /> Alle jetzt prüfen</button>
      </div>
      <form class="row" style="gap:6px" onsubmit={(ev) => { ev.preventDefault(); addBlockTarget(); }}>
        <input class="input grow" placeholder="Ziel hinzufügen, z. B. shop.example.org" bind:value={bkAdd} />
        <button class="btn sm" type="submit" disabled={!bkAdd.trim()}><Icon name="plus" size={14} /> Hinzufügen</button>
      </form>
      {#if !bkData}
        <div class="muted small">Lade …</div>
      {:else if !bkData.rows.length}
        <div class="muted small">Noch keine Ziele – feste Ziele eintragen oder warten, bis über die Gruppe Seiten aufgerufen wurden.</div>
      {:else}
        <div class="tblwrap">
          <table class="table blk">
            <thead>
              <tr>
                <th>Ziel</th>
                {#each G.exits as xid}<th>{exitById[xid]?.name || xid}</th>{/each}
                <th>Läuft über</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each bkData.rows as row (row.domain)}
                <tr class:over={row.over}>
                  <td><span class="strong">{row.domain}</span>{#if row.manual}<span class="tiny muted"> · fest</span>{/if}</td>
                  {#each G.exits as xid}
                    {@const r = row.results[xid]}
                    {@const c = blkCell(r, G.block?.fails || 4)}
                    <td title={r ? `${r.detail || ''}${r.checked ? ' · geprüft ' + date(r.checked, true) : ' · nur gemeldet'}` : 'noch nicht geprüft'}>
                      {#if c}<span class="badge {c[0]}">{c[1]}</span>{#if r.checked}<div class="tiny muted">{sinceText(r.checked)}</div>{/if}{:else}<span class="tiny muted">–</span>{/if}
                    </td>
                  {/each}
                  <td>
                    {#if row.via}{exitById[row.via]?.name || row.via}{:else}<span class="muted">–</span>{/if}
                    {#if row.over}<div><span class="badge warn">Ausnahme</span></div>{/if}
                  </td>
                  <td class="right nowrap">
                    <button class="btn sm ghost" title="Jetzt über alle Ausgänge prüfen" onclick={() => checkBlock(row.domain)}><Icon name="refresh" size={14} /></button>
                    <button class="btn sm ghost" title="Gespeicherte Ergebnisse verwerfen" onclick={() => resetBlock(row.domain)}><Icon name="trash" size={14} /></button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (bkOpen = false)}>Schließen</button>
  {/snippet}
</Modal>

<Modal bind:open={svOpen} title={svCur ? `Proxy ${svCur.name}` : 'Proxy anlegen'} width={620}>
  <div class="stack">
    <div class="field"><label for="sv-name">Name</label><input id="sv-name" class="input" bind:value={sv.name} /></div>
    {#if pxProto}<FieldForm fields={pxProto.server_fields} bind:values={svValues} />{/if}
    <label class="switch"><input type="checkbox" bind:checked={sv.enabled} /><span class="track"></span> Aktiv</label>
    <div class="row small muted" style="gap:6px">Ports auf dem Host weiterleiten <Info title="Firewall-Regeln" wide><PortHelp ports={[svValues.socks_port && { proto: 'tcp', port: Number(svValues.socks_port), note: 'SOCKS5' }, svValues.http_port && { proto: 'tcp', port: Number(svValues.http_port), note: 'HTTP' }].filter(Boolean)} /></Info></div>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (svOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveServer} disabled={!sv.name}>{svCur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
  .stdetail {
    margin-top: 3px;
    max-width: 260px;
    color: var(--text-2);
  }
  .rot {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .tblwrap {
    overflow-x: auto;
  }
  .table.blk td {
    vertical-align: top;
  }
  .table.blk tr.over td {
    background: color-mix(in srgb, var(--warn) 7%, transparent);
  }
  .warn-text {
    color: var(--warn);
  }
  .nowrap {
    white-space: nowrap;
  }
  .rotbox {
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
  }
  .rotline {
    gap: 10px;
    align-items: center;
    min-height: 32px;
  }
  .input.num {
    width: 80px;
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
  }
  .glim {
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--panel-2);
  }
  .limcell {
    min-width: 140px;
    max-width: 170px;
  }
  .limline {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 6px;
    align-items: center;
    margin-top: 3px;
  }
  .linkish {
    display: block;
    width: 100%;
    background: none;
    border: 0;
    padding: 0;
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .limnow {
    border: 1px solid var(--border);
    border-radius: var(--radius, 10px);
    background: var(--panel-2);
  }
  .exsrv {
    max-width: 220px;
  }
  tr.off {
    opacity: 0.6;
  }
  .trgrid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 4px 14px;
    margin-top: 10px;
  }
  .trrow {
    display: flex;
    align-items: center;
    gap: 8px;
    border: 0;
    background: none;
    font: inherit;
    color: inherit;
    padding: 4px 6px;
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    min-width: 0;
  }
  .trrow:hover,
  .trrow.sel {
    background: var(--accent-soft);
  }
  .share {
    width: 70px;
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
  .flow {
    display: flex;
    align-items: stretch;
    gap: 8px;
    flex-wrap: wrap;
  }
  .tile {
    flex: 1 1 200px;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
    text-align: left;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--panel);
    padding: 12px 14px;
    cursor: pointer;
    font: inherit;
    color: var(--text);
  }
  .tile:hover {
    border-color: var(--accent);
  }
  .tile .tl {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
  }
  .tile .big {
    font-size: 26px;
    font-weight: 700;
    line-height: 1.1;
  }
  .arrow {
    display: flex;
    align-items: center;
    color: var(--text-2);
  }
  .linkitem {
    width: 100%;
    border: 0;
    background: none;
    font: inherit;
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .linkitem:hover {
    background: var(--hover, rgba(127, 127, 127, 0.06));
  }
  .linkbtn {
    border: 0;
    background: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font: inherit;
  }
  @media (max-width: 700px) {
    .arrow {
      display: none;
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
  }
  .section-head {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    justify-content: space-between;
    margin: 26px 0 12px;
  }
  .group {
    display: flex;
    flex-direction: column;
  }
  .actions {
    display: flex;
    gap: 6px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    margin-top: auto;
  }
  .active-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .active-row :global(svg) {
    color: var(--accent);
  }
  .members {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .members li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 8px;
    border-radius: var(--radius-sm);
    min-height: 32px;
  }
  .members li.cur {
    background: var(--accent-soft);
  }
  .members.edit li {
    border: 1px solid var(--border);
  }
  .members.edit {
    margin-bottom: 8px;
  }
  .dot.ok {
    background: var(--ok);
  }
  .dot.warn {
    background: var(--warn);
  }
  .dot.bad {
    background: var(--bad);
  }
  .dot.muted {
    background: var(--border-strong);
  }
  .bad-text {
    color: var(--bad);
    margin-top: 3px;
  }
  .nowrap {
    white-space: nowrap;
    text-align: right;
  }
  .removed {
    margin: 8px 0 0;
    padding-left: 18px;
  }
  .label {
    font-weight: 600;
    font-size: 13px;
  }
  textarea.input {
    margin-top: 8px;
    min-height: 140px;
    resize: vertical;
    font-size: 12px;
  }
  .srvlogo {
    position: relative;
    display: inline-flex;
  }
  .srvlogo .dot {
    position: absolute;
    right: -2px;
    bottom: -2px;
    border: 2px solid var(--panel);
    width: 10px;
    height: 10px;
  }
</style>
