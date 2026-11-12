<script>
  // Netzwerk-Übersicht: Geräte → Server → Ausgang → Internet, mit aktuellem Verkehr und Störungen.
  // Ziehen: Gerät/Nutzer/Server auf eine Gruppe (oder „Direkt“) = Ausgang zuweisen;
  // WireGuard-Gerät auf ein anderes Gerät desselben Servers = Zugriff erlauben bzw. entziehen.
  import Icon from './Icon.svelte';
  import ProtoLogo from './ProtoLogo.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, run } from '../lib/api.js';
  import { ago, speed, fmtNum, PROTO_LABEL } from '../lib/format.js';
  import { meta } from '../lib/state.svelte.js';
  import SearchInput from './SearchInput.svelte';
  import Fold from './Fold.svelte';
  import Info from './Info.svelte';
  import { tokens, matches } from '../lib/pick.js';

  let topo = $state({ peers: [], users: [], server_via: {}, issues: [] });
  let servers = $state([]);
  let ex = $state({ exits: [], groups: [] });
  let live = $state({ peers: [], exits: {}, total: {} });
  let loaded = $state(false);
  let showOffline = $state(null); // null = automatisch (bei vielen Geräten nur aktive)

  async function load() {
    try {
      const [t, s, x] = await Promise.all([get('/topology'), get('/servers'), get('/exits')]);
      topo = t;
      servers = s;
      ex = x;
      loaded = true;
    } catch {
      /* alter Stand bleibt stehen */
    }
  }
  async function poll() {
    try {
      live = await get('/live');
    } catch {
      /* nächster Versuch */
    }
  }
  load();
  poll();
  $effect(() => {
    const a = setInterval(load, 10000);
    const b = setInterval(poll, 2000);
    return () => {
      clearInterval(a);
      clearInterval(b);
    };
  });

  const byId = (l) => Object.fromEntries(l.map((x) => [x.id, x]));
  const serverById = $derived(byId(servers));
  const groupById = $derived(byId(ex.groups));
  const exitById = $derived(byId(ex.exits));
  const userById = $derived(byId(topo.users));
  const peerById = $derived(byId(topo.peers));
  const rateOf = $derived(Object.fromEntries((live.peers || []).map((p) => [p.id, p])));
  const sum = (p) => (p ? p.up + p.down : 0);

  const withOffline = $derived(showOffline ?? topo.peers.length <= 24);

  // Suche: Nutzer, Gerät, Dienst, Server, Adresse – zeigt Treffer auch offline
  let tq = $state('');
  const toks = $derived(tokens(tq));
  function peerShown(p, u) {
    if (toks.length) {
      const s = serverById[p.server_id];
      return matches(`${u.name} ${p.name} ${PROTO_LABEL[p.protocol] || p.protocol} ${s?.name || ''} ${p.address || p.address4 || ''}`, toks);
    }
    return withOffline || p.online;
  }
  const hitCount = $derived(toks.length ? topo.peers.filter((p) => userById[p.user_id] && peerShown(p, userById[p.user_id])).length : 0);

  // ---------- Anordnung ----------
  const W = 1090;
  const COL = { dev: 36, devW: 286, srv: 420, srvW: 176, out: 700, outW: 214, net: 1000 };
  const ROW = 28;

  // Viele Nutzer: kompakt – eine Zeile je Nutzer (aufklappbar), Linien je Nutzer und Server gebündelt,
  // nur die ersten „limit“ Nutzer (aktive zuerst), Rest über „weitere anzeigen“ bzw. die Suche.
  const COMPACT_FROM = 25;
  let openUsers = $state({});
  let limit = $state(20);
  const usersWithPeers = $derived(
    topo.users.map((u) => ({ u, ps: topo.peers.filter((p) => p.user_id === u.id && peerShown(p, u)) })).filter((x) => x.ps.length),
  );
  const compact = $derived(!toks.length && usersWithPeers.length > COMPACT_FROM);
  function toggleUser(id) {
    openUsers = { ...openUsers, [id]: !openUsers[id] };
  }

  const layout = $derived.by(() => {
    const rows = []; // Nutzer-Köpfe und Geräte
    const bundles = []; // kompakt: Linie Nutzer → Server
    const peerY = {};
    const userY = {};
    let y = 8;
    let list = usersWithPeers;
    let hidden = 0;
    if (compact) {
      const on = (x) => x.ps.some((p) => p.online);
      list = [...list].sort((a, b) => on(b) - on(a) || a.u.name.localeCompare(b.u.name));
      hidden = Math.max(0, list.length - limit);
      list = list.slice(0, limit);
    }
    for (const { u, ps } of list) {
      if (compact && !openUsers[u.id]) {
        rows.push({ type: 'user', u, y, n: ps.length, ps, collapsed: true });
        userY[u.id] = y + 15;
        const bySrv = {};
        for (const p of ps) {
          peerY[p.id] = y + 15;
          (bySrv[p.server_id] ||= []).push(p);
        }
        for (const [sid, list2] of Object.entries(bySrv)) bundles.push({ uid: u.id, sid: Number(sid), y: y + 15, ps: list2 });
        y += 36;
        continue;
      }
      rows.push({ type: 'user', u, y, n: ps.length, ps });
      userY[u.id] = y + 14;
      y += 30;
      for (const p of ps) {
        rows.push({ type: 'peer', p, y });
        peerY[p.id] = y + ROW / 2;
        y += ROW;
      }
      y += 12;
    }
    if (hidden) {
      rows.push({ type: 'more', y, n: hidden });
      y += 44;
    }
    const devH = y;
    // Server: auf Höhe ihrer Geräte, ohne Überlappung
    const SH = 62;
    const want = servers.map((s) => {
      const ys = topo.peers.filter((p) => p.server_id === s.id && peerY[p.id] != null).map((p) => peerY[p.id]);
      return { s, y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length - SH / 2 : Infinity };
    });
    want.sort((a, b) => a.y - b.y || a.s.id - b.s.id);
    const srvY = {};
    let sy = 8;
    for (const w of want) {
      const yy = Math.max(sy, w.y === Infinity ? sy : w.y);
      srvY[w.s.id] = yy + SH / 2;
      sy = yy + SH + 14;
    }
    // Ausgänge: „Direkt“, dann Gruppen mit ihren Ausgängen
    const outs = [{ type: 'direct', id: 0, h: 58 }];
    for (const g of ex.groups) outs.push({ type: 'group', id: g.id, g, h: 46 + g.exits.length * 24 });
    const outTotal = outs.reduce((a, o) => a + o.h + 16, -16);
    const H = Math.max(devH, sy, outTotal + 16, 240);
    let oy = Math.max(8, (H - outTotal) / 2);
    const outY = {};
    for (const o of outs) {
      o.y = oy;
      outY[o.id] = oy + (o.type === 'group' ? 23 : o.h / 2);
      oy += o.h + 16;
    }
    return { rows, bundles, peerY, userY, srvY, outs, outY, H, SH };
  });

  // ---------- Verkehr je Weg ----------
  const flows = $derived.by(() => {
    const m = new Map(); // "server:ziel" → {sid, gid, rate, n, partial}
    const add = (sid, gid, rate, partial) => {
      const k = sid + ':' + gid + (partial ? ':p' : '');
      const f = m.get(k) || { sid, gid, rate: 0, n: 0, partial };
      f.rate += rate;
      f.n++;
      m.set(k, f);
    };
    const seen = new Set();
    for (const p of topo.peers) {
      if (!p.enabled || !p.active) continue;
      seen.add(p.server_id);
      add(p.server_id, p.via.all || 0, sum(rateOf[p.id]), false);
      for (const g of p.via.partial) add(p.server_id, g, 0, true);
    }
    for (const s of servers) {
      if (seen.has(s.id)) continue; // Server ohne Zugänge: eingestellten Weg zeigen
      const v = topo.server_via?.[s.id];
      add(s.id, v?.all || 0, 0, false);
      for (const g of v?.partial || []) add(s.id, g, 0, true);
    }
    return [...m.values()].filter((f) => f.gid === 0 || groupById[f.gid]);
  });
  const outRate = $derived.by(() => {
    const r = {};
    for (const f of flows) if (!f.partial) r[f.gid] = (r[f.gid] || 0) + f.rate;
    return r;
  });
  const exitRate = (g, id) => {
    const real = live.exits?.[id];
    if (real) return real.up + real.down;
    return g.status?.active === id ? outRate[g.id] || 0 : 0;
  };

  const STATE = {
    ok: ['ok', 'läuft'],
    failover: ['warn', 'Ausweich-Ausgang'],
    blocked: ['bad', 'gesperrt – alle Ausgänge gestört'],
    direct: ['warn', 'direkt – alle Ausgänge gestört'],
    waiting: ['muted', 'wird geprüft'],
  };
  function exitHealth(e) {
    const s = e.status;
    if (!e.enabled) return 'muted';
    if (!s || !s.checked) return 'muted';
    if (!s.up || s.error) return 'bad';
    if (s.loss > 10 || s.rtt > 300) return 'warn';
    return 'ok';
  }

  // ---------- Linien ----------
  const curve = (x1, y1, x2, y2) => {
    const d = Math.max(40, (x2 - x1) * 0.45);
    return `M${x1},${y1} C${x1 + d},${y1} ${x2 - d},${y2} ${x2},${y2}`;
  };
  const width = (rate) => (rate > 0 ? 1.5 + Math.min(3.6, Math.log10(1 + rate / 800) * 1.05) : 1.4);
  const moving = (rate) => rate > 1500;

  // ---------- Auswahl ----------
  let sel = $state(null); // {kind: 'peer'|'user'|'server'|'group'|'direct', id}
  const isSel = (kind, id) => sel?.kind === kind && sel.id === id;
  function pick(kind, id) {
    sel = isSel(kind, id) ? null : { kind, id };
  }
  function peerHot(p) {
    if (!sel) return true;
    if (sel.kind === 'peer') return sel.id === p.id || selReach.has(p.id);
    if (sel.kind === 'user') return sel.id === p.user_id;
    if (sel.kind === 'server') return sel.id === p.server_id;
    if (sel.kind === 'group') return p.via.all === sel.id || p.via.partial.includes(sel.id);
    if (sel.kind === 'direct') return !p.via.all;
    return true;
  }
  function flowHot(f) {
    if (!sel) return true;
    const tgt = (p) => (f.partial ? p.via.partial.includes(f.gid) : (p.via.all || 0) === f.gid);
    if (sel.kind === 'peer') {
      const p = peerById[sel.id];
      return !!p && p.server_id === f.sid && tgt(p);
    }
    if (sel.kind === 'user') return topo.peers.some((p) => p.user_id === sel.id && p.server_id === f.sid && tgt(p));
    if (sel.kind === 'server') return sel.id === f.sid;
    if (sel.kind === 'group') return sel.id === f.gid;
    if (sel.kind === 'direct') return f.gid === 0;
    return true;
  }
  const selPeer = $derived(sel?.kind === 'peer' ? peerById[sel.id] : null);
  const selReach = $derived(new Set(selPeer?.reach || []));

  const SCOPE_TEXT = { peer: 'Regel am Gerät', user: 'Regel am Nutzer', server: 'Regel bzw. Einstellung am Server', global: 'Regel für alle' };
  function viaText(v) {
    if (!v) return 'direkt über den Server';
    let t = v.all ? `alles über Gruppe „${groupById[v.all]?.name || '?'}“` : 'direkt über den Server';
    if (v.all && v.scope) t += ` (${SCOPE_TEXT[v.scope]})`;
    if (v.partial.length) t += `; bestimmte Ziele über ${v.partial.map((g) => `„${groupById[g]?.name || '?'}“`).join(', ')}`;
    return t;
  }

  // ---------- Ziehen ----------
  let stage;
  let drag = $state(null); // {kind, id, x0, y0, x, y, moved}
  let over = $state(null); // {kind, id} – Ziel unter dem Zeiger
  function point(e) {
    const r = stage.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }
  function startDrag(e, kind, id, x0, y0) {
    if (e.button !== 0) return;
    e.preventDefault();
    const p = point(e);
    drag = { kind, id, x0, y0, x: p.x, y: p.y, sx: p.x, sy: p.y, moved: false };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp, { once: true });
  }
  function onMove(e) {
    if (!drag) return;
    const p = point(e);
    drag.x = p.x;
    drag.y = p.y;
    if (!drag.moved && Math.hypot(p.x - drag.sx, p.y - drag.sy) > 7) drag.moved = true;
    if (drag.moved) {
      const el = document.elementFromPoint(e.clientX, e.clientY)?.closest?.('[data-drop]');
      const [kind, id] = (el?.dataset.drop || '').split(':');
      over = kind ? { kind, id: Number(id) } : null;
    }
  }
  async function onUp() {
    window.removeEventListener('pointermove', onMove);
    const d = drag;
    const t = over;
    drag = null;
    over = null;
    if (!d) return;
    if (!d.moved) return pick(d.kind, d.id);
    if (!t || !canDrop(d, t)) return;
    if (t.kind === 'group' || t.kind === 'direct') await assign(d, t);
    else if (t.kind === 'peer') await reach(d.id, t.id);
  }
  function canDrop(d, t) {
    if (!d?.moved || !t) return false;
    if (t.kind === 'group' || t.kind === 'direct') return true;
    if (t.kind === 'peer' && d.kind === 'peer' && d.id !== t.id) {
      const a = peerById[d.id];
      const b = peerById[t.id];
      return !!a && !!b && a.protocol === 'wireguard' && a.server_id === b.server_id;
    }
    return false;
  }
  const dropOk = (kind, id) => drag?.moved && canDrop(drag, { kind, id });

  function srcName(d) {
    if (d.kind === 'peer') {
      const p = peerById[d.id];
      return `Gerät „${p?.name}“ (${userById[p?.user_id]?.name || '?'})`;
    }
    if (d.kind === 'user') return `Nutzer „${userById[d.id]?.name}“ (alle Zugänge)`;
    return `Server „${serverById[d.id]?.name}“ (alle Zugänge)`;
  }
  async function assign(d, t) {
    const g = t.kind === 'group' ? groupById[t.id] : null;
    const ok = await confirmDialog({
      title: g ? `Über Gruppe „${g.name}“ leiten?` : 'Direkt über den Server leiten?',
      text: g
        ? `${srcName(d)}: Der gesamte Verkehr läuft danach über die Ausgangsgruppe „${g.name}“. Regeln für bestimmte Ziele bleiben bestehen. Du findest die Regel unter „Proxy & Ausgänge“ → Ziel-Regeln.`
        : `${srcName(d)}: Der Verkehr geht danach direkt über den Server hinaus. Regeln für bestimmte Ziele bleiben bestehen.`,
      ok: 'Zuweisen',
    });
    if (!ok) return;
    if (await run(() => post('/routes/assign', { scope: d.kind, scope_id: d.id, group: g ? g.id : 0 }), 'Ausgang zugewiesen')) setTimeout(load, 600);
  }
  async function reach(from, to) {
    const a = peerById[from];
    const b = peerById[to];
    const has = (a.reach || []).includes(to);
    const ok = await confirmDialog({
      title: has ? 'Zugriff entziehen?' : 'Zugriff erlauben?',
      text: has
        ? `„${a.name}“ darf „${b.name}“ danach nicht mehr erreichen. Der Zugriff von „${a.name}“ wird dabei auf „Ausgewählte Geräte“ umgestellt.`
        : `„${a.name}“ darf „${b.name}“ danach erreichen (Antworten kommen immer zurück). Der Zugriff von „${a.name}“ wird dabei auf „Ausgewählte Geräte“ umgestellt.`,
      ok: has ? 'Entziehen' : 'Erlauben',
      danger: has,
    });
    if (!ok) return;
    if (await run(() => post(`/peers/${from}/reach`, { target: to, allow: !has }), has ? 'Zugriff entzogen' : 'Zugriff erlaubt')) {
      sel = { kind: 'peer', id: from };
      setTimeout(load, 600);
    }
  }

  // lange Namenslisten kürzen: „a, b, c … und 40 weitere“
  const short = (l, n = 8) => (l.length > n ? `${l.slice(0, n).join(', ')} … und ${l.length - n} weitere` : l.join(', '));

  const KIND_ICON ={ client: 'phone', server: 'server', site: 'network', access: 'key' };
  const total = $derived(live.total || {});
  const srvRate = (id) => topo.peers.filter((p) => p.server_id === id).reduce((a, p) => a + sum(rateOf[p.id]), 0);
  const onlineN = $derived(topo.peers.filter((p) => p.online).length);
</script>

<div class="grid cols-4 facts">
  <div class="card card-pad"><div class="muted small">Geräte online</div><div class="strong big">{onlineN} <span class="muted small">/ {topo.peers.length}</span></div></div>
  <div class="card card-pad">
    <div class="muted small">Verkehr gerade</div>
    <div class="strong big">↓ {speed(total.down)}</div>
    <div class="tiny muted">↑ {speed(total.up)}</div>
  </div>
  <div class="card card-pad">
    <div class="muted small">Server</div>
    <div class="strong big">{servers.filter((s) => s.enabled && s.status?.running).length} <span class="muted small">/ {servers.filter((s) => s.enabled).length} laufen</span></div>
  </div>
  <div class="card card-pad">
    <div class="muted small">Ausgänge</div>
    <div class="strong big">
      {ex.exits.filter((e) => exitHealth(e) === 'ok').length} <span class="muted small">/ {ex.exits.filter((e) => e.enabled).length} verbunden</span>
    </div>
  </div>
</div>

<!-- Wo hakt es? -->
<div class="issues">
  {#if !topo.issues.length}
    <div class="card row ok-line"><Icon name="check" size={16} /> <span>{loaded ? 'Keine Störungen – alle Server, Ausgänge und Regeln arbeiten.' : 'Lädt …'}</span></div>
  {:else}
    <Fold id="net-issues" icon="alert" tone={topo.issues.some((i) => i.level === 'bad') ? 'bad' : 'warn'} title={topo.issues.length === 1 ? 'Eine Auffälligkeit' : `${topo.issues.length} Auffälligkeiten`}>
      <div class="ilist">
        {#each topo.issues as i}
          <div class="issue {i.level}">
            <span class="dotl"></span>
            <span class="grow">{i.text}</span>
            {#if i.link}<a class="small" href={i.link}>Ansehen</a>{/if}
          </div>
        {/each}
      </div>
    </Fold>
  {/if}
</div>

<div class="card">
  <div class="card-head">
    <div>
      <h2>Karte <Info title="Bedienung der Karte">
        <ul>
          <li>Anklicken zeigt den Weg vom Gerät über den Server zum Ausgang.</li>
          <li>Gerät, Nutzer oder Server auf eine Gruppe ziehen = Ausgang zuweisen (legt eine Ziel-Regel an).</li>
          <li>WireGuard-Gerät auf ein anderes desselben Servers ziehen = Zugriff erlauben oder entziehen.</li>
        </ul>
      </Info></h2>
    </div>
    <div class="row wrap" style="gap:10px;justify-content:flex-end">
      <SearchInput bind:value={tq} placeholder="Nutzer, Gerät, Dienst, Server …" width="250px" />
      {#if toks.length}
        <span class="muted small">{hitCount} {hitCount === 1 ? 'Treffer' : 'Treffer'}</span>
      {:else}
        <label class="switch small"><input type="checkbox" checked={withOffline} onchange={(e) => (showOffline = e.currentTarget.checked)} /><span class="track"></span> Offline-Geräte zeigen</label>
      {/if}
    </div>
  </div>
  <div class="scroll">
    <div class="stage" bind:this={stage} style="width:{W}px;height:{layout.H}px" class:dragging={drag?.moved}>
      <svg width={W} height={layout.H} aria-hidden="true">
        <!-- Gerät → Server -->
        {#each layout.rows.filter((r) => r.type === 'peer') as r (r.p.id)}
          {@const p = r.p}
          {@const rt = sum(rateOf[p.id])}
          {#if layout.srvY[p.server_id] != null}
            <path
              d={curve(COL.dev + COL.devW, layout.peerY[p.id], COL.srv, layout.srvY[p.server_id])}
              class="edge"
              class:on={p.online}
              class:flow={moving(rt)}
              class:off={!p.active || !p.enabled}
              class:dim={sel?.kind === 'peer' ? sel.id !== p.id : !peerHot(p)}
              style="stroke-width:{width(rt)}"
            />
          {/if}
        {/each}
        <!-- kompakt: Nutzer → Server, gebündelt -->
        {#each layout.bundles as b (b.uid + ':' + b.sid)}
          {@const rt = b.ps.reduce((a, p) => a + sum(rateOf[p.id]), 0)}
          {#if layout.srvY[b.sid] != null}
            <path
              d={curve(COL.dev + COL.devW, b.y, COL.srv, layout.srvY[b.sid])}
              class="edge"
              class:on={b.ps.some((p) => p.online)}
              class:flow={moving(rt)}
              class:off={b.ps.every((p) => !p.active || !p.enabled)}
              class:dim={!b.ps.some((p) => peerHot(p))}
              style="stroke-width:{width(rt)}"
            />
          {/if}
        {/each}
        <!-- Server → Ausgang -->
        {#each flows as f (f.sid + ':' + f.gid + (f.partial ? 'p' : ''))}
          {#if layout.srvY[f.sid] != null && layout.outY[f.gid] != null}
            {@const g = groupById[f.gid]}
            <path
              d={curve(COL.srv + COL.srvW, layout.srvY[f.sid], COL.out, layout.outY[f.gid])}
              class="edge out"
              class:on={f.n > 0}
              class:flow={moving(f.rate)}
              class:partial={f.partial}
              class:bad={g && (g.status?.state === 'blocked' || !g.enabled)}
              class:dim={!flowHot(f)}
              style="stroke-width:{width(f.rate)}"
            />
          {/if}
        {/each}
        <!-- Ausgang → Internet -->
        {#each layout.outs as o (o.id)}
          {@const rt = outRate[o.id] || 0}
          {@const blocked = o.type === 'group' && (o.g.status?.state === 'blocked' || !o.g.enabled)}
          <path
            d={curve(COL.out + COL.outW, layout.outY[o.id], COL.net, layout.H / 2)}
            class="edge out"
            class:on={!blocked}
            class:bad={blocked}
            class:flow={moving(rt) && !blocked}
            class:dim={sel && !((sel.kind === 'group' && sel.id === o.id) || (sel.kind === 'direct' && o.id === 0) || flows.some((f) => f.gid === o.id && !f.partial && flowHot(f)))}
            style="stroke-width:{width(rt)}"
          />
        {/each}
        <!-- Zugriff des gewählten WireGuard-Geräts -->
        {#if selPeer}
          {#each [...selReach].filter((id) => layout.peerY[id] != null) as id (id)}
            {@const y1 = layout.peerY[selPeer.id]}
            {@const y2 = layout.peerY[id]}
            <path d="M{COL.dev},{y1} C{COL.dev - 34},{y1} {COL.dev - 34},{y2} {COL.dev},{y2}" class="reach" />
          {/each}
        {/if}
        <!-- Linie beim Ziehen -->
        {#if drag?.moved}
          <path d="M{drag.x0},{drag.y0} L{drag.x},{drag.y}" class="dragline" class:ok={over && canDrop(drag, over)} />
        {/if}
      </svg>

      <!-- Geräte -->
      {#each layout.rows as r (r.type + (r.type === 'user' ? r.u.id : r.type === 'more' ? '' : r.p.id))}
        {#if r.type === 'more'}
          <div class="morerow" style="left:{COL.dev}px;top:{r.y}px;width:{COL.devW}px">
            <button type="button" class="btn sm" onclick={() => (limit += 25)}><Icon name="plus" size={14} /> {Math.min(25, r.n)} weitere von {r.n}</button>
            <span class="tiny muted">oder oben suchen</span>
          </div>
        {:else if r.type === 'user'}
          {@const u = r.u}
          {@const urate = r.collapsed ? r.ps.reduce((a, p) => a + sum(rateOf[p.id]), 0) : 0}
          <div
            class="urow"
            class:compact={r.collapsed}
            class:sel={isSel('user', u.id)}
            class:dim={r.collapsed && !r.ps.some((p) => peerHot(p))}
            style="left:{COL.dev}px;top:{r.y}px;width:{COL.devW}px"
            onpointerdown={(e) => startDrag(e, 'user', u.id, COL.dev + COL.devW, r.y + (r.collapsed ? 15 : 14))}
            role="button"
            tabindex="0"
            onkeydown={(e) => e.key === 'Enter' && pick('user', u.id)}
            title="Nutzer – ziehen, um alle seine Zugänge über eine Gruppe zu leiten"
          >
            {#if compact}
              <button type="button" class="ux" class:open={!r.collapsed} onpointerdown={(e) => e.stopPropagation()} onclick={() => toggleUser(u.id)} title={r.collapsed ? 'Geräte zeigen' : 'Geräte einklappen'} aria-label="Geräte zeigen"><Icon name="chevron" size={14} /></button>
            {:else}
              <Icon name="user" size={14} />
            {/if}
            {#if r.collapsed}<span class="dot" class:on={r.ps.some((p) => p.online)}></span>{/if}
            <span class="grow strong ellipsis">{u.name}</span>
            {#if u.status && u.status !== 'ok'}<span class="badge {u.status === 'throttled' ? 'warn' : 'bad'}">{{ throttled: 'gedrosselt', blocked: 'gesperrt', expired: 'abgelaufen', disabled: 'aus' }[u.status] || u.status}</span>{/if}
            {#if r.collapsed}
              {#each [...new Set(r.ps.map((p) => p.protocol))] as pr}<ProtoLogo id={pr} size={14} />{/each}
              <span class="tiny muted">{r.n}</span>
              {#if urate > 0}<span class="rate">{speed(urate)}</span>{/if}
            {/if}
          </div>
        {:else}
          {@const p = r.p}
          {@const rt = rateOf[p.id]}
          <div
            class="prow"
            class:sel={isSel('peer', p.id)}
            class:dim={!peerHot(p)}
            class:offp={!p.active || !p.enabled}
            class:drop={dropOk('peer', p.id)}
            class:over={over?.kind === 'peer' && over.id === p.id && dropOk('peer', p.id)}
            style="left:{COL.dev}px;top:{r.y}px;width:{COL.devW}px;height:{ROW - 2}px"
            onpointerdown={(e) => startDrag(e, 'peer', p.id, COL.dev + COL.devW, r.y + ROW / 2)}
            data-drop="peer:{p.id}"
            role="button"
            tabindex="0"
            onkeydown={(e) => e.key === 'Enter' && pick('peer', p.id)}
          >
            <span class="dot" class:on={p.online}></span>
            <ProtoLogo id={p.protocol} size={15} />
            <span class="grow name">{p.name}</span>
            {#if p.via.all || p.via.partial.length}<span class="viatag" title={viaText(p.via)}><Icon name="route" size={11} /></span>{/if}
            {#if sum(rt) > 0}<span class="rate">{speed(sum(rt))}</span>{:else if !p.enabled}<span class="rate muted">aus</span>{:else if !p.active}<span class="rate muted">gesperrt</span>{/if}
          </div>
        {/if}
      {/each}

      <!-- Server -->
      {#each servers as s (s.id)}
        {#if layout.srvY[s.id] != null}
          {@const up = s.status?.running}
          <div
            class="node srv"
            class:sel={isSel('server', s.id)}
            class:bad={s.enabled && !up}
            class:offn={!s.enabled}
            style="left:{COL.srv}px;top:{layout.srvY[s.id] - layout.SH / 2}px;width:{COL.srvW}px;height:{layout.SH}px"
            onpointerdown={(e) => startDrag(e, 'server', s.id, COL.srv + COL.srvW, layout.srvY[s.id])}
            role="button"
            tabindex="0"
            onkeydown={(e) => e.key === 'Enter' && pick('server', s.id)}
            title={s.status?.detail || ''}
          >
            <ProtoLogo id={s.protocol} size={26} />
            <div class="grow">
              <div class="strong name">{s.name}</div>
              <div class="tiny muted">{#if !s.enabled}deaktiviert{:else if !up}läuft nicht{:else}{s.online} / {s.peers} online{/if}</div>
              {#if srvRate(s.id) > 0}<div class="tiny rate">{speed(srvRate(s.id))}</div>{/if}
            </div>
            <span class="dot" class:on={up} class:badd={s.enabled && !up}></span>
          </div>
        {/if}
      {/each}

      <!-- Ausgänge -->
      {#each layout.outs as o (o.id)}
        {#if o.type === 'direct'}
          <div
            class="node outn"
            class:sel={isSel('direct', 0)}
            class:drop={dropOk('direct', 0)}
            class:over={over?.kind === 'direct' && dropOk('direct', 0)}
            style="left:{COL.out}px;top:{o.y}px;width:{COL.outW}px;height:{o.h}px"
            onclick={() => pick('direct', 0)}
            data-drop="direct:0"
            role="button"
            tabindex="0"
            onkeydown={(e) => e.key === 'Enter' && pick('direct', 0)}
          >
            <span class="ic"><Icon name="server" size={18} /></span>
            <div class="grow">
              <div class="strong">Direkt</div>
              <div class="tiny muted name" title={meta.server_host}>über den Server</div>
            </div>
            {#if outRate[0] > 0}<span class="rate">{speed(outRate[0])}</span>{/if}
          </div>
        {:else}
          {@const g = o.g}
          {@const st = g.enabled ? STATE[g.status?.state || 'waiting'] || STATE.waiting : ['muted', 'deaktiviert']}
          <div
            class="node grp"
            class:sel={isSel('group', g.id)}
            class:bad={st[0] === 'bad'}
            class:warn={st[0] === 'warn'}
            class:drop={dropOk('group', g.id)}
            class:over={over?.kind === 'group' && over.id === g.id && dropOk('group', g.id)}
            style="left:{COL.out}px;top:{o.y}px;width:{COL.outW}px;height:{o.h}px"
            onclick={() => pick('group', g.id)}
            data-drop="group:{g.id}"
            role="button"
            tabindex="0"
            onkeydown={(e) => e.key === 'Enter' && pick('group', g.id)}
          >
            <div class="ghead">
              <span class="ic"><Icon name="route" size={16} /></span>
              <div class="grow">
                <div class="strong name">{g.name}</div>
                <div class="tiny {st[0] === 'ok' ? 'muted' : st[0] + '-t'}">{st[1]}</div>
              </div>
              {#if outRate[g.id] > 0}<span class="rate">{speed(outRate[g.id])}</span>{/if}
            </div>
            {#each g.exits as id, i}
              {@const e = exitById[id]}
              {#if e}
                <div class="exit" class:act={g.status?.active === id} title={e.status?.error || ''}>
                  <span class="dot {exitHealth(e)}"></span>
                  <span class="grow name">{i + 1}. {e.name}</span>
                  {#if exitRate(g, id) > 0}<span class="rate">{speed(exitRate(g, id))}</span>{:else if e.status?.up}<span class="tiny muted">{fmtNum(Math.round(e.status.rtt))} ms{e.status.loc ? ' · ' + e.status.loc : ''}</span>{/if}
                </div>
              {/if}
            {/each}
          </div>
        {/if}
      {/each}

      <!-- Internet -->
      <div class="inet" style="left:{COL.net}px;top:{layout.H / 2 - 40}px">
        <span class="globe"><Icon name="globe" size={30} /></span>
        <div class="strong small">Internet</div>
      </div>

      {#if loaded && !topo.peers.length}
        <div class="hint" style="left:{COL.dev}px;top:40px;width:{COL.devW}px">Noch keine Geräte – lege unter „Nutzer“ Zugänge an.</div>
      {:else if loaded && !layout.rows.length}
        <div class="hint" style="left:{COL.dev}px;top:40px;width:{COL.devW}px">Gerade ist kein Gerät online.</div>
      {/if}
    </div>
  </div>
  <div class="legend tiny muted">
    <span><i class="ln on"></i> verbunden</span><span><i class="ln flowl"></i> Verkehr fließt (Dicke = Menge)</span><span><i class="ln part"></i> nur bestimmte Ziele</span><span
      ><i class="ln badl"></i> gesperrt / gestört</span
    ><span><i class="ln rch"></i> darf erreichen</span>
  </div>
</div>

<!-- Auswahl -->
{#if sel}
  <div class="card card-pad detail">
    {#if sel.kind === 'peer' && selPeer}
      {@const p = selPeer}
      {@const s = serverById[p.server_id]}
      <div class="row">
        <ProtoLogo id={p.protocol} size={28} />
        <div class="grow">
          <div class="strong">{p.name} <span class="muted">· {userById[p.user_id]?.name}</span></div>
          <div class="muted tiny">{PROTO_LABEL[p.protocol]} auf „{s?.name}“{p.address ? ' · ' + p.address : ''} · {p.online ? 'online' : 'zuletzt da ' + ago(p.last_seen)}</div>
        </div>
        <a class="btn sm" href="#/users/{p.user_id}"><Icon name="edit" size={14} /> Zum Nutzer</a>
        <button class="btn sm ghost" onclick={() => (sel = null)}>Schließen</button>
      </div>
      <div class="facts2">
        <div><span class="muted">Verkehr gerade</span><b>↓ {speed(rateOf[p.id]?.down)} · ↑ {speed(rateOf[p.id]?.up)}</b></div>
        <div><span class="muted">Weg nach außen</span><b>{viaText(p.via)}</b></div>
        {#if p.protocol === 'wireguard'}
          <div>
            <span class="muted">Darf erreichen</span><b>{short((p.reach || []).map((id) => peerById[id]?.name).filter(Boolean)) || 'kein anderes Gerät'}</b>
          </div>
        {/if}
        {#if p.protocol === 'hysteria2'}<div><span class="muted">Hinweis</span><b>Hysteria2 folgt nur Regeln für den Server und „alle“ – zum Zuweisen den Server ziehen.</b></div>{/if}
        {#if !p.enabled || !p.active}<div><span class="muted">Zustand</span><b class="bad-t">{!p.enabled ? 'deaktiviert' : 'gesperrt (Limit, Ablauf oder Nutzer aus)'}</b></div>{/if}
      </div>
    {:else if sel.kind === 'user' && userById[sel.id]}
      {@const u = userById[sel.id]}
      {@const ps = topo.peers.filter((p) => p.user_id === u.id)}
      <div class="row">
        <span class="ic big"><Icon name="user" size={18} /></span>
        <div class="grow">
          <div class="strong">{u.name}</div>
          <div class="muted tiny">{ps.filter((p) => p.online).length} von {ps.length} Zugängen online{u.reason ? ' · ' + u.reason : ''}</div>
        </div>
        <a class="btn sm" href="#/users/{u.id}"><Icon name="edit" size={14} /> Zum Nutzer</a>
        <button class="btn sm ghost" onclick={() => (sel = null)}>Schließen</button>
      </div>
      <div class="facts2">
        <div><span class="muted">Verkehr gerade</span><b>{speed(ps.reduce((a, p) => a + sum(rateOf[p.id]), 0))}</b></div>
        {#each ps as p}<div><span class="muted">{p.name} ({PROTO_LABEL[p.protocol]})</span><b>{viaText(p.via)}</b></div>{/each}
      </div>
    {:else if sel.kind === 'server' && serverById[sel.id]}
      {@const s = serverById[sel.id]}
      <div class="row">
        <ProtoLogo id={s.protocol} size={28} />
        <div class="grow">
          <div class="strong">{s.name}</div>
          <div class="muted tiny">{PROTO_LABEL[s.protocol]} · {s.status?.detail || (s.status?.running ? 'läuft' : 'läuft nicht')}</div>
        </div>
        {#if s.protocol === 'wireguard'}<a class="btn sm" href="#/network/{s.id}">Geräte und Zugriff</a>{/if}
        <a class="btn sm" href="#/servers"><Icon name="edit" size={14} /> Server</a>
        <button class="btn sm ghost" onclick={() => (sel = null)}>Schließen</button>
      </div>
      <div class="facts2">
        <div><span class="muted">Verkehr gerade</span><b>{speed(srvRate(s.id))}</b></div>
        <div><span class="muted">Weg nach außen (Server-Ebene)</span><b>{viaText(topo.server_via?.[s.id])}</b></div>
        {#each flows.filter((f) => f.sid === s.id && !f.partial) as f}
          <div><span class="muted">{f.gid ? `Über „${groupById[f.gid]?.name}“` : 'Direkt'}</span><b>{f.n} {f.n === 1 ? 'Zugang' : 'Zugänge'} · {speed(f.rate)}</b></div>
        {/each}
      </div>
    {:else if sel.kind === 'group' && groupById[sel.id]}
      {@const g = groupById[sel.id]}
      {@const ps = topo.peers.filter((p) => p.via.all === g.id || p.via.partial.includes(g.id))}
      <div class="row">
        <span class="ic big"><Icon name="route" size={18} /></span>
        <div class="grow">
          <div class="strong">Ausgangsgruppe {g.name}</div>
          <div class="muted tiny">
            {g.status?.active ? `aktiv: ${exitById[g.status.active]?.name}` : 'kein aktiver Ausgang'}{g.status?.reason ? ' · ' + g.status.reason : ''} · bei Ausfall aller: {g.on_fail === 'direct'
              ? 'direkt'
              : 'sperren'}
          </div>
        </div>
        <a class="btn sm" href="#/proxy/rules"><Icon name="edit" size={14} /> Gruppen und Regeln</a>
        <button class="btn sm ghost" onclick={() => (sel = null)}>Schließen</button>
      </div>
      <div class="facts2">
        <div><span class="muted">Verkehr gerade</span><b>{speed(outRate[g.id])}</b></div>
        <div><span class="muted">Genutzt von</span><b>{ps.length ? short(ps.map((p) => `${userById[p.user_id]?.name} · ${p.name}`)) : 'niemandem'}</b></div>
      </div>
    {:else if sel.kind === 'direct'}
      <div class="row">
        <span class="ic big"><Icon name="server" size={18} /></span>
        <div class="grow">
          <div class="strong">Direkt über den Server</div>
          <div class="muted tiny">Verkehr verlässt den Server mit dessen eigener Adresse ({meta.server_host}).</div>
        </div>
        <button class="btn sm ghost" onclick={() => (sel = null)}>Schließen</button>
      </div>
      <div class="facts2">
        <div><span class="muted">Verkehr gerade</span><b>{speed(outRate[0])}</b></div>
        <div><span class="muted">Zugänge</span><b>{topo.peers.filter((p) => p.enabled && p.active && !p.via.all).length}</b></div>
      </div>
    {/if}
  </div>
{/if}

<style>
  .facts .big {
    font-size: 20px;
  }
  .issues {
    margin: 16px 0;
  }
  .ilist {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 260px;
    overflow: auto;
  }
  .ok-line {
    color: var(--ok);
    gap: 8px;
    font-size: 14px;
    padding: 10px 16px;
    border-color: var(--ok-soft);
  }
  .ihead {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--warn);
  }
  .issue {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13.5px;
  }
  .dotl {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex: none;
    background: var(--warn);
  }
  .issue.bad .dotl {
    background: var(--bad);
  }
  .scroll {
    overflow-x: auto;
    padding: 14px 16px 6px;
  }
  .stage {
    position: relative;
    margin: 0 auto;
    user-select: none;
    touch-action: none;
  }
  svg {
    position: absolute;
    inset: 0;
    overflow: visible;
    pointer-events: none;
  }
  .edge {
    fill: none;
    stroke: var(--border-strong);
    stroke-dasharray: 3 5;
    transition: opacity 0.15s;
  }
  .edge.on {
    stroke: var(--ok);
    stroke-dasharray: none;
    opacity: 0.55;
  }
  .edge.out.on {
    stroke: var(--accent);
    opacity: 0.5;
  }
  .edge.flow {
    opacity: 0.9;
    stroke-dasharray: 5 6;
    animation: flow 0.8s linear infinite;
  }
  .edge.partial {
    stroke-dasharray: 2 6;
    stroke: var(--accent);
    opacity: 0.6;
  }
  .edge.bad {
    stroke: var(--bad);
    stroke-dasharray: 4 5;
    opacity: 0.8;
  }
  .edge.off {
    stroke: var(--border-strong);
    stroke-dasharray: 2 6;
    opacity: 0.5;
  }
  .edge.dim {
    opacity: 0.07 !important;
    animation: none;
  }
  @keyframes flow {
    to {
      stroke-dashoffset: -11;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .edge.flow {
      animation: none;
    }
  }
  .reach {
    fill: none;
    stroke: var(--warn);
    stroke-width: 2;
  }
  .dragline {
    stroke: var(--muted);
    stroke-width: 2;
    stroke-dasharray: 5 5;
  }
  .dragline.ok {
    stroke: var(--accent);
    stroke-dasharray: none;
    stroke-width: 2.5;
  }
  .urow,
  .prow,
  .node {
    position: absolute;
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: grab;
    box-sizing: border-box;
  }
  .urow {
    height: 28px;
    padding: 0 8px;
    color: var(--text-2);
    border-radius: 8px;
    font-size: 13px;
  }
  .urow:hover,
  .urow.sel {
    background: var(--panel-2);
  }
  .urow.sel {
    outline: 2px solid var(--accent);
  }
  .urow.compact {
    height: 30px;
    border: 1px solid var(--border);
    background: var(--panel);
    gap: 6px;
    transition: opacity 0.15s;
  }
  .urow.dim {
    opacity: 0.3;
  }
  .urow .strong {
    min-width: 56px;
  }
  .urow.compact .badge {
    font-size: 10.5px;
    padding: 0 5px;
    height: 18px;
  }
  .ux {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    padding: 2px;
    display: grid;
    place-items: center;
    border-radius: 5px;
    transition: transform 0.15s;
  }
  .ux:hover {
    color: var(--accent);
    background: var(--panel-2);
  }
  .ux.open {
    transform: rotate(90deg);
  }
  .morerow {
    position: absolute;
    display: flex;
    align-items: center;
    gap: 10px;
    height: 34px;
  }
  .prow {
    padding: 0 8px 0 10px;
    border: 1px solid var(--border);
    background: var(--panel);
    border-radius: 8px;
    font-size: 13px;
    transition: opacity 0.15s;
  }
  .prow:hover {
    border-color: var(--border-strong);
  }
  .prow.sel {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-soft);
  }
  .prow.dim {
    opacity: 0.3;
  }
  .prow.offp .name {
    color: var(--muted);
    text-decoration: line-through;
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .rate {
    font-size: 11.5px;
    font-variant-numeric: tabular-nums;
    color: var(--accent);
    white-space: nowrap;
  }
  .rate.muted {
    color: var(--muted);
  }
  .viatag {
    color: var(--accent);
    display: inline-flex;
  }
  .node {
    padding: 8px 12px;
    border: 1px solid var(--border);
    background: var(--panel);
    border-radius: 12px;
    box-shadow: var(--shadow);
  }
  .node.sel {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-soft);
  }
  .node.bad {
    border-color: var(--bad);
    background: var(--bad-soft);
  }
  .node.warn {
    border-color: var(--warn);
  }
  .node.offn {
    opacity: 0.55;
  }
  .outn,
  .grp {
    cursor: pointer;
  }
  .grp {
    flex-direction: column;
    align-items: stretch;
    gap: 4px;
  }
  .ghead {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .exit {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12.5px;
    padding: 2px 6px;
    border-radius: 6px;
    color: var(--text-2);
    height: 20px;
  }
  .exit.act {
    background: var(--accent-soft);
    color: var(--text);
    font-weight: 600;
  }
  .ic {
    width: 30px;
    height: 30px;
    border-radius: 9px;
    background: var(--accent-soft);
    color: var(--accent);
    display: grid;
    place-items: center;
    flex: none;
  }
  .ic.big {
    width: 36px;
    height: 36px;
  }
  .dragging .drop {
    border-color: var(--accent);
    border-style: dashed;
  }
  .dragging .over {
    background: var(--accent-soft);
    border-style: solid;
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .dragging .urow,
  .dragging .prow,
  .dragging .node {
    cursor: grabbing;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--border-strong);
    flex: none;
  }
  .dot.on,
  .dot.ok {
    background: var(--ok);
  }
  .dot.warn {
    background: var(--warn);
  }
  .dot.bad,
  .dot.badd {
    background: var(--bad);
  }
  .inet {
    position: absolute;
    width: 80px;
    text-align: center;
  }
  .globe {
    width: 56px;
    height: 56px;
    margin: 0 auto 4px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background: var(--accent);
    color: #fff;
  }
  .hint {
    position: absolute;
    color: var(--muted);
    font-size: 13px;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    padding: 8px 18px 12px;
    border-top: 1px solid var(--border);
  }
  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .ln {
    display: inline-block;
    width: 22px;
    height: 0;
    border-top: 2px solid var(--border-strong);
  }
  .ln.on {
    border-color: var(--ok);
  }
  .ln.flowl {
    border-top: 4px dashed var(--accent);
  }
  .ln.part {
    border-top: 2px dotted var(--accent);
  }
  .ln.badl {
    border-top: 2px dashed var(--bad);
  }
  .ln.rch {
    border-color: var(--warn);
  }
  .detail {
    margin-top: 16px;
  }
  .facts2 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 10px 24px;
    margin-top: 12px;
    font-size: 13.5px;
  }
  .facts2 div {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .bad-t {
    color: var(--bad);
  }
  .warn-t {
    color: var(--warn);
  }
</style>
