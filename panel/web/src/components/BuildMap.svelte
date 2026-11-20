<script>
  // Netzwerk „Aufbau“: Server → Stufe 1 → Stufe 2 → Stufe 3 → Internet. Automatisch angeordnet.
  // Ziehen:
  //   Server auf Ausgang/Gruppe/„Direkt“      = Weg des Servers (Ziel-Regel „Alles“ für diesen Server)
  //   Ausgang auf Ausgang                    = über diesen verbinden (Kaskade)
  //   Ausgang auf „Direkt“                   = Kaskade aufheben
  //   Ausgang auf Gruppe                     = in die Gruppe aufnehmen (aus einer Gruppe gezogen: verschieben)
  //   Ausgang aus einer Gruppe auf „Nicht verwendet“ = aus der Gruppe nehmen
  //   „+ Ausgang“, „+ Gruppe“, „+ Server“    = anlegen (dort, wo sie landen, z. B. „+ Ausgang“ auf einen Ausgang = dahinter)
  // Eigener Weg (Nutzer und Geräte mit eigener Ziel-Regel „Alles“):
  //   „+ Nutzer/Gerät“ auf Ausgang/Gruppe/„Direkt“ = Auswahl „Für wen?“, dann Regel anlegen
  //   Nutzer/Gerät auf Ausgang/Gruppe/„Direkt“  = Weg ändern; auf „Nicht verwendet“ = eigenen Weg entfernen
  //   „+“-Griff am Ende eines gewählten Wegs     = weitere Stufe anhängen (Kaskade aus Sicht der Quelle), „−“ = letzte Stufe weg
  import Icon from './Icon.svelte';
  import ProtoLogo from './ProtoLogo.svelte';
  import Modal from './Modal.svelte';
  import Picker from './Picker.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { userItems, peerItems } from '../lib/pick.js';
  import { speed, fmtNum } from '../lib/format.js';
  import { go, intent } from '../lib/state.svelte.js';

  let servers = $state([]);
  let ex = $state({ exits: [], groups: [] });
  let rt = $state({ routes: [] });
  let live = $state({ exits: {} });
  let loaded = $state(false);

  async function load() {
    try {
      const [s, x, r] = await Promise.all([get('/servers'), get('/exits'), get('/routes')]);
      servers = s;
      ex = x;
      rt = r;
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
    const b = setInterval(poll, 3000);
    return () => {
      clearInterval(a);
      clearInterval(b);
    };
  });

  const byId = (l) => Object.fromEntries((l || []).map((x) => [x.id, x]));
  const exitById = $derived(byId(ex.exits));
  const groupById = $derived(byId(ex.groups));
  const serverById = $derived(byId(servers));
  const routes = $derived((rt.routes || []).filter((r) => r.enabled));

  // ---------- Zustand ----------
  function health(e) {
    const s = e?.status;
    if (!e?.enabled) return 'muted';
    if (!s || !s.checked) return 'muted';
    if (!s.up || s.error) return 'bad';
    if (s.loss > 10 || (s.rtt > 300 && e.type !== 'tor')) return 'warn';
    return 'ok';
  }
  const rateOf = (id) => {
    const r = live.exits?.[id];
    return r ? r.up + r.down : 0;
  };
  function exitInfo(e) {
    const r = rateOf(e.id);
    if (r > 0) return speed(r);
    if (!e.enabled) return 'deaktiviert';
    if (e.status?.error) return 'gestört';
    if (e.status?.up) return `${fmtNum(Math.round(e.status.rtt))} ms${e.status.loc ? ' · ' + e.status.loc : ''}`;
    if (e.mode === 'standby') return 'Bereitschaft';
    return e.status?.checked ? 'getrennt' : 'wird geprüft';
  }
  const TYPE = { wireguard: 'WireGuard', openvpn: 'OpenVPN', tor: 'Tor' };

  // ---------- Kaskade ----------
  // Vorgänger-Kette (nächster zuerst)
  function chainOf(e) {
    const out = [];
    const seen = new Set([e?.id]);
    for (let cur = e; cur?.via && out.length < 3; ) {
      const v = exitById[cur.via];
      if (!v || seen.has(v.id)) break;
      seen.add(v.id);
      out.push(v);
      cur = v;
    }
    return out;
  }
  const depthOf = (e) => Math.min(3, chainOf(e).length + 1);

  // ---------- Knoten ----------
  const realGroups = $derived(ex.groups.filter((g) => !g.auto));
  const inGroups = (id) => realGroups.filter((g) => g.exits.includes(id));
  // Ziel einer Regel als Knoten: „g:ID“, „e:ID“ (Ausgang allein bzw. automatische Gruppe) oder „direct“
  function ruleTarget(r) {
    if (r.group) {
      const g = groupById[r.group];
      if (!g) return 'direct';
      return g.auto ? `e:${g.auto}` : `g:${g.id}`;
    }
    const c = r.chain || [];
    return c.length ? `e:${c[c.length - 1]}` : 'direct';
  }
  const targetKeys = $derived(new Set(routes.map(ruleTarget)));
  const viaUsed = $derived(new Set(ex.exits.filter((e) => e.via && exitById[e.via]).map((e) => e.via)));
  const chainUsed = $derived(new Set(routes.flatMap((r) => r.chain || [])));

  // Ausgänge außerhalb von Gruppen: in den Spalten, wenn sie eine Rolle spielen, sonst „Nicht verwendet“
  const looseExits = $derived(ex.exits.filter((e) => !inGroups(e.id).length));
  const placed = (e) => targetKeys.has(`e:${e.id}`) || !!(e.via && exitById[e.via]) || viaUsed.has(e.id) || chainUsed.has(e.id);
  const trayExits = $derived(looseExits.filter((e) => !placed(e)));

  const NODE_W = 236;
  const SRV_W = 184;
  const GAP = 70;
  const PAD = 16;
  const TOP = 40;
  const EX_H = 52;
  const G_HEAD = 40;
  const ROW_H = 30;
  const VGAP = 14;
  const SRV_H = 52;
  const PSN_H = 44;
  const OWN_HEAD = 26;

  // eigene Regel „Alles“ einer Quelle (Server, Nutzer, Gerät) – die erste greift
  const ownRule = (scope, id) => routes.filter((r) => r.scope === scope && r.scope_id === id && r.match === 'all').sort((a, b) => a.id - b.id)[0];
  // Weg eines Servers für „Alles“: eigene Regel vor der Regel für alle
  function serverRule(s) {
    const own = ownRule('server', s.id);
    if (own) return { r: own, own: true };
    const all = routes.filter((r) => r.scope === 'global' && r.match === 'all').sort((a, b) => a.id - b.id)[0];
    return all ? { r: all, own: false } : null;
  }
  // weitere Regeln, die nur einen Teil des Verkehrs betreffen (bestimmte Ziele) – Anzeige „+n“
  const extraRules = (s) => routes.filter((r) => r.match !== 'all' && ((r.scope === 'server' && r.scope_id === s.id) || r.scope === 'global')).length;
  const personalRules = $derived(routes.filter((r) => (r.scope === 'user' || r.scope === 'peer') && r.match !== 'all').length);

  // ---------- Nutzer und Geräte mit eigenem Weg ----------
  const userById = $derived(byId(rt.users));
  const peerById = $derived(byId(rt.peers));
  function personName(kind, id) {
    if (kind === 'user') return userById[id]?.name || `Nutzer ${id}`;
    const p = peerById[id];
    return p ? `${userById[p.user_id]?.name || '?'} · ${p.name}` : `Gerät ${id}`;
  }
  const persons = $derived.by(() => {
    const seen = new Set();
    const out = [];
    for (const r of [...routes].sort((a, b) => a.id - b.id)) {
      if (r.match !== 'all' || (r.scope !== 'user' && r.scope !== 'peer')) continue;
      const key = `${r.scope[0]}${r.scope_id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const p = r.scope === 'peer' ? peerById[r.scope_id] : null;
      out.push({
        key,
        kind: r.scope,
        id: r.scope_id,
        r,
        name: personName(r.scope, r.scope_id),
        proto: p?.protocol || '',
        hy: p?.protocol === 'hysteria2',
        off: r.scope === 'user' ? userById[r.scope_id]?.enabled === false : p?.enabled === false,
      });
    }
    return out.sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'user' ? -1 : 1));
  });
  // Quelle aus Schlüssel „s12“, „u3“, „p7“
  const KIND = { s: 'server', u: 'user', p: 'peer' };
  const srcOf = (key) => ({ kind: KIND[key[0]], id: Number(key.slice(1)) });
  const srcKeyOf = (s) => (s && (s.kind === 'server' || s.kind === 'user' || s.kind === 'peer') ? `${s.kind[0]}${s.id}` : '');
  function srcName(src) {
    if (src.kind === 'server') return `„${serverById[src.id]?.name || '?'}“`;
    return `${src.kind === 'user' ? 'Nutzer' : 'Gerät'} „${personName(src.kind, src.id)}“`;
  }

  // Knoten, der einen Ausgang zeigt (eigene Karte oder Zeile der ersten Gruppe)
  const nodeOfExit = (id) => {
    const g = inGroups(id)[0];
    return g ? `g:${g.id}` : `e:${id}`;
  };
  // erste Stufe auf dem Weg zu einem Ziel
  function firstOf(key) {
    if (key === 'direct') return 'direct';
    let e = null;
    if (key[0] === 'e') e = exitById[Number(key.slice(2))];
    else {
      const g = groupById[Number(key.slice(2))];
      e = exitById[g?.status?.active] || exitById[g?.exits?.[0]];
    }
    if (!e) return key;
    const c = chainOf(e);
    return c.length ? nodeOfExit(c[c.length - 1].id) : key;
  }

  const view = $derived.by(() => {
    // Knoten der Stufen
    const nodes = {};
    for (const g of realGroups) {
      const d = Math.max(1, ...g.exits.map((id) => (exitById[id] ? depthOf(exitById[id]) : 1)));
      nodes[`g:${g.id}`] = { key: `g:${g.id}`, kind: 'group', id: g.id, g, depth: d, h: G_HEAD + Math.max(1, g.exits.length) * ROW_H + 8 };
    }
    for (const e of looseExits) if (placed(e)) nodes[`e:${e.id}`] = { key: `e:${e.id}`, kind: 'exit', id: e.id, e, depth: depthOf(e), h: EX_H };
    const stages = Math.max(1, ...Object.values(nodes).map((n) => n.depth));
    const colX = (i) => PAD + SRV_W + GAP + (i - 1) * (NODE_W + GAP); // Stufe i
    const netX = colX(stages + 1);
    const W = netX + 120 + PAD;

    // Kanten: Kaskade (Vorgänger → Nachfolger)
    const edges = [];
    const seen = new Set();
    const anchor = {}; // Ausgang → {key, row}
    for (const e of ex.exits) {
      if (!e.via || !exitById[e.via]) continue;
      const to = inGroups(e.id).map((g) => `g:${g.id}`);
      if (!to.length && nodes[`e:${e.id}`]) to.push(`e:${e.id}`);
      for (const t of to) {
        const k = `${e.via}>${t}`;
        if (seen.has(k)) continue;
        seen.add(k);
        edges.push({ kind: 'via', from: e.via, to: t });
      }
    }

    // Server und ihr Weg
    const srv = servers.map((s, i) => {
      const sr = serverRule(s);
      const target = sr ? ruleTarget(sr.r) : 'direct';
      return { key: `s${s.id}`, kind: 'server', id: s.id, name: s.name, s, sr, target, first: firstOf(target), y: TOP + i * (SRV_H + VGAP), h: SRV_H };
    });
    // darunter: Nutzer und Geräte mit eigenem Weg
    const ownTop = TOP + srv.length * (SRV_H + VGAP) + (srv.length ? 10 : 0);
    const psn = persons.map((p, i) => {
      const target = ruleTarget(p.r);
      return { ...p, target, first: firstOf(target), y: ownTop + OWN_HEAD + i * (PSN_H + VGAP), h: PSN_H };
    });
    const src = [...srv, ...psn];

    // Anordnung: je Stufe nach der mittleren Höhe der Vorgänger, sonst untereinander
    const pos = {};
    const center = (key) => (pos[key] ? pos[key].y + (nodes[key]?.kind === 'group' ? G_HEAD / 2 : nodes[key] ? EX_H / 2 : 23) : null);
    const exitY = (id) => {
      const k = nodeOfExit(id);
      const p = pos[k];
      if (!p) return null;
      if (k[0] === 'g') {
        const i = groupById[Number(k.slice(2))].exits.indexOf(id);
        return p.y + G_HEAD + i * ROW_H + ROW_H / 2;
      }
      return p.y + EX_H / 2;
    };
    let bottom = psn.length ? psn[psn.length - 1].y + PSN_H : ownTop + OWN_HEAD + 34;
    let directY = null;
    for (let d = 1; d <= stages; d++) {
      const list = Object.values(nodes).filter((n) => n.depth === d);
      for (const n of list) {
        const ys = [];
        for (const x of src) if (x.first === n.key) ys.push(x.y + x.h / 2);
        for (const ed of edges) if (ed.to === n.key) {
          const y = exitY(ed.from);
          if (y != null) ys.push(y);
        }
        n.bary = ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : Infinity;
      }
      list.sort((a, b) => a.bary - b.bary || a.key.localeCompare(b.key));
      let cur = TOP;
      for (const n of list) {
        const want = Number.isFinite(n.bary) ? n.bary - (n.kind === 'group' ? G_HEAD / 2 : n.h / 2) : cur;
        const y = Math.max(cur, want);
        pos[n.key] = { x: colX(d), y };
        cur = y + n.h + VGAP;
      }
      if (d === 1) {
        const ds = src.filter((x) => x.first === 'direct').map((x) => x.y + x.h / 2);
        const want = ds.length ? ds.reduce((a, b) => a + b, 0) / ds.length - 23 : cur;
        directY = Math.max(cur, want);
        pos.direct = { x: colX(1), y: directY };
        cur = directY + 46 + VGAP;
      }
      bottom = Math.max(bottom, cur - VGAP);
    }

    // Wege der Quellen (für Hervorhebung und Farbe)
    const pathEdges = {}; // Quelle („s12“, „u3“, „p7“) → Set der Kanten
    const terminals = new Set();
    for (const x of src) {
      const set = new Set([`${x.key}>${x.first}`]);
      terminals.add(x.target);
      if (x.target !== 'direct') {
        let e = x.target[0] === 'e' ? exitById[Number(x.target.slice(2))] : exitById[groupById[Number(x.target.slice(2))]?.status?.active] || exitById[groupById[Number(x.target.slice(2))]?.exits?.[0]];
        let to = x.target;
        for (const v of e ? chainOf(e) : []) {
          set.add(`${v.id}>${to}`);
          to = nodeOfExit(v.id);
        }
      }
      set.add(`${x.target}>net`);
      pathEdges[x.key] = set;
    }
    // Ins Internet: Ziele von Regeln und Knoten ohne Nachfolger
    const sources = new Set(edges.map((ed) => nodeOfExit(ed.from)));
    const netFrom = Object.keys(nodes).filter((k) => targetKeys.has(k) || !sources.has(k));
    netFrom.push('direct');
    const ncs = netFrom.map(center).filter((y) => y != null);
    const netY = Math.max(TOP, (ncs.length ? ncs.reduce((a, b) => a + b, 0) / ncs.length : TOP) - 23);
    bottom = Math.max(bottom, netY + 46);

    return { nodes, pos, srv, psn, src, ownTop, edges, stages, colX, netX, W, H: bottom + 20, pathEdges, netFrom, netY, exitY, center, terminals };
  });

  // ---------- Linien ----------
  const curve = (x1, y1, x2, y2) => {
    const d = Math.max(30, (x2 - x1) * 0.45);
    return `M${x1},${y1} C${x1 + d},${y1} ${x2 - d},${y2} ${x2},${y2}`;
  };
  const lines = $derived.by(() => {
    const v = view;
    const out = [];
    const on = (id) => [...Object.values(v.pathEdges)].some((s) => s.has(id));
    const hot = (id) => (selSrc ? v.pathEdges[selSrc]?.has(id) : null);
    const leftY = (key) => v.center(key);
    for (const x of v.src) {
      const id = `${x.key}>${x.first}`;
      const p = v.pos[x.first];
      if (!p) continue;
      out.push({ id, d: curve(PAD + SRV_W, x.y + x.h / 2, p.x, leftY(x.first)), on: on(id), hot: hot(id), direct: x.first === 'direct', psn: x.kind !== 'server' });
    }
    for (const ed of v.edges) {
      const y1 = v.exitY(ed.from);
      const fk = nodeOfExit(ed.from);
      const p1 = v.pos[fk];
      const p2 = v.pos[ed.to];
      if (y1 == null || !p1 || !p2) continue;
      const id = `${ed.from}>${ed.to}`;
      out.push({ id, d: curve(p1.x + NODE_W, y1, p2.x, leftY(ed.to)), on: on(id), hot: hot(id), via: true });
    }
    for (const k of v.netFrom) {
      const p = v.pos[k];
      if (!p) continue;
      const id = `${k}>net`;
      const y = k === 'direct' || !v.nodes[k] ? p.y + 23 : v.center(k);
      out.push({ id, d: curve(p.x + NODE_W, y, v.netX, v.netY + 23), on: on(id), hot: hot(id), direct: k === 'direct' });
    }
    return out;
  });

  // ---------- Auswahl ----------
  let sel = $state(null); // {kind: 'server'|'user'|'peer'|'exit'|'group'|'direct', id}
  // gewählte oder gezeigte Quelle („s12“, „u3“, „p7“); beim Ziehen nichts abdunkeln – alle Ziele bleiben gut sichtbar
  const selSrc = $derived(drag?.moved ? '' : srcKeyOf(sel) || hoverSrc);
  let hoverSrc = $state('');
  const isSel = (kind, id) => sel?.kind === kind && sel.id === id;
  function pick(kind, id) {
    sel = isSel(kind, id) ? null : { kind, id };
  }
  // Knoten auf dem Weg der gewählten Quelle
  const onPath = (key) => {
    if (!selSrc) return true;
    const set = view.pathEdges[selSrc];
    if (!set) return false;
    // „e:ID“ bzw. Ausgangs-ID → Knoten, der den Ausgang zeigt (Ausgang in einer Gruppe: die Gruppe)
    const nk = (s) => (s.startsWith('e:') ? nodeOfExit(Number(s.slice(2))) : /^\d+$/.test(s) ? nodeOfExit(Number(s)) : s);
    for (const id of set) {
      const [a, b] = id.split('>');
      if (nk(a) === key || nk(b) === key) return true;
    }
    return false;
  };

  // ---------- Ziehen ----------
  let drag = $state(null); // {kind, id, from, label, x, y, moved}
  let over = $state(null); // {kind, id}
  function startDrag(ev, kind, id, label, from = 0) {
    if (ev.button !== 0) return;
    ev.stopPropagation();
    drag = { kind, id, from, label, x: ev.clientX, y: ev.clientY, sx: ev.clientX, sy: ev.clientY, moved: false };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp, { once: true });
  }
  function onMove(ev) {
    if (!drag) return;
    drag.x = ev.clientX;
    drag.y = ev.clientY;
    if (!drag.moved && Math.hypot(ev.clientX - drag.sx, ev.clientY - drag.sy) > 5) drag.moved = true;
    const el = document.elementFromPoint(ev.clientX, ev.clientY)?.closest('[data-drop]');
    if (el) {
      const [kind, id] = el.dataset.drop.split(':');
      over = { kind, id: Number(id) || 0 };
    } else over = null;
  }
  async function onUp() {
    window.removeEventListener('pointermove', onMove);
    const d = drag;
    const t = over;
    drag = null;
    over = null;
    if (!d) return;
    if (!d.moved) {
      // Klick
      if (d.kind.startsWith('new-')) create(d.kind.slice(4), { kind: 'canvas', id: 0 });
      else if (d.kind !== 'extend') pick(d.kind, d.id);
      return;
    }
    if (t && canDrop(d, t)) await act(d, t);
  }

  const isPath = (t) => ['group', 'exit', 'direct'].includes(t.kind) && (t.kind !== 'group' || !!groupById[t.id]?.exits.length);
  // Ziel als Schlüssel ↔ als {kind, id}
  const keyToT = (key) => (key === 'direct' ? { kind: 'direct', id: 0 } : { kind: key[0] === 'g' ? 'group' : 'exit', id: Number(key.slice(2)) });
  const srcEntry = (key) => view.src.find((x) => x.key === key);
  const curStages = (key) => {
    const x = srcEntry(key);
    return x ? stagesTo(keyToT(x.target)) : [];
  };
  // „+“-Griff: Stufen nach dem Anhängen von t; Widerspruch, wenn der Ausgang schon einen anderen Weg hat
  function extended(key, t) {
    const cur = curStages(key);
    if (!cur.length) return stagesTo(t);
    return [...cur, { kind: t.kind === 'group' ? 'group' : 'exit', id: t.id }];
  }
  function extendConflict(key, t) {
    if (t.kind !== 'exit') return '';
    const cur = curStages(key);
    if (!cur.length) return '';
    const b = exitById[t.id];
    const last = cur[cur.length - 1].id;
    if (cur.some((s) => s.kind === 'exit' && s.id === t.id)) return `„${b?.name}“ liegt schon auf diesem Weg.`;
    if (b && b.via && b.via !== last) return `„${b.name}“ läuft schon über „${exitById[b.via]?.name || '?'}“ – ein Ausgang hat nur einen Weg. Für diesen Weg einen zweiten Ausgang anlegen.`;
    return '';
  }

  function canDrop(d, t) {
    if (!d || !t) return false;
    if (d.kind === 'new-person') return isPath(t) || t.kind === 'canvas';
    if (d.kind.startsWith('new-')) return true;
    if (d.kind === 'server') return isPath(t);
    if (d.kind === 'user' || d.kind === 'peer') return isPath(t) || t.kind === 'tray';
    if (d.kind === 'extend') {
      const cur = curStages(d.id);
      if (cur.length >= 3 || cur.some((s) => s.kind === 'group')) return false;
      if (!cur.length) return isPath(t) && t.kind !== 'direct';
      if (t.kind === 'group') {
        const g = groupById[t.id];
        return !!g?.exits.length && !g.exits.some((id) => cur.some((s) => s.kind === 'exit' && s.id === id));
      }
      if (t.kind !== 'exit') return false;
      const b = exitById[t.id];
      if (!b || cur.some((s) => s.kind === 'exit' && s.id === b.id)) return false;
      const last = exitById[cur[cur.length - 1].id];
      if (last?.type === 'tor' && b.type === 'wireguard') return false; // Tor überträgt nur TCP
      return !extendConflict(d.id, t);
    }
    if (d.kind !== 'exit') return false;
    const a = exitById[d.id];
    if (!a) return false;
    if (t.kind === 'group') return !groupById[t.id]?.exits.includes(a.id);
    if (t.kind === 'tray') return !!d.from;
    if (a.via_rule) return false; // Weg bestimmt eine Ziel-Regel
    if (t.kind === 'direct') return !!a.via;
    if (t.kind !== 'exit') return false;
    const b = exitById[t.id];
    if (!b || b.id === a.id || a.via === b.id) return false;
    if (chainOf(b).some((v) => v.id === a.id)) return false; // Kreis
    if (b.type === 'tor' && a.type === 'wireguard') return false; // Tor überträgt nur TCP
    if (b.type === 'tor' && a.type === 'openvpn') return true; // tcp prüft der Server
    const after = (id, n = 0) => (n > 3 ? n : Math.max(n, ...ex.exits.filter((x) => x.via === id).map((x) => after(x.id, n + 1))));
    return chainOf(b).length + 2 + after(a.id) <= 3;
  }
  const dropOk = (kind, id) => !!drag?.moved && canDrop(drag, { kind, id });
  const isOver = (kind, id) => over?.kind === kind && over.id === id && dropOk(kind, id);

  // Was beim Loslassen passiert (Hinweis unter der Karte)
  const nm = (k, id) => (k === 'exit' ? `„${exitById[id]?.name}“` : k === 'group' ? `Gruppe „${groupById[id]?.name}“` : k === 'server' ? `„${serverById[id]?.name}“` : '');
  const hint = $derived.by(() => {
    if (!drag?.moved) return '';
    const d = drag;
    const t = over;
    if (d.kind === 'exit' && exitById[d.id]?.via_rule && (!t || t.kind === 'exit' || t.kind === 'direct'))
      return `Den Weg von ${nm('exit', d.id)} bestimmt die Ziel-Regel ${exitById[d.id].via_rule} – dort ändern. In eine Gruppe ziehen geht.`;
    if (d.kind === 'extend' && t && t.kind === 'exit' && extendConflict(d.id, t)) return extendConflict(d.id, t);
    if (!t || t.kind === 'canvas') {
      if (d.kind === 'server') return 'Auf einen Ausgang, eine Gruppe oder „Direkt“ ziehen';
      if (d.kind === 'user' || d.kind === 'peer') return 'Auf einen Ausgang, eine Gruppe oder „Direkt“ ziehen = Weg ändern · auf „Nicht verwendet“ = eigenen Weg entfernen';
      if (d.kind === 'exit') return 'Auf einen Ausgang ziehen = dahinter schalten · auf eine Gruppe = aufnehmen · auf „Direkt“ = Kaskade aufheben';
      if (d.kind === 'extend') return 'Auf einen Ausgang oder eine Gruppe ziehen = als weitere Stufe anhängen (höchstens 3, eine Gruppe nur am Ende)';
      if (d.kind === 'new-person') return 'Auf einen Ausgang, eine Gruppe oder „Direkt“ ziehen – danach Nutzer oder Gerät wählen';
      return 'Loslassen zum Anlegen – auf einem Ausgang: dahinter, auf einer Gruppe: darin';
    }
    if (!canDrop(d, t)) return 'Hier nicht möglich';
    if (d.kind === 'server') return `${nm('server', d.id)}: Verkehr ${t.kind === 'direct' ? 'direkt ins Internet' : `über ${pathText(t)}`}`;
    if (d.kind === 'user' || d.kind === 'peer') {
      const who = srcName({ kind: d.kind, id: d.id });
      if (t.kind === 'tray') return `Eigenen Weg von ${who} entfernen – danach gilt wieder der Weg ${d.kind === 'peer' ? 'des Nutzers bzw. ' : ''}des Servers`;
      return `${who}: Verkehr ${t.kind === 'direct' ? 'direkt ins Internet' : `über ${pathText(t)}`}`;
    }
    if (d.kind === 'extend') return `${srcName(srcOf(d.id))}: Verkehr über ${stagesText(extended(d.id, t))}`;
    if (d.kind === 'new-person') return t.kind === 'direct' ? 'Nutzer oder Gerät wählen, das direkt ins Internet geht' : `Nutzer oder Gerät wählen, das über ${pathText(t)} geht`;
    if (d.kind === 'exit') {
      if (t.kind === 'exit') return `${nm('exit', d.id)} über ${nm('exit', t.id)} verbinden`;
      if (t.kind === 'direct') return `${nm('exit', d.id)} direkt verbinden`;
      if (t.kind === 'group') return `${nm('exit', d.id)} ${d.from ? 'verschieben nach' : 'aufnehmen in'} ${nm('group', t.id)}`;
      if (t.kind === 'tray') return `${nm('exit', d.id)} aus ${nm('group', d.from)} nehmen`;
    }
    if (d.kind === 'new-exit') return t.kind === 'exit' ? `Neuer Ausgang hinter ${nm('exit', t.id)}` : t.kind === 'group' ? `Neuer Ausgang in ${nm('group', t.id)}` : 'Neuen Ausgang anlegen';
    if (d.kind === 'new-group') return t.kind === 'exit' ? `Neue Gruppe mit ${nm('exit', t.id)}` : 'Neue Gruppe anlegen';
    if (d.kind === 'new-server') return 'Neuen Server anlegen';
    return '';
  });

  // Stufen bis zu einem Ziel (für Regeln)
  function stagesTo(t) {
    if (t.kind === 'direct') return [];
    if (t.kind === 'exit') {
      const e = exitById[t.id];
      return [...chainOf(e).reverse().map((v) => ({ kind: 'exit', id: v.id })), { kind: 'exit', id: e.id }];
    }
    const g = groupById[t.id];
    const first = exitById[g?.status?.active] || exitById[g?.exits?.[0]];
    return [...(first ? chainOf(first).reverse() : []).map((v) => ({ kind: 'exit', id: v.id })), { kind: 'group', id: t.id }];
  }
  const stagesText = (st) => st.map((s) => (s.kind === 'exit' ? exitById[s.id]?.name : `Gruppe ${groupById[s.id]?.name}`)).join(' → ') || 'direkt';
  const pathText = (t) => stagesText(stagesTo(t));

  async function act(d, t) {
    if (d.kind === 'server') return setServerPath(d.id, t);
    if (d.kind === 'user' || d.kind === 'peer') return t.kind === 'tray' ? removeOwn({ kind: d.kind, id: d.id }) : applyPath({ kind: d.kind, id: d.id }, stagesTo(t));
    if (d.kind === 'extend') return applyPath(srcOf(d.id), extended(d.id, t));
    if (d.kind.startsWith('new-')) return create(d.kind.slice(4), t);
    if (t.kind === 'exit') return setVia(d.id, t.id);
    if (t.kind === 'direct') return setVia(d.id, 0);
    if (t.kind === 'group') return toGroup(d.id, d.from, t.id);
    if (t.kind === 'tray') return fromGroup(d.id, d.from);
  }
  const later = () => setTimeout(load, 600);

  const setServerPath = (sid, t) => applyPath({ kind: 'server', id: sid }, stagesTo(t));

  // Weg einer Quelle (Server, Nutzer, Gerät) setzen: eigene Regel „Alles“ ändern oder anlegen
  async function applyPath(src, stages, ask = true) {
    const own = ownRule(src.kind, src.id);
    const name = srcName(src);
    const dest = stages.length ? `über ${stagesText(stages)}` : 'direkt über den Server hinaus';
    if (ask) {
      const who =
        src.kind === 'server'
          ? `Der gesamte Verkehr des Servers ${name} läuft danach ${dest}. Regeln für bestimmte Ziele, Nutzer und Geräte gehen weiterhin vor.`
          : src.kind === 'user'
            ? `Der gesamte Verkehr von ${name} läuft danach ${dest} – auf allen Zugängen außer Hysteria2. Regeln für bestimmte Ziele und eigene Wege einzelner Geräte gehen vor.`
            : `Der gesamte Verkehr des Geräts ${name.replace(/^Gerät /, '')} läuft danach ${dest}. Regeln für bestimmte Ziele gehen vor.${peerById[src.id]?.protocol === 'hysteria2' ? ' Achtung: Hysteria2 folgt nur Server-Regeln – für dieses Gerät gilt die Regel nicht.' : ''}`;
      const ok = await confirmDialog({
        title: stages.length ? `${name} über ${stagesText(stages)}?` : `${name} direkt ins Internet?`,
        text: `${who} Das Panel ${own ? 'ändert dafür die eigene Ziel-Regel' : 'legt dafür eine eigene Ziel-Regel an'}.`,
        ok: 'Übernehmen',
      });
      if (!ok) return false;
    }
    const r = own
      ? await run(() => put(`/routes/${own.id}`, { stages }), 'Weg geändert')
      : await run(() => post('/routes', { name: '', enabled: true, scope: src.kind, scope_id: src.id, match: 'all', nets: '', domains: '', lists: [], stages }), 'Weg geändert');
    if (r) {
      sel = { kind: src.kind, id: src.id };
      later();
    }
    return !!r;
  }
  // letzte Stufe vom Weg einer Quelle nehmen
  function shrink(key) {
    const cur = curStages(key);
    if (cur.length) applyPath(srcOf(key), cur.slice(0, -1));
  }
  // eigenen Weg eines Nutzers oder Geräts entfernen (Regel löschen)
  async function removeOwn(src) {
    const r = ownRule(src.kind, src.id);
    if (!r) return;
    const name = srcName(src);
    const ok = await confirmDialog({
      title: `Eigenen Weg von ${name} entfernen?`,
      text: `Die Ziel-Regel ${r.name ? `„${r.name}“` : `#${r.id}`} wird gelöscht. Danach gilt wieder der Weg ${src.kind === 'peer' ? 'des Nutzers bzw. ' : ''}des Servers. Regeln für bestimmte Ziele bleiben erhalten.`,
      ok: 'Entfernen',
      danger: true,
    });
    if (!ok) return;
    if (await run(() => del(`/routes/${r.id}`), 'Eigener Weg entfernt')) {
      if (isSel(src.kind, src.id)) sel = null;
      later();
    }
  }

  // „Für wen?“ – neuer eigener Weg für einen Nutzer oder ein Gerät
  let who = $state({ open: false, value: '', target: 'direct' });
  const whoItems = $derived([...userItems(rt.users || [], 'user', rt.peers || []), ...peerItems(rt.peers || [], rt.users || [], servers, 'peer')]);
  const whoSrc = $derived.by(() => {
    const [kind, id] = String(who.value || '').split(':');
    return kind && Number(id) ? { kind, id: Number(id) } : null;
  });
  const whoHy = $derived(whoSrc?.kind === 'peer' && peerById[whoSrc.id]?.protocol === 'hysteria2');
  const whoOwn = $derived(whoSrc ? ownRule(whoSrc.kind, whoSrc.id) : null);
  const tVal = (t) => (t.kind === 'direct' || t.kind === 'canvas' ? 'direct' : `${t.kind}:${t.id}`);
  const valToT = (v) => {
    if (v === 'direct') return { kind: 'direct', id: 0 };
    const [kind, id] = v.split(':');
    return { kind, id: Number(id) };
  };
  function openWho(t) {
    who = { open: true, value: '', target: tVal(t) };
  }
  async function saveWho() {
    if (!whoSrc || whoHy) return;
    if (await applyPath(whoSrc, stagesTo(valToT(who.target)), false)) who.open = false;
  }
  async function setVia(id, via) {
    const a = exitById[id];
    const b = via ? exitById[via] : null;
    const ok = await confirmDialog({
      title: b ? `„${a.name}“ über „${b.name}“ verbinden?` : `„${a.name}“ direkt verbinden?`,
      text: b
        ? `Der Tunnel von „${a.name}“ läuft danach über „${b.name}“ (Kaskade): Der Anbieter von „${a.name}“ sieht nur die Adresse von „${b.name}“. Fällt „${b.name}“ aus, bleibt „${a.name}“ getrennt – nie direkt. „${a.name}“ wird dafür neu verbunden.`
        : `„${a.name}“ verbindet sich danach direkt über den Server statt über „${exitById[a.via]?.name || '?'}“. Der Ausgang wird dafür neu verbunden.`,
      ok: b ? 'Verbinden' : 'Direkt verbinden',
    });
    if (!ok) return;
    if (await run(() => put(`/exits/${id}`, { via }), b ? 'Kaskade eingerichtet' : 'Kaskade aufgehoben')) {
      sel = { kind: 'exit', id };
      later();
    }
  }
  async function toGroup(id, from, gid) {
    const e = exitById[id];
    const g = groupById[gid];
    const f = from ? groupById[from] : null;
    const ok = await confirmDialog({
      title: f ? `„${e.name}“ nach „${g.name}“ verschieben?` : `„${e.name}“ in „${g.name}“ aufnehmen?`,
      text: `„${e.name}“ wird letzter Ausweich-Ausgang der Gruppe „${g.name}“${f ? ` und verlässt „${f.name}“` : ''}. Die Reihenfolge änderst du unter „Proxy & Ausgänge“ → Gruppen.`,
      ok: f ? 'Verschieben' : 'Aufnehmen',
    });
    if (!ok) return;
    if (!(await run(() => put(`/groups/${gid}`, { exits: [...g.exits, id] }), f ? 'Ausgang verschoben' : 'Ausgang aufgenommen'))) return;
    if (f) await run(() => put(`/groups/${from}`, { exits: f.exits.filter((x) => x !== id) }));
    later();
  }
  async function fromGroup(id, from) {
    const e = exitById[id];
    const f = groupById[from];
    const last = f.exits.length === 1;
    const ok = await confirmDialog({
      title: `„${e.name}“ aus „${f.name}“ nehmen?`,
      text: `Der Ausgang selbst bleibt erhalten.${last ? ` Die Gruppe „${f.name}“ hat danach keinen Ausgang mehr – Verkehr über sie wird je nach Einstellung gesperrt oder geht direkt.` : ''}`,
      ok: 'Herausnehmen',
      danger: last,
    });
    if (!ok) return;
    if (await run(() => put(`/groups/${from}`, { exits: f.exits.filter((x) => x !== id) }), 'Aus der Gruppe genommen')) later();
  }
  // Anlegen: Dialog auf der passenden Seite, danach zurück zur Karte
  function create(kind, t) {
    if (kind === 'person') return openWho(t);
    intent.back = '/network';
    if (kind === 'exit') {
      intent.via = t.kind === 'exit' ? t.id : 0;
      intent.group = t.kind === 'group' ? t.id : 0;
      intent.create = 'exit';
      go('/proxy/exits');
    } else if (kind === 'group') {
      intent.exits = t.kind === 'exit' ? [t.id] : [];
      intent.create = 'group';
      go('/proxy/groups');
    } else {
      intent.create = 'server';
      go('/servers');
    }
  }
  function edit(kind, id) {
    intent.back = '/network';
    intent.edit = { kind, id };
    go(kind === 'group' ? '/proxy/groups' : '/proxy/exits');
  }

  // ---------- Details ----------
  const selExit = $derived(sel?.kind === 'exit' ? exitById[sel.id] : null);
  const selGroup = $derived(sel?.kind === 'group' ? groupById[sel.id] : null);
  const selSource = $derived(srcKeyOf(sel) ? srcEntry(srcKeyOf(sel)) : null);
  const selSrv = $derived(selSource?.kind === 'server' ? selSource : null);
  const selPsn = $derived(selSource && selSource.kind !== 'server' ? selSource : null);
  const usedBy = (key) => view.src.filter((x) => x.target === key || x.first === key).map((x) => x.name);
  // „+“/„−“ am Ende des Wegs der gewählten Quelle
  const handle = $derived.by(() => {
    const x = selSource;
    if (!x || drag?.moved) return null;
    const v = view;
    let px, py;
    if (x.target === 'direct') {
      if (!v.pos.direct) return null;
      px = v.pos.direct.x;
      py = v.pos.direct.y + 23;
    } else if (x.target[0] === 'g') {
      const p = v.pos[x.target];
      if (!p) return null;
      px = p.x;
      py = p.y + G_HEAD / 2;
    } else {
      const id = Number(x.target.slice(2));
      const p = v.pos[nodeOfExit(id)];
      py = v.exitY(id);
      if (!p || py == null) return null;
      px = p.x;
    }
    const cur = stagesTo(keyToT(x.target));
    return { key: x.key, x: px + NODE_W + 6, y: py, plus: cur.length < 3 && !cur.some((s) => s.kind === 'group'), minus: cur.length > 0 };
  });
  // Auswahl „Weg“ für einen Server (ohne Ziehen)
  const targetOptions = $derived([
    { v: 'direct', label: 'Direkt' },
    ...realGroups.filter((g) => g.exits.length).map((g) => ({ v: `group:${g.id}`, label: `Gruppe ${g.name}` })),
    ...ex.exits.map((e) => ({ v: `exit:${e.id}`, label: [...chainOf(e).reverse(), e].map((x) => x.name).join(' → ') })),
  ]);
  const curTarget = (x) => (x.target === 'direct' ? 'direct' : x.target[0] === 'g' ? `group:${x.target.slice(2)}` : `exit:${x.target.slice(2)}`);
  const chooseTarget = (src, v) => applyPath(src, stagesTo(valToT(v)));
</script>

<div class="card">
  <div class="card-head">
    <div class="palette">
      <span class="muted small">Ziehen zum Anlegen:</span>
      <button class="pal" onpointerdown={(e) => startDrag(e, 'new-server', 0, '+ Server')} title="Ziehen oder klicken: Server anlegen"><Icon name="server" size={14} /> Server</button>
      <button class="pal" onpointerdown={(e) => startDrag(e, 'new-exit', 0, '+ Ausgang')} title="Auf einen Ausgang ziehen = dahinter schalten, auf eine Gruppe = darin anlegen"><Icon name="globe" size={14} /> Ausgang</button>
      <button class="pal" onpointerdown={(e) => startDrag(e, 'new-group', 0, '+ Gruppe')} title="Auf einen Ausgang ziehen = Gruppe mit diesem Ausgang"><Icon name="layers" size={14} /> Gruppe</button>
      <button class="pal psn" onpointerdown={(e) => startDrag(e, 'new-person', 0, '+ Nutzer/Gerät')} title="Auf einen Ausgang, eine Gruppe oder „Direkt“ ziehen = eigener Weg für einen Nutzer oder ein Gerät"><Icon name="user" size={14} /> Nutzer/Gerät</button>
    </div>
    <div class="legend tiny muted">
      <span><i class="ln on"></i> Weg der Server</span>
      <span><i class="ln psn"></i> Eigener Weg</span>
      <span><i class="ln"></i> nicht genutzt</span>
    </div>
  </div>

  <div class="scroll" data-drop="canvas:0">
    <div class="canvas" style="width:{view.W}px;height:{view.H}px" class:dragging={drag?.moved}>
      <!-- Spaltenköpfe -->
      <div class="colh" style="left:{PAD}px;width:{SRV_W}px">Server</div>
      {#each Array.from({ length: view.stages }, (_, i) => i + 1) as d}
        <div class="colh" style="left:{view.colX(d)}px;width:{NODE_W}px">Stufe {d}{#if d === 1}<span class="muted"> · verbindet direkt</span>{:else}<span class="muted"> · über Stufe {d - 1}</span>{/if}</div>
      {/each}
      <div class="colh" style="left:{view.netX}px;width:110px">Internet</div>

      <svg class="wires" width={view.W} height={view.H} aria-hidden="true">
        {#each lines as l (l.id)}
          <path d={l.d} class:on={l.on} class:via={l.via} class:direct={l.direct} class:psn={l.psn} class:hot={l.hot === true} class:dim={l.hot === false} />
        {/each}
      </svg>

      <!-- Server -->
      {#each view.srv as x (x.s.id)}
        {@const s = x.s}
        <div
          class="node srv"
          class:sel={isSel('server', s.id)}
          class:off={!s.enabled}
          class:dim={selSrc && selSrc !== x.key}
          style="left:{PAD}px;top:{x.y}px;width:{SRV_W}px;height:{SRV_H}px"
          onpointerdown={(e) => startDrag(e, 'server', s.id, s.name)}
          onpointerenter={() => (hoverSrc = x.key)}
          onpointerleave={() => hoverSrc === x.key && (hoverSrc = '')}
          role="button"
          tabindex="0"
          onkeydown={(e) => e.key === 'Enter' && pick('server', s.id)}
          title="Ziehen auf einen Ausgang, eine Gruppe oder „Direkt“ = Weg dieses Servers"
        >
          <ProtoLogo id={s.protocol} size={22} />
          <div class="grow">
            <div class="strong name">{s.name}</div>
            <div class="tiny muted name">{x.sr ? (x.sr.own ? 'eigene Regel' : 'Regel für alle') : 'keine Regel'}{#if extraRules(s)} · +{extraRules(s)} für Ziele{/if}</div>
          </div>
          <span class="dot" class:on={s.status?.running} class:bad={s.enabled && !s.status?.running}></span>
        </div>
      {/each}
      {#if !view.srv.length && loaded}<div class="muted small" style="position:absolute;left:{PAD}px;top:{TOP}px;width:{SRV_W}px">Noch kein Server – „Server“ oben hineinziehen.</div>{/if}

      <!-- Nutzer und Geräte mit eigenem Weg -->
      <div class="ownh" style="left:{PAD}px;top:{view.ownTop}px;width:{SRV_W}px" title="Nutzer und Geräte mit eigener Ziel-Regel „Alles“ – alle anderen nehmen den Weg ihres Servers">Eigener Weg</div>
      {#each view.psn as x (x.key)}
        <div
          class="node psn"
          class:sel={isSel(x.kind, x.id)}
          class:off={x.off || x.hy}
          class:dim={selSrc && selSrc !== x.key}
          style="left:{PAD}px;top:{x.y}px;width:{SRV_W}px;height:{PSN_H}px"
          onpointerdown={(e) => startDrag(e, x.kind, x.id, x.name)}
          onpointerenter={() => (hoverSrc = x.key)}
          onpointerleave={() => hoverSrc === x.key && (hoverSrc = '')}
          role="button"
          tabindex="0"
          onkeydown={(e) => e.key === 'Enter' && pick(x.kind, x.id)}
          title="Ziehen auf einen Ausgang, eine Gruppe oder „Direkt“ = Weg ändern · auf „Nicht verwendet“ = eigenen Weg entfernen"
        >
          {#if x.kind === 'peer'}<ProtoLogo id={x.proto} size={18} />{:else}<span class="pic"><Icon name="user" size={13} /></span>{/if}
          <div class="grow">
            <div class="strong name">{x.name}</div>
            <div class="tiny muted name">{x.kind === 'user' ? 'Nutzer · alle Zugänge' : 'Gerät'}{x.hy ? ' · gilt nicht (Hysteria2)' : ''}</div>
          </div>
        </div>
      {:else}
        {#if loaded}<div class="ownempty tiny muted" style="left:{PAD}px;top:{view.ownTop + OWN_HEAD}px;width:{SRV_W}px">Keiner – „Nutzer/Gerät“ oben auf einen Ausgang ziehen.</div>{/if}
      {/each}

      <!-- Direkt -->
      {#if view.pos.direct}
        <div
          class="node direct"
          class:sel={isSel('direct', 0)}
          class:drop={dropOk('direct', 0)}
          class:over={isOver('direct', 0)}
          class:dim={!onPath('direct')}
          style="left:{view.pos.direct.x}px;top:{view.pos.direct.y}px;width:{NODE_W}px;height:46px"
          data-drop="direct:0"
          role="button"
          tabindex="0"
          onclick={() => pick('direct', 0)}
          onkeydown={(e) => e.key === 'Enter' && pick('direct', 0)}
        >
          <span class="ic"><Icon name="server" size={16} /></span>
          <div class="grow"><div class="strong">Direkt</div><div class="tiny muted">ohne Ausgang</div></div>
        </div>
      {/if}

      <!-- Stufen -->
      {#each Object.values(view.nodes) as n (n.key)}
        {@const p = view.pos[n.key]}
        {#if p}
          {#if n.kind === 'group'}
            {@const g = n.g}
            <div
              class="node grp"
              class:sel={isSel('group', g.id)}
              class:off={!g.enabled}
              class:drop={dropOk('group', g.id)}
              class:over={isOver('group', g.id)}
              class:dim={!onPath(n.key)}
              style="left:{p.x}px;top:{p.y}px;width:{NODE_W}px;height:{n.h}px"
              data-drop="group:{g.id}"
            >
              <button class="ghead" onclick={() => pick('group', g.id)}>
                <span class="ic"><Icon name="layers" size={15} /></span>
                <span class="grow">
                  <span class="strong name">{g.name}</span>
                  <span class="tiny muted name">{targetKeys.has(n.key) ? `Gruppe · ${g.exits.length} Ausgänge` : 'Gruppe · keine Regel'}</span>
                </span>
              </button>
              {#each g.exits as id, i}
                {@const e = exitById[id]}
                {#if e}
                  <div
                    class="row-exit"
                    class:act={g.status?.active === id}
                    class:sel={isSel('exit', id)}
                    class:drop={dropOk('exit', id)}
                    class:over={isOver('exit', id)}
                    data-drop="exit:{id}"
                    onpointerdown={(ev) => startDrag(ev, 'exit', id, e.name, g.id)}
                    role="button"
                    tabindex="0"
                    onkeydown={(ev) => ev.key === 'Enter' && pick('exit', id)}
                    title={e.status?.error || (e.via ? `über ${chainOf(e).map((v) => v.name).join(' → ')}` : 'Ziehen: auf einen Ausgang = dahinter schalten, auf eine Gruppe = verschieben')}
                  >
                    <span class="dot {health(e)}"></span>
                    <span class="grow name">{i + 1}. {e.name}</span>
                    {#if e.via}<Icon name="link" size={11} />{/if}
                    <span class="tiny muted nowrap">{exitInfo(e)}</span>
                  </div>
                {/if}
              {/each}
              {#if !g.exits.length}<div class="row-exit empty tiny muted">leer – Ausgang hineinziehen</div>{/if}
            </div>
          {:else}
            {@const e = n.e}
            <div
              class="node exn"
              class:sel={isSel('exit', e.id)}
              class:off={!e.enabled}
              class:drop={dropOk('exit', e.id)}
              class:over={isOver('exit', e.id)}
              class:dim={!onPath(n.key)}
              style="left:{p.x}px;top:{p.y}px;width:{NODE_W}px;height:{EX_H}px"
              data-drop="exit:{e.id}"
              onpointerdown={(ev) => startDrag(ev, 'exit', e.id, e.name)}
              role="button"
              tabindex="0"
              onkeydown={(ev) => ev.key === 'Enter' && pick('exit', e.id)}
              title={e.status?.error || 'Ziehen: auf einen Ausgang = dahinter schalten, auf eine Gruppe = aufnehmen'}
            >
              <ProtoLogo id={e.type} size={22} />
              <div class="grow">
                <div class="strong name">{e.name}</div>
                <div class="tiny muted name">{TYPE[e.type] || e.type} · {exitInfo(e)}</div>
              </div>
              <span class="dot {health(e)}"></span>
            </div>
          {/if}
        {/if}
      {/each}

      <!-- Internet -->
      <div class="node net" style="left:{view.netX}px;top:{view.netY}px;width:110px;height:46px">
        <span class="ic"><Icon name="globe" size={16} /></span><span class="strong">Internet</span>
      </div>

      <!-- Weg der gewählten Quelle verlängern / kürzen -->
      {#if handle}
        {#if handle.plus}
          <button class="hdl plus" style="left:{handle.x}px;top:{handle.y - (handle.minus ? 24 : 11)}px" onpointerdown={(e) => startDrag(e, 'extend', handle.key, '+ Stufe')} title="Auf einen Ausgang oder eine Gruppe ziehen = weitere Stufe anhängen" aria-label="Stufe anhängen">+</button>
        {/if}
        {#if handle.minus}
          <button class="hdl" style="left:{handle.x}px;top:{handle.y + (handle.plus ? 2 : -11)}px" onclick={() => shrink(handle.key)} title="Letzte Stufe entfernen" aria-label="Letzte Stufe entfernen">−</button>
        {/if}
      {/if}
    </div>
  </div>

  <!-- Nicht verwendet -->
  <div class="tray" class:drop={dropOk('tray', 0)} class:over={isOver('tray', 0)} data-drop="tray:0">
    <span class="muted small">Nicht verwendet</span>
    {#if drag?.moved && (drag.kind === 'user' || drag.kind === 'peer')}<span class="tiny muted">Hier ablegen = eigenen Weg entfernen</span>{/if}
    {#each trayExits as e (e.id)}
      <button class="chip" class:sel={isSel('exit', e.id)} data-drop="exit:{e.id}" class:over={isOver('exit', e.id)} onpointerdown={(ev) => startDrag(ev, 'exit', e.id, e.name)} title="Ziehen: auf eine Gruppe = aufnehmen, auf einen Ausgang = dahinter schalten; Server hierher ziehen = Weg über diesen Ausgang">
        <span class="dot {health(e)}"></span>{e.name}<span class="tiny muted">{TYPE[e.type] || e.type}</span>
      </button>
    {:else}
      <span class="tiny muted">{drag?.from ? 'Hier ablegen = aus der Gruppe nehmen' : 'Alle Ausgänge sind eingebunden.'}</span>
    {/each}
  </div>

  <div class="foot tiny muted">
    {#if hint}<span class="hint"><Icon name="info" size={13} /> {hint}</span>
    {:else}
      Klicken = Details · Server, Nutzer oder Gerät ziehen = Weg festlegen · „+“ am Ende eines gewählten Wegs = Stufe anhängen · Ausgang auf Ausgang = dahinter schalten (höchstens 3 Stufen)
      {#if personalRules} · Außerdem {personalRules} {personalRules === 1 ? 'Regel' : 'Regeln'} für bestimmte Ziele einzelner Nutzer oder Geräte – <button class="linkbtn" onclick={() => go('/proxy/rules')}>Ziel-Regeln</button>{/if}
    {/if}
  </div>
</div>

<!-- Details zur Auswahl -->
{#if selSrv}
  {@const x = selSrv}
  <div class="card card-pad detail">
    <div class="spread">
      <h3 class="row"><ProtoLogo id={x.s.protocol} size={20} /> {x.s.name}</h3>
      <button class="btn sm ghost icon" onclick={() => (sel = null)} aria-label="Schließen"><Icon name="x" size={15} /></button>
    </div>
    <div class="field" style="max-width:520px">
      <label for="bm-target">Weg für den gesamten Verkehr</label>
      <select id="bm-target" class="input" value={curTarget(x)} onchange={(e) => chooseTarget({ kind: 'server', id: x.s.id }, e.currentTarget.value)}>
        {#each targetOptions as o}<option value={o.v}>{o.label}</option>{/each}
      </select>
      <div class="help">{x.sr ? (x.sr.own ? 'Eigene Ziel-Regel dieses Servers.' : 'Folgt der Regel für alle – eine Änderung legt eine eigene Regel für diesen Server an.') : 'Keine Regel – direkt.'} Regeln für bestimmte Ziele, Nutzer und Geräte gehen vor.</div>
    </div>
    <div class="row wrap" style="margin-top:10px">
      <button class="btn sm" onclick={() => go('/proxy/rules')}><Icon name="route" size={14} /> Ziel-Regeln</button>
      <button class="btn sm" onclick={() => go('/servers')}><Icon name="server" size={14} /> Server</button>
    </div>
  </div>
{:else if selPsn}
  {@const x = selPsn}
  {@const uid = x.kind === 'user' ? x.id : peerById[x.id]?.user_id}
  <div class="card card-pad detail">
    <div class="spread">
      <h3 class="row">{#if x.kind === 'peer'}<ProtoLogo id={x.proto} size={20} />{:else}<Icon name="user" size={18} />{/if} {x.name} <span class="badge">{x.kind === 'user' ? 'Nutzer' : 'Gerät'}</span></h3>
      <button class="btn sm ghost icon" onclick={() => (sel = null)} aria-label="Schließen"><Icon name="x" size={15} /></button>
    </div>
    <div class="field" style="max-width:520px">
      <label for="bm-ptarget">Weg für den gesamten Verkehr</label>
      <select id="bm-ptarget" class="input" value={curTarget(x)} onchange={(e) => chooseTarget({ kind: x.kind, id: x.id }, e.currentTarget.value)}>
        {#each targetOptions as o}<option value={o.v}>{o.label}</option>{/each}
      </select>
      <div class="help">
        {x.kind === 'user' ? 'Gilt für alle Zugänge dieses Nutzers außer Hysteria2. Regeln für bestimmte Ziele und eigene Wege einzelner Geräte gehen vor.' : 'Gilt nur für dieses Gerät. Regeln für bestimmte Ziele gehen vor.'}
        Ziel-Regel {x.r.name ? `„${x.r.name}“` : `#${x.r.id}`}. Mit „+“ am Ende des Wegs hängst du eine weitere Stufe an.
      </div>
      {#if x.hy}<div class="help" style="color:var(--warn)">Hysteria2 folgt nur Server-Regeln – diese Regel greift für das Gerät nicht.</div>{/if}
    </div>
    <div class="row wrap" style="margin-top:10px">
      <button class="btn sm danger" onclick={() => removeOwn({ kind: x.kind, id: x.id })}><Icon name="trash" size={14} /> Eigenen Weg entfernen</button>
      {#if uid}<button class="btn sm" onclick={() => go(`/users/${uid}/peers`)}><Icon name="user" size={14} /> Nutzer öffnen</button>{/if}
      <button class="btn sm" onclick={() => go('/proxy/rules')}><Icon name="route" size={14} /> Ziel-Regeln</button>
    </div>
  </div>
{:else if selExit}
  {@const e = selExit}
  {@const st = e.status}
  <div class="card card-pad detail">
    <div class="spread">
      <h3 class="row"><ProtoLogo id={e.type} size={20} /> {e.name} <span class="dot {health(e)}"></span></h3>
      <button class="btn sm ghost icon" onclick={() => (sel = null)} aria-label="Schließen"><Icon name="x" size={15} /></button>
    </div>
    <dl class="kv">
      <dt>Art</dt><dd>{TYPE[e.type] || e.type}{e.mode === 'standby' ? ' · Bereitschaft' : ''}{e.enabled ? '' : ' · deaktiviert'}</dd>
      <dt>Zustand</dt><dd>{st?.error ? st.error : st?.up ? `verbunden · ${fmtNum(Math.round(st.rtt))} ms${st.loc ? ' · ' + st.loc : ''}${st.ip ? ' · ' + st.ip : ''}` : exitInfo(e)}</dd>
      <dt>Verbunden über</dt><dd>{e.via ? chainOf(e).map((v) => v.name).join(' → ') : 'direkt'}{#if e.via_rule} <span class="muted">(bestimmt von Regel {e.via_rule})</span>{/if}</dd>
      <dt>Gruppen</dt><dd>{inGroups(e.id).map((g) => g.name).join(', ') || '–'}</dd>
      {#if usedBy(nodeOfExit(e.id)).length}<dt>Genutzt von</dt><dd>{usedBy(nodeOfExit(e.id)).join(', ')}</dd>{/if}
    </dl>
    {#if !e.via_rule}
      <div class="field" style="max-width:420px;margin-top:10px">
        <label for="bm-via">Verbunden über (Kaskade)</label>
        <select id="bm-via" class="input" value={e.via || 0} onchange={(ev) => setVia(e.id, Number(ev.currentTarget.value))}>
          <option value={0}>direkt</option>
          {#each ex.exits.filter((b) => b.id !== e.id && (b.id === e.via || canDrop({ kind: 'exit', id: e.id, moved: true }, { kind: 'exit', id: b.id }))) as b}<option value={b.id}>{[...chainOf(b).reverse(), b].map((v) => v.name).join(' → ')}</option>{/each}
        </select>
      </div>
    {/if}
    <div class="row wrap" style="margin-top:10px">
      <button class="btn sm" onclick={() => edit('exit', e.id)}><Icon name="edit" size={14} /> Bearbeiten</button>
    </div>
  </div>
{:else if selGroup}
  {@const g = selGroup}
  <div class="card card-pad detail">
    <div class="spread">
      <h3 class="row"><Icon name="layers" size={18} /> Gruppe {g.name}</h3>
      <button class="btn sm ghost icon" onclick={() => (sel = null)} aria-label="Schließen"><Icon name="x" size={15} /></button>
    </div>
    <dl class="kv">
      <dt>Aktiv</dt><dd>{exitById[g.status?.active]?.name || '–'}</dd>
      <dt>Reihenfolge</dt><dd>{g.exits.map((id, i) => `${i + 1}. ${exitById[id]?.name || '?'}`).join(' · ') || 'leer'}</dd>
      <dt>Bei Ausfall</dt><dd>{g.on_fail === 'direct' ? 'direkt weiter' : 'sperren'}</dd>
      {#if usedBy(`g:${g.id}`).length}<dt>Genutzt von</dt><dd>{usedBy(`g:${g.id}`).join(', ')}</dd>{/if}
    </dl>
    <div class="row wrap" style="margin-top:10px">
      <button class="btn sm" onclick={() => edit('group', g.id)}><Icon name="edit" size={14} /> Bearbeiten</button>
    </div>
  </div>
{/if}

{#if drag?.moved}
  <div class="ghost" class:psn={drag.kind === 'user' || drag.kind === 'peer' || drag.kind === 'new-person'} style="left:{drag.x + 12}px;top:{drag.y + 10}px">{drag.label}</div>
{/if}

<Modal bind:open={who.open} title="Eigener Weg für Nutzer oder Gerät" width={540}>
  <div class="field">
    <label for="bm-who">Für wen?</label>
    <Picker id="bm-who" items={whoItems} bind:value={who.value} placeholder="Nutzer oder Gerät suchen …" />
  </div>
  <div class="field">
    <label for="bm-who-target">Weg für den gesamten Verkehr</label>
    <select id="bm-who-target" class="input" bind:value={who.target}>
      {#each targetOptions as o}<option value={o.v}>{o.label}</option>{/each}
    </select>
  </div>
  <div class="help">
    {#if whoSrc?.kind === 'user'}Gilt für alle Zugänge dieses Nutzers außer Hysteria2.{:else if whoSrc}Gilt nur für dieses Gerät.{:else}Ein Nutzer-Weg gilt für alle seine Zugänge (außer Hysteria2), ein Geräte-Weg nur für das Gerät.{/if}
    Regeln für bestimmte Ziele gehen weiterhin vor.
  </div>
  {#if whoHy}<div class="help" style="color:var(--warn)">Hysteria2 folgt nur Server-Regeln – für dieses Gerät geht das nicht. Wähle den Nutzer oder ändere den Weg des Servers.</div>{/if}
  {#if whoOwn}<div class="help">Hat schon einen eigenen Weg – er wird geändert.</div>{/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (who.open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveWho} disabled={!whoSrc || whoHy}>Übernehmen</button>
  {/snippet}
</Modal>

<style>
  .palette {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .pal {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 30px;
    padding: 0 12px;
    border-radius: var(--radius-sm);
    border: 1px dashed var(--border-strong);
    background: var(--panel-2);
    color: var(--text);
    font: inherit;
    font-size: var(--fs-sm);
    font-weight: 600;
    cursor: grab;
    touch-action: none;
  }
  .pal::before {
    content: '+';
    color: var(--accent);
    font-weight: 700;
  }
  .pal:hover {
    border-color: var(--accent);
  }
  .legend {
    display: flex;
    gap: 14px;
  }
  @media (max-width: 720px) {
    .legend {
      display: none !important;
    }
  }
  .legend span {
    white-space: nowrap;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .ln {
    width: 22px;
    height: 0;
    border-top: 2px dashed var(--border-strong);
  }
  .ln.on {
    border-top: 2.5px solid var(--accent);
  }
  .ln.psn {
    border-top: 2.5px solid var(--person);
  }
  .pal.psn::before {
    color: var(--person);
  }
  .pal.psn:hover {
    border-color: var(--person);
  }
  .ownh {
    position: absolute;
    font-size: var(--fs-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--person);
    font-weight: 600;
    padding-top: 4px;
    border-top: 1px dashed var(--border-strong);
  }
  .ownempty {
    position: absolute;
    line-height: 1.4;
  }
  .node.psn {
    cursor: grab;
    touch-action: none;
    gap: 8px;
    border-left: 3px solid var(--person);
  }
  .node.psn.sel {
    border-color: var(--person);
    box-shadow: 0 0 0 3px var(--person-soft);
  }
  .pic {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background: var(--person-soft);
    color: var(--person);
    flex: none;
  }
  .wires path.on.psn,
  .wires path.on.psn.direct {
    stroke: var(--person);
  }
  .hdl {
    position: absolute;
    width: 22px;
    height: 22px;
    padding: 0;
    border-radius: 50%;
    border: 1px solid var(--border-strong);
    background: var(--panel);
    color: var(--text);
    font: inherit;
    font-weight: 700;
    line-height: 1;
    display: grid;
    place-items: center;
    cursor: pointer;
    box-shadow: var(--shadow);
    z-index: 2;
  }
  .hdl.plus {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
    cursor: grab;
    touch-action: none;
  }
  .hdl:hover {
    border-color: var(--accent);
  }
  .scroll {
    overflow-x: auto;
    padding-bottom: 6px;
  }
  .canvas {
    position: relative;
    margin: 0 auto;
    user-select: none;
  }
  .colh {
    position: absolute;
    top: 12px;
    font-size: var(--fs-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .colh .muted {
    text-transform: none;
    letter-spacing: 0;
    font-weight: 400;
  }
  .wires {
    position: absolute;
    inset: 0;
    pointer-events: none;
    overflow: visible;
  }
  .wires path {
    fill: none;
    stroke: var(--border-strong);
    stroke-width: 1.5;
    stroke-dasharray: 5 4;
    transition: opacity 0.15s, stroke 0.15s;
  }
  .wires path.on {
    stroke: var(--accent);
    stroke-width: 2.2;
    stroke-dasharray: none;
  }
  .wires path.on.direct {
    stroke: var(--muted);
  }
  .wires path.hot {
    stroke-width: 3.2;
  }
  .wires path.dim {
    opacity: 0.15;
  }
  .node {
    position: absolute;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 12px;
    border-radius: 10px;
    background: var(--panel);
    border: 1px solid var(--border-strong);
    box-shadow: var(--shadow);
    font-size: var(--fs-md);
    transition: opacity 0.15s, border-color 0.12s, box-shadow 0.12s;
  }
  .node .name {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .node.srv,
  .node.exn {
    cursor: grab;
    touch-action: none;
  }
  .node.srv {
    border-left: 3px solid var(--accent);
  }
  .node.sel {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .node.dim {
    opacity: 0.35;
  }
  .node.off {
    opacity: 0.6;
    border-style: dashed;
  }
  .node.direct,
  .node.net {
    background: var(--panel-2);
  }
  .node.net {
    justify-content: center;
    gap: 8px;
  }
  .ic {
    width: 28px;
    height: 28px;
    border-radius: 8px;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
    flex: none;
  }
  .node.grp {
    flex-direction: column;
    align-items: stretch;
    gap: 0;
    padding: 0 0 6px;
  }
  .ghead {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 40px;
    padding: 0 12px;
    border: none;
    background: none;
    font: inherit;
    color: inherit;
    text-align: left;
    cursor: pointer;
    border-bottom: 1px solid var(--border);
    margin-bottom: 4px;
  }
  .ghead .grow {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .row-exit {
    display: flex;
    align-items: center;
    gap: 7px;
    height: 28px;
    margin: 0 6px 2px;
    padding: 0 8px;
    border-radius: 7px;
    font-size: var(--fs-sm);
    cursor: grab;
    touch-action: none;
    border: 1px solid transparent;
  }
  .row-exit:hover {
    background: var(--panel-2);
  }
  .row-exit.act {
    background: var(--accent-soft);
  }
  .row-exit.sel {
    border-color: var(--accent);
  }
  .row-exit.empty {
    cursor: default;
  }
  .drop {
    outline: 2px dashed var(--accent);
    outline-offset: 2px;
  }
  .over {
    outline: 2px solid var(--accent);
    background: var(--accent-soft) !important;
  }
  .dot.ok {
    background: var(--ok);
  }
  .dot.bad {
    background: var(--bad);
  }
  .tray {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin: 0 16px 12px;
    padding: 10px 12px;
    border: 1px dashed var(--border-strong);
    border-radius: 10px;
    min-height: 48px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 30px;
    padding: 0 10px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--panel);
    color: var(--text);
    font: inherit;
    font-size: var(--fs-sm);
    font-weight: 600;
    cursor: grab;
    touch-action: none;
  }
  .chip.sel {
    border-color: var(--accent);
  }
  .foot {
    padding: 0 16px 14px;
    min-height: 18px;
  }
  .hint {
    color: var(--accent);
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
  }
  .linkbtn {
    border: none;
    background: none;
    padding: 0;
    color: var(--accent);
    font: inherit;
    cursor: pointer;
  }
  .detail {
    margin-top: 16px;
  }
  .detail h3 {
    gap: 8px;
  }
  .ghost {
    position: fixed;
    z-index: 200;
    pointer-events: none;
    padding: 5px 10px;
    border-radius: 8px;
    background: var(--accent);
    color: #fff;
    font-size: var(--fs-sm);
    font-weight: 600;
    box-shadow: var(--shadow-lg);
  }
  .ghost.psn {
    background: var(--person);
  }
</style>
