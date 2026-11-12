// Einträge für Auswahlfelder (Picker) und Suche über Nutzer, Geräte und Server.
import { PROTO_LABEL } from './format.js';

// Suchtext in Wörter zerlegen; jedes Wort muss irgendwo vorkommen („anna iphone wg“)
export function tokens(q) {
  return (q || '').toLowerCase().split(/\s+/).filter(Boolean);
}
export function matches(text, toks) {
  if (!toks.length) return true;
  const t = (text || '').toLowerCase();
  return toks.every((w) => t.includes(w));
}

const byId = (l) => (Array.isArray(l) ? Object.fromEntries(l.map((x) => [x.id, x])) : l || {});

// Server: {id, name, protocol, enabled}
export function serverItems(servers, prefix = '') {
  return servers.map((s) => ({
    value: prefix ? `${prefix}:${s.id}` : s.id,
    label: s.name,
    sub: PROTO_LABEL[s.protocol] || s.protocol,
    proto: s.protocol,
    off: s.enabled === false,
    group: 'Server',
    search: `${s.name} ${PROTO_LABEL[s.protocol] || s.protocol} server`,
  }));
}

// Nutzer: {id, name, enabled, note?}
export function userItems(users, prefix = '', peers = null) {
  const n = {};
  if (peers) for (const p of peers) n[p.user_id] = (n[p.user_id] || 0) + 1;
  return users.map((u) => ({
    value: prefix ? `${prefix}:${u.id}` : u.id,
    label: u.name,
    sub: [peers ? `${n[u.id] || 0} ${n[u.id] === 1 ? 'Zugang' : 'Zugänge'}` : '', u.note || ''].filter(Boolean).join(' · '),
    icon: 'user',
    off: u.enabled === false,
    group: 'Nutzer',
    search: `${u.name} ${u.note || ''} nutzer`,
  }));
}

// Geräte/Zugänge: {id, name, protocol, user_id, server_id, enabled, address4?}
// Anzeige „Nutzer · Gerät“, darunter Dienst und Server – so sind gleichnamige Geräte unterscheidbar.
export function peerItems(peers, users, servers, prefix = '') {
  const u = byId(users);
  const s = byId(servers);
  return peers.map((p) => {
    const srv = s[p.server_id];
    const proto = p.protocol || srv?.protocol || '';
    const pl = PROTO_LABEL[proto] || proto;
    const user = u[p.user_id]?.name || p.user_name || p.user || '?';
    const addr = p.address4 || p.settings?.address4 || '';
    const srvName = srv?.name || p.server || '';
    return {
      value: prefix ? `${prefix}:${p.id}` : p.id,
      label: `${user} · ${p.name}`,
      sub: [pl, srvName && srvName !== pl ? srvName : '', addr].filter(Boolean).join(' · '),
      proto,
      off: p.enabled === false,
      group: 'Geräte',
      search: `${user} ${p.name} ${pl} ${srvName} ${addr} gerät`,
    };
  });
}
