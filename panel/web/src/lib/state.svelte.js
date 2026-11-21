// Globaler Zustand: Anmeldung, Metadaten (Protokolle), Benachrichtigungen, Route.

export const session = $state({ user: null, checked: false });
export const meta = $state({ protocols: [], version: '', dry_run: false, server_host: '', sub_host: '', lan4: '', lan6: '', pub4: '', pub6: '' });
export const toasts = $state([]);
// status: Kennzahlen des Servers und „Braucht Aufmerksamkeit“ (GET /api/status, alle 5 s aus App.svelte)
export const status = $state({ host: null, attention: [], peers: 0, peers_online: 0, at: 0 });
// intent: Absicht über Seitenwechsel hinweg (z. B. Schnellaktion „Nutzer anlegen“ öffnet den Dialog)
// create: user | exit | group | server; via/group/exits: Vorbelegung; edit: {kind, id}; back: danach zurück zu dieser Adresse
export const intent = $state({ create: '', via: 0, group: 0, exits: [], edit: null, back: '' });
export const route = $state({ path: location.hash.slice(1) || '/' });

window.addEventListener('hashchange', () => {
  route.path = location.hash.slice(1) || '/';
});

// replace: Adresse ersetzen statt neuen Eintrag im Verlauf anlegen (Weiterleitungen)
export function go(path, replace = false) {
  if (!replace) {
    location.hash = path;
    return;
  }
  history.replaceState(null, '', '#' + path);
  route.path = path;
}

// Alte Adressen (vor dem Umbau auf 7 Bereiche) → neue, damit Lesezeichen und Links weiter funktionieren
const MOVED = [
  [/^\/plans$/, '/users/plans'],
  [/^\/network$/, '/routing/map'],
  [/^\/network\/live$/, '/routing/live'],
  [/^\/network\/access$/, '/servers/access'],
  [/^\/network\/(\d+)(\/matrix)?$/, (m) => `/servers/wg/${m[1]}${m[2] || ''}`],
  [/^\/proxy(\/overview)?$/, '/routing'],
  [/^\/proxy\/(exits|groups|rules|proxy)$/, (m) => `/routing/${m[1]}`],
  [/^\/iplists$/, '/routing/iplists'],
  [/^\/settings\/system$/, '/system'],
  [/^\/settings\/events$/, '/system/events'],
  [/^\/health(\/overview)?$/, '/system'],
  [/^\/health\/(updates|events)$/, (m) => `/system/${m[1]}`],
  [/^\/settings$/, '/system/settings'],
  [/^\/settings\/(\w+)$/, (m) => `/system/settings/${m[1]}`],
  [/^\/account$/, '/system/account'],
];
export function moved(path) {
  for (const [re, to] of MOVED) {
    const m = path.match(re);
    if (m) return typeof to === 'function' ? to(m) : to;
  }
  return '';
}

let toastId = 0;
export function toast(msg, kind = 'ok') {
  const id = ++toastId;
  toasts.push({ id, msg, kind });
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id);
    if (i >= 0) toasts.splice(i, 1);
  }, kind === 'error' ? 7000 : 3500);
}

export function protocol(id) {
  return meta.protocols.find((p) => p.id === id);
}
