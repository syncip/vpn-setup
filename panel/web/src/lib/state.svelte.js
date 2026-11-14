// Globaler Zustand: Anmeldung, Metadaten (Protokolle), Benachrichtigungen, Route.

export const session = $state({ user: null, checked: false });
export const meta = $state({ protocols: [], version: '', dry_run: false, server_host: '', sub_host: '', lan4: '', lan6: '', pub4: '', pub6: '' });
export const toasts = $state([]);
// status: Kennzahlen des Servers und „Braucht Aufmerksamkeit“ (GET /api/status, alle 5 s aus App.svelte)
export const status = $state({ host: null, attention: [], peers: 0, peers_online: 0, at: 0 });
// intent: Absicht über Seitenwechsel hinweg (z. B. Schnellaktion „Nutzer anlegen“ öffnet den Dialog)
export const intent = $state({ create: '' });
export const route = $state({ path: location.hash.slice(1) || '/' });

window.addEventListener('hashchange', () => {
  route.path = location.hash.slice(1) || '/';
});

export function go(path) {
  location.hash = path;
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
