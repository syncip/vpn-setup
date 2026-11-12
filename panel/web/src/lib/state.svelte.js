// Globaler Zustand: Anmeldung, Metadaten (Protokolle), Benachrichtigungen, Route.

export const session = $state({ user: null, checked: false });
export const meta = $state({ protocols: [], version: '', dry_run: false, server_host: '', sub_host: '', lan4: '', lan6: '' });
export const toasts = $state([]);
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
