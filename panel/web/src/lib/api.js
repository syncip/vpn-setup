import { session, toast } from './state.svelte.js';

async function request(method, path, body) {
  let res;
  try {
    res = await fetch('/api' + path, {
      method,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'vpnpanel' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    // Server nicht erreichbar (Neustart, Netz weg) – verständliche Meldung statt „Failed to fetch“
    const e = new Error('Keine Verbindung zum Server');
    e.offline = true;
    throw e;
  }
  let data = {};
  try {
    data = await res.json();
  } catch {
    /* leer */
  }
  if (res.status === 401 && !path.startsWith('/auth/login')) {
    session.user = null;
  }
  if (!res.ok) throw new Error(data.error || res.statusText || 'Fehler');
  return data;
}

export const get = (p) => request('GET', p);
export const post = (p, b = {}) => request('POST', p, b);
export const put = (p, b = {}) => request('PUT', p, b);
export const del = (p) => request('DELETE', p);

// run führt eine Aktion aus und zeigt Erfolg/Fehler an.
export async function run(fn, okMsg) {
  try {
    const r = await fn();
    if (okMsg) toast(okMsg);
    return r ?? true;
  } catch (e) {
    toast(e.message, 'error');
    return null;
  }
}
