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

// postFile: POST mit JSON, Antwort als Datei (z. B. Sicherung) → wird im Browser gespeichert.
export async function postFile(path, body, fallbackName) {
  let res;
  try {
    res = await fetch('/api' + path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'vpnpanel' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error('Keine Verbindung zum Server');
  }
  if (!res.ok) {
    let data = {};
    try {
      data = await res.json();
    } catch {
      /* leer */
    }
    if (res.status === 401) session.user = null;
    throw new Error(data.error || res.statusText || 'Fehler');
  }
  const blob = await res.blob();
  const m = /filename="?([^";]+)"?/.exec(res.headers.get('Content-Disposition') || '');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1] : fallbackName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  return { size: blob.size, name: a.download };
}

// upload: Formular mit Datei (multipart) senden, Antwort als JSON.
export async function upload(path, form) {
  let res;
  try {
    res = await fetch('/api' + path, { method: 'POST', credentials: 'same-origin', headers: { 'X-Requested-With': 'vpnpanel' }, body: form });
  } catch {
    throw new Error('Keine Verbindung zum Server');
  }
  let data = {};
  try {
    data = await res.json();
  } catch {
    /* leer */
  }
  if (res.status === 401) session.user = null;
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
