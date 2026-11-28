// Gemeinsame Live-Daten (GET /api/live, alle 2 s, nur solange die Seite sichtbar ist).
// Mehrere Fenster derselben Seite (Grafik, Geräteliste, Kennzahlen) teilen sich eine Abfrage:
//   const lv = liveFeed(() => userId, () => aktiv)   – im <script> einer Komponente aufrufen
//   statt der Nutzer-ID geht auch 'server:<ID>' (Verlauf nur der Zugänge dieses Servers)
//   lv.d    – letzte Antwort ({total, history, peers, errors}) oder null
//   lv.err  – Fehlertext der letzten Abfrage, lv.at – Zeitpunkt der letzten Antwort (ms)
// Abgefragt wird nur, solange mindestens ein Fenster aktiv ist.
import { get } from './api.js';

const feeds = new Map(); // Schlüssel ('' bzw. Nutzer-ID) → {state, subs, timer}

function feed(key) {
  let f = feeds.get(key);
  if (!f) {
    const state = $state({ d: null, err: '', at: 0 });
    f = { state, subs: 0, timer: 0, busy: false, vis: null };
    feeds.set(key, f);
  }
  return f;
}

function poll(key, f) {
  if (f.busy || document.hidden) return;
  f.busy = true;
  get(!key ? '/live' : key.startsWith('server:') ? `/live?server=${key.slice(7)}` : `/live?user=${key}`)
    .then((d) => {
      f.state.d = d;
      f.state.at = Date.now();
      f.state.err = '';
    })
    .catch((e) => (f.state.err = e.message))
    .finally(() => (f.busy = false));
}

const fn = (v) => (typeof v === 'function' ? v : () => v);

export function liveFeed(user = 0, on = true) {
  const getUser = fn(user);
  const getOn = fn(on);
  let key = $state(null);
  $effect(() => {
    if (!getOn()) {
      key = null;
      return;
    }
    const k = getUser() ? String(getUser()) : '';
    const f = feed(k);
    key = k;
    f.subs++;
    if (f.subs === 1) {
      poll(k, f);
      f.timer = setInterval(() => poll(k, f), 2000);
      f.vis = () => !document.hidden && poll(k, f);
      document.addEventListener('visibilitychange', f.vis);
    }
    return () => {
      f.subs--;
      if (!f.subs) {
        clearInterval(f.timer);
        document.removeEventListener('visibilitychange', f.vis);
      }
    };
  });
  const st = () => (key == null ? null : feeds.get(key)?.state);
  return {
    get d() {
      return st()?.d ?? null;
    },
    get err() {
      return st()?.err || '';
    },
    get at() {
      return st()?.at || 0;
    },
  };
}
