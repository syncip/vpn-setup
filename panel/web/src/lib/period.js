// Zeitraum und Gliederung für Verlaufsgrafiken (Gegenstück: internal/api/period.go).
//   Auswahl sel = { mode, offset, from, to, grain }
//     mode:   '24h' | '7d' | '30d' | '90d' | '365d' (die letzten …) · 'day' | 'week' | 'month' | 'year' (Kalender) · 'custom'
//     offset: 0 = aktueller Zeitraum, -1 = davor … (Blättern mit ◀ ▶)
//     from/to: 'JJJJ-MM-TT' (nur custom, beide Tage eingeschlossen)
//     grain:  'auto' | 'hour' | 'day' | 'week' | 'month'
// Tage, Wochen (ab Montag) und Monate in der Zeitzone des Browsers.

export const MODES = [
  ['24h', 'Letzte 24 Std.'],
  ['7d', 'Letzte 7 Tage'],
  ['30d', 'Letzte 30 Tage'],
  ['90d', 'Letzte 90 Tage'],
  ['365d', 'Letzte 12 Monate'],
  ['day', 'Tag'],
  ['week', 'Woche'],
  ['month', 'Monat'],
  ['year', 'Jahr'],
  ['custom', 'Frei (von – bis)'],
];
export const GRAINS = [
  ['auto', 'Automatisch'],
  ['hour', 'Stunden'],
  ['day', 'Tage'],
  ['week', 'Wochen'],
  ['month', 'Monate'],
];
export const GRAIN_MS = { hour: 3600000, day: 86400000, week: 7 * 86400000, month: 30 * 86400000 };
const LAST = { '24h': 1, '7d': 7, '30d': 30, '90d': 90, '365d': 365 };
const MAX_HOUR_SPAN = 93 * 86400000;
export const DEFAULT = { mode: '24h', offset: 0, from: '', to: '', grain: 'auto' };

export const TZ = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch {
    return '';
  }
})();

// Beginn des Abschnitts, in dem t (ms) liegt
export function slotStart(t, grain) {
  const d = new Date(t);
  if (grain === 'hour') return t - (((t % 3600000) + 3600000) % 3600000);
  if (grain === 'month') return new Date(d.getFullYear(), d.getMonth(), 1).getTime();
  if (grain === 'week') return new Date(d.getFullYear(), d.getMonth(), d.getDate() - ((d.getDay() + 6) % 7)).getTime();
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}
// Beginn des folgenden Abschnitts
export function slotNext(t, grain) {
  const d = new Date(t);
  if (grain === 'hour') return t + 3600000;
  if (grain === 'month') return new Date(d.getFullYear(), d.getMonth() + 1, 1).getTime();
  if (grain === 'week') return new Date(d.getFullYear(), d.getMonth(), d.getDate() + 7).getTime();
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).getTime();
}

const day0 = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
const parseDay = (s) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || '');
  return m ? new Date(+m[1], +m[2] - 1, +m[3]) : null;
};
export const isoDay = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

// Kalenderwoche nach ISO 8601
export function isoWeek(t) {
  const d = new Date(t);
  const x = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const wd = x.getUTCDay() || 7;
  x.setUTCDate(x.getUTCDate() + 4 - wd);
  const y0 = new Date(Date.UTC(x.getUTCFullYear(), 0, 1));
  return Math.ceil(((x - y0) / 86400000 + 1) / 7);
}

function autoGrain(span, mode) {
  if (mode === 'day') return 'hour';
  if (mode === 'year' || mode === '365d') return 'month';
  if (span <= 3 * 86400000) return 'hour';
  if (span <= 92 * 86400000) return 'day';
  return 'month';
}

// resolve: Auswahl → { from, to (ms, to exklusiv), grain, label, canNext }
export function resolve(sel, now = Date.now()) {
  const s = { ...DEFAULT, ...(sel || {}) };
  const off = Math.min(0, Math.trunc(+s.offset || 0));
  const n = new Date(now);
  let from, to, label;
  if (LAST[s.mode]) {
    const len = LAST[s.mode] * 86400000;
    to = now + off * len;
    from = to - len;
    label = off ? `${fmtDay(from)} – ${fmtDay(to)}` : MODES.find((m) => m[0] === s.mode)[1];
  } else if (s.mode === 'day') {
    const d = day0(n);
    d.setDate(d.getDate() + off);
    from = d.getTime();
    to = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).getTime();
    label = off === 0 ? 'Heute' : off === -1 ? 'Gestern' : new Date(from).toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' });
  } else if (s.mode === 'week') {
    from = slotStart(now, 'week') + 0;
    const d = new Date(from);
    from = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 7 * off).getTime();
    to = slotNext(from, 'week');
    label = `KW ${isoWeek(from)} · ${fmtDay(from)} – ${fmtDay(to - 1)}`;
  } else if (s.mode === 'month') {
    from = new Date(n.getFullYear(), n.getMonth() + off, 1).getTime();
    to = slotNext(from, 'month');
    label = new Date(from).toLocaleDateString('de-DE', { month: 'long', year: 'numeric' });
  } else if (s.mode === 'year') {
    from = new Date(n.getFullYear() + off, 0, 1).getTime();
    to = new Date(n.getFullYear() + off + 1, 0, 1).getTime();
    label = String(n.getFullYear() + off);
  } else {
    const a = parseDay(s.from) || new Date(day0(n).getTime() - 6 * 86400000);
    let b = parseDay(s.to) || day0(n);
    if (b < a) b = a;
    from = a.getTime();
    to = new Date(b.getFullYear(), b.getMonth(), b.getDate() + 1).getTime();
    label = `${fmtDay(from)} – ${fmtDay(to - 1)}`;
  }
  const span = to - from;
  let grain = GRAIN_MS[s.grain] ? s.grain : autoGrain(span, s.mode);
  if (grain === 'hour' && span > MAX_HOUR_SPAN) grain = 'day';
  const canNext = s.mode !== 'custom' && off < 0;
  return { from, to, grain, label, canNext, offset: off, mode: s.mode };
}

const fmtDay = (t) => new Date(t).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: '2-digit' });

// Abfrage für die API (Sekunden)
export function query(r) {
  const p = new URLSearchParams({ from: String(Math.floor(r.from / 1000)), to: String(Math.ceil(r.to / 1000)), grain: r.grain });
  if (TZ) p.set('tz', TZ);
  return p.toString();
}

// Beschriftung eines Abschnitts (Tooltip)
export function slotLabel(t, grain) {
  const d = new Date(t);
  if (grain === 'month') return d.toLocaleDateString('de-DE', { month: 'long', year: 'numeric' });
  if (grain === 'week') return `KW ${isoWeek(t)} · ${fmtDay(t)} – ${fmtDay(slotNext(t, 'week') - 1)}`;
  if (grain === 'day') return d.toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' });
  return d.toLocaleString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) + ' – ' + new Date(t + 3600000).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
}
export const GRAIN_WORD = { hour: 'Stunde', day: 'Tag', week: 'Woche', month: 'Monat' };
