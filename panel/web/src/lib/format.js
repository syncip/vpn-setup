const GB = 1024 ** 3;

export function bytes(b) {
  b = Number(b) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) {
    b /= 1024;
    i++;
  }
  const d = i === 0 ? 0 : b < 10 ? 2 : b < 100 ? 1 : 0;
  return b.toLocaleString('de-DE', { minimumFractionDigits: d, maximumFractionDigits: d }) + ' ' + u[i];
}

export const gb = (n) => (Number(n) || 0) * GB;

export function rate(mbit) {
  if (!mbit) return 'unbegrenzt';
  if (mbit >= 1000) return (mbit / 1000).toLocaleString('de-DE', { maximumFractionDigits: 1 }) + ' Gbit/s';
  return mbit.toLocaleString('de-DE', { maximumFractionDigits: 1 }) + ' Mbit/s';
}

export function ago(ts) {
  if (!ts) return 'nie';
  const d = Date.now() / 1000 - ts;
  if (d < 180) return 'online';
  if (d < 3600) return `vor ${Math.floor(d / 60)} Min.`;
  if (d < 86400) return `vor ${Math.floor(d / 3600)} Std.`;
  if (d < 7 * 86400) return `vor ${Math.floor(d / 86400)} Tag${d >= 2 * 86400 ? 'en' : ''}`;
  return date(ts);
}

export const isOnline = (ts) => ts && Date.now() / 1000 - ts < 180;

export function date(ts, time = false) {
  if (!ts) return '–';
  const d = new Date(ts * 1000);
  const o = { day: '2-digit', month: '2-digit', year: 'numeric' };
  if (time) Object.assign(o, { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleString('de-DE', o);
}

export function toDateInput(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export function fromDateInput(s) {
  if (!s) return 0;
  const [y, m, d] = s.split('-').map(Number);
  return Math.floor(new Date(y, m - 1, d, 23, 59, 59).getTime() / 1000);
}

export const STATUS = {
  ok: { label: 'Aktiv', tone: 'ok' },
  throttled: { label: 'Gedrosselt', tone: 'warn' },
  blocked: { label: 'Gesperrt', tone: 'bad' },
  disabled: { label: 'Deaktiviert', tone: 'muted' },
  expired: { label: 'Abgelaufen', tone: 'bad' },
};

export const PERIODS = {
  none: 'gesamt',
  daily: 'pro Tag',
  weekly: 'pro Woche',
  monthly: 'pro Monat',
};

export const WEEKDAYS = ['Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'];

// Kurzbeschreibung von Limits in Worten
export function limitsSummary(l) {
  if (!l) return 'Keine Limits';
  const parts = [];
  if (l.traffic_gb > 0) {
    parts.push(`${fmtNum(l.traffic_gb)} GB ${PERIODS[l.period] || ''}`.trim());
    if (l.on_limit === 'throttle') parts.push(`danach ${rate(l.limit_down_mbit)}`);
    else parts.push('danach gesperrt');
  } else parts.push('Datenvolumen unbegrenzt');
  if (l.speed_down_mbit || l.speed_up_mbit) parts.push(`max. ↓ ${rate(l.speed_down_mbit)}`);
  if (l.tiers?.length) parts.push(`${l.tiers.length} Drosselstufe${l.tiers.length > 1 ? 'n' : ''}`);
  if (l.max_devices) parts.push(`max. ${l.max_devices} Zugänge`);
  return parts.join(' · ');
}

export const fmtNum = (n) => (Number(n) || 0).toLocaleString('de-DE', { maximumFractionDigits: 2 });

export const PROTO_LABEL = { wireguard: 'WireGuard', vless: 'VLESS', hysteria2: 'Hysteria2' };

// copy kopiert in die Zwischenablage; Fallback für Browser ohne Clipboard-API (z. B. ohne HTTPS).
export async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

export function download(name, content) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// Tiefe Kopie (funktioniert auch mit Svelte-State-Proxies, anders als structuredClone)
export const clone = (v) => (v == null ? v : JSON.parse(JSON.stringify(v)));

// speed: Bytes pro Sekunde → bit/s mit passender Einheit
export function speed(bps) {
  let b = (Number(bps) || 0) * 8;
  const u = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
  let i = 0;
  while (b >= 1000 && i < u.length - 1) {
    b /= 1000;
    i++;
  }
  const d = i === 0 ? 0 : b < 10 ? 2 : b < 100 ? 1 : 0;
  return b.toLocaleString('de-DE', { minimumFractionDigits: d, maximumFractionDigits: d }) + ' ' + u[i];
}

// duration: Sekunden → „2 Std. 5 Min.“
export function duration(s) {
  s = Math.max(0, Math.floor(s));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} Min.`;
  if (s < 86400) return `${Math.floor(s / 3600)} Std. ${Math.floor((s % 3600) / 60)} Min.`;
  return `${Math.floor(s / 86400)} T. ${Math.floor((s % 86400) / 3600)} Std.`;
}
