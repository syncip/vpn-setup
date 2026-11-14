// Zustand eines Ausgangs – eine Stelle für Tabelle, Übersicht und Live-Anzeige.
//   tone: ok | warn | bad | idle | limit | muted
import { fmtNum } from './format.js';

export function exitState(e) {
  const s = e.status;
  const lim = e.limit;
  if (!e.enabled) return { tone: 'muted', label: 'Deaktiviert', icon: 'power', detail: 'Von Hand ausgeschaltet' };
  if (lim?.status === 'blocked') return { tone: 'limit', label: 'Abgeschaltet', icon: 'gauge', detail: lim.reason || 'Datenlimit erreicht' };
  const standby = e.mode === 'standby';
  if (standby && !s?.connected) {
    const bad = s?.checked && s.error;
    return { tone: bad ? 'warn' : 'idle', label: 'Bereitschaft', icon: 'clock', detail: bad ? `getrennt · letzte Prüfung: ${s.error}` : 'getrennt, verbindet bei Bedarf' };
  }
  if (!s || !s.checked) return { tone: 'muted', label: 'Wird geprüft', icon: 'refresh', detail: 'noch keine Messung' };
  if (!s.up) return { tone: 'bad', label: 'Getrennt', icon: 'x', detail: s.error || 'Tunnel nicht verbunden' };
  if (s.error) return { tone: 'bad', label: 'Gestört', icon: 'alert', detail: s.error };
  if (s.loss >= 50) return { tone: 'bad', label: 'Gestört', icon: 'alert', detail: `${fmtNum(Math.round(s.loss))} % Verlust` };
  if (s.loss > 10 || s.rtt > 300) return { tone: 'warn', label: 'Instabil', icon: 'activity', detail: `${fmtNum(Math.round(s.loss))} % Verlust · ${fmtNum(Math.round(s.rtt))} ms` };
  return { tone: 'ok', label: 'Verbunden', icon: 'check', detail: standby ? 'Bereitschaft · gerade verbunden' : `${fmtNum(Math.round(s.rtt))} ms · ${fmtNum(Math.round(s.loss))} % Verlust` };
}

// Kurzform für Zähler und Badge-Klassen (ok | warn | bad | muted)
export const toneClass = (t) => ({ idle: 'muted', limit: 'warn' })[t] || t;
