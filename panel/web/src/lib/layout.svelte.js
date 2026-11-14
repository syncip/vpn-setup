// Fenster-Anordnung je Seite (Reihenfolge, Breite, ausgeblendet), pro Admin auf dem Server
// gespeichert (GET/PUT /api/layout). Board.svelte liest und schreibt hier.
import { get, put } from './api.js';
import { toast } from './state.svelte.js';

export const layout = $state({
  data: {}, // board-id → { order: [], hidden: [], w: {} }
  loaded: false,
  active: '', // Board der aktuellen Seite (PageHead zeigt dann „Anordnen“)
  editing: '', // Board, das gerade angeordnet wird
});

let loading = null;
export function loadLayout() {
  if (layout.loaded) return Promise.resolve();
  loading ||= get('/layout')
    .then((d) => {
      layout.data = d && typeof d === 'object' ? d : {};
    })
    .catch(() => {})
    .finally(() => {
      layout.loaded = true;
      loading = null;
    });
  return loading;
}

let timer = 0;
export function saveLayout() {
  clearTimeout(timer);
  timer = setTimeout(async () => {
    try {
      await put('/layout', $state.snapshot(layout.data));
    } catch (e) {
      toast('Anordnung nicht gespeichert: ' + e.message, 'error');
    }
  }, 500);
}

export function resetLayout(board) {
  delete layout.data[board];
  saveLayout();
}
