<script>
  // Zeitraum-Wahl für Verlaufsgrafiken: letzte 24 Std./7/30/90 Tage/12 Monate, Kalender (Tag, Woche, Monat, Jahr)
  // mit ◀ ▶ zum Blättern, frei von–bis und die Gliederung (Stunden, Tage, Wochen, Monate).
  // Die Auswahl wird je id pro Admin gespeichert (layout „period:<id>“). Logik: lib/period.js.
  //   value (bindable): Auswahl · onchange(resolved): nach jeder Änderung · start: Vorgabe-Modus
  import Icon from './Icon.svelte';
  import { untrack } from 'svelte';
  import { layout, loadLayout, saveLayout } from '../lib/layout.svelte.js';
  import { MODES, GRAINS, DEFAULT, resolve, isoDay } from '../lib/period.js';

  let { id = '', value = $bindable(null), start = '' } = $props();

  loadLayout();
  const key = $derived(id ? `period:${id}` : '');
  let taken = false;
  $effect(() => {
    if (taken || (key && !layout.loaded)) return;
    taken = true;
    const saved = untrack(() => key && layout.data[key]);
    untrack(() => {
      if (saved && MODES.some((m) => m[0] === saved.mode)) value = { ...DEFAULT, ...saved };
      else if (!value) value = { ...DEFAULT, mode: MODES.some((m) => m[0] === start) ? start : DEFAULT.mode };
    });
  });
  const sel = $derived(value || { ...DEFAULT, mode: start || DEFAULT.mode });
  const r = $derived(resolve(sel));

  function set(patch) {
    const v = { ...sel, ...patch };
    if (v.mode === 'custom' && (!v.from || !v.to)) {
      // frei: mit dem gerade gezeigten Zeitraum beginnen
      v.from = v.from || isoDay(new Date(r.from));
      v.to = v.to || isoDay(new Date(r.to - 1));
    }
    value = v;
    if (key) {
      layout.data[key] = { mode: v.mode, grain: v.grain, from: v.from, to: v.to, offset: v.offset };
      saveLayout();
    }
  }
  const today = isoDay(new Date());
</script>

<div class="pp" role="group" aria-label="Zeitraum">
  <select class="input sm" value={sel.mode} onchange={(e) => set({ mode: e.currentTarget.value, offset: 0 })} aria-label="Zeitraum" title="Zeitraum">
    <optgroup label="Die letzten …">
      {#each MODES.slice(0, 5) as [k, l]}<option value={k}>{l}</option>{/each}
    </optgroup>
    <optgroup label="Kalender">
      {#each MODES.slice(5, 9) as [k, l]}<option value={k}>{l}</option>{/each}
    </optgroup>
    <option value="custom">{MODES[9][1]}</option>
  </select>

  {#if sel.mode === 'custom'}
    <input class="input sm" type="date" value={sel.from} max={sel.to || today} onchange={(e) => e.currentTarget.value && set({ from: e.currentTarget.value })} aria-label="von" />
    <span class="muted small">–</span>
    <input class="input sm" type="date" value={sel.to} min={sel.from} max={today} onchange={(e) => e.currentTarget.value && set({ to: e.currentTarget.value })} aria-label="bis" />
  {:else}
    <div class="nav">
      <button class="ib" onclick={() => set({ offset: r.offset - 1 })} title="Davor" aria-label="Davor"><Icon name="chevron-down" size={14} /></button>
      <span class="small strong lbl" title={r.label}>{r.label}</span>
      <button class="ib next" onclick={() => set({ offset: r.offset + 1 })} disabled={!r.canNext} title="Danach" aria-label="Danach"><Icon name="chevron-down" size={14} /></button>
      {#if r.offset < 0}<button class="btn ghost sm" onclick={() => set({ offset: 0 })} title="Zum aktuellen Zeitraum">Jetzt</button>{/if}
    </div>
  {/if}

  <label class="gr small muted">
    je
    <select class="input sm" value={sel.grain || 'auto'} onchange={(e) => set({ grain: e.currentTarget.value })} aria-label="Gliederung" title="Gliederung der Balken">
      {#each GRAINS as [k, l]}<option value={k}>{k === 'auto' ? `${l} (${GRAINS.find((g) => g[0] === r.grain)?.[1]})` : l}</option>{/each}
    </select>
  </label>
</div>

<style>
  .pp {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 10px;
  }
  .pp :global(.input.sm) {
    height: 30px;
    padding: 2px 8px;
    font-size: var(--fs-sm);
    width: auto;
  }
  .nav {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
  }
  .lbl {
    min-width: 7em;
    text-align: center;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ib {
    display: inline-grid;
    place-items: center;
    width: 28px;
    height: 28px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--panel);
    color: inherit;
    cursor: pointer;
    transform: rotate(90deg);
  }
  .ib.next {
    transform: rotate(-90deg);
  }
  .ib:disabled {
    opacity: 0.4;
    cursor: default;
  }
  .ib:not(:disabled):hover {
    background: var(--panel-2);
  }
  .gr {
    display: flex;
    align-items: center;
    gap: 6px;
  }
</style>
