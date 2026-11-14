<script>
  // Anordenbare Fenster: 12-Spalten-Raster, Reihenfolge per Ziehen (oder Pfeilen), Breite per −/+,
  // Ausblenden per Auge. Gespeichert pro Admin (lib/layout.svelte.js).
  //   widgets: [{ id, title, w (1–12), body: Snippet, show?: false = gerade nicht vorhanden }]
  // Ausgeblendete Fenster lassen sich im Anordnen-Modus jederzeit wieder einblenden – es geht nichts verloren.
  import Icon from './Icon.svelte';
  import { layout, loadLayout, saveLayout, resetLayout } from '../lib/layout.svelte.js';

  let { id, widgets = [] } = $props();
  const STEPS = [3, 4, 6, 8, 9, 12];

  loadLayout();
  $effect(() => {
    layout.active = id;
    return () => {
      if (layout.active === id) layout.active = '';
      if (layout.editing === id) layout.editing = '';
    };
  });

  const editing = $derived(layout.editing === id);
  const saved = $derived(layout.data[id] || {});
  const byId = $derived(Object.fromEntries(widgets.map((w) => [w.id, w])));

  // Reihenfolge: gespeicherte zuerst, neue Fenster an ihrer Stelle aus den Vorgaben einfügen
  const order = $derived.by(() => {
    const known = new Set(widgets.map((w) => w.id));
    const out = (saved.order || []).filter((x) => known.has(x));
    widgets.forEach((w, i) => {
      if (out.includes(w.id)) return;
      let at = 0;
      for (let j = i - 1; j >= 0; j--) {
        const k = out.indexOf(widgets[j].id);
        if (k >= 0) {
          at = k + 1;
          break;
        }
      }
      out.splice(at, 0, w.id);
    });
    return out;
  });
  const hidden = $derived(new Set((saved.hidden || []).filter((x) => byId[x])));
  const width = (wid) => Math.min(12, Math.max(1, saved.w?.[wid] || byId[wid]?.w || 6));
  const visible = $derived(order.filter((x) => byId[x] && byId[x].show !== false && !hidden.has(x)));
  const hiddenList = $derived(order.filter((x) => hidden.has(x)));

  function store(patch) {
    const cur = layout.data[id] || {};
    layout.data[id] = { order: [...order], hidden: [...hidden], w: { ...(cur.w || {}) }, ...patch };
    saveLayout();
  }
  function move(wid, to) {
    const o = order.filter((x) => x !== wid);
    o.splice(Math.max(0, Math.min(o.length, to)), 0, wid);
    store({ order: o });
  }
  // Schritt nach links/rechts unter den sichtbaren Fenstern
  function step(wid, dir) {
    const v = visible.indexOf(wid);
    const other = visible[v + dir];
    if (!other) return;
    const o = order.filter((x) => x !== wid);
    const k = o.indexOf(other);
    o.splice(dir > 0 ? k + 1 : k, 0, wid);
    store({ order: o });
  }
  function resize(wid, dir) {
    const cur = width(wid);
    const next = dir > 0 ? STEPS.find((s) => s > cur) : [...STEPS].reverse().find((s) => s < cur);
    if (!next) return;
    store({ w: { ...(layout.data[id]?.w || {}), [wid]: next } });
  }
  function hide(wid) {
    store({ hidden: [...hidden, wid] });
  }
  function unhide(wid) {
    store({ hidden: [...hidden].filter((x) => x !== wid) });
  }

  // Ziehen am Griff mit Zeiger-Ereignissen (Maus, Finger, Stift)
  let dragging = $state('');
  let over = $state({ id: '', after: false });
  let boardEl;
  function onGripDown(e, wid) {
    if (e.button !== 0) return;
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    dragging = wid;
  }
  function onGripMove(e) {
    if (!dragging) return;
    const el = document.elementFromPoint(e.clientX, e.clientY)?.closest('.bw');
    if (!el || !boardEl?.contains(el) || el.dataset.wid === dragging) {
      over = { id: '', after: false };
      return;
    }
    const r = el.getBoundingClientRect();
    const sameRow = e.clientY > r.top + 8 && e.clientY < r.bottom - 8;
    over = { id: el.dataset.wid, after: sameRow ? e.clientX > r.left + r.width / 2 : e.clientY > r.top + r.height / 2 };
  }
  function onGripUp() {
    if (dragging && over.id) {
      const o = order.filter((x) => x !== dragging);
      const k = o.indexOf(over.id);
      move(dragging, over.after ? k + 1 : k);
    }
    dragging = '';
    over = { id: '', after: false };
  }
</script>

{#if editing}
  <div class="board-bar">
    <Icon name="grid" size={16} />
    <div class="grow small">
      <b>Fenster anordnen</b> – am Griff ziehen (oder Pfeile), Breite mit <b>−</b>/<b>+</b>, Auge blendet aus.
      {#if hiddenList.length}
        <div class="row wrap hidden-row">
          <span class="muted">Ausgeblendet:</span>
          {#each hiddenList as h}
            <button class="chip" onclick={() => unhide(h)} title="Wieder einblenden"><Icon name="eye" size={13} /> {byId[h].title}</button>
          {/each}
        </div>
      {/if}
    </div>
    <button class="btn sm ghost" onclick={() => resetLayout(id)} title="Reihenfolge, Breiten und Sichtbarkeit auf die Vorgabe zurücksetzen"><Icon name="refresh" size={14} /> Zurücksetzen</button>
    <button class="btn sm primary" onclick={() => (layout.editing = '')}><Icon name="check" size={14} /> Fertig</button>
  </div>
{/if}

<div class="board" class:editing class:is-dragging={!!dragging} bind:this={boardEl}>
  {#each visible as wid (wid)}
    {@const w = byId[wid]}
    {@const span = width(wid)}
    <div
      class="bw"
      class:sm={span <= 4}
      class:md={span > 4 && span <= 8}
      class:dragging={dragging === wid}
      class:drop-before={over.id === wid && !over.after}
      class:drop-after={over.id === wid && over.after}
      style="--w:{span}"
      data-wid={wid}
      role="group"
      aria-label={w.title}
    >
      {#if editing}
        <div class="bw-tools">
          <span class="grip" title="Ziehen zum Verschieben" role="button" tabindex="-1" aria-label="Verschieben" onpointerdown={(e) => onGripDown(e, wid)} onpointermove={onGripMove} onpointerup={onGripUp} onpointercancel={onGripUp}><Icon name="grip" size={16} /></span>
          <span class="bw-title">{w.title}</span>
          <span class="grow"></span>
          <button class="tb" onclick={() => step(wid, -1)} title="Nach vorn" disabled={visible[0] === wid}><Icon name="arrow-left" size={14} /></button>
          <button class="tb" onclick={() => step(wid, 1)} title="Nach hinten" disabled={visible.at(-1) === wid}><Icon name="arrow-right" size={14} /></button>
          <button class="tb" onclick={() => resize(wid, -1)} title="Schmaler" disabled={span <= STEPS[0]}><Icon name="minus" size={14} /></button>
          <span class="tiny muted nowrap">{span}/12</span>
          <button class="tb" onclick={() => resize(wid, 1)} title="Breiter" disabled={span >= 12}><Icon name="plus" size={14} /></button>
          <button class="tb" onclick={() => hide(wid)} title="Ausblenden"><Icon name="eye-off" size={14} /></button>
        </div>
      {/if}
      <div class="bw-body">{@render w.body()}</div>
    </div>
  {/each}
  {#if !visible.length}
    <div class="card card-pad muted small" style="grid-column:1/-1">Alle Fenster sind ausgeblendet. <button class="btn sm" onclick={() => (layout.editing = id)}>Anordnen</button></div>
  {/if}
</div>

<style>
  .board {
    display: grid;
    grid-template-columns: repeat(12, minmax(0, 1fr));
    grid-auto-flow: row dense;
    gap: 16px;
    align-items: stretch;
  }
  .bw {
    grid-column: span var(--w);
    min-width: 0;
    display: flex;
    flex-direction: column;
    position: relative;
  }
  .bw-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .bw-body > :global(*) {
    flex: 1;
  }
  .bw-body > :global(* + *) {
    flex: none;
  }
  @media (max-width: 1100px) {
    .bw.sm {
      grid-column: span 6;
    }
    .bw:not(.sm) {
      grid-column: span 12;
    }
  }
  @media (max-width: 720px) {
    .bw,
    .bw.sm {
      grid-column: span 12;
    }
  }
  .editing .bw {
    outline: 2px dashed var(--border);
    outline-offset: 3px;
    border-radius: var(--radius);
  }
  .editing .bw-body {
    pointer-events: none;
    opacity: 0.9;
  }
  .bw.dragging {
    opacity: 0.4;
  }
  .is-dragging,
  .is-dragging .grip {
    cursor: grabbing;
    user-select: none;
  }
  .bw.drop-before {
    box-shadow: -4px 0 0 0 var(--accent);
  }
  .bw.drop-after {
    box-shadow: 4px 0 0 0 var(--accent);
  }
  .bw-tools {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 4px 6px;
    margin-bottom: 6px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 12px;
  }
  .grip {
    cursor: grab;
    touch-action: none;
    padding: 2px;
    color: var(--muted);
    display: inline-flex;
  }
  .bw-title {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  .tb {
    border: none;
    background: none;
    color: var(--text);
    width: 24px;
    height: 24px;
    border-radius: 6px;
    display: inline-grid;
    place-items: center;
    cursor: pointer;
    flex: none;
  }
  .tb:hover:not(:disabled) {
    background: var(--panel);
  }
  .tb:disabled {
    opacity: 0.35;
    cursor: default;
  }
  .board-bar {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 14px;
    margin-bottom: 14px;
    border: 1px solid var(--accent);
    border-radius: var(--radius);
    background: var(--panel);
    position: sticky;
    top: 8px;
    z-index: 5;
    box-shadow: var(--shadow);
  }
  .hidden-row {
    margin-top: 6px;
    gap: 6px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 1px solid var(--border);
    background: var(--panel-2);
    color: var(--text);
    border-radius: 999px;
    padding: 2px 10px;
    font: inherit;
    font-size: 12px;
    cursor: pointer;
  }
  .chip:hover {
    border-color: var(--accent);
  }
</style>
