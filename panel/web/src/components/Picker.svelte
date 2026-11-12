<script>
  // Auswahlfeld mit Suche – für lange Listen (Nutzer, Geräte, Server).
  // items: [{value, label, sub?, proto?, icon?, group?, off?, search?}]
  // none: Text für den Leer-Eintrag (Wert noneValue), z. B. „Alle Geräte“; ohne none gibt es keinen.
  // onpick(item): wird bei jeder Auswahl gerufen. keep=false: Feld zeigt danach wieder den Platzhalter
  // (für „Hinzufügen“-Auswahlen).
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';
  import ProtoLogo from './ProtoLogo.svelte';
  import { tokens, matches } from '../lib/pick.js';

  let {
    items = [],
    value = $bindable(),
    placeholder = 'wählen …',
    none = '',
    noneValue = 0,
    onpick,
    keep = true,
    id = undefined,
    disabled = false,
    width = '',
    max = 150,
  } = $props();

  let open = $state(false);
  let q = $state('');
  let active = $state(0);
  let btn;
  let input = $state();
  let listEl = $state();
  let pos = $state({ left: 0, top: 0, width: 320, up: false, maxH: 340 });

  const all = $derived(none ? [{ value: noneValue, label: none, icon: 'globe', isNone: true }, ...items] : items);
  const current = $derived(keep ? all.find((i) => i.value === value || (value != null && String(i.value) === String(value))) : null);
  const toks = $derived(tokens(q));
  const hits = $derived(all.filter((i) => i.isNone ? !toks.length : matches(i.search || `${i.label} ${i.sub || ''}`, toks)));
  const shown = $derived(hits.slice(0, max));

  function place() {
    if (!btn) return;
    const r = btn.getBoundingClientRect();
    const w = Math.max(r.width, 300);
    const below = window.innerHeight - r.bottom - 12;
    const above = r.top - 12;
    const up = below < 260 && above > below;
    const left = Math.min(r.left, window.innerWidth - w - 8);
    pos = { left: Math.max(8, left), top: up ? r.top - 4 : r.bottom + 4, width: w, up, maxH: Math.max(160, Math.min(380, (up ? above : below) - 52)) };
  }
  async function show() {
    if (disabled) return;
    q = '';
    place();
    open = true;
    const i = shown.findIndex((x) => x === current);
    active = i >= 0 ? i : 0;
    await tick();
    input?.focus();
    scrollActive();
  }
  function hide(focusBtn = true) {
    open = false;
    if (focusBtn) btn?.focus();
  }
  function choose(it) {
    if (!it) return;
    if (keep) value = it.value;
    onpick?.(it);
    hide();
  }
  async function scrollActive() {
    await tick();
    listEl?.querySelector('.opt.act')?.scrollIntoView({ block: 'nearest' });
  }
  function key(e) {
    if (e.key === 'ArrowDown') {
      active = Math.min(shown.length - 1, active + 1);
      scrollActive();
    } else if (e.key === 'ArrowUp') {
      active = Math.max(0, active - 1);
      scrollActive();
    } else if (e.key === 'Enter') {
      choose(shown[active]);
    } else if (e.key === 'Escape') {
      hide();
    } else if (e.key === 'Tab') {
      hide(false);
      return;
    } else return;
    e.preventDefault();
    e.stopPropagation();
  }
  function btnKey(e) {
    if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      show();
    }
  }
  $effect(() => {
    q;
    active = 0;
  });
  // schließen bei Klick daneben, mitwandern beim Scrollen
  $effect(() => {
    if (!open) return;
    const down = (e) => {
      if (!e.target.closest?.('.picker-pop') && !btn?.contains(e.target)) hide(false);
    };
    const move = (e) => {
      if (e.target instanceof Node && listEl?.contains(e.target)) return;
      place();
    };
    window.addEventListener('pointerdown', down, true);
    window.addEventListener('scroll', move, true);
    window.addEventListener('resize', move);
    return () => {
      window.removeEventListener('pointerdown', down, true);
      window.removeEventListener('scroll', move, true);
      window.removeEventListener('resize', move);
    };
  });
</script>

<button
  type="button"
  class="input picker"
  class:open
  bind:this={btn}
  {id}
  {disabled}
  style={width ? `width:${width}` : ''}
  onclick={() => (open ? hide() : show())}
  onkeydown={btnKey}
  aria-haspopup="listbox"
  aria-expanded={open}
>
  {#if current}
    {#if current.proto}<ProtoLogo id={current.proto} size={16} />{:else if current.icon}<Icon name={current.icon} size={15} />{/if}
    <span class="cur ellipsis">{current.label}{#if current.sub}<span class="muted"> · {current.sub}</span>{/if}</span>
  {:else}
    <span class="cur ellipsis muted">{placeholder}</span>
  {/if}
  <Icon name="chevron-down" size={15} />
</button>

{#if open}
  <div class="picker-pop card" class:up={pos.up} style="left:{pos.left}px;top:{pos.top}px;width:{pos.width}px" role="presentation">
    <div class="srch">
      <Icon name="search" size={15} />
      <input bind:this={input} bind:value={q} onkeydown={key} placeholder="Suchen …" aria-label="Suchen" autocomplete="off" spellcheck="false" />
      {#if q}<button type="button" class="clr" onclick={() => { q = ''; input.focus(); }} aria-label="Suche leeren"><Icon name="x" size={14} /></button>{/if}
    </div>
    <div class="opts" bind:this={listEl} style="max-height:{pos.maxH}px" role="listbox">
      {#each shown as it, i}
        {#if it.group && it.group !== shown[i - 1]?.group}<div class="grp">{it.group}</div>{/if}
        <button
          type="button"
          class="opt"
          class:act={i === active}
          class:sel={it === current}
          class:off={it.off}
          role="option"
          aria-selected={it === current}
          onmousemove={() => (active = i)}
          onclick={() => choose(it)}
        >
          <span class="ic">{#if it.proto}<ProtoLogo id={it.proto} size={18} />{:else if it.icon}<Icon name={it.icon} size={16} />{/if}</span>
          <span class="txt">
            <span class="lbl ellipsis">{it.label}{#if it.off}<span class="muted"> (aus)</span>{/if}</span>
            {#if it.sub}<span class="sub ellipsis">{it.sub}</span>{/if}
          </span>
          {#if it === current}<Icon name="check" size={15} />{/if}
        </button>
      {:else}
        <div class="nohit">Keine Treffer für „{q}“</div>
      {/each}
      {#if hits.length > shown.length}<div class="nohit">{hits.length - shown.length} weitere – Suche verfeinern</div>{/if}
    </div>
  </div>
{/if}

<style>
  .picker {
    display: flex;
    align-items: center;
    gap: 8px;
    text-align: left;
    cursor: pointer;
    min-width: 0;
  }
  .picker:disabled {
    cursor: default;
    opacity: 0.6;
  }
  .picker.open {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .cur {
    flex: 1;
    min-width: 0;
  }
  .picker-pop {
    position: fixed;
    z-index: 200;
    box-shadow: var(--shadow-lg);
    overflow: hidden;
    padding: 0;
  }
  .picker-pop.up {
    transform: translateY(-100%);
  }
  .srch {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    color: var(--muted);
  }
  .srch input {
    flex: 1;
    border: none;
    outline: none;
    background: none;
    font: inherit;
    color: var(--text);
    min-width: 0;
    height: 24px;
  }
  .clr {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    display: grid;
    place-items: center;
    padding: 2px;
  }
  .opts {
    overflow-y: auto;
    padding: 4px;
  }
  .grp {
    font-size: 11px;
    font-weight: 650;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    padding: 8px 8px 4px;
  }
  .opt {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
    border: none;
    background: none;
    font: inherit;
    color: var(--text);
    text-align: left;
    padding: 6px 8px;
    border-radius: 6px;
    cursor: pointer;
  }
  .opt.act {
    background: var(--panel-2);
  }
  .opt.sel {
    color: var(--accent);
  }
  .opt.off .lbl {
    opacity: 0.6;
  }
  .ic {
    width: 18px;
    display: grid;
    place-items: center;
    flex: none;
    color: var(--muted);
  }
  .txt {
    display: flex;
    flex-direction: column;
    min-width: 0;
    flex: 1;
  }
  .lbl {
    font-weight: 550;
  }
  .sub {
    font-size: 12px;
    color: var(--muted);
  }
  .nohit {
    padding: 10px;
    color: var(--muted);
    font-size: 13px;
  }
</style>
