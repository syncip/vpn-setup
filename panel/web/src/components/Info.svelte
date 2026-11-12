<script>
  // „i“-Knopf: öffnet ein Popup mit Hilfe, Hinweisen oder Befehlen (z. B. Firewall-Regeln).
  // Inhalt als children (Snippet) oder text. wide: breites Popup für Befehle/Tabellen.
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';

  let { title = 'Info', text = '', wide = false, children, label = '' } = $props();

  let open = $state(false);
  let btn;
  let pop = $state();
  let pos = $state({ left: 0, top: 0, up: false, w: 340 });

  function place() {
    if (!btn) return;
    const r = btn.getBoundingClientRect();
    const w = Math.min(wide ? 620 : 360, window.innerWidth - 16);
    const left = Math.max(8, Math.min(r.left - 20, window.innerWidth - w - 8));
    const below = window.innerHeight - r.bottom;
    const up = below < 240 && r.top > below;
    pos = { left, top: up ? r.top - 6 : r.bottom + 6, up, w, maxH: Math.max(160, (up ? r.top : below) - 24) };
  }
  async function toggle(e) {
    e.preventDefault();
    e.stopPropagation();
    if (open) return (open = false);
    place();
    open = true;
    await tick();
    pop?.focus();
  }
  $effect(() => {
    if (!open) return;
    const down = (e) => {
      if (!pop?.contains(e.target) && !btn?.contains(e.target)) open = false;
    };
    const key = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        open = false;
        btn?.focus();
      }
    };
    const move = (e) => {
      if (e.target instanceof Node && pop?.contains(e.target)) return;
      place();
    };
    window.addEventListener('pointerdown', down, true);
    window.addEventListener('keydown', key, true);
    window.addEventListener('scroll', move, true);
    window.addEventListener('resize', move);
    return () => {
      window.removeEventListener('pointerdown', down, true);
      window.removeEventListener('keydown', key, true);
      window.removeEventListener('scroll', move, true);
      window.removeEventListener('resize', move);
    };
  });
</script>

<button type="button" class="info-btn" class:on={open} bind:this={btn} onclick={toggle} title={title} aria-label="Info: {title}" aria-expanded={open}>
  <Icon name="info" size={15} />{#if label}<span>{label}</span>{/if}
</button>

{#if open}
  <div class="info-pop card" class:up={pos.up} bind:this={pop} tabindex="-1" role="dialog" aria-label={title}
    style="left:{pos.left}px;top:{pos.top}px;width:{pos.w}px;max-height:{pos.maxH}px">
    <div class="ih">
      <Icon name="info" size={15} />
      <strong class="grow">{title}</strong>
      <button type="button" class="x" onclick={() => (open = false)} aria-label="Schließen"><Icon name="x" size={14} /></button>
    </div>
    <div class="ib">
      {#if children}{@render children()}{:else}<p>{text}</p>{/if}
    </div>
  </div>
{/if}

<style>
  .info-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    padding: 2px;
    border-radius: 50%;
    vertical-align: middle;
    font: inherit;
    font-size: 12px;
    font-weight: 550;
    line-height: 1;
  }
  .info-btn span {
    text-transform: none;
  }
  .info-btn:hover,
  .info-btn.on {
    color: var(--accent);
  }
  .info-pop {
    position: fixed;
    z-index: 210;
    box-shadow: var(--shadow-lg);
    display: flex;
    flex-direction: column;
    padding: 0;
    outline: none;
    text-align: left;
    font-weight: 400;
    text-transform: none;
    letter-spacing: 0;
    white-space: normal;
  }
  .info-pop.up {
    transform: translateY(-100%);
  }
  .ih {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px 8px;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
  }
  .ih strong {
    color: var(--text);
    font-size: 13.5px;
  }
  .x {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    display: grid;
    place-items: center;
    padding: 2px;
  }
  .ib {
    padding: 10px 14px 12px;
    font-size: 13px;
    color: var(--text-2);
    overflow: auto;
    line-height: 1.5;
  }
  .ib :global(p) {
    margin: 0 0 8px;
  }
  .ib :global(p:last-child) {
    margin-bottom: 0;
  }
  .ib :global(ul) {
    margin: 0 0 8px;
    padding-left: 18px;
  }
  .ib :global(pre) {
    font-family: var(--mono);
    font-size: 12px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    overflow-x: auto;
    white-space: pre;
    margin: 4px 0 8px;
  }
</style>
