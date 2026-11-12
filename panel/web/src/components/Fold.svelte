<script>
  // Zuklappbarer Bereich (Hinweise, Auffälligkeiten, Erklärungen). Der Zustand wird pro „id“
  // im Browser gemerkt. head: optionaler Inhalt rechts im Kopf (Zähler, Knöpfe).
  import Icon from './Icon.svelte';

  let { id = '', title = '', icon = '', tone = '', open: initial = true, head, children, count = null } = $props();

  const key = () => 'fold:' + id;
  function read() {
    if (!id) return initial;
    try {
      const v = localStorage.getItem(key());
      return v === null ? initial : v === '1';
    } catch {
      return initial;
    }
  }
  let open = $state(read());
  function toggle() {
    open = !open;
    if (!id) return;
    try {
      localStorage.setItem(key(), open ? '1' : '0');
    } catch {
      /* egal */
    }
  }
</script>

<div class="fold {tone}" class:closed={!open}>
  <div class="fh">
    <button type="button" class="ft" onclick={toggle} aria-expanded={open}>
      <span class="chev" class:open><Icon name="chevron" size={15} /></span>
      {#if icon}<Icon name={icon} size={16} />{/if}
      <span class="tt">{title}</span>
      {#if count !== null}<span class="badge {tone}">{count}</span>{/if}
    </button>
    {#if head}<div class="fx">{@render head()}</div>{/if}
  </div>
  {#if open}<div class="fb">{@render children?.()}</div>{/if}
</div>

<style>
  .fold {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--panel);
  }
  .fold.warn {
    border-color: color-mix(in srgb, var(--warn) 45%, var(--border));
  }
  .fold.bad {
    border-color: color-mix(in srgb, var(--bad) 45%, var(--border));
  }
  .fold.ok {
    border-color: color-mix(in srgb, var(--ok) 35%, var(--border));
  }
  .fh {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 10px 4px 4px;
  }
  .ft {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 0;
    border: none;
    background: none;
    font: inherit;
    color: var(--text);
    cursor: pointer;
    padding: 8px 8px;
    text-align: left;
    border-radius: 8px;
  }
  .ft:hover {
    background: var(--panel-2);
  }
  .tt {
    font-weight: 650;
  }
  .warn .ft :global(svg:not(.chev svg)) {
    color: var(--warn);
  }
  .bad .ft :global(svg) {
    color: var(--bad);
  }
  .ok .ft :global(svg) {
    color: var(--ok);
  }
  .chev {
    display: grid;
    place-items: center;
    color: var(--muted);
    transition: transform 0.15s;
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .fx {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .fb {
    padding: 0 14px 12px;
  }
</style>
