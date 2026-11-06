<script>
  import Icon from './Icon.svelte';
  let { open = $bindable(false), title = '', subtitle = '', width = 560, children, footer, onclose } = $props();

  function close() {
    open = false;
    onclose?.();
  }
  function key(e) {
    if (open && e.key === 'Escape') close();
  }
</script>

<svelte:window onkeydown={key} />

{#if open}
  <div class="backdrop" role="presentation" onmousedown={(e) => e.target === e.currentTarget && close()}>
    <div class="modal card" style="max-width:{width}px" role="dialog" aria-modal="true" aria-label={title}>
      <div class="head">
        <div class="grow">
          <h2>{title}</h2>
          {#if subtitle}<div class="muted small">{subtitle}</div>{/if}
        </div>
        <button class="btn ghost icon" onclick={close} aria-label="Schließen"><Icon name="x" /></button>
      </div>
      <div class="body">{@render children?.()}</div>
      {#if footer}<div class="foot">{@render footer()}</div>{/if}
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(10, 14, 25, 0.5);
    backdrop-filter: blur(2px);
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 6vh 16px 16px;
    z-index: 50;
    overflow-y: auto;
    animation: fade 0.12s ease-out;
  }
  .modal {
    width: 100%;
    box-shadow: var(--shadow-lg);
    animation: pop 0.14s ease-out;
  }
  .head {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 18px 20px 0;
  }
  .body {
    padding: 18px 20px;
  }
  .foot {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 14px 20px;
    border-top: 1px solid var(--border);
    background: var(--panel-2);
    border-radius: 0 0 var(--radius) var(--radius);
  }
  @keyframes fade {
    from {
      opacity: 0;
    }
  }
  @keyframes pop {
    from {
      transform: translateY(8px) scale(0.98);
      opacity: 0;
    }
  }
</style>
