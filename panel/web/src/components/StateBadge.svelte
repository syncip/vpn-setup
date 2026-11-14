<script>
  // Deutliche Zustandsanzeige: farbige Pille mit Symbol (und pulsierendem Punkt bei „Verbunden“).
  import Icon from './Icon.svelte';
  let { tone = 'muted', label = '', icon = '', title = '', small = false } = $props();
</script>

<span class="sb {tone}" class:small {title}>
  {#if tone === 'ok'}<span class="pulse"></span>{:else if icon}<Icon name={icon} size={small ? 11 : 13} />{/if}
  {label}
</span>

<style>
  .sb {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px 3px 8px;
    border-radius: 999px;
    font-size: 12.5px;
    font-weight: 600;
    white-space: nowrap;
    border: 1px solid transparent;
    line-height: 1.4;
  }
  .sb.small {
    font-size: 11.5px;
    padding: 1px 8px 1px 6px;
    gap: 5px;
  }
  .ok {
    color: var(--ok);
    background: var(--ok-soft);
    border-color: color-mix(in srgb, var(--ok) 30%, transparent);
  }
  .warn {
    color: var(--warn);
    background: var(--warn-soft);
    border-color: color-mix(in srgb, var(--warn) 30%, transparent);
  }
  .bad {
    color: var(--bad);
    background: var(--bad-soft);
    border-color: color-mix(in srgb, var(--bad) 35%, transparent);
  }
  .idle {
    color: var(--accent);
    background: var(--accent-soft);
    border-color: color-mix(in srgb, var(--accent) 30%, transparent);
  }
  .limit {
    color: #fff;
    background: var(--warn);
  }
  .muted {
    color: var(--muted);
    background: var(--panel-2);
    border-color: var(--border);
  }
  .pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--ok) 60%, transparent);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    70% {
      box-shadow: 0 0 0 6px transparent;
    }
    100% {
      box-shadow: 0 0 0 0 transparent;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .pulse {
      animation: none;
    }
  }
</style>
