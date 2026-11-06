<script>
  import { bytes, gb } from '../lib/format.js';
  // Verbrauch mit Fortschrittsbalken (wenn ein Limit gilt)
  let { used = 0, limitGb = 0, compact = false, tiers = [] } = $props();
  const max = $derived(gb(limitGb));
  const pct = $derived(max > 0 ? Math.min(100, (used / max) * 100) : 0);
  const tone = $derived(pct >= 100 ? 'bad' : pct >= 80 ? 'warn' : 'ok');
</script>

<div class="usage" class:compact>
  <div class="spread small">
    <span class="strong">{bytes(used)}</span>
    {#if max > 0}<span class="muted">von {bytes(max)}</span>{:else}<span class="muted">unbegrenzt</span>{/if}
  </div>
  {#if max > 0}
    <div class="track">
      <div class="fill {tone}" style="width:{pct}%"></div>
      {#each tiers as t}
        {#if t.after_gb > 0 && t.after_gb < limitGb}
          <div class="mark" style="left:{(t.after_gb / limitGb) * 100}%" title="Drosselung ab {t.after_gb} GB"></div>
        {/if}
      {/each}
    </div>
  {/if}
</div>

<style>
  .usage {
    min-width: 140px;
  }
  .track {
    position: relative;
    height: 6px;
    border-radius: 6px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    margin-top: 5px;
    overflow: hidden;
  }
  .fill {
    height: 100%;
    border-radius: 6px;
    background: var(--ok);
    transition: width 0.3s;
  }
  .fill.warn {
    background: var(--warn);
  }
  .fill.bad {
    background: var(--bad);
  }
  .mark {
    position: absolute;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--text-2);
    opacity: 0.5;
  }
  .compact .track {
    height: 5px;
  }
</style>
