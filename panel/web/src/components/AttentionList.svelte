<script>
  // „Braucht Aufmerksamkeit“: Einträge aus GET /api/status (status.attention), je mit Link zur Stelle,
  // an der es sich beheben lässt.
  import Icon from './Icon.svelte';
  import { status } from '../lib/state.svelte.js';

  let { compact = false, empty = true } = $props();
  const tone = { error: 'bad', warn: 'warn', info: 'info' };
  const icon = { error: 'alert', warn: 'alert', info: 'download' };
  const ext = (l) => /^https?:/.test(l || '');
</script>

{#if status.attention.length}
  <div class="att" class:compact>
    {#each status.attention as a (a.key)}
      <div class="att-row {tone[a.level]}">
        <span class="att-ic"><Icon name={icon[a.level]} size={15} /></span>
        <div class="grow">
          <div class="att-title">{a.title}</div>
          {#if a.detail && !compact}<div class="small muted att-detail">{a.detail}</div>{/if}
        </div>
        {#if a.link}
          <a class="btn sm" href={a.link} target={ext(a.link) ? '_blank' : undefined} rel={ext(a.link) ? 'noopener noreferrer' : undefined}>{ext(a.link) ? 'Ansehen' : 'Öffnen'}</a>
        {/if}
      </div>
    {/each}
  </div>
{:else if empty && status.at}
  <div class="att-ok"><Icon name="check" size={16} /> Alles in Ordnung – nichts braucht gerade Aufmerksamkeit.</div>
{/if}

<style>
  .att {
    display: flex;
    flex-direction: column;
  }
  .att-row {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
  }
  .att-row:first-child {
    border-top: none;
  }
  .att-ic {
    margin-top: 2px;
    display: grid;
    place-items: center;
  }
  .att-row.bad .att-ic {
    color: var(--bad);
  }
  .att-row.warn .att-ic {
    color: var(--warn);
  }
  .att-row.info .att-ic {
    color: var(--accent, #4a64e8);
  }
  .att-title {
    font-weight: 550;
  }
  .att-detail {
    white-space: pre-line;
    margin-top: 2px;
  }
  .compact .att-row {
    padding: 8px 12px;
  }
  .att-ok {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 14px;
    color: var(--ok, #2f9e6a);
  }
</style>
