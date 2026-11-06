<script>
  import Icon from './Icon.svelte';
  // Liste von Texten (z. B. Netze 192.168.1.0/24)
  let { value = $bindable(), placeholder = '', mono = true } = $props();
  let draft = $state('');

  function add() {
    const v = draft.trim();
    if (!v) return;
    for (const part of v.split(/[\s,;]+/).filter(Boolean)) {
      if (!(value || []).includes(part)) value = [...(value || []), part];
    }
    draft = '';
  }
  function remove(i) {
    value = (value || []).filter((_, j) => j !== i);
  }
</script>

<div class="list">
  {#each value || [] as v, i}
    <span class="chip" class:mono>{v}<button type="button" onclick={() => remove(i)} aria-label="Entfernen"><Icon name="x" size={13} /></button></span>
  {/each}
  <input class="input" class:mono {placeholder} bind:value={draft}
    onkeydown={(e) => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); } }}
    onblur={add} />
</div>

<style>
  .list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
  }
  .list .input {
    flex: 1;
    min-width: 160px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 28px;
    padding: 0 4px 0 10px;
    border-radius: 7px;
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 550;
    font-size: 12.5px;
  }
  .chip.mono {
    font-family: var(--mono);
  }
  .chip button {
    border: none;
    background: none;
    color: inherit;
    cursor: pointer;
    display: grid;
    place-items: center;
    padding: 2px;
    border-radius: 5px;
  }
  .chip button:hover {
    background: rgba(0, 0, 0, 0.08);
  }
</style>
