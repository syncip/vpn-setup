<script>
  import Icon from './Icon.svelte';
  import ListInput from './ListInput.svelte';
  // Reality-Tarnziele: [{dest, server_names: []}]
  let { value = $bindable() } = $props();

  function add() {
    value = [...(value || []), { dest: '', server_names: [] }];
  }
  function remove(i) {
    value = (value || []).filter((_, j) => j !== i);
  }
</script>

<div class="stack-sm">
  {#each value || [] as t, i}
    <div class="target">
      <div class="grid cols-2" style="gap:10px">
        <div class="field">
          <span class="label">Ziel (Host:Port)</span>
          <input class="input mono" bind:value={t.dest} placeholder="www.example.com:443" />
        </div>
        <div class="field">
          <span class="label">SNIs (Servernamen)</span>
          <ListInput bind:value={t.server_names} placeholder="leer = Host des Ziels" />
        </div>
      </div>
      <button type="button" class="btn ghost sm icon danger" onclick={() => remove(i)} aria-label="Ziel entfernen"><Icon name="trash" size={15} /></button>
    </div>
  {/each}
  <div><button type="button" class="btn sm" onclick={add}><Icon name="plus" size={15} /> Tarnziel</button></div>
</div>

<style>
  .target {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--panel-2);
  }
  .target > :first-child {
    flex: 1;
  }
</style>
