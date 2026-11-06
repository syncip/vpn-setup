<script>
  import Icon from './Icon.svelte';
  import ListInput from './ListInput.svelte';
  import TargetsInput from './TargetsInput.svelte';

  // Formular aus Feldbeschreibungen der Protokolltreiber.
  // fields: [{key,label,type,default,options,help,advanced,kinds,placeholder}]
  let { fields = [], values = $bindable({}), kind = '', peers = [] } = $props();
  let showAdv = $state(false);

  const visible = $derived(fields.filter((f) => !f.kinds?.length || f.kinds.includes(kind)));
  const basic = $derived(visible.filter((f) => !f.advanced && shown(f)));
  const adv = $derived(visible.filter((f) => f.advanced && shown(f)));

  function shown(f) {
    if (f.type === 'peers') return values.access === 'custom';
    return true;
  }
  function togglePeer(id) {
    const cur = values.access_peers || [];
    values.access_peers = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
  }
  function num(e, key) {
    const v = e.currentTarget.value;
    values[key] = v === '' ? 0 : Number(v);
  }
</script>

{#snippet field(f)}
  <div class="field">
    {#if f.type === 'bool'}
      <label class="switch">
        <input type="checkbox" bind:checked={values[f.key]} />
        <span class="track"></span>
        <span class="strong">{f.label}</span>
      </label>
    {:else}
      <label for="f-{f.key}">{f.label}</label>
      {#if f.type === 'select'}
        <select id="f-{f.key}" class="input" bind:value={values[f.key]}>
          {#each f.options as o}<option value={o.value}>{o.label}</option>{/each}
        </select>
      {:else if f.type === 'number'}
        <input id="f-{f.key}" class="input" type="number" value={values[f.key] ?? ''} oninput={(e) => num(e, f.key)} placeholder={f.placeholder || ''} />
      {:else if f.type === 'cidrlist' || f.type === 'textlist'}
        <ListInput bind:value={values[f.key]} placeholder={f.placeholder || 'Eintrag + Enter'} mono={f.type === 'cidrlist'} />
      {:else if f.type === 'targets'}
        <TargetsInput bind:value={values[f.key]} />
      {:else if f.type === 'peers'}
        <div class="peers">
          {#each peers as p}
            <label class="peer">
              <input type="checkbox" checked={(values.access_peers || []).includes(p.id)} onchange={() => togglePeer(p.id)} />
              <span>{p.name}</span><span class="muted small">{p.user_name}</span>
            </label>
          {:else}
            <span class="muted small">Keine anderen Geräte auf diesem Server.</span>
          {/each}
        </div>
      {:else}
        <input id="f-{f.key}" class="input" class:mono={f.type === 'cidr'} bind:value={values[f.key]} placeholder={f.placeholder || ''} readonly={f.readonly} />
      {/if}
    {/if}
    {#if f.help}<div class="help">{f.help}</div>{/if}
  </div>
{/snippet}

<div class="stack">
  {#each basic as f (f.key)}{@render field(f)}{/each}
  {#if adv.length}
    <button type="button" class="adv-toggle" onclick={() => (showAdv = !showAdv)}>
      <Icon name={showAdv ? 'chevron-down' : 'chevron'} size={16} />
      Erweitert <span class="muted">({adv.length} Einstellungen)</span>
    </button>
    {#if showAdv}
      <div class="adv stack">
        {#each adv as f (f.key)}{@render field(f)}{/each}
      </div>
    {/if}
  {/if}
</div>

<style>
  .adv-toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: none;
    background: none;
    font: inherit;
    font-weight: 600;
    color: var(--text-2);
    cursor: pointer;
    padding: 4px 0;
    align-self: flex-start;
  }
  .adv-toggle:hover {
    color: var(--accent);
  }
  .adv {
    padding: 14px;
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius-sm);
  }
  .peers {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 200px;
    overflow: auto;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
  }
  .peer {
    display: flex;
    gap: 8px;
    align-items: center;
    cursor: pointer;
  }
</style>
