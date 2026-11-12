<script>
  // Suchfeld für Listen (filtert auf der Seite)
  import Icon from './Icon.svelte';
  let { value = $bindable(''), placeholder = 'Suchen …', width = '260px' } = $props();
</script>

<div class="sbox" style="width:{width}">
  <Icon name="search" size={15} />
  <input class="input" type="search" bind:value {placeholder} aria-label={placeholder} autocomplete="off" spellcheck="false" onkeydown={(e) => e.key === 'Escape' && value && (e.stopPropagation(), (value = ''))} />
</div>

<style>
  .sbox {
    position: relative;
    max-width: 100%;
    min-width: 160px;
  }
  .sbox :global(svg) {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--muted);
    pointer-events: none;
  }
  .sbox .input {
    padding-left: 32px;
    height: 32px;
  }
</style>
