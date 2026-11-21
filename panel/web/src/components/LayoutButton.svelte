<script>
  // „Anpassen“ / „Fertig“ – erscheint, wenn die Seite ein Board (anordenbare Fenster) hat.
  import Icon from './Icon.svelte';
  import { layout } from '../lib/layout.svelte.js';
</script>

{#if layout.active}
  <button class="btn ghost" class:primary={layout.editing === layout.active} onclick={() => (layout.editing = layout.editing === layout.active ? '' : layout.active)} title="Fenster dieser Seite verschieben, in der Breite ändern, ausblenden oder hinzufügen"><Icon name={layout.editing === layout.active ? 'check' : 'grid'} size={16} /> {layout.editing === layout.active ? 'Fertig' : 'Anpassen'}</button>
{/if}
