<script>
  // „Anordnen“ / „Fertig“ – erscheint, wenn die Seite ein Board (anordenbare Fenster) hat.
  import Icon from './Icon.svelte';
  import { layout } from '../lib/layout.svelte.js';
</script>

{#if layout.active}
  <button class="btn" class:primary={layout.editing === layout.active} onclick={() => (layout.editing = layout.editing === layout.active ? '' : layout.active)} title="Fenster dieser Seite verschieben, in der Breite ändern oder ausblenden"><Icon name="grid" size={16} /> {layout.editing === layout.active ? 'Fertig' : 'Anordnen'}</button>
{/if}
