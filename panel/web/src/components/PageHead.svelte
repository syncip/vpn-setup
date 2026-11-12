<script>
  // Seitenkopf. help: Erklärung der Seite als „i“-Popup neben dem Titel (Snippet), helpTitle: dessen Überschrift.
  import Info from './Info.svelte';
  let { title, subtitle = '', children, help, helpTitle = '', helpWide = false } = $props();
</script>

<div class="page-head">
  <div class="grow">
    <h1>{title}{#if help}&nbsp;<Info title={helpTitle || title} wide={helpWide}>{@render help()}</Info>{/if}</h1>
    {#if subtitle}<div class="muted">{subtitle}</div>{/if}
  </div>
  {#if children}<div class="row wrap">{@render children()}</div>{/if}
</div>

<style>
  .page-head {
    display: flex;
    align-items: flex-end;
    gap: 16px;
    margin-bottom: 22px;
    flex-wrap: wrap;
  }
  h1 :global(.info-btn) {
    font-size: 13px;
  }
</style>
