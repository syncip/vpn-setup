<script>
  let { title, subtitle = '', children } = $props();
</script>

<div class="page-head">
  <div class="grow">
    <h1>{title}</h1>
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
</style>
