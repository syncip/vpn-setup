<script module>
  // confirmDialog({title, text, ok, danger}) → Promise<boolean>
  let resolver = null;
  export const dlg = $state({ open: false, title: '', text: '', ok: 'OK', danger: false });

  export function confirmDialog(o) {
    Object.assign(dlg, { ok: 'OK', danger: false, text: '' }, o, { open: true });
    return new Promise((r) => (resolver = r));
  }
  function done(v) {
    dlg.open = false;
    resolver?.(v);
    resolver = null;
  }
  export { done };
</script>

<script>
  import Modal from './Modal.svelte';
</script>

<Modal bind:open={dlg.open} title={dlg.title} width={440} onclose={() => done(false)}>
  <p style="margin:0" class="muted">{dlg.text}</p>
  {#snippet footer()}
    <button class="btn" onclick={() => done(false)}>Abbrechen</button>
    <button class="btn {dlg.danger ? 'danger solid' : 'primary'}" onclick={() => done(true)}>{dlg.ok}</button>
  {/snippet}
</Modal>
