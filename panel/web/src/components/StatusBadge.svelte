<script>
  // Nutzerstatus (Aktiv, Gedrosselt, Gesperrt …) – gleiche Pille wie bei Ausgängen, ohne Puls
  import StateBadge from './StateBadge.svelte';
  import { STATUS } from '../lib/format.js';
  let { status = 'ok', reason = '' } = $props();
  const s = $derived(STATUS[status] || { label: status, tone: 'muted' });
</script>

<StateBadge tone={s.tone} label={s.label} title={reason} small pulse={false} />
