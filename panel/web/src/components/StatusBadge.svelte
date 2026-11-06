<script>
  import { STATUS } from '../lib/format.js';
  let { status = 'ok', reason = '' } = $props();
  const s = $derived(STATUS[status] || { label: status, tone: 'muted' });
</script>

<span class="badge {s.tone}" title={reason}>{s.label}</span>
