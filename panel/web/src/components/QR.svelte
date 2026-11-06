<script>
  import QRCode from 'qrcode';
  let { text = '', size = 220 } = $props();
  let src = $state('');
  let err = $state('');

  $effect(() => {
    const t = text;
    err = '';
    QRCode.toDataURL(t || ' ', { margin: 1, width: size * 2, errorCorrectionLevel: t.length > 600 ? 'L' : 'M' })
      .then((u) => (src = u))
      .catch(() => (err = 'Zu lang für einen QR-Code'));
  });
</script>

{#if err}
  <div class="muted small">{err}</div>
{:else if src}
  <img {src} width={size} height={size} alt="QR-Code" class="qr" />
{/if}

<style>
  .qr {
    border-radius: 10px;
    background: #fff;
    padding: 6px;
    border: 1px solid var(--border);
    image-rendering: pixelated;
  }
</style>
