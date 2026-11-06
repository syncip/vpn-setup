<script>
  import QRCode from 'qrcode';
  let { text = '', size = 220 } = $props();
  let src = $state('');
  let err = $state('');
  let big = $state(false);

  // Kommentarzeilen (z. B. „# WireGuard – Handy“) braucht keine App, sie machen den Code
  // nur dichter, und Sonderzeichen darin verwirren manche Scanner.
  const clean = (t) => (/^\[Interface\]/m.test(t) ? t.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n') : t);

  $effect(() => {
    const t = clean(text || '');
    err = '';
    QRCode.toDataURL(t || ' ', { margin: 4, width: 800, errorCorrectionLevel: t.length > 300 ? 'L' : 'M' })
      .then((u) => (src = u))
      .catch(() => (err = 'Zu lang für einen QR-Code'));
  });
</script>

{#if err}
  <div class="muted small">{err}</div>
{:else if src}
  <button type="button" class="qr-btn" onclick={() => (big = !big)} title={big ? 'Kleiner' : 'Größer anzeigen'}>
    <img {src} width={big ? Math.round(size * 1.7) : size} height={big ? Math.round(size * 1.7) : size} alt="QR-Code" class="qr" />
  </button>
{/if}

<style>
  .qr-btn {
    border: none;
    padding: 0;
    background: none;
    cursor: zoom-in;
    max-width: 100%;
  }
  .qr {
    display: block;
    max-width: 100%;
    height: auto;
    border-radius: 10px;
    background: #fff;
    border: 1px solid var(--border);
    image-rendering: pixelated;
  }
</style>
