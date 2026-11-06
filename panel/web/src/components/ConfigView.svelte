<script>
  import Icon from './Icon.svelte';
  import QR from './QR.svelte';
  import { get } from '../lib/api.js';
  import { copy, download } from '../lib/format.js';
  import { toast } from '../lib/state.svelte.js';

  // Zeigt Konfiguration, Links und Anleitung eines Zugangs.
  let { peerId } = $props();
  let cc = $state(null);
  let err = $state('');
  let qrFor = $state(null);

  $effect(() => {
    cc = null;
    err = '';
    get(`/peers/${peerId}/config`).then((r) => {
      cc = r;
      const f = r.files?.find((x) => x.qr);
      qrFor = f ? f.content : r.links?.[0]?.url || null;
    }).catch((e) => (err = e.message));
  });

  async function cp(t) {
    await copy(t);
    toast('Kopiert');
  }
</script>

{#if err}
  <div class="notice bad">{err}</div>
{:else if !cc}
  <div class="muted">Lade …</div>
{:else}
  <div class="stack">
    {#if cc.info?.length}
      <dl class="kv">
        {#each cc.info as [k, v]}<dt>{k}</dt><dd class="mono">{v}</dd>{/each}
      </dl>
    {/if}

    {#if qrFor}
      <div class="qr-wrap">
        <QR text={qrFor} size={230} />
        <div class="muted small">Mit der App scannen</div>
      </div>
    {/if}

    {#each cc.files || [] as f}
      <div class="stack-sm">
        <div class="spread">
          <span class="strong mono">{f.name}</span>
          <div class="row">
            <button class="btn sm" onclick={() => (qrFor = f.content)}><Icon name="qr" size={15} /> QR</button>
            <button class="btn sm" onclick={() => cp(f.content)}><Icon name="copy" size={15} /> Kopieren</button>
            <button class="btn sm" onclick={() => download(f.name, f.content)}><Icon name="download" size={15} /> Datei</button>
          </div>
        </div>
        <pre class="code">{f.content}</pre>
      </div>
    {/each}

    {#if cc.links?.length}
      <div class="stack-sm">
        <span class="label">Links</span>
        {#each cc.links as l}
          <div class="link">
            <span class="badge accent">{l.label}</span>
            <code class="grow ellipsis">{l.url}</code>
            <button class="btn sm icon" title="QR-Code" onclick={() => (qrFor = l.url)}><Icon name="qr" size={15} /></button>
            <button class="btn sm icon" title="Kopieren" onclick={() => cp(l.url)}><Icon name="copy" size={15} /></button>
          </div>
        {/each}
      </div>
    {/if}

    {#if cc.instructions?.length}
      <div class="stack-sm">
        <span class="label">Einrichtung</span>
        <ol class="steps">
          {#each cc.instructions as s}<li>{s}</li>{/each}
        </ol>
      </div>
    {/if}
  </div>
{/if}

<style>
  .qr-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
  }
  .link {
    display: flex;
    gap: 8px;
    align-items: center;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--panel-2);
  }
  .steps {
    margin: 0;
    padding-left: 20px;
    color: var(--text-2);
  }
  .steps li {
    margin: 3px 0;
  }
</style>
