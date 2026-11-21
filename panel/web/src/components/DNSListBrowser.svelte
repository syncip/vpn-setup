<script>
  // Inhalt einer Blockliste durchsuchen und anpassen (Fenster):
  //   list:   angelegte Liste → Domains herausnehmen (Online-Liste), eigene löschen/ergänzen, wieder aufnehmen
  //   preset: bekannte Liste ({ index, name, url, note }) → nur ansehen, dann hinzufügen
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import SearchInput from './SearchInput.svelte';
  import { get, post } from '../lib/api.js';
  import { fmtNum } from '../lib/format.js';
  import { toast } from '../lib/state.svelte.js';

  let { open = $bindable(false), list = null, preset = null, start = '', onchange, onadd } = $props();

  const SRC = {
    own: ['Eigener Eintrag', 'accent'],
    url: ['Online-Liste', ''],
    allow: ['Ausnahme der Liste', 'ok'],
    excluded: ['Herausgenommen', 'warn'],
  };
  const FILTERS = [
    ['', 'Alle'],
    ['own', 'Eigene'],
    ['url', 'Online-Liste'],
    ['allow', 'Ausnahmen'],
    ['excluded', 'Herausgenommen'],
  ];
  const PAGE = 100;

  let q = $state('');
  let src = $state('');
  let page = $state(null);
  let items = $state([]);
  let loading = $state(false);
  let err = $state('');
  let addText = $state('');
  let busy = $state(false);
  let seq = 0;

  const url = $derived(list ? `/dns/lists/${list.id}/entries` : preset ? `/dns/presets/${preset.index}/entries` : '');
  const allowList = $derived(list?.mode === 'allow');

  async function fetchPage(offset) {
    const my = ++seq;
    loading = true;
    try {
      const p = new URLSearchParams({ q, offset: String(offset), limit: String(PAGE) });
      if (src) p.set('src', src);
      const r = await get(`${url}?${p}`);
      if (my !== seq) return;
      page = r;
      items = offset ? [...items, ...r.items] : r.items;
      err = '';
    } catch (e) {
      if (my === seq) err = e.message;
    } finally {
      if (my === seq) loading = false;
    }
  }
  // neu suchen bei Änderung (kurz verzögert beim Tippen)
  let timer = 0;
  $effect(() => {
    if (!open || !url) return;
    q;
    src;
    clearTimeout(timer);
    timer = setTimeout(() => fetchPage(0), 250);
    return () => clearTimeout(timer);
  });
  $effect(() => {
    if (open) {
      q = start || '';
      src = '';
      items = [];
      page = null;
      addText = '';
    }
  });

  async function edit(body, okText) {
    busy = true;
    try {
      const r = await post(`/dns/lists/${list.id}/entries`, body);
      toast(r.msg || okText);
      await fetchPage(0);
      onchange?.();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      busy = false;
    }
  }
  function addDomains() {
    const add = addText
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!add.length) return;
    edit({ add }, 'Ergänzt').then(() => (addText = ''));
  }
  const removeText = (it) => (it.src === 'own' ? 'Eigenen Eintrag löschen' : allowList ? 'Aus der Liste herausnehmen – gilt nicht mehr als Freigabe' : 'Aus der Liste herausnehmen – wird nicht mehr gesperrt (bleibt auch nach dem Neuladen draußen)');
</script>

<Modal bind:open title={list ? `Blockliste „${list.name}“` : `Bekannte Liste „${preset?.name || ''}“`} subtitle={list ? (allowList ? 'Freigaben durchsuchen und anpassen' : 'Gesperrte Domains durchsuchen und anpassen') : 'Vorschau – die Liste ist noch nicht angelegt'} width={760}>
  <div class="stack" style="gap:10px">
    <div class="row wrap" style="gap:8px">
      <SearchInput bind:value={q} placeholder="Domain oder Teil davon …" width="280px" />
      {#if list}
        <div class="segmented sm">
          {#each FILTERS as [k, l]}
            {#if k === '' || k === 'own' || list.url}<button class:active={src === k} onclick={() => (src = k)}>{l}</button>{/if}
          {/each}
        </div>
      {/if}
      <span class="grow"></span>
      {#if page}
        <span class="muted small nowrap">
          {fmtNum(page.matched)} Treffer · {fmtNum(page.total)} Domains{#if page.own && list?.url}&nbsp;({fmtNum(page.own)} eigene){/if}{#if page.excluded}&nbsp;· {fmtNum(page.excluded)} herausgenommen{/if}
        </span>
      {/if}
    </div>

    {#if list}
      <div class="row" style="gap:8px">
        <input class="input" bind:value={addText} placeholder={allowList ? 'Domains freigeben, z. B. beispiel.de (mehrere mit Leerzeichen)' : 'Domains ergänzen, z. B. werbung.example (mehrere mit Leerzeichen)'} onkeydown={(e) => e.key === 'Enter' && addDomains()} />
        <button class="btn" onclick={addDomains} disabled={busy || !addText.trim()}><Icon name="plus" size={15} /> Ergänzen</button>
      </div>
    {:else if preset}
      <div class="notice small"><Icon name="info" size={16} /><span>{preset.note}. Die Vorschau lädt die Liste einmal auf den Server (15 Minuten im Speicher). Anpassen kannst du sie nach dem Hinzufügen.</span></div>
    {/if}

    {#if err}<div class="notice bad small"><Icon name="alert" size={16} /><span>{err}</span></div>{/if}

    <div class="tbl">
      <table class="table">
        <thead><tr><th>Domain</th><th>Herkunft</th>{#if list}<th></th>{/if}</tr></thead>
        <tbody>
          {#each items as it (it.src + it.d)}
            <tr class:off={it.src === 'excluded'}>
              <td class="mono small dom">{it.d}</td>
              <td><span class="badge {SRC[it.src][1]}">{SRC[it.src][0]}</span></td>
              {#if list}
                <td class="right nowrap">
                  {#if it.src === 'excluded'}
                    <button class="btn sm" disabled={busy} onclick={() => edit({ restore: [it.d] }, 'Wieder aufgenommen')}><Icon name="reset" size={14} /> Wieder aufnehmen</button>
                  {:else}
                    <button class="btn sm ghost" class:danger={it.src === 'own'} disabled={busy} title={removeText(it)} onclick={() => edit({ remove: [it.d] }, 'Entfernt')}>
                      <Icon name={it.src === 'own' ? 'trash' : 'eye-off'} size={14} /> {it.src === 'own' ? 'Löschen' : 'Herausnehmen'}
                    </button>
                  {/if}
                </td>
              {/if}
            </tr>
          {:else}
            <tr><td colspan="3" class="empty small">{loading ? 'Lädt …' : q ? `Nichts gefunden für „${q}“` : 'Keine Einträge'}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if page && items.length < page.matched}
      <button class="btn sm" style="align-self:center" disabled={loading} onclick={() => fetchPage(items.length)}>Weitere {fmtNum(Math.min(PAGE, page.matched - items.length))} laden ({fmtNum(page.matched - items.length)} übrig)</button>
    {/if}
    {#if list?.url}
      <div class="muted tiny">„Herausnehmen“ wirkt sofort und bleibt beim Neuladen der Online-Liste bestehen. Unter „Herausgenommen“ lässt es sich rückgängig machen.</div>
    {/if}
  </div>
  {#snippet footer()}
    {#if preset && onadd}<button class="btn primary" onclick={() => ((open = false), onadd(preset))}><Icon name="plus" size={15} /> Liste hinzufügen</button>{/if}
    <button class="btn" onclick={() => (open = false)}>Schließen</button>
  {/snippet}
</Modal>

<style>
  .tbl {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    max-height: 52vh;
    overflow: auto;
  }
  .tbl thead th {
    position: sticky;
    top: 0;
    background: var(--panel);
    z-index: 1;
  }
  .dom {
    word-break: break-all;
  }
  tr.off td {
    opacity: 0.65;
  }
</style>
