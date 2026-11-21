<script>
  // System → „Was gilt?“: Nutzer, Gerät, Server, Ausgangsgruppe oder Gerät ohne VPN suchen und alles sehen,
  // was dafür gilt – Routing, DNS, SmartDNS, Limits, Zugriff, Einstellungen – jeweils mit Herkunft.
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Picker from '../components/Picker.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import SearchInput from '../components/SearchInput.svelte';
  import { get } from '../lib/api.js';
  import { go } from '../lib/state.svelte.js';

  let { kind = '', id = 0 } = $props();

  const KINDS = {
    user: ['Nutzer', 'user'],
    peer: ['Geräte', 'phone'],
    server: ['Server', 'server'],
    group: ['Ausgangsgruppen', 'layers'],
    client: ['Geräte ohne VPN', 'globe'],
  };

  let targets = $state([]);
  let data = $state(null);
  let error = $state('');
  let loading = $state(false);
  let filter = $state('');

  const items = $derived(
    targets.map((t) => ({
      value: `${t.kind}:${t.id}`,
      label: t.name,
      sub: t.sub,
      proto: t.kind === 'peer' || t.kind === 'server' ? t.proto : undefined,
      icon: KINDS[t.kind]?.[1],
      group: KINDS[t.kind]?.[0],
      off: t.off,
      search: `${t.name} ${t.sub || ''} ${KINDS[t.kind]?.[0]}`,
    })),
  );
  const counts = $derived(Object.fromEntries(Object.keys(KINDS).map((k) => [k, targets.filter((t) => t.kind === k).length])));

  let pick = $state('');
  $effect(() => {
    pick = kind && id ? `${kind}:${id}` : '';
  });
  function open(v) {
    if (!v) return;
    const [k, i] = String(v).split(':');
    if (k && i) go(`/system/effective/${k}/${i}`);
  }

  async function loadTargets() {
    targets = await get('/effective').catch(() => []);
  }
  loadTargets();

  async function load(k, i) {
    if (!k || !i) {
      data = null;
      return;
    }
    loading = true;
    error = '';
    try {
      data = await get(`/effective?kind=${encodeURIComponent(k)}&id=${i}`);
    } catch (e) {
      data = null;
      error = e.message || 'Fehler';
    }
    loading = false;
  }
  $effect(() => {
    load(kind, id);
  });

  // Zeilenfilter: Abschnitte und Zeilen, die zum Suchtext passen
  const sections = $derived.by(() => {
    if (!data) return [];
    const f = filter.trim().toLowerCase();
    if (!f) return data.sections;
    return data.sections
      .map((s) => {
        if (s.title.toLowerCase().includes(f)) return s;
        const rows = (s.rows || []).filter((r) => [r.label, r.value, r.sub, r.from].some((x) => x && x.toLowerCase().includes(f)));
        return { ...s, rows, empty: '' };
      })
      .filter((s) => s.rows?.length);
  });
</script>

<PageHead title="Was gilt?" subtitle="Alle wirksamen Einstellungen für einen Nutzer, ein Gerät, einen Server oder eine Gruppe" helpTitle="Was gilt?">
  {#snippet help()}
    <p>Viele Einstellungen lassen sich auf mehreren Ebenen setzen – für alle, je Server, je Nutzer oder je Gerät. Diese Seite zeigt, was am Ende <b>wirklich gilt</b>, und woher es kommt (grau rechts: „über …“).</p>
    <p>Die Werte stammen aus denselben Daten, mit denen das Panel die Konfiguration erzeugt. Ein Klick auf einen verknüpften Eintrag (Pfeil) öffnet dessen Übersicht, das Stift-Symbol die Seite zum Ändern.</p>
    <p>Rangfolge: Gerät vor Nutzer vor Server vor „alle“. Beim Routing kommen Domains und Netze vor „alles“.</p>
  {/snippet}
</PageHead>

<div class="card pickcard">
  <div class="card-pad row wrap" style="gap:10px;align-items:center">
    <Icon name="search" size={18} />
    <div class="grow" style="min-width:220px">
      <Picker {items} bind:value={pick} onpick={(it) => open(it.value)} placeholder="Nutzer, Gerät, Server, Gruppe suchen …" width="100%" max={300} />
    </div>
    {#if data}
      <SearchInput bind:value={filter} placeholder="In den Einstellungen suchen …" width="240px" />
    {/if}
  </div>
</div>

{#if !kind || !id}
  <div class="kinds">
    {#each Object.entries(KINDS) as [k, [label, icon]]}
      <div class="card kind">
        <div class="card-head"><h2><Icon name={icon} size={16} /> {label}</h2><span class="muted small">{counts[k] || 0}</span></div>
        <div class="klist">
          {#each targets.filter((t) => t.kind === k).slice(0, 8) as t (t.id)}
            <a href={`#/system/effective/${k}/${t.id}`} class:off={t.off}>
              {#if t.proto && (k === 'peer' || k === 'server')}<ProtoLogo id={t.proto} size={14} />{/if}
              <span class="ellipsis">{t.name}</span>
              {#if t.sub}<span class="muted tiny ellipsis">{t.sub}</span>{/if}
            </a>
          {:else}
            <span class="muted small" style="padding:6px 14px">keine</span>
          {/each}
          {#if (counts[k] || 0) > 8}<span class="muted tiny" style="padding:4px 14px">… weitere über die Suche</span>{/if}
        </div>
      </div>
    {/each}
  </div>
{:else if error}
  <div class="notice bad"><Icon name="alert" size={16} /><span>{error}</span></div>
{:else if data}
  <div class="head card">
    <div class="card-pad row" style="gap:12px">
      <span class="big-ic">{#if data.proto}<ProtoLogo id={data.proto} size={28} />{:else}<Icon name={KINDS[data.kind]?.[1] || 'info'} size={24} />{/if}</span>
      <div class="grow" style="min-width:0">
        <div class="strong ellipsis" style="font-size:var(--fs-lg)">{data.name}</div>
        <div class="muted small">{data.sub}</div>
      </div>
      {#if loading}<span class="muted small">lädt …</span>{/if}
      <button class="btn icon ghost" title="Neu laden" aria-label="Neu laden" onclick={() => load(kind, id)}><Icon name="refresh" size={16} /></button>
    </div>
  </div>
  <div class="grid">
    {#each sections as s (s.key)}
      <div class="card sec">
        <div class="card-head"><h2><Icon name={s.icon} size={16} /> {s.title}</h2></div>
        {#if s.rows?.length}
          <div class="rows">
            {#each s.rows as r, i (i)}
              <div class="r">
                <div class="lbl">{r.label}</div>
                <div class="val">
                  <div class="v" class:ok={r.tone === 'ok'} class:warn={r.tone === 'warn'} class:bad={r.tone === 'bad'} class:muted={r.tone === 'muted'}>
                    {#if r.tone === 'ok' || r.tone === 'warn' || r.tone === 'bad'}<span class="dot"></span>{/if}
                    {#if r.target}
                      <a href={`#/system/effective/${r.target.replace(':', '/')}`} title="Was gilt hier?">{r.value} <Icon name="arrow-right" size={12} /></a>
                    {:else}
                      <span>{r.value}</span>
                    {/if}
                    {#if r.link}<a class="edit" href={r.link} title="Ändern" aria-label="Ändern"><Icon name="edit" size={12} /></a>{/if}
                  </div>
                  {#if r.sub}<div class="tiny muted">{r.sub}</div>{/if}
                  {#if r.from}<div class="from tiny">über {r.from}</div>{/if}
                </div>
              </div>
            {/each}
          </div>
        {:else}
          <div class="card-pad muted small">{s.empty || 'Nichts gesetzt.'}</div>
        {/if}
        {#if s.note}<div class="note tiny muted"><Icon name="info" size={12} /> {s.note}</div>{/if}
      </div>
    {:else}
      <div class="empty"><h3>Nichts gefunden</h3><p class="muted">Keine Einstellung passt zu „{filter}“.</p></div>
    {/each}
  </div>
{:else}
  <div class="boot"></div>
{/if}

<style>
  .pickcard {
    margin-bottom: 14px;
  }
  .kinds {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 280px), 1fr));
    gap: 14px;
  }
  .klist {
    display: flex;
    flex-direction: column;
    padding: 4px 0 8px;
  }
  .klist a {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    color: inherit;
    text-decoration: none;
    min-width: 0;
  }
  .klist a:hover {
    background: var(--panel-2);
  }
  .klist a.off {
    opacity: 0.55;
  }
  .klist a .tiny {
    margin-left: auto;
    flex-shrink: 1;
  }
  .head {
    margin-bottom: 14px;
  }
  .big-ic {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 44px;
    height: 44px;
    border-radius: 10px;
    background: var(--panel-2);
    flex-shrink: 0;
  }
  /* Spalten wie ein Mauerwerk: Karten unterschiedlicher Höhe ohne Lücken */
  .grid {
    columns: 440px auto;
    column-gap: 14px;
  }
  .sec {
    min-width: 0;
    break-inside: avoid;
    margin-bottom: 14px;
  }
  .grid > .empty {
    column-span: all;
  }
  .rows {
    display: flex;
    flex-direction: column;
  }
  .r {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(0, 3fr);
    gap: 4px 14px;
    padding: 8px 14px;
    border-top: 1px solid var(--border);
  }
  .r:first-child {
    border-top: 0;
  }
  .lbl {
    color: var(--muted);
    font-size: var(--fs-sm);
    overflow-wrap: anywhere;
  }
  .val {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .v {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    font-weight: 500;
  }
  .v a {
    color: var(--accent);
    text-decoration: none;
  }
  .v a:hover {
    text-decoration: underline;
  }
  .v .edit {
    color: var(--muted);
    opacity: 0.6;
  }
  .v .edit:hover {
    opacity: 1;
  }
  .v.muted {
    color: var(--muted);
    font-weight: 400;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
    flex-shrink: 0;
  }
  .v.ok .dot {
    background: var(--ok);
  }
  .v.warn .dot {
    background: var(--warn);
  }
  .v.bad .dot {
    background: var(--bad);
  }
  .from {
    color: var(--muted);
    opacity: 0.85;
    font-style: italic;
  }
  .note {
    display: flex;
    gap: 6px;
    align-items: flex-start;
    padding: 8px 14px 10px;
    border-top: 1px solid var(--border);
  }
  @media (max-width: 560px) {
    .r {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
