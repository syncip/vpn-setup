<script>
  // Paket-Updates: Panel, Xray, Hysteria2 und Debian-Pakete. Nur Anzeige – eingespielt wird im Container.
  //   compact: kurze Karte für die Übersicht (mit Link auf Zustand → Updates)
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import { get, post, put, run } from '../lib/api.js';
  import { date, ago } from '../lib/format.js';
  import { meta } from '../lib/state.svelte.js';

  let { compact = false } = $props();
  let d = $state(null);
  let busy = $state('');
  let showAll = $state(false);

  async function load() {
    try {
      d = await get('/updates');
    } catch {}
  }
  load();
  $effect(() => {
    const t = setInterval(load, 60000);
    return () => clearInterval(t);
  });
  async function check() {
    busy = 'check';
    const r = await run(() => post('/updates/check'));
    busy = '';
    if (r) {
      d = r;
      Object.assign(meta, await get('/meta'));
    }
  }
  async function setAuto(on) {
    if (await run(() => put('/settings', { pkg_refresh: on ? '1' : '0' }), on ? 'Paketlisten werden täglich aktualisiert' : 'Automatisches Aktualisieren aus')) load();
  }
  async function refresh() {
    busy = 'refresh';
    const r = await run(() => post('/updates/refresh'), 'Paketlisten aktualisiert');
    busy = '';
    if (r) d = r;
  }

  const bins = $derived((d?.items || []).filter((i) => i.kind !== 'debian'));
  const debs = $derived((d?.items || []).filter((i) => i.kind === 'debian'));
  const shownDebs = $derived(showAll ? debs : debs.filter((i) => i.security || i.relevant).length ? debs.filter((i) => i.security || i.relevant) : debs.slice(0, 10));
  const pending = $derived(bins.filter((i) => i.available).length + debs.length);
  const HOW = { panel: 'Neues Programm laden, wie in der README beschrieben', binary: 'bash vpn-setup.sh im Container', debian: 'apt full-upgrade im Container' };
</script>

<div class="card">
  <div class="card-head">
    <h3>
      <Icon name="download" size={16} /> Updates
      {#if !compact}
        <Info title="Updates" wide>
          <p>Das Panel zeigt neue Versionen nur an – <b>installiert wird nichts automatisch</b>.</p>
          <ul>
            <li><b>Panel:</b> neues Programm laden und einspielen wie in der README beschrieben.</li>
            <li><b>Xray, Hysteria2:</b> <span class="mono">bash vpn-setup.sh</span> im Container ausführen (aktualisiert beide).</li>
            <li><b>Debian-Pakete:</b> <span class="mono">apt full-upgrade</span> im Container. Gezählt wird, was in den Paketlisten steht – die aktualisiert Debian meist selbst (apt-daily), sonst „Paketlisten aktualisieren“.</li>
            <li>Das WireGuard-Kernelmodul liegt auf dem Proxmox-Host und lässt sich aus dem Container nicht prüfen.</li>
          </ul>
        </Info>
      {/if}
    </h3>
    {#if d}
      {#if !d.checked}<span class="badge muted">{d.busy ? 'prüft …' : 'noch nicht geprüft'}</span>
      {:else if pending}<span class="badge {d.security ? 'bad' : 'warn'}">{pending}{d.security ? ` · ${d.security} Sicherheit` : ''}</span>{:else}<span class="badge ok">aktuell</span>{/if}
    {/if}
    {#if compact}<span class="grow"></span><a href="#/health/updates" class="small">Details</a>{/if}
  </div>
  {#if !d}
    <div class="card-pad muted small">Lade …</div>
  {:else if compact}
    <div class="list">
      {#each bins as i}
        <div class="item">
          <span class="dot" class:on={!i.available && i.latest} class:warn={i.available}></span>
          <span class="grow small strong">{i.name}</span>
          <span class="small mono">{i.installed}{#if i.available}&nbsp;→ <b>{i.latest}</b>{/if}</span>
        </div>
      {/each}
      <div class="item">
        <span class="dot" class:on={d.checked && !debs.length} class:warn={debs.length && !d.security} class:bad={d.security}></span>
        <span class="grow small strong">Debian-Pakete</span>
        <span class="small">{!d.checked ? 'noch nicht geprüft' : debs.length ? `${debs.length} aktualisierbar${d.security ? `, ${d.security} Sicherheit` : ''}` : 'aktuell'}</span>
      </div>
    </div>
    <div class="card-pad tiny muted" style="padding-top:0">Geprüft {d.checked ? ago(d.checked) : '–'}{#if d.lists_at}&nbsp;· Paketlisten von {date(d.lists_at, true)}{/if}</div>
  {:else}
    <div class="card-pad stack-sm">
      <div class="row wrap" style="gap:8px">
        <button class="btn" onclick={check} disabled={!!busy || !!d.busy}><Icon name="refresh" size={15} /> {busy === 'check' ? 'Prüfe …' : 'Jetzt prüfen'}</button>
        <button class="btn" onclick={refresh} disabled={!!busy || !!d.busy} title="apt-get update: lädt nur die Paketlisten neu, installiert nichts"><Icon name="download" size={15} /> {busy === 'refresh' ? 'Lade Paketlisten …' : 'Paketlisten aktualisieren'}</button>
        <span class="grow"></span>
        <span class="small muted">Geprüft {d.checked ? date(d.checked, true) : '–'}{#if d.lists_at}&nbsp;· Paketlisten von {date(d.lists_at, true)}{/if}</span>
      </div>
      <label class="switch small"><input type="checkbox" checked={d.auto_lists} onchange={(e) => setAuto(e.currentTarget.checked)} /><span class="track"></span> Paketlisten einmal am Tag selbst aktualisieren (apt-get update – installiert nichts)</label>
      {#if d.disabled}<div class="notice small"><Icon name="info" size={16} /><span>Die Online-Prüfung ist ausgeschaltet (Einstellungen → Allgemein) – neue Versionen von Panel, Xray und Hysteria2 werden nicht abgefragt. Debian-Pakete prüft das Panel trotzdem.</span></div>{/if}
      {#if d.dry_run}<div class="notice warn small"><Icon name="alert" size={16} /><span>Testmodus – Beispielwerte.</span></div>{/if}
      {#each d.errors || [] as e}<div class="notice bad small"><Icon name="alert" size={16} /><span>{e}</span></div>{/each}
      {#if d.refresh_error}<div class="notice bad small"><Icon name="alert" size={16} /><span>Paketlisten: {d.refresh_error}</span></div>{/if}
    </div>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Programm</th><th>Installiert</th><th>Neueste</th><th>Einspielen</th></tr></thead>
        <tbody>
          {#each bins as i}
            <tr>
              <td class="strong">{i.name}</td>
              <td class="mono small">{i.installed || '–'}</td>
              <td class="mono small">
                {#if !i.latest}<span class="muted">unbekannt</span>
                {:else if i.available}<span class="badge warn">{i.latest}</span>{#if i.url}&nbsp;<a href={i.url} target="_blank" rel="noopener noreferrer" class="tiny">Änderungen</a>{/if}
                {:else}<span class="badge ok">aktuell</span>{/if}
              </td>
              <td class="small muted">{i.available ? HOW[i.kind] : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="card-head" style="border-top:1px solid var(--border)">
      <h3 class="small">Debian-Pakete {#if debs.length}<span class="muted">({debs.length})</span>{/if}</h3>
      {#if debs.length}<span class="small muted">Einspielen: <span class="mono">apt full-upgrade</span> im Container</span>{/if}
    </div>
    <div class="table-wrap">
      <table class="table">
        <tbody>
          {#each shownDebs as i (i.name)}
            <tr>
              <td><span class="mono small strong">{i.name}</span>{#if i.security}&nbsp;<span class="badge bad">Sicherheit</span>{/if}{#if i.relevant}&nbsp;<span class="badge">vom Panel genutzt</span>{/if}</td>
              <td class="mono tiny muted">{i.installed}</td>
              <td class="mono tiny">→ {i.latest}</td>
              <td class="tiny muted">{i.source}</td>
            </tr>
          {:else}
            <tr><td class="empty small">{#if d.checked}<Icon name="check" size={15} /> Alle Debian-Pakete sind aktuell (laut Paketlisten).{:else}Noch nicht geprüft – „Jetzt prüfen“ oder ein paar Sekunden warten.{/if}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if debs.length > shownDebs.length || showAll}
      <div class="card-pad" style="padding-top:8px"><button class="btn sm ghost" onclick={() => (showAll = !showAll)}>{showAll ? 'Nur wichtige zeigen' : `Alle ${debs.length} Pakete zeigen`}</button></div>
    {/if}
  {/if}
</div>

<style>
  .list {
    display: flex;
    flex-direction: column;
    padding: 6px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 7px 12px;
  }
</style>
