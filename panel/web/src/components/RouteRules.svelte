<script>
  // Ziel-Regeln: welcher Verkehr über welche Ausgangsgruppe läuft (global, je Server, Nutzer oder Gerät).
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import Picker from './Picker.svelte';
  import Info from './Info.svelte';
  import SearchInput from './SearchInput.svelte';
  import { PROTO_LABEL, ago, fmtNum } from '../lib/format.js';
  import { peerItems, userItems, serverItems, tokens, matches } from '../lib/pick.js';

  // reload: Zähler der Elternseite – ändert er sich (z. B. neue Gruppe), wird neu geladen
  let { reload = 0 } = $props();

  let d = $state({ routes: [], servers: [], users: [], peers: [], groups: [], exits: [], lists: [], error: '', dns: null });
  const when = (ts) => (ago(ts) === 'online' ? 'gerade eben' : ago(ts));
  let loaded = $state(false);

  async function load() {
    try {
      d = await get('/routes');
      loaded = true;
    } catch {
      /* Seite zeigt den alten Stand */
    }
  }
  $effect(() => {
    reload;
    load();
  });
  $effect(() => {
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  });

  const by = (list) => Object.fromEntries(list.map((x) => [x.id, x]));
  const serverById = $derived(by(d.servers));
  const userById = $derived(by(d.users));
  const peerById = $derived(by(d.peers));
  const groupById = $derived(by(d.groups));
  const listById = $derived(by(d.lists));
  const exitById = $derived(by(d.exits || []));

  // Kaskade: Stufen einer Regel (Stufe 1 zuerst). Eine automatische Gruppe steht für ihren Ausgang.
  function stagesOf(r) {
    const chain = (r.chain || []).map((id) => ({ kind: 'exit', id }));
    if (r.group === 0) return chain;
    const g = groupById[r.group];
    return [...chain, g?.auto ? { kind: 'exit', id: g.auto } : { kind: 'group', id: r.group }];
  }
  const stageName = (s) => (s.kind === 'exit' ? exitById[s.id]?.name || 'Ausgang ?' : `Gruppe ${groupById[s.id]?.name || '?'}`);
  const isDirect = (r) => r.group === 0 && !(r.chain || []).length;
  const viaText = (r) => (isDirect(r) ? 'direkt' : stagesOf(r).map(stageName).join(' → '));
  // Stufen im Formular als „e:ID“ (Ausgang) bzw. „g:ID“ (Gruppe)
  const key = (s) => (s.kind === 'exit' ? 'e:' : 'g:') + s.id;
  const unkey = (k) => ({ kind: k[0] === 'e' ? 'exit' : 'group', id: Number(k.slice(2)) });

  const SCOPE = { global: 'Alle', server: 'Server', user: 'Nutzer', peer: 'Gerät' };
  const ORDER = { peer: 0, user: 1, server: 2, global: 3 };

  function scopeText(r) {
    if (r.scope === 'server') return serverById[r.scope_id]?.name || '?';
    if (r.scope === 'user') return userById[r.scope_id]?.name || '?';
    if (r.scope === 'peer') {
      const p = peerById[r.scope_id];
      return p ? `${userById[p.user_id]?.name || '?'} · ${p.name} (${PROTO_LABEL[p.protocol] || p.protocol})` : '?';
    }
    return 'alle Nutzer und Geräte';
  }
  function targetText(r) {
    if (r.match === 'all') return 'Alles';
    const parts = [];
    if (r.domains.length) parts.push(r.domains.slice(0, 3).join(', ') + (r.domains.length > 3 ? ` +${r.domains.length - 3}` : ''));
    if (r.nets.length) parts.push(r.nets.length === 1 ? r.nets[0] : `${r.nets.length} Netze`);
    for (const id of r.lists) parts.push(`Liste „${listById[id]?.name || id}“`);
    return parts.join(' · ') || '–';
  }
  // Anzeige in der Reihenfolge, in der die Regeln greifen
  const sorted = $derived(
    [...d.routes].sort((a, b) => ORDER[a.scope] - ORDER[b.scope] || a.scope_id - b.scope_id || (a.match === 'all') - (b.match === 'all') || a.id - b.id),
  );
  // Suche über Regeln: Nutzer, Gerät, Server, Ziele, Gruppe, Notiz
  let rq = $state('');
  const peerPicks = $derived(Object.fromEntries(peerItems(d.peers, d.users, d.servers).map((i) => [i.value, i])));
  const shownRoutes = $derived.by(() => {
    const t = tokens(rq);
    if (!t.length) return sorted;
    return sorted.filter((r) =>
      matches(
        [SCOPE[r.scope], scopeText(r), r.scope === 'peer' ? peerPicks[r.scope_id]?.search : '', targetText(r), viaText(r), r.name].join(' '),
        t,
      ),
    );
  });

  let open = $state(false);
  let cur = $state(null);
  let f = $state({});

  // „Regel anlegen“ steht im Seitenkopf (Proxy-Seite) und ruft das hier auf
  let addPending = false;
  export function add() {
    if (loaded) openRule();
    else addPending = true; // öffnet, sobald die Regeln geladen sind
  }
  $effect(() => {
    if (loaded && addPending) {
      addPending = false;
      openRule();
    }
  });
  function openRule(r = null) {
    cur = r;
    const g0 = d.groups.find((g) => g.enabled && !g.auto);
    f = r
      ? { name: r.name, enabled: r.enabled, scope: r.scope, scope_id: r.scope_id, match: r.match, nets: r.nets.join('\n'), domains: r.domains.join('\n'), lists: [...r.lists], stages: stagesOf(r).map(key) }
      : { name: '', enabled: true, scope: 'global', scope_id: 0, match: 'all', nets: '', domains: '', lists: [], stages: g0 ? ['g:' + g0.id] : [] };
    open = true;
  }
  function setScope(s) {
    if (f.scope === s) return;
    f.scope = s;
    // bei vielen Nutzern nichts vorwählen – erst suchen
    f.scope_id = s === 'server' && d.servers.length === 1 ? d.servers[0].id : 0;
  }
  function toggleList(id) {
    f.lists = f.lists.includes(id) ? f.lists.filter((x) => x !== id) : [...f.lists, id];
  }
  // neue Stufe vorn: die bisherigen laufen dann über sie (eine Gruppe bleibt die letzte)
  function addStage() {
    const used = new Set(f.stages);
    const e = d.exits.find((x) => x.enabled && !used.has('e:' + x.id)) || d.exits[0];
    if (e) f.stages = ['e:' + e.id, ...f.stages];
  }
  const stageBad = $derived((f.stages || []).some((k, i) => k[0] === 'g' && i < f.stages.length - 1));
  async function save() {
    const body = $state.snapshot(f);
    body.scope_id = Number(body.scope_id) || 0;
    body.stages = body.stages.map(unkey);
    const r = cur ? await run(() => put(`/routes/${cur.id}`, body), 'Regel gespeichert') : await run(() => post('/routes', body), 'Regel angelegt');
    if (r) {
      open = false;
      load();
    }
  }
  async function toggle(r) {
    if (await run(() => put(`/routes/${r.id}`, { enabled: !r.enabled }), r.enabled ? 'Regel deaktiviert' : 'Regel aktiviert')) load();
  }
  async function remove(r) {
    if (!(await confirmDialog({ title: 'Regel löschen?', text: 'Der Verkehr läuft danach wieder nach den übrigen Regeln.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/routes/${r.id}`), 'Regel gelöscht')) load();
  }

  // Hinweise im Formular
  const hyOnly = $derived.by(() => {
    if (f.scope === 'server') return serverById[f.scope_id]?.protocol === 'hysteria2';
    if (f.scope === 'peer') return peerById[f.scope_id]?.protocol === 'hysteria2';
    return false;
  });
  const valid = $derived(
    (f.scope === 'global' || Number(f.scope_id) > 0) && (f.match === 'all' || (f.domains || '').trim() || (f.nets || '').trim() || (f.lists || []).length > 0),
  );
</script>

<div class="section-head">
  <div>
    <h2>Ziel-Regeln</h2>
    <div class="muted small">Welcher Verkehr über welche Ausgänge läuft (auch hintereinander) – für WireGuard, OpenVPN, VLESS, Hysteria2 und Proxy</div>
  </div>
  <div class="row" style="gap:8px">
    {#if d.routes.length > 5}<SearchInput bind:value={rq} placeholder="Regeln durchsuchen …" width="230px" />{/if}
  </div>
</div>
{#if d.error}<div class="notice bad" style="margin-bottom:12px"><Icon name="alert" /><span>{d.error}</span></div>{/if}
<div class="card">
  <div class="list">
    {#each shownRoutes as r (r.id)}
      {@const g = groupById[r.group]}
      <div class="item" class:off={!r.enabled}>
        <span class="badge scope {r.scope}" title="Gilt für">{SCOPE[r.scope]}</span>
        <div class="grow">
          <div class="strong">
            {scopeText(r)}
            <span class="muted">·</span>
            <span class="what">{targetText(r)}</span>
            <Icon name="arrow-right" size={14} />
            {#if isDirect(r)}<span class="via direct">direkt über den Server</span>{:else}<span class="via"
                >{#each stagesOf(r) as s, i}{#if i}<span class="chev">→</span>{/if}{s.kind === 'group' ? g?.name || 'Gruppe ?' : exitById[s.id]?.name || 'Ausgang ?'}{/each}</span
              >{/if}
          </div>
          {#if r.name || r.note}
            <div class="tiny">
              {#if r.name}<span class="muted">{r.name}</span>{/if}
              {#if r.note && r.enabled}<span class="warn-text"><Icon name="alert" size={12} /> wirkt nicht: {r.note}</span>{/if}
            </div>
          {/if}
          {#if r.dns}
            <!-- Domain-Erkennung für WireGuard/OpenVPN: zeigt, ob DNS-Anfragen des Geräts ankommen -->
            <div class="tiny dnsline">
              {#if r.dns.error}
                <span class="warn-text"><Icon name="alert" size={12} /> {r.dns.error}</span>
              {:else if r.dns.queries}
                <span class="ok-text"><Icon name="check" size={12} /> Domains erkannt: {fmtNum(r.dns.addrs)} {r.dns.addrs === 1 ? 'Adresse' : 'Adressen'} gelernt, letzte DNS-Anfrage {when(r.dns.last)}</span>
              {:else if r.dns.addrs}
                <span class="muted">{fmtNum(r.dns.addrs)} {r.dns.addrs === 1 ? 'Adresse' : 'Adressen'} gelernt (seit dem Neustart noch keine neue DNS-Anfrage)</span>
              {:else}
                <span class="warn-text"
                  ><Icon name="alert" size={12} /> Noch keine DNS-Anfrage für diese Domains gesehen – am Gerät VPN trennen und neu verbinden, dann das Ziel aufrufen. Bleibt es dabei,
                  nutzt das Gerät verschlüsseltes DNS (Browser: „Sicheres DNS“, Android: „Privates DNS“).</span
                >
              {/if}
            </div>
          {/if}
        </div>
        <label class="switch" title={r.enabled ? 'Aktiv' : 'Aus'}><input type="checkbox" checked={r.enabled} onchange={() => toggle(r)} /><span class="track"></span></label>
        <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => openRule(r)}><Icon name="edit" size={15} /></button>
        <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(r)}><Icon name="trash" size={15} /></button>
      </div>
    {:else}
      <div class="empty small">
        {#if sorted.length}Keine Regel passt zu „{rq}“.{:else}Noch keine Regel – aller Verkehr geht direkt über den Server.{#if loaded && !d.groups.length}
          Lege zuerst unten einen Ausgang und eine Gruppe an.{/if}{/if}
      </div>
    {/each}
  </div>
  {#if sorted.length > 1 || d.dns?.running}
    <div class="foot muted tiny">
      {#if sorted.length > 1}Rangfolge: Gerät vor Nutzer vor Server vor „Alle“. Innerhalb einer Ebene greifen Regeln für bestimmte Ziele vor „Alles“. Die erste passende Regel gilt.{/if}
      {#if d.dns?.running}
        <div>
          DNS-Umleiter für Domain-Regeln (WireGuard/OpenVPN): {#if d.dns.queries}{fmtNum(d.dns.queries)} Anfragen von {d.dns.clients} {d.dns.clients === 1 ? 'Gerät' : 'Geräten'} seit dem
            Start, zuletzt {when(d.dns.last)}.{:else}läuft, hat aber noch keine DNS-Anfrage eines Geräts gesehen.{/if}
        </div>
      {/if}
    </div>
  {/if}
</div>

<Modal bind:open title={cur ? 'Regel bearbeiten' : 'Regel anlegen'} width={620}>
  <div class="stack">
    <div class="field">
      <span class="label">Gilt für <Info title="Gilt für" text="Rangfolge: Gerät vor Nutzer vor Server vor „Alle“. „Nutzer“ gilt für alle Zugänge des Nutzers. Hysteria2-Zugänge folgen nur Regeln für „Server“ und „Alle“." /></span>
      <div class="segmented">
        {#each Object.entries(SCOPE) as [k, label]}
          <button class:active={f.scope === k} onclick={() => setScope(k)} disabled={k !== 'global' && !d[k + 's']?.length}>{label}</button>
        {/each}
      </div>
      {#if f.scope === 'server'}
        <Picker items={serverItems(d.servers)} bind:value={f.scope_id} placeholder="Server suchen …" />
      {:else if f.scope === 'user'}
        <Picker items={userItems(d.users, '', d.peers)} bind:value={f.scope_id} placeholder="Nutzer suchen …" />
      {:else if f.scope === 'peer'}
        <Picker items={peerItems(d.peers, d.users, d.servers)} bind:value={f.scope_id} placeholder="Gerät suchen (Name, Nutzer, Dienst, Server) …" />
      {:else}
        <div class="muted small">Alle Nutzer und Geräte, solange keine genauere Regel greift</div>
      {/if}
      {#if hyOnly && f.scope === 'peer'}<div class="help warn-text">Hysteria2 kann Geräte nicht einzeln leiten – für diesen Zugang bitte eine Regel für den Server anlegen.</div>{/if}
    </div>

    <div class="field">
      <span class="label">Ziele</span>
      <div class="segmented">
        <button class:active={f.match === 'all'} onclick={() => (f.match = 'all')}>Alles</button>
        <button class:active={f.match === 'targets'} onclick={() => (f.match = 'targets')}>Nur bestimmte Ziele</button>
      </div>
    </div>
    {#if f.match === 'targets'}
      <div class="field">
        <label for="rt-dom">Domains <Info title="Domains" text="Eine pro Zeile, Unterdomains sind eingeschlossen. „*“ steht für beliebige Zeichen (netflix.*, ipv4-*.nflxvideo.net). Bei WireGuard und OpenVPN erkennt der Server die Ziele an den DNS-Anfragen des Geräts. Eine neue Regel greift, sobald das Gerät den Namen neu auflöst (VPN kurz trennen und verbinden hilft). Fest erzwungenes verschlüsseltes DNS (DoH, „Privates DNS“ mit Anbieter) umgeht das." /></label>
        <textarea id="rt-dom" class="input mono" rows="3" bind:value={f.domains} placeholder={'netflix.com\nnflxvideo.net'}></textarea>
      </div>
      <div class="field">
        <label for="rt-nets">IP-Netze (IPv4)</label>
        <textarea id="rt-nets" class="input mono" rows="2" bind:value={f.nets} placeholder={'203.0.113.0/24'}></textarea>
      </div>
      <div class="field">
        <span class="label">Ziellisten</span>
        {#if d.lists.length}
          <div class="row wrap" style="gap:6px">
            {#each d.lists as l}
              <button class="btn sm" class:primary={f.lists.includes(l.id)} onclick={() => toggleList(l.id)}>{l.name}{#if !l.enabled}&nbsp;(aus){/if}</button>
            {/each}
          </div>
        {:else}
          <div class="help">Noch keine – unter „IP-Listen“ eine Liste der Art „Zielliste“ anlegen (auch als Online-Liste).</div>
        {/if}
      </div>
    {/if}

    <div class="field">
      <span class="label">Über <Info title="Über">
          <p>Bis zu drei Stufen hintereinander (Kaskade), z. B. <b>Cloudflare WARP → Windscribe</b> oder <b>WARP → Tor</b>. Stufe 1 verbindet sich direkt, jede weitere durch die vorige.</p>
          <p>Die letzte Stufe kann auch eine Ausgangsgruppe sein: Sie wechselt bei Ausfall wie gewohnt, alle ihre Ausgänge laufen dann über die Stufe davor.</p>
          <p>Ein Ausgang ist ein Tunnel und hat nur einen Weg. Braucht eine andere Regel denselben Ausgang anders (z. B. direkt statt über WARP), lässt sich die Regel nicht speichern – dafür einen zweiten Ausgang anlegen.</p>
          <p>„Direkt“ ist nützlich als Ausnahme, z. B. „Alles über Mullvad, nur die Bank direkt“. Ausgänge können nur IPv4 – bei „Alles“ wird IPv6 ins Internet für diese Geräte gesperrt.</p>
        </Info></span
      >
      {#if !f.stages.length}
        <div class="stage direct"><Icon name="server" size={15} /> <span class="grow">Direkt über den Server (Ausnahme)</span></div>
      {/if}
      {#each f.stages as k, i (i)}
        {@const last = i === f.stages.length - 1}
        <div class="stage">
          <span class="num">{i + 1}.</span>
          <select class="input" bind:value={f.stages[i]} aria-label="Stufe {i + 1}">
            <optgroup label="Ausgänge">
              {#each d.exits as x}<option value={'e:' + x.id}>{x.name}{x.type === 'tor' ? ' (Tor)' : ''}{x.enabled ? '' : ' (deaktiviert)'}</option>{/each}
            </optgroup>
            {#if last || k[0] === 'g'}
              <optgroup label="Ausgangsgruppen (Wechsel bei Ausfall)">
                {#each d.groups.filter((g) => !g.auto) as g}<option value={'g:' + g.id}>Gruppe {g.name}{g.enabled ? '' : ' (deaktiviert)'}</option>{/each}
              </optgroup>
            {/if}
          </select>
          <button class="btn sm icon ghost" title="Stufe entfernen" onclick={() => (f.stages = f.stages.filter((_, j) => j !== i))}><Icon name="x" size={15} /></button>
        </div>
      {/each}
      <div class="row wrap" style="gap:8px">
        {#if f.stages.length < 3 && d.exits.length}
          <button class="btn sm" onclick={addStage}><Icon name="plus" size={14} /> {f.stages.length ? 'Stufe davor' : 'Ausgang wählen'}</button>
        {/if}
        {#if !f.stages.length && d.groups.some((g) => !g.auto)}
          <button class="btn sm" onclick={() => (f.stages = ['g:' + d.groups.find((g) => !g.auto).id])}><Icon name="plus" size={14} /> Gruppe wählen</button>
        {/if}
        {#if f.stages.length}<button class="btn sm ghost" onclick={() => (f.stages = [])}>Direkt</button>{/if}
      </div>
      {#if stageBad}<div class="help warn-text">Eine Gruppe kann nur die letzte Stufe sein – davor einzelne Ausgänge.</div>{/if}
      {#if f.stages.length}
        <div class="help">
          Weg: Gerät → Server → {f.stages.map((k) => stageName(unkey(k))).join(' → ')} → Internet.
          {#if f.stages.length > 1}Der letzte Anbieter sieht nur die Adresse des vorigen. Fällt eine Stufe aus, bleibt der Weg gesperrt – nie direkt.{/if}
        </div>
      {/if}
    </div>

    <div class="field"><label for="rt-name">Notiz (optional)</label><input id="rt-name" class="input" bind:value={f.name} placeholder="z. B. Streaming über USA" maxlength="60" /></div>
    <label class="switch"><input type="checkbox" bind:checked={f.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={!valid || stageBad}>{cur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
  .section-head {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    justify-content: space-between;
    margin: 26px 0 12px;
  }
  .list {
    display: flex;
    flex-direction: column;
    padding: 6px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 9px 12px;
    border-radius: 8px;
  }
  .item.off .grow {
    opacity: 0.5;
  }
  .item .strong {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .what {
    font-weight: 500;
  }
  .via {
    color: var(--accent);
  }
  .chev {
    color: var(--muted);
    margin: 0 4px;
  }
  .stage {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .stage .num {
    width: 20px;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .stage.direct {
    padding: 9px 12px;
    border: 1px dashed var(--border-strong);
    border-radius: 8px;
    color: var(--text-2);
  }
  .via.direct {
    color: var(--muted);
  }
  .scope {
    min-width: 58px;
    text-align: center;
  }
  .foot {
    padding: 8px 18px 12px;
    border-top: 1px solid var(--border);
  }
  .segmented {
    align-self: flex-start;
    margin-bottom: 8px;
  }
  .ok-text {
    color: var(--ok);
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .dnsline {
    margin-top: 2px;
  }
  .warn-text {
    color: var(--warn);
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  textarea {
    resize: vertical;
  }
</style>
