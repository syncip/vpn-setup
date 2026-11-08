<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import FieldForm from '../components/FieldForm.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { ago, clone, date, fmtNum } from '../lib/format.js';
  import { protocol, toast } from '../lib/state.svelte.js';

  let d = $state({ exits: [], groups: [], error: '' });
  let servers = $state([]);
  let loaded = $state(false);

  async function load() {
    try {
      const [x, s] = await Promise.all([get('/exits'), get('/servers')]);
      d = x;
      servers = s.filter((v) => v.protocol === 'proxy');
      loaded = true;
    } catch (e) {
      toast(e.message, 'error');
    }
  }
  load();
  $effect(() => {
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  });

  const exitById = $derived(Object.fromEntries(d.exits.map((e) => [e.id, e])));
  const groupById = $derived(Object.fromEntries(d.groups.map((g) => [g.id, g])));

  const STATE = {
    ok: ['ok', 'Bevorzugter Ausgang'],
    failover: ['warn', 'Ausweich-Ausgang'],
    blocked: ['bad', 'Alle Ausgänge gestört – gesperrt'],
    direct: ['warn', 'Alle Ausgänge gestört – direkt'],
    waiting: ['muted', 'Wird geprüft …'],
  };

  function health(e) {
    const s = e.status;
    if (!e.enabled) return ['muted', 'deaktiviert'];
    if (!s || !s.checked) return ['muted', 'noch nicht geprüft'];
    if (!s.up) return ['bad', s.error || 'nicht verbunden'];
    if (s.error) return ['bad', s.error];
    if (s.loss >= 50) return ['bad', `${fmtNum(s.loss)} % Verlust`];
    if (s.loss > 10 || s.rtt > 300) return ['warn', 'instabil'];
    return ['ok', 'verbunden'];
  }

  // ---------- Prüfen ----------
  let checking = $state(false);
  async function check(speed) {
    checking = true;
    await run(() => post('/exits/check', { speed }), speed ? 'Geschwindigkeitstest läuft (bis zu einer Minute)' : 'Prüfung läuft');
    setTimeout(load, speed ? 20000 : 6000);
    setTimeout(() => {
      checking = false;
      load();
    }, speed ? 60000 : 12000);
  }

  // ---------- Ausgänge ----------
  let exOpen = $state(false);
  let exCur = $state(null);
  let ex = $state({ name: '', config: '', username: '', password: '', enabled: true });
  let exBusy = $state(false);
  let removedInfo = $state(null);
  const exType = $derived(ex.config.toLowerCase().includes('[interface]') ? 'wireguard' : ex.config.trim() ? 'openvpn' : exCur?.type || '');

  function openExit(e = null) {
    exCur = e;
    ex = { name: e?.name || '', config: '', username: e?.username || '', password: '', enabled: e ? e.enabled : true };
    exOpen = true;
  }
  async function readFile(ev) {
    const f = ev.currentTarget.files?.[0];
    if (!f) return;
    if (f.size > 256 * 1024) return toast('Datei zu groß', 'error');
    ex.config = await f.text();
    if (!ex.name) ex.name = f.name.replace(/\.(conf|ovpn)$/i, '').slice(0, 48);
  }
  async function saveExit() {
    exBusy = true;
    const body = { name: ex.name, enabled: ex.enabled };
    if (ex.config.trim()) body.config = ex.config;
    if (exType === 'openvpn') {
      body.username = ex.username;
      if (ex.password) body.password = ex.password;
    }
    const r = exCur ? await run(() => put(`/exits/${exCur.id}`, body), 'Ausgang gespeichert') : await run(() => post('/exits', body), 'Ausgang angelegt');
    exBusy = false;
    if (r) {
      exOpen = false;
      if (r.removed?.length) removedInfo = { name: ex.name, list: r.removed };
      ex.password = '';
      ex.config = '';
      load();
    }
  }
  async function toggleExit(e) {
    if (await run(() => put(`/exits/${e.id}`, { enabled: !e.enabled }), e.enabled ? 'Ausgang deaktiviert' : 'Ausgang aktiviert')) load();
  }
  async function removeExit(e) {
    const used = e.groups.map((id) => groupById[id]?.name).filter(Boolean);
    if (!(await confirmDialog({ title: `Ausgang ${e.name} löschen?`, text: used.length ? `Er wird auch aus ${used.join(', ')} entfernt.` : 'Der Tunnel wird abgebaut.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/exits/${e.id}`), 'Ausgang gelöscht')) load();
  }

  // ---------- Gruppen ----------
  let grOpen = $state(false);
  let grCur = $state(null);
  let gr = $state({});
  function openGroup(g = null) {
    grCur = g;
    gr = g
      ? clone($state.snapshot({ name: g.name, enabled: g.enabled, exits: g.exits, on_fail: g.on_fail, max_loss: g.max_loss, max_rtt: g.max_rtt, min_mbit: g.min_mbit, dns: g.dns }))
      : { name: '', enabled: true, exits: d.exits.length === 1 ? [d.exits[0].id] : [], on_fail: 'block', max_loss: 20, max_rtt: 400, min_mbit: 0, dns: '1.1.1.1, 9.9.9.9' };
    grOpen = true;
  }
  function toggleMember(id) {
    gr.exits = gr.exits.includes(id) ? gr.exits.filter((x) => x !== id) : [...gr.exits, id];
  }
  function moveUp(i) {
    if (i < 1) return;
    const l = [...gr.exits];
    [l[i - 1], l[i]] = [l[i], l[i - 1]];
    gr.exits = l;
  }
  async function saveGroup() {
    const body = $state.snapshot(gr);
    for (const k of ['max_loss', 'max_rtt', 'min_mbit']) body[k] = Number(body[k]) || 0;
    const r = grCur ? await run(() => put(`/groups/${grCur.id}`, body), 'Gruppe gespeichert') : await run(() => post('/groups', body), 'Gruppe angelegt');
    if (r) {
      grOpen = false;
      load();
    }
  }
  async function removeGroup(g) {
    if (!(await confirmDialog({ title: `Gruppe ${g.name} löschen?`, text: 'Die Ausgänge selbst bleiben erhalten.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/groups/${g.id}`), 'Gruppe gelöscht')) load();
  }
  async function switchTo(g, exitId) {
    if (!exitId || exitId === g.status?.active) return;
    if (await run(() => post(`/groups/${g.id}/switch`, { exit: exitId }), 'Umgeschaltet')) load();
  }

  // ---------- Proxy-Server ----------
  let svOpen = $state(false);
  let svCur = $state(null);
  let sv = $state({ name: '', enabled: true });
  let svValues = $state({});
  const pxProto = $derived(protocol('proxy'));
  function openServer(s = null) {
    svCur = s;
    sv = { name: s?.name || 'Proxy', enabled: s ? s.enabled : true };
    if (s) svValues = clone($state.snapshot(s.settings));
    else {
      const v = {};
      for (const f of pxProto?.server_fields || []) if (f.default !== undefined) v[f.key] = clone(f.default);
      if (d.groups.length) v.group = d.groups[0].id;
      svValues = v;
    }
    svOpen = true;
  }
  async function saveServer() {
    const body = { name: sv.name, enabled: sv.enabled, settings: $state.snapshot(svValues) };
    const ok = svCur ? await run(() => put(`/servers/${svCur.id}`, body), 'Proxy gespeichert') : await run(() => post('/servers', { ...body, protocol: 'proxy' }), 'Proxy angelegt');
    if (ok) {
      svOpen = false;
      load();
    }
  }
  function serverPorts(s) {
    return (s.ports || []).map((p) => `${p.note.startsWith('SOCKS') ? 'SOCKS5' : 'HTTP'} ${p.port}`).join(' · ') || 'keine Ports aktiv';
  }
</script>

<PageHead title="Proxy" subtitle="SOCKS5/HTTP-Proxy und Ausgänge über externe VPNs (WireGuard- oder OpenVPN-Konfigurationen)">
  <button class="btn" onclick={() => check(false)} disabled={checking || !d.exits.length}><Icon name="refresh" size={16} /> Jetzt prüfen</button>
  <button class="btn" onclick={() => check(true)} disabled={checking || !d.exits.length} title="Lädt 5 MB über jeden Ausgang"><Icon name="gauge" size={16} /> Geschwindigkeit messen</button>
</PageHead>

{#if d.error}<div class="notice bad" style="margin-bottom:16px"><Icon name="alert" /><span>{d.error}</span></div>{/if}

<!-- Proxy-Server -->
<div class="card">
  <div class="card-head">
    <div><h2>Proxy-Server</h2><div class="muted tiny">Zugänge legst du beim Nutzer an (Zugang hinzufügen → Proxy)</div></div>
    <button class="btn sm primary" onclick={() => openServer()}><Icon name="plus" size={15} /> Proxy anlegen</button>
  </div>
  <div class="list">
    {#each servers as s}
      {@const g = groupById[s.settings.group]}
      <div class="item">
        <span class="srvlogo"><ProtoLogo id="proxy" size={30} /><span class="dot" class:on={s.status.running} class:bad={s.enabled && !s.status.running}></span></span>
        <div class="grow">
          <div class="strong">{s.name} {#if !s.enabled}<span class="badge muted">aus</span>{/if}</div>
          <div class="muted tiny">{serverPorts(s)} · Ausgang: {g ? g.name : 'direkt über den Server'} · {s.status.detail}</div>
        </div>
        <span class="badge" title="online / Zugänge">{s.online} / {s.peers}</span>
        <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => openServer(s)}><Icon name="edit" size={15} /></button>
      </div>
    {:else}
      <div class="empty small">Noch kein Proxy-Server.</div>
    {/each}
  </div>
</div>

<!-- Gruppen -->
<div class="section-head">
  <div><h2>Ausgangsgruppen</h2><div class="muted small">Mehrere Ausgänge in fester Reihenfolge – fällt einer aus, übernimmt der nächste automatisch</div></div>
  <button class="btn sm" onclick={() => openGroup()} disabled={!d.exits.length}><Icon name="plus" size={15} /> Gruppe anlegen</button>
</div>
<div class="grid cols-2">
  {#each d.groups as g}
    {@const st = STATE[g.status?.state || (g.enabled ? 'waiting' : '')] || ['muted', 'deaktiviert']}
    {@const act = exitById[g.status?.active]}
    <div class="card group">
      <div class="card-head">
        <div>
          <h3>{g.name}</h3>
          <div class="muted tiny">
            Bei Ausfall aller: {g.on_fail === 'direct' ? 'direkt über den Server' : 'sperren'} · Grenzen {fmtNum(g.max_loss)} % Verlust, {fmtNum(g.max_rtt)} ms{g.min_mbit ? `, ${fmtNum(g.min_mbit)} Mbit/s` : ''}
          </div>
        </div>
        <span class="badge {st[0]}">{g.enabled ? st[1] : 'deaktiviert'}</span>
      </div>
      <div class="card-pad stack" style="gap:10px">
        {#if g.enabled}
          <div class="active-row">
            <Icon name="route" size={16} />
            <span class="grow">Aktiv: <b>{act ? act.name : 'keiner'}</b>
              {#if act?.status?.ip}<span class="muted small"> · {act.status.ip} {act.status.loc}</span>{/if}
              {#if g.status?.since}<span class="muted tiny"> · seit {date(g.status.since, true)}</span>{/if}
            </span>
          </div>
          {#if g.status?.reason}<div class="muted tiny">{g.status.reason}</div>{/if}
        {/if}
        <ol class="members">
          {#each g.exits as id, i}
            {@const e = exitById[id]}
            {#if e}
              {@const h = health(e)}
              <li class:cur={g.status?.active === id}>
                <span class="dot {h[0]}" class:on={h[0] === 'ok'}></span>
                <span class="grow">{i + 1}. {e.name} {#if g.status?.pinned === id}<span class="badge accent" title="Von Hand gewählt – wird statt des ersten Ausgangs bevorzugt. Ausgang 1 wählen = normale Reihenfolge.">gewählt</span>{/if}</span>
                <span class="muted tiny">{e.status?.rtt ? `${fmtNum(Math.round(e.status.rtt))} ms` : ''}</span>
                {#if g.enabled && e.enabled && g.status?.active !== id}
                  <button class="btn sm ghost" onclick={() => switchTo(g, id)} title="Von Hand auf diesen Ausgang umschalten">Umschalten</button>
                {/if}
              </li>
            {/if}
          {:else}
            <li class="muted small">Keine Ausgänge in der Gruppe</li>
          {/each}
        </ol>
        {#if g.users.length}
          <div class="muted tiny">Genutzt von: {g.users.map((u) => u.name).join(', ')}</div>
        {/if}
      </div>
      <div class="actions">
        <button class="btn sm" onclick={() => openGroup(g)}><Icon name="edit" size={15} /> Bearbeiten</button>
        <span class="grow"></span>
        <button class="btn sm icon ghost danger" title="Löschen" onclick={() => removeGroup(g)}><Icon name="trash" size={15} /></button>
      </div>
    </div>
  {:else}
    {#if loaded}<div class="card empty small" style="grid-column:1/-1">{d.exits.length ? 'Noch keine Gruppe – lege eine an und wähle sie beim Proxy-Server als Ausgang.' : 'Lade zuerst einen Ausgang hoch.'}</div>{/if}
  {/each}
</div>

<!-- Ausgänge -->
<div class="section-head">
  <div><h2>Ausgänge</h2><div class="muted small">Externe VPN-Verbindungen – nur für Gruppen, der Server selbst nutzt sie nicht</div></div>
  <button class="btn sm primary" onclick={() => openExit()}><Icon name="upload" size={15} /> Ausgang hochladen</button>
</div>
<div class="card">
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Name</th><th>Status</th><th>Antwortzeit</th><th>Verlust</th><th>Tempo</th><th>Öffentliche IP</th><th></th></tr></thead>
      <tbody>
        {#each d.exits as e}
          {@const h = health(e)}
          {@const s = e.status}
          <tr>
            <td>
              <div class="row" style="gap:8px">
                <ProtoLogo id={e.type} size={22} />
                <div>
                  <div class="strong">{e.name}</div>
                  <div class="muted tiny mono">{e.server}</div>
                </div>
              </div>
            </td>
            <td>
              <span class="badge {h[0]}">{h[1]}</span>
              {#if e.error}<div class="tiny bad-text">{e.error}</div>{/if}
              {#if e.need_auth && !e.has_auth}<div class="tiny bad-text">Benutzername/Passwort fehlen</div>{/if}
            </td>
            <td>{s?.rtt ? `${fmtNum(Math.round(s.rtt))} ms` : '–'}</td>
            <td>{s?.checked ? `${fmtNum(Math.round(s.loss))} %` : '–'}</td>
            <td title={s?.mbit_at ? `gemessen ${ago(s.mbit_at)}` : ''}>{s?.mbit ? `${fmtNum(Math.round(s.mbit))} Mbit/s` : '–'}</td>
            <td>{#if s?.ip}<span class="mono small">{s.ip}</span> <span class="badge">{s.loc}</span>{:else}–{/if}</td>
            <td class="nowrap">
              {#if e.removed.length}<span class="badge muted" title={'Beim Hochladen entfernt: ' + e.removed.join(', ')}><Icon name="filter" size={12} /> {e.removed.length}</span>{/if}
              <button class="btn sm icon ghost" title={e.enabled ? 'Deaktivieren' : 'Aktivieren'} onclick={() => toggleExit(e)}><Icon name="power" size={15} /></button>
              <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => openExit(e)}><Icon name="edit" size={15} /></button>
              <button class="btn sm icon ghost danger" title="Löschen" onclick={() => removeExit(e)}><Icon name="trash" size={15} /></button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="7" class="empty small">Noch keine Ausgänge. Lade die WireGuard- oder OpenVPN-Konfiguration deines Anbieters hoch.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

<div class="notice" style="margin-top:18px">
  <Icon name="info" />
  <span>Hochgeladene Konfigurationen werden bereinigt: Skripte (PostUp, up/down), Routen, DNS-Änderungen und Dateiverweise fallen weg. Der Server prüft alle 30 Sekunden Antwortzeit und Verlust jedes Ausgangs (Ping und HTTPS über den Tunnel) und schaltet bei Störung auf den nächsten Ausgang der Gruppe; zurück geht es, wenn der bevorzugte Ausgang 10 Minuten stabil war. Nur IPv4.</span>
</div>

<Modal bind:open={exOpen} title={exCur ? `Ausgang ${exCur.name}` : 'Ausgang hochladen'} width={680}>
  <div class="stack">
    <div class="field"><label for="ex-name">Name</label><input id="ex-name" class="input" bind:value={ex.name} placeholder="z. B. Anbieter USA" /></div>
    <div class="field">
      <label for="ex-file">Konfiguration (.conf von WireGuard oder .ovpn von OpenVPN)</label>
      <input id="ex-file" type="file" accept=".conf,.ovpn,.txt" onchange={readFile} />
      <textarea class="input mono" rows="8" bind:value={ex.config} placeholder={exCur ? 'leer lassen = Konfiguration behalten' : '[Interface] … bzw. client / remote … <ca> …'}></textarea>
      {#if exType}<div class="help">Erkannt: <b>{exType === 'wireguard' ? 'WireGuard' : 'OpenVPN'}</b></div>{/if}
    </div>
    {#if exType === 'openvpn'}
      <div class="grid cols-2">
        <div class="field"><label for="ex-user">Benutzername</label><input id="ex-user" class="input" bind:value={ex.username} autocomplete="off" /></div>
        <div class="field"><label for="ex-pw">Passwort</label><input id="ex-pw" class="input" type="password" bind:value={ex.password} autocomplete="new-password" placeholder={exCur?.has_auth ? 'gespeichert – leer = unverändert' : ''} /></div>
      </div>
      <div class="help">Nur nötig, wenn die Konfiguration „auth-user-pass“ enthält (bei vielen Anbietern die OpenVPN-Zugangsdaten aus dem Kundenbereich, nicht das Login-Passwort).</div>
    {/if}
    <label class="switch"><input type="checkbox" bind:checked={ex.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (exOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveExit} disabled={exBusy || !ex.name || (!exCur && !ex.config.trim())}>{exCur ? 'Speichern' : 'Hochladen'}</button>
  {/snippet}
</Modal>

<Modal open={!!removedInfo} onclose={() => (removedInfo = null)} title="Konfiguration bereinigt" width={520}>
  {#if removedInfo}
    <p class="small">Aus „{removedInfo.name}“ wurden diese Einträge entfernt, weil sie das System verändern könnten:</p>
    <ul class="removed">{#each removedInfo.list as r}<li class="mono small">{r}</li>{/each}</ul>
  {/if}
  {#snippet footer()}<button class="btn primary" onclick={() => (removedInfo = null)}>Verstanden</button>{/snippet}
</Modal>

<Modal bind:open={grOpen} title={grCur ? `Gruppe ${grCur.name}` : 'Gruppe anlegen'} width={640}>
  <div class="stack">
    <div class="field"><label for="gr-name">Name</label><input id="gr-name" class="input" bind:value={gr.name} placeholder="z. B. USA" /></div>
    <div class="field">
      <span class="label">Ausgänge (Reihenfolge = Vorrang)</span>
      <ol class="members edit">
        {#each gr.exits || [] as id, i}
          <li>
            <span class="grow">{i + 1}. {exitById[id]?.name || id}</span>
            <button class="btn sm icon ghost" title="Nach oben" disabled={i === 0} onclick={() => moveUp(i)}><Icon name="arrow-up" size={14} /></button>
            <button class="btn sm icon ghost" title="Entfernen" onclick={() => toggleMember(id)}><Icon name="x" size={14} /></button>
          </li>
        {/each}
      </ol>
      <div class="row wrap" style="gap:6px">
        {#each d.exits.filter((e) => !(gr.exits || []).includes(e.id)) as e}
          <button class="btn sm" onclick={() => toggleMember(e.id)}><Icon name="plus" size={13} /> {e.name}</button>
        {/each}
      </div>
    </div>
    <div class="field">
      <label for="gr-fail">Wenn alle Ausgänge gestört sind</label>
      <select id="gr-fail" class="input" bind:value={gr.on_fail}>
        <option value="block">Sperren – kein Verkehr (Standort bleibt sicher verborgen)</option>
        <option value="direct">Direkt über den Server weiterleiten</option>
      </select>
    </div>
    <div class="grid cols-3">
      <div class="field"><label for="gr-loss">Max. Verlust (%)</label><input id="gr-loss" class="input" type="number" bind:value={gr.max_loss} /></div>
      <div class="field"><label for="gr-rtt">Max. Antwortzeit (ms)</label><input id="gr-rtt" class="input" type="number" bind:value={gr.max_rtt} /><div class="help">0 = egal</div></div>
      <div class="field"><label for="gr-mbit">Min. Tempo (Mbit/s)</label><input id="gr-mbit" class="input" type="number" bind:value={gr.min_mbit} /><div class="help">0 = egal; braucht den Geschwindigkeitstest</div></div>
    </div>
    <div class="field"><label for="gr-dns">DNS-Server (über den Ausgang)</label><input id="gr-dns" class="input mono" bind:value={gr.dns} /><div class="help">Namen werden über den aktiven Ausgang aufgelöst, damit Dienste den passenden Standort sehen.</div></div>
    <label class="switch"><input type="checkbox" bind:checked={gr.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (grOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveGroup} disabled={!gr.name}>{grCur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<Modal bind:open={svOpen} title={svCur ? `Proxy ${svCur.name}` : 'Proxy anlegen'} width={620}>
  <div class="stack">
    <div class="field"><label for="sv-name">Name</label><input id="sv-name" class="input" bind:value={sv.name} /></div>
    {#if pxProto}<FieldForm fields={pxProto.server_fields} bind:values={svValues} />{/if}
    <label class="switch"><input type="checkbox" bind:checked={sv.enabled} /><span class="track"></span> Aktiv</label>
    <div class="notice small"><Icon name="info" size={16} /><span>Die Ports müssen auf dem Proxmox-Host per TCP an den Container weitergeleitet werden (Einstellungen → Ports).</span></div>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (svOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={saveServer} disabled={!sv.name}>{svCur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
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
  .section-head {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    justify-content: space-between;
    margin: 26px 0 12px;
  }
  .group {
    display: flex;
    flex-direction: column;
  }
  .actions {
    display: flex;
    gap: 6px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    margin-top: auto;
  }
  .active-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .active-row :global(svg) {
    color: var(--accent);
  }
  .members {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .members li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 8px;
    border-radius: var(--radius-sm);
    min-height: 32px;
  }
  .members li.cur {
    background: var(--accent-soft);
  }
  .members.edit li {
    border: 1px solid var(--border);
  }
  .members.edit {
    margin-bottom: 8px;
  }
  .dot.ok {
    background: var(--ok);
  }
  .dot.warn {
    background: var(--warn);
  }
  .dot.bad {
    background: var(--bad);
  }
  .dot.muted {
    background: var(--border-strong);
  }
  .bad-text {
    color: var(--bad);
    margin-top: 3px;
  }
  .nowrap {
    white-space: nowrap;
    text-align: right;
  }
  .removed {
    margin: 8px 0 0;
    padding-left: 18px;
  }
  .label {
    font-weight: 600;
    font-size: 13px;
  }
  textarea.input {
    margin-top: 8px;
    min-height: 140px;
    resize: vertical;
    font-size: 12px;
  }
  .srvlogo {
    position: relative;
    display: inline-flex;
  }
  .srvlogo .dot {
    position: absolute;
    right: -2px;
    bottom: -2px;
    border: 2px solid var(--panel);
    width: 10px;
    height: 10px;
  }
</style>
