<script>
  // DNS für Geräte ohne VPN (Fernseher, Router …): Einrichtung, freigegebene Geräte und wer von außen fragt.
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import Modal from './Modal.svelte';
  import PortHelp from './PortHelp.svelte';
  import SearchInput from './SearchInput.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { ago, fmtNum, copy } from '../lib/format.js';
  import { toast } from '../lib/state.svelte.js';

  let { onchange } = $props();

  let d = $state({ external: { public: false, clients: [], seen: [], self: '', self_ips: [] }, profiles: [], dns_enabled: true, out_interface: 'eth0', dry_run: false });
  let loaded = $state(false);
  async function load() {
    d = await get('/dns/clients');
    loaded = true;
  }
  load();
  $effect(() => {
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  });

  const x = $derived(d.external);
  const when = (ts) => (!ts ? 'nie' : ago(ts) === 'online' ? 'gerade eben' : ago(ts));
  const globalProfile = $derived(d.profiles.find((p) => p.global && p.enabled));
  const profName = (id) => (id === -1 ? 'ohne Filter' : id > 0 ? d.profiles.find((p) => p.id === id)?.name || `Profil #${id}` : globalProfile ? `${globalProfile.name} (global)` : 'ohne Filter (kein globales Profil)');
  const strangers = $derived(x.seen.filter((s) => !s.client));
  const dnsIP4 = $derived(x.self_ips.find((a) => !a.includes(':')) || '');
  const dnsIP6 = $derived(x.self_ips.find((a) => a.includes(':')) || '');

  async function setPublic(on) {
    if (on && !x.clients.some((c) => c.enabled)) {
      if (!(await confirmDialog({ title: 'DNS von außen einschalten?', text: 'Noch ist kein Gerät freigegeben – Anfragen werden verworfen, aber hier angezeigt. So siehst du die Adresse deines Geräts und kannst es mit einem Klick freigeben.', ok: 'Einschalten' }))) return;
    }
    if (await run(() => put('/dns/settings', { public: on }), on ? 'DNS von außen eingeschaltet' : 'DNS von außen ausgeschaltet')) {
      await load();
      onchange?.();
    }
  }

  // ---------- Gerät freigeben ----------
  let open = $state(false);
  let busy = $state(false);
  let f = $state({});
  function edit(c, addr) {
    f = c
      ? { id: c.id, name: c.name, addrs: c.addrs.join('\n'), profile: c.profile, note: c.note, enabled: c.enabled }
      : { id: 0, name: '', addrs: addr || '', profile: 0, note: '', enabled: true };
    open = true;
  }
  async function save() {
    busy = true;
    const body = { name: f.name, addrs: [f.addrs], profile: Number(f.profile), note: f.note, enabled: f.enabled };
    const ok = await run(() => (f.id ? put(`/dns/clients/${f.id}`, body) : post('/dns/clients', body)), 'Gespeichert');
    busy = false;
    if (ok) {
      open = false;
      load();
      onchange?.();
    }
  }
  async function toggle(c) {
    if (await run(() => put(`/dns/clients/${c.id}`, { enabled: !c.enabled }))) load();
  }
  async function remove(c) {
    if (!(await confirmDialog({ title: `„${c.name}“ löschen?`, text: 'Das Gerät bekommt danach keine Antworten mehr vom Panel-DNS.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/dns/clients/${c.id}`), 'Gelöscht')) {
      load();
      onchange?.();
    }
  }
  async function forget(addr) {
    if (!addr && !(await confirmDialog({ title: 'Liste leeren?', text: 'Die Liste der Absender wird geleert; neue Anfragen erscheinen wieder.', ok: 'Leeren' }))) return;
    if (await run(() => del(`/dns/seen${addr ? `?addr=${encodeURIComponent(addr)}` : ''}`))) load();
  }

  let q = $state('');
  let showAll = $state(false);
  const seenShown = $derived.by(() => {
    const t = q.trim().toLowerCase();
    let rows = x.seen;
    if (t) rows = rows.filter((s) => [s.addr, s.host, s.client_name, s.name].some((v) => (v || '').toLowerCase().includes(t)));
    return showAll ? rows : rows.slice(0, 50);
  });
  const cp = (t) => copy(t).then(() => toast('Kopiert'));
  const valid = $derived(f.name?.trim() && f.addrs?.trim());
</script>

<div class="grid cols-2 top">
  <div class="card card-pad stack" style="gap:10px">
    <div class="row" style="gap:10px">
      <div class="grow">
        <strong>DNS von außen</strong>
        <Info title="DNS ohne VPN" wide>
          <p>Geräte, die kein VPN können (Fernseher, Konsole, Router zu Hause), tragen den Server direkt als DNS-Server ein. Dann gelten für sie Filterprofile und Protokoll wie für VPN-Geräte.</p>
          <p><b>Nur freigegebene Absender</b> bekommen Antworten. Ein offener DNS-Server für alle würde sofort für Angriffe (DNS-Verstärkung) missbraucht – deshalb gibt es das nicht. Fremde Anfragen werden verworfen, aber unten mitgezählt.</p>
          <p>Wechselt die Adresse deines Anschlusses, trag statt der IP einen DynDNS-Namen ein (z. B. von der FRITZ!Box: <code>xyz.myfritz.net</code>) – das Panel löst ihn alle 5 Minuten neu auf.</p>
        </Info>
        <div class="muted small">Port 53 auf {d.out_interface} → Panel-DNS</div>
      </div>
      <label class="switch"><input type="checkbox" checked={x.public} disabled={!d.dns_enabled} onchange={(e) => setPublic(e.currentTarget.checked)} /><span class="track"></span></label>
    </div>
    {#if !d.dns_enabled}
      <div class="notice warn small"><Icon name="alert" size={16} /><span>Erst den Panel-DNS einschalten (Einstellungen).</span></div>
    {:else if x.public}
      <div class="notice okn small"><Icon name="check" size={16} /><span>{x.clients.filter((c) => c.enabled).length} {x.clients.filter((c) => c.enabled).length === 1 ? 'freigegebenes Gerät' : 'freigegebene Geräte'} · {strangers.length} {strangers.length === 1 ? 'fremder Absender' : 'fremde Absender'} gesehen</span></div>
    {:else}
      <div class="muted small">Aus – Anfragen von außen erreichen den Panel-DNS nicht.</div>
    {/if}
  </div>

  <div class="card card-pad stack" style="gap:8px">
    <div class="row" style="gap:6px">
      <strong>So richtest du es ein</strong>
      <Info title="Portweiterleitung auf dem Proxmox-Host" wide>
        <PortHelp ports={[{ proto: 'udp', port: 53, note: 'DNS' }, { proto: 'tcp', port: 53, note: 'DNS, große Antworten' }]} />
        <p class="muted">Im Container leitet das Panel Port 53 selbst an den DNS-Dienst weiter – sonst ist nichts zu tun.</p>
      </Info>
    </div>
    <ol class="steps small">
      <li><b>Proxmox-Host:</b> UDP und TCP 53 an den Container weiterleiten (i-Symbol: fertige Befehle).</li>
      <li><b>Hier:</b> „DNS von außen“ einschalten und das Gerät freigeben – mit der öffentlichen IP deines Anschlusses (steht in der Router-Oberfläche; fremde Absender unten zeigen sie auch) oder einem DynDNS-Namen.</li>
      <li>
        <b>Am Gerät</b> (Fernseher: Netzwerk → IP-Einstellungen → DNS manuell) bzw. besser im Router als DNS-Server eintragen:
        {#if dnsIP4}<button class="ipbtn mono" title="Kopieren" onclick={() => cp(dnsIP4)}>{dnsIP4} <Icon name="copy" size={12} /></button>{/if}
        {#if dnsIP6}<button class="ipbtn mono" title="Kopieren" onclick={() => cp(dnsIP6)}>{dnsIP6} <Icon name="copy" size={12} /></button>{/if}
        {#if !dnsIP4 && !dnsIP6}<span class="mono">{x.self || 'öffentliche IP des Servers'}</span>{/if}
      </li>
      <li><b>Prüfen:</b> Gerät benutzen – unten erscheint es mit „freigegeben“. Taucht es als <i>fremd</i> auf, stimmt die Adresse nicht: dort auf „Freigeben“ klicken.</li>
    </ol>
    <div class="tiny muted">Zweiten DNS-Server am Gerät leer lassen – sonst fragt es teils dort und umgeht den Filter. Viele Fernseher und Android-Geräte nutzen fest eingebaute DNS-Server (z. B. 8.8.8.8); das lässt sich nur im Router abfangen.</div>
  </div>
</div>

<div class="card" style="margin-top:14px">
  <div class="card-head">
    <h2>Freigegebene Geräte <span class="muted small">{x.clients.length}</span></h2>
    <button class="btn sm primary" onclick={() => edit()}><Icon name="plus" size={14} /> Gerät freigeben</button>
  </div>
  {#if loaded && !x.clients.length}
    <div class="empty small"><Icon name="lock" size={18} /><p>Noch kein Gerät freigegeben.</p></div>
  {:else}
    <div class="list">
      {#each x.clients as c (c.id)}
        <div class="item" class:off={!c.enabled}>
          <Icon name="laptop" size={18} />
          <div class="grow">
            <div class="line">
              <strong>{c.name}</strong>
              {#each c.addrs as a}<span class="chip mono">{a}</span>{/each}
            </div>
            <div class="tiny muted sub">
              <span><Icon name="shield" size={12} /> {profName(c.profile)}</span>
              <span>· {fmtNum(c.queries)} Anfragen{#if c.blocked}, <span class="bad-text">{fmtNum(c.blocked)} gesperrt</span>{/if}</span>
              <span>· zuletzt {when(c.last)}</span>
              {#each c.resolved as r}
                <span class={r.err ? 'warn-text' : ''}>· {r.host} → {r.addrs.length ? r.addrs.join(', ') : r.err}</span>
              {/each}
              {#if c.note}<span>· {c.note}</span>{/if}
            </div>
          </div>
          <label class="switch" title={c.enabled ? 'Aktiv' : 'Aus'}><input type="checkbox" checked={c.enabled} onchange={() => toggle(c)} /><span class="track"></span></label>
          <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => edit(c)}><Icon name="edit" size={15} /></button>
          <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(c)}><Icon name="trash" size={15} /></button>
        </div>
      {/each}
    </div>
  {/if}
</div>

<div class="card" style="margin-top:14px">
  <div class="card-head">
    <h2>
      Wer fragt von außen?
      <Info title="Absender außerhalb des VPN" text="Alle Adressen außerhalb des VPN, die den Panel-DNS gefragt haben – freigegebene Geräte und fremde (deren Anfragen verworfen werden). Hostname = Rückwärtsauflösung der IP, meist der Anbieter. Die Liste übersteht Neustarts; Einträge älter als 30 Tage verschwinden." />
      <span class="muted small">{x.seen.length}</span>
    </h2>
    <div class="row" style="gap:8px">
      {#if x.seen.length > 8}<SearchInput bind:value={q} placeholder="IP, Host, Domain …" width="220px" />{/if}
      {#if x.seen.length}<button class="btn sm ghost" onclick={() => forget('')}><Icon name="trash" size={14} /> Leeren</button>{/if}
    </div>
  </div>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Absender</th><th>Hostname</th><th>Gerät</th><th class="right">Anfragen</th><th>Zuletzt</th><th>Letzte Domain</th><th></th></tr></thead>
      <tbody>
        {#each seenShown as s (s.addr)}
          <tr>
            <td class="mono small nowrap">{s.addr}</td>
            <td class="small ellipsis hostcell" title={s.host}>{s.host || '–'}</td>
            <td class="nowrap">
              {#if s.client}
                <span class="badge ok"><Icon name="check" size={12} /> {s.client_name || 'freigegeben'}</span>
              {:else}
                <span class="badge bad" title="Anfragen werden verworfen"><Icon name="alert" size={12} /> fremd</span>
              {/if}
            </td>
            <td class="right small">{fmtNum(s.queries)}{#if s.blocked}<div class="tiny bad-text">{fmtNum(s.blocked)} gesperrt</div>{/if}</td>
            <td class="small nowrap muted" title={new Date(s.last * 1000).toLocaleString('de-DE')}>{when(s.last)}<div class="tiny">seit {new Date(s.first * 1000).toLocaleDateString('de-DE')}</div></td>
            <td class="mono tiny ellipsis namecell" title={s.name}>{s.name || '–'}</td>
            <td class="right nowrap">
              {#if !s.client}<button class="btn sm" onclick={() => edit(null, s.addr)}><Icon name="check" size={13} /> Freigeben</button>{/if}
              <button class="btn sm icon ghost" title="Aus der Liste entfernen" onclick={() => forget(s.addr)}><Icon name="x" size={13} /></button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="7" class="muted small" style="padding:20px">{x.public ? 'Noch keine Anfragen von außen.' : 'DNS von außen ist aus.'}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if !showAll && !q && x.seen.length > 50}<div style="text-align:center;padding:10px"><button class="btn sm" onclick={() => (showAll = true)}>Alle {x.seen.length} zeigen</button></div>{/if}
</div>

<Modal bind:open title={f.id ? 'Gerät bearbeiten' : 'Gerät freigeben'} subtitle="Darf den Panel-DNS ohne VPN nutzen" width={560}>
  <div class="stack">
    <div class="field">
      <label for="dx-name">Name</label>
      <input id="dx-name" class="input" bind:value={f.name} maxlength="48" placeholder="z. B. Fernseher Wohnzimmer" />
    </div>
    <div class="field">
      <label for="dx-addrs">Adressen <Info title="Adressen" text="Öffentliche IP-Adressen (IPv4/IPv6), Netze (höchstens /16 bzw. /48 – bei IPv6 am besten das /64 des Anschlusses) oder DynDNS-Namen. Eine pro Zeile." /></label>
      <textarea id="dx-addrs" class="input mono" rows="3" bind:value={f.addrs} placeholder={'203.0.113.10\n2001:db8:1234:5678::/64\nmeinzuhause.myfritz.net'}></textarea>
    </div>
    <div class="field">
      <label for="dx-prof">Filterprofil</label>
      <select id="dx-prof" class="input" bind:value={f.profile}>
        <option value={0}>Globales Profil{globalProfile ? ` (${globalProfile.name})` : ' – keins vorhanden'}</option>
        {#each d.profiles as p}<option value={p.id}>{p.name}{p.enabled ? '' : ' (aus)'}</option>{/each}
        <option value={-1}>Ohne Filter</option>
      </select>
    </div>
    <div class="field">
      <label for="dx-note">Notiz</label>
      <input id="dx-note" class="input" bind:value={f.note} maxlength="300" placeholder="optional" />
    </div>
    <label class="switch"><input type="checkbox" bind:checked={f.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={busy || !valid}>Speichern</button>
  {/snippet}
</Modal>

<style>
  .top {
    align-items: start;
  }
  .steps {
    margin: 0;
    padding-left: 20px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .ipbtn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 1px solid var(--border);
    background: var(--panel);
    border-radius: 6px;
    font-size: 12px;
    padding: 1px 7px;
    cursor: pointer;
    color: var(--text);
    margin: 2px 2px 0 0;
  }
  .ipbtn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }
  .list {
    display: flex;
    flex-direction: column;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 16px;
    border-top: 1px solid var(--border);
  }
  .item.off {
    opacity: 0.55;
  }
  .line {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .sub {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 3px;
    align-items: center;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 8px;
    font-size: 12px;
  }
  .mono {
    font-family: var(--mono, ui-monospace, monospace);
  }
  .empty {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 16px;
    color: var(--text-2);
  }
  .empty p {
    margin: 0;
  }
  .hostcell {
    max-width: 220px;
  }
  .namecell {
    max-width: 220px;
  }
</style>
