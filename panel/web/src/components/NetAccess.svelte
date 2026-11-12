<script>
  // Netzwerk → Zugriff: welche Nutzer, Tarife oder Geräte welche WireGuard-Netze erreichen dürfen
  // (Tunnelnetz eines Servers und die Netze hinter dessen Geräten, z. B. Homelab).
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import Picker from './Picker.svelte';
  import Info from './Info.svelte';
  import SearchInput from './SearchInput.svelte';
  import ProtoLogo from './ProtoLogo.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { peerItems, userItems, tokens, matches } from '../lib/pick.js';
  import { PROTO_LABEL } from '../lib/format.js';

  let d = $state({ grants: [], networks: [], servers: [], users: [], peers: [], plans: [] });
  let loaded = $state(false);
  async function load() {
    try {
      d = await get('/netaccess');
      loaded = true;
    } catch {
      /* alter Stand bleibt */
    }
  }
  load();

  const by = (l) => Object.fromEntries((l || []).map((x) => [x.id, x]));
  const userById = $derived(by(d.users));
  const peerById = $derived(by(d.peers));
  const planById = $derived(by(d.plans));
  const netById = $derived(by(d.networks));
  const serverById = $derived(by(d.servers));

  // Freigaben je Netz (für die Netz-Kacheln)
  const grantsPerNet = $derived.by(() => {
    const m = {};
    for (const g of d.grants) if (g.enabled) for (const s of g.servers) m[s] = (m[s] || 0) + 1;
    return m;
  });

  function whoParts(g) {
    if (g.all) return [{ icon: 'users', text: 'Alle Nutzer' }];
    return [
      ...g.plans.map((id) => ({ icon: 'tag', text: planById[id]?.name || `Tarif ${id}` })),
      ...g.users.map((id) => ({ icon: 'user', text: userById[id]?.name || `Nutzer ${id}` })),
      ...g.peers.map((id) => {
        const p = peerById[id];
        return { proto: p?.protocol, text: p ? `${userById[p.user_id]?.name || '?'} · ${p.name}` : `Gerät ${id}` };
      }),
    ];
  }
  const netName = (id) => netById[id]?.name || serverById[id]?.name || `Server ${id}`;

  // Suche über Name, Netze und Berechtigte
  let q = $state('');
  const shown = $derived.by(() => {
    const t = tokens(q);
    return d.grants.filter((g) => matches(`${g.name} ${g.note} ${g.servers.map(netName).join(' ')} ${whoParts(g).map((p) => p.text).join(' ')}`, t));
  });

  async function toggle(g) {
    if (await run(() => put(`/netaccess/${g.id}`, { enabled: !g.enabled }), g.enabled ? 'Freigabe deaktiviert' : 'Freigabe aktiviert')) load();
  }
  async function remove(g) {
    if (!(await confirmDialog({ title: 'Freigabe löschen?', text: `„${g.name}“ – die Geräte erreichen diese Netze danach nicht mehr.`, ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/netaccess/${g.id}`), 'Freigabe gelöscht')) load();
  }

  // ---------- Formular ----------
  let open = $state(false);
  let f = $state({ id: 0, name: '', enabled: true, servers: [], all: false, users: [], plans: [], peers: [], note: '' });
  let busy = $state(false);
  function edit(g = null, server = 0) {
    f = g
      ? { id: g.id, name: g.name, enabled: g.enabled, servers: [...g.servers], all: g.all, users: [...g.users], plans: [...g.plans], peers: [...g.peers], note: g.note || '' }
      : { id: 0, name: '', enabled: true, servers: server ? [server] : [], all: false, users: [], plans: [], peers: [], note: '' };
    open = true;
  }
  function toggleNet(id) {
    f.servers = f.servers.includes(id) ? f.servers.filter((x) => x !== id) : [...f.servers, id];
  }
  const whoItems = $derived([
    ...d.plans.map((p) => ({ value: `plan:${p.id}`, label: p.name, sub: 'alle Nutzer mit diesem Tarif', icon: 'tag', group: 'Tarife', search: `${p.name} tarif` })),
    ...userItems(d.users, 'user', d.peers),
    ...peerItems(d.peers, d.users, d.servers, 'peer'),
  ]);
  function addWho(it) {
    const [k, v] = String(it.value).split(':');
    const id = Number(v);
    const key = { plan: 'plans', user: 'users', peer: 'peers' }[k];
    if (key && !f[key].includes(id)) f[key] = [...f[key], id];
  }
  function dropWho(key, id) {
    f[key] = f[key].filter((x) => x !== id);
  }
  const valid = $derived(f.name.trim() && f.servers.length && (f.all || f.users.length || f.plans.length || f.peers.length));
  async function save() {
    busy = true;
    const body = { name: f.name.trim(), enabled: f.enabled, servers: f.servers, all: f.all, users: f.users, plans: f.plans, peers: f.peers, note: f.note };
    const ok = await run(() => (f.id ? put(`/netaccess/${f.id}`, body) : post('/netaccess', body)), 'Freigabe gespeichert');
    busy = false;
    if (ok) {
      open = false;
      load();
    }
  }
  // Vorschlag für den Namen
  $effect(() => {
    if (!open || f.id || f.name) return;
    if (f.servers.length === 1 && (f.users.length || f.plans.length || f.peers.length || f.all)) {
      const who = f.all ? 'Alle' : f.plans.length ? planById[f.plans[0]]?.name : f.users.length ? userById[f.users[0]]?.name : peerById[f.peers[0]]?.name;
      if (who) f.name = `${who} → ${netName(f.servers[0])}`.slice(0, 48);
    }
  });
</script>

<div class="card">
  <div class="card-head">
    <h2>
      Netze
      <Info title="Zugriff auf Netze" wide>
        <p>Ein <b>Netz</b> ist ein WireGuard-Server: sein Tunnelnetz und die Netze hinter dessen Geräten (z. B. ein Homelab). Mit einer <b>Freigabe</b> erreichen Geräte anderer Server dieses Netz – z. B. „Anna darf auf WireGuard 1 und WireGuard 2“.</p>
        <ul>
          <li>Gilt für <b>WireGuard</b>, <b>OpenVPN</b> und <b>VLESS</b> – egal, an welchem Server die Geräte hängen.</li>
          <li>Ohne Freigabe sind die Server-Netze voneinander getrennt. Innerhalb eines Servers gilt weiter der dort eingestellte Zugriff zwischen Geräten.</li>
          <li>Die Firewall-Regeln, NAT und Routen setzt das Panel selbst. Auf dem Proxmox-Host ist dafür nichts nötig.</li>
          <li>Geräte im Ziel-Netz sehen die Anfragen mit der Adresse des Servers (NAT). Ihr eigener Rückweg ändert sich dadurch nicht.</li>
          <li><b>Geteilter Tunnel</b> (WireGuard „split“): Die freigegebenen Netze stehen danach in AllowedIPs – die Konfiguration bzw. das Abo <b>neu laden</b>. OpenVPN ohne Internet: Routen kommen beim nächsten Verbinden.</li>
          <li><b>VLESS</b> gilt auch – je Zugang. In v2RayTun &amp; Co. dafür „LAN umgehen“ / „Bypass LAN“ ausschalten, sonst schickt die App private Adressen gar nicht in den Tunnel.</li>
          <li><b>Hysteria2 und Proxy</b> können Nutzer nicht einzeln leiten – dort wirken Freigaben nicht. Private Ziele sind für sie gesperrt (Ausnahmen unter Einstellungen → Sicherheit).</li>
        </ul>
      </Info>
    </h2>
    <button class="btn primary sm" onclick={() => edit()} disabled={!d.networks.length}><Icon name="plus" size={15} /> Freigabe anlegen</button>
  </div>
  {#if !loaded}
    <div class="empty small">Lade …</div>
  {:else if !d.networks.length}
    <div class="empty small">Noch kein aktiver WireGuard-Server – Netze entstehen aus WireGuard-Servern.</div>
  {:else}
    <div class="nets">
      {#each d.networks as n (n.id)}
        <div class="net">
          <div class="row" style="gap:8px">
            <ProtoLogo id="wireguard" size={18} />
            <span class="strong">{n.name}</span>
            <span class="muted tiny">{n.iface}</span>
            <span class="grow"></span>
            <button class="btn sm ghost icon" title="Freigabe für dieses Netz anlegen" onclick={() => edit(null, n.id)}><Icon name="plus" size={14} /></button>
          </div>
          <div class="tiny mono">{n.nets.slice(0, 4).join(', ')}{n.nets.length > 4 ? ` +${n.nets.length - 4}` : ''}</div>
          <div class="tiny muted">{n.devices} {n.devices === 1 ? 'Gerät' : 'Geräte'} · {grantsPerNet[n.id] || 0} {grantsPerNet[n.id] === 1 ? 'Freigabe' : 'Freigaben'}</div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<div class="card" style="margin-top:14px">
  <div class="card-head">
    <h2>Freigaben <span class="muted small">{d.grants.length}</span></h2>
    {#if d.grants.length > 5}<SearchInput bind:value={q} placeholder="Name, Netz, Nutzer, Gerät …" width="240px" />{/if}
  </div>
  {#if loaded && !d.grants.length}
    <div class="empty small">
      <Icon name="lock" size={18} />
      <p>Keine Freigaben – die Netze der Server sind voneinander getrennt.</p>
    </div>
  {:else}
    <div class="list">
      {#each shown as g (g.id)}
        <div class="item" class:off={!g.enabled}>
          <div class="grow">
            <div class="line">
              {#each whoParts(g).slice(0, 4) as p}
                <span class="chip">{#if p.proto}<ProtoLogo id={p.proto} size={13} />{:else}<Icon name={p.icon} size={13} />{/if} {p.text}</span>
              {/each}
              {#if whoParts(g).length > 4}<span class="muted small">+{whoParts(g).length - 4}</span>{/if}
              <Icon name="arrow-right" size={14} />
              {#each g.servers as s}<span class="chip net-chip"><Icon name="network" size={13} /> {netName(s)}</span>{/each}
            </div>
            <div class="tiny muted sub">
              <span>{g.name}</span>
              <span>· {g.reach.devices} {g.reach.devices === 1 ? 'Gerät' : 'Geräte'}{g.reach.users > 1 ? ` von ${g.reach.users} Nutzern` : ''}</span>
              {#if g.reach.names.length}
                <Info title="Betroffene Geräte" label="Geräte anzeigen">
                  <ul>{#each g.reach.names as n}<li>{n}</li>{/each}</ul>
                  {#if g.reach.devices > g.reach.names.length}<p>… und {g.reach.devices - g.reach.names.length} weitere.</p>{/if}
                </Info>
              {/if}
              {#if g.reach.other}
                <span class="warn-text"><Icon name="alert" size={12} /> {g.reach.other} weitere Zugänge (Hysteria2, Proxy)</span>
                <Info title="Andere Protokolle" text="Hysteria2 und Proxy können Nutzer nicht einzeln leiten. Freigaben gelten für WireGuard-, OpenVPN- und VLESS-Zugänge; für diese hier wirken sie nicht." />
              {/if}
              {#if g.note}<span>· {g.note}</span>{/if}
            </div>
          </div>
          <label class="switch" title={g.enabled ? 'Aktiv' : 'Aus'}><input type="checkbox" checked={g.enabled} onchange={() => toggle(g)} /><span class="track"></span></label>
          <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => edit(g)}><Icon name="edit" size={15} /></button>
          <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(g)}><Icon name="trash" size={15} /></button>
        </div>
      {:else}
        <div class="empty small">Keine Freigabe passt zur Suche.</div>
      {/each}
    </div>
  {/if}
</div>

<Modal bind:open title={f.id ? 'Freigabe bearbeiten' : 'Freigabe anlegen'} width={620}>
  <div class="stack">
    <div class="field">
      <span class="label">Netze <Info title="Netze" text="Diese WireGuard-Netze (Tunnelnetz und Netze hinter den Geräten) dürfen die unten gewählten Nutzer erreichen." /></span>
      <div class="netpick">
        {#each d.networks as n (n.id)}
          <button type="button" class="choice" class:active={f.servers.includes(n.id)} onclick={() => toggleNet(n.id)}>
            <span class="ic"><Icon name={f.servers.includes(n.id) ? 'check' : 'network'} size={16} /></span>
            <span><span class="strong">{n.name}</span><br /><span class="muted tiny mono">{n.nets.slice(0, 3).join(', ')}{n.nets.length > 3 ? ' …' : ''}</span></span>
          </button>
        {/each}
      </div>
    </div>
    <div class="field">
      <span class="label">Wer darf zugreifen?</span>
      <label class="switch"><input type="checkbox" bind:checked={f.all} /><span class="track"></span> Alle Nutzer</label>
      {#if !f.all}
        <Picker items={whoItems} keep={false} onpick={addWho} placeholder="Tarif, Nutzer oder Gerät suchen …" />
        <div class="chips">
          {#each f.plans as id}<span class="chip"><Icon name="tag" size={13} /> {planById[id]?.name || id}<button type="button" title="Entfernen" onclick={() => dropWho('plans', id)}><Icon name="x" size={12} /></button></span>{/each}
          {#each f.users as id}<span class="chip"><Icon name="user" size={13} /> {userById[id]?.name || id}<button type="button" title="Entfernen" onclick={() => dropWho('users', id)}><Icon name="x" size={12} /></button></span>{/each}
          {#each f.peers as id}
            {@const p = peerById[id]}
            <span class="chip"
              >{#if p}<ProtoLogo id={p.protocol} size={13} />{/if} {p ? `${userById[p.user_id]?.name || '?'} · ${p.name}` : id}<span class="muted tiny">{p ? PROTO_LABEL[p.protocol] : ''}</span><button
                type="button"
                title="Entfernen"
                onclick={() => dropWho('peers', id)}><Icon name="x" size={12} /></button
              ></span
            >
          {/each}
          {#if !f.plans.length && !f.users.length && !f.peers.length}<span class="muted small">Noch niemand gewählt.</span>{/if}
        </div>
      {/if}
    </div>
    <div class="grid cols-2">
      <div class="field">
        <label for="na-name">Name</label>
        <input id="na-name" class="input" bind:value={f.name} maxlength="48" placeholder="z. B. Anna → Homelab" />
      </div>
      <div class="field">
        <label for="na-note">Notiz</label>
        <input id="na-note" class="input" bind:value={f.note} maxlength="300" placeholder="optional" />
      </div>
    </div>
    <label class="switch"><input type="checkbox" bind:checked={f.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={busy || !valid}>Speichern</button>
  {/snippet}
</Modal>

<style>
  .nets {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 10px;
    padding: 4px 16px 16px;
  }
  .net {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px 10px 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .mono {
    font-family: var(--mono, ui-monospace, monospace);
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
  .item + .item {
    border-top: 1px solid var(--border);
  }
  .item.off .grow {
    opacity: 0.5;
  }
  .line {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .sub {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 4px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: 999px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    font-size: 13px;
  }
  .chip button {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    display: grid;
    place-items: center;
    padding: 0 0 0 2px;
  }
  .chip button:hover {
    color: var(--bad);
  }
  .net-chip {
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 35%, var(--border));
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
  }
  .netpick {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 8px;
  }
  .warn-text {
    color: var(--warn, #b7791f);
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
</style>
