<script>
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';
  import TrafficPanel from '../components/TrafficPanel.svelte';
  import LivePanel from '../components/LivePanel.svelte';
  import Usage from '../components/Usage.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import LimitsForm from '../components/LimitsForm.svelte';
  import ConfigView from '../components/ConfigView.svelte';
  import PeerEditor from '../components/PeerEditor.svelte';
  import QR from '../components/QR.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { bytes, ago, date, rate, isOnline, limitsSummary, toDateInput, fromDateInput, copy, PERIODS, clone } from '../lib/format.js';
  import { go, protocol, toast } from '../lib/state.svelte.js';

  let { id } = $props();
  let d = $state(null);
  let plans = $state([]);
  let servers = $state([]);
  let tab = $state('overview');
  let liveOn = $state(0);

  async function load() {
    [d, plans, servers] = await Promise.all([get(`/users/${id}`), get('/plans'), get('/servers')]);
    initForms();
  }
  load().catch((e) => toast(e.message, 'error'));


  const u = $derived(d?.user);
  const byServer = $derived.by(() => {
    const m = new Map();
    for (const p of d?.peers || []) {
      if (!m.has(p.server_id)) m.set(p.server_id, { name: p.server_name, protocol: p.protocol, peers: [] });
      m.get(p.server_id).peers.push(p);
    }
    return [...m.entries()];
  });

  // ---------- Formulare ----------
  let edit = $state({});
  let limMode = $state('none');
  let limPlan = $state(0);
  let lim = $state({});
  function initForms() {
    edit = { name: u.name, note: u.note, expires: toDateInput(u.expires_at), enabled: u.enabled };
    limMode = d.custom ? 'custom' : u.plan_id ? 'plan' : 'none';
    limPlan = u.plan_id || plans[0]?.id || 0;
    lim = d.custom ? clone($state.snapshot(u.limits)) : { traffic_gb: 0, period: 'monthly', reset_day: 1, on_limit: 'throttle', tiers: [] };
  }

  async function saveSettings() {
    const ok = await run(() => put(`/users/${id}`, { name: edit.name, note: edit.note, expires_at: fromDateInput(edit.expires), enabled: edit.enabled }), 'Gespeichert');
    if (ok) load();
  }
  async function saveLimits() {
    const body = limMode === 'custom' ? { custom: true, limits: $state.snapshot(lim) } : { custom: false, plan_id: limMode === 'plan' ? limPlan : 0 };
    const ok = await run(() => put(`/users/${id}`, body), 'Limits gespeichert');
    if (ok) load();
  }
  async function toggleEnabled() {
    const ok = await run(() => put(`/users/${id}`, { enabled: !u.enabled }), u.enabled ? 'Nutzer deaktiviert' : 'Nutzer aktiviert');
    if (ok) load();
  }
  async function remove() {
    if (!(await confirmDialog({ title: `${u.name} löschen?`, text: 'Alle Zugänge und die Statistik dieses Nutzers werden gelöscht. Verbundene Geräte verlieren sofort die Verbindung.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/users/${id}`), 'Nutzer gelöscht')) go('/users');
  }
  async function reset(what) {
    const text = what === 'all' ? 'Die gesamte Statistik (auch Gesamtverbrauch) wird auf 0 gesetzt.' : 'Der Verbrauch im aktuellen Zeitraum wird auf 0 gesetzt. Eine Drosselung oder Sperre wird damit aufgehoben.';
    if (!(await confirmDialog({ title: 'Verbrauch zurücksetzen?', text, ok: 'Zurücksetzen' }))) return;
    if (await run(() => post(`/users/${id}/reset`, { what }), 'Zurückgesetzt')) load();
  }
  async function newToken() {
    if (!(await confirmDialog({ title: 'Neuen Abo-Link erzeugen?', text: 'Der alte Link funktioniert danach nicht mehr. Die App muss den neuen Link importieren.', ok: 'Neu erzeugen', danger: true }))) return;
    if (await run(() => post(`/users/${id}/token`), 'Neuer Abo-Link erzeugt')) load();
  }

  // ---------- Zugänge ----------
  let editorOpen = $state(false);
  let editPeer = $state(null);
  let cfgPeer = $state(null);
  let cfgOpen = $state(false);
  function addPeer() {
    editPeer = null;
    editorOpen = true;
  }
  function editP(p) {
    editPeer = p;
    editorOpen = true;
  }
  function showCfg(p) {
    cfgPeer = p;
    cfgOpen = true;
  }
  async function togglePeer(p) {
    if (await run(() => put(`/peers/${p.id}`, { enabled: !p.enabled }))) load();
  }
  async function removePeer(p) {
    if (!(await confirmDialog({ title: `${p.name} löschen?`, text: 'Das Gerät verliert sofort die Verbindung. Die Konfiguration muss für eine neue Verbindung neu eingerichtet werden.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/peers/${p.id}`), 'Zugang gelöscht')) load();
  }
  async function regen(p) {
    if (!(await confirmDialog({ title: 'Neue Schlüssel erzeugen?', text: 'Die alte Konfiguration funktioniert danach nicht mehr – das Gerät muss neu eingerichtet werden.', ok: 'Neu erzeugen', danger: true }))) return;
    if (await run(() => put(`/peers/${p.id}`, { regenerate_keys: true }), 'Neue Schlüssel erzeugt')) load();
  }

  const kindIcon = { client: 'phone', server: 'server', site: 'network', access: 'key' };
  const kindLabel = (proto, kind) => protocol(proto)?.kinds?.find((k) => k.id === kind)?.label || kind;
</script>

{#if u}
  <a href="#/users" class="back small"><Icon name="back" size={15} /> Alle Nutzer</a>
  <div class="head">
    <span class="avatar" class:on={u.online}>{u.name.slice(0, 1).toUpperCase()}</span>
    <div class="grow">
      <div class="row wrap"><h1>{u.name}</h1><StatusBadge status={u.status} reason={u.status_reason} /></div>
      <div class="muted small">
        {u.plan_name && !d.custom ? `Tarif ${u.plan_name}` : d.custom ? 'Individuelle Limits' : 'Keine Limits'}
        · angelegt {date(u.created)}{u.expires_at ? ` · gültig bis ${date(u.expires_at)}` : ''}
        {#if u.status_reason}· <span class="strong">{u.status_reason}</span>{/if}
      </div>
    </div>
    <div class="row">
      <button class="btn" onclick={toggleEnabled}><Icon name="power" size={16} /> {u.enabled ? 'Deaktivieren' : 'Aktivieren'}</button>
      <button class="btn danger" onclick={remove}><Icon name="trash" size={16} /> Löschen</button>
    </div>
  </div>

  <div class="tabs">
    <button class:active={tab === 'overview'} onclick={() => (tab = 'overview')}><Icon name="activity" size={16} /> Übersicht</button>
    <button class:active={tab === 'peers'} onclick={() => (tab = 'peers')}><Icon name="phone" size={16} /> Zugänge <span class="badge">{d.peers.length}</span></button>
    <button class:active={tab === 'limits'} onclick={() => (tab = 'limits')}><Icon name="gauge" size={16} /> Limits</button>
    <button class:active={tab === 'sub'} onclick={() => (tab = 'sub')}><Icon name="link" size={16} /> Abo-Link</button>
    <button class:active={tab === 'settings'} onclick={() => (tab = 'settings')}><Icon name="settings" size={16} /> Einstellungen</button>
  </div>

  {#if tab === 'overview'}
    <div class="grid cols-4">
      <div class="card card-pad">
        <div class="muted small">Verbrauch {PERIODS[u.effective?.period] || 'gesamt'}</div>
        <div style="margin-top:6px"><Usage used={u.period_up + u.period_down} limitGb={u.effective?.traffic_gb || 0} tiers={u.effective?.tiers || []} /></div>
        {#if u.next_reset}<div class="muted tiny" style="margin-top:6px">Zurücksetzung am {date(u.next_reset)}</div>{/if}
      </div>
      <div class="card card-pad">
        <div class="muted small">Aktuelles Tempo</div>
        <div class="big">{u.rate_down || u.rate_up ? rate(u.rate_down) : 'frei'}</div>
        <div class="muted tiny">{u.rate_up ? `Upload ${rate(u.rate_up)}` : 'ohne Begrenzung'}</div>
      </div>
      <div class="card card-pad">
        <div class="muted small">Gesamt seit Beginn</div>
        <div class="big">{bytes(u.total_up + u.total_down)}</div>
        <div class="muted tiny">↓ {bytes(u.total_down)} · ↑ {bytes(u.total_up)}</div>
      </div>
      <div class="card card-pad">
        <div class="muted small">Zuletzt da</div>
        <div class="big row"><span class="dot" class:on={liveOn > 0 || isOnline(u.last_seen)}></span>{liveOn > 0 ? 'online' : ago(u.last_seen)}</div>
        <div class="muted tiny">{u.devices} Zugänge</div>
      </div>
    </div>
    <div style="margin-top:16px"><LivePanel user={id} compact bind:connected={liveOn} /></div>
    <div style="margin-top:16px"><TrafficPanel url={`/users/${id}/traffic`} /></div>
  {:else if tab === 'peers'}
    <div class="spread" style="margin-bottom:12px">
      <div class="muted small">Jeder Zugang ist ein Gerät (WireGuard) bzw. eine Kennung (VLESS, Hysteria2). Limits gelten für den Nutzer.</div>
      <button class="btn primary" onclick={addPeer}><Icon name="plus" size={16} /> Zugang hinzufügen</button>
    </div>
    <div class="stack">
      {#each byServer as [sid, g]}
        <div class="card">
          <div class="card-head">
            <h3><span class="badge">{protocol(g.protocol)?.label || g.protocol}</span> {g.name}</h3>
            {#if g.protocol === 'wireguard'}<a class="small" href="#/network/{sid}">Netzwerk ansehen</a>{/if}
          </div>
          <div class="table-wrap">
            <table class="table">
              <tbody>
                {#each g.peers as p}
                  <tr>
                    <td style="width:44px"><span class="pill-icon"><Icon name={kindIcon[p.kind] || 'key'} size={16} /></span></td>
                    <td>
                      <div class="strong">{p.name} {#if !p.enabled}<span class="badge muted">aus</span>{/if}{#if p.enabled && !p.active}<span class="badge bad">gesperrt</span>{/if}</div>
                      <div class="muted tiny">{kindLabel(p.protocol, p.kind)}{p.settings?.address4 ? ` · ${p.settings.address4}` : ''}{p.settings?.routes?.length ? ` · Netze: ${p.settings.routes.join(', ')}` : ''}</div>
                    </td>
                    <td class="small nowrap">↓ {bytes(p.total_down)} · ↑ {bytes(p.total_up)}</td>
                    <td class="small nowrap"><span class="row"><span class="dot" class:on={p.online}></span>{ago(p.last_seen)}</span>{#if p.endpoint}<div class="muted tiny mono">{p.endpoint}</div>{/if}</td>
                    <td class="right nowrap">
                      <button class="btn sm" onclick={() => showCfg(p)}><Icon name="qr" size={15} /> Konfiguration</button>
                      <button class="btn sm icon" title="Bearbeiten" onclick={() => editP(p)}><Icon name="edit" size={15} /></button>
                      <button class="btn sm icon" title={p.enabled ? 'Deaktivieren' : 'Aktivieren'} onclick={() => togglePeer(p)}><Icon name="power" size={15} /></button>
                      <button class="btn sm icon" title="Neue Schlüssel" onclick={() => regen(p)}><Icon name="refresh" size={15} /></button>
                      <button class="btn sm icon danger" title="Löschen" onclick={() => removePeer(p)}><Icon name="trash" size={15} /></button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      {:else}
        <div class="card empty"><h3>Keine Zugänge</h3><p>Füge ein Gerät oder einen VLESS-Zugang hinzu.</p></div>
      {/each}
    </div>
  {:else if tab === 'limits'}
    <div class="card card-pad" style="max-width:820px">
      <div class="stack">
        <div class="segmented">
          <button class:active={limMode === 'none'} onclick={() => (limMode = 'none')}>Keine Limits</button>
          <button class:active={limMode === 'plan'} onclick={() => (limMode = 'plan')} disabled={!plans.length}>Tarif</button>
          <button class:active={limMode === 'custom'} onclick={() => (limMode = 'custom')}>Individuell</button>
        </div>
        {#if limMode === 'plan'}
          <div class="stack-sm">
            {#each plans as p}
              <button class="choice" class:active={limPlan === p.id} onclick={() => (limPlan = p.id)}>
                <span class="ic"><Icon name="tag" /></span>
                <span><span class="strong">{p.name}</span><br /><span class="muted small">{limitsSummary(p.limits)}</span></span>
              </button>
            {/each}
          </div>
        {:else if limMode === 'custom'}
          <LimitsForm bind:value={lim} />
        {:else}
          <div class="muted">Unbegrenztes Volumen und Tempo.</div>
        {/if}
        <div class="row wrap">
          <button class="btn primary" onclick={saveLimits}>Limits speichern</button>
          <span class="grow"></span>
          <button class="btn" onclick={() => reset('period')}><Icon name="refresh" size={15} /> Verbrauch im Zeitraum zurücksetzen</button>
          <button class="btn danger" onclick={() => reset('all')}>Gesamte Statistik zurücksetzen</button>
        </div>
      </div>
    </div>
  {:else if tab === 'sub'}
    <div class="card card-pad sub" style="max-width:820px">
      <QR text={d.sub_url} size={220} />
      <div class="stack grow">
        <div>
          <h2>Abo-Link</h2>
          <p class="muted small">Enthält alle VLESS-Zugänge dieses Nutzers. In v2RayTun (Android), Streisand oder V2Box (iOS) als Abonnement importieren – die App aktualisiert sich automatisch und zeigt Verbrauch, Limit und Ablaufdatum an.</p>
        </div>
        <div class="input-group">
          <input class="input mono" readonly value={d.sub_url} />
          <button class="btn" style="border-radius:0 8px 8px 0" onclick={() => copy(d.sub_url).then(() => toast('Kopiert'))}><Icon name="copy" size={15} /></button>
        </div>
        <div class="row"><button class="btn danger" onclick={newToken}><Icon name="refresh" size={15} /> Neuen Link erzeugen</button></div>
        <div class="help">WireGuard-Geräte haben keinen Abo-Link – ihre Konfiguration findest du unter „Zugänge“.</div>
      </div>
    </div>
  {:else if tab === 'settings'}
    <div class="card card-pad" style="max-width:640px">
      <div class="stack">
        <div class="field"><label for="ue-name">Name</label><input id="ue-name" class="input" bind:value={edit.name} /></div>
        <div class="field"><label for="ue-note">Notiz</label><textarea id="ue-note" class="input" bind:value={edit.note}></textarea></div>
        <div class="field">
          <label for="ue-exp">Gültig bis</label>
          <div class="row"><input id="ue-exp" class="input" type="date" bind:value={edit.expires} style="max-width:220px" />{#if edit.expires}<button class="btn sm" onclick={() => (edit.expires = '')}>Unbegrenzt</button>{/if}</div>
          <div class="help">Nach Ablauf werden alle Zugänge gesperrt.</div>
        </div>
        <label class="switch"><input type="checkbox" bind:checked={edit.enabled} /><span class="track"></span> Nutzer aktiv</label>
        <div><button class="btn primary" onclick={saveSettings}>Speichern</button></div>
      </div>
    </div>
  {/if}

  <PeerEditor bind:open={editorOpen} peer={editPeer} userId={id} {servers} onsaved={load} />
  <Modal bind:open={cfgOpen} title={cfgPeer ? `${cfgPeer.name} – Konfiguration` : ''} subtitle={cfgPeer?.server_name} width={680}>
    {#if cfgPeer && cfgOpen}<ConfigView peerId={cfgPeer.id} />{/if}
  </Modal>
{/if}

<style>
  .back {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    margin-bottom: 12px;
    color: var(--muted);
  }
  .back:hover {
    color: var(--accent);
  }
  .head {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }
  .avatar {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 700;
    font-size: 20px;
    position: relative;
  }
  .avatar.on::after {
    content: '';
    position: absolute;
    right: 0;
    bottom: 0;
    width: 13px;
    height: 13px;
    border-radius: 50%;
    background: var(--ok);
    border: 2px solid var(--bg);
  }
  .big {
    font-size: 20px;
    font-weight: 700;
    margin: 4px 0 2px;
  }
  .sub {
    display: flex;
    gap: 24px;
    align-items: flex-start;
    flex-wrap: wrap;
  }
</style>
