<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import Modal from '../components/Modal.svelte';
  import Info from '../components/Info.svelte';
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
  import { bytes, ago, date, rate, duration, isOnline, onlineFor, sinceClock, limitsSummary, toDateInput, fromDateInput, copy, PERIODS, clone } from '../lib/format.js';
  import { go, protocol, toast } from '../lib/state.svelte.js';

  let { id, tab: tabParam = 'overview' } = $props();
  let d = $state(null);
  let plans = $state([]);
  let servers = $state([]);
  // Tab steht in der Adresse (#/users/<id>/<tab>) – Neuladen bleibt auf der Ansicht
  const TABS = ['overview', 'peers', 'limits', 'sub', 'settings'];
  const tab = $derived(TABS.includes(tabParam) ? tabParam : 'overview');
  const setTab = (t) => go(t === 'overview' ? `/users/${id}` : `/users/${id}/${t}`);
  let liveOn = $state(0);
  let now = $state(Date.now() / 1000);
  $effect(() => {
    const t = setInterval(() => (now = Date.now() / 1000), 15000);
    return () => clearInterval(t);
  });

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

  // Was steckt im Abo? (aktive VLESS-/Hysteria2-Zugänge und WireGuard-Geräte „Handy / Laptop“)
  const subSummary = $derived.by(() => {
    const n = {};
    for (const p of d?.peers || []) {
      if (!p.enabled || !p.active || p.protocol === 'openvpn' || (p.protocol === 'wireguard' && p.kind !== 'client')) continue;
      n[p.protocol] = (n[p.protocol] || 0) + 1;
    }
    return Object.entries(n).map(([k, c]) => `${c}× ${protocol(k)?.label || k}`).join(' · ');
  });

  // sing-box-Profil: Hysteria2 + WireGuard „Handy / Laptop“ mit vollem Tunnel (kein VLESS)
  const sbSummary = $derived.by(() => {
    const n = {};
    for (const p of d?.peers || []) {
      if (!p.enabled || !p.active) continue;
      if (p.protocol === 'hysteria2' || (p.protocol === 'wireguard' && p.kind === 'client' && (p.settings?.tunnel || 'full') === 'full')) n[p.protocol] = (n[p.protocol] || 0) + 1;
    }
    return Object.entries(n).map(([k, c]) => `${c}× ${protocol(k)?.label || k}`).join(' · ');
  });
  let sideQR = $state('sub');
  const sideText = $derived(sideQR === 'singbox' && d?.singbox_url ? d.singbox_url : d?.sub_url);

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
    <button class:active={tab === 'overview'} onclick={() => setTab('overview')}><Icon name="activity" size={16} /> Übersicht</button>
    <button class:active={tab === 'peers'} onclick={() => setTab('peers')}><Icon name="phone" size={16} /> Zugänge <span class="badge">{d.peers.length}</span></button>
    <button class:active={tab === 'limits'} onclick={() => setTab('limits')}><Icon name="gauge" size={16} /> Limits</button>
    <button class:active={tab === 'sub'} onclick={() => setTab('sub')}><Icon name="link" size={16} /> Abo-Link</button>
    <button class:active={tab === 'settings'} onclick={() => setTab('settings')}><Icon name="settings" size={16} /> Einstellungen</button>
  </div>

  {#if tab === 'overview'}
   <div class="ud">
   <div class="ud-main">
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
        <div class="muted small">{liveOn > 0 || u.online ? 'Online' : 'Zuletzt da'}</div>
        <div class="big row"><span class="dot" class:on={liveOn > 0 || u.online || isOnline(u.last_seen)}></span>{liveOn > 0 || u.online ? (u.online_since ? duration(now - u.online_since) : 'online') : ago(u.last_seen)}</div>
        <div class="muted tiny">{(liveOn > 0 || u.online) && u.online_since ? `${sinceClock(u.online_since)} · ` : ''}{u.devices} Zugänge</div>
      </div>
    </div>
    <div style="margin-top:16px"><LivePanel user={id} compact bind:connected={liveOn} /></div>
    <div style="margin-top:16px"><TrafficPanel url={`/users/${id}/traffic`} /></div>
   </div>
   <aside class="ud-side">
    <div class="card">
      <div class="card-head"><h3>Abo-Link</h3><button class="btn sm ghost" onclick={() => setTab('sub')}>Mehr</button></div>
      <div class="card-pad stack-sm side-sub">
        {#if sbSummary && d.singbox_url}
          <div class="segmented sm">
            <button class:active={sideQR === 'sub'} onclick={() => (sideQR = 'sub')}>Abo</button>
            <button class:active={sideQR === 'singbox'} onclick={() => (sideQR = 'singbox')}>sing-box-App</button>
          </div>
        {/if}
        <QR text={sideText} size={168} />
        <div class="muted tiny" style="text-align:center">
          {#if sideQR === 'singbox'}In der sing-box-App scannen · {sbSummary}{:else}{subSummary || 'Noch keine Zugänge im Abo'}{/if}
        </div>
        <div class="row">
          <button class="btn sm grow" onclick={() => copy(sideText).then(() => toast(sideQR === 'singbox' ? 'sing-box-Import-Link kopiert' : 'Abo-Link kopiert'))}><Icon name="copy" size={15} /> Kopieren</button>
          <button class="btn sm danger" title="Neuen Abo-Link erzeugen (alter Link wird ungültig)" onclick={newToken}><Icon name="refresh" size={15} /> Neu</button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h3>Zugänge</h3><button class="btn sm ghost" onclick={() => setTab('peers')}>Verwalten</button></div>
      <div class="side-list">
        {#each d.peers as p}
          <button class="side-peer" onclick={() => showCfg(p)} title="Konfiguration anzeigen">
            <ProtoLogo id={p.protocol} size={22} />
            <div class="grow" style="min-width:0">
              <div class="strong ellipsis">{p.name}</div>
              <div class="muted tiny ellipsis">{p.server_name}{p.settings?.address4 ? ` · ${p.settings.address4}` : ''}</div>
            </div>
            {#if !p.enabled}<span class="badge muted">aus</span>{:else if !p.active}<span class="badge bad">gesperrt</span>{:else}<span class="dot" class:on={p.online} title={p.online ? onlineFor(p.online_since, now) : ago(p.last_seen)}></span>{/if}
            <Icon name="qr" size={15} />
          </button>
        {:else}
          <div class="empty small">Keine Zugänge</div>
        {/each}
      </div>
    </div>
    <div class="card card-pad">
      <dl class="kv">
        <dt>Limits</dt><dd>{d.custom ? 'Individuell' : u.plan_name ? `Tarif ${u.plan_name}` : 'keine'}</dd>
        {#if u.effective}<dt></dt><dd class="muted small">{limitsSummary(u.effective)}</dd>{/if}
        <dt>Gültig bis</dt><dd>{u.expires_at ? date(u.expires_at) : 'unbegrenzt'}</dd>
        {#if u.next_reset}<dt>Zurücksetzung</dt><dd>{date(u.next_reset)}</dd>{/if}
        <dt>Angelegt</dt><dd>{date(u.created)}</dd>
        {#if u.note}<dt>Notiz</dt><dd style="white-space:pre-wrap">{u.note}</dd>{/if}
      </dl>
    </div>
   </aside>
   </div>
  {:else if tab === 'peers'}
    <div class="spread" style="margin-bottom:12px">
      <div class="muted small">Jeder Zugang ist ein Gerät (WireGuard) bzw. eine Kennung (VLESS, Hysteria2). Limits gelten für den Nutzer.</div>
      <button class="btn primary" onclick={addPeer}><Icon name="plus" size={16} /> Zugang hinzufügen</button>
    </div>
    <div class="stack">
      {#each byServer as [sid, g]}
        <div class="card">
          <div class="card-head">
            <h3 class="row" style="gap:8px"><ProtoLogo id={g.protocol} size={24} /> {g.name} <span class="muted small" style="font-weight:400">{protocol(g.protocol)?.label || g.protocol}</span></h3>
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
                    <td class="small nowrap" title={p.online && p.online_since ? sinceClock(p.online_since) : ''}><span class="row"><span class="dot" class:on={p.online}></span>{p.online ? onlineFor(p.online_since, now) : ago(p.last_seen)}</span>{#if p.endpoint}<div class="muted tiny mono">{p.endpoint}</div>{/if}</td>
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
          <h2>Abo-Link <Info title="Abo-Link" wide>
            <p>Enthält alle aktiven Zugänge dieses Nutzers: VLESS, Hysteria2 und WireGuard-Geräte „Handy / Laptop“.</p>
            <p>In Hiddify, v2rayNG, v2RayTun (Android), Streisand oder V2Box (iOS) als Abonnement importieren – die App aktualisiert sich automatisch und zeigt Verbrauch, Limit und Ablaufdatum an.</p>
            <p>Hiddify (sing-box) kann VLESS mit aktuellem Xray nicht nutzen – dort Hysteria2 oder WireGuard wählen. OpenVPN steht nicht im Abo – jedes OpenVPN-Profil wird einzeln unter „Zugänge“ → „Konfiguration“ eingerichtet.</p>
            <p><b>Link bekannt geworden?</b> „Neuen Link erzeugen“: Der alte Link (auch die OpenVPN-Profil-Links) funktioniert dann sofort nicht mehr – die Zugänge selbst bleiben gültig. Sollen auch die Geräte nicht mehr verbinden können, unter „Zugänge“ neue Schlüssel erzeugen.</p>
          </Info></h2>
          {#if subSummary}<div class="muted small">Enthält {subSummary}</div>{/if}
        </div>
        <div class="input-group">
          <input class="input mono" readonly value={d.sub_url} />
          <button class="btn" style="border-radius:0 8px 8px 0" onclick={() => copy(d.sub_url).then(() => toast('Kopiert'))}><Icon name="copy" size={15} /></button>
        </div>
        <div class="row"><button class="btn danger" onclick={newToken}><Icon name="refresh" size={15} /> Neuen Link erzeugen</button></div>
        {#if d.singbox_url}
          <div class="sb-box">
            {#if sbSummary}<QR text={d.singbox_url} size={150} />{/if}
            <div class="stack-sm grow">
              <span class="strong">Offizielle sing-box-App <Info title="sing-box" text="Die sing-box-App liest keine Abo-Links, sondern ein fertiges Profil. Den QR-Code in der App scannen (Profile → „+“ → QR-Code) – das Profil aktualisiert sich dann selbst. Nötig sind Hysteria2 oder WireGuard „Handy / Laptop“ mit vollem Tunnel. VLESS fehlt bewusst: Xray ab 26.9.9 lehnt sing-box (auch Hiddify) ab." /></span>
              <span class="muted small">{#if sbSummary}Enthält {sbSummary}, automatische Wahl des schnellsten Servers.{:else}<strong>Keine passenden Zugänge</strong>{/if}</span>
              {#if sbSummary}<div><button class="btn sm" onclick={() => copy(d.singbox_url).then(() => toast('Kopiert'))}><Icon name="copy" size={15} /> Import-Link kopieren</button></div>{/if}
            </div>
          </div>
        {/if}
      </div>
    </div>
  {:else if tab === 'settings'}
    <div class="card card-pad" style="max-width:640px">
      <div class="stack">
        <div class="field"><label for="ue-name">Name</label><input id="ue-name" class="input" bind:value={edit.name} /></div>
        <div class="field"><label for="ue-note">Notiz</label><textarea id="ue-note" class="input" bind:value={edit.note}></textarea></div>
        <div class="field">
          <label for="ue-exp">Gültig bis <Info title="Gültig bis" text="Leer = unbegrenzt. Nach Ablauf werden alle Zugänge gesperrt." /></label>
          <div class="row"><input id="ue-exp" class="input" type="date" bind:value={edit.expires} style="max-width:220px" />{#if edit.expires}<button class="btn sm" onclick={() => (edit.expires = '')}>Unbegrenzt</button>{/if}</div>
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
  .sb-box {
    display: flex;
    gap: 16px;
    align-items: flex-start;
    flex-wrap: wrap;
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--panel-2);
  }
  .segmented.sm button {
    font-size: 12px;
    padding: 4px 10px;
  }
  .ud {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    gap: 16px;
    align-items: start;
  }
  .ud-side {
    display: flex;
    flex-direction: column;
    gap: 16px;
    position: sticky;
    top: 16px;
  }
  .side-sub {
    align-items: center;
  }
  .side-sub .row {
    width: 100%;
  }
  .side-list {
    padding: 6px;
    display: flex;
    flex-direction: column;
  }
  .side-peer {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 8px;
    width: 100%;
    text-align: left;
    background: none;
    border: 0;
    font: inherit;
    color: inherit;
    cursor: pointer;
  }
  .side-peer:hover {
    background: var(--panel-2);
  }
  @media (max-width: 1320px) {
    .ud {
      grid-template-columns: minmax(0, 1fr);
    }
    .ud-side {
      position: static;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      align-items: start;
    }
  }
  .sub {
    display: flex;
    gap: 24px;
    align-items: flex-start;
    flex-wrap: wrap;
  }
</style>
