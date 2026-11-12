<script>
  import Icon from '../components/Icon.svelte';
  import ProtoLogo from '../components/ProtoLogo.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import Info from '../components/Info.svelte';
  import Usage from '../components/Usage.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import LimitsForm from '../components/LimitsForm.svelte';
  import { get, post, run } from '../lib/api.js';
  import { ago, isOnline, onlineFor, sinceClock, rate, fromDateInput, limitsSummary, PROTO_LABEL } from '../lib/format.js';
  import { tokens, matches } from '../lib/pick.js';
  // Uhr für die Online-Dauer
  let now = $state(Date.now() / 1000);
  $effect(() => {
    const t = setInterval(() => (now = Date.now() / 1000), 15000);
    return () => clearInterval(t);
  });
  import { go, protocol, toast } from '../lib/state.svelte.js';

  let users = $state([]);
  let plans = $state([]);
  let servers = $state([]);
  let loaded = $state(false);
  let q = $state('');
  let filter = $state('all');
  let sort = $state('name');

  async function load() {
    [users, plans, servers] = await Promise.all([get('/users'), get('/plans'), get('/servers')]);
    loaded = true;
  }
  load();

  const filters = [
    { id: 'all', label: 'Alle' },
    { id: 'online', label: 'Online' },
    { id: 'ok', label: 'Aktiv' },
    { id: 'throttled', label: 'Gedrosselt' },
    { id: 'blocked', label: 'Gesperrt/Abgelaufen' },
    { id: 'disabled', label: 'Deaktiviert' },
  ];
  const shown = $derived.by(() => {
    const t = tokens(q);
    let list = users.filter((u) => {
      if (t.length && !matches(`${u.name} ${u.note || ''} ${u.plan_name || ''} ${u.find || ''} ${(u.protocols || []).map((p) => PROTO_LABEL[p] || p).join(' ')}`, t)) return false;
      if (filter === 'online') return u.online;
      if (filter === 'blocked') return u.status === 'blocked' || u.status === 'expired';
      if (filter !== 'all') return u.status === filter;
      return true;
    });
    const key = {
      name: (u) => u.name.toLowerCase(),
      usage: (u) => -(u.period_up + u.period_down),
      seen: (u) => -(u.last_seen || 0),
    }[sort];
    return [...list].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
  });
  const count = (id) => (id === 'all' ? users.length : users.filter((u) => (id === 'online' ? u.online : id === 'blocked' ? u.status === 'blocked' || u.status === 'expired' : u.status === id)).length);

  // ---------- Anlegen ----------
  let createOpen = $state(false);
  let nu = $state({});
  let nuLimits = $state({});
  function openCreate() {
    nu = { name: '', note: '', mode: plans.length ? 'plan' : 'none', plan_id: plans[0]?.id || 0, expires: '', access: {} };
    for (const s of servers) if (s.enabled) nu.access[s.id] = { on: true, kind: protocol(s.protocol)?.kinds?.[0]?.id || '', name: '' };
    nuLimits = { traffic_gb: 0, period: 'monthly', reset_day: 1, on_limit: 'throttle', tiers: [] };
    createOpen = true;
  }
  async function create() {
    const accesses = Object.entries(nu.access)
      .filter(([, a]) => a.on)
      .map(([id, a]) => ({ server_id: Number(id), kind: a.kind, name: a.name || defaultDevName(Number(id), a.kind) }));
    const body = {
      name: nu.name,
      note: nu.note,
      custom: nu.mode === 'custom',
      plan_id: nu.mode === 'plan' ? nu.plan_id : 0,
      limits: nu.mode === 'custom' ? $state.snapshot(nuLimits) : null,
      expires_at: fromDateInput(nu.expires),
      accesses,
    };
    const r = await run(() => post('/users', body));
    if (r) {
      if (r.errors?.length) r.errors.forEach((e) => toast(e, 'error'));
      createOpen = false;
      go(`/users/${r.id}`);
    }
  }
  function defaultDevName(sid, kind) {
    const s = servers.find((x) => x.id === sid);
    if (s?.protocol === 'wireguard') return kind === 'site' ? 'Netzwerk' : kind === 'server' ? 'Server' : 'Handy';
    return nu.name;
  }
</script>

<PageHead title="Nutzer" subtitle="{users.length} Nutzer · {users.filter((u) => u.online).length} online">
  <button class="btn primary" onclick={openCreate}><Icon name="plus" size={16} /> Nutzer anlegen</button>
</PageHead>

<div class="card">
  <div class="toolbar">
    <div class="search">
      <Icon name="search" size={16} />
      <input class="input" placeholder="Name, Gerät, Dienst, Server, Adresse, Tarif …" bind:value={q} />
    </div>
    <div class="row wrap">
      {#each filters as f}
        <button class="chip" class:active={filter === f.id} onclick={() => (filter = f.id)}>{f.label} <span class="muted">{count(f.id)}</span></button>
      {/each}
    </div>
    <select class="input sort" bind:value={sort} aria-label="Sortierung">
      <option value="name">Name</option>
      <option value="usage">Verbrauch</option>
      <option value="seen">Zuletzt da</option>
    </select>
  </div>
  <div class="table-wrap">
    <table class="table">
      <thead>
        <tr><th>Nutzer</th><th>Status</th><th>Tarif / Limits</th><th>Verbrauch (Zeitraum)</th><th>Tempo</th><th>Zugänge</th><th>Zuletzt da</th></tr>
      </thead>
      <tbody>
        {#each shown as u (u.id)}
          <tr class="click" onclick={() => go(`/users/${u.id}`)}>
            <td>
              <div class="row">
                <span class="avatar" class:on={u.online}>{u.name.slice(0, 1).toUpperCase()}</span>
                <div>
                  <div class="strong">{u.name}</div>
                  {#if u.note}<div class="muted tiny ellipsis" style="max-width:220px">{u.note}</div>{/if}
                </div>
              </div>
            </td>
            <td><StatusBadge status={u.status} reason={u.status_reason} /></td>
            <td>
              {#if u.plan_name && !u.limits}<span class="badge accent">{u.plan_name}</span>
              {:else if u.limits}<span class="badge">Individuell</span>
              {:else}<span class="muted small">keine</span>{/if}
            </td>
            <td style="min-width:170px"><Usage used={u.period_up + u.period_down} limitGb={u.effective?.traffic_gb || 0} tiers={u.effective?.tiers || []} compact /></td>
            <td class="small nowrap">
              {#if u.status === "blocked" || u.status === "expired" || u.status === "disabled"}<span class="muted">–</span>{:else if u.rate_down || u.rate_up}<span class:warn-text={u.status === "throttled"}>↓ {rate(u.rate_down)}</span>{:else}<span class="muted">frei</span>{/if}
            </td>
            <td>
              <div class="row">
                {#each u.protocols || [] as p}<ProtoLogo id={p} size={20} />{/each}
                <span class="muted small">{u.devices}</span>
              </div>
            </td>
            <td class="small nowrap" title={u.online && u.online_since ? sinceClock(u.online_since) : ''}><span class="row"><span class="dot" class:on={u.online || isOnline(u.last_seen)}></span>{u.online ? onlineFor(u.online_since, now) : ago(u.last_seen)}</span></td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if loaded && !shown.length}
      <div class="empty">
        {#if users.length}<h3>Keine Treffer</h3>Filter oder Suche anpassen.
        {:else}<h3>Noch keine Nutzer</h3><p>Lege den ersten Nutzer an – Zugänge für alle Server werden automatisch erstellt.</p><button class="btn primary" onclick={openCreate}><Icon name="plus" size={16} /> Nutzer anlegen</button>{/if}
      </div>
    {/if}
  </div>
</div>

<Modal bind:open={createOpen} title="Nutzer anlegen" width={660}>
  <div class="stack">
    <div class="grid cols-2">
      <div class="field">
        <label for="nu-name">Name</label>
        <input id="nu-name" class="input" bind:value={nu.name} placeholder="z. B. anna (a–z, 0–9, _ - .)" maxlength="32" />
      </div>
      <div class="field">
        <label for="nu-exp">Gültig bis <Info title="Gültig bis" text="Leer = unbegrenzt. Nach Ablauf werden alle Zugänge gesperrt." /></label>
        <input id="nu-exp" class="input" type="date" bind:value={nu.expires} title="Leer = unbegrenzt" />
      </div>
    </div>
    <div class="field">
      <label for="nu-note">Notiz</label>
      <input id="nu-note" class="input" bind:value={nu.note} placeholder="optional" />
    </div>

    <div class="field">
      <span class="label">Limits</span>
      <div class="segmented">
        <button class:active={nu.mode === 'none'} onclick={() => (nu.mode = 'none')}>Keine</button>
        <button class:active={nu.mode === 'plan'} onclick={() => (nu.mode = 'plan')} disabled={!plans.length}>Tarif</button>
        <button class:active={nu.mode === 'custom'} onclick={() => (nu.mode = 'custom')}>Individuell</button>
      </div>
      {#if nu.mode === 'plan'}
        <select class="input" bind:value={nu.plan_id} style="margin-top:8px">
          {#each plans as p}<option value={p.id}>{p.name} – {limitsSummary(p.limits)}</option>{/each}
        </select>
      {:else if nu.mode === 'custom'}
        <div style="margin-top:10px"><LimitsForm bind:value={nuLimits} /></div>
      {/if}
    </div>

    <div class="field">
      <span class="label">Zugänge automatisch anlegen <Info title="Zugänge" text="Für jeden gewählten Server wird ein Zugang angelegt. Weitere Geräte (z. B. Homelab-Netz) kannst du danach beim Nutzer hinzufügen." /></span>
      {#each servers as s}
        {#if nu.access?.[s.id]}
          {@const p = protocol(s.protocol)}
          <div class="acc">
            <label class="switch"><input type="checkbox" bind:checked={nu.access[s.id].on} /><span class="track"></span></label>
            <div class="grow">
              <div class="strong">{s.name}</div>
              <div class="muted tiny">{p?.label}</div>
            </div>
            {#if nu.access[s.id].on && p?.kinds?.length > 1}
              <select class="input" style="width:auto" bind:value={nu.access[s.id].kind}>
                {#each p.kinds as k}<option value={k.id}>{k.label}</option>{/each}
              </select>
              <input class="input" style="width:140px" placeholder={defaultDevName(s.id, nu.access[s.id].kind)} bind:value={nu.access[s.id].name} />
            {/if}
          </div>
        {/if}
      {:else}
        <div class="muted small">Noch keine Server angelegt.</div>
      {/each}
    </div>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (createOpen = false)}>Abbrechen</button>
    <button class="btn primary" onclick={create} disabled={!nu.name}>Anlegen</button>
  {/snippet}
</Modal>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .search {
    position: relative;
    flex: 1;
    min-width: 220px;
    max-width: 360px;
  }
  .search :global(svg) {
    position: absolute;
    left: 11px;
    top: 10px;
    color: var(--muted);
  }
  .search .input {
    padding-left: 34px;
  }
  .sort {
    width: auto;
    margin-left: auto;
  }
  .chip {
    border: 1px solid var(--border);
    background: var(--panel);
    border-radius: 20px;
    padding: 4px 11px;
    font: inherit;
    font-size: 12.5px;
    font-weight: 550;
    color: var(--text-2);
    cursor: pointer;
  }
  .chip.active {
    background: var(--accent-soft);
    border-color: var(--accent);
    color: var(--accent);
  }
  .avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background: var(--panel-2);
    border: 1px solid var(--border);
    font-weight: 650;
    color: var(--text-2);
    position: relative;
    flex: none;
  }
  .avatar.on::after {
    content: '';
    position: absolute;
    right: -1px;
    bottom: -1px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--ok);
    border: 2px solid var(--panel);
  }
  .warn-text {
    color: var(--warn);
    font-weight: 600;
  }
  .acc {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
  }
</style>
