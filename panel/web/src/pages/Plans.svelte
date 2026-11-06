<script>
  import Icon from '../components/Icon.svelte';
  import PageHead from '../components/PageHead.svelte';
  import Modal from '../components/Modal.svelte';
  import LimitsForm from '../components/LimitsForm.svelte';
  import { confirmDialog } from '../components/Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { rate, PERIODS, fmtNum, clone } from '../lib/format.js';

  let plans = $state([]);
  let loaded = $state(false);
  async function load() {
    plans = await get('/plans');
    loaded = true;
  }
  load();

  let open = $state(false);
  let cur = $state(null);
  let form = $state({});

  const presets = [
    { name: 'Unbegrenzt', description: 'Keine Limits', limits: { traffic_gb: 0, period: 'monthly', reset_day: 1, on_limit: 'block', tiers: [] } },
    { name: 'Standard', description: '100 GB/Monat, danach gedrosselt', limits: { traffic_gb: 100, period: 'monthly', reset_day: 1, on_limit: 'throttle', limit_down_mbit: 5, limit_up_mbit: 2, tiers: [{ after_gb: 70, down_mbit: 30, up_mbit: 10 }] } },
    { name: 'Gast', description: '10 GB, danach gesperrt', limits: { traffic_gb: 10, period: 'monthly', reset_day: 1, on_limit: 'block', speed_down_mbit: 25, speed_up_mbit: 10, max_devices: 2, tiers: [] } },
  ];

  function openNew(preset = presets[1]) {
    cur = null;
    form = clone(preset);
    open = true;
  }
  function openEdit(p) {
    cur = p;
    form = clone($state.snapshot({ name: p.name, description: p.description, limits: p.limits }));
    open = true;
  }
  async function save() {
    const body = $state.snapshot(form);
    const ok = cur ? await run(() => put(`/plans/${cur.id}`, body), 'Tarif gespeichert') : await run(() => post('/plans', body), 'Tarif angelegt');
    if (ok) {
      open = false;
      load();
    }
  }
  async function remove(p) {
    if (!(await confirmDialog({ title: `Tarif ${p.name} löschen?`, text: p.users ? `${p.users} Nutzer haben diesen Tarif – sie haben danach keine Limits mehr.` : 'Der Tarif wird gelöscht.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/plans/${p.id}`), 'Tarif gelöscht')) load();
  }
</script>

<PageHead title="Tarife & Limits" subtitle="Wiederverwendbare Limits für Datenvolumen, Geschwindigkeit und Drosselung">
  <button class="btn primary" onclick={() => openNew()}><Icon name="plus" size={16} /> Tarif anlegen</button>
</PageHead>

<div class="grid cols-3">
  {#each plans as p}
    {@const l = p.limits}
    <div class="card plan">
      <div class="card-head">
        <div>
          <h3>{p.name}</h3>
          {#if p.description}<div class="muted tiny">{p.description}</div>{/if}
        </div>
        <span class="badge">{p.users} Nutzer</span>
      </div>
      <div class="card-pad">
        <div class="vol">
          {#if l.traffic_gb > 0}<span class="num">{fmtNum(l.traffic_gb)}</span> GB <span class="muted">{PERIODS[l.period]}</span>{:else}<span class="num">∞</span> <span class="muted">unbegrenzt</span>{/if}
        </div>
        <ul class="facts">
          {#if l.traffic_gb > 0}
            <li><Icon name={l.on_limit === 'throttle' ? 'gauge' : 'lock'} size={15} /> Danach {l.on_limit === 'throttle' ? `gedrosselt auf ${rate(l.limit_down_mbit)}` : 'gesperrt'}</li>
          {/if}
          <li><Icon name="zap" size={15} /> Tempo {l.speed_down_mbit ? `max. ↓ ${rate(l.speed_down_mbit)} / ↑ ${rate(l.speed_up_mbit)}` : 'unbegrenzt'}</li>
          {#each l.tiers || [] as t}
            <li><Icon name="activity" size={15} /> Ab {fmtNum(t.after_gb)} GB: ↓ {rate(t.down_mbit)}</li>
          {/each}
          <li><Icon name="phone" size={15} /> {l.max_devices ? `max. ${l.max_devices} Zugänge` : 'beliebig viele Zugänge'}</li>
        </ul>
      </div>
      <div class="actions">
        <button class="btn sm" onclick={() => openEdit(p)}><Icon name="edit" size={15} /> Bearbeiten</button>
        <span class="grow"></span>
        <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(p)}><Icon name="trash" size={15} /></button>
      </div>
    </div>
  {/each}
</div>

{#if loaded && !plans.length}
  <div class="card empty">
    <h3>Noch keine Tarife</h3>
    <p>Starte mit einer Vorlage:</p>
    <div class="row" style="justify-content:center">
      {#each presets as pr}<button class="btn" onclick={() => openNew(pr)}>{pr.name}</button>{/each}
    </div>
  </div>
{/if}

<div class="notice" style="margin-top:18px">
  <Icon name="info" />
  <span>Limits gelten pro Nutzer über alle seine Zugänge (WireGuard + VLESS zusammen). Geschwindigkeitsgrenzen gelten pro Gerät bzw. pro VLESS-Nutzer. Individuelle Limits stellst du direkt beim Nutzer ein.</span>
</div>

<Modal bind:open title={cur ? `Tarif ${cur.name} bearbeiten` : 'Tarif anlegen'} width={720}>
  <div class="stack">
    <div class="grid cols-2">
      <div class="field"><label for="pl-name">Name</label><input id="pl-name" class="input" bind:value={form.name} /></div>
      <div class="field"><label for="pl-desc">Beschreibung</label><input id="pl-desc" class="input" bind:value={form.description} /></div>
    </div>
    {#if form.limits}<LimitsForm bind:value={form.limits} />{/if}
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={!form.name}>{cur ? 'Speichern' : 'Anlegen'}</button>
  {/snippet}
</Modal>

<style>
  .plan {
    display: flex;
    flex-direction: column;
  }
  .vol {
    font-size: 15px;
    font-weight: 600;
    margin-bottom: 10px;
  }
  .num {
    font-size: 30px;
    font-weight: 750;
    letter-spacing: -0.03em;
  }
  .facts {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
    color: var(--text-2);
    font-size: 13px;
  }
  .facts li {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .facts :global(svg) {
    color: var(--accent);
  }
  .actions {
    display: flex;
    gap: 6px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    margin-top: auto;
  }
</style>
