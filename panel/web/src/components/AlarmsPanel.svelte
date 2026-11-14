<script>
  // Alarme: einstellbare Regeln (Schwellen, Limits, Probleme), die per E-Mail melden.
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import Modal from './Modal.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { ago, date, fmtNum } from '../lib/format.js';
  import { toast } from '../lib/state.svelte.js';

  let d = $state(null);
  let targets = $state({ exit: [], group: [], user: [] });

  async function load() {
    try {
      d = await get('/alarms');
    } catch (e) {
      toast(e.message, 'error');
    }
  }
  async function loadTargets() {
    const [x, s] = await Promise.all([get('/exits').catch(() => null), get('/search').catch(() => null)]);
    targets = {
      exit: (x?.exits || []).map((e) => ({ id: e.id, name: e.name, sub: e.limits ? '' : 'ohne Limit' })),
      group: (x?.groups || []).map((g) => ({ id: g.id, name: g.name })),
      user: (s?.users || []).map((u) => ({ id: u.id, name: u.name })),
    };
  }
  load();
  loadTargets();
  $effect(() => {
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  });

  const typeBy = $derived(Object.fromEntries((d?.types || []).map((t) => [t.key, t])));
  const groups = $derived.by(() => {
    const m = new Map();
    for (const t of d?.types || []) {
      if (!m.has(t.group)) m.set(t.group, []);
      m.get(t.group).push(t);
    }
    return [...m];
  });
  const TARGET_ALL = { exit: 'Alle Ausgänge', group: 'Alle Gruppen', user: 'Alle Nutzer' };
  const REPEATS = [
    [0, 'nur einmal'],
    [1, 'stündlich'],
    [6, 'alle 6 Stunden'],
    [12, 'alle 12 Stunden'],
    [24, 'täglich'],
    [168, 'wöchentlich'],
  ];
  const MINUTES = [0, 2, 5, 10, 15, 30, 60, 180];

  function condition(a) {
    const t = typeBy[a.type];
    if (!t) return a.type;
    let c = '';
    if (t.unit === 'Tage') c = `unter ${fmtNum(a.threshold)} Tagen`;
    else if (t.unit === 'Anzahl') c = `ab ${fmtNum(a.threshold)}`;
    else if (t.unit) c = `ab ${fmtNum(a.threshold)} ${t.unit}`;
    else c = 'sobald es eintritt';
    if (a.minutes) c += ` · ${a.minutes} Min. lang`;
    return c;
  }
  function targetName(a) {
    const t = typeBy[a.type];
    if (!t?.target) return 'Server';
    if (!a.target) return TARGET_ALL[t.target];
    return targets[t.target]?.find((x) => x.id === a.target)?.name || `#${a.target}`;
  }
  const repeatText = (h) => REPEATS.find((r) => r[0] === h)?.[1] || `alle ${h} Stunden`;
  const since = (ts) => (ago(ts) === 'online' ? 'gerade eben' : ago(ts));
  const nameOf = (id) => d?.alarms.find((a) => a.id === id)?.name || '';

  // ---------- Bearbeiten ----------
  let open = $state(false);
  let cur = $state(null);
  let f = $state(null);
  let busy = $state(false);
  function edit(a = null) {
    cur = a;
    f = a ? { ...a, to: (a.to || []).join(', ') } : { name: '', type: 'cpu', target: 0, threshold: 90, minutes: 15, repeat: 0, recover: true, enabled: true, to: '' };
    open = true;
  }
  function setType(k) {
    const t = typeBy[k];
    const auto = !f.name || f.name === typeBy[f.type]?.label;
    f.type = k;
    f.threshold = t.def;
    f.minutes = t.minutes;
    f.target = 0;
    if (auto) f.name = '';
  }
  async function save() {
    busy = true;
    const body = { ...f, threshold: Number(f.threshold) || 0, minutes: Number(f.minutes) || 0, repeat: Number(f.repeat) || 0, target: Number(f.target) || 0, to: f.to.split(/[,;\s]+/).filter(Boolean) };
    const r = cur ? await run(() => put(`/alarms/${cur.id}`, body), 'Alarm gespeichert') : await run(() => post('/alarms', body), 'Alarm angelegt');
    busy = false;
    if (r) {
      open = false;
      load();
    }
  }
  async function toggle(a) {
    if (await run(() => put(`/alarms/${a.id}`, { ...a, enabled: !a.enabled }), a.enabled ? 'Alarm aus' : 'Alarm an')) load();
  }
  async function remove(a) {
    if (!(await confirmDialog({ title: `Alarm „${a.name}“ löschen?`, ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/alarms/${a.id}`), 'Alarm gelöscht')) load();
  }
  let testing = $state(0);
  async function test(a) {
    testing = a.id;
    const r = await run(() => post(`/alarms/${a.id}/test`));
    testing = 0;
    if (r) toast(`Testmail an ${r.to.join(', ')} angenommen`);
  }
  const ft = $derived(f ? typeBy[f.type] : null);
</script>

{#if !d}
  <div class="card card-pad muted small">Lade …</div>
{:else}
  <div class="stack">
    {#if !d.mail_ok}
      <div class="notice warn small"><Icon name="alert" size={16} /><span>Der Mailversand ist nicht eingerichtet – Alarme werden geprüft und unter „Braucht Aufmerksamkeit“ angezeigt, aber nicht verschickt. <a href="#/settings/notify">Benachrichtigungen einrichten</a></span></div>
    {:else if !d.recipients.length}
      <div class="notice warn small"><Icon name="alert" size={16} /><span>Kein Administrator hat Benachrichtigungen mit E-Mail-Adresse eingeschaltet („Mein Konto“). Alarme ohne eigene Empfänger gehen deshalb an niemanden.</span></div>
    {/if}

    <div class="card">
      <div class="card-head">
        <h3><Icon name="alert" size={16} /> Aktuelle Alarme {#if d.active.filter((x) => x.active).length}<span class="badge bad">{d.active.filter((x) => x.active).length}</span>{/if}</h3>
      </div>
      <div class="list">
        {#each d.active as x (x.key)}
          <div class="item">
            <span class="dot" class:bad={x.active} class:warn={!x.active}></span>
            <div class="grow" style="min-width:0">
              <div class="small strong">{x.title}</div>
              <div class="tiny muted">
                {nameOf(x.alarm_id)} · seit {date(x.since, true)}
                {#if !x.active}· wartet auf die eingestellte Dauer{:else if x.sent}· gemeldet {since(x.sent)}{/if}
              </div>
              {#if x.detail}<div class="tiny muted pre">{x.detail}</div>{/if}
            </div>
          </div>
        {:else}
          <div class="item small muted"><Icon name="check" size={15} /> Gerade kein Alarm.</div>
        {/each}
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <h3>
          <Icon name="list" size={16} /> Alarme
          <Info title="Alarme" wide>
            <p>Jeder Alarm prüft jede Minute eine Bedingung. Ist sie erfüllt – und das so lange wie unter „Dauer“ eingestellt –, geht eine Mail hinaus.</p>
            <ul>
              <li><b>Wiederholen:</b> solange der Alarm besteht, erneut melden (sonst nur einmal).</li>
              <li><b>Entwarnung:</b> Mail, wenn der Alarm vorbei ist.</li>
              <li><b>Empfänger:</b> eigene Adressen oder – leer – alle Administratoren mit eingeschalteten Benachrichtigungen ({d.recipients.join(', ') || 'derzeit niemand'}).</li>
            </ul>
            <p>Unabhängig von den Anlässen unter „Benachrichtigungen“; nur der Mailserver muss eingerichtet sein.</p>
          </Info>
        </h3>
        <button class="btn primary sm" onclick={() => edit()}><Icon name="plus" size={15} /> Alarm</button>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Alarm</th><th>Für</th><th>Bedingung</th><th>Meldung</th><th></th></tr></thead>
          <tbody>
            {#each d.alarms as a (a.id)}
              <tr class:off={!a.enabled}>
                <td>
                  <div class="strong small">{a.name}{#if !a.enabled}&nbsp;<span class="badge muted">aus</span>{/if}</div>
                  {#if a.name !== typeBy[a.type]?.label}<div class="tiny muted">{typeBy[a.type]?.label}</div>{/if}
                </td>
                <td class="small">{targetName(a)}</td>
                <td class="small nowrap">{condition(a)}</td>
                <td class="small">
                  {repeatText(a.repeat)}{a.recover ? ' · mit Entwarnung' : ''}
                  {#if a.to?.length}<div class="tiny muted">an {a.to.join(', ')}</div>{/if}
                </td>
                <td class="right nowrap">
                  <button class="btn sm icon ghost" title={a.enabled ? 'Ausschalten' : 'Einschalten'} onclick={() => toggle(a)}><Icon name="power" size={15} /></button>
                  <button class="btn sm icon ghost" title="Testmail an die Empfänger" disabled={testing === a.id || !d.mail_ok} onclick={() => test(a)}><Icon name="mail" size={15} /></button>
                  <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => edit(a)}><Icon name="edit" size={15} /></button>
                  <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(a)}><Icon name="trash" size={15} /></button>
                </td>
              </tr>
            {:else}
              <tr><td colspan="5" class="empty small">Keine Alarme. Lege einen an, z. B. „CPU über 90 % für 15 Minuten“.</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  </div>
{/if}

<Modal bind:open title={cur ? `Alarm ${cur.name}` : 'Alarm anlegen'} width={620}>
  {#if f && ft}
    <div class="stack">
      <div class="field">
        <label for="al-type">Was soll gemeldet werden?</label>
        <select id="al-type" class="input" value={f.type} onchange={(e) => setType(e.currentTarget.value)}>
          {#each groups as [g, list]}
            <optgroup label={g}>{#each list as t}<option value={t.key}>{t.label}</option>{/each}</optgroup>
          {/each}
        </select>
        <div class="tiny muted" style="margin-top:4px">{ft.help}</div>
      </div>
      <div class="grid cols-2">
        {#if ft.target}
          <div class="field">
            <label for="al-target">Für</label>
            <select id="al-target" class="input" bind:value={f.target}>
              <option value={0}>{TARGET_ALL[ft.target]}</option>
              {#each targets[ft.target] as x}<option value={x.id}>{x.name}{x.sub ? ` (${x.sub})` : ''}</option>{/each}
            </select>
          </div>
        {/if}
        {#if ft.unit}
          <div class="field">
            <label for="al-th">{ft.unit === 'Tage' ? 'Melden unter' : 'Melden ab'}</label>
            <div class="input-group"><input id="al-th" class="input" type="number" min="0" step="any" bind:value={f.threshold} /><span class="suffix">{ft.unit}</span></div>
          </div>
        {/if}
        <div class="field">
          <label for="al-min">Dauer <Info title="Dauer" text="So lange muss die Bedingung ohne Unterbrechung erfüllt sein, bevor gemeldet wird – gegen kurze Spitzen. 0 = sofort." /></label>
          <select id="al-min" class="input" bind:value={f.minutes}>
            {#each MINUTES as m}<option value={m}>{m ? `${m} Minuten` : 'sofort'}</option>{/each}
            {#if !MINUTES.includes(f.minutes)}<option value={f.minutes}>{f.minutes} Minuten</option>{/if}
          </select>
        </div>
        <div class="field">
          <label for="al-rep">Melden</label>
          <select id="al-rep" class="input" bind:value={f.repeat}>
            {#each REPEATS as [v, l]}<option value={v}>{v ? `${l}, solange er besteht` : l}</option>{/each}
            {#if !REPEATS.some((r) => r[0] === f.repeat)}<option value={f.repeat}>alle {f.repeat} Stunden</option>{/if}
          </select>
        </div>
      </div>
      <div class="field"><label for="al-name">Name</label><input id="al-name" class="input" bind:value={f.name} placeholder={ft.label} /></div>
      <div class="field">
        <label for="al-to">Empfänger</label>
        <input id="al-to" class="input" bind:value={f.to} placeholder={d?.recipients.length ? `leer = ${d.recipients.join(', ')}` : 'leer = Administratoren mit Benachrichtigungen'} />
        <div class="tiny muted" style="margin-top:4px">Mehrere Adressen mit Komma trennen.</div>
      </div>
      <label class="switch"><input type="checkbox" bind:checked={f.recover} /><span class="track"></span> Entwarnung schicken, wenn der Alarm vorbei ist</label>
      <label class="switch"><input type="checkbox" bind:checked={f.enabled} /><span class="track"></span> Aktiv</label>
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={busy}>{cur ? 'Speichern' : 'Anlegen'}</button>
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
    align-items: flex-start;
    gap: 10px;
    padding: 8px 12px;
  }
  .item .dot {
    margin-top: 6px;
  }
  tr.off td:not(:last-child) {
    opacity: 0.55;
  }
  .pre {
    white-space: pre-line;
    margin-top: 2px;
  }
</style>
