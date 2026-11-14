<script>
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import { limitsSummary, WEEKDAYS } from '../lib/format.js';

  // Limits: Datenvolumen, Zeitraum, Verhalten bei Limit, Grundtempo, Drosselstufen, Geräte
  // exit: für Ausgänge (true/'exit': „Abschalten“) bzw. Gruppen ('group': „Sperren“) – ohne Zugänge
  let { value = $bindable(), exit = false } = $props();

  $effect.pre(() => {
    if (!value) return;
    value.period ??= 'monthly';
    value.on_limit ??= 'throttle';
    value.reset_day ||= 1;
    value.tiers ??= [];
  });

  function n(e) {
    const v = e.currentTarget.value;
    return v === '' ? 0 : Math.max(0, Number(v));
  }
  function addTier() {
    const last = value.tiers.at(-1);
    value.tiers = [...value.tiers, { after_gb: last ? last.after_gb * 2 : 50, down_mbit: last ? Math.max(1, last.down_mbit / 2) : 20, up_mbit: last ? Math.max(1, last.up_mbit / 2) : 10 }];
  }
  function removeTier(i) {
    value.tiers = value.tiers.filter((_, j) => j !== i);
  }
</script>

{#if value}
  <div class="stack">
    <div class="notice"><Icon name="info" /> <span>{exit && exit !== 'group' ? limitsSummary(value).replace('danach gesperrt', 'danach abgeschaltet') : limitsSummary(value)}</span></div>

    <section>
      <h3><Icon name="layers" size={16} /> Datenvolumen</h3>
      <div class="grid cols-2">
        <div class="field">
          <label for="l-gb">Volumen</label>
          <div class="input-group">
            <input id="l-gb" class="input" type="number" min="0" step="1" value={value.traffic_gb || ''} oninput={(e) => (value.traffic_gb = n(e))} placeholder="unbegrenzt" />
            <span class="suffix">GB</span>
          </div>
        </div>
        <div class="field">
          <label for="l-period">Zeitraum</label>
          <select id="l-period" class="input" bind:value={value.period}>
            <option value="monthly">Monatlich zurücksetzen</option>
            <option value="weekly">Wöchentlich zurücksetzen</option>
            <option value="daily">Täglich zurücksetzen</option>
            <option value="none">Nie zurücksetzen (Gesamtvolumen)</option>
          </select>
        </div>
        {#if value.period === 'monthly'}
          <div class="field">
            <label for="l-day">Zurücksetzen am</label>
            <select id="l-day" class="input" bind:value={value.reset_day}>
              {#each Array.from({ length: 28 }, (_, i) => i + 1) as d}<option value={d}>{d}. des Monats</option>{/each}
            </select>
          </div>
        {:else if value.period === 'weekly'}
          <div class="field">
            <label for="l-wd">Zurücksetzen am</label>
            <select id="l-wd" class="input" bind:value={value.reset_day}>
              {#each WEEKDAYS as d, i}<option value={i + 1}>{d}</option>{/each}
            </select>
          </div>
        {/if}
      </div>
      {#if value.traffic_gb > 0}
        <div class="field" style="margin-top:12px">
          <span class="label">Wenn das Volumen verbraucht ist</span>
          <div class="grid cols-2">
            <button type="button" class="choice" class:active={value.on_limit === 'throttle'} onclick={() => (value.on_limit = 'throttle')}>
              <span class="ic"><Icon name="gauge" /></span><span><span class="strong">Drosseln</span><br /><span class="muted small">Weiter nutzbar, aber langsam</span></span>
            </button>
            <button type="button" class="choice" class:active={value.on_limit === 'block'} onclick={() => (value.on_limit = 'block')}>
              <span class="ic"><Icon name="lock" /></span><span><span class="strong">{exit && exit !== 'group' ? 'Abschalten' : 'Sperren'}</span><br /><span class="muted small">{exit === 'group' ? 'Kein Verkehr mehr über die Gruppe bis zum nächsten Zeitraum' : exit ? 'Bis zum nächsten Zeitraum – Gruppen schalten um' : 'Bis zum nächsten Zeitraum'}</span></span>
            </button>
          </div>
        </div>
        {#if value.on_limit === 'throttle'}
          <div class="grid cols-2" style="margin-top:12px">
            <div class="field">
              <label for="l-ld">Download danach</label>
              <div class="input-group"><input id="l-ld" class="input" type="number" min="0" value={value.limit_down_mbit || ''} oninput={(e) => (value.limit_down_mbit = n(e))} /><span class="suffix">Mbit/s</span></div>
            </div>
            <div class="field">
              <label for="l-lu">Upload danach</label>
              <div class="input-group"><input id="l-lu" class="input" type="number" min="0" value={value.limit_up_mbit || ''} oninput={(e) => (value.limit_up_mbit = n(e))} /><span class="suffix">Mbit/s</span></div>
            </div>
          </div>
        {/if}
      {/if}
    </section>

    <section>
      <h3><Icon name="zap" size={16} /> Geschwindigkeit</h3>
      <div class="grid cols-2">
        <div class="field">
          <label for="l-sd">Download max.</label>
          <div class="input-group"><input id="l-sd" class="input" type="number" min="0" value={value.speed_down_mbit || ''} oninput={(e) => (value.speed_down_mbit = n(e))} placeholder="unbegrenzt" /><span class="suffix">Mbit/s</span></div>
        </div>
        <div class="field">
          <label for="l-su">Upload max.</label>
          <div class="input-group"><input id="l-su" class="input" type="number" min="0" value={value.speed_up_mbit || ''} oninput={(e) => (value.speed_up_mbit = n(e))} placeholder="unbegrenzt" /><span class="suffix">Mbit/s</span></div>
        </div>
      </div>
    </section>

    <section>
      <div class="spread">
        <h3><Icon name="activity" size={16} /> Drosselstufen <Info title="Drosselstufen" text="Ab einem Verbrauch im Zeitraum wird langsamer – z. B. „ab 50 GB nur noch 20 Mbit/s“. Es gilt die höchste erreichte Stufe." /></h3>
        <button type="button" class="btn sm" onclick={addTier}><Icon name="plus" size={15} /> Stufe</button>
      </div>
      {#each value.tiers as t, i}
        <div class="tier">
          <span class="small muted">ab</span>
          <div class="input-group"><input class="input" type="number" min="0" value={t.after_gb} oninput={(e) => (t.after_gb = n(e))} /><span class="suffix">GB</span></div>
          <span class="small muted">↓</span>
          <div class="input-group"><input class="input" type="number" min="0" value={t.down_mbit || ''} oninput={(e) => (t.down_mbit = n(e))} placeholder="frei" /><span class="suffix">Mbit/s</span></div>
          <span class="small muted">↑</span>
          <div class="input-group"><input class="input" type="number" min="0" value={t.up_mbit || ''} oninput={(e) => (t.up_mbit = n(e))} placeholder="frei" /><span class="suffix">Mbit/s</span></div>
          <button type="button" class="btn ghost sm icon danger" onclick={() => removeTier(i)} aria-label="Stufe entfernen"><Icon name="trash" size={15} /></button>
        </div>
      {:else}
        <div class="muted small">Keine Drosselstufen.</div>
      {/each}
    </section>

    {#if !exit}
    <section>
      <h3><Icon name="phone" size={16} /> Zugänge</h3>
      <div class="field" style="max-width:260px">
        <label for="l-md">Höchstens</label>
        <div class="input-group"><input id="l-md" class="input" type="number" min="0" value={value.max_devices || ''} oninput={(e) => (value.max_devices = n(e))} placeholder="unbegrenzt" /><span class="suffix">Zugänge</span></div>
      </div>
    </section>
    {/if}
  </div>
{/if}

<style>
  section h3 {
    display: flex;
    align-items: center;
    gap: 7px;
    margin-bottom: 10px;
    font-size: 14px;
  }
  .tier {
    display: grid;
    grid-template-columns: auto 1fr auto 1fr auto 1fr auto;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
  }
  @media (max-width: 640px) {
    .tier {
      grid-template-columns: auto 1fr auto;
    }
  }
</style>
