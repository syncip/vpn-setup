<script>
  // „Weg ins Internet“ je Zugang eines Nutzers: welche Ziel-Regeln greifen und in welcher Reihenfolge.
  // Gleiche Rangfolge wie der Server: Gerät → Nutzer → Server → Alle; je Ebene erst Regeln mit Zielen,
  // die erste Regel für „Alles“ beendet die Suche. Hysteria2 folgt nur Server und Alle.
  import Icon from './Icon.svelte';
  import ProtoLogo from './ProtoLogo.svelte';
  import { get } from '../lib/api.js';
  import { go } from '../lib/state.svelte.js';

  let { userId, peers = [] } = $props();

  let d = $state(null);
  $effect(() => {
    userId;
    get('/routes')
      .then((r) => (d = r))
      .catch(() => (d = null));
  });

  const by = (list) => Object.fromEntries((list || []).map((x) => [x.id, x]));
  const groupById = $derived(by(d?.groups));
  const exitById = $derived(by(d?.exits));
  const serverById = $derived(by(d?.servers));

  function via(r) {
    const st = (r.chain || []).map((id) => exitById[id]?.name || 'Ausgang ?');
    if (r.group) {
      const g = groupById[r.group];
      st.push(g?.auto ? exitById[g.auto]?.name || 'Ausgang ?' : `Gruppe ${g?.name || '?'}`);
    }
    return st.length ? st.join(' → ') : 'direkt';
  }
  function targets(r) {
    const parts = [];
    if (r.domains?.length) parts.push(r.domains.slice(0, 2).join(', ') + (r.domains.length > 2 ? ` +${r.domains.length - 2}` : ''));
    if (r.nets?.length) parts.push(r.nets.length === 1 ? r.nets[0] : `${r.nets.length} Netze`);
    if (r.lists?.length) parts.push(r.lists.length === 1 ? '1 Liste' : `${r.lists.length} Listen`);
    return parts.join(' · ') || 'bestimmte Ziele';
  }
  const LEVEL = { peer: 'Gerät', user: 'Nutzer', server: 'Server', global: 'Alle' };

  function path(p) {
    if (!d) return [];
    const hy = p.protocol === 'hysteria2';
    const scopes = hy ? [['server', p.server_id], ['global', 0]] : [['peer', p.id], ['user', userId], ['server', p.server_id], ['global', 0]];
    const out = [];
    for (const [sc, id] of scopes) {
      const rs = d.routes
        .filter((r) => r.enabled && r.scope === sc && (sc === 'global' || r.scope_id === id))
        .sort((a, b) => (a.match === 'all') - (b.match === 'all') || a.id - b.id);
      for (const r of rs) {
        out.push({ r, level: LEVEL[sc], what: r.match === 'all' ? 'alles Übrige' : targets(r), via: via(r) });
        if (r.match === 'all') return out;
      }
    }
    out.push({ r: null, level: '', what: 'alles Übrige', via: 'direkt' });
    return out;
  }
</script>

{#if d && peers.length}
  <div class="card">
    <div class="card-head">
      <h3><Icon name="route" size={16} /> Weg ins Internet</h3>
      <button class="btn sm ghost" onclick={() => go('/routing/rules')}>Ziel-Regeln <Icon name="arrow-right" size={14} /></button>
    </div>
    <div class="list">
      {#each peers as p (p.id)}
        <div class="peer">
          <div class="who"><ProtoLogo id={p.protocol} size={18} /> <span class="strong ellipsis">{p.name}</span> <span class="muted tiny">{serverById[p.server_id]?.name || ''}</span></div>
          <div class="steps">
            {#each path(p) as s}
              <button class="step" class:direct={s.via === 'direkt'} disabled={!s.r} onclick={() => go('/routing/rules')} title={s.r ? `Regel ${s.r.name || '#' + s.r.id} (${s.level})` : 'Keine Regel – direkt über den Server'}>
                <span class="muted">{s.what}</span> <Icon name="arrow-right" size={12} /> <span class="strong">{s.via}</span>{#if s.level}<span class="lvl">{s.level}</span>{/if}
              </button>
            {/each}
          </div>
        </div>
      {/each}
    </div>
  </div>
{/if}

<style>
  .list {
    display: flex;
    flex-direction: column;
  }
  .peer {
    display: grid;
    grid-template-columns: minmax(160px, 240px) minmax(0, 1fr);
    gap: 6px 16px;
    align-items: start;
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
  }
  .peer:last-child {
    border-bottom: none;
  }
  .who {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    padding-top: 3px;
  }
  .steps {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .step {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--panel-2);
    color: var(--text);
    font: inherit;
    font-size: var(--fs-sm);
    cursor: pointer;
  }
  .step:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .step:disabled {
    cursor: default;
  }
  .step:not(.direct) .strong {
    color: var(--accent);
  }
  .lvl {
    font-size: var(--fs-xs);
    color: var(--muted);
    border-left: 1px solid var(--border);
    padding-left: 5px;
  }
  @media (max-width: 720px) {
    .peer {
      grid-template-columns: minmax(0, 1fr);
      padding: 10px 14px;
    }
  }
</style>
