<script>
  // Firewall-Befehle für den Proxmox-Host: Portweiterleitung an den Container (IPv4 und IPv6).
  // ports: [{port, to?, proto, server?, note?}]
  import Icon from './Icon.svelte';
  import { meta, toast } from '../lib/state.svelte.js';
  import { copy } from '../lib/format.js';

  let { ports = [] } = $props();

  const c4 = $derived(meta.lan4 || '<Container-IPv4>');
  const c6 = $derived(meta.lan6 || '<Container-IPv6>');
  const PUB6 = $derived(meta.pub6 || '<öffentliche IPv6 für den Container>');

  function rule(p, v6, op) {
    const dport = p.to ? `${p.port}:${p.to}` : `${p.port}`;
    const dest = v6 ? `[${c6}]:${p.to ? `${p.port}-${p.to}` : p.port}` : `${c4}:${p.to ? `${p.port}-${p.to}` : p.port}`;
    return `${v6 ? 'ip6tables' : 'iptables'} -t nat ${op} PREROUTING -i vmbr0${v6 ? ` -d ${PUB6}` : ''} -p ${p.proto} --dport ${dport} -j DNAT --to-destination ${dest}`;
  }
  const uniq = $derived.by(() => {
    const seen = new Set();
    return ports.filter((p) => {
      const k = `${p.proto}/${p.port}/${p.to || 0}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  });
  const now = $derived(uniq.flatMap((p) => [rule(p, false, '-A'), rule(p, true, '-A')]).join('\n'));
  const ifaces = $derived(
    uniq
      .flatMap((p) => [
        `    post-up   ${rule(p, false, '-A')}`,
        `    post-down ${rule(p, false, '-D')}`,
        `    post-up   ${rule(p, true, '-A')}`,
        `    post-down ${rule(p, true, '-D')}`,
      ])
      .join('\n'),
  );
  const cp = (t) => copy(t).then(() => toast('Kopiert'));
</script>

{#if uniq.length}
  <p>Auf dem <b>Proxmox-Host</b> müssen diese Ports an den Container{meta.lan4 ? ` (${meta.lan4})` : ''} weitergeleitet sein:</p>
  <ul>
    {#each ports as p}<li><b>{p.proto.toUpperCase()} {p.port}{p.to ? `–${p.to}` : ''}</b>{p.server ? ` – ${p.server}` : ''}{p.note ? ` (${p.note})` : ''}</li>{/each}
  </ul>
  <p class="ph"><b>Dauerhaft</b> in <code>/etc/network/interfaces</code> im Block von <code>vmbr1</code> <button type="button" class="cp" onclick={() => cp(ifaces)}><Icon name="copy" size={13} /> kopieren</button></p>
  <pre>{ifaces}</pre>
  <p class="ph"><b>Sofort</b> (gilt bis zum Neustart) <button type="button" class="cp" onclick={() => cp(now)}><Icon name="copy" size={13} /> kopieren</button></p>
  <pre>{now}</pre>
  <p class="muted">{meta.pub6 || !meta.lan6 ? 'Platzhalter in spitzen Klammern ersetzen. ' : ''}{#if meta.pub6}Öffentliche IPv6 {meta.pub6} aus der Server-Adresse ({meta.server_host}) übernommen{meta.lan6 ? `, interne ${meta.lan6} vom Container` : ''}. {/if}Die IPv6-Zeilen nur, wenn der Container eine eigene öffentliche IPv6 hat. Zusätzlich muss Weiterleitung auf dem Host an sein (<code>net.ipv4.ip_forward=1</code>).</p>
{:else}
  <p>Für diesen Dienst muss auf dem Host kein Port weitergeleitet werden.</p>
{/if}

<style>
  .ph {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin: 10px 0 2px !important;
  }
  .cp {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 1px solid var(--border);
    background: var(--panel);
    border-radius: 6px;
    font: inherit;
    font-size: 12px;
    padding: 2px 7px;
    cursor: pointer;
    color: var(--text-2);
  }
  .cp:hover {
    color: var(--accent);
    border-color: var(--accent);
  }
</style>
