<script>
  // Eigene Logos der Protokolle (liegen im Repo unter web/src/assets/logos, werden ins Programm eingebettet)
  import wireguard from '../assets/logos/wireguard.svg';
  import vless from '../assets/logos/vless.svg';
  import hysteria2 from '../assets/logos/hysteria2.svg';
  import openvpn from '../assets/logos/openvpn.svg';
  import proxy from '../assets/logos/proxy.svg';
  import { PROTO_LABEL } from '../lib/format.js';

  let { id, size = 20, label = false } = $props();
  const LOGOS = { wireguard, vless, hysteria2, openvpn, proxy };
  const name = $derived(PROTO_LABEL[id] || id);
</script>

<span class="plogo" class:withlabel={label} title={name}>
  {#if LOGOS[id]}
    <img src={LOGOS[id]} alt={label ? '' : name} width={size} height={size} draggable="false" />
  {/if}
  {#if label}<span>{name}</span>{/if}
</span>

<style>
  .plogo { display: inline-flex; align-items: center; gap: 0.4em; vertical-align: middle; line-height: 1; }
  .plogo img { display: block; flex: none; border-radius: 22%; }
  .withlabel span { white-space: nowrap; }
</style>
