<script>
  // DNS für Geräte ohne VPN (Fernseher, Router …): Einrichtung, freigegebene Geräte und wer von außen fragt.
  import Icon from './Icon.svelte';
  import Info from './Info.svelte';
  import Modal from './Modal.svelte';
  import PortHelp from './PortHelp.svelte';
  import SearchInput from './SearchInput.svelte';
  import { confirmDialog } from './Confirm.svelte';
  import { get, post, put, del, run } from '../lib/api.js';
  import { ago, fmtNum, copy, bytes } from '../lib/format.js';
  import { toast } from '../lib/state.svelte.js';

  let { onchange } = $props();

  let d = $state({ external: { public: false, clients: [], seen: [], self: '', self_ips: [] }, profiles: [], dns_enabled: true, out_interface: 'eth0', dry_run: false, tls: {}, smart: { hits: [] }, settings: {} });
  let loaded = $state(false);
  async function load() {
    d = await get('/dns/clients');
    loaded = true;
  }
  load();
  $effect(() => {
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  });

  const x = $derived(d.external);
  const when = (ts) => (!ts ? 'nie' : ago(ts) === 'online' ? 'gerade eben' : ago(ts));
  const globalProfile = $derived(d.profiles.find((p) => p.global && p.enabled));
  const profName = (id) => (id === -1 ? 'ohne Filter' : id > 0 ? d.profiles.find((p) => p.id === id)?.name || `Profil #${id}` : globalProfile ? `${globalProfile.name} (global)` : 'ohne Filter (kein globales Profil)');
  const strangers = $derived(x.seen.filter((s) => !s.client));
  const dnsIP4 = $derived(x.self_ips.find((a) => !a.includes(':')) || '');
  const dnsIP6 = $derived(x.self_ips.find((a) => a.includes(':')) || '');

  async function setPublic(on) {
    if (on && !x.clients.some((c) => c.enabled)) {
      if (!(await confirmDialog({ title: 'DNS von außen einschalten?', text: 'Noch ist kein Gerät freigegeben – Anfragen werden verworfen, aber hier angezeigt. So siehst du die Adresse deines Geräts und kannst es mit einem Klick freigeben.', ok: 'Einschalten' }))) return;
    }
    if (await run(() => put('/dns/settings', { public: on }), on ? 'DNS von außen eingeschaltet' : 'DNS von außen ausgeschaltet')) {
      await load();
      onchange?.();
    }
  }

  // ---------- DoH/DoT ----------
  const T = $derived(d.tls || {});
  let tf = $state(null); // Formular (null = nicht geöffnet)
  function editTLS() {
    tf = { tls_host: d.settings.tls_host || '', dot_port: Number(d.settings.dot_port) || 853, acme_email: d.settings.acme_email || '' };
  }
  async function saveTLS(on) {
    const body = tf ? { tls_host: tf.tls_host.trim(), dot_port: Number(tf.dot_port) || 853, acme_email: tf.acme_email.trim() } : {};
    if (on !== undefined) body.tls = on;
    if (await run(() => put('/dns/settings', body), on === false ? 'DoH/DoT ausgeschaltet' : 'Gespeichert')) {
      await load();
      tf = null;
      onchange?.();
    }
  }
  let tfInit = false;
  $effect(() => {
    if (loaded && !tfInit) {
      tfInit = true;
      if (!d.settings.tls_host) editTLS();
    }
  });
  // Cloudflare-Token: geht nur hin (secrets.env auf dem Server), kommt nie zurück
  let cfOpen = $state(false);
  let cfTok = $state('');
  let cfBusy = $state(false);
  let cfCheck = $state(null);
  async function saveCF() {
    cfBusy = true;
    const r = await run(() => put('/dns/tls/token', { token: cfTok.trim() }));
    cfBusy = false;
    if (r) {
      cfTok = '';
      cfOpen = false;
      cfCheck = r.check;
      toast(r.check?.ok ? 'Token gespeichert und geprüft' : 'Token gespeichert', r.check && !r.check.ok ? 'error' : 'ok');
      load();
    }
  }
  async function verifyCF() {
    cfBusy = true;
    cfCheck = await run(() => post('/dns/tls/token/verify', {}));
    cfBusy = false;
  }
  async function removeCF() {
    if (!(await confirmDialog({ title: 'Token entfernen?', text: 'Das Zertifikat kann danach nicht mehr automatisch erneuert werden.', ok: 'Entfernen', danger: true }))) return;
    if (await run(() => del('/dns/tls/token'), 'Token entfernt')) {
      cfCheck = null;
      load();
    }
  }
  let renewing = $state(false);
  async function renew() {
    renewing = true;
    await run(() => post('/dns/tls/renew', {}), 'Zertifikat wird geholt – das dauert 1–3 Minuten');
    renewing = false;
    load();
  }
  $effect(() => {
    if (!T.issuing) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  });
  const dohURL = (c) => `https://${c.token}.${T.host}/dns-query`;
  const dotHost = (c) => `${c.token}.${T.host}`;
  const days = (ts) => Math.round((ts - Date.now() / 1000) / 86400);
  let linkFor = $state(null);
  async function newToken(c) {
    if (!(await confirmDialog({ title: 'Neue Kennung?', text: 'Die bisherigen DoH-/DoT-Links von „' + c.name + '“ funktionieren danach nicht mehr – am Gerät neu eintragen.', ok: 'Neu erzeugen' }))) return;
    if (await run(() => put(`/dns/clients/${c.id}`, { new_token: true }), 'Neue Kennung erzeugt')) load();
  }

  // ---------- Gerät freigeben ----------
  let open = $state(false);
  let busy = $state(false);
  let f = $state({});
  function edit(c, addr) {
    f = c
      ? { id: c.id, name: c.name, addrs: c.addrs.join('\n'), profile: c.profile, note: c.note, enabled: c.enabled, learn: c.learn }
      : { id: 0, name: '', addrs: addr || '', profile: 0, note: '', enabled: true, learn: false };
    open = true;
  }
  async function save() {
    busy = true;
    const body = { name: f.name, addrs: [f.addrs], profile: Number(f.profile), note: f.note, enabled: f.enabled, learn: f.learn };
    const ok = await run(() => (f.id ? put(`/dns/clients/${f.id}`, body) : post('/dns/clients', body)), 'Gespeichert');
    busy = false;
    if (ok) {
      open = false;
      load();
      onchange?.();
    }
  }
  async function toggle(c) {
    if (await run(() => put(`/dns/clients/${c.id}`, { enabled: !c.enabled }))) load();
  }
  async function remove(c) {
    if (!(await confirmDialog({ title: `„${c.name}“ löschen?`, text: 'Das Gerät bekommt danach keine Antworten mehr vom Panel-DNS.', ok: 'Löschen', danger: true }))) return;
    if (await run(() => del(`/dns/clients/${c.id}`), 'Gelöscht')) {
      load();
      onchange?.();
    }
  }
  async function forget(addr) {
    if (!addr && !(await confirmDialog({ title: 'Liste leeren?', text: 'Die Liste der Absender wird geleert; neue Anfragen erscheinen wieder.', ok: 'Leeren' }))) return;
    if (await run(() => del(`/dns/seen${addr ? `?addr=${encodeURIComponent(addr)}` : ''}`))) load();
  }

  let q = $state('');
  let showAll = $state(false);
  const seenShown = $derived.by(() => {
    const t = q.trim().toLowerCase();
    let rows = x.seen;
    if (t) rows = rows.filter((s) => [s.addr, s.host, s.client_name, s.name].some((v) => (v || '').toLowerCase().includes(t)));
    return showAll ? rows : rows.slice(0, 50);
  });
  const cp = (t) => copy(t).then(() => toast('Kopiert'));
  const valid = $derived(f.name?.trim() && (f.addrs?.trim() || T.on));
</script>

<div class="grid cols-2 top">
  <div class="card card-pad stack" style="gap:10px">
    <div class="row" style="gap:10px">
      <div class="grow">
        <strong>DNS von außen</strong>
        <Info title="DNS ohne VPN" wide>
          <p>Geräte, die kein VPN können (Fernseher, Konsole, Router zu Hause), tragen den Server direkt als DNS-Server ein. Dann gelten für sie Filterprofile und Protokoll wie für VPN-Geräte.</p>
          <p><b>Nur freigegebene Absender</b> bekommen Antworten. Ein offener DNS-Server für alle würde sofort für Angriffe (DNS-Verstärkung) missbraucht – deshalb gibt es das nicht. Fremde Anfragen werden verworfen, aber unten mitgezählt.</p>
          <p>Wechselt die Adresse deines Anschlusses, trag statt der IP einen DynDNS-Namen ein (z. B. von der FRITZ!Box: <code>xyz.myfritz.net</code>) – das Panel löst ihn alle 5 Minuten neu auf.</p>
        </Info>
        <div class="muted small">Port 53 auf {d.out_interface} → Panel-DNS</div>
      </div>
      <label class="switch"><input type="checkbox" checked={x.public} disabled={!d.dns_enabled} onchange={(e) => setPublic(e.currentTarget.checked)} /><span class="track"></span></label>
    </div>
    {#if !d.dns_enabled}
      <div class="notice warn small"><Icon name="alert" size={16} /><span>Erst den Panel-DNS einschalten (Einstellungen).</span></div>
    {:else if x.public}
      <div class="notice okn small"><Icon name="check" size={16} /><span>{x.clients.filter((c) => c.enabled).length} {x.clients.filter((c) => c.enabled).length === 1 ? 'freigegebenes Gerät' : 'freigegebene Geräte'} · {strangers.length} {strangers.length === 1 ? 'fremder Absender' : 'fremde Absender'} gesehen</span></div>
    {:else}
      <div class="muted small">Aus – Anfragen von außen erreichen den Panel-DNS nicht.</div>
    {/if}
  </div>

  <div class="card card-pad stack" style="gap:8px">
    <div class="row" style="gap:6px">
      <strong>So richtest du es ein</strong>
      <Info title="Portweiterleitung auf dem Proxmox-Host" wide>
        <PortHelp ports={[{ proto: 'udp', port: 53, note: 'DNS' }, { proto: 'tcp', port: 53, note: 'DNS, große Antworten' }, ...(T.on ? [{ proto: 'tcp', port: T.dot_port || 853, note: 'DNS-over-TLS' }] : [])]} />
        <p class="muted">Im Container leitet das Panel Port 53 selbst an den DNS-Dienst weiter – sonst ist nichts zu tun.</p>
      </Info>
    </div>
    <ol class="steps small">
      <li><b>Proxmox-Host:</b> UDP und TCP 53 an den Container weiterleiten (i-Symbol: fertige Befehle).</li>
      <li><b>Hier:</b> „DNS von außen“ einschalten und das Gerät freigeben – mit der öffentlichen IP deines Anschlusses (steht in der Router-Oberfläche; fremde Absender unten zeigen sie auch) oder einem DynDNS-Namen.</li>
      <li>
        <b>Am Gerät</b> (Fernseher: Netzwerk → IP-Einstellungen → DNS manuell) bzw. besser im Router als DNS-Server eintragen:
        {#if dnsIP4}<button class="ipbtn mono" title="Kopieren" onclick={() => cp(dnsIP4)}>{dnsIP4} <Icon name="copy" size={12} /></button>{/if}
        {#if dnsIP6}<button class="ipbtn mono" title="Kopieren" onclick={() => cp(dnsIP6)}>{dnsIP6} <Icon name="copy" size={12} /></button>{/if}
        {#if !dnsIP4 && !dnsIP6}<span class="mono">{x.self || 'öffentliche IP des Servers'}</span>{/if}
      </li>
      <li><b>Prüfen:</b> Gerät benutzen – unten erscheint es mit „freigegeben“. Taucht es als <i>fremd</i> auf, stimmt die Adresse nicht: dort auf „Freigeben“ klicken.</li>
    </ol>
    <div class="tiny muted">Zweiten DNS-Server am Gerät leer lassen – sonst fragt es teils dort und umgeht den Filter. Viele Fernseher und Android-Geräte nutzen fest eingebaute DNS-Server (z. B. 8.8.8.8); das lässt sich nur im Router abfangen.</div>
  </div>
</div>

<div class="card" style="margin-top:14px">
  <div class="card-head">
    <h2>
      <Icon name="lock" size={16} /> Verschlüsselt: DoH und DoT
      <Info title="DNS-over-HTTPS / DNS-over-TLS" wide>
        <p>Jedes freigegebene Gerät bekommt eine eigene <b>Kennung</b>. Damit funktioniert der Panel-DNS von überall – ohne feste IP, im Mobilfunk und in fremden WLANs:</p>
        <ul>
          <li><b>Android</b> (Einstellungen → Netzwerk → Privates DNS): <code>&lt;kennung&gt;.{T.host || 'dns.example.org'}</code></li>
          <li><b>Browser</b> (Chrome, Firefox, Brave → Sicheres DNS → eigener Anbieter), <b>iOS/macOS</b> (z. B. per Profil), <b>Router</b> mit DoH: <code>https://&lt;kennung&gt;.{T.host || 'dns.example.org'}/dns-query</code></li>
        </ul>
        <p><b>Adresse merken</b> (je Gerät): Wer per DoH/DoT fragt, darf 24 Stunden lang auch normales DNS (Port 53) nutzen – so funktioniert z. B. der Fernseher hinter demselben Router, ohne feste IP einzutragen. Dafür muss „DNS von außen“ an sein.</p>
        <p><b>Zertifikat:</b> Das Panel holt bei Let's Encrypt eines für den Namen und alle Kennungen (<code>*.name</code>). Geprüft wird über einen DNS-Eintrag, den das Panel über die Cloudflare-API anlegt und wieder löscht; fehlende A-/AAAA-Einträge für den Namen und <code>*.name</code> legt es ebenfalls an (ohne Cloudflare-Proxy – DoT geht nicht über den Proxy). Erneuert wird automatisch 30 Tage vor Ablauf. Mit dem Einschalten akzeptierst du die Nutzungsbedingungen von Let's Encrypt.</p>
        <p><b>API-Token</b> (Cloudflare → Profil → API-Tokens → „DNS bearbeiten“ für die Zone) gehört <i>nicht</i> ins Panel, sondern auf den Server: Zeile <code>CF_API_TOKEN=…</code> in <code>{T.token_file || '/etc/vpn/secrets.env'}</code> (Rechte 600). Das Panel liest die Datei bei Bedarf, ein Neustart ist nicht nötig.</p>
      </Info>
    </h2>
    {#if T.host && !tf}
      <label class="switch" title={T.on ? 'An' : 'Aus'}><input type="checkbox" checked={d.settings.tls === '1'} disabled={!d.dns_enabled} onchange={(e) => saveTLS(e.currentTarget.checked)} /><span class="track"></span></label>
    {/if}
  </div>
  <div class="card-pad stack" style="gap:10px;padding-top:0">
    {#if tf}
      <div class="grid cols-3" style="gap:10px">
        <div class="field">
          <label for="tls-host">DNS-Name <Info title="DNS-Name" text="Eine eigene Subdomain deiner Cloudflare-Zone, z. B. dns.example.org. Die Kennungen werden Unterdomains davon (abc123.dns.example.org). „Nur DNS“ (graue Wolke), nicht über den Cloudflare-Proxy." /></label>
          <input id="tls-host" class="input mono" bind:value={tf.tls_host} placeholder="dns.example.org" />
        </div>
        <div class="field">
          <label for="tls-port">DoT-Port</label>
          <input id="tls-port" class="input" type="number" min="1" max="65535" bind:value={tf.dot_port} />
        </div>
        <div class="field">
          <label for="tls-mail">E-Mail für Let's Encrypt <span class="muted">(optional)</span></label>
          <input id="tls-mail" class="input" bind:value={tf.acme_email} placeholder="Hinweise zum Ablauf" />
        </div>
      </div>
      <div class="row" style="gap:8px">
        <button class="btn primary" onclick={() => saveTLS(d.settings.tls === '1' || !d.settings.tls_host ? true : undefined)} disabled={!tf.tls_host.trim() || !d.dns_enabled}>{d.settings.tls_host ? 'Speichern' : 'Einschalten'}</button>
        {#if d.settings.tls_host}<button class="btn" onclick={() => (tf = null)}>Abbrechen</button>{/if}
        {#if !d.dns_enabled}<span class="small warn-text">Erst den Panel-DNS einschalten.</span>{/if}
      </div>
    {:else}
      <div class="row wrap" style="gap:8px">
        <span class="mono strong">{T.host}</span>
        <button class="btn sm ghost" onclick={editTLS}><Icon name="edit" size={13} /> Ändern</button>
        <span class="grow"></span>
        {#if T.on}
          <span class="badge {T.doh ? 'ok' : 'muted'}">DoH (443) {T.doh ? 'bereit' : 'aus'}</span>
          <span class="badge {T.dot ? 'ok' : 'muted'}">DoT ({T.dot_port}) {T.dot ? 'bereit' : 'aus'}</span>
          {#if T.q_doh || T.q_dot}<span class="tiny muted">{fmtNum(T.q_doh)} DoH- · {fmtNum(T.q_dot)} DoT-Anfragen{T.denied ? ` · ${fmtNum(T.denied)} abgewiesen` : ''}</span>{/if}
        {/if}
      </div>
      {#if T.on}
        <div class="certline small">
          <Icon name={T.has_cert && !T.cert.self_signed ? 'check' : 'alert'} size={15} />
          {#if T.issuing}
            <span>Zertifikat wird geholt … <span class="muted">{T.step}</span></span>
          {:else if T.has_cert}
            <span>Zertifikat {T.cert.self_signed ? 'selbstsigniert (Testmodus)' : `von ${T.cert.issuer}`} für <span class="mono">{T.cert.names.join(', ')}</span> · gültig bis {new Date(T.cert.not_after * 1000).toLocaleDateString('de-DE')} <span class="muted">({days(T.cert.not_after)} Tage)</span></span>
          {:else}
            <span class="warn-text">Noch kein Zertifikat – DoH/DoT laufen erst danach.</span>
          {/if}
          <span class="grow"></span>
          <button class="btn sm" onclick={renew} disabled={renewing || T.issuing || !T.token_set}><Icon name="refresh" size={13} /> {T.has_cert ? 'Jetzt erneuern' : 'Zertifikat holen'}</button>
        </div>
        <div class="cfbox">
          <div class="row wrap" style="gap:8px">
            <Icon name="key" size={15} />
            <strong class="small">Cloudflare-API-Token</strong>
            <Info title="Cloudflare-API-Token" wide>
              <p>Damit legt das Panel den Prüfeintrag für Let's Encrypt an und erneuert das Zertifikat automatisch.</p>
              <p><b>Anlegen:</b> Cloudflare → Profil → API-Tokens → „Token erstellen“ → Vorlage „DNS-Zone bearbeiten“, unter „Zonenressourcen“ nur die Zone von {T.host || 'deinem DNS-Namen'} wählen.</p>
              <p><b>Speicherort:</b> nur auf dem Server in <code>{T.token_file}</code> (Rechte 600) – nicht in der Datenbank, nicht in Sicherungen des Panels. Die Oberfläche zeigt es nie wieder an; zum Ändern einfach neu eintragen.</p>
            </Info>
            {#if T.token_set}<span class="badge ok"><Icon name="check" size={12} /> hinterlegt</span>{:else}<span class="badge warn">fehlt</span>{/if}
            <span class="grow"></span>
            {#if T.token_set && !cfOpen}
              <button class="btn sm" onclick={verifyCF} disabled={cfBusy}><Icon name="activity" size={13} /> Prüfen</button>
              <button class="btn sm" onclick={() => (cfOpen = true)}><Icon name="edit" size={13} /> Ersetzen</button>
              <button class="btn sm icon ghost danger" title="Entfernen" onclick={removeCF}><Icon name="trash" size={14} /></button>
            {/if}
          </div>
          {#if !T.token_set || cfOpen}
            <form class="row wrap" style="gap:8px;margin-top:8px" onsubmit={(e) => (e.preventDefault(), saveCF())}>
              <input class="input mono grow" style="min-width:240px" type="password" autocomplete="off" spellcheck="false" bind:value={cfTok} placeholder="Token einfügen" aria-label="Cloudflare-API-Token" />
              <button class="btn primary" type="submit" disabled={cfBusy || cfTok.trim().length < 20}>{cfBusy ? 'Prüfe …' : 'Speichern'}</button>
              {#if cfOpen}<button class="btn" type="button" onclick={() => ((cfOpen = false), (cfTok = ''))}>Abbrechen</button>{/if}
            </form>
          {/if}
          {#if cfCheck}<div class="tiny {cfCheck.ok ? 'ok-text' : 'bad-text'}" style="margin-top:6px">{cfCheck.message}</div>{/if}
        </div>
        {#if T.error && !T.issuing}<div class="notice bad small"><Icon name="alert" size={16} /><span>{T.error}</span></div>{/if}
        <div class="tiny muted">
          Auf dem Proxmox-Host zusätzlich TCP {T.dot_port} weiterleiten <Info title="Port für DoT" wide><PortHelp ports={[{ proto: 'tcp', port: T.dot_port || 853, note: 'DNS-over-TLS' }]} /></Info> · DoH läuft über Port 443 (nginx). Links je Gerät stehen unten.
        </div>
      {:else}
        <div class="muted small">Aus – {d.dns_enabled ? 'Schalter oben rechts.' : 'erst den Panel-DNS einschalten.'}</div>
      {/if}
    {/if}
  </div>
</div>

{#if d.smart?.domains || d.smart?.hits?.length}
  <div class="card" style="margin-top:14px">
    <div class="card-head">
      <h2>
        <Icon name="route" size={16} /> SmartDNS-Proxy
        <Info title="SmartDNS für Geräte ohne VPN" text="Für SmartDNS-Domains der Filterprofile antwortet der Panel-DNS Geräten ohne VPN mit der Adresse des Servers. nginx reicht diese HTTPS-Verbindungen (Port 443) an den Proxy, der sie über die Ausgangsgruppe weiterleitet. Zahlen seit dem Start des Dienstes." />
      </h2>
      <span class="badge {d.smart.running ? 'ok' : 'muted'}">{d.smart.running ? 'läuft' : d.dry_run ? 'Testmodus' : 'aus'}</span>
    </div>
    <div class="card-pad stack" style="gap:8px;padding-top:0">
      <div class="small muted">
        {fmtNum(d.smart.domains)} Domains · {fmtNum(d.smart.total)} Verbindungen ({fmtNum(d.smart.active)} offen) · {bytes(d.smart.bytes)}{d.smart.denied ? ` · ${fmtNum(d.smart.denied)} abgewiesen` : ''} · Antwortadresse {d.smart.target4 || '–'}{d.smart.target6 ? `, ${d.smart.target6}` : ''}
      </div>
      {#if !d.smart.target4}<div class="notice warn small"><Icon name="alert" size={16} /><span>Die öffentliche IPv4 des Servers ist unbekannt (Einstellung „Server-Adresse“) – SmartDNS antwortet dann mit den echten Adressen.</span></div>{/if}
      {#if !x.public && !T.on}<div class="tiny muted">Wirkt erst, wenn „DNS von außen“ oder DoH/DoT an ist – VPN-Geräte nutzen SmartDNS ohnehin über die Ziel-Regeln.</div>{/if}
      {#each d.smart.hits.slice(0, 12) as h}
        <div class="row small" style="gap:8px">
          <span class="mono tiny grow ellipsis">{h.domain}</span>
          <span class="tiny muted">{fmtNum(h.conns)}× · {bytes(h.bytes)} · {when(h.last)}</span>
          {#if h.err}<span class="tiny warn-text ellipsis" style="max-width:260px" title={h.err}>{h.err}</span>{/if}
        </div>
      {/each}
    </div>
  </div>
{/if}

<div class="card" style="margin-top:14px">
  <div class="card-head">
    <h2>Freigegebene Geräte <span class="muted small">{x.clients.length}</span></h2>
    <button class="btn sm primary" onclick={() => edit()}><Icon name="plus" size={14} /> Gerät freigeben</button>
  </div>
  {#if loaded && !x.clients.length}
    <div class="empty small"><Icon name="lock" size={18} /><p>Noch kein Gerät freigegeben.</p></div>
  {:else}
    <div class="list">
      {#each x.clients as c (c.id)}
        <div class="item" class:off={!c.enabled}>
          <Icon name="laptop" size={18} />
          <div class="grow">
            <div class="line">
              <strong>{c.name}</strong>
              {#each c.addrs as a}<span class="chip mono">{a}</span>{/each}
              {#if !c.addrs.length}<span class="chip">nur DoH/DoT</span>{/if}
              {#if c.learn}<span class="chip" title="Wer per DoH/DoT fragt, darf 24 h auch normales DNS">Adresse merken{c.learned.length ? `: ${c.learned.join(', ')}` : ''}</span>{/if}
            </div>
            {#if T.on && T.host && c.token}
              <div class="links">
                <button class="ipbtn mono" title="DoT – Android „Privates DNS“ (kopieren)" onclick={() => cp(dotHost(c))}><b>DoT</b> {dotHost(c)} <Icon name="copy" size={12} /></button>
                <button class="ipbtn mono" title="DoH – Browser, iOS, Router (kopieren)" onclick={() => cp(dohURL(c))}><b>DoH</b> {dohURL(c)} <Icon name="copy" size={12} /></button>
                <button class="btn sm ghost" title="Neue Kennung (alte Links werden ungültig)" onclick={() => newToken(c)}><Icon name="refresh" size={12} /></button>
              </div>
            {/if}
            <div class="tiny muted sub">
              <span><Icon name="shield" size={12} /> {profName(c.profile)}</span>
              <span>· {fmtNum(c.queries)} Anfragen{#if c.blocked}, <span class="bad-text">{fmtNum(c.blocked)} gesperrt</span>{/if}</span>
              <span>· zuletzt {when(c.last)}</span>
              {#each c.resolved as r}
                <span class={r.err ? 'warn-text' : ''}>· {r.host} → {r.addrs.length ? r.addrs.join(', ') : r.err}</span>
              {/each}
              {#if c.note}<span>· {c.note}</span>{/if}
            </div>
          </div>
          <label class="switch" title={c.enabled ? 'Aktiv' : 'Aus'}><input type="checkbox" checked={c.enabled} onchange={() => toggle(c)} /><span class="track"></span></label>
          <button class="btn sm icon ghost" title="Bearbeiten" onclick={() => edit(c)}><Icon name="edit" size={15} /></button>
          <button class="btn sm icon ghost danger" title="Löschen" onclick={() => remove(c)}><Icon name="trash" size={15} /></button>
        </div>
      {/each}
    </div>
  {/if}
</div>

<div class="card" style="margin-top:14px">
  <div class="card-head">
    <h2>
      Wer fragt von außen?
      <Info title="Absender außerhalb des VPN" text="Alle Adressen außerhalb des VPN, die den Panel-DNS gefragt haben – freigegebene Geräte und fremde (deren Anfragen verworfen werden). Hostname = Rückwärtsauflösung der IP, meist der Anbieter. Die Liste übersteht Neustarts; Einträge älter als 30 Tage verschwinden." />
      <span class="muted small">{x.seen.length}</span>
    </h2>
    <div class="row" style="gap:8px">
      {#if x.seen.length > 8}<SearchInput bind:value={q} placeholder="IP, Host, Domain …" width="220px" />{/if}
      {#if x.seen.length}<button class="btn sm ghost" onclick={() => forget('')}><Icon name="trash" size={14} /> Leeren</button>{/if}
    </div>
  </div>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Absender</th><th>Hostname</th><th>Gerät</th><th class="right">Anfragen</th><th>Zuletzt</th><th>Letzte Domain</th><th></th></tr></thead>
      <tbody>
        {#each seenShown as s (s.addr)}
          <tr>
            <td class="mono small nowrap">{s.addr}</td>
            <td class="small ellipsis hostcell" title={s.host}>{s.host || '–'}</td>
            <td class="nowrap">
              {#if s.client}
                <span class="badge ok"><Icon name="check" size={12} /> {s.client_name || 'freigegeben'}</span>
              {:else}
                <span class="badge bad" title="Anfragen werden verworfen"><Icon name="alert" size={12} /> fremd</span>
              {/if}
            </td>
            <td class="right small">{fmtNum(s.queries)}{#if s.blocked}<div class="tiny bad-text">{fmtNum(s.blocked)} gesperrt</div>{/if}</td>
            <td class="small nowrap muted" title={new Date(s.last * 1000).toLocaleString('de-DE')}>{when(s.last)}<div class="tiny">seit {new Date(s.first * 1000).toLocaleDateString('de-DE')}</div></td>
            <td class="mono tiny ellipsis namecell" title={s.name}>{s.name || '–'}</td>
            <td class="right nowrap">
              {#if !s.client}<button class="btn sm" onclick={() => edit(null, s.addr)}><Icon name="check" size={13} /> Freigeben</button>{/if}
              <button class="btn sm icon ghost" title="Aus der Liste entfernen" onclick={() => forget(s.addr)}><Icon name="x" size={13} /></button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="7" class="muted small" style="padding:20px">{x.public ? 'Noch keine Anfragen von außen.' : 'DNS von außen ist aus.'}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if !showAll && !q && x.seen.length > 50}<div style="text-align:center;padding:10px"><button class="btn sm" onclick={() => (showAll = true)}>Alle {x.seen.length} zeigen</button></div>{/if}
</div>

<Modal bind:open title={f.id ? 'Gerät bearbeiten' : 'Gerät freigeben'} subtitle="Darf den Panel-DNS ohne VPN nutzen" width={560}>
  <div class="stack">
    <div class="field">
      <label for="dx-name">Name</label>
      <input id="dx-name" class="input" bind:value={f.name} maxlength="48" placeholder="z. B. Fernseher Wohnzimmer" />
    </div>
    <div class="field">
      <label for="dx-addrs">Adressen{#if T.on}&nbsp;<span class="muted">(optional bei DoH/DoT)</span>{/if} <Info title="Adressen" text="Öffentliche IP-Adressen (IPv4/IPv6), Netze (höchstens /16 bzw. /48 – bei IPv6 am besten das /64 des Anschlusses) oder DynDNS-Namen. Eine pro Zeile. Für normales DNS (Port 53) nötig; Geräte mit DoH/DoT erkennt das Panel an ihrer Kennung." /></label>
      <textarea id="dx-addrs" class="input mono" rows="3" bind:value={f.addrs} placeholder={'203.0.113.10\n2001:db8:1234:5678::/64\nmeinzuhause.myfritz.net'}></textarea>
    </div>
    <div class="field">
      <label for="dx-prof">Filterprofil</label>
      <select id="dx-prof" class="input" bind:value={f.profile}>
        <option value={0}>Globales Profil{globalProfile ? ` (${globalProfile.name})` : ' – keins vorhanden'}</option>
        {#each d.profiles as p}<option value={p.id}>{p.name}{p.enabled ? '' : ' (aus)'}</option>{/each}
        <option value={-1}>Ohne Filter</option>
      </select>
    </div>
    <div class="field">
      <label for="dx-note">Notiz</label>
      <input id="dx-note" class="input" bind:value={f.note} maxlength="300" placeholder="optional" />
    </div>
    {#if T.on}
      <div class="row" style="gap:6px">
        <label class="switch"><input type="checkbox" bind:checked={f.learn} /><span class="track"></span> Adresse merken</label>
        <Info title="Adresse merken" text="Fragt das Gerät (z. B. Handy oder Router) per DoH/DoT, darf seine öffentliche Adresse 24 Stunden lang auch normales DNS über Port 53 nutzen – praktisch für Fernseher im selben Heimnetz, ohne feste IP. Braucht „DNS von außen“." />
      </div>
    {/if}
    <label class="switch"><input type="checkbox" bind:checked={f.enabled} /><span class="track"></span> Aktiv</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Abbrechen</button>
    <button class="btn primary" onclick={save} disabled={busy || !valid}>Speichern</button>
  {/snippet}
</Modal>

<style>
  .top {
    align-items: start;
  }
  .steps {
    margin: 0;
    padding-left: 20px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .ipbtn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 1px solid var(--border);
    background: var(--panel);
    border-radius: 6px;
    font-size: 12px;
    padding: 1px 7px;
    cursor: pointer;
    color: var(--text);
    margin: 2px 2px 0 0;
  }
  .ipbtn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }
  .list {
    display: flex;
    flex-direction: column;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 16px;
    border-top: 1px solid var(--border);
  }
  .item.off {
    opacity: 0.55;
  }
  .line {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .sub {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 3px;
    align-items: center;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 8px;
    font-size: 12px;
  }
  .mono {
    font-family: var(--mono, ui-monospace, monospace);
  }
  .empty {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 16px;
    color: var(--text-2);
  }
  .empty p {
    margin: 0;
  }
  .hostcell {
    max-width: 220px;
  }
  .namecell {
    max-width: 220px;
  }
  .links {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
    margin-top: 4px;
  }
  .links .ipbtn {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cfbox {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 12px;
  }
  .certline {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
</style>
