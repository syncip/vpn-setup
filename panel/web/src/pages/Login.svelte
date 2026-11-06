<script>
  import Icon from '../components/Icon.svelte';
  import { post } from '../lib/api.js';

  let { onlogin } = $props();
  let username = $state('');
  let password = $state('');
  let code = $state('');
  let needCode = $state(false);
  let err = $state('');
  let busy = $state(false);

  async function submit(e) {
    e.preventDefault();
    busy = true;
    err = '';
    try {
      const r = await post('/auth/login', { username, password, code });
      if (r.need_totp) {
        needCode = true;
      } else {
        onlogin();
      }
    } catch (x) {
      err = x.message;
    }
    busy = false;
  }
</script>

<div class="wrap">
  <form class="card box" onsubmit={submit}>
    <div class="logo"><Icon name="shield" size={26} /></div>
    <h1>VPN-Panel</h1>
    <p class="muted">Bitte anmelden</p>
    {#if !needCode}
      <div class="field">
        <label for="u">Benutzer</label>
        <input id="u" class="input" bind:value={username} autocomplete="username" required />
      </div>
      <div class="field">
        <label for="p">Passwort</label>
        <input id="p" class="input" type="password" bind:value={password} autocomplete="current-password" required />
      </div>
    {:else}
      <div class="field">
        <label for="c">Code aus der Authenticator-App</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input id="c" class="input mono code" bind:value={code} inputmode="numeric" autocomplete="one-time-code" maxlength="8" autofocus required />
      </div>
    {/if}
    {#if err}<div class="notice bad">{err}</div>{/if}
    <button class="btn primary" type="submit" disabled={busy}>{needCode ? 'Bestätigen' : 'Anmelden'}</button>
    {#if needCode}<button type="button" class="btn ghost" onclick={() => { needCode = false; code = ''; }}>Zurück</button>{/if}
  </form>
</div>

<style>
  .wrap {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 16px;
    background: radial-gradient(circle at 30% 20%, var(--accent-soft), transparent 50%), var(--bg);
  }
  .box {
    width: 100%;
    max-width: 380px;
    padding: 32px 28px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .box h1 {
    text-align: center;
  }
  .box p {
    text-align: center;
    margin: -10px 0 6px;
  }
  .logo {
    width: 52px;
    height: 52px;
    border-radius: 14px;
    margin: 0 auto;
    display: grid;
    place-items: center;
    color: #fff;
    background: linear-gradient(135deg, #5b77ff, #3b54d4);
  }
  .code {
    font-size: 20px;
    letter-spacing: 0.3em;
    text-align: center;
    height: 46px;
  }
  .btn {
    height: 40px;
  }
</style>
