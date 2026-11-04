(function () {
  'use strict';
  const root = document.querySelector('[data-company-migration]');
  if (!root) return;
  const recovery = root.hasAttribute('data-recovery');
  const find = name => root.querySelector('[data-' + name + ']');
  const choice = find('migration-choice'), password = find('owner-password'), code = find('owner-code');
  const message = find('migration-message'), reviewHost = find('migration-full-review');
  const confirmation = find('migration-confirm'), ack = find('migration-ack');
  const originals = find('migration-original'), originalPanel = find('migration-original-panel');
  let context = '', reviewed = null, busy = false, generation = 0, abort = null, pending = '';
  const storageKey = 'lightwork.company-signin.pending';
  try { pending = sessionStorage.getItem(storageKey) || ''; } catch (_) { /* Native history remains available. */ }
  function say(text, error) { message.textContent = text; message.setAttribute('role', error ? 'alert' : 'status'); }
  function invalidate() {
    reviewed = null; ack.checked = false; confirmation.hidden = true;
    reviewHost.hidden = true; reviewHost.replaceChildren(); find('migration-apply').disabled = true;
  }
  function lock(value) {
    busy = value;
    ['migration-load', 'migration-review', 'migration-apply', 'migration-read-original'].forEach(name => {
      const control = find(name);
      control.disabled = value || (name === 'migration-review' && !choice.value) || (name === 'migration-apply' && (!reviewed || !ack.checked));
    });
  }
  // Ends the proof of an unfinished review on the server; a failure here changes nothing the owner can see.
  function endProof() {
    fetch(recovery ? '/auth/company-signin-recovery/cancel' : '/api/v1/settings/sign-in-migration/cancel',
      { method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' }).catch(() => {});
  }
  function credentials() {
    if (!password.reportValidity()) throw new Error('Enter this computer\'s original owner passphrase.');
    const email = find('owner-email');
    if (email && !email.reportValidity()) throw new Error('Enter the original owner\'s email.');
    return { email: email ? email.value.trim() : '', password: password.value, code: code.value.trim() };
  }
  function stamp() { return JSON.stringify([choice.value, password.value, code.value, recovery ? find('owner-email').value : '', context]); }
  function remember(operation) {
    pending = operation;
    try { sessionStorage.setItem(storageKey, operation); } catch (_) { /* Native history remains available. */ }
    addOriginal(operation, 'Latest submitted request');
  }
  function addOriginal(value, label) {
    if (!/^[a-f0-9]{32}$/.test(value)) return;
    let option = Array.from(originals.options).find(item => item.value === value);
    if (!option) { option = document.createElement('option'); option.value = value; originals.append(option); }
    option.textContent = label; originals.value = value; originalPanel.hidden = false;
  }
  async function request(url, body) {
    abort = new AbortController();
    const timer = setTimeout(() => abort && abort.abort(), 20000);
    try {
      const response = await fetch(url, { method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: abort.signal,
        headers: body ? { 'Content-Type': 'application/json', Accept: 'application/json' } : { Accept: 'application/json' }, body: body ? JSON.stringify(body) : undefined });
      if (!(response.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) throw new Error('The sign-in response could not be verified. No request was repeated.');
      const reader = response.body.getReader(); const chunks = []; let size = 0;
      for (;;) { const next = await reader.read(); if (next.done) break; size += next.value.length;
        if (size > 262144) { await reader.cancel(); throw new Error('This complete response is too large. No request was repeated.'); } chunks.push(next.value); }
      const bytes = new Uint8Array(size); let position = 0; chunks.forEach(chunk => { bytes.set(chunk, position); position += chunk.length; });
      const result = JSON.parse(new TextDecoder().decode(bytes));
      if (!response.ok) {
        const error = new Error(typeof result.detail === 'string' ? result.detail.slice(0, 2000) : 'The sign-in request was refused. Keep your choices and read the original result if a save was submitted.');
        error.status = response.status; throw error;
      }
      return result;
    } finally { clearTimeout(timer); abort = null; }
  }
  function clearPrivate() {
    generation++; if (abort) abort.abort(); invalidate(); choice.replaceChildren(); choice.disabled = true;
    password.value = ''; code.value = ''; const email = find('owner-email'); if (email) email.value = '';
    if (!recovery) { find('preset-directory').value = ''; find('preset-application').value = ''; }
    originals.replaceChildren(); originalPanel.hidden = true; context = ''; find('migration-next').hidden = true;
    lock(false); say('Your account or access changed. Private choices were cleared; sign in again before continuing.', true);
  }
  function failure(error) {
    if (error.status === 401 || error.status === 403) { clearPrivate(); say(error.message, true); }
    else say(error.message || 'The reply was interrupted. No request was repeated. Read the original result if a save was submitted.', true);
  }
  async function load() {
    if (busy) return; const started = generation; invalidate(); lock(true);
    try {
      const result = await request(recovery ? '/auth/company-signin-recovery/lookup' : '/api/v1/settings/sign-in-migration', recovery ? credentials() : undefined);
      if (started !== generation) return;
      if (!recovery && context && context !== result.context) { clearPrivate(); return; }
      if (!recovery) context = result.context;
      const selected = choice.value; const rows = recovery ? result.requests.filter(row => row.kind === 'activation') : result.checks;
      const placeholder = document.createElement('option'); placeholder.value = ''; placeholder.textContent = rows.length ? 'Choose a dated sign-in' : 'No current verified choices';
      choice.replaceChildren(placeholder); rows.forEach(row => { const option = document.createElement('option'); option.value = row.value; option.textContent = row.label; choice.append(option); });
      if (rows.some(row => row.value === selected)) choice.value = selected;
      choice.disabled = !rows.length;
      result.requests.forEach(row => addOriginal(row.value, row.label)); if (pending) addOriginal(pending, 'Last submitted request');
      say(rows.length ? 'Choose the sign-in to review. No settings have changed.' : 'Try company sign-in before activation, or keep the original owner sign-in while setup is incomplete.');
    } catch (error) { if (started === generation) failure(error); } finally { if (started === generation) lock(false); }
  }
  async function review() {
    if (busy || !choice.value) return; const started = generation; const formStamp = stamp(); lock(true); invalidate();
    try {
      const creds = credentials();
      const result = await request(recovery ? '/auth/company-signin-recovery/review' : '/api/v1/settings/sign-in-migration/review', recovery ? { ...creds, operation: choice.value } : { check: choice.value, password: creds.password, code: creds.code, context });
      if (started !== generation) return;
      if (formStamp !== stamp() || (!recovery && result.context !== context)) { say('Your choices changed while the review loaded. Keep them and review again.', true); return; }
      Object.entries(result.changes).forEach(([label, value]) => { const field = document.createElement('div'); field.className = 'mv-field';
        const heading = document.createElement('strong'); heading.textContent = label; const text = document.createElement('p'); text.textContent = value; field.append(heading, text); reviewHost.append(field); });
      const notice = document.createElement('p'); notice.textContent = result.notice; reviewHost.append(notice);
      reviewed = { ...result, stamp: formStamp }; reviewHost.hidden = false; confirmation.hidden = false;
      say('Read the complete change, then confirm it. Nothing has been changed yet.'); ack.focus();
    } catch (error) { if (started === generation) failure(error); } finally { if (started === generation) lock(false); }
  }
  async function apply() {
    if (busy || !reviewed || !ack.checked) return;
    if (reviewed.stamp !== stamp()) { invalidate(); say('Your choices changed. Review them again before saving.', true); return; }
    const started = generation, saved = reviewed; lock(true); remember(saved.operation);
    try {
      const body = recovery ? { ...credentials(), token: saved.token, confirmed: true } : { token: saved.token, confirmed: true };
      const result = await request(recovery ? '/auth/company-signin-recovery/apply' : '/api/v1/settings/sign-in-migration/activate', body);
      if (started !== generation) return; invalidate(); say(result.message, !result.confirmed);
      if (result.confirmed) { password.value = ''; code.value = ''; find('migration-next').hidden = false;
        if (recovery) say(result.message + ' Enter the owner passphrase again for another original-result lookup.'); }
    } catch (error) { if (started === generation) { invalidate(); failure(error); } } finally { if (started === generation) lock(false); }
  }
  async function readOriginal() {
    if (busy || !originals.value) return; const started = generation; lock(true);
    try {
      const result = await request(recovery ? '/auth/company-signin-recovery/original' : '/api/v1/settings/sign-in-migration/original/' + originals.value + '?context=' + encodeURIComponent(context), recovery ? { ...credentials(), operation: originals.value } : undefined);
      if (started !== generation) return; say(result.message, !result.confirmed);
    } catch (error) { if (started === generation) failure(error); } finally { if (started === generation) lock(false); }
  }
  find('migration-load').addEventListener('click', load); find('migration-review').addEventListener('click', review);
  find('migration-apply').addEventListener('click', apply); find('migration-read-original').addEventListener('click', readOriginal);
  find('migration-cancel').addEventListener('click', () => { invalidate(); endProof(); say('Review cancelled. No sign-in change was submitted.'); });
  if (!recovery) {
    const provider = find('preset-provider'), directory = find('preset-directory'), application = find('preset-application'), prepare = find('preset-prepare');
    provider.addEventListener('change', () => {
      const google = provider.value === 'google'; directory.hidden = google; directory.required = !google;
      find('preset-directory-label').hidden = google;
      find('preset-directory-label').textContent = provider.value === 'okta' ? "Okta organization's HTTPS address" : 'Microsoft Directory ID';
    });
    prepare.addEventListener('click', async () => {
      if (busy || !application.reportValidity() || (!directory.hidden && !directory.reportValidity())) return;
      const started = generation, entered = JSON.stringify([provider.value, directory.value, application.value]);
      lock(true); prepare.disabled = true; invalidate();
      try {
        const fresh = await request('/api/v1/settings/sign-in-migration/context');
        if (started !== generation || context && context !== fresh.context) { if (started === generation) clearPrivate(); return; }
        context = fresh.context;
        const result = await request('/api/v1/settings/sign-in-migration/preset', {provider: provider.value, directory: directory.value.trim(), application: application.value.trim(), context});
        const active = () => started === generation && entered === JSON.stringify([provider.value, directory.value, application.value]);
        if (!active()) return;
        if (!window.stageCompanySigninDraft || !await window.stageCompanySigninDraft(result.values, context, active)) {
          if (active()) say('The preset was not inserted. Keep entered Settings work; review or cancel those drafts before preparing a preset.', true);
          return;
        }
        if (active()) say(result.notice);
      } catch (error) { if (started === generation) failure(error); }
      finally { if (started === generation) { lock(false); prepare.disabled = false; } }
    });
  }
  choice.addEventListener('change', () => { invalidate(); lock(busy); }); password.addEventListener('input', invalidate);
  code.addEventListener('input', invalidate);
  if (recovery) find('owner-email').addEventListener('input', invalidate);
  ack.addEventListener('change', () => lock(busy));
  ['workspace-changed', 'account-context-changed'].forEach(name => document.addEventListener('lightwork:' + name, clearPrivate));
  window.addEventListener('lightwork:copilot-context-changed', clearPrivate);
  document.addEventListener('lightwork:copilot-context-changed', event => {
    if (event.detail && event.detail.reason === 'selection') { invalidate(); return; } clearPrivate();
  });
  window.LightworkCompanySigninMigration = {
    async open(expected, original, isCurrent) {
      if (recovery || busy || typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected) || typeof original !== 'boolean') return false;
      const started = generation, previous = stamp();
      try {
        const result = await request('/api/v1/settings/sign-in-migration/context');
        if (started !== generation || (isCurrent && !isCurrent()) || previous !== stamp() || result.context !== expected) return false;
        if (context && context !== result.context) { clearPrivate(); return false; }
        context = result.context; root.scrollIntoView({ block: 'start', behavior: 'smooth' });
        (original && !originalPanel.hidden ? find('migration-read-original') : password).focus();
        return true;
      } catch (error) { if (started === generation) failure(error); return false; }
    }
  };
  if (pending) addOriginal(pending, 'Last submitted request');
}());
