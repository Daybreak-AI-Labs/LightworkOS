'use strict';
(function () {
  const host = document.getElementById('installation-security'); if (!host) return;
  const byId = id => document.getElementById('is-' + id), base = '/api/v1/admin/installation-security';
  let state = null, review = null, busy = false, generation = 0, queued = false, pending = null;
  const controllers = new Set(), storage = 'lightwork:installation-policy-original';
  try { pending = JSON.parse(sessionStorage.getItem(storage) || 'null'); } catch (_) { /* Server retains latest attempt. */ }
  function save(value) { pending = value; try { if (value) sessionStorage.setItem(storage, JSON.stringify(value)); else sessionStorage.removeItem(storage); } catch (_) { /* Native readback still works. */ } }
  function invalidate() { review = null; byId('review-panel').hidden = true; }
  function lock(value) {
    busy = value; host.querySelectorAll('input,select,textarea,button').forEach(item => { item.disabled = value; });
    if (!value) {
      const row = selected(); byId('review').disabled = !row || row.locked || !!pending;
      byId('apply').disabled = !review || !!pending;
      if (row?.locked) byId('value').querySelectorAll('input,select,textarea').forEach(item => { item.disabled = true; });
      if (queued) { queued = false; void refresh(); }
    }
  }
  async function request(path, body) {
    const controller = new AbortController(), deadline = setTimeout(() => controller.abort(), 20000); controllers.add(controller);
    try {
      const response = await fetch(base + path, {method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal,
        headers: {'Accept': 'application/json', ...(body ? {'Content-Type': 'application/json'} : {})}, ...(body ? {body: JSON.stringify(body)} : {})});
      const text = await response.text(); if (text.length > 160000) throw new Error('The policy response is too large. Refresh before changing anything.');
      const value = JSON.parse(text); if (!response.ok) throw new Error(value.detail || value.message || 'The installation refused this request.'); return value;
    } finally { clearTimeout(deadline); controllers.delete(controller); }
  }
  function selected() { return state?.rows.find(row => row.id === byId('policy').value); }
  function groupOf(row) { return row.id.startsWith('auth.') ? 'signin' : row.id.startsWith('containment.') ? 'lockdown' : 'work'; }
  function choices(keep) {
    byId('policy').replaceChildren(new Option('Choose a policy', ''));
    state.rows.filter(row => groupOf(row) === byId('group').value).forEach(row => byId('policy').appendChild(new Option(row.label + (row.locked ? ' · fixed by policy' : ''), row.id, false, row.id === keep)));
    field();
  }
  function field() {
    invalidate(); byId('value').replaceChildren(); byId('inherit').checked = false;
    const row = selected(); byId('current').textContent = row ? row.value_text + ' · ' + row.source_text : '';
    byId('help').textContent = row?.help || '';
    if (!row) { lock(false); return; }
    const label = document.createElement('label'); label.textContent = row.control === 'secret' ? 'New protected value (never shown again)' : 'New choice';
    label.htmlFor = 'is-input'; let control;
    if (row.control === 'select' || row.control === 'multiselect') {
      control = document.createElement('select'); control.multiple = row.control === 'multiselect';
      row.choices.forEach(item => control.appendChild(new Option(item.label, String(item.value), false, row.control === 'multiselect' ? (row.value || []).includes(String(item.value)) : String(row.value ?? '') === String(item.value))));
    } else if (row.control === 'list') {
      control = document.createElement('textarea'); control.rows = 4; control.value = (row.value || []).join('\n'); label.textContent = 'One choice per line';
    } else {
      control = document.createElement('input'); control.type = row.control === 'toggle' ? 'checkbox' : row.control === 'number' ? 'number' : row.control === 'secret' ? 'password' : 'text';
      if (row.control === 'toggle') control.checked = row.value === true;
      else control.value = row.control === 'secret' ? '' : row.value ?? '';
      if (row.control === 'secret') { control.autocomplete = 'new-password'; control.dataset.private = 'true'; }
      if (row.control === 'number') { if (row.minimum != null) control.min = row.minimum; if (row.maximum != null) control.max = row.maximum; control.step = row.step; }
    }
    control.id = 'is-input'; control.className = 'input'; if (row.max_length) control.maxLength = row.max_length;
    control.addEventListener('input', invalidate); label.appendChild(control); byId('value').appendChild(label); if (!busy) lock(false);
  }
  function valueOf(row) {
    const control = byId('input');
    if (row.control === 'toggle') return control.checked;
    if (row.control === 'number') return control.value === '' ? null : Number(control.value);
    if (row.control === 'multiselect') return Array.from(control.selectedOptions, item => item.value);
    if (row.control === 'list') return control.value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
    return control.value;
  }
  async function refresh() {
    if (busy) { queued = true; return; }
    const keep = byId('policy').value, ticket = ++generation; invalidate(); lock(true);
    try {
      const current = await request(''); if (ticket !== generation) return; state = current;
      if (pending?.context !== state.context) save(null);
      if (!pending && state.latest_attempt && ['unconfirmed', 'applying', 'unknown'].includes(state.latest_attempt.status)) save({...state.latest_attempt, context: state.context});
      const summary = byId('summary'); summary.replaceChildren();
      const workName = {local:'This computer',docker:'Docker container',podman:'Podman container',gvisor:'Stronger container isolation',kubernetes:'Company cluster',ssh:'Remote computer',devcontainer:'Project work area',firecracker:'Separate small machine',modal:'Cloud work area'}[current.summary.work_area] || 'Specialist work area';
      ['Work area chosen: ' + workName + (current.summary.container_required ? ' · isolated work required' : ''),
       'Company sign-in: ' + (current.summary.company_signin === null ? 'unknown (its settings could not be read)' : current.summary.company_signin ? 'on' : 'off') + (current.summary.company_login_configured ? ' · local browser details complete' : ' · browser setup incomplete'),
       'Single sign-on: ' + (current.summary.single_signon_configured ? 'local details complete' : 'setup incomplete') + (current.summary.single_signon_support ? '' : ' · optional support unavailable')].forEach(text => { const item = document.createElement('p'); item.textContent = text; summary.appendChild(item); });
      byId('notice').textContent = current.notice; choices(keep);
      byId('try-signin').hidden = !(current.summary.company_login_configured || current.summary.single_signon_configured);
      byId('signin-link').href = current.summary.company_login_configured ? '/auth/login?return_to=%2Fsettings%2Fsecurity-installation' : '/saml/login';
      byId('attempt').hidden = !pending; byId('status').textContent = pending ? 'Read the original attempt before another change.' : 'Current policy read from its controlling sources.';
    } catch (error) { state = null; invalidate(); byId('policy').replaceChildren(new Option('Refresh to read current policy', '')); byId('status').textContent = error.message; }
    finally { lock(false); }
  }
  async function readAttempt() {
    if (busy || !state || !pending) return;
    const ticket = generation, context = state.context; lock(true);
    try {
      const result = await request('/attempt/' + pending.operation); if (ticket !== generation || state?.context !== context) return;
      byId('attempt-message').textContent = result.message;
      byId('acknowledge').hidden = !['unconfirmed', 'applying', 'unknown'].includes(result.status);
      if (!['unconfirmed', 'applying', 'unknown'].includes(result.status)) save(null);
      byId('status').textContent = result.message;
    } catch (error) { byId('status').textContent = error.message + ' The original attempt is retained; no policy write was repeated.'; }
    finally { lock(false); }
  }
  byId('form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !state || pending) return; const row = selected(); if (!row || row.locked) return;
    const ticket = generation, context = state.context; invalidate(); lock(true);
    try {
      const result = await request('/review', {context, revision: state.revision, setting: row.id, value: valueOf(row), inherit: byId('inherit').checked});
      if (ticket !== generation || state?.context !== context) return; review = result;
      byId('changes').replaceChildren(); result.changes.forEach(item => { const line = document.createElement('p'); line.textContent = item.label + ': ' + item.before + ' → ' + item.after; byId('changes').appendChild(line); });
      byId('warnings').replaceChildren(); result.warnings.forEach(text => { const item = document.createElement('li'); item.textContent = text; byId('warnings').appendChild(item); });
      byId('review-panel').hidden = false; byId('status').textContent = result.message;
      if (row.control === 'secret') byId('input').value = '';
    } catch (error) { byId('status').textContent = error.message; }
    finally { lock(false); }
  });
  byId('apply').addEventListener('click', async () => {
    if (busy || !state || !review || pending) return; const saved = review, ticket = generation, context = state.context; lock(true); let sent = false;
    try {
      if (!window.mvConfirm || !await window.mvConfirm('Apply exactly the policy shown in this review? Sign-in and independent approval safeguards still apply.', {okText: 'Apply this policy'}) || ticket !== generation) return;
      save({operation: saved.operation, context}); sent = true; invalidate(); byId('attempt').hidden = false;
      const result = await request('/apply', {token: saved.token, confirmed: true});
      if (ticket !== generation || state?.context !== context) return;
      byId('attempt-message').textContent = result.message; byId('status').textContent = result.message;
      if (!['unconfirmed', 'unknown', 'applying'].includes(result.status)) save(null);
      byId('acknowledge').hidden = !pending;
    } catch (error) { byId('status').textContent = error.message + (sent ? ' Read the saved original result; this change will not be submitted again.' : ''); }
    finally { lock(false); if (sent) { await refresh(); if (pending) await readAttempt(); } }
  });
  byId('acknowledge').addEventListener('click', async () => {
    if (busy || !pending || !state) return; const original = pending, ticket = generation; lock(true);
    try {
      if (!window.mvConfirm || !await window.mvConfirm('I have reviewed current policy and Activity. Record my review without claiming the earlier change succeeded or repeating it.', {okText: 'Record my review'}) || ticket !== generation) return;
      const result = await request('/attempt/review', {context: state.context, operation: original.operation, confirmed: true});
      if (ticket !== generation || state?.context !== original.context) return;
      byId('attempt-message').textContent = result.message; if (result.status !== 'unconfirmed') save(null);
    } catch (error) { byId('status').textContent = error.message; } finally { lock(false); await refresh(); }
  });
  host.querySelectorAll('[data-check]').forEach(button => button.addEventListener('click', async () => {
    if (busy || !state) return; const ticket = generation; lock(true);
    try { const result = await request('/check/' + button.dataset.check, {}); if (ticket === generation) byId('check-status').textContent = result.message; }
    catch (error) { byId('check-status').textContent = error.message; } finally { lock(false); }
  }));
  byId('group').addEventListener('change', () => choices()); byId('policy').addEventListener('change', field); byId('inherit').addEventListener('change', invalidate);
  byId('discard').addEventListener('click', invalidate); byId('refresh').addEventListener('click', refresh); byId('read-attempt').addEventListener('click', readAttempt);
  document.addEventListener('lightwork:product-operation-complete', refresh); window.addEventListener('lightwork:product-state-changed', refresh);
  window.addEventListener('lightwork:draft-context-changed', () => { generation++; controllers.forEach(item => item.abort()); state = null; invalidate(); save(null); queued = true; if (!busy) void refresh(); });
  void refresh();
}());
