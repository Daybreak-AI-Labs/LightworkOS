/* Keys are shown only on a fresh native response; history contains metadata. */
(function () {
  'use strict';
  var page = window.LightworkAccessKeysPage, root = document.getElementById('ak-requests'); if (!page || !root) return;
  var status = document.getElementById('akr-status'), reviewBox = document.getElementById('akr-review'), resultBox = document.getElementById('akr-result');
  var choice = document.getElementById('akr-original'), read = document.getElementById('akr-read'), refresh = document.getElementById('akr-refresh');
  var context = '', generation = 0, busy = false, enabled = false, invalid = false, shownKey = '', storage = 'lightwork-access-key-original';
  var initial = new URL(location.href).searchParams.get('key_request') || ''; if (!/^[a-f0-9]{32}$/.test(initial)) initial = '';
  function node(tag, text, parent) { var n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (parent) parent.append(n); return n; }
  function lock(value) { busy = value; read.disabled = value || !context || !choice.value; refresh.disabled = value; choice.disabled = value; document.querySelectorAll('#ak-form button').forEach(function (button) { button.disabled = value || invalid || !enabled; }); document.querySelectorAll('#ak-keys button,#ak-sa-list button').forEach(function (button) { button.disabled = value || invalid; }); }
  function clear() { generation++; context = ''; invalid = true; shownKey = ''; page.clear(); reviewBox.replaceChildren(); resultBox.replaceChildren(); var empty = node('option', 'Choose an original request'); empty.value = ''; choice.replaceChildren(empty); status.textContent = 'Your account or access changed. Reload Access keys before continuing. Nothing was repeated.'; lock(false); }
  async function request(path, body) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 20000);
    try {
      var response = await fetch('/api/v1/access-key-requests' + path, {method:body ? 'POST' : 'GET', credentials:'same-origin',cache:'no-store',
        headers:{'Content-Type':'application/json'},body:body ? JSON.stringify(body) : undefined,signal:controller.signal});
      var raw = await response.text(); if (raw.length > 16777216) throw new Error('The complete key list exceeds its supported display limit. Nothing was changed.');
      var value; try { value = JSON.parse(raw); } catch (_) { value = {}; }
      if (!response.ok || response.redirected) { var error = new Error(window.mvPlainDetail ? window.mvPlainDetail(value.detail) || 'This request could not be confirmed. Read its original record.' : typeof value.detail === 'string' ? value.detail : 'This request could not be confirmed.'); error.authority = response.redirected || response.status === 401 || response.status === 403; throw error; }
      if (context && value.context !== context) { var changed = new Error('Your account or workspace changed.'); changed.authority = true; throw changed; }
      return value;
    } finally { clearTimeout(timer); }
  }
  function fail(error) { if (error.authority) clear(); else status.textContent = error.name === 'AbortError' ? 'The reply was interrupted. Read the original record; no key will be issued again automatically.' : error.message; }
  function select(operation, label) { if (!Array.from(choice.options).some(function (o) { return o.value === operation; })) { var option = node('option', label, choice); option.value = operation; } choice.value = operation; }
  function accept(state) {
    context = state.context; enabled = state.enabled;
    var all = state.keys.concat((state.service_accounts || []).flatMap(function (account) { return account.keys; }));
    if (shownKey && !all.some(function (key) { return key.id === shownKey; })) { shownKey = ''; page.clearSecret(); }
    page.accept(state);
    var selected = choice.value || initial, pending; initial = '';
    try { pending = JSON.parse(sessionStorage.getItem(storage) || 'null'); } catch (_) { pending = null; }
    if (!selected && pending && pending.context === context) selected = pending.operation;
    choice.replaceChildren(); var empty = node('option', 'Choose an original request', choice); empty.value = '';
    state.requests.forEach(function (row) { var option = node('option', row.label, choice); option.value = row.value; });
    if (/^[a-f0-9]{32}$/.test(selected || '')) select(selected, 'Original request retained in this browser');
    status.textContent = state.enabled ? state.notice : 'New access keys are turned off. Your original records remain readable; current keys may be reviewed for revocation.';
  }
  async function reload() {
    if (busy || invalid) return false; var started = ++generation; lock(true);
    try { var state = await request(new URL(location.href).searchParams.get('all') ? '?all=1' : ''); if (started !== generation) return false; accept(state); return true; }
    catch (error) { if (started === generation) fail(error); return false; }
    finally { if (started === generation) lock(false); }
  }
  function result(value) {
    resultBox.replaceChildren(); node('p', value.message, resultBox); node('p', value.notice, resultBox);
    if (value.current_key) {
      var key = value.current_key; node('p', 'Current key: ' + key.label + '. Its current state is separate from the original record.', resultBox);
      if (['active','expiring','rotating'].includes(key.status)) { var revoke = node('button', 'Review revocation of this current key', resultBox); revoke.className = 'btn btn--danger'; revoke.type = 'button'; revoke.addEventListener('click', function () { review('revoke', key.id); }); }
    }
    status.textContent = value.confirmed ? 'The original change is confirmed. The secret is not part of this history.' : 'The original change remains unconfirmed. Nothing will be repeated automatically.';
  }
  async function original() {
    if (busy || invalid || !context || !choice.value) return; var started = ++generation; lock(true); root.open = true; reviewBox.replaceChildren();
    try { var value = await request('/requests/' + choice.value); if (started === generation) result(value); }
    catch (error) { if (started === generation) fail(error); }
    finally { if (started === generation) lock(false); }
  }
  function reviewValues(rows) {
    if (!Array.isArray(rows) || rows.length !== 8) throw new Error('This complete review could not be displayed. No key was changed.');
    rows.forEach(function (row) {
      if (!row || typeof row.label !== 'string' || !Object.prototype.hasOwnProperty.call(row,'after')) throw new Error('This complete review could not be displayed. No key was changed.');
      node('h4', row.label, reviewBox); var value = row.after;
      if (Array.isArray(value)) { var list = node('ul', undefined, reviewBox); value.forEach(function (item) { if (typeof item !== 'string') throw new Error('This complete permission review is unavailable.'); node('li', item, list); }); }
      else { var text = node('p', value === null ? 'Not applicable' : value, reviewBox); text.style.whiteSpace = 'pre-wrap'; text.style.overflowWrap = 'anywhere'; }
    });
  }
  async function review(action, keyId) {
    if (busy || invalid || !context) return; var started = ++generation, body = {context:context,action:action}; root.open = true; lock(true); reviewBox.replaceChildren();
    if (action === 'create') { body.label = document.getElementById('ak-label').value; body.scopes = Array.from(document.querySelectorAll('#ak-scope-boxes input:checked')).map(function (f) { return f.value; }); body.workspace = document.getElementById('ak-workspace').value; var days = document.getElementById('ak-days').value; if (days) body.expires_in_days = Number(days); var owner = document.getElementById('ak-owner').value; if (owner) body.owner = owner; }
    else body.key_id = keyId;
    try {
      var checked = await request('/review', body); if (started !== generation) return; reviewValues(checked.changes);
      var label = node('label', undefined, reviewBox), consent = node('input', undefined, label); label.style.display = 'flex'; label.style.gap = 'var(--space-2)'; label.style.alignItems = 'flex-start'; label.style.marginBlock = 'var(--space-3)'; consent.type = 'checkbox'; consent.style.flexShrink = '0'; label.append(document.createTextNode('I reviewed this complete key change.'));
      var actions = node('div', undefined, reviewBox); actions.style.display = 'flex'; actions.style.flexWrap = 'wrap'; actions.style.gap = 'var(--space-2)';
      var apply = node('button', action === 'revoke' ? 'Revoke reviewed key' : action === 'rotate' ? 'Issue reviewed replacement' : 'Issue reviewed key', actions); apply.type = 'button'; apply.className = action === 'revoke' ? 'btn btn--danger' : 'btn btn--primary'; apply.disabled = true;
      consent.addEventListener('change', function () { apply.disabled = busy || !consent.checked; });
      apply.addEventListener('click', async function () {
        if (busy || !consent.checked || started !== generation) return;
        try { sessionStorage.setItem(storage, JSON.stringify({context:context,operation:checked.operation})); } catch (_) { status.textContent = 'This browser could not retain the original request. Allow site storage first; no key was submitted.'; return; }
        select(checked.operation, 'Original request just reviewed'); lock(true); apply.disabled = true; page.clearSecret(); shownKey = '';
        try {
          var value = await request('/apply', {token:checked.token,confirmed:true}); if (started !== generation) return;
          var fresh = await request(''); if (started !== generation) return; accept(fresh); reviewBox.replaceChildren(); result(value);
          var allowed = fresh.keys.concat((fresh.service_accounts || []).flatMap(function (account) { return account.keys; }));
          if (value.secret && value.key && allowed.some(function (key) { return key.id === value.key.id; })) { shownKey = value.key.id; page.showSecret(value); }
        } catch (error) { if (started === generation) { reviewBox.replaceChildren(); fail(error); } }
        finally { if (started === generation) lock(false); }
      });
      var cancel = node('button', 'Cancel this review', actions); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', function () { if (!busy) { reviewBox.replaceChildren(); status.textContent = 'Review cancelled. Entered work and current keys were kept.'; } });
      status.textContent = 'Nothing has changed. Confirm this exact reviewed request once.'; reviewBox.scrollIntoView({block:'start'}); consent.focus();
    } catch (error) { if (started === generation) { reviewBox.replaceChildren(); fail(error); } }
    finally { if (started === generation) lock(false); }
  }
  document.getElementById('ak-form').addEventListener('submit', function (event) { event.preventDefault(); review('create'); });
  document.getElementById('ak-form').addEventListener('input', function () { if (!busy && reviewBox.childElementCount) { generation++; reviewBox.replaceChildren(); status.textContent = 'Your choices changed. Review the current form again; nothing was changed.'; } });
  choice.addEventListener('change', original); read.addEventListener('click', original); refresh.addEventListener('click', reload);
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (event.detail && event.detail.reason === 'selection') { if (!busy) { reviewBox.replaceChildren(); reload(); } } else clear(); });
  window.addEventListener('lightwork:context-changed', clear);
  window.LightworkAccessKeys = {review:review,reload:reload,open:async function (expected, originals, isCurrent) {
    if (busy || invalid || !/^[a-f0-9]{64}$/.test(expected) || (isCurrent && !isCurrent())) return false;
    var started = generation;
    try { var state = await request(''); if (started !== generation || (isCurrent && !isCurrent()) || state.context !== expected) return false; accept(state); root.open = originals; var target = originals ? choice : document.getElementById('ak-label'); if (isCurrent && !isCurrent()) return false; target.scrollIntoView({block:'center'}); target.focus(); lock(false); return document.activeElement === target; }
    catch (error) { if (started === generation) fail(error); return false; }
  }};
  lock(false); reload().then(function (loaded) { if (loaded && choice.value) original(); });
})();
