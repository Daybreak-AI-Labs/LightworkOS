/* Complete native agent removal/reset; uncertainty reads the original request. */
(function () {
  'use strict';
  var root = document.getElementById('agent-override-change'); if (!root) return;
  var status = document.getElementById('aoc-status'), reviewBox = document.getElementById('aoc-review'), resultBox = document.getElementById('aoc-result');
  var choice = document.getElementById('aoc-original'), readButton = document.getElementById('aoc-read'), refresh = document.getElementById('aoc-refresh');
  var context = '', generation = 0, busy = false, editing = false, invalidEditor = false, storageKey = 'lightwork-agent-override-change';
  var initial = new URL(location.href).searchParams.get('agent_change'); if (!/^[a-f0-9]{32}$/.test(initial || '')) initial = '';
  function node(tag, text, parent) {
    var value = document.createElement(tag); if (text !== undefined) value.textContent = text;
    if (tag === 'ul') { value.style.listStyle = 'none'; value.style.paddingInline = '0'; value.style.marginInline = '0'; }
    if (tag === 'dd') { value.style.marginInline = '0'; value.style.minWidth = '0'; }
    if (tag === 'dt') { value.style.fontWeight = '600'; value.style.marginBlockStart = '0.6rem'; }
    if (parent) parent.append(value); return value;
  }
  function lock(value) {
    busy = value; readButton.disabled = value || !choice.value; refresh.disabled = value; choice.disabled = value;
    document.querySelectorAll('[data-agent-change]').forEach(function (button) { button.disabled = value || !context || !editing || invalidEditor; });
  }
  function clearAuthority() {
    generation++; context = ''; invalidEditor = true; reviewBox.replaceChildren(); resultBox.replaceChildren(); var empty = node('option', 'Choose an original change'); empty.value = ''; choice.replaceChildren(empty);
    var form = document.getElementById('agent-form'); if (form) { form.querySelectorAll('input,textarea,select').forEach(function (field) { field.value = ''; }); form.hidden = true; }
    status.textContent = 'Your account or access changed. Reload Agent Factory before continuing. Nothing was repeated.'; lock(false);
  }
  async function request(path, body) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 20000);
    try {
      var response = await fetch('/api/v1/agent-override-changes' + path, {method:body ? 'POST' : 'GET', credentials:'same-origin', cache:'no-store',
        headers:{'Content-Type':'application/json'}, body:body ? JSON.stringify(body) : undefined, signal:controller.signal});
      var text = await response.text(); if (text.length > 2097152) throw new Error('The complete review is too large to display. Nothing was changed.');
      var value; try { value = JSON.parse(text); } catch (_) { value = {}; }
      if (!response.ok || response.redirected) { var error = new Error(window.mvPlainDetail ? window.mvPlainDetail(value.detail) || 'This change could not be confirmed. Read the original result.' : typeof value.detail === 'string' ? value.detail : 'This change could not be confirmed. Read the original result.'); error.authority = response.redirected || response.status === 401 || response.status === 403; throw error; }
      if (context && value.context !== context) { var changed = new Error('Your account or workspace changed.'); changed.authority = true; throw changed; }
      return value;
    } finally { clearTimeout(timer); }
  }
  function failure(error) { if (error.authority) clearAuthority(); else status.textContent = error.name === 'AbortError' ? 'The reply was interrupted. Read the original result; nothing will be changed again automatically.' : error.message; }
  function selected(operation, label) { if (!Array.from(choice.options).some(function (option) { return option.value === operation; })) { var option = node('option', label, choice); option.value = operation; } choice.value = operation; }
  function show(result) {
    if (result.context !== context) { clearAuthority(); return; }
    resultBox.replaceChildren(); node('p', result.message, resultBox); if (result.current) node('p', result.current, resultBox); node('p', result.notice, resultBox);
    if (result.name) { var current = !!result.current_generation; var link = node('a', current ? 'Open the latest saved definition' : 'Open Agent Factory', resultBox); link.href = current ? '/agents?name=' + encodeURIComponent(result.name) : '/agents'; }
    status.textContent = result.confirmed ? 'The original change is confirmed. Your entered editor work was kept; current settings are separate.' : 'The original change is unconfirmed. Read current settings separately; nothing will be repeated automatically.';
  }
  async function load() {
    if (busy) return; var started = ++generation, selectedValue = choice.value || initial; initial = ''; lock(true);
    try {
      var state = await request(''); if (started !== generation) return; context = state.context; editing = state.editing;
      var pending; try { pending = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch (_) { pending = null; }
      if (pending && pending.context === context && /^[a-f0-9]{32}$/.test(pending.operation)) selectedValue = selectedValue || pending.operation;
      choice.replaceChildren(); var empty = node('option', 'Choose an original change', choice); empty.value = '';
      state.requests.forEach(function (row) { var option = node('option', row.label, choice); option.value = row.value; });
      if (selectedValue) selected(selectedValue, 'Original request retained in this browser'); status.textContent = state.notice;
    } catch (error) { if (started === generation) failure(error); }
    finally { if (started === generation) lock(false); }
  }
  async function readOriginal() {
    if (busy || !context || !choice.value) return; var started = ++generation, operation = choice.value; lock(true); reviewBox.replaceChildren(); root.open = true;
    try { var result = await request('/requests/' + encodeURIComponent(operation)); if (started === generation) show(result); }
    catch (error) { if (started === generation) failure(error); }
    finally { if (started === generation) lock(false); }
  }
  function renderReview(changes) {
    var remaining = 10000;
    function append(host, value, depth) {
      if (--remaining < 0 || depth > 16) throw new Error('This complete definition exceeds the display limit. Shorten it in the ordinary editor before trying again.');
      if (Array.isArray(value)) { if (!value.length) { node('p', 'None', host); return; } var list = node('ul', undefined, host); value.forEach(function (item) { append(node('li', undefined, list), item, depth + 1); }); }
      else if (value && typeof value === 'object') { var list = node('dl', undefined, host); Object.entries(value).forEach(function (entry) { node('dt', entry[0], list); append(node('dd', undefined, list), entry[1], depth + 1); }); }
      else { var text = node('p', value === null || value === undefined || value === '' ? 'Not specified' : typeof value === 'boolean' ? value ? 'Yes' : 'No' : value, host); text.style.whiteSpace = 'pre-wrap'; text.style.overflowWrap = 'anywhere'; }
    }
    if (!Array.isArray(changes) || !changes.length) throw new Error('The complete current definition could not be displayed. Nothing was changed.');
    changes.forEach(function (change) { if (!change || typeof change.label !== 'string' || !Object.prototype.hasOwnProperty.call(change, 'after')) throw new Error('This complete review is unavailable. Nothing was changed.'); node('h4', change.label, reviewBox); append(reviewBox, change.after, 0); });
  }
  async function review(name, action) {
    if (busy || !context || !editing || invalidEditor) return; var started = ++generation; lock(true); reviewBox.replaceChildren(); root.open = true;
    try {
      var checked = await request('/review', {name:name, action:action, context:context}); if (started !== generation) return;
      node('h3', checked.source_kind === 'damaged' ? 'Review discard of this exact damaged saved setup' : action === 'remove_custom' ? 'Review removal of this custom agent' : 'Review reset to the built-in definition', reviewBox); renderReview(checked.changes);
      var label = node('label', undefined, reviewBox), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode(checked.source_kind === 'damaged' ? ' I understand the saved instructions are unavailable and reviewed discarding this exact damaged setup and its effect.' : ' I reviewed the complete definition and its effect.'));
      var apply = node('button', action === 'remove_custom' ? 'Remove reviewed custom agent' : 'Reset reviewed definition', reviewBox); apply.type = 'button'; apply.className = 'btn btn--danger'; apply.disabled = true;
      consent.addEventListener('change', function () { apply.disabled = busy || !consent.checked; });
      apply.addEventListener('click', async function () {
        if (busy || !consent.checked || started !== generation) return;
        try { sessionStorage.setItem(storageKey, JSON.stringify({context:context, operation:checked.operation})); } catch (_) { status.textContent = 'This browser could not retain the original request. Allow site storage first; nothing was submitted.'; return; }
        selected(checked.operation, 'Original change just reviewed'); lock(true); apply.disabled = true; status.textContent = 'Submitting this reviewed change once. Current editor work is kept.';
        try { var result = await request('/apply', {token:checked.token, confirmed:true}); if (started === generation) { reviewBox.replaceChildren(); show(result); } }
        catch (error) { if (started === generation) { reviewBox.replaceChildren(); failure(error); } }
        finally { if (started === generation) lock(false); }
      });
      var cancel = node('button', 'Cancel this review', reviewBox); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', function () { if (!busy) { reviewBox.replaceChildren(); status.textContent = 'Review cancelled. The saved definition and entered editor work were kept.'; } });
      status.textContent = 'Nothing has changed. Review the full saved definition; unsaved editor changes are separate.'; reviewBox.scrollIntoView({block:'start'}); consent.focus();
    } catch (error) { if (started === generation) { reviewBox.replaceChildren(); failure(error); } }
    finally { if (started === generation) lock(false); }
  }
  document.querySelectorAll('[data-agent-change]').forEach(function (button) { button.addEventListener('click', function () { review(button.dataset.agentChange, button.dataset.agentChangeAction); }); });
  choice.addEventListener('change', readOriginal); readButton.addEventListener('click', readOriginal); refresh.addEventListener('click', load);
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (event.detail && event.detail.reason === 'selection') { if (!busy) { reviewBox.replaceChildren(); load(); } } else { clearAuthority(); load(); } });
  window.addEventListener('lightwork:context-changed', function () { clearAuthority(); load(); });
  window.LightworkAgentOverrideChanges = {review:review}; lock(false); load().then(function () { if (!busy && context && choice.value) readOriginal(); });
})();
