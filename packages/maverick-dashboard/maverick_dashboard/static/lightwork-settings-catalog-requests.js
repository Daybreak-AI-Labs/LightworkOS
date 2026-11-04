/* Protected settings custody: only opaque original identities survive reload. */
(function () {
  'use strict';
  var root = document.getElementById('settings-all-groups');
  if (!root) return;
  var expected = root.dataset.requestContext, panel = document.getElementById('settings-original-requests');
  var choice = document.getElementById('settings-original-choice'), status = document.getElementById('settings-original-status');
  var read = document.getElementById('settings-original-read'), refresh = document.getElementById('settings-original-refresh');
  var previous = document.getElementById('settings-original-previous'), next = document.getElementById('settings-original-next');
  var page = document.getElementById('settings-original-page'), offset = 0, nextOffset = null;
  var API = '/api/v1/settings/catalog-requests', generation = 0, current = true, busy = false;
  var key = 'lightwork:settings-original:' + expected, pending = '';
  try { pending = sessionStorage.getItem(key) || ''; } catch (_) { /* Server history also retains the original. */ }
  if (!/^[a-f0-9]{32}$/.test(pending)) pending = '';
  function say(text) { window.mvStatus ? window.mvStatus(status, text) : (status.textContent = text); }
  function clear() {
    current = false; generation += 1; choice.replaceChildren(new Option('Reload Settings to use this account', '')); read.disabled = true;
    pending = ''; previous.disabled = next.disabled = refresh.disabled = true; page.textContent = '';
    say('Your account, workspace or access changed. Private settings work was cleared; reload this page.');
    root.replaceChildren();
    document.querySelectorAll('dialog.settings-review').forEach(function (dialog) { dialog.dispatchEvent(new Event('cancel', {cancelable: true})); });
  }
  async function call(path, body, ticket) {
    if (!current) throw new Error('Reload Settings before continuing.');
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 20000);
    try {
      var response = await fetch(path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/json', Accept: 'application/json'}, signal: controller.signal,
        body: body ? JSON.stringify(body) : undefined});
      if (response.redirected || response.status === 401 || response.status === 403) {
        clear(); throw new Error('Your account, workspace or access changed. Private settings work was cleared; reload Settings.');
      }
      var text = await response.text(); if (text.length > 2097152) throw new Error('This complete response is too large. Keep your draft and review fewer settings together.');
      var data = JSON.parse(text);
      if (response.status === 409 && !data.conflicts && /account|workspace|access changed/.test(String(data.detail || data.message))) {
        clear(); throw new Error('Your account, workspace or access changed. Private settings work was cleared; reload Settings.');
      }
      if (!current || ticket !== generation || (data.context && data.context !== expected) || (data.original && data.original.context !== expected)) {
        clear(); throw new Error('Private settings from a changed account cannot be displayed. Reload Settings.');
      }
      return {response: response, data: data};
    } catch (failure) {
      if (failure.name === 'AbortError') throw new Error('Reading this request timed out. Your draft and original request were kept. No automatic retry was made.');
      throw failure;
    } finally { clearTimeout(timer); }
  }
  async function inventory(isCurrent, wanted) {
    var ticket = generation, result = await call(API + '?context=' + encodeURIComponent(expected) + '&offset=' + (wanted === undefined ? offset : wanted), null, ticket);
    if (!result.response.ok) throw new Error(result.data.detail || 'Original requests could not be read. Your draft is kept.');
    if (isCurrent && !isCurrent()) return false;
    var selected = choice.value || pending;
    choice.replaceChildren(new Option('Choose a request', ''));
    result.data.requests.forEach(function (item) { choice.add(new Option(item.label, item.value)); });
    if (pending && !Array.from(choice.options).some(function (item) { return item.value === pending; })) choice.add(new Option('Last reviewed original request', pending));
    choice.value = selected; read.disabled = !choice.value; offset = result.data.offset; nextOffset = result.data.next_offset;
    previous.disabled = offset === 0; next.disabled = nextOffset === null;
    page.textContent = result.data.total ? 'Showing ' + (offset + 1) + '–' + Math.min(offset + 100, result.data.total) + ' of ' + result.data.total + ' retained requests.' : 'No original requests are kept for this account and workspace. Requests you send from Settings appear here.';
    return true;
  }
  function remember(plan) {
    pending = plan.operation; choice.add(new Option('Last reviewed request', pending)); choice.value = pending; read.disabled = false;
    try { sessionStorage.setItem(key, pending); } catch (_) { /* The server history remains available. */ }
    say('Saving this original reviewed request. An interrupted response must be checked before a new decision.');
  }
  function outcome(value) {
    say(value.message + (value.recorded_at ? ' Recorded ' + new Date(value.recorded_at * 1000).toLocaleString() + '.' : '') +
      (value.restart ? ' Check configuration status for required service restarts.' : '') + (value.current ? ' ' + value.current : '') +
      (value.settings && value.settings.length ? ' Requested settings: ' + value.settings.join('; ') + '.' : ''));
  }
  async function readOriginal() {
    if (!choice.value || busy || !current) return;
    busy = true; read.disabled = true;
    try {
      var result = await call(API + '/' + choice.value + '?context=' + encodeURIComponent(expected), null, generation);
      if (!result.response.ok) throw new Error(result.data.detail || 'This original request could not be read. Nothing was repeated.');
      outcome(result.data);
    } catch (failure) { say(failure.message); }
    finally { busy = false; read.disabled = !current || !choice.value; }
  }
  choice.addEventListener('change', function () { read.disabled = !current || !choice.value; });
  read.addEventListener('click', readOriginal);
  refresh.addEventListener('click', async function () {
    if (busy) return; busy = true; refresh.disabled = true;
    try { await inventory(); say('Original requests refreshed. Your current editable choices were kept.'); }
    catch (failure) { say(failure.message); }
    finally { busy = false; refresh.disabled = !current; }
  });
  async function changePage(wanted) {
    if (busy || !current) return; busy = true; previous.disabled = next.disabled = true;
    try { await inventory(null, wanted); }
    catch (failure) { say(failure.message); }
    finally { busy = false; previous.disabled = !current || offset === 0; next.disabled = !current || nextOffset === null; }
  }
  previous.addEventListener('click', function () { changePage(Math.max(0, offset - 100)); });
  next.addEventListener('click', function () { if (nextOffset !== null) changePage(nextOffset); });
  async function verify() {
    try { await inventory(); } catch (failure) { if (current) say(failure.message); }
  }
  document.addEventListener('lightwork:copilot-context-changed', verify);
  window.addEventListener('lightwork:copilot-context-changed', clear);
  window.addEventListener('lightwork:draft-context-changed', clear);
  window.LightworkSettingsCatalog = {
    review: async function (changes, revision) {
      var result = await call(API + '/review', {changes: changes, expected_revision: revision, context: expected}, generation);
      if (!result.response.ok) { var failure = new Error(result.data.message || result.data.detail || 'This change could not be reviewed. Your draft is kept.'); failure.status = result.response.status; failure.data = result.data; throw failure; }
      return result.data;
    },
    save: async function (plan) {
      if (!current || plan.context !== expected || !/^[a-f0-9]{32}$/.test(plan.operation || '')) throw new Error('Review the current settings before saving.');
      remember(plan);
      try {
        var result = await call('/api/v1/settings/catalog', {changes: plan.changes, expected_revision: plan.revision, reviewed_token: plan.token, confirm: true}, generation);
        if (result.data.original) outcome(result.data.original);
        return result;
      } catch (failure) { if (current) say('The response was interrupted. Read the original result; your draft is kept and nothing will be repeated automatically.'); throw failure; }
    },
    open: async function (context, original, isCurrent) {
      if (!current || context !== expected || root.dataset.saving === '1' || busy) return false;
      var ticket = generation;
      try {
        if (!await inventory(isCurrent) || ticket !== generation || !current || (isCurrent && !isCurrent())) return false;
        var target = original ? choice : document.getElementById('settings-all-search');
        if (!target || !target.isConnected) return false;
        target.scrollIntoView({block: 'center'}); target.focus(); return true;
      } catch (failure) { if (current) say(failure.message); return false; }
    }
  };
  verify();
})();
