'use strict';
(function () {
  const host = document.getElementById('approval-challenges');
  if (!host) return;
  const byId = name => document.getElementById('ac-' + name);
  const generate = byId('generate'), imported = byId('import'), choice = byId('choice');
  const family = generate.elements.namedItem('family'), quorum = generate.elements.namedItem('quorum');
  const file = imported.elements.namedItem('file'), status = byId('status'), review = byId('review');
  const download = byId('download'), recover = byId('recover');
  const storage = 'lightwork:approval-challenge-original';
  let state = null, current = null, busy = false, generation = 0, refreshQueued = false, pending = null, offset = 0;
  const active = new Set();
  try { pending = JSON.parse(sessionStorage.getItem(storage) || 'null'); } catch (_) { /* Saved receipt discovery remains available. */ }
  function savePending(value) {
    pending = value;
    try { if (value) sessionStorage.setItem(storage, JSON.stringify(value)); else sessionStorage.removeItem(storage); } catch (_) { /* Private browser storage may be unavailable. */ }
  }
  function clear() { current = null; review.hidden = true; download.hidden = true; download.removeAttribute('href'); }
  function lock(value) {
    busy = value;
    host.querySelectorAll('button,select,input').forEach(item => { item.disabled = value; });
    if (!value) {
      generate.querySelector('button').disabled = !state?.enabled || !family.value || Boolean(pending);
      imported.querySelector('button').disabled = !state?.enabled || !file.files?.length || Boolean(pending);
      byId('setup').hidden = !state?.can_configure;
      byId('read').disabled = !choice.value;
      recover.hidden = !pending;
      byId('check').disabled = !current?.can_check || Boolean(pending && pending.id !== current.id);
      byId('export').disabled = !current?.can_export;
      byId('newer').hidden = state?.previous == null;
      byId('older').hidden = state?.next == null;
      if (refreshQueued) { refreshQueued = false; void refresh(); }
    }
  }
  async function request(path, body) {
    const controller = new AbortController(), deadline = setTimeout(() => controller.abort(), 20000);
    active.add(controller);
    try {
      const response = await fetch('/api/v1/learning/approval-challenges' + path, {
        method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal,
        headers: {'Accept': 'application/json', ...(body ? {'Content-Type': 'application/json'} : {})},
        body: body ? JSON.stringify(body) : undefined,
      });
      const reader = response.body.getReader(), chunks = []; let size = 0;
      try {
        for (;;) {
          const piece = await reader.read(); if (piece.done) break;
          size += piece.value.length;
          if (size > 128 * 1024) { await reader.cancel(); throw new Error('The saved result exceeded its display allowance. Refresh and choose a record.'); }
          chunks.push(piece.value);
        }
      } finally { reader.releaseLock(); }
      const bytes = new Uint8Array(size); let start = 0;
      chunks.forEach(chunk => { bytes.set(chunk, start); start += chunk.length; });
      let value;
      try { value = JSON.parse(new TextDecoder().decode(bytes)); } catch (_) { throw new Error('The saved result could not be read. Read the original operation before continuing.'); }
      if (!response.ok) {
        const refusal = new Error(typeof value.detail === 'string' ? value.detail : 'The challenge could not be checked. Review its saved state.');
        refusal.status = response.status;
        throw refusal;
      }
      return value;
    } catch (error) {
      if (controller.signal.aborted) throw new Error('The connection ended before its saved result could be read. Read the original operation; no check will be repeated.');
      throw error;
    } finally { clearTimeout(deadline); active.delete(controller); }
  }
  function display(value) {
    clear(); current = value; review.hidden = false;
    byId('title').textContent = value.title;
    byId('origin').textContent = value.source + ' · ' + value.origin + ' · ' + value.when + ' · ' + value.quorum + ' required sign-off' + (value.quorum === 1 ? '' : 's');
    byId('result').textContent = value.status + '. ' + value.explanation;
    byId('steps').replaceChildren(); value.steps.forEach(step => { const item = document.createElement('li'); item.textContent = step; byId('steps').appendChild(item); });
    byId('bounds').textContent = value.bounds + ' The corrected practice explored ' + value.model_states + ' possible situations within its bound.';
    byId('limit').textContent = value.limitations;
    byId('check').hidden = !value.can_check; byId('export').hidden = !value.can_export;
    byId('remove').hidden = !value.can_remove;
    byId('resolve').hidden = !value.can_resolve; download.hidden = !value.download_ready;
    if (value.download_ready) download.href = '/api/v1/learning/approval-challenges/' + encodeURIComponent(value.id) + '/download';
  }
  async function refresh(selected) {
    if (busy) { refreshQueued = true; return; }
    const chosen = selected || choice.value || new URLSearchParams(location.search).get('record') || '', previousFamily = family.value, ticket = ++generation;
    clear(); lock(true);
    try {
      const value = await request('?offset=' + offset);
      if (ticket !== generation) return;
      state = value;
      if (pending && pending.context !== value.context) savePending(null);
      family.replaceChildren(new Option('Choose a change to explore', ''));
      value.patterns.forEach(row => family.appendChild(new Option(row.label, row.value, false, row.value === previousFamily)));
      choice.replaceChildren(new Option('Choose a saved challenge', ''));
      value.records.forEach(row => choice.appendChild(new Option(row.title + ' · ' + row.when + ' · ' + row.status, row.id, false, row.id === chosen)));
      byId('setting').textContent = value.enabled ? 'Local approval challenges are on. Checks and sharing need separate review.' : 'Local approval challenges are off. An installation administrator can turn them on here.';
      byId('setup').textContent = value.enabled ? 'Turn local challenges off' : 'Turn local challenges on';
      byId('page').textContent = value.total ? 'Showing ' + (value.offset + 1) + '–' + Math.min(value.offset + 40, value.total) + ' of ' + value.total + ' saved challenges.' : 'No saved challenge yet.';
      status.textContent = pending ? 'An original check needs its saved result. Read that operation before starting another check.' : value.detail;
    } catch (error) {
      state = null; family.replaceChildren(new Option('Refresh to check available changes', '')); choice.replaceChildren(new Option('Refresh to check saved records', ''));
      status.textContent = error.message;
    } finally { lock(false); }
  }
  async function inspect(identity) {
    if (busy || !state) return;
    const selected = identity || choice.value; if (!selected) return;
    const ticket = ++generation, context = state.context;
    clear(); lock(true);
    try {
      const value = await request('/' + encodeURIComponent(selected));
      if (ticket === generation && value.context === context) {
        if (value.removed) { clear(); status.textContent = value.detail; if (pending?.id === selected) savePending(null); return; }
        display(value); status.textContent = value.status;
        if (pending?.id === selected && value.state !== 'checking' && (pending.action !== 'check' || value.receipts.check === pending.operation)) savePending(null);
      }
    } catch (error) { clear(); status.textContent = error.message + (pending ? ' The original operation is still saved for readback; starting another check is blocked.' : ''); }
    finally { lock(false); }
  }
  async function mutate(path, body, prompt, identity, tracked) {
    if (busy || !state) return;
    const context = state.context, ticket = generation;
    let submitted = false, refused = false, result, failure;
    lock(true);
    try {
      const okText = {'': 'Build challenge', '/import': 'Review this file', '/setup': body.enabled ? 'Allow challenges' : 'Stop challenges'}[path]
        || {check: 'Check scenario', export: 'Authorize sharing', resolve: 'Mark as unknown', remove: 'Remove practice'}[path.split('/').pop()] || 'Save this change';
      if (!window.mvConfirm || !await window.mvConfirm(prompt, {okText}) || ticket !== generation || state?.context !== context) return;
      submitted = true; clear();
      if (tracked) savePending({id: identity, context, operation: body.operation, action: path.endsWith('/check') ? 'check' : path === '/import' ? 'import' : 'generate'});
      result = await request(path, {...body, context, confirm: true});
    } catch (error) {
      failure = error;
      // The server turned a new challenge or file away before saving anything (a full
      // list, a file it does not support): there is no original to read back, so the
      // pending marker must not keep this page from trying again.
      refused = submitted && tracked && (path === '' || path === '/import') && error.status >= 400 && error.status < 500;
      if (refused) savePending(null);
      else if (submitted && state?.context === context) {
        try {
          if (identity) {
            const checked = await request('/' + encodeURIComponent(identity));
            const action = ['check', 'export', 'resolve', 'remove'].find(name => path.endsWith('/' + name));
            if (checked.context === context && action === 'remove' && checked.removed && checked.receipt === body.operation) result = {removed: true, detail: checked.detail};
            else if (checked.context === context && (!action || checked.receipts?.[action] === body.operation)) result = {record: checked, detail: checked.status + '. The original saved state was read after the response was lost. No check or export was repeated.'};
          } else {
            const checked = await request('?offset=' + offset);
            if (checked.context === context && checked.enabled === body.enabled) result = {detail: 'The effective local challenge setting was read. No change was repeated.'};
          }
        } catch (_) { /* Original operation remains blocked until actual readback. */ }
      }
    } finally { lock(false); }
    if (!submitted || ticket !== generation || state?.context !== context) return;
    if (result?.record && pending?.id === result.record.id && result.record.state !== 'checking' && (pending.action !== 'check' || result.record.receipts.check === pending.operation)) savePending(null);
    if (result?.record) {
      display(result.record); status.textContent = result.detail; lock(false);
      // Fresh detail rechecks both authority and installed code. Never revive
      // controls or assurances from the earlier mutation response.
      await refresh(result.record.id);
      if (state?.context === context) await inspect(result.record.id);
    } else if (result) { await refresh(); status.textContent = result.detail; }
    else { status.textContent = failure.message + (refused ? '' : ' Its outcome may be recorded. Read the original saved operation before another check.'); lock(false); }
  }
  const operation = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
  generate.addEventListener('submit', event => {
    event.preventDefault(); if (!family.value || pending) return;
    const id = operation();
    void mutate('', {operation: id, family: family.value, quorum: Number(quorum.value)},
      'Build a fictional challenge for “' + family.selectedOptions[0].textContent + '” with ' + quorum.value + ' required sign-off(s), and check it in a disposable local copy? No real request, customer credential, paid AI call, live safeguard or export is involved. This selected modeled check does not prove complete protection.', 'ACP-' + id, true);
  });
  imported.addEventListener('submit', async event => {
    event.preventDefault(); if (busy || pending || !file.files?.length) return;
    const selected = file.files[0], ticket = generation;
    if (!selected.size || selected.size > 8192) { status.textContent = 'Choose a challenge file within the 8 KB limit.'; return; }
    try {
      const bytes = new Uint8Array(await selected.arrayBuffer());
      if (ticket !== generation || file.files[0] !== selected) return;
      const encoded = btoa(String.fromCharCode(...bytes)), id = operation();
      await mutate('/import', {operation: id, file: encoded}, 'Review this small challenge file as a supported practice file? Uploaded code, custom instructions and customer data are not accepted. Nothing runs until you separately confirm its local check.', 'ACP-' + id, true);
    } catch (_) { status.textContent = 'This selected file could not be read. Choose it again.'; }
    finally { file.value = ''; if (!busy) lock(false); }
  });
  byId('setup').addEventListener('click', () => {
    if (state) void mutate('/setup', {previous: state.enabled, enabled: !state.enabled}, state.enabled ? 'Stop creating and checking local approval challenges? Existing evidence remains reviewable.' : 'Allow fictional approval models and isolated local checks on this installation? Checks and exact exports still need separate consent. No live request or live safeguard is changed.', null, false);
  });
  function selectedAction(action, prompt, tracked) {
    if (current) void mutate('/' + encodeURIComponent(current.id) + '/' + action, {revision: current.revision, operation: action === 'remove' ? current.receipts.remove || operation() : operation()}, prompt, current.id, tracked);
  }
  byId('check').addEventListener('click', () => selectedAction('check', 'Check this exact imported practice scenario against this installation’s approval safeguards? This check uses fresh disposable databases, no customer settings or credentials, no network and at most 10 seconds. Nothing is activated in production.', true));
  byId('export').addEventListener('click', () => selectedAction('export', 'Authorize sharing this exact practice scenario and required sign-off count? The shared file contains only declared limits, sequence and checks that refuse outdated sign-offs. It includes no customer incident, account, workspace, request identity, private values, local timings or installation’s software details. A recipient must review and check it separately. No live approval rule is activated.', false));
  byId('resolve').addEventListener('click', () => selectedAction('resolve', 'Mark the interrupted original check as unknown? No check is repeated and no current protection is claimed.', false));
  byId('remove').addEventListener('click', () => selectedAction('remove', 'Remove this inactive saved practice and its local result to make room for another practice? Its decision receipt stays in the activity history. Files you previously shared are not recalled. A check in progress cannot be removed.', false));
  byId('read').addEventListener('click', () => void inspect());
  recover.addEventListener('click', () => { if (pending) void inspect(pending.id); });
  byId('refresh').addEventListener('click', async () => { await refresh(); if (pending && state) await inspect(pending.id); });
  byId('older').addEventListener('click', () => { if (state?.next != null) { offset = state.next; void refresh(); } });
  byId('newer').addEventListener('click', () => { if (state?.previous != null) { offset = state.previous; void refresh(); } });
  family.addEventListener('change', () => lock(false)); file.addEventListener('change', () => lock(false));
  choice.addEventListener('change', () => { ++generation; clear(); lock(false); });
  window.addEventListener('lightwork:product-state-changed', () => void refresh());
  document.addEventListener('lightwork:product-operation-complete', () => void refresh());
  document.addEventListener('lightwork:account-context-changed', () => {
    ++generation; active.forEach(controller => controller.abort()); clear(); state = null; file.value = ''; savePending(null); offset = 0;
    if (busy) refreshQueued = true; else void refresh();
  });
  window.addEventListener('pagehide', () => { active.forEach(controller => controller.abort()); clear(); file.value = ''; });
  void refresh().then(() => { if (pending && state) void inspect(pending.id); else if (new URLSearchParams(location.search).has('record') && state) void inspect(new URLSearchParams(location.search).get('record')); });
})();
