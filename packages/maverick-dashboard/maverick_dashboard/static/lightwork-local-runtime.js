(() => {
  'use strict';
  const root = document.getElementById('la-root');
  if (!root) return;
  const el = id => document.getElementById('la-' + id), base = '/api/v1/admin/local-ai';
  const states = {running: 'Program running', stopped: 'Server stopped', unknown: 'Status needs attention'};
  const receipts = {unknown: 'Result unknown', started: 'Start accepted', stopped: 'Stopped', saved: 'Settings saved', waiting: 'Awaiting approval', refused: 'Not applied'};
  const actions = {start: 'Start', stop: 'Stop', configure: 'Settings'};
  let current = null, busy = false, review = null, origin = null, uncertain = null, dirty = false;
  function note(text) { el('status').textContent = text; }
  async function call(path = '', data) {
    const response = await fetch(base + path, {method: data ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
      headers: data ? {'Content-Type': 'application/json'} : {}, body: data ? JSON.stringify(data) : undefined});
    let value;
    try { value = await response.json(); } catch (_) { throw new Error('The response could not be read. Refresh or check the saved request.'); }
    if (!response.ok) { const error = new Error(typeof value.detail === 'string' ? value.detail : value.message || 'This request could not be completed. Refresh current status.'); error.status = response.status; throw error; }
    return value;
  }
  function controls() {
    const ready = !!current && !busy;
    el('start').disabled = !ready || !current.can_start || !!uncertain;
    el('stop').disabled = !ready || !current.can_stop;
    el('health').disabled = !ready || current.state === 'stopped';
    ['engine', 'resource', 'allow', 'save'].forEach(id => { el(id).disabled = !ready || !current.models.length || !!uncertain; });
    el('refresh').disabled = busy;
    el('confirm').disabled = busy || !review || !el('confirm-check').checked;
  }
  function remember() {
    try { if (uncertain) sessionStorage.setItem('lightwork-local-ai-request', JSON.stringify(uncertain)); else sessionStorage.removeItem('lightwork-local-ai-request'); } catch (_) { /* Saved history remains available without browser storage. */ }
  }
  function render(state, preserveDraft) {
    const changed = current && current.context !== state.context;
    const retain = preserveDraft && dirty && !changed;
    const draftKept = retain && current && current.settings_revision !== state.settings_revision;
    if (current && current.revision !== state.revision) el('health-result').textContent = 'Starting a program does not establish model readiness or answer quality. Check health before use.';
    current = state;
    if (changed) { dirty = false; review = null; uncertain = null; el('review').close(); el('receipt').textContent = ''; remember(); }
    el('state').textContent = states[state.state] || 'Status unavailable';
    el('message').textContent = state.message;
    el('program').textContent = state.engine || 'Choose a program';
    el('model').textContent = state.model || 'Choose an available local model';
    el('enabled').textContent = state.enabled ? 'Allowed' : 'Turned off';
    el('blocked').hidden = !state.blocked;
    el('blocked').textContent = state.blocked;
    const previous = retain ? el('resource').value : state.model_choice;
    el('resource').replaceChildren();
    for (const item of state.models) { const option = document.createElement('option'); option.value = item.value; option.textContent = item.label; el('resource').append(option); }
    if (!state.models.length) { const option = document.createElement('option'); option.value = ''; option.textContent = 'No supported local models available'; el('resource').append(option); }
    if (state.models.some(item => item.value === previous)) el('resource').value = previous;
    if (!retain) { el('engine').value = state.engine_choice; el('allow').checked = state.enabled; }
    el('requests').replaceChildren();
    if (!state.requests.length) { const item = document.createElement('li'); item.textContent = 'You have no saved local AI requests in this workspace.'; el('requests').append(item); }
    for (const item of state.requests) {
      const row = document.createElement('li'), button = document.createElement('button'); button.type = 'button'; button.className = 'btn btn--ghost';
      button.textContent = `${actions[item.action]} · ${new Date(item.at * 1000).toLocaleString()} · ${receipts[item.state]}`;
      button.addEventListener('click', () => inspect(item.id)); row.append(button); el('requests').append(row);
    }
    if (uncertain && uncertain.context !== state.context) { uncertain = null; remember(); }
    controls();
    return draftKept;
  }
  async function refresh(preserveDraft = true) {
    busy = true; controls();
    try { const kept = render(await call(), preserveDraft); note(kept ? 'Current settings changed. Your unsaved choices were kept; review them before saving.' : 'Current local AI status refreshed.'); }
    catch (error) { current = null; review = null; el('review').close(); note(error.message); }
    finally { busy = false; controls(); }
  }
  async function inspect(id) {
    if (busy || !current) return;
    const context = current.context; busy = true; controls();
    try {
      const saved = await call('/requests/' + encodeURIComponent(id));
      const latest = await call();
      if (latest.context !== context) { render(latest, false); note('Your account or workspace changed. Open a current saved request.'); return; }
      el('receipt').textContent = `${receipts[saved.state]}: ${saved.message}`;
      if (uncertain && uncertain.id === id && (saved.state !== 'unknown' || latest.state === 'stopped')) { uncertain = null; remember(); }
      render(latest, true);
    } catch (error) {
      if (error.status === 404 && uncertain && uncertain.id === id) { uncertain = null; remember(); document.getElementById('la-check-original')?.remove(); }
      note(error.message);
    }
    finally { busy = false; controls(); }
  }
  async function prepare(action, extra = {}) {
    if (busy || !current || (uncertain && action !== 'stop')) return;
    const context = current.context; busy = true; controls(); origin = document.activeElement;
    try {
      const prepared = await call('/review', {context, revision: current.revision, action, ...extra});
      if (!current || current.context !== context) throw new Error('Your account or workspace changed. Review current local AI again.');
      review = prepared; el('review-summary').textContent = prepared.summary; el('confirm-check').checked = false; el('review').showModal(); el('confirm-check').focus();
    } catch (error) { note(error.message); }
    finally { busy = false; controls(); }
  }
  el('form').addEventListener('submit', event => { event.preventDefault(); prepare('configure', {enabled: el('allow').checked, engine: el('engine').value, model: el('resource').value}); });
  ['engine', 'resource', 'allow'].forEach(id => el(id).addEventListener('change', () => { dirty = true; }));
  el('start').addEventListener('click', () => prepare('start'));
  el('stop').addEventListener('click', () => prepare('stop'));
  el('refresh').addEventListener('click', () => refresh());
  el('confirm-check').addEventListener('change', controls);
  el('review').addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  el('review').addEventListener('close', () => { review = null; el('confirm-check').checked = false; if (origin && origin.isConnected) origin.focus(); controls(); });
  el('confirm').addEventListener('click', async () => {
    if (busy || !review || !current || !el('confirm-check').checked) return;
    const prepared = review, context = current.context;
    uncertain = {id: prepared.request_id, context}; remember(); busy = true; controls(); el('cancel').disabled = true;
    try {
      const saved = await call('/execute', {token: prepared.token, confirmed: true});
      if (saved.action === 'configure' && saved.state === 'saved') dirty = false;
      if (saved.state !== 'unknown') { uncertain = null; remember(); }
      note(saved.message); el('receipt').textContent = `${receipts[saved.state]}: ${saved.message}`;
    } catch (error) {
      if (error.status === 409 || error.status === 422) { uncertain = null; remember(); note(error.message); }
      else note(error.message + ' Check the original saved request below; Lightwork will not repeat it automatically.');
    }
    finally { busy = false; el('cancel').disabled = false; el('review').close(); controls(); }
    try { render(await call(), true); } catch (error) { note(error.message); }
    if (uncertain && current && uncertain.context === current.context) addRecovery();
  });
  function addRecovery() {
    if (!uncertain || document.getElementById('la-check-original')) return;
    const button = document.createElement('button'); button.id = 'la-check-original'; button.className = 'btn btn--ghost'; button.type = 'button'; button.textContent = 'Check original request';
    button.addEventListener('click', async () => { if (!uncertain) return; await inspect(uncertain.id); if (!uncertain) button.remove(); });
    el('receipt').after(button);
  }
  el('health').addEventListener('click', async () => {
    if (busy || !current) return;
    busy = true; controls();
    try { const result = await call('/health'); el('health-result').textContent = result.message; }
    catch (error) { el('health-result').textContent = error.message; }
    finally { busy = false; controls(); }
  });
  el('copilot').addEventListener('click', () => {
    const button = document.getElementById('mv-copilot-fab');
    if (button && button.getAttribute('aria-expanded') !== 'true') button.click(); else if (!button) note('Open Copilot from the workspace toolbar to choose the local AI controls.');
  });
  document.addEventListener('lightwork:product-operation-complete', event => {
    if (String((event.detail || {}).operation || '').startsWith('local_ai.') && !busy && !review) refresh();
  });
  try {
    const stored = JSON.parse(sessionStorage.getItem('lightwork-local-ai-request'));
    if (stored && /^[a-f0-9]{32}$/.test(stored.id) && /^[a-f0-9]{64}$/.test(stored.context)) uncertain = stored;
  } catch (_) { /* Current native request history is the authority. */ }
  refresh(false).then(() => { if (uncertain && current) { note('An earlier response was interrupted. Check the original request before another change.'); addRecovery(); } });
})();
