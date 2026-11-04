(function () {
  'use strict';
  const API = '/api/v1/specialist-drafts';
  const first = ['Decision', 'Complete draft', 'Currently used definition', 'AI used for answer checks'];
  const last = ['Limits and consequences', 'If the response is lost'];
  const optional = ['Selected tool services', 'Tool-service limits', 'Fictional sample request', 'Every saved question and passing condition', 'Publication tests', 'Reason for publishing without a complete passing check', 'Earlier unconfirmed decisions'];
  function node(tag, text, parent) { const value = document.createElement(tag); if (text !== undefined) value.textContent = text; if (parent) parent.append(value); return value; }
  function display(parent, value, limits, depth) {
    if (--limits.nodes < 0 || depth > 12) throw new Error('The complete specialist review exceeds its supported display limit. Nothing can be confirmed.');
    if (Array.isArray(value)) {
      if (!value.length) { node('p', 'None entered', parent); return; }
      const list = node('ul', undefined, parent);
      value.forEach(item => display(node('li', undefined, list), item, limits, depth + 1));
    } else if (value && typeof value === 'object') {
      const list = node('dl', undefined, parent);
      Object.entries(value).forEach(([key, item]) => { if (--limits.nodes < 0) throw new Error('The complete specialist review is unavailable.'); node('dt', key, list); display(node('dd', undefined, list), item, limits, depth + 1); });
    } else if (value === null || value === '') node('span', 'None entered', parent);
    else if (['string', 'number', 'boolean'].includes(typeof value)) node('span', typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value), parent);
    else throw new Error('The complete specialist review contains an unsupported value.');
  }
  function renderReview(host, changes) {
    if (!Array.isArray(changes) || changes.length < 6 || changes.length > 13 || JSON.stringify(changes).length > 1200000 ||
        changes.some(row => !row || Object.keys(row).sort().join('|') !== 'after|label' || typeof row.label !== 'string') ||
        first.some((label, index) => changes[index].label !== label) || last.some((label, index) => changes[changes.length - 2 + index].label !== label) ||
        changes.slice(4, -2).some(row => !optional.includes(row.label)) || new Set(changes.map(row => row.label)).size !== changes.length) {
      throw new Error('The complete specialist review is unavailable. Nothing can be confirmed.');
    }
    const fragment = document.createDocumentFragment(), limits = {nodes: 8192};
    changes.forEach(row => { const section = node('section', undefined, fragment); section.className = 'specialist-draft-review-row'; node('h3', row.label, section); display(section, row.after, limits, 0); });
    host.replaceChildren(fragment); return true;
  }
  let openAuthor = async () => false;
  async function reviewPlaybook(host, options) {
    const current = () => host.isConnected && options.isCurrent();
    const fetchCurrent = async (path, body) => {
      let response, value;
      try { response = await fetch(API + path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: body === undefined ? {} : {'Content-Type': 'application/json'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})}); value = await response.json(); }
      catch (_) { throw new Error('The reply could not be confirmed. Read the original decision; nothing will be repeated automatically.'); }
      if (!current()) throw new Error('The current playbook or account changed. Reopen its complete review.');
      if ([401, 403].includes(response.status)) { host.replaceChildren(); throw new Error('Current access no longer permits this draft. Reopen Workflow Builder after access is restored.'); }
      if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'This draft decision is unavailable. Your entered playbook is kept.');
      return value;
    };
    host.replaceChildren();
    const state = await fetchCurrent('?name=' + encodeURIComponent(options.name));
    const value = await fetchCurrent('/review', {name: options.name, action: 'save', context: state.context, entered: options.entered, title: options.title || '', acknowledge_previous: options.acknowledge_previous === true});
    if (!current()) return false;
    renderReview(host, value.changes);
    const status = node('p', 'Read the complete Save draft review. The specialist in use will remain unchanged.', host); status.setAttribute('role', 'status');
    const label = node('label', undefined, host), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode(' I reviewed every setting and consequence above.'));
    const apply = node('button', 'Confirm Save draft', host); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.disabled = true;
    const read = node('button', 'Read this original Save draft', host); read.type = 'button'; read.className = 'btn'; read.hidden = true;
    let submitted = false, waiting = false;
    consent.addEventListener('change', () => { apply.disabled = !consent.checked || submitted || waiting || !current(); });
    read.addEventListener('click', async () => {
      if (waiting || !current()) return; waiting = true; read.disabled = true;
      try { const result = await fetchCurrent('/originals/' + value.operation); status.textContent = result.message; if (result.confirmed) options.onSaved(result, {newAgent: state.current === null}); }
      catch (error) { if (current()) status.textContent = error.message; }
      finally { waiting = false; read.disabled = !current(); }
    });
    apply.addEventListener('click', async () => {
      if (!consent.checked || submitted || waiting || !current()) return;
      submitted = true; waiting = true; apply.disabled = true; read.hidden = false;
      try { const result = await fetchCurrent('/apply', {token: value.token, confirmed: true}); status.textContent = result.message; if (result.confirmed) options.onSaved(result, {newAgent: state.current === null}); }
      catch (error) { if (current()) status.textContent = error.message; }
      finally { waiting = false; read.disabled = !current(); }
    });
    consent.focus(); return true;
  }
  window.LWSpecialistDrafts = {renderReview, reviewPlaybook, openAuthor: (...args) => openAuthor(...args), reviewEntered: (...args) => reviewEntered(...args)};
  const history = document.querySelector('[data-specialist-original-history]');
  if (history) {
    const choice = history.querySelector('select'), message = history.querySelector('[data-specialist-history-status]'), output = history.querySelector('[data-specialist-history-result]');
    let historyGeneration = 0;
    function clearHistory(event) {
      if (event?.type === 'lightwork:copilot-context-changed' && event.detail?.reason === 'selection') return;
      historyGeneration++; history.hidden = true; choice.replaceChildren(); output.replaceChildren(); message.textContent = '';
    }
    async function historyGet(path, current) {
      const response = await fetch(API + path, {credentials: 'same-origin', cache: 'no-store'}), value = await response.json();
      if (current !== historyGeneration) throw new Error('The current account changed.');
      if ([401,403].includes(response.status)) { clearHistory(); throw new Error('Your current access does not include this original history.'); }
      if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'The original history is unavailable. Nothing was repeated.');
      return value;
    }
    async function readHistory(identifier) {
      const current = ++historyGeneration; output.replaceChildren();
      try { const value = await historyGet('/originals/' + encodeURIComponent(identifier), current); if (current !== historyGeneration) return;
        node('h3', value.action, output); node('p', value.message, output);
        if (value.run) value.run.results.forEach(item => { const section = node('section', undefined, output); node('h4', item.task, section); node('p', item.answer || 'No answer received', section); node('p', item.sample ? 'Sample answer only; no passing conditions were declared.' : item.passed ? 'Entered passing conditions met.' : 'Entered passing conditions not met.', section); });
        message.textContent = 'Original result read. No work was repeated.';
      } catch (error) { if (current === historyGeneration) message.textContent = error.message; }
    }
    async function loadHistory() {
      const current = ++historyGeneration; output.replaceChildren();
      try { const value = await historyGet('/history', current); if (current !== historyGeneration) return;
        choice.replaceChildren(); node('option', 'Choose…', choice).value = '';
        value.originals.forEach(row => { node('option', row.label, choice).value = row.value; }); history.hidden = !value.originals.length;
        const original = new URLSearchParams(location.search).get('draft_original'); if (/^[a-f0-9]{32}$/.test(original || '')) await readHistory(original);
      } catch (error) { if (current === historyGeneration) message.textContent = error.message; }
    }
    choice.addEventListener('change', () => { if (choice.value) readHistory(choice.value); }); history.querySelector('button').addEventListener('click', loadHistory);
    ['lightwork:account-context-changed','lightwork:workspace-changed','lightwork:authority-changed','lightwork:copilot-context-changed'].forEach(event => document.addEventListener(event, clearHistory)); window.addEventListener('lightwork:context-changed', clearHistory);
    loadHistory();
  }
  const root = document.querySelector('[data-specialist-drafts]');
  if (!root) return;
  const form = document.getElementById('agent-form'), editor = () => window.LWSpecialistDraftEditor;
  let generation = 0, accessGeneration = 0, state = null, busy = false, reviewed = null, pending = '', draftChanged = false;
  const status = root.querySelector('[data-sd-status]'), review = root.querySelector('[data-sd-review]'), result = root.querySelector('[data-sd-result]');
  const draft = root.querySelector('[data-sd-draft]'), earlier = root.querySelector('[data-sd-earlier]'), originals = root.querySelector('[data-sd-original]');
  const title = root.querySelector('[data-sd-title]'), task = root.querySelector('[data-sd-task]'), reason = root.querySelector('[data-sd-reason]');
  const acknowledge = root.querySelector('[data-sd-acknowledge]');
  const readButton = root.querySelector('[data-sd-read-original]');
  const buttons = [...root.querySelectorAll('button[data-sd-action]')];
  function name() { return editor()?.name() || form?.dataset.name || ''; }
  function lock(value) { busy = value; buttons.forEach(button => { button.disabled = value || (!state && button.dataset.sdAction !== 'refresh'); }); root.setAttribute('aria-busy', String(value)); }
  function invalidate() { reviewed = null; review.replaceChildren(); }
  function clear() { generation++; accessGeneration++; editor()?.clearPrivate?.(); state = null; reviewed = null; pending = ''; draftChanged = false; acknowledge.checked = false; [review, result].forEach(host => host.replaceChildren()); [draft, earlier, originals].forEach(select => select.replaceChildren()); [title, task, reason].forEach(field => { field.value = ''; }); root.hidden = true; status.textContent = ''; lock(false); }
  async function request(path, body, expected) {
    const currentAccess = accessGeneration;
    let response, data;
    try { response = await fetch(API + path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: body === undefined ? {} : {'Content-Type': 'application/json'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})}); data = await response.json(); }
    catch (_) { throw new Error('The reply could not be confirmed. Read the original decision before submitting another request.'); }
    if ([401, 403].includes(response.status) && currentAccess === accessGeneration) { clear(); throw new Error('Your current access no longer permits this specialist view. Reopen it after access is restored.'); }
    if (expected !== generation || currentAccess !== accessGeneration) throw new Error('The current specialist view changed.');
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'This specialist decision is unavailable. Your entered draft has been kept.');
    return data;
  }
  function choices(select, rows) { const selected = select.value; select.replaceChildren(); const blank = node('option', 'Choose…', select); blank.value = ''; rows.forEach(row => { const item = node('option', row.label, select); item.value = row.value; }); if (rows.some(row => row.value === selected)) select.value = selected; }
  function useState(value) { state = value; editor()?.toolServices?.(value.tool_services); root.hidden = false; choices(draft, value.drafts); choices(earlier, value.earlier); choices(originals, value.originals); lock(false); }
  async function bootstrapDraft(current, selected) {
    if (form?.dataset.creating !== '1' || name() || draftChanged || !/^SPD-[a-f0-9]{32}$/.test(selected || '')) return null;
    const saved = await request('/drafts/' + encodeURIComponent(selected), undefined, current);
    if (current !== generation || name() || draftChanged || !editor()?.identify) return null;
    const fresh = await request('?name=' + encodeURIComponent(saved.name), undefined, current);
    if (current !== generation || name() || draftChanged || fresh.context !== saved.context || !fresh.drafts.some(row => row.value === selected)) return null;
    editor().identify(saved.name); return fresh;
  }
  async function load() {
    const current = ++generation; invalidate(); lock(true);
    try {
      const selected = new URLSearchParams(location.search).get('specialist_draft');
      const bootstrap = await bootstrapDraft(current, selected);
      if (!name()) { status.textContent = 'Give the custom agent a short name before reviewing its draft.'; return; }
      const value = bootstrap || await request('?name=' + encodeURIComponent(name()), undefined, current);
      if (current !== generation) return; useState(value); if (value.drafts.some(row => row.value === selected)) draft.value = selected;
      status.textContent = bootstrap ? 'Your owned draft is selected. Choose Load draft to put its complete settings in this blank editor; nothing has been published.' : 'The current specialist and your retained drafts are ready. Entered work has been kept.';
    }
    catch (error) { if (current === generation) status.textContent = error.message; }
    finally { if (current === generation) lock(false); }
  }
  function entered() { const bridge = editor(); if (!bridge) throw new Error('The complete draft editor is still loading.'); const value = bridge.get(); const {expected_generation: _generation, publish_without_passing_tests: _override, override_reason: _reason, ...patch} = value; return patch; }
  function body(action, selected) { if (!state) throw new Error('Refresh the specialist before reviewing a decision.'); return {name: name(), action, context: state.context, ...(action === 'save' || ((action === 'try' || action === 'check') && !selected) ? {entered: entered()} : {selected}), title: title.value, task: action === 'try' ? task.value : '', reason: ['publish', 'restore'].includes(action) ? reason.value : '', acknowledge_previous: acknowledge.checked}; }
  function showResult(value) {
    result.replaceChildren(); node('h3', value.action, result); node('p', value.message, result);
    if (value.run) {
      const run = value.run;
      node('p', ({prepared: 'Waiting to start', running: 'Checking answers', done: 'Finished', stopped: 'Stopped', unknown: 'Result unconfirmed'}[run.state] || 'Result unconfirmed') + '. ' + run.results.length + ' answers received; ' + run.passed + ' passed. Recorded model spend: $' + Number(run.spent_dollars).toFixed(6) + '.', result);
      run.results.forEach(item => { const section = node('section', undefined, result); node('h4', item.task, section); node('p', item.answer || 'No answer was received.', section); node('p', item.sample ? 'Sample answer only; no passing conditions were declared.' : item.passed ? 'Entered passing conditions met.' : 'Entered passing conditions not met.', section); });
    }
    if (!value.confirmed) node('p', 'This remains unknown. A matching current specialist does not confirm the original decision. Any later intentional decision needs its own full review.', result);
  }
  async function readOriginal(identifier) {
    if (!identifier || busy) return;
    const current = ++generation; invalidate(); lock(true);
    try { const value = await request('/originals/' + encodeURIComponent(identifier), undefined, current); if (current !== generation) return; showResult(value); status.textContent = 'Read the original result. No answer request or publication was repeated.'; await refreshChoices(current); }
    catch (error) { if (current === generation) status.textContent = error.message; }
    finally { if (current === generation) lock(false); }
  }
  async function submitReview(action, selected) {
    if (busy) return;
    const current = ++generation; invalidate(); lock(true);
    try {
      const value = await request('/review', body(action, selected), current);
      if (current !== generation || value.context !== state.context) return;
      const rows = node('div', undefined, review); renderReview(rows, value.changes); reviewed = value;
      const label = node('label', undefined, review), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode(' I reviewed every setting and consequence above.'));
      const apply = node('button', 'Confirm this decision', review); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.disabled = true;
      consent.addEventListener('change', () => { apply.disabled = !consent.checked || busy || reviewed !== value; });
      apply.addEventListener('click', async () => {
        if (!consent.checked || busy || reviewed !== value || current !== generation) return;
        lock(true); apply.disabled = true; pending = value.operation; readButton.hidden = false;
        try { const outcome = await request('/apply', {token: value.token, confirmed: true}, current); if (current !== generation) return; invalidate(); showResult(outcome); status.textContent = outcome.message; if (outcome.draft) draft.value = outcome.draft; }
        catch (error) { if (current === generation) { invalidate(); status.textContent = error.message + ' Read the original decision; this request will not be repeated automatically.'; } }
        finally { if (current === generation) { lock(false); await refreshChoices(current); } }
      });
      const cancel = node('button', 'Cancel this review', review); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', () => { if (!busy) { invalidate(); status.textContent = 'This review was closed. Earlier submitted decisions and their originals are kept.'; root.querySelector('[data-sd-action="preview"]').focus(); } });
      status.textContent = 'Read the full review before confirming. Nothing has been submitted.'; consent.focus();
    } catch (error) { if (current === generation) status.textContent = error.message; }
    finally { if (current === generation) lock(false); }
  }
  async function refreshChoices(current) { try { const value = await request('?name=' + encodeURIComponent(name()), undefined, current); if (current === generation) useState(value); } catch (error) { if (current === generation) status.textContent += ' ' + error.message; } }
  async function reviewEntered(action) { if (!state) await load(); if (state) return submitReview(action); }
  buttons.forEach(button => button.addEventListener('click', async () => {
    const action = button.dataset.sdAction;
    if (action === 'refresh') { await load(); return; }
    if (action === 'preview') {
      if (busy) return; const current = ++generation; invalidate(); lock(true);
      try { const value = await request('/preview', body('save'), current); if (current === generation) { renderReview(review, value.changes); status.textContent = value.message; } }
      catch (error) { if (current === generation) status.textContent = error.message; } finally { if (current === generation) lock(false); }
      return;
    }
    if (action === 'load') {
      if (!draft.value || busy) return;
      if (draftChanged && !(await window.mvConfirm('Replace your currently entered editor settings with this saved draft? Your retained drafts and original decisions remain available.', {okText: 'Load saved draft'}))) return;
      const current = ++generation; invalidate(); lock(true);
      try { const value = await request('/drafts/' + encodeURIComponent(draft.value), undefined, current); if (current !== generation || value.context !== state.context || value.name !== name()) return; editor().apply(value.profile); draftChanged = false; title.value = value.title; status.textContent = 'The saved draft is in the editor. It has not been published; review it against current settings before using it.'; }
      catch (error) { if (current === generation) status.textContent = error.message; } finally { if (current === generation) lock(false); }
      return;
    }
    const selected = action === 'restore' ? earlier.value : action === 'publish' ? draft.value : undefined;
    if (['publish', 'restore'].includes(action) && !selected) { status.textContent = 'Choose a named retained version first.'; return; }
    await submitReview(action, selected);
  }));
  form?.addEventListener('input', () => { draftChanged = true; if (reviewed || busy) { generation++; invalidate(); lock(false); status.textContent = 'The entered draft changed. Review it again before confirming.'; } });
  [draft, earlier, title, task, reason, acknowledge].forEach(field => field.addEventListener('input', () => { generation++; invalidate(); lock(false); }));
  originals.addEventListener('change', () => readOriginal(originals.value)); readButton.addEventListener('click', () => readOriginal(pending));
  openAuthor = async (value, options = {}) => {
    if (!value || Object.keys(value).sort().join('|') !== 'binding|context|name' || !/^[a-f0-9]{64}$/.test(value.binding) || !/^[a-f0-9]{64}$/.test(value.context) || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value.name) || typeof options.isCurrent !== 'function' || !options.isCurrent() || busy || value.name !== name()) return false;
    const current = generation;
    let fresh; try { fresh = await request('?name=' + encodeURIComponent(value.name), undefined, current); } catch (_) { return false; }
    if (current !== generation || !options.isCurrent() || busy || fresh.context !== value.context || fresh.binding !== value.binding) return false;
    useState(fresh); root.scrollIntoView({block: 'start'}); if (!options.isCurrent() || current !== generation) return false;
    root.querySelector('[data-sd-action="preview"]').focus(); return options.isCurrent() && current === generation;
  };
  ['lightwork:context-changed', 'lightwork:workspace-changed', 'lightwork:account-changed'].forEach(event => { document.addEventListener(event, clear); window.addEventListener(event, clear); });
  document.addEventListener('lightwork:account-context-changed', clear); document.addEventListener('lightwork:authority-changed', clear);
  document.addEventListener('lightwork:copilot-context-changed', event => { if (event.detail?.reason !== 'selection') clear(); });
  document.addEventListener('lightwork:product-operation-complete', event => { if (String(event.detail?.operation || '').startsWith('specialists.drafts.')) { generation++; invalidate(); status.textContent = 'A specialist decision changed. Refresh its drafts; your entered editor settings have been kept.'; } });
  const originalFromLink = new URLSearchParams(location.search).get('draft_original');
  if (/^[a-f0-9]{32}$/.test(originalFromLink || '')) { pending = originalFromLink; readButton.hidden = false; }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', load); else load();
}());
