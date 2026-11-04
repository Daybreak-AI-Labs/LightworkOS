(function () {
  'use strict';
  const root = document.getElementById('fd-selected-step-check'); if (!root) return;
  const by = name => document.getElementById('fd-step-check-' + name), api = '/api/v1/workflow-step-checks';
  let busy = false, generation = 0, context = '', pending = null, ownsDialog = false, inputDraft = null;
  const live = () => window.__fdLiveFlow ? window.__fdLiveFlow() : null;
  const selected = () => window.__fdEngine ? window.__fdEngine.selected() : null;
  const snapshot = () => JSON.stringify([live(), selected()]);
  const node = (tag, text, parent) => { const value = document.createElement(tag); if (text !== undefined) value.textContent = String(text); if (parent) parent.append(value); return value; };
  const say = message => { by('status').textContent = message; };
  const remember = () => { try { if (pending) sessionStorage.setItem('lightwork:selected-step-original', JSON.stringify(pending)); else sessionStorage.removeItem('lightwork:selected-step-original'); } catch (_) {} };
  function clearPrivate() { generation++; context = ''; pending = null; inputDraft = null; busy = false; remember();
    if (ownsDialog) { document.getElementById('mv-form-fields')?.querySelectorAll('input,select').forEach(value => { value.value = ''; }); document.getElementById('mv-form-cancel')?.click(); ownsDialog = false; }
    by('result').replaceChildren(); by('read').hidden = true; say('Your account or workspace changed. Private step values were cleared.'); }
  async function request(path, body) {
    const F = 'This check could not be confirmed. Read the original result without repeating it.';
    const T = 'The reply could not be confirmed. Read the original result below; nothing repeats automatically.';
    const A = 'Sign in with current workflow permission before reading or checking private values.';
    const value = await window.mvFetchJSON(api + path, {method: body ? 'POST' : 'GET', cache: 'no-store',
      headers: context ? {'X-Lightwork-Step-Context': context} : {}, body: body || undefined, timeout: 30000,
      serverDetail: F, messages: {401: A, 403: A, timeout: T, offline: T, unreadable: T},
      onAccess: clearPrivate, contextChange: /account or workspace changed/, onContextChange: clearPrivate}, 'check the step');
    if (context && value.context && context !== value.context) { clearPrivate(); throw new Error('Your current account changed. Private values were cleared.'); }
    return value;
  }
  function show(value) {
    by('result').replaceChildren(); say(value.message);
    if (!value.current) { node('p', 'The original confirmation remains separate from current source permission. Private output is withheld because its source or safeguards changed.', by('result')); return; }
    if (value.result) { node('h3', value.result.label, by('result')); node('p', value.result.message, by('result'));
      if (value.result.answered) { const answer = node('p', typeof value.result.value === 'boolean' ? (value.result.value ? 'Yes' : 'No') : String(value.result.value), by('result')); answer.style.whiteSpace = 'pre-wrap'; answer.style.overflowWrap = 'anywhere'; } }
  }
  async function read() {
    if (busy || !pending || live()?.id !== pending.flow) return;
    const started = generation, original = pending; context = original.context; busy = true;
    try { const value = await request('/original/' + encodeURIComponent(original.id)); if (started === generation && pending === original && live()?.id === original.flow) show(value); }
    catch (error) { if (started === generation) say(error.message); } finally { if (started === generation) busy = false; }
  }
  async function ask(source, shape, saved, started) {
    const current = () => started === generation && snapshot() === saved;
    const scope = JSON.stringify([shape.context, source.flow.id, source.step, shape.fields]);
    const fields = Object.entries(shape.fields).map(([key, declaration]) => ({key, label: key.replaceAll('_', ' '),
      type: declaration.type === 'boolean' ? 'select' : 'text', required: declaration.type !== 'string',
      ...(inputDraft?.scope === scope ? {default: inputDraft.values[key]} : {}),
      ...(declaration.type === 'boolean' ? {options: [{value: '', label: 'Choose an answer'}, {value: 'yes', label: 'Yes'}, {value: 'no', label: 'No'}]} : {}),
      preserveWhitespace: declaration.type === 'string', allowEmpty: declaration.type === 'string',
      help: declaration.type === 'integer' ? 'Whole number from ' + declaration.min + ' to ' + declaration.max :
            declaration.type === 'string' ? 'Up to ' + declaration.max_length + ' characters. Spaces and empty text are preserved.' : 'Choose Yes or No explicitly.'}));
    ownsDialog = true;
    const entered = await window.mvForm('Try “' + shape.label + '”', fields, {okText: 'Review this check'});
    ownsDialog = false;
    if (entered === null || !current()) { if (started === generation) busy = false; return; }
    inputDraft = {scope, values: {...entered}};
    Object.entries(shape.fields).forEach(([key, declaration]) => { if (declaration.type === 'boolean') entered[key] = entered[key] === 'yes'; });
    try {
      const review = await request('/review', {...source, context, inputs: entered});
      if (!current()) return;
      by('result').replaceChildren();
      const list = node('dl', undefined, by('result')); list.style.overflowWrap = 'anywhere';
      review.changes.forEach(row => { node('dt', row.label, list); const value = node('dd', row.after, list); value.style.whiteSpace = 'pre-wrap'; value.style.marginInlineStart = 'var(--space-3)'; });
      const confirmation = node('label', undefined, by('result')), check = node('input', undefined, confirmation); check.type = 'checkbox';
      confirmation.append(document.createTextNode(' I reviewed this step and every entered value.'));
      const apply = node('button', 'Run only this step', by('result')); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.disabled = true;
      check.addEventListener('change', () => { apply.disabled = !check.checked || !current(); });
      apply.addEventListener('click', async () => {
        if (!check.checked || !current() || busy) return;
        busy = true; apply.disabled = true; check.disabled = true;
        pending = {flow: source.flow.id, context, id: review.id}; remember(); by('read').hidden = false;
        try { const value = await request('/apply', {token: review.token, confirmed: true}); if (current()) show(value); }
        catch (error) { if (current()) say(error.message); }
        finally { if (started === generation) busy = false; }
      });
      say('Review this complete check. Nothing has run yet.'); by('result').scrollIntoView({block: 'nearest'}); check.focus();
    } catch (error) { if (current()) say(error.message); }
    finally { if (started === generation) busy = false; }
  }
  async function open(form, stillCurrent = () => true) {
    if (busy || document.getElementById('mv-form')?.open || typeof window.mvForm !== 'function' || !stillCurrent()) return false;
    const source = {flow: live(), step: selected()};
    if (!source.flow?.id || !source.step) { say('Save your workflow and select a taught step first. Saving does not publish it.'); return false; }
    if (form && (form.flow !== source.flow.id || form.step !== source.step)) return false;
    const started = ++generation, saved = snapshot(); let opened = false; busy = true;
    try {
      const shape = await request('/inputs', source);
      if (started !== generation || snapshot() !== saved || document.getElementById('mv-form')?.open || !stillCurrent() || (form && shape.context !== form.context)) return false;
      context = shape.context; by('result').replaceChildren(); root.hidden = false;
      opened = true; void ask(source, shape, saved, started); return true;
    } catch (error) { if (started === generation) say(error.message); return false; }
    finally { if (started === generation && !opened) busy = false; }
  }
  window.LWWorkflowStepChecks = {open, openSelected: () => open(null)};
  by('read').addEventListener('click', () => void read());
  try { const saved = JSON.parse(sessionStorage.getItem('lightwork:selected-step-original') || 'null');
    if (saved && Object.keys(saved).sort().join(',') === 'context,flow,id' && /^[a-f0-9]{64}$/.test(saved.context) && /^WSC-[a-f0-9]{32}$/.test(saved.id)) { pending = saved; by('read').hidden = false; } } catch (_) {}
  ['lightwork:workspace-changed', 'lightwork:account-context-changed'].forEach(name => document.addEventListener(name, clearPrivate));
  window.addEventListener('lightwork:context-changed', clearPrivate);
  document.addEventListener('lightwork:copilot-context-changed', event => { if (event.detail?.reason !== 'selection') clearPrivate(); });
  document.addEventListener('lightwork:copilot-selection', () => { generation++; busy = false; by('result').replaceChildren(); say('Select a taught step, then try it with ordinary named values.'); });
})();
