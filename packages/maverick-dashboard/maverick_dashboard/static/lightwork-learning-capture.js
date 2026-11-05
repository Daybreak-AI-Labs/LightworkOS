// Flow run page: "Keep this run as a learning example". Enrolls the run at
// its first approval with plain, editable descriptions of its data, then
// lets the owner review the finished example and allow learning from it.
// Every rule (owner, workspace, pause, retention, review before use) is
// checked by the server; this script only guides and shows results.
(() => {
  'use strict';
  function renderReview(host, changes) {
    if (!host || !Array.isArray(changes) || !changes.length || changes.length > 16390 ||
        changes.some(row => !row || Object.keys(row).some(key => !['label', 'after'].includes(key)) ||
          typeof row.label !== 'string' || typeof row.after !== 'string') ||
        new TextEncoder().encode(JSON.stringify(changes)).length > 600000) return false;
    const wrapper = document.createElement('div'); wrapper.className = 'lx-complete-review';
    const count = document.createElement('p'); count.textContent = 'Complete review · ' + changes.length + ' details'; wrapper.append(count);
    const list = document.createElement('dl'); list.style.cssText = 'overflow-wrap:anywhere;white-space:pre-wrap;min-width:0';
    changes.forEach(row => { const label = document.createElement('dt'), value = document.createElement('dd');
      label.textContent = row.label; value.textContent = row.after; value.style.marginInlineStart = '0';
      list.append(label, value); });
    wrapper.append(list); host.append(wrapper); return true;
  }
  window.LightworkLearningCapture = Object.freeze({renderReview});
  const card = document.getElementById('lx-card');
  if (!card) return;
  const enc = encodeURIComponent;
  const base = '/api/v1/flows/' + enc(card.dataset.flowId || '') + '/runs/' + enc(card.dataset.runId || '') + '/episode-capture';
  const $ = id => document.getElementById('lx-' + id);
  const KINDS = { string: 'Text', integer: 'Whole number', number: 'Number', boolean: 'Yes or no', null: 'Nothing',
    object: 'Group of details', array: 'List' };
  const DAY = 86400;
  let prepared = null, model = null, record = null, busy = false, scope = null, reviewed = null, pending = null, epoch = 0;
  const decisionBase = '/api/v1/learning-example-decisions/' + enc(card.dataset.flowId || '') + '/' + enc(card.dataset.runId || '');
  const pendingKey = 'lightwork-example-decision:' + card.dataset.flowId + ':' + card.dataset.runId;
  function remember() { try { if (pending) sessionStorage.setItem(pendingKey, JSON.stringify(pending)); else sessionStorage.removeItem(pendingKey); } catch (_) {} }
  function forgetPrivate() { epoch++; scope = null; reviewed = null; pending = null; remember(); clearCurrentState(); $('decision-review').replaceChildren(); $('original-choice').replaceChildren(); $('original').hidden = true; }
  async function decisionApi(path, body) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 20000);
    try { const response = await fetch(decisionBase + path, {method: body === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'same-origin', signal: controller.signal,
      headers: {'Content-Type': 'application/json', ...(scope ? {'X-Lightwork-Example-Context': scope} : {})}, body: body === undefined ? undefined : JSON.stringify(body)});
      if (response.redirected) throw Object.assign(new Error('Please sign in again.'), {status: 401});
      const text = await response.text(); if (text.length > 1100000) throw new Error('The complete review could not be read safely. Nothing was confirmed.');
      const value = JSON.parse(text); if (!response.ok) throw Object.assign(new Error(typeof value.detail === 'string' ? value.detail : value.detail && value.detail.message || 'Check current status before continuing.'), {status: response.status, code: value.detail && value.detail.code});
      if (scope && value.context !== scope) throw Object.assign(new Error('Your account or workspace changed.'), {status: 403});
      return value;
    } finally { clearTimeout(timer); }
  }
  function showOriginal(message) { $('original').hidden = !pending && !$('original-choice').options.length; $('original-status').textContent = message || 'Check the original decision without repeating it.'; }
  async function readOriginal() {
    if (!pending && scope && $('original-choice').value) pending = {operation: $('original-choice').value, context: scope};
    if (!pending || pending.context !== scope) return;
    const started = epoch, value = await decisionApi('/requests/' + enc(pending.operation)); if (started !== epoch) return;
    showOriginal(value.message + ' Current example: ' + human(value.current_status) + '.');
    if (value.confirmed) { reviewed = null; $('decision-review').replaceChildren(); await load(); showOriginal(value.message + ' This is a historical decision; current status is shown separately.'); }
  }
  async function prepareDecision(kind) {
    if (!record || !scope) return;
    const reason = $(kind === 'grant' ? 'grant-reason' : 'review-reason').value.trim();
    if (!reason) { say('Enter a brief reason before reviewing your decision.'); return; }
    const body = {context: scope, kind, reason};
    if (kind === 'grant') { body.use_until = Math.min(endOfDay($('grant-until').value), record.retain_until - 60); body.retain_copies = $('grant-copies').checked; }
    const started = epoch, value = await decisionApi('/review', body); if (started !== epoch) return;
    const host = $('decision-review'); host.replaceChildren();
    if (!renderReview(host, value.changes)) { reviewed = null; say('The complete review could not be displayed. Nothing was confirmed. Check current status.'); return; }
    reviewed = {token: value.token, operation: value.operation, context: scope};
    const choice = make('label', 'mv-form__field'); const check = make('input'); check.type = 'checkbox';
    choice.append(check, document.createTextNode(' I reviewed every retained detail and this decision.')); host.append(choice);
    const save = make('button', 'btn btn--primary', kind === 'grant' ? 'Confirm learning permission' : kind === 'accept' ? 'Confirm acceptance' : 'Confirm rejection'); save.type = 'button'; save.disabled = true;
    check.addEventListener('change', () => { save.disabled = !check.checked; });
    save.addEventListener('click', () => run(async () => { if (!check.checked || !reviewed) return;
      const original = reviewed; pending = {operation: original.operation, context: original.context}; remember(); reviewed = null;
      host.replaceChildren(); showOriginal('Recording your reviewed decision…');
      try { const result = await decisionApi('/apply', {token: original.token, confirmed: true}); if (started !== epoch) return; showOriginal(result.message); await load(); }
      catch (error) { if (error.status === 401 || error.status === 403 || error.code === 'example_context_changed') throw error;
        showOriginal('The decision could not be confirmed. Read its original result; nothing will be submitted again automatically.'); say(error.message); }
    })); host.append(save); host.scrollIntoView({block: 'start'}); check.focus();
  }

  function make(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function human(value) { return typeof window.mvHuman === 'function' ? window.mvHuman(String(value)) : String(value).replace(/[_.-]+/g, ' '); }
  function say(text) { window.mvStatus($('status'), text); }
  async function api(path, body, action) {
    return window.mvFetchJSON(base + path, {method: body === undefined ? 'GET' : 'POST', cache: 'no-store', body: body}, action);
  }
  function isoDay(epoch) { const d = new Date(epoch * 1000); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
  function endOfDay(value) { const t = Date.parse(value + 'T23:59:00'); return Number.isFinite(t) ? t / 1000 : NaN; }
  function show(section) { ['enroll', 'review', 'grant'].forEach(name => { $(name).hidden = name !== section; }); $('next').hidden = true; }
  function clearCurrentState() {
    prepared = null; model = null; record = null; reviewed = null; show(null);
    $('describe').replaceChildren(); $('evidence').replaceChildren(); $('decision-review').replaceChildren();
    $('review-reason').value = ''; $('grant-reason').value = ''; $('grant-copies').checked = false;
  }

  // ---- plain editor for a data description ------------------------------------------
  function blank(kind) {
    if (kind === 'string') return { type: 'string', maxLength: 1024 };
    if (kind === 'integer' || kind === 'number') return { type: kind, minimum: -1000000000000, maximum: 1000000000000 };
    if (kind === 'object') return { type: 'object', properties: {}, required: [], additionalProperties: false };
    if (kind === 'array') return { type: 'array', items: { type: 'string', maxLength: 1024 }, minItems: 1, maxItems: 1 };
    return { type: kind };
  }
  function numberField(label, value, onChange, extra) {
    const wrap = make('label', 'mv-form__field', label);
    const input = make('input', 'input');
    input.type = 'number';
    Object.assign(input, extra || {});
    input.value = value;
    input.addEventListener('change', () => onChange(Number(input.value)));
    wrap.append(input);
    return wrap;
  }
  function editor(schema, label, replace, removable) {
    const box = make(schema.type === 'object' ? 'fieldset' : 'div', 'lx-field');
    const head = make(schema.type === 'object' ? 'legend' : 'div', 'lx-field__head');
    const kind = make('select', 'select');
    kind.setAttribute('aria-label', 'Kind of value for ' + label);
    Object.keys(KINDS).forEach(k => { const o = make('option', null, KINDS[k]); o.value = k; kind.append(o); });
    kind.value = schema.type;
    kind.addEventListener('change', () => { replace(blank(kind.value)); render(); });
    head.append(make('strong', null, label + ' '), kind);
    if (removable) {
      const remove = make('button', 'btn btn--ghost', 'Remove'); remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove ' + label);
      remove.addEventListener('click', () => { removable(); render(); });
      head.append(remove);
    }
    box.append(head);
    if (schema.type === 'string') {
      box.append(numberField('Longest text (characters)', schema.maxLength, v => { schema.maxLength = Math.min(1024, Math.max(1, v || 1)); }, { min: 1, max: 1024 }));
    } else if (schema.type === 'integer' || schema.type === 'number') {
      box.append(numberField('Smallest', schema.minimum, v => { schema.minimum = v; }),
        numberField('Largest', schema.maximum, v => { schema.maximum = v; }));
    } else if (schema.type === 'array') {
      box.append(numberField('Exactly how many items', schema.minItems, v => { schema.minItems = schema.maxItems = Math.min(64, Math.max(0, v || 0)); }, { min: 0, max: 64 }));
      box.append(editor(schema.items, 'Each item', next => { schema.items = next; }));
    } else if (schema.type === 'object') {
      Object.keys(schema.properties).forEach(key => {
        box.append(editor(schema.properties[key], human(key), next => { schema.properties[key] = next; }, () => {
          delete schema.properties[key];
          schema.required = schema.required.filter(k => k !== key);
        }));
      });
      const addRow = make('div', 'fr__actions');
      const name = make('input', 'input');
      name.type = 'text'; name.maxLength = 200;
      name.setAttribute('aria-label', 'Name of a new detail in ' + label + ', exactly as it appears');
      name.placeholder = 'Name of a detail, exactly as it appears';
      const add = make('button', 'btn btn--ghost', 'Add a detail'); add.type = 'button';
      add.addEventListener('click', () => {
        const key = name.value.trim();
        if (!key || Object.prototype.hasOwnProperty.call(schema.properties, key)) return;
        schema.properties[key] = blank('string');
        schema.required.push(key);
        render();
      });
      addRow.append(name, add);
      box.append(addRow);
    }
    return box;
  }
  function render() {
    const host = $('describe');
    host.replaceChildren();
    host.append(editor(model.input_schema, 'What the run starts with', next => { model.input_schema = next; }));
    Object.keys(model.tool_data_schemas).forEach(tool => {
      const pair = model.tool_data_schemas[tool];
      host.append(editor(pair.arguments, 'What “' + human(tool) + '” is sent', next => { pair.arguments = next; }));
      if ((model.unknown_results || []).includes(tool) && !Object.keys(pair.result.properties || {}).length) {
        host.append(make('p', 'fr__msg', 'Lightwork hasn’t seen what “' + human(tool) + '” gives back yet. Add each detail it returns.'));
      }
      host.append(editor(pair.result, 'What “' + human(tool) + '” gives back', next => { pair.result = next; }));
    });
  }

  // ---- showing a recorded example ---------------------------------------------------------
  function status(row) {
    record = row;
    const kind = row.status;
    if (kind === 'audit_pending') { show(null); say('Waiting for the activity log to confirm the last change. Refresh the page in a moment.'); return; }
    if (['enrolled', 'capturing', 'paused'].includes(kind)) {
      show(null); say('This run is being kept as a learning example. Approve its actions as usual; review it here when it finishes.'); return;
    }
    if (kind === 'awaiting_review') { show('review'); say('The run finished. Review what it did before it can be used for learning.'); return; }
    if (kind === 'accepted' && row.training_available === true) {
      show(null); $('next').hidden = false; say('Accepted, and new flows may learn from it.'); return;
    }
    if (kind === 'accepted' && row.grant_sha256) {
      show(null); say('Permission to learn from this example has ended. Keep a fresh run as a new example if this work still needs to be taught.');
      return;
    }
    if (kind === 'accepted') {
      show('grant');
      const until = row.retain_until;
      $('grant-until').max = isoDay(until - 60);
      $('grant-until').min = isoDay(Date.now() / 1000);
      $('grant-until').value = isoDay(until - 60);
      say('Accepted as a learning example. Allow learning from it when you’re ready.');
      return;
    }
    show(null);
    say({ rejected: 'You chose not to use this run as an example.', withdrawn: 'This example is no longer used for learning.',
      expired: 'This example has expired.', unusable: 'This run didn’t produce a usable example.' }[kind] || 'This run isn’t a learning example.');
  }

  async function run(action) {
    if (busy) return;
    busy = true; card.setAttribute('aria-busy', 'true'); ['refresh', 'accept', 'reject', 'grant-go', 'original-read', 'original-choice'].forEach(name => $(name).disabled = true);
    try { await action(); } catch (failure) {
      if (failure && (failure.status === 401 || failure.status === 403 || failure.code === 'example_context_changed')) forgetPrivate();
      else { reviewed = null; $('decision-review').replaceChildren(); }
      say(failure && (failure.status === 401 || failure.status === 403)
        ? 'This learning example is not available to your account right now. Private details and unfinished review were cleared.'
        : failure && failure.message || 'We could not confirm current status. Your entered reason is kept; read the original result after an interrupted decision.');
      $('status').focus();
    } finally { busy = false; card.setAttribute('aria-busy', 'false'); ['refresh', 'accept', 'reject', 'grant-go', 'original-read', 'original-choice'].forEach(name => $(name).disabled = false); }
  }
  async function load() {
    const started = epoch, oldReason = $('review-reason').value, oldGrant = $('grant-reason').value;
    if (card.dataset.capture === 'off') {
      clearCurrentState();
      say('Keeping runs as learning examples is turned off. To keep runs like this one, turn on Keep workflow examples for learning in Settings, then reload this page.');
      return;
    }
    clearCurrentState(); say('Checking this run’s learning status…');
    try {
      const history = await decisionApi('/history'); if (started !== epoch) return;
      scope = history.context; const choice = $('original-choice'); choice.replaceChildren();
      history.choices.forEach(item => { const option = make('option', null, item.label); option.value = item.value; choice.append(option); });
      try { const saved = JSON.parse(sessionStorage.getItem(pendingKey)); if (saved && saved.context === scope && /^[a-f0-9]{32}$/.test(saved.operation)) pending = saved; } catch (_) {}
      const fromLink = new URLSearchParams(location.search).get('example_decision');
      if (fromLink && /^[a-f0-9]{32}$/.test(fromLink)) pending = {context: scope, operation: fromLink};
      if (pending && pending.context !== scope) { pending = null; remember(); }
      if (pending && !history.choices.some(item => item.value === pending.operation)) { const option = make('option', null, 'Original submitted decision'); option.value = pending.operation; choice.append(option); }
      if (pending) choice.value = pending.operation;
      showOriginal();
    } catch (error) { if (error.status !== 404) throw error; }
    let row = null, value = null;
    try { value = await decisionApi(''); if (started !== epoch) return; row = value.record; } catch (failure) {
      if (!(failure && failure.status === 404)) throw failure;
    }
    if (row) {
      if (scope && scope !== value.context) { forgetPrivate(); say('Your account or workspace changed. Reload before continuing.'); return; }
      scope = value.context; status(row);
      $('review-reason').value = oldReason; $('grant-reason').value = oldGrant;
      if (row.status === 'awaiting_review' && !renderReview($('evidence'), value.changes)) { show(null); say('The complete retained details could not be displayed. Nothing can be approved from this preview.'); }
      return;
    }
    try { prepared = await api('/suggestion', undefined, 'check this run’s learning status'); } catch (failure) {
      if (failure && (failure.status === 404 || failure.status === 409)) {
        say('This run can’t become a learning example now. Examples start at the flow’s first approval, before any action runs, and example collection must be on.');
        return;
      }
      throw failure;
    }
    model = prepared.suggestion;
    const now = Date.now() / 1000;
    $('until').min = isoDay(now);
    $('until').max = isoDay(now + (prepared.max_days || 7) * DAY - 60);
    $('until').value = $('until').max;
    render();
    show('enroll');
    say('This run is waiting at its first approval, so it can be kept as a learning example.');
  }

  $('enroll-go').addEventListener('click', () => run(async () => {
    if (!prepared || !model) return;
    const now = Date.now() / 1000;
    const until = Math.min(endOfDay($('until').value), now + (prepared.max_days || 7) * DAY - 60);
    if (!(until > now)) { say('Choose a date from today up to a week ahead.'); return; }
    const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
      'Keep this run’s details as a learning example until ' + (window.mvDateAbsolute ? window.mvDateAbsolute(until) : new Date(until * 1000).toLocaleDateString()) + '? It’s encrypted and only you can review it.',
      { okText: 'Keep as example' });
    if (!ok) return;
    const row = await api('', { expected_pause_binding: prepared.expected_pause_binding, allowed_tools: prepared.allowed_tools,
      input_schema: model.input_schema, tool_data_schemas: model.tool_data_schemas, retain_until: until }, 'keep this run as a learning example');
    status(row);
  }));
  $('accept').addEventListener('click', () => run(() => prepareDecision('accept')));
  $('reject').addEventListener('click', () => run(() => prepareDecision('reject')));
  $('grant-go').addEventListener('click', () => run(() => prepareDecision('grant')));
  $('original-choice').addEventListener('change', () => { const value = $('original-choice').value; pending = value ? {operation: value, context: scope} : null; remember(); showOriginal(); });
  $('original-read').addEventListener('click', () => run(readOriginal));
  ['review-reason', 'grant-reason', 'grant-until', 'grant-copies'].forEach(name => $(name).addEventListener('input', () => { reviewed = null; $('decision-review').replaceChildren(); }));
  window.addEventListener('lightwork:context-changed', forgetPrivate);
  document.addEventListener('lightwork:workspace-changing', forgetPrivate);
  document.addEventListener('lightwork:copilot-context-changed', event => {
    if (event.detail && event.detail.reason === 'selection') { reviewed = null; $('decision-review').replaceChildren(); run(async () => { const value = await decisionApi(''); if (value.context !== scope) forgetPrivate(); }); }
    else forgetPrivate();
  });
  $('refresh').addEventListener('click', () => run(load));
  run(load);
})();
