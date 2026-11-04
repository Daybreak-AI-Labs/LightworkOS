/* Complete selected-target review; interrupted originals are read, never repeated. */
(function () {
  'use strict';
  var root = document.getElementById('learning-transfers'); if (!root) return;
  function find(id) { return root.querySelector('#lt-' + id); }
  var source = find('source'), target = find('target'), instructions = find('instructions'), file = find('file'), retry = find('retry');
  var refresh = find('refresh'), review = find('review'), choice = find('choice'), original = find('original');
  var status = find('status'), preview = find('preview'), result = find('result');
  var state = null, pending = null, busy = false, generation = 0, dirty = false, requests = new Set();
  var selectedOperation = new URL(location.href).searchParams.get('learning_transfer') || '';
  if (!/^[a-f0-9]{32}$/.test(selectedOperation)) selectedOperation = '';
  function node(tag, text, parent) { var item = document.createElement(tag); if (text !== undefined) item.textContent = text; if (parent) parent.append(item); return item; }
  function values() { return {source: source.value, target: target.value, instructions: instructions.value, retry_judged: retry.checked}; }
  function stamp() { return JSON.stringify(values()); }
  function lock(value) {
    busy = value; [source, target, instructions, file, retry, refresh, choice].forEach(function (input) { input.disabled = value; });
    review.disabled = value || !state || !state.available; original.disabled = value || !pending;
  }
  function invalidate() { preview.replaceChildren(); }
  function clear() {
    generation++; requests.forEach(function (controller) { controller.abort(); }); requests.clear();
    state = pending = null; selectedOperation = ''; instructions.value = ''; file.value = ''; retry.checked = false; dirty = false;
    source.replaceChildren(); target.replaceChildren(); choice.replaceChildren(); invalidate(); result.replaceChildren(); original.hidden = true;
    lock(false); status.textContent = 'Your account, workspace or access changed. Refresh before continuing.';
  }
  async function request(path, body) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 30000); requests.add(controller);
    try {
      var response = await fetch('/api/v1/learning-transfers' + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined, signal: controller.signal});
      var text = await response.text(); if (text.length > 6 * 1024 * 1024) throw new Error('The complete reply exceeds the supported size. Your draft is kept; read the original request before another test.');
      var value; try { value = JSON.parse(text); } catch (_) { value = {}; }
      if (response.redirected || !response.ok) {
        if (response.redirected || [401, 403].includes(response.status) || response.status === 409 && typeof value.detail === 'string' && value.detail.startsWith('Your account or workspace changed.')) clear();
        throw new Error(typeof value.detail === 'string' ? value.detail : 'The reply could not be checked. Read the original request before another test.');
      }
      if (state && value.context && state.context !== value.context) { clear(); throw new Error('Your account or workspace changed. Refresh current choices.'); }
      return value;
    } finally { clearTimeout(timer); requests.delete(controller); }
  }
  function preserve(row, publish) {
    if (row) sessionStorage.setItem('learning-transfer:' + row.context, JSON.stringify(row));
    pending = row; original.hidden = !row;
    if (row && publish !== false) {
      selectedOperation = row.operation;
      document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: {kind: 'learning_transfer', operation: row.operation}}}));
    }
  }
  function saved(context) { try { var row = JSON.parse(sessionStorage.getItem('learning-transfer:' + context) || 'null'); return row && row.context === context && /^[a-f0-9]{32}$/.test(row.operation) ? row : null; } catch (_) { return null; } }
  function choices(select, rows, selected, label) {
    select.replaceChildren(); node('option', label, select).value = '';
    rows.forEach(function (row) { node('option', row.label, select).value = row.value; });
    if (rows.some(function (row) { return row.value === selected; })) select.value = selected;
    else if (selected) { var old = node('option', 'Previous choice is unavailable; choose a current model', select); old.value = selected; old.disabled = true; select.value = selected; }
  }
  async function load(isCurrent) {
    if (busy) return false; var started = ++generation, entered = stamp(); invalidate(); lock(true);
    try {
      var next = await request('/current'); if (started !== generation || isCurrent && !isCurrent() || entered !== stamp()) return false;
      state = next; choices(source, next.models, source.value, 'Choose a model'); choices(target, next.models, target.value, 'Choose a different model');
      choices(choice, next.requests, choice.value, 'Choose an original test');
      preserve(pending || saved(next.context), false);
      status.textContent = next.available ? 'Current models and sources checked. Your entered choices are kept; review everything before starting.' : next.problem;
      return true;
    } catch (error) { if (started === generation) { state = null; status.textContent = error.message; } return false; }
    finally { if (started === generation) lock(false); }
  }
  function show(row) {
    result.replaceChildren(); node('h4', 'Your original lesson test', result); node('p', row.message, result);
    if (row.job && row.job.problem) node('p', row.job.problem, result);
    if (row.result) {
      row.result.reports.forEach(function (report) { node('h5', report.Model, result); node('p', Object.entries(report).filter(function (entry) { return entry[0] !== 'Model'; }).map(function (entry) { return entry[0] + ': ' + entry[1]; }).join('\n'), result); });
      if (row.result.reports.some(function (report) { return !Object.prototype.hasOwnProperty.call(report, 'Checks not completed'); })) node('p', 'This earlier result does not record how many checks were completed. Do not treat it as a complete check.', result);
      node('p', 'Recorded AI cost: $' + row.result.spent + '. ' + row.result.meaning, result);
    }
    if (row.task_href) { var link = node('a', 'Read current progress and stop controls', result); link.href = row.task_href; link.className = 'btn btn--ghost'; }
  }
  async function readOriginal(operation, isCurrent) {
    if (busy || !/^[a-f0-9]{32}$/.test(operation)) return false; var started = ++generation; invalidate(); lock(true);
    try {
      var row = await request('/requests/' + operation); if (started !== generation || isCurrent && !isCurrent()) return false;
      preserve({context: row.context, operation: operation}, !isCurrent); show(row); status.textContent = 'The original request was read. No lesson test was repeated.'; return true;
    } catch (error) { if (started === generation) status.textContent = error.message + ' No test was repeated.'; return false; }
    finally { if (started === generation) lock(false); }
  }
  function completeValue(value, parent) {
    if (Array.isArray(value)) { value.forEach(function (item, index) { if (typeof item === 'string') node('p', String(index + 1) + '. ' + item, parent); else Object.entries(item).forEach(function (entry) { node('h6', entry[0], parent); node('p', entry[1], parent); }); }); }
    else node('p', value, parent);
  }
  function renderReview(row, entered, started) {
    node('h4', 'Review this complete lesson test', preview);
    row.review.forEach(function (item) { node('h5', item.label, preview); completeValue(item.after, preview); });
    var label = node('label', undefined, preview), check = node('input', undefined, label); check.type = 'checkbox';
    node('span', ' I reviewed every lesson, question, supplied instruction, intended change and spending limit.', label);
    var apply = node('button', 'Start reviewed lesson test', preview); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.disabled = true;
    check.addEventListener('change', function () { apply.disabled = !check.checked; });
    apply.addEventListener('click', async function () {
      if (busy || !check.checked || started !== generation || entered !== stamp()) return;
      try { preserve({context: row.context, operation: row.operation}); } catch (_) { status.textContent = 'This browser could not keep the original request. Allow site storage before starting; no test was started.'; return; }
      var saving = ++generation; lock(true); apply.disabled = true;
      try { var outcome = await request('/start', {token: row.token, confirm: true}); if (saving !== generation) return; show(outcome); dirty = false; status.textContent = 'Read the original task for current progress. No automatic retry is made.'; }
      catch (error) { if (saving === generation) status.textContent = error.message + ' The original may have started. Check it before preparing another lesson test.'; }
      finally { if (saving === generation) { invalidate(); lock(false); } }
    });
    var cancel = node('button', 'Cancel review', preview); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', function () { if (!busy) invalidate(); });
  }
  review.addEventListener('click', async function () {
    if (busy || !state || !state.available) return; var entered = stamp(), started = ++generation; invalidate(); lock(true);
    try { var row = await request('/review', Object.assign({context: state.context, revision: state.revision}, values())); if (started === generation && entered === stamp()) renderReview(row, entered, started); }
    catch (error) { if (started === generation) status.textContent = error.message; }
    finally { if (started === generation) lock(false); }
  });
  file.addEventListener('change', async function () {
    var selected = file.files[0], started = ++generation; invalidate(); if (!selected) return;
    if (selected.size > 1048576) { status.textContent = 'Choose a plain text copy up to 1 MB. Your instructions are kept.'; return; }
    var before = instructions.value;
    if (before && !await window.mvConfirm('Replace the entered instructions with this file?', {okText: 'Replace instructions'})) return;
    if (started !== generation || before !== instructions.value) return;
    try { var text = await selected.text(); if (started !== generation || selected !== file.files[0] || before !== instructions.value) return; if (text.includes('\u0000') || !text.trim()) throw new Error(); instructions.value = text; dirty = true; }
    catch (_) { if (started === generation) status.textContent = 'That plain text copy could not be read. Your instructions are kept.'; }
  });
  [source, target, instructions, retry].forEach(function (input) { input.addEventListener('input', function () { generation++; dirty = true; invalidate(); }); });
  refresh.addEventListener('click', function () { load(); }); choice.addEventListener('change', function () { if (choice.value) readOriginal(choice.value); }); original.addEventListener('click', function () { if (pending) readOriginal(pending.operation); });
  window.LightworkLearningTransfers = {open: async function (expected, read, isCurrent) {
    var entered = stamp(), before = generation, operation = selectedOperation, current = function () { return (!isCurrent || isCurrent()) && entered === stamp(); };
    if (busy || !current()) return false;
    var next = await request('/current'); if (!current() || before !== generation) return false;
    if (next.context !== expected) { clear(); return false; }
    if (read) { if (!operation || !await readOriginal(operation, current) || !current()) return false; original.focus(); }
    else { if (!state && !await load(current) || !current()) return false; source.focus(); }
    root.scrollIntoView({block: 'start'}); return true;
  }};
  document.addEventListener('lightwork:copilot-selection', function (event) { var selection = event.detail && event.detail.selection; if (selection && selection.kind === 'learning_transfer' && /^[a-f0-9]{32}$/.test(selection.operation)) selectedOperation = selection.operation; });
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (!event.detail || event.detail.reason !== 'selection') clear(); });
  document.addEventListener('lightwork:workspace-changed', clear); document.addEventListener('lightwork:account-context-changed', clear); window.addEventListener('lightwork:context-changed', clear);
  window.addEventListener('beforeunload', function (event) { if (dirty && instructions.value) { event.preventDefault(); event.returnValue = ''; } });
  load().then(function () { if (selectedOperation && !busy) readOriginal(selectedOperation); });
})();
