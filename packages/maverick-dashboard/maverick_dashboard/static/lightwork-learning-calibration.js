/* Actual checker judgments; protected complete review and original-only recovery. */
(function () {
  'use strict';
  var root = document.getElementById('learning-calibration'); if (!root) return;
  function find(id) { return root.querySelector('#lc-' + id); }
  function node(tag, text, parent) { var item = document.createElement(tag); if (text !== undefined) item.textContent = text; if (parent) parent.append(item); return item; }
  var model = find('model'), choice = find('choice'), status = find('status'), current = find('current'), preview = find('review-panel'), result = find('result');
  var state = null, pending = null, held = false, busy = false, generation = 0, drafts = [], page = null, requests = new Set();
  var initial = new URL(location.href).searchParams.get('checker_request') || '';
  if (!/^[a-f0-9]{32}$/.test(initial)) initial = '';
  function values(action) { return action === 'assess' ? {action: action, original_operation: choice.value || pending && pending.operation || ''} : {action: 'judge', model: model.value, cases: drafts.filter(function (row) { return row.model === model.value; }).map(function (row) { return {reference: row.reference, answer: row.answer, correct: row.correct, basis: row.basis}; })}; }
  function stamp() { return JSON.stringify([model.value, drafts, choice.value]); }
  function invalidate() { preview.replaceChildren(); }
  function lock(value) {
    busy = value; root.querySelectorAll('input,textarea,select,button').forEach(function (input) { input.disabled = value; });
    find('load').disabled = value || !state || !state.available || !model.value;
    find('review').disabled = value || held || !state || !state.available || !drafts.some(function (row) { return row.model === model.value; });
    find('assess').disabled = value || held || !state || !state.available || !(choice.value || pending && pending.operation);
    find('original').disabled = value || !pending;
    var apply = preview.querySelector('[data-review-expires]'), check = preview.querySelector('[data-review-confirm]');
    if (apply) apply.disabled = value || !check || !check.checked || Date.now() / 1000 >= Number(apply.dataset.reviewExpires);
  }
  function clear() {
    generation++; requests.forEach(function (controller) { controller.abort(); }); requests.clear();
    state = pending = null; drafts = []; page = null; held = false; model.replaceChildren(); choice.replaceChildren();
    find('cases').replaceChildren(); find('questions').replaceChildren(); find('page-status').textContent = ''; invalidate(); result.replaceChildren();
    find('original').hidden = true; lock(false); current.textContent = status.textContent = 'Your account, workspace or access changed. Refresh before continuing.';
  }
  async function request(path, body, copilot) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 30000); requests.add(controller);
    try {
      var response = await fetch((copilot ? '/api/v1/copilot/product-operations' : '/api/v1/learning-calibration') + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined, signal: controller.signal});
      var text = await response.text(); if (text.length > 6 * 1024 * 1024) throw new Error('The complete reply exceeds the supported size. Read the original checker request before another check.');
      var value; try { value = JSON.parse(text); } catch (_) { value = {}; }
      if (response.redirected || !response.ok) {
        if (response.redirected || [401, 403].includes(response.status) || response.status === 409 && typeof value.detail === 'string' && value.detail.startsWith('Your account or workspace changed.')) clear();
        throw new Error(typeof value.detail === 'string' ? value.detail : 'The reply could not be checked. Read the original request before another check.');
      }
      if (!copilot && state && value.context && state.context !== value.context) { clear(); throw new Error('Your account or workspace changed. Refresh current choices.'); }
      return value;
    } finally { clearTimeout(timer); requests.delete(controller); }
  }
  function remember(row) {
    if (row) sessionStorage.setItem('checker-calibration:' + row.context, JSON.stringify(row));
    pending = row; held = Boolean(row && row.unknown); find('original').hidden = !row;
  }
  function saved(context) { try { var row = JSON.parse(sessionStorage.getItem('checker-calibration:' + context) || 'null'); return row && row.context === context && /^[a-f0-9]{32}$/.test(row.operation) ? row : null; } catch (_) { return null; } }
  function options(select, rows, previous, prompt) {
    select.replaceChildren(); node('option', prompt, select).value = '';
    rows.forEach(function (row) { node('option', row.label, select).value = row.value; });
    if (rows.some(function (row) { return row.value === previous; })) select.value = previous;
    else if (previous) { var retained = node('option', 'Previous choice is unavailable; choose a current option', select); retained.value = previous; retained.disabled = true; select.value = previous; }
  }
  async function load(isCurrent) {
    if (busy) return false; var started = ++generation, entered = stamp(); invalidate(); lock(true);
    try {
      var row = await request('/current'); if (started !== generation || isCurrent && !isCurrent() || entered !== stamp()) return false;
      state = row; options(model, row.models, model.value, 'Choose current questions'); options(choice, row.requests, choice.value, 'Choose an original check');
      remember(pending || saved(row.context));
      current.textContent = row.checker + ': ' + row.retained_current_checker_samples + ' retained measurements for this checker. ' +
        (row.current_receipt ? 'Its current reliability assessment meets the required checks.' : 'No current reliability assessment is ready.') +
        ' At least ' + row.minimum_samples + ' measurements, including independently labelled correct and incorrect responses, are required. ' + (row.problem || '');
      status.textContent = held ? 'The original reply is unconfirmed. Read its original result before another check.' : 'Current choices checked. Your entered responses and labels are kept.';
      return true;
    } catch (error) {
      if (started === generation) { state = null; current.textContent = error.message; try { var identity = await request('/context'); if (started === generation) remember(saved(identity.context)); } catch (_) {} }
      return false;
    } finally { if (started === generation) lock(false); }
  }
  function renderDrafts() {
    var list = find('cases'); list.replaceChildren();
    drafts.filter(function (row) { return row.model === model.value; }).forEach(function (row, index) {
      var article = node('article', undefined, list); article.className = 'panel stack'; node('h4', 'Response ' + (index + 1), article); node('p', row.question, article);
      node('p', 'Saved expected answer: ' + row.expected, article);
      [['answer', 'Response to ask the checker about', 8000], ['basis', 'Why you independently know this label is correct', 2000]].forEach(function (entry) {
        var label = node('label', entry[1], article), input = node('textarea', undefined, label); input.className = 'textarea'; input.rows = 3; input.maxLength = entry[2]; input.required = true; input.value = row[entry[0]];
        input.addEventListener('input', function () { row[entry[0]] = input.value; generation++; invalidate(); });
      });
      var label = node('label', 'Does this supplied response correctly answer the question?', article), truth = node('select', undefined, label); truth.className = 'select'; truth.required = true;
      node('option', 'Choose your independent label', truth).value = '';
      node('option', 'Correct response', truth).value = 'true'; node('option', 'Incorrect response', truth).value = 'false'; truth.value = row.correct === null ? '' : String(row.correct);
      truth.addEventListener('change', function () { row.correct = truth.value === '' ? null : truth.value === 'true'; generation++; invalidate(); });
      var remove = node('button', 'Remove this response', article); remove.type = 'button'; remove.className = 'btn btn--ghost';
      remove.addEventListener('click', function () { if (busy) return; drafts = drafts.filter(function (item) { return item !== row; }); generation++; invalidate(); renderDrafts(); lock(false); });
    });
  }
  async function browse(offset) {
    if (busy || !state || !model.value) return; var selected = model.value, started = ++generation; invalidate(); lock(true);
    try {
      var row = await request('/questions?model=' + encodeURIComponent(selected) + '&offset=' + offset); if (started !== generation || selected !== model.value) return;
      page = row; find('questions').replaceChildren(); find('page-status').textContent = row.total + ' saved questions. Showing ' + row.cases.length + ' on this page; other pages remain available.';
      find('previous').hidden = row.offset === 0; find('next').hidden = row.next === null;
      row.cases.forEach(function (item) {
        var article = node('article', undefined, find('questions')); article.className = 'stack'; node('p', item.question, article);
        if (!item.supported) { node('p', item.notice, article); return; }
        var add = node('button', 'Add a labelled response for this question', article); add.type = 'button'; add.className = 'btn btn--ghost';
        add.addEventListener('click', function () {
          if (busy) return; if (drafts.filter(function (entry) { return entry.model === model.value; }).length >= 64) { status.textContent = 'One complete check supports at most 64 labelled responses.'; return; }
          drafts.push({model: model.value, reference: item.value, question: item.question, expected: item.expected, answer: '', correct: null, basis: ''});
          generation++; invalidate(); renderDrafts(); lock(false); find('cases').lastElementChild.querySelector('textarea').focus();
        });
      });
    } catch (error) { if (started === generation) status.textContent = error.message; }
    finally { if (started === generation) lock(false); }
  }
  function show(row) {
    result.replaceChildren(); node('h4', 'Your original answer check', result); node('p', row.message, result);
    if (row.job && row.job.problem) node('p', row.job.problem, result);
    if (row.result) { row.result.reports.forEach(function (report) { Object.entries(report).forEach(function (entry) { node('p', entry[0] + ': ' + entry[1], result); }); }); node('p', 'Recorded AI cost: $' + row.result.spent + '. ' + row.result.meaning, result); }
    if (row.task_href) { var link = node('a', 'Read current progress and stop controls', result); link.href = row.task_href; link.className = 'btn btn--ghost'; }
  }
  async function readOriginal(operation, isCurrent) {
    if (busy || !/^[a-f0-9]{32}$/.test(operation)) return false; var started = ++generation; invalidate(); lock(true);
    try {
      var row = await request('/requests/' + operation); if (started !== generation || isCurrent && !isCurrent()) return false;
      var terminal = row.confirmed && row.job && ['done', 'failed', 'stopped', 'not_started'].includes(row.job.state);
      remember({context: row.context, operation: operation, unknown: !terminal}); show(row);
      status.textContent = 'The original request was read. No checker judgment or assessment was repeated.'; return true;
    } catch (error) { if (started === generation) status.textContent = error.message + ' Nothing was repeated.'; return false; }
    finally { if (started === generation) lock(false); }
  }
  function complete(value, parent) { if (Array.isArray(value)) value.forEach(function (item, index) { node('h5', 'Response ' + (index + 1), parent); Object.entries(item).forEach(function (entry) { node('h6', entry[0], parent); node('p', entry[1], parent); }); }); else node('p', value, parent); }
  async function review(action) {
    if (busy || held || !state || !state.available) return; var started = ++generation, entered = stamp(); invalidate(); lock(true);
    try {
      var row = await request('/review', Object.assign({context: state.context, revision: state.revision}, values(action)));
      if (started !== generation || entered !== stamp()) return;
      node('h4', 'Review this complete answer check', preview); row.review.forEach(function (entry) { node('h5', entry.label, preview); complete(entry.after, preview); });
      node('p', 'Review valid until ' + new Date(row.expires * 1000).toLocaleString() + '.', preview);
      var label = node('label', undefined, preview), check = node('input', undefined, label); check.type = 'checkbox'; check.dataset.reviewConfirm = 'true'; node('span', ' I reviewed every source, response, independent label, storage effect and spending limit.', label);
      var apply = node('button', action === 'assess' ? 'Save reviewed assessment' : 'Start reviewed answer check', preview); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.dataset.reviewExpires = row.expires; apply.disabled = true;
      check.addEventListener('change', function () { apply.disabled = !check.checked || Date.now() / 1000 >= row.expires; });
      apply.addEventListener('click', async function () {
        if (busy || !check.checked || started !== generation || entered !== stamp()) return;
        if (Date.now() / 1000 >= row.expires) { status.textContent = 'This review expired. Review current choices again; your entered responses are kept.'; invalidate(); lock(false); return; }
        try { remember({context: row.context, operation: row.operation, unknown: true}); } catch (_) { status.textContent = 'This browser cannot retain the original request. Allow site storage before starting; nothing was started.'; return; }
        var saving = ++generation; lock(true); apply.disabled = true;
        try { var outcome = await request('/start', {token: row.token, confirm: true}); if (saving !== generation) return; show(outcome); status.textContent = 'Read the original task for its current progress. No automatic retry is made.'; }
        catch (error) { if (saving === generation) status.textContent = error.message + ' The original may have started. Read it before another check.'; }
        finally { if (saving === generation) { invalidate(); lock(false); } }
      });
      var cancel = node('button', 'Keep current checker record', preview); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', function () { if (!busy) invalidate(); });
    } catch (error) { if (started === generation) status.textContent = error.message; }
    finally { if (started === generation) lock(false); }
  }
  find('form').addEventListener('submit', function (event) { event.preventDefault(); review('judge'); });
  find('assess').addEventListener('click', function () { review('assess'); });
  find('refresh').addEventListener('click', function () { load(); }); find('load').addEventListener('click', function () { browse(0); });
  find('previous').addEventListener('click', function () { if (page) browse(Math.max(0, page.offset - 50)); }); find('next').addEventListener('click', function () { if (page && page.next !== null) browse(page.next); });
  model.addEventListener('change', function () { generation++; invalidate(); find('questions').replaceChildren(); page = null; find('previous').hidden = find('next').hidden = true; renderDrafts(); lock(false); });
  choice.addEventListener('change', function () { if (choice.value) readOriginal(choice.value); }); find('original').addEventListener('click', function () { if (pending) readOriginal(pending.operation); });
  window.LightworkLearningCalibration = {openReview: async function (selection, options) {
    if (!selection || Object.keys(selection).length || busy || !options || typeof options.isCurrent !== 'function') return false;
    var before = generation, entered = stamp(); if (location.pathname !== '/learned' || !/^[a-f0-9]{64}$/.test(options.context || '') || !options.isCurrent()) return false;
    var catalog = await request('/catalog', {page:'/learned',selection:{}}, true);
    if (before !== generation || entered !== stamp() || !options.isCurrent() || catalog.context !== options.context ||
        !(catalog.operations || []).some(function (row) { return row.id === 'learning.checker_calibration_form' && row.available; })) return false;
    await request('/current'); if (before !== generation || entered !== stamp() || !options.isCurrent()) return false;
    if (!state && !await load(options.isCurrent) || !options.isCurrent() || entered !== stamp()) return false;
    find('title').focus(); root.scrollIntoView({block: 'start'}); return true;
  }};
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (!event.detail || event.detail.reason !== 'selection') clear(); });
  document.addEventListener('lightwork:workspace-changed', clear); document.addEventListener('lightwork:account-context-changed', clear); window.addEventListener('lightwork:context-changed', clear);
  window.addEventListener('beforeunload', function (event) { if (drafts.some(function (row) { return row.answer || row.basis; })) { event.preventDefault(); event.returnValue = ''; } });
  load().then(function () { if (initial && !busy) readOriginal(initial); });
})();
