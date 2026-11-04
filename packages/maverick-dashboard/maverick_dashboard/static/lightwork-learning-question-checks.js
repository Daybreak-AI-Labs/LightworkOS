/* Complete check-only learning questions; current private source and original custody. */
(function () {
  'use strict';
  var root = document.getElementById('learning-question-checks'); if (!root) return;
  function get(id) { return root.querySelector('#lqc-' + id); }
  function el(tag, text, parent) { var item = document.createElement(tag); if (text !== undefined) item.textContent = text; if (parent) parent.append(item); return item; }
  var model = get('model'), samples = get('samples'), choice = get('choice'), status = get('status'), preview = get('review-panel'), result = get('result');
  var state = null, selected = [], page = null, pending = null, busy = false, held = false, generation = 0, requests = new Set();
  function stamp() { return JSON.stringify([model.value, samples.value, selected, choice.value]); }
  function invalidate() { preview.replaceChildren(); }
  function lock(value) {
    busy = value; root.querySelectorAll('button,input,select').forEach(function (control) { control.disabled = value; });
    get('load').disabled = value || !state || !state.available || !model.value;
    get('review').disabled = value || held || !state || !state.available || !selected.some(function (row) { return row.model === model.value; });
    get('original').disabled = value || !(choice.value || pending && pending.operation);
    var confirm = preview.querySelector('[data-confirm]'), apply = preview.querySelector('[data-apply]');
    if (apply) apply.disabled = value || !confirm.checked || Date.now() / 1000 >= Number(apply.dataset.expires);
  }
  function clear() {
    generation++; requests.forEach(function (request) { request.abort(); }); requests.clear();
    state = pending = page = null; selected = []; held = false; model.replaceChildren(); choice.replaceChildren();
    get('questions').replaceChildren(); get('selected').replaceChildren(); get('page-status').textContent = ''; invalidate(); result.replaceChildren();
    get('current').textContent = status.textContent = 'Your account, workspace or access changed. Refresh before continuing.'; lock(false);
  }
  async function request(path, body) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 30000); requests.add(controller);
    try {
      var response = await fetch('/api/v1/learning-question-checks' + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined, signal: controller.signal});
      var text = await response.text(); if (text.length > 2 * 1024 * 1024) throw new Error('The complete reply is unavailable. Read the original outcome before another check.');
      var row; try { row = JSON.parse(text); } catch (_) { row = {}; }
      if (response.redirected || !response.ok || !(response.headers.get('content-type') || '').includes('application/json')) {
        if (response.redirected || [401, 403].includes(response.status)) clear();
        throw new Error(typeof row.detail === 'string' ? row.detail : 'The reply could not be checked. Read the original outcome before starting another check.');
      }
      if (state && row.context && state.context !== row.context) { clear(); throw new Error('Your account or workspace changed. Refresh before continuing.'); }
      return row;
    } finally { clearTimeout(timer); requests.delete(controller); }
  }
  function saved(context) { try { var row = JSON.parse(sessionStorage.getItem('learning-question-check:' + context) || 'null'); return row && row.context === context && /^[a-f0-9]{32}$/.test(row.operation) ? row : null; } catch (_) { return null; } }
  function remember(row) { if (row) sessionStorage.setItem('learning-question-check:' + row.context, JSON.stringify(row)); pending = row; held = Boolean(row && row.unknown); }
  function options(select, rows, previous, prompt) {
    select.replaceChildren(); el('option', prompt, select).value = '';
    rows.forEach(function (row) { el('option', row.label, select).value = row.value; });
    if (rows.some(function (row) { return row.value === previous; })) select.value = previous;
    else if (previous) { var old = el('option', 'Previous choice is unavailable in this view', select); old.value = previous; old.disabled = true; select.value = previous; }
  }
  async function load(isCurrent) {
    if (busy) return false; var started = ++generation, entered = stamp(); lock(true);
    try {
      var row = await request('/current'); if (started !== generation || entered !== stamp() || isCurrent && !isCurrent()) return false;
      if (state && state.revision !== row.revision) { result.replaceChildren(); invalidate(); get('questions').replaceChildren(); selected.forEach(function (item) { item.question = 'Previously selected question; review its current text before checking.'; item.expected = ''; }); renderSelected(); }
      state = row; options(model, row.models, model.value, 'Choose a current model'); options(choice, row.requests, choice.value, 'Choose an original check'); remember(pending || saved(row.context));
      get('current').textContent = row.problem || 'Current question choices checked. Answer checker: ' + row.checker + '. Your selected questions are kept.';
      status.textContent = held ? 'The original reply is unconfirmed. Read its outcome before another check.' : 'Choose saved questions, then review their complete content and spending.'; return true;
    } catch (error) { if (started === generation) { state = null; get('current').textContent = error.message; } return false; }
    finally { if (started === generation) lock(false); }
  }
  function renderSelected() {
    get('selected').replaceChildren(); selected.filter(function (row) { return row.model === model.value; }).forEach(function (row) {
      var article = el('article', undefined, get('selected')); article.className = 'glass-card stack'; el('h4', row.question, article); el('p', 'Expected answer: ' + row.expected, article);
      var remove = el('button', 'Remove from this check', article); remove.type = 'button'; remove.className = 'btn btn--ghost';
      remove.addEventListener('click', function () { if (!busy) { selected = selected.filter(function (item) { return item !== row; }); generation++; invalidate(); renderSelected(); lock(false); } });
    });
  }
  async function browse(offset) {
    if (busy || !state || !model.value) return; var started = ++generation, selectedModel = model.value; invalidate(); lock(true);
    try {
      var row = await request('/questions?model=' + encodeURIComponent(selectedModel) + '&offset=' + offset); if (started !== generation || selectedModel !== model.value) return;
      page = row; get('questions').replaceChildren(); get('page-status').textContent = row.total + ' saved questions; ' + row.cases.length + ' shown on this page.';
      get('previous').hidden = row.offset === 0; get('next').hidden = row.next === null;
      row.cases.forEach(function (item) {
        var article = el('article', undefined, get('questions')); article.className = 'glass-card stack'; el('p', item.question, article);
        if (!item.supported) { el('p', item.notice, article); return; }
        el('p', 'Expected answer: ' + item.expected, article);
        var add = el('button', 'Include this question', article); add.type = 'button'; add.className = 'btn btn--ghost';
        add.addEventListener('click', function () {
          if (busy) return;
          if (selected.some(function (entry) { return entry.model === selectedModel && entry.reference === item.value; })) { status.textContent = 'That question is already selected.'; return; }
          if (selected.filter(function (entry) { return entry.model === selectedModel; }).length >= 16) { status.textContent = 'One complete check supports at most 16 questions.'; return; }
          selected.push({model: selectedModel, reference: item.value, question: item.question, expected: item.expected}); generation++; invalidate(); renderSelected(); lock(false);
        });
      });
    } catch (error) { if (started === generation) status.textContent = error.message; }
    finally { if (started === generation) lock(false); }
  }
  function full(value, parent) {
    if (Array.isArray(value)) value.forEach(function (item, index) { el('h5', 'Question ' + (index + 1), parent); Object.entries(item).forEach(function (entry) { el('h6', entry[0], parent); el('p', entry[1], parent); }); });
    else el('p', value, parent);
  }
  function show(row) {
    result.replaceChildren(); el('h4', 'Your original question check', result); el('p', row.message, result);
    if (row.job && row.job.problem) el('p', row.job.problem, result);
    if (row.result) { row.result.reports.forEach(function (report) { Object.entries(report).forEach(function (entry) { el('p', entry[0] + ': ' + entry[1], result); }); }); el('p', 'Recorded AI cost: $' + row.result.spent + '. ' + row.result.meaning, result); }
    if (row.private_report_unavailable) el('p', row.private_report_unavailable, result);
    (row.checks || []).forEach(function (check, index) {
      var article = el('article', undefined, result); article.className = 'glass-card stack'; el('h4', 'Question ' + (index + 1), article); el('p', check.goal, article); el('p', 'Expected answer: ' + check.expected, article);
      el('p', 'Requested: ' + check.requested_samples + '. Judged: ' + check.samples + '. Unavailable: ' + check.unavailable + '.', article);
      el('p', !check.complete ? 'Incomplete; no conclusion that this question is too easy.' : !check.discriminative ? 'Consistently passed in this check; no automatic removal.' : 'Not consistently passed in this check.', article);
      check.observations.forEach(function (observation, attempt) { el('h5', 'Answer ' + (attempt + 1), article); el('p', observation.response === null ? 'Complete response unavailable.' : observation.response === '' ? 'No answer text was returned.' : observation.response, article); el('p', observation.verdict === null ? 'Judgment unavailable.' : observation.verdict ? 'Checker judgment: passed.' : 'Checker judgment: did not pass.', article); });
    });
    if (row.task_href) { var link = el('a', 'Read progress or stop this check', result); link.href = row.task_href; }
  }
  async function readOriginal(isCurrent) {
    var operation = choice.value || pending && pending.operation; if (busy || !/^[a-f0-9]{32}$/.test(operation || '')) return false;
    var started = ++generation; lock(true);
    try {
      var row = await request('/requests/' + operation); if (started !== generation || isCurrent && !isCurrent()) return false;
      var terminal = row.confirmed && row.job && ['done', 'failed', 'stopped', 'not_started'].includes(row.job.state);
      remember({context: row.context, operation: operation, unknown: !terminal}); show(row); status.textContent = 'Original outcome read. No answer, judgment or removal was repeated.'; return true;
    } catch (error) { if (started === generation) status.textContent = error.message + ' Nothing was repeated.'; return false; }
    finally { if (started === generation) lock(false); }
  }
  async function review() {
    if (busy || held || !state || !state.available) return; var started = ++generation, entered = stamp(); invalidate(); lock(true);
    try {
      var row = await request('/review', {context: state.context, revision: state.revision, model: model.value, samples: Number(samples.value), references: selected.filter(function (item) { return item.model === model.value; }).map(function (item) { return item.reference; })});
      if (started !== generation || entered !== stamp()) return;
      el('h4', 'Review this complete question check', preview); row.review.forEach(function (entry) { el('h5', entry.label, preview); full(entry.after, preview); });
      var label = el('label', undefined, preview), checked = el('input', undefined, label); checked.type = 'checkbox'; checked.dataset.confirm = 'true'; el('span', ' I reviewed every question, expected answer, provider use and spending limit.', label);
      var apply = el('button', 'Start reviewed question check', preview); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.dataset.apply = 'true'; apply.dataset.expires = row.expires; apply.disabled = true;
      checked.addEventListener('change', function () { apply.disabled = !checked.checked || Date.now() / 1000 >= row.expires; });
      apply.addEventListener('click', async function () {
        if (busy || !checked.checked || started !== generation || entered !== stamp()) return;
        if (Date.now() / 1000 >= row.expires) { invalidate(); status.textContent = 'This review expired. Review current sources again; your choices are kept.'; lock(false); return; }
        try { remember({context: row.context, operation: row.operation, unknown: true}); } catch (_) { status.textContent = 'Allow this site to retain the original request before starting. Nothing was started.'; return; }
        var saving = ++generation; lock(true);
        try { var outcome = await request('/start', {token: row.token, confirm: true}); if (saving === generation) { show(outcome); status.textContent = 'The original request is retained. Read its progress; no automatic retry is made.'; } }
        catch (error) { if (saving === generation) status.textContent = error.message + ' The original may have started. Read its outcome before another check.'; }
        finally { if (saving === generation) { invalidate(); lock(false); } }
      });
      var cancel = el('button', 'Keep questions unchanged', preview); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', function () { if (!busy) invalidate(); }); preview.focus();
    } catch (error) { if (started === generation) status.textContent = error.message; }
    finally { if (started === generation) lock(false); }
  }
  get('form').addEventListener('submit', function (event) { event.preventDefault(); review(); });
  get('refresh').addEventListener('click', function () { load(); }); get('load').addEventListener('click', function () { browse(0); });
  get('previous').addEventListener('click', function () { if (page) browse(Math.max(0, page.offset - 50)); }); get('next').addEventListener('click', function () { if (page && page.next !== null) browse(page.next); });
  model.addEventListener('change', function () { generation++; page = null; invalidate(); get('questions').replaceChildren(); get('page-status').textContent = ''; renderSelected(); lock(false); });
  samples.addEventListener('change', function () { generation++; invalidate(); }); choice.addEventListener('change', function () { generation++; lock(false); });
  get('original').addEventListener('click', function () { readOriginal(); });
  window.LightworkLearningQuestionChecks = {open: async function (context, isCurrent) {
    if (busy || !/^[a-f0-9]{64}$/.test(context) || isCurrent && !isCurrent()) return false;
    var entered = stamp(), loaded = await load(isCurrent); if (!loaded || state.context !== context || entered !== stamp() || isCurrent && !isCurrent()) return false;
    root.scrollIntoView({block:'start'}); model.focus(); return true;
  }};
  ['workspace-changed','account-context-changed','lightwork:workspace-changed','lightwork:account-context-changed'].forEach(function (name) { window.addEventListener(name, clear); document.addEventListener(name, clear); });
  load();
})();
