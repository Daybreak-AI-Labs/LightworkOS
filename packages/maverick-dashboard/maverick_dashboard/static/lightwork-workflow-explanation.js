/* One current explanation, shared with Copilot. No raw source data or execution. */
(function () {
  'use strict';
  var panel = document.getElementById('wx-panel');
  if (!panel || !panel.dataset.flowId) return;
  var content = document.getElementById('wx-content'), status = document.getElementById('wx-status');
  var refresh = document.getElementById('wx-refresh'), controller = null, generation = 0;
  function element(tag, text, parent) {
    var node = document.createElement(tag); if (text !== undefined) node.textContent = String(text);
    if (parent) parent.appendChild(node); return node;
  }
  function date(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) return 'Not available';
    return new Date(value * 1000).toLocaleString();
  }
  function link(value, parent) {
    if (!value || typeof value.href !== 'string' || !value.href.startsWith('/') || value.href.startsWith('//') || /[\\\u0000-\u0020]/.test(value.href)) return;
    var node = element('a', value.label, parent); node.href = value.href; node.className = 'btn btn--ghost';
  }
  function section(title, parent) { var node = element('section', undefined, parent); element('h3', title, node); return node; }
  function describe(value, parent) { if (!value) return; element('p', value.status, parent); if (value.message) element('p', value.message, parent); }
  function render(report) {
    content.replaceChildren();
    element('p', report.basis + ' · Version ' + report.explained_version + ' · ' + report.name, content);
    var publication = section('Which version is available', content); describe(report.publication, publication);
    if (report.publication.published_version) element('p', 'Published version ' + report.publication.published_version, publication);
    var evidence = section('Examples and permission to learn', content), learning = report.learning;
    describe(learning, evidence);
    if (learning && learning.allowed_until) element('p', 'Recorded learning deadline: ' + date(learning.allowed_until) + '.', evidence);
    if (learning && typeof learning.teaching_rounds === 'number') element('p',
      learning.teaching_rounds + ' recorded teaching ' + (learning.teaching_rounds === 1 ? 'round' : 'rounds') + '. ' + learning.source_scope, evidence);
    if (learning && learning.examples.length) {
      var list = element('ul', undefined, evidence);
      learning.examples.forEach(function (example) {
        var row = element('li', undefined, list); element('strong', example.title, row);
        element('p', example.permission + ' · Reviewed by ' + example.reviewed_by + ' · Permission ends ' + date(example.allowed_until), row);
        link(example.source_run, row);
      });
    }
    if (learning && learning.taught_steps) {
      var taught = element('ul', undefined, evidence);
      learning.taught_steps.forEach(function (step) {
        element('li', step.title + ': ' + step.status + (typeof step.example_count === 'number'
          ? ' · ' + step.example_count + ' entered examples' : ''), taught);
      });
    }
    link(report.teach, evidence);
    var approval = section('Permission to take action', content); describe(report.action_approval, approval);
    if (report.run) {
      var run = section('What this run actually recorded', content);
      element('p', report.run.status + (report.run.practice_run ? ' · Practice run' : ''), run);
      element('p', report.run.release + '. ' + report.run.review + '.', run);
      var actions = element('ul', undefined, run);
      report.run.actions.forEach(function (action) { element('li', action.action + ': ' + action.recorded_result, actions); });
      link(report.run.progress, run);
    }
    var limits = element('ul', undefined, content);
    report.limits.forEach(function (text) { element('li', text, limits); });
    status.textContent = 'Checked ' + date(report.checked_at) + '. Saved evidence only; unsaved designer changes are excluded.';
  }
  async function load() {
    if (controller) controller.abort();
    controller = new AbortController(); var activeController = controller, started = ++generation;
    refresh.disabled = true; content.replaceChildren(); status.textContent = 'Checking the saved workflow and current permissions…';
    var url = '/api/v1/flows/' + encodeURIComponent(panel.dataset.flowId) + '/explanation';
    if (panel.dataset.runId) url += '?run_id=' + encodeURIComponent(panel.dataset.runId);
    try {
      var body = await window.mvFetchJSON(url, {cache: 'no-store', signal: activeController.signal, timeout: 30000});
      if (started !== generation) return;
      if (!body || !body.explanation || typeof body.explanation.is_learned !== 'boolean') throw new Error('unavailable');
      panel.hidden = !body.explanation.is_learned;
      if (!panel.hidden) render(body.explanation);
    } catch (_) {
      if (started === generation) {
        panel.hidden = false; content.replaceChildren();
        status.textContent = 'The current explanation could not be confirmed. Check access and the saved workflow, then refresh. No learning or action permission is established by this page.';
      }
    } finally { if (started === generation) refresh.disabled = false; }
  }
  refresh.addEventListener('click', load);
  window.addEventListener('lightwork:flow-loaded', load);
  window.addEventListener('lightwork:product-state-changed', load);
  document.addEventListener('lightwork:product-operation-complete', load);
  var runStatus = document.getElementById('fr-status');
  if (runStatus && typeof MutationObserver === 'function') {
    var lastRunStatus = runStatus.textContent;
    new MutationObserver(function () {
      if (runStatus.textContent !== lastRunStatus) { lastRunStatus = runStatus.textContent; load(); }
    }).observe(runStatus, {childList: true, subtree: true, characterData: true});
  }
  window.addEventListener('focus', load);
  load();
})();
