(function () {
  'use strict';
  var host = document.getElementById('agent-recent-work');
  if (!host) return;
  var days = document.getElementById('agent-activity-days'), load = document.getElementById('agent-activity-load');
  var message = document.getElementById('agent-activity-message'), results = document.getElementById('agent-activity-results');
  var generation = 0, controller = null, context = null, unavailable = false;
  function clear() {
    generation += 1;
    if (controller) controller.abort();
    results.textContent = ''; results.hidden = true; context = null;
  }
  function boundary() { clear(); unavailable = true; load.disabled = true; days.disabled = true; message.textContent = 'Your account, workspace or access changed. Reload this page before reading private work.'; }
  window.addEventListener('lightwork:workspace-changed', boundary);
  window.addEventListener('lightwork:account-context-changed', boundary);
  function add(tag, text, parent) { var node = document.createElement(tag); node.textContent = text; (parent || results).appendChild(node); return node; }
  function date(value) { return new Date(value * 1000).toLocaleString(); }
  function render(value) {
    results.textContent = ''; results.hidden = false;
    if (value.more) add('p', 'Newest 50 records only; older work is not included.');
    var labels = {finished:'Finished', waiting:'Waiting for your answer', stopped:'Stopped or paused', working:'Working'};
    var summary = add('div', ''); summary.className = 'jc-cards';
    Object.keys(labels).forEach(function (key) {
      var card = add('div', '', summary); card.className = 'jc-stat';
      add('div', String(value.counts[key]), card).className = 'n';
      add('div', labels[key], card).className = 'l';
    });
    if (!value.tasks.length) add('p', 'No tasks you can currently open were found in this period.');
    value.tasks.forEach(function (task) {
      var card = add('article', ''); card.style.cssText = 'border-top:1px solid var(--hairline);padding-block:var(--space-3);overflow-wrap:anywhere;';
      var heading = add('h4', '', card), link = add('a', task.title || 'Untitled task', heading); link.href = task.href;
      add('p', task.status + ' · Started ' + date(task.created_at) + ' · Updated ' + date(task.updated_at), card);
      if (task.reason) add('p', task.reason, card);
      if (task.next_step) add('p', task.next_step, card);
      add('p', task.cost === null ? 'Recorded run cost unavailable' : 'Recorded run cost: USD ' + Number(task.cost).toLocaleString(undefined, {maximumFractionDigits:6, minimumFractionDigits:2}), card);
      if (task.approved) add('p', 'A person approved the saved result. This does not establish answer accuracy or business value.', card);
      var action = add('a', 'Open complete task and recovery controls', card); action.href = task.href;
    });
    var trend = add('details', ''); add('summary', 'Task creation over time (UTC)', trend);
    var periods = add('ul', '', trend);
    value.trend.forEach(function (row) { add('li', row.from + (row.to !== row.from ? ' to ' + row.to : '') + ': ' + row.tasks + (row.tasks === 1 ? ' task' : ' tasks'), periods); });
    var about = add('details', ''); add('summary', 'About these records', about);
    add('p', value.scope, about);
    add('p', 'Queued: ' + value.counts.queued + ' · State unavailable: ' + value.counts.other + ' · Approved saved results: ' + value.counts.approved, about);
    add('p', 'Tasks with unavailable recorded cost: ' + value.cost_unknown + '. Unavailable cost is not counted as free.', about);
  }
  async function read(expectedContext, expectedRevision, isCurrent) {
    if (unavailable) return false;
    var started = ++generation, period = days.value;
    if (controller) controller.abort(); controller = new AbortController();
    load.disabled = true; message.textContent = 'Reading current work…';
    var headers = {}; if (expectedContext || context) headers['X-Lightwork-Agent-Activity-Context'] = expectedContext || context;
    try {
      var response = await fetch('/api/v1/agents/' + encodeURIComponent(host.dataset.agentName) + '/recent-work?days=' + period, {headers:headers, signal:controller.signal, cache:'no-store', redirect:'error'});
      if (started !== generation || period !== days.value || (isCurrent && !isCurrent())) return false;
      if (response.status === 401 || response.status === 403) { boundary(); return false; }
      if (!response.ok || !/^application\/json\b/i.test(response.headers.get('content-type') || '')) throw new Error('Recent work could not be read. Refresh this view; your editor changes are kept.');
      var value = await response.json();
      if (started !== generation || period !== days.value || (isCurrent && !isCurrent())) return false;
      if (!/^[a-f0-9]{64}$/.test(value.context) || value.context !== response.headers.get('X-Lightwork-Agent-Activity-Context') || value.name !== host.dataset.agentName || (expectedContext && expectedContext !== value.context)) { boundary(); return false; }
      if (expectedRevision && expectedRevision !== value.revision) { clear(); message.textContent = 'The specialist or its work changed. Prepare the current view again; your editor changes are kept.'; return false; }
      context = value.context; render(value); message.textContent = 'Current recent work loaded. No tasks were changed.';
      return true;
    } catch (error) {
      if (started === generation && error.name !== 'AbortError') { results.textContent = ''; results.hidden = true; message.textContent = error.message || 'Recent work is unavailable. Refresh this view; your editor changes are kept.'; }
      return false;
    } finally { if (!unavailable && started === generation) load.disabled = false; }
  }
  load.addEventListener('click', function () { read(); });
  load.disabled = false;
  days.addEventListener('change', function () { clear(); load.disabled = false; message.textContent = 'Choose Read recent work to load this period.'; });
  function focusPanel() {
    var dialog = document.getElementById('jobcard-dlg'); if (!dialog.open) dialog.showModal();
    host.scrollIntoView({block:'start'}); load.focus();
  }
  function anchor() { if (window.location.hash === '#agent-recent-work' && !unavailable) focusPanel(); }
  window.addEventListener('hashchange', anchor); anchor();
  window.LightworkAgentActivity = {open:async function (expectedContext, name, revision, isCurrent) {
    if (name !== host.dataset.agentName || unavailable || (isCurrent && !isCurrent())) return false;
    if (days.value !== '30') { message.textContent = 'Your chosen period is kept. Set Last 30 days, then prepare this view again to open the same reviewed period.'; return false; }
    if (!(await read(expectedContext, revision, isCurrent))) return false;
    focusPanel(); return true;
  }};
})();
