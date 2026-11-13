/* Current native learning work remains reachable without starting it again. */
(function () {
  'use strict';
  var root = document.getElementById('learning-job-history'); if (!root) return;
  var choice = document.getElementById('learning-job-choice'), refresh = document.getElementById('learning-job-refresh');
  var status = document.getElementById('learning-job-status'), output = document.getElementById('learning-job-result');
  var stop = document.getElementById('learning-job-stop'), review = document.getElementById('learning-job-review');
  var original = document.getElementById('learning-job-original'), originalStatus = document.getElementById('learning-job-original-status');
  var generation = 0, current = null, busy = false, queued = false, publishingSelection = false, ownsSelection = false, publishedSelection = null;
  var selectedAtOpen = new URL(window.location.href).searchParams.get('learning_task');
  if (!/^[a-f0-9]{16}$/.test(selectedAtOpen || '')) selectedAtOpen = '';
  ownsSelection = !!selectedAtOpen;
  var API = '/api/v1/learning-ops/job-history';
  function node(tag, text, parent) { var element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (parent) parent.append(element); return element; }
  function when(value) { return window.mvWhen ? window.mvWhen(value) : new Date(value * 1000).toLocaleString(); }
  function lock(value) { busy = value; refresh.disabled = value; choice.disabled = value; var stoppable = !!(current && current.job.state === 'running' && current.job.can_stop); stop.hidden = !stoppable; stop.disabled = value || !stoppable; original.disabled = value; if (!value && queued) { queued = false; queueMicrotask(load); } }
  function selection() { if (!ownsSelection) return; var selected = current?.job.id || ''; if (selected === publishedSelection) return; publishedSelection = selected; publishingSelection = true; try { document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: current ? {kind: 'learning_job', id: current.job.id} : {}}})); } finally { publishingSelection = false; } }
  function saved() { if (!current) return null; try { var value = JSON.parse(sessionStorage.getItem('learning-job-stop:' + current.context + ':' + current.job.id) || 'null'); if (value && value.context === current.context && value.job === current.job.id && /^[a-f0-9]{32}$/.test(value.operation)) return value; } catch (_) { /* The authorized native receipt can still be read. */ } return current.original_stop && /^[a-f0-9]{32}$/.test(current.original_stop.operation) ? {context: current.context, job: current.job.id, operation: current.original_stop.operation} : null; }
  function save(row) {
    sessionStorage.setItem('learning-job-stop:' + row.context + ':' + row.job, JSON.stringify(row));
    var keys = Object.keys(sessionStorage).filter(function (key) { return key.startsWith('learning-job-stop:'); });
    keys.slice(0, Math.max(0, keys.length - 40)).forEach(function (key) { sessionStorage.removeItem(key); });
  }
  async function request(path, body) {
    var F = 'The current result could not be read. No work was repeated.';
    return window.mvFetchJSON(API + path, {method: body ? 'POST' : 'GET', cache: 'no-store', body: body || undefined, timeout: 20000,
      serverDetail: F, messages: {timeout: F, offline: F, unreadable: F}}, 'read the learning task');
  }
  function show(row) {
    current = row; output.replaceChildren();
    var heading = node('h3', row.job.label, output); heading.style.overflowWrap = 'anywhere';
    var details = node('dl', undefined, output);
    [['Started', when(row.job.started_at)], ['Current recorded status', row.status]].forEach(function (item) { node('dt', item[0], details); node('dd', item[1], details); });
    if (row.job.finished_at) { node('dt', 'Finished', details); node('dd', when(row.job.finished_at), details); }
    if (row.job.recorded_at) { node('dt', 'Last saved observation', details); node('dd', when(row.job.recorded_at), details); }
    if (!row.job.observation_saved) node('p', 'The current result is not confirmed as saved. Read the underlying learning records before making a new decision.', output);
    if (row.job.problem) node('p', row.job.problem, output);
    (row.observations || []).forEach(function (report) {
      node('h4', report.label, output); var counts = node('dl', undefined, output);
      Object.entries(report.counts).forEach(function (item) { node('dt', item[0], counts); node('dd', String(item[1]), counts); });
    });
    node('p', row.notice, output); status.textContent = 'Latest recorded progress is shown.';
    original.hidden = !saved(); selection(); lock(false);
  }
  async function readSelected() {
    if (busy) return;
    ownsSelection = true;
    if (!choice.value) { current = null; review.replaceChildren(); output.replaceChildren(); original.hidden = true; originalStatus.textContent = ''; selection(); lock(false); return; }
    var id = choice.value, started = ++generation; review.replaceChildren(); originalStatus.textContent = ''; lock(true);
    try { var row = await request('/' + encodeURIComponent(id)); if (started === generation) show(row); }
    catch (error) { if (started === generation) { current = null; output.replaceChildren(); status.textContent = error.message; original.hidden = true; selection(); } }
    finally { if (started === generation) lock(false); }
  }
  async function load() {
    if (busy) { queued = true; return; } var selected = choice.value || selectedAtOpen, started = ++generation; selectedAtOpen = ''; review.replaceChildren(); current = null; lock(true);
    try {
      var history = await request(''); if (started !== generation) return;
      choice.replaceChildren(); var empty = node('option', 'Choose a recent learning task', choice); empty.value = '';
      history.jobs.forEach(function (row) { var option = node('option', row.job.label + ' / ' + when(row.job.started_at) + ' / ' + row.status, choice); option.value = row.job.id; });
      choice.value = history.jobs.some(function (row) { return row.job.id === selected; }) ? selected : '';
      output.replaceChildren(); status.textContent = history.notice; original.hidden = true;
      if (choice.value) show(history.jobs.find(function (row) { return row.job.id === choice.value; })); else selection();
    } catch (error) { if (started === generation) { output.replaceChildren(); status.textContent = error.message; original.hidden = true; } }
    finally { if (started === generation) lock(false); }
  }
  refresh.addEventListener('click', function () { ownsSelection = true; load(); }); choice.addEventListener('change', readSelected);
  stop.addEventListener('click', async function () {
    if (!busy && current) { ownsSelection = true; selection(); }
    if (busy || !current || !current.job.can_stop) return;
    var started = ++generation, id = current.job.id; lock(true); review.replaceChildren();
    try {
      var reviewed = await request('/' + encodeURIComponent(id)); if (started !== generation) return;
      show(reviewed); if (!reviewed.job.can_stop || reviewed.job.state !== 'running') return;
      node('h3', 'Review this stop request', review);
      node('p', reviewed.job.label + ' / ' + when(reviewed.job.started_at) + ' / ' + reviewed.status, review);
      node('p', 'Request a stop at this task\'s next safe point. Completed work remains. This does not undo earlier changes or prove the task has stopped.', review);
      var label = node('label', undefined, review), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode(' I reviewed this exact task and want to request a stop.'));
      var apply = node('button', 'Confirm reviewed stop', review); apply.type = 'button'; apply.className = 'btn'; apply.disabled = true;
      consent.addEventListener('change', function () { apply.disabled = busy || !consent.checked; });
      apply.addEventListener('click', async function () {
        if (busy || !consent.checked || started !== generation || !current || current.job.id !== id) return;
        var operation = (window.mvNewId ? window.mvNewId() : crypto.randomUUID()).replace(/-/g, ''), body = {context: reviewed.context, revision: reviewed.revision, operation: operation, confirm: true};
        try { save({context: reviewed.context, job: id, operation: operation}); }
        catch (_) { originalStatus.textContent = 'The original request could not be saved in this browser. Nothing was submitted. Allow site storage before continuing.'; return; }
        lock(true); apply.disabled = true; original.hidden = false;
        try { var result = await request('/' + encodeURIComponent(id) + '/stop', body); if (started === generation) { show(result.current); review.replaceChildren(); originalStatus.textContent = result.receipt.message; } }
        catch (error) { if (started === generation) { review.replaceChildren(); originalStatus.textContent = 'The original stop reply is unconfirmed. Check its original outcome; no stop or work will be repeated automatically. ' + (error.name === 'AbortError' ? '' : error.message); } }
        finally { if (started === generation) lock(false); }
      });
      var cancel = node('button', 'Cancel this review', review); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', function () { if (!busy) review.replaceChildren(); });
      consent.focus();
    } catch (error) { if (started === generation) status.textContent = error.message; }
    finally { if (started === generation) lock(false); }
  });
  original.addEventListener('click', async function () {
    var row = saved(); if (busy || !row) return; var started = ++generation; review.replaceChildren(); lock(true);
    ownsSelection = true; selection();
    try { var result = await request('/' + encodeURIComponent(row.job) + '/stop/' + encodeURIComponent(row.operation)); if (started === generation) { show(result.current); originalStatus.textContent = result.message; } }
    catch (error) { if (started === generation) originalStatus.textContent = error.message + ' Nothing was repeated.'; }
    finally { if (started === generation) lock(false); }
  });
  function changed() { if (publishingSelection) return; generation++; current = null; review.replaceChildren(); output.replaceChildren(); choice.replaceChildren(); original.hidden = true; originalStatus.textContent = ''; status.textContent = 'Your account, workspace or access changed. Reading your current recent tasks.'; selectedAtOpen = new URL(window.location.href).searchParams.get('learning_task') || ''; if (!/^[a-f0-9]{16}$/.test(selectedAtOpen)) selectedAtOpen = ''; queued = false; lock(false); load(); }
  document.addEventListener('lightwork:workspace-changed', changed);
  document.addEventListener('lightwork:account-context-changed', changed);
  window.addEventListener('lightwork:context-changed', changed);
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (event.detail?.reason !== 'selection') changed(); });
  document.addEventListener('lightwork:copilot-selection', function (event) { if (publishingSelection) return; var value = event.detail?.selection; ownsSelection = !!(current && value?.kind === 'learning_job' && value.id === current.job.id); publishedSelection = ownsSelection ? value.id : null; });
  document.addEventListener('lightwork:product-operation-complete', load);
  window.addEventListener('lightwork:product-state-changed', load);
  load();
}());
