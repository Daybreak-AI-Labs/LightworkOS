// Learned page: more self-coaching tools -- clash check by meaning, trying
// proven lessons on other models, test cases (find, download, add) and the
// one-time hold-out record. Global administrators only.
(function () {
  'use strict';
  var root = document.getElementById('lpo-root');
  if (!root || !window.LWJobs) return;
  var J = window.LWJobs;
  var el = J.el, plural = J.plural;
  var API = '/api/v1/learning-ops/self-harness';
  function $(id) { return document.getElementById(id); }
  function say(id, text) { window.mvStatus($(id), text || ''); }
  function fill(id, nodes) {
    var box = $(id);
    box.textContent = '';
    (Array.isArray(nodes) ? nodes : [nodes]).forEach(function (n) { if (n) box.appendChild(n); });
  }
  function addOptions(select, models) {
    models.forEach(function (m) { var o = el('option', null, m.label); o.value = m.value; select.appendChild(o); });
  }

  function loadPlan() {
    J.request(API + '/plan').then(function (d) {
      var parts = [d.enabled ? 'Self-coaching is on.' : 'Self-coaching is off. Some tools below need it on: turn on ' + d.places.self_coaching + '.'];
      parts.push(d.test_cases_set_up ? '' : 'Test cases are not set up yet. Use Learning questions below to choose Lightwork’s managed location.');
      parts.push(d.spending_limit != null ? 'Testing can spend up to ' + J.money(d.spending_limit) + ' per run.' : '');
      say('lpo-plan', parts.filter(Boolean).join(' '));
      addOptions($('lpo-clash-model'), d.models);
    }).catch(async function (failure) {
      say('lpo-plan', await J.problem(failure, 'load the self-coaching tools'));
    });
  }

  // The native request is retained BEFORE dispatch. Recovery only reads it.
  (function meaningCheck() {
    var context = '', pending = null, busy = false, generation = 0, poll = null;
    var run = $('lpo-clash-run'), model = $('lpo-clash-model'), review = $('lpo-clash-review');
    var choice = $('lpo-clash-original'), read = $('lpo-clash-recover'), refresh = $('lpo-clash-refresh');
    var key = 'lightwork-meaning-check';
    var initial = new URL(location.href).searchParams.get('meaning_check');
    if (!/^[a-f0-9]{32}$/.test(initial || '')) initial = '';
    function lock(value) { busy = value; run.disabled = value || !context; model.disabled = value; refresh.disabled = value; choice.disabled = value; read.disabled = value || !choice.value; }
    function forget() { generation++; clearTimeout(poll); context = ''; pending = null; review.replaceChildren(); fill('lpo-clash-out', []); choice.replaceChildren(el('option', null, 'Choose your original check')); say('lpo-clash-status', 'Your account or access changed. Refresh the current controls before continuing.'); lock(false); }
    function save(value) { sessionStorage.setItem(key, JSON.stringify(value)); pending = value; }
    function saved() { try { var value = JSON.parse(sessionStorage.getItem(key) || 'null'); return value && value.context === context && /^[a-f0-9]{32}$/.test(value.operation) ? value : null; } catch (_) { return null; } }
    async function request(path, body) {
      var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 20000);
      try {
        var response = await fetch(API + '/clash-check' + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined, signal: controller.signal});
        var text = await response.text(); if (text.length > 262144) throw new Error('This complete response is too large to review. No work was repeated.');
        var value; try { value = JSON.parse(text); } catch (_) { value = {}; }
        if (!response.ok || response.redirected) { var error = new Error(typeof value.detail === 'string' ? value.detail : 'The current check could not be read. Nothing was repeated.'); error.authority = response.redirected || response.status === 401 || response.status === 403; throw error; }
        if (context && value.context && value.context !== context) { var changed = new Error('Your account or workspace changed.'); changed.authority = true; throw changed; }
        return value;
      } finally { clearTimeout(timer); }
    }
    function failure(error) { if (error.authority) forget(); else say('lpo-clash-status', error.name === 'AbortError' ? 'The reply was interrupted. Read the original result; no AI work will be repeated automatically.' : error.message); }
    function present(result) {
      if (result.context !== context) { forget(); return; }
      fill('lpo-clash-out', []); var output = $('lpo-clash-out'); output.append(el('p', null, result.message));
      if (result.state) output.append(el('p', null, 'Recorded progress: ' + ({admitted: 'Waiting to start', running: 'In progress', stopping: 'Stop requested', done: 'Finished', stopped: 'Stopped', failed: 'Could not finish', not_started: 'Not started', unconfirmed: 'Latest observation is unconfirmed'}[result.state] || 'Unavailable')));
      if (result.problem) output.append(el('p', null, result.problem));
      if (result.checked !== undefined) {
        output.append(el('p', null, result.checked + ' AI judgments received; ' + result.unknown + ' unavailable or not completed. ' + result.flagged + ' possible conflicts flagged by AI; ' + result.wording_flags + ' wording flags without an AI judgment. Recorded AI cost: ' + J.money(result.spent) + '.'));
        (result.pairs || []).forEach(function (pair) { var section = el('section'); section.append(el('h4', null, pair.area), el('p', null, pair.first), el('p', null, pair.second), el('p', 'muted', pair.basis)); output.append(section); });
        if (!result.flagged && !result.wording_flags) output.append(el('p', null, 'No possible conflicts were flagged among the completed comparisons. Unavailable judgments remain unknown.'));
      }
      if (result.task_href) { var link = el('a', null, 'Open progress and stop controls'); link.href = result.task_href; output.append(link); }
      output.append(el('p', 'muted', result.notice)); say('lpo-clash-status', result.active ? 'The original check is running. Read its latest progress without starting another.' : 'Original result read. No work was repeated.');
      clearTimeout(poll); if (result.active) { var current = generation; poll = setTimeout(function () { if (current === generation && !busy && choice.value === result.operation) readOriginal(); }, 1500); }
    }
    async function load() {
      if (busy) return; var current = ++generation, selected = choice.value || initial; initial = ''; clearTimeout(poll); lock(true);
      try {
        var state = await request(''); if (current !== generation) return;
        context = state.context; pending = saved(); selected = selected || (pending && pending.operation) || '';
        choice.replaceChildren(); var empty = el('option', null, 'Choose your original check'); empty.value = ''; choice.append(empty);
        state.requests.forEach(function (row) { var option = el('option', null, row.label); option.value = row.value; choice.append(option); });
        if (selected && !state.requests.some(function (row) { return row.value === selected; })) { var original = el('option', null, 'Original request saved in this browser'); original.value = selected; choice.append(original); }
        choice.value = selected; say('lpo-clash-status', state.notice); review.replaceChildren();
      } catch (error) { if (current === generation) failure(error); }
      finally { if (current === generation) lock(false); }
    }
    async function readOriginal() {
      if (busy || !context || !choice.value) return; var current = ++generation, operation = choice.value; clearTimeout(poll); lock(true); review.replaceChildren();
      try { var result = await request('/requests/' + encodeURIComponent(operation)); if (current === generation) present(result); }
      catch (error) { if (current === generation) failure(error); }
      finally { if (current === generation) lock(false); }
    }
    run.addEventListener('click', async function () {
      if (busy || !context) return; var current = ++generation; clearTimeout(poll); lock(true); review.replaceChildren();
      try {
        var reviewed = await request('/review', {context: context, model_id: model.value || null}); if (current !== generation) return;
        review.append(el('h4', null, 'Review this exact meaning check'));
        reviewed.changes.forEach(function (change) { review.append(el('h5', null, change.label)); if (Array.isArray(change.after)) { var list = el('ul'); change.after.forEach(function (line) { list.append(el('li', null, line)); }); review.append(list); } else review.append(el('p', null, change.after)); });
        var label = el('label'), consent = el('input'); consent.type = 'checkbox'; label.append(consent, document.createTextNode(' I reviewed all listed lessons and spending settings.')); review.append(label);
        var apply = el('button', 'btn', 'Start reviewed meaning check'); apply.type = 'button'; apply.disabled = true; review.append(apply);
        consent.addEventListener('change', function () { apply.disabled = busy || !consent.checked; });
        apply.addEventListener('click', async function () {
          if (busy || !consent.checked || current !== generation) return;
          try { save({context: context, operation: reviewed.operation}); } catch (_) { say('lpo-clash-status', 'This browser could not retain the original request. Allow site storage before starting; no AI call was made.'); return; }
          var option = el('option', null, 'Original request just reviewed'); option.value = reviewed.operation; choice.append(option); choice.value = reviewed.operation;
          lock(true); apply.disabled = true; say('lpo-clash-status', 'Submitting this reviewed original request…');
          try { var result = await request('', {context: context, token: reviewed.token, confirmed: true}); if (current === generation) { review.replaceChildren(); present(result); } }
          catch (error) { if (current === generation) { review.replaceChildren(); failure(error); } }
          finally { if (current === generation) lock(false); }
        });
        var cancel = el('button', 'btn btn--ghost', 'Cancel this review'); cancel.type = 'button'; cancel.addEventListener('click', function () { if (!busy) review.replaceChildren(); }); review.append(cancel); consent.focus();
        say('lpo-clash-status', 'No AI call has been made. Read every listed lesson before confirming.');
      } catch (error) { if (current === generation) failure(error); }
      finally { if (current === generation) lock(false); }
    });
    model.addEventListener('change', function () { generation++; clearTimeout(poll); review.replaceChildren(); lock(false); say('lpo-clash-status', 'Selection changed. Review the current lessons before starting. Your original request remains available.'); });
    choice.addEventListener('change', readOriginal); read.addEventListener('click', readOriginal); refresh.addEventListener('click', load);
    document.addEventListener('lightwork:copilot-context-changed', function (event) { if (event.detail && event.detail.reason === 'selection') { if (!busy) load(); } else { forget(); load(); } });
    window.addEventListener('lightwork:context-changed', function () { forget(); load(); });
    lock(false); load().then(function () { if (choice.value && context && !busy) readOriginal(); });
  })();

  var harvest = $('lpo-harvest');
  harvest.addEventListener('click', async function () {
    var mode = $('lpo-harvest-mode').value;
    if (mode === 'auto' && !(await window.mvConfirm('Add new test cases from past work straight away, without reviewing them first? They are used to judge future lessons.',
      { okText: 'Add them' }))) return;
    harvest.disabled = true;
    say('lpo-cases-status', 'Looking through past work…');
    try {
      var d = await J.request(API + '/test-cases/harvest', { method: 'POST', json: { mode: mode } });
      say('lpo-cases-status', !d.found ? 'No new test cases were found.' : (mode === 'auto'
        ? 'Added ' + plural(d.found, 'test case') + '.'
        : 'Found ' + plural(d.found, 'test case') + '. Review them in the lessons list above (refresh the page).'));
    } catch (failure) {
      say('lpo-cases-status', await J.problem(failure, 'find new test cases'));
    } finally { harvest.disabled = false; }
  });

  var exportBtn = $('lpo-export');
  exportBtn.addEventListener('click', async function () {
    exportBtn.disabled = true;
    say('lpo-cases-status', 'Preparing the download…');
    try {
      var r = await J.request(API + '/test-cases/export', { raw: true });
      J.saveBlob(await r.blob(), 'Lightwork-test-cases.json');
      say('lpo-cases-status', 'Downloaded ' + plural(Number(r.headers.get('X-Lightwork-Cases') || 0), 'test case') + '.');
    } catch (failure) {
      say('lpo-cases-status', await J.problem(failure, 'download the test cases'));
    } finally { exportBtn.disabled = false; }
  });

  (function questionImport() {
    var input = $('lpo-import-file'), mode = $('lpo-import-how'), check = $('lpo-import-check');
    var originals = $('lpo-import-original'), read = $('lpo-import-recover'), refresh = $('lpo-import-refresh');
    var context = '', revision = '', generation = 0, accessGeneration = 0, reading = 0, busy = false, locked = true;
    var key = 'lightwork-question-import';
    function placeholder() { var option = el('option', null, 'Choose your original import'); option.value = ''; return option; }
    function status(message) { say('lpo-import-status', message); }
    function lock() {
      check.disabled = busy || locked; input.disabled = locked; mode.disabled = locked;
      refresh.disabled = busy; originals.disabled = busy || locked; read.disabled = busy || locked || !originals.value;
    }
    function invalidate() { generation++; $('lpo-cases-out').replaceChildren(); }
    function clear() {
      accessGeneration++; invalidate(); reading++; context = ''; revision = ''; locked = true; busy = false;
      input.value = ''; mode.value = 'merge'; originals.replaceChildren(placeholder());
      $('lpo-import-result').replaceChildren(); status('Your account or access changed. Refresh the current controls before continuing.'); lock();
    }
    function saved() {
      try { var value = JSON.parse(sessionStorage.getItem(key) || 'null'); return value && value.context === context && /^[a-f0-9]{32}$/.test(value.operation) ? value : null; }
      catch (_) { return null; }
    }
    function remember(value) { sessionStorage.setItem(key, JSON.stringify({context: context, operation: value.operation})); }
    function addOriginal(value, label) {
      if (!Array.from(originals.options).some(function (option) { return option.value === value; })) {
        var option = el('option', null, label); option.value = value; originals.appendChild(option);
      }
    }
    async function request(path, options) {
      options = options || {};
      var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 20000);
      var headers = {'Content-Type': 'application/json'};
      if (context) headers['X-Lightwork-Import-Context'] = context;
      if (options.token) headers['X-Lightwork-Import-Review'] = options.token;
      try {
        var response = await fetch(API + '/test-cases/import' + path, {method: options.body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', headers: headers, body: options.body, signal: controller.signal});
        var text = await response.text(); if (text.length > 262144) throw new Error('The complete review is too large to display. Nothing was repeated.');
        var value; try { value = JSON.parse(text); } catch (_) { value = {}; }
        if (!response.ok || response.redirected) {
          var detail = value.detail;
          var failure = new Error(typeof detail === 'string' ? detail : detail && detail.message || 'The current import could not be read. Nothing was repeated.');
          failure.authority = response.redirected || response.status === 401 || response.status === 403 || !!(detail && detail.context_lost); throw failure;
        }
        if (context && value.context && value.context !== context) { var changed = new Error('Your account or workspace changed.'); changed.authority = true; throw changed; }
        return value;
      } finally { clearTimeout(timer); }
    }
    function failed(error, access, current, message) {
      if (access !== accessGeneration) return;
      if (error.authority) { clear(); return; }
      if (current === undefined || current === generation) status(message || error.message || 'The current import could not be read. Your chosen file is kept.');
    }
    async function controls(expected, isCurrent) {
      var access = accessGeneration, current = generation;
      try {
        var state = await request('');
        if (access !== accessGeneration || current !== generation || isCurrent && !isCurrent()) return false;
        if (expected && state.context !== expected) { clear(); throw new Error('Your account or workspace changed. Open the current controls again.'); }
        if (revision && revision !== state.revision) invalidate();
        context = state.context; revision = state.revision; locked = false;
        $('lpo-import-notice').textContent = state.notice;
        var chosen = originals.value;
        originals.replaceChildren(placeholder());
        state.requests.forEach(function (row) { addOriginal(row.value, row.label); });
        var pending = saved(); if (pending) addOriginal(pending.operation, 'Original import · awaiting its result');
        if (chosen) originals.value = chosen; else if (pending) originals.value = pending.operation;
        lock(); return true;
      } catch (error) { failed(error, access, current); throw error; }
    }
    // Every saved field is displayed, including fields Lightwork preserves but
    // does not interpret. No editable file code is needed for this review.
    function label(keyName) {
      var names = {goal: 'Question or task', expected: 'Expected answer', task_source: 'Completed-work source', goal_id: 'Completed work',
        tenant: 'Workspace', owner: 'Owner', digest: 'Source fingerprint', authoring_request: 'Original question reference',
        privacy_schema: 'Source protection', source_goal_ids: 'Original work', added_at: 'Saved at', _lightwork_case_effects_v1: 'Import history'};
      return names[keyName] || keyName.replace(/_/g, ' ').replace(/^./, function (character) { return character.toUpperCase(); });
    }
    function detail(value, field) {
      if (field === 'privacy_schema' && value === 'owned-task-question-v1') value = 'Protected question from completed work';
      if (!value || typeof value !== 'object') return el('p', null, value === null ? 'Not set' : String(value));
      var list = el(Array.isArray(value) ? 'ol' : 'dl');
      Object.keys(value).forEach(function (name) {
        if (Array.isArray(value)) { var item = el('li'); item.appendChild(detail(value[name])); list.appendChild(item); }
        else { list.appendChild(el('dt', null, label(name))); var description = el('dd'); description.appendChild(detail(value[name], name)); list.appendChild(description); }
      });
      if (!Object.keys(value).length) list.appendChild(el('p', 'muted', 'No saved details.'));
      return list;
    }
    function collection(title, data, models) {
      var section = el('details'), heading = el('summary', null, title); section.appendChild(heading);
      Object.keys(data).forEach(function (name) {
        var group = el('section');
        var model = models.find(function (row) { return row.key === name; });
        group.appendChild(el('h4', null, model ? model.label : label(name)));
        group.appendChild(detail(data[name])); section.appendChild(group);
      });
      if (!Object.keys(data).length) section.appendChild(el('p', 'muted', 'No questions.'));
      return section;
    }
    input.addEventListener('change', invalidate); mode.addEventListener('change', invalidate);
    document.addEventListener('lightwork:account-context-changed', clear);
    originals.addEventListener('change', function () { reading++; lock(); });
    refresh.addEventListener('click', function () { controls().catch(function () {}); });
    read.addEventListener('click', async function () {
      var operation = originals.value, access = accessGeneration, sequence = ++reading;
      if (locked || busy || !operation) return;
      busy = true; lock();
      try {
        var row = await request('/requests/' + operation);
        if (access !== accessGeneration || sequence !== reading || originals.value !== operation) return;
        $('lpo-import-result').replaceChildren(el('p', null, row.message));
        if (row.confirmed && saved() && saved().operation === operation) sessionStorage.removeItem(key);
      } catch (error) { failed(error, access); }
      finally { if (access === accessGeneration) { busy = false; lock(); } }
    });
    check.addEventListener('click', async function () {
      if (locked || busy) return;
      var file = input.files && input.files[0], replace = mode.value === 'replace';
      if (!file) { status('Choose a learning-question file first.'); return; }
      if (file.size > 5 * 1024 * 1024) { status('Choose a file of 5 MiB or less. Nothing was shortened or changed.'); return; }
      invalidate(); var current = generation, access = accessGeneration, selectedContext = context;
      function same() { return access === accessGeneration && current === generation && selectedContext === context && !locked && file === input.files[0] && replace === (mode.value === 'replace'); }
      busy = true; lock(); status('Reading the complete file and current questions…');
      try {
        var body = await J.readFile(file); if (!same()) return;
        var data = await request('/preview?replace=' + replace, {body: body}); if (!same()) return;
        var nodes = [el('p', null, data.notice), J.table(['Model', 'Questions now', 'After import'], data.keys.map(function (row) { return [row.label, String(row.now), String(row.after)]; })),
          collection('Complete chosen file', data.file, data.keys), collection('Current saved questions', data.before, data.keys), collection('Questions after this import', data.after, data.keys)];
        var apply = el('button', replace ? 'btn btn--danger' : 'btn btn--primary', replace ? 'Replace with this reviewed file' : 'Add these reviewed questions');
        apply.type = 'button'; var dispatched = false;
        apply.addEventListener('click', async function () {
          if (busy || dispatched || !same()) return;
          apply.disabled = true;
          var confirmed = await window.mvConfirm(replace ? 'Replace all ' + data.total_now + ' current questions with the ' + data.total_after + ' reviewed questions? Questions outside this file will be removed.' : 'Add ' + plural(data.added, 'new question') + ' from this reviewed file? Current questions and their saved details stay in place.', {okText: replace ? 'Replace' : 'Add'});
          if (!same()) return;
          if (!confirmed) { apply.disabled = false; return; }
          try { remember(data); } catch (_) { status('This browser cannot keep your original request for recovery. Nothing was imported.'); apply.disabled = false; return; }
          dispatched = true; busy = true; lock();
          addOriginal(data.operation, 'Original import · awaiting its result'); originals.value = data.operation;
          try {
            var row = await request('?confirm=true&replace=' + replace, {body: body, token: data.token});
            if (!same()) return;
            $('lpo-import-result').replaceChildren(el('p', null, row.message));
            invalidate(); if (row.confirmed) sessionStorage.removeItem(key);
            status('Read the original result for this import. Refresh before reviewing another file.');
          } catch (error) { failed(error, access, current, error.message + ' Read original result; this import will not be repeated. Your chosen file is kept.'); }
          finally { if (access === accessGeneration) { busy = false; lock(); } }
        });
        nodes.push(apply); fill('lpo-cases-out', nodes);
        status(replace ? 'Review the complete before and after questions. Replacement removes questions outside the file.' : 'Review the complete file and preserved questions before adding ' + plural(data.added, 'new question') + '.');
      } catch (error) { failed(error, access, current); }
      finally { if (access === accessGeneration) { busy = false; lock(); } }
    });
    window.LightworkLearnedCaseImport = {open: async function (expected, isCurrent) {
      if (!/^[a-f0-9]{64}$/.test(expected || '') || typeof isCurrent !== 'function' || !isCurrent()) throw new Error('Open the current question-import controls again.');
      if (!await controls(expected, isCurrent) || !isCurrent()) return false;
      $('learning-case-import').scrollIntoView({behavior: 'smooth', block: 'start'}); input.focus();
      return true;
    }};
    lock(); controls().catch(function () {});
  })();

  loadPlan();
})();
