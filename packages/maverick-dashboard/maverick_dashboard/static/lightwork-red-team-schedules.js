// Scheduled attack tests on the AI assurance page: list, schedule, cancel
// and start the checks that are due. Every change goes through the existing
// administrator-only routes; this file only turns them into buttons.
(function () {
  'use strict';
  var root = document.getElementById('rts-root');
  if (!root) return;
  var api = root.getAttribute('data-api-base') || '';
  var admin = root.getAttribute('data-admin') === '1';
  var rows = document.getElementById('rts-rows');
  var status = document.getElementById('rts-status');
  var form = document.getElementById('rts-create');
  var formStatus = document.getElementById('rts-create-status');
  var runDue = document.getElementById('rts-run-due');
  var names = { assets: {}, agents: {} };
  try {
    var island = document.getElementById('rts-names');
    if (island) names = JSON.parse(island.textContent || '{}') || names;
  } catch (e) { /* names stay generic */ }
  var columns = admin ? 7 : 6;

  function say(el, text) { window.mvStatus(el, String(text || '')); }
  function errorText(failure, action) {
    if (typeof window.mvErrorText === 'function') return window.mvErrorText(failure, action);
    return 'Could not ' + action + '. Try again.';
  }
  function when(ts) {
    return (typeof window.mvWhen === 'function' ? window.mvWhen(ts) : '') || '';
  }
  function often(seconds) {
    var s = Number(seconds) || 0;
    var day = 86400;
    if (s === day) return 'Every day';
    if (s === 7 * day) return 'Every week';
    if (s === 14 * day) return 'Every two weeks';
    if (s % day === 0 && s > 0) return 'Every ' + (s / day) + ' days';
    if (s % 3600 === 0 && s > 0) return s === 3600 ? 'Every hour' : 'Every ' + (s / 3600) + ' hours';
    return 'Every ' + Math.max(1, Math.round(s / 60)) + ' minutes';
  }
  function stateText(row) {
    if (row.status === 'active') return row.run_claimed ? 'Active (a check is starting)' : 'Active';
    if (row.status === 'cancelled') return 'Cancelled';
    return typeof window.mvHuman === 'function' ? window.mvHuman(row.status) : 'Unknown';
  }
  function cell(tr, text, header) {
    var td = document.createElement(header ? 'th' : 'td');
    if (header) td.scope = 'row';
    td.textContent = text;
    tr.appendChild(td);
    return td;
  }
  function message(text, withButton) {
    rows.textContent = '';
    var tr = document.createElement('tr');
    var td = cell(tr, text);
    td.colSpan = columns;
    if (withButton && form) {
      var go = document.createElement('button');
      go.type = 'button';
      go.className = 'btn btn--ghost';
      go.textContent = 'Schedule a check';
      go.addEventListener('click', function () {
        var first = form.querySelector('select');
        if (first) first.focus();
      });
      td.appendChild(document.createTextNode(' '));
      td.appendChild(go);
    }
    rows.appendChild(tr);
  }

  function render(items) {
    if (!items.length) {
      message(admin
        ? 'No checks are scheduled yet. Set one up so attack tests repeat on their own.'
        : 'No checks are scheduled yet. Ask an administrator to schedule one.', admin);
      return;
    }
    rows.textContent = '';
    items.forEach(function (row) {
      var tr = document.createElement('tr');
      cell(tr, names.assets[row.target_asset_id] || 'An AI system not in your inventory', true);
      cell(tr, names.agents[row.external_agent_id] || 'A testing agent no longer registered');
      cell(tr, often(row.cadence_seconds));
      cell(tr, row.status === 'active' ? (when(row.next_run_at) || 'As soon as due checks start') : '—');
      cell(tr, String(Number(row.run_count) || 0));
      cell(tr, stateText(row));
      if (admin) {
        var td = cell(tr, '');
        if (row.status === 'active') {
          var btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'btn btn--danger';
          btn.textContent = 'Cancel';
          btn.setAttribute('aria-label', 'Cancel the scheduled check for ' + (names.assets[row.target_asset_id] || 'this AI system'));
          btn.addEventListener('click', function () { cancel(row, btn); });
          td.appendChild(btn);
        } else {
          td.textContent = '—';
        }
      }
      rows.appendChild(tr);
    });
  }

  function load() {
    return window.mvFetchJSON(api + '/schedules?limit=100')
      .then(function (data) {
        var items = Array.isArray(data && data.items) ? data.items : [];
        render(items);
        if (data && data.truncated) say(status, 'Showing the first ' + items.length + ' scheduled checks.');
      })
      .catch(function (failure) {
        message(errorText(failure, 'load the scheduled checks'));
      });
  }

  function post(path, body) {
    return window.mvFetchJSON(api + path, { method: 'POST', body: body || {} });
  }

  async function cancel(row, button) {
    var ok = await window.mvConfirm(
      'Cancel this scheduled check? No new checks will start for it. A check that has already started still finishes.',
      { okText: 'Cancel schedule' });
    if (!ok) return;
    button.disabled = true;
    say(status, 'Cancelling…');
    try {
      await post('/schedules/' + encodeURIComponent(row.id) + '/cancel', {
        expected_revision: Number(row.revision) || 1,
        rationale: 'Cancelled from the scheduled checks list.'
      });
      say(status, 'Scheduled check cancelled.');
      await load();
    } catch (failure) {
      say(status, errorText(failure, 'cancel the scheduled check'));
      button.disabled = false;
    }
  }

  if (runDue) {
    runDue.addEventListener('click', async function () {
      var ok = await window.mvConfirm(
        'Start every scheduled check that is due now? Each one sends made-up attack prompts to the test copy of its AI system.',
        { okText: 'Start due checks' });
      if (!ok) return;
      runDue.disabled = true;
      say(status, 'Starting due checks…');
      try {
        var result = await post('/schedules/run-due', { limit: 20 });
        var started = Number(result && result.count) || 0;
        var failed = Array.isArray(result && result.failures) ? result.failures.length : 0;
        var text = started === 0 && failed === 0
          ? 'Nothing is due right now.'
          : 'Started ' + started + (started === 1 ? ' check.' : ' checks.') +
            (started ? ' Refresh the page to see them under recent test runs.' : '');
        if (failed) text += ' ' + failed + (failed === 1 ? ' check' : ' checks') +
          ' could not start. Check that the testing agent is still registered.';
        say(status, text);
        await load();
      } catch (failure) {
        say(status, errorText(failure, 'start the due checks'));
      } finally {
        runDue.disabled = false;
      }
    });
  }

  function reference(input) {
    if (input && input.value) return input.value;
    var value = (window.crypto && typeof window.crypto.randomUUID === 'function')
      ? window.crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2);
    if (input) input.value = value;
    return value;
  }

  if (form) {
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var fields = new FormData(form);
      if (!fields.get('asset_id') || !fields.get('external_agent_id')) {
        say(formStatus, 'Choose the AI system and the testing agent first.');
        return;
      }
      if (!fields.has('safe_target_environment')) {
        say(formStatus, 'Confirm that the checks will test a separate test copy.');
        return;
      }
      var body = {
        asset_id: String(fields.get('asset_id')),
        external_agent_id: String(fields.get('external_agent_id')),
        idempotency_key: reference(form.querySelector('[name="idempotency_key"]')),
        safe_target_environment: true,
        cadence_seconds: Number(fields.get('cadence_seconds')) || 604800
      };
      var first = String(fields.get('first_run_at') || '');
      if (first) {
        var at = new Date(first).getTime();
        if (!isFinite(at)) { say(formStatus, 'Choose a valid date and time for the first check.'); return; }
        body.first_run_at = Math.max(1, Math.floor(at / 1000));
      }
      var button = form.querySelector('button[type=submit]');
      if (button) button.disabled = true;
      say(formStatus, 'Scheduling…');
      try {
        await post('/schedules', body);
        say(formStatus, 'Check scheduled.');
        form.reset();
        var ref = form.querySelector('[name="idempotency_key"]');
        if (ref) ref.value = '';
        await load();
      } catch (failure) {
        say(formStatus, errorText(failure, 'schedule the check'));
      } finally {
        if (button) button.disabled = false;
      }
    });
  }

  load();
})();
