/* Settings > Maintenance: installation operations (services, versions, release
   checks, setup checks, whole configuration, database, moves and upkeep). */
(function () {
  'use strict';
  var root = document.querySelector('[data-ops="services"]');
  if (!root) return;
  var BASE = '/api/v1/admin/installation';
  var SERVICES = '/api/v1/admin/services';

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function q(sel) { return document.querySelector(sel); }
  function out(name) { return q('[data-ops-out="' + name + '"]'); }
  function say(name, text) { window.mvStatus(q('[data-ops-status="' + name + '"]'), text || ''); }
  function when(ts) { return window.mvWhen ? window.mvWhen(ts) : ''; }
  function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }
  async function failText(failure, action) {
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function call(path, method, body) {
    return window.mvFetchJSON(path, {method: method || 'GET', cache: 'no-store', body: body});
  }
  async function confirmed(message, okText) {
    return window.mvConfirm ? window.mvConfirm(message, {okText: okText}) : false;
  }
  function badge(ok, yes, no) { return el('span', 'badge ' + (ok ? 'active' : 'blocked'), ok ? yes : no); }
  function list(rows) {
    var ul = el('ul', 'maintenance-list');
    rows.forEach(function (row) {
      var li = el('li');
      li.appendChild(el('span', 'maintenance-label', row.label));
      if (row.value != null) li.appendChild(el('span', null, row.value));
      if (row.ok != null) li.appendChild(badge(row.ok, row.yes || 'OK', row.no || 'Needs attention'));
      ul.appendChild(li);
    });
    return ul;
  }
  function table(headers, rows) {
    var wrap = el('div', 'ops-scroll');
    var t = el('table');
    var head = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
    var thead = el('thead'); thead.appendChild(head); t.appendChild(thead);
    var body = el('tbody');
    rows.forEach(function (cells) {
      var tr = el('tr');
      cells.forEach(function (cell) {
        var td = el('td');
        if (cell && cell.nodeType) td.appendChild(cell); else td.textContent = cell == null ? '' : String(cell);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    t.appendChild(body); wrap.appendChild(t);
    return wrap;
  }
  function technical(rows) {
    if (!rows || !rows.length) return null;
    var details = el('details', 'settings-details');
    details.appendChild(el('summary', null, 'Technical details (for your IT team)'));
    var ul = el('ul', 'maintenance-list');
    rows.forEach(function (row) { ul.appendChild(el('li', 'muted', typeof row === 'string' ? row : row.text)); });
    details.appendChild(ul);
    return details;
  }
  function show(name, nodes) {
    var box = out(name); if (!box) return;
    box.textContent = '';
    nodes.forEach(function (node) { if (node) box.appendChild(node); });
  }
  function para(text) { return el('p', null, text); }

  // ---- services ---------------------------------------------------------------
  function serviceRow(svc) {
    var state = svc.running ? 'Running since ' + when(svc.since)
      : (svc.last_error ? svc.last_error
        : (svc.setting_driven && svc.wanted === false ? 'Turned off in All settings' : 'Not running from this app'));
    var actions = el('span', 'ops-actions');
    function button(label, action, danger) {
      var b = el('button', 'btn' + (danger ? ' btn--danger' : ''), label);
      b.type = 'button';
      b.setAttribute('aria-label', label + ' ' + svc.label);
      b.addEventListener('click', function () { serviceAction(svc, action, b); });
      actions.appendChild(b);
    }
    var off = svc.setting_driven && svc.wanted === false;
    if (svc.running) {
      if (!off) button('Restart', 'restart');
      button('Stop', 'stop', true);
    } else if (!off) {
      button('Start', 'start');
    }
    if (off) {
      var link = el('a', 'btn btn--ghost', 'Turn on in All settings');
      link.href = svc.settings_href || '/settings/all';
      link.setAttribute('aria-label', 'Turn on ' + svc.label + ' in All settings');
      actions.appendChild(link);
    }
    var name = el('div');
    name.appendChild(el('strong', null, svc.label));
    name.appendChild(el('div', 'muted', svc.about));
    var status = el('div');
    status.appendChild(badge(svc.running, 'Running', 'Stopped'));
    status.appendChild(el('div', 'muted', state));
    var log = svc.log && svc.log.length ? technical(svc.log) : null;
    if (log) status.appendChild(log);
    return [name, status, actions];
  }
  async function loadServices() {
    say('services', 'Checking services…');
    try {
      var data = await call(SERVICES);
      var rows = data.services.map(serviceRow);
      if (data.dashboard) rows.unshift(dashboardRow(data.dashboard));
      show('services', [table(['Service', 'Status', 'Actions'], rows)]);
      say('services', '');
    } catch (failure) { say('services', await failText(failure, 'check the services')); }
  }
  function dashboardRow(app) {
    var name = el('div');
    name.appendChild(el('strong', null, app.label));
    name.appendChild(el('div', 'muted', app.about));
    var status = el('div');
    status.appendChild(badge(true, 'Running', 'Stopped'));
    status.appendChild(el('div', 'muted', 'Running since ' + when(app.since)));
    var actions = el('span', 'ops-actions');
    if (app.can_restart) {
      var b = el('button', 'btn', 'Restart');
      b.type = 'button';
      b.setAttribute('aria-label', 'Restart ' + app.label);
      b.addEventListener('click', function () { restartDashboard(app, b); });
      actions.appendChild(b);
      actions.appendChild(el('span', 'muted', app.note));
    } else {
      actions.appendChild(el('span', 'muted', app.note));
    }
    return [name, status, actions];
  }
  async function restartDashboard(app, button) {
    if (!await confirmed('Restart this app? Everyone using it is disconnected for a moment while it starts again. ' + app.note, 'Restart')) return;
    button.disabled = true;
    say('services', 'Restarting this app…');
    try {
      var data = await call(SERVICES + '/dashboard/restart', 'POST', {confirm: true});
      say('services', data.summary);
    } catch (failure) {
      button.disabled = false;
      say('services', await failText(failure, 'restart this app'));
    }
  }
  async function serviceAction(svc, action, button) {
    var body = {service: svc.kind, confirm: false};
    if (action === 'stop' || action === 'restart') {
      var ok = await confirmed(action === 'stop'
        ? 'Stop ' + svc.label + '? ' + svc.about + ' That stops until it is started again.'
        : 'Restart ' + svc.label + '? Work it is doing right now is interrupted.', action === 'stop' ? 'Stop' : 'Restart');
      if (!ok) return;
      body.confirm = true;
    }
    button.disabled = true;
    say('services', (action === 'start' ? 'Starting ' : action === 'stop' ? 'Stopping ' : 'Restarting ') + svc.label + '…');
    try {
      await call(SERVICES + '/' + action, 'POST', body);
      await loadServices();
      say('services', svc.label + (action === 'stop' ? ' stopped.' : ' started.'));
    } catch (failure) {
      button.disabled = false;
      say('services', await failText(failure, action + ' ' + svc.label));
    }
  }

  // ---- read-only panels -------------------------------------------------------
  var runners = {};
  runners.services = loadServices;
  runners.version = async function () {
    say('version', 'Reading versions…');
    try {
      var data = await call(BASE + '/versions');
      show('version', [para(data.summary),
        table(['Part', 'Version'], data.parts.map(function (p) { return [p.name, p.installed ? p.version : 'Not installed']; })),
        list(data.details)]);
      say('version', '');
    } catch (failure) { say('version', await failText(failure, 'read the versions')); }
  };
  runners.release = async function () {
    say('version', 'Checking every release part. This can take a minute…');
    try {
      var data = await call(BASE + '/release-check', 'POST');
      show('version', [el('p', null, ''), list([{label: 'Release parts', value: data.summary, ok: data.ready,
        yes: 'All present', no: 'Something is missing'}]), technical(data.technical)]);
      say('version', '');
    } catch (failure) { say('version', await failText(failure, 'check the release parts')); }
  };
  runners.setup = async function () {
    say('setup', 'Running setup checks…');
    try {
      var data = await call('/api/v1/setup/checks');
      var nodes = [];
      [['Running tasks', data.runtime], ['Assurance reviews', data.assurance]].forEach(function (pair) {
        var report = pair[1] || {};
        nodes.push(el('h3', null, pair[0]));
        nodes.push(list([{label: 'Ready', value: report.ready ? 'Ready' : 'Not ready yet', ok: report.ready === true,
          yes: 'Ready', no: 'Not ready'}]));
        var rows = el('ul', 'maintenance-list');
        (report.checks || []).forEach(function (c) {
          var li = el('li');
          li.appendChild(el('span', 'maintenance-label', c.title || 'Check'));
          li.appendChild(el('span', 'muted', c.summary || ''));
          li.appendChild(badge(c.status === 'ready', 'Ready', c.state_label || 'Needs fixing'));
          if (c.fix_href && c.fix_label) { var a = el('a', 'btn btn--ghost', c.fix_label); a.href = c.fix_href; li.appendChild(a); }
          rows.appendChild(li);
        });
        nodes.push(rows);
        nodes.push(technical((report.checks || []).filter(function (c) { return c.detail; }).map(function (c) { return (c.title || 'Check') + ': ' + c.detail; })));
      });
      show('setup', nodes);
      say('setup', '');
    } catch (failure) { say('setup', await failText(failure, 'run the setup checks')); }
  };
  runners.config = async function () {
    say('config', 'Reading every setting…');
    try {
      var data = await call(BASE + '/configuration');
      var nodes = [para(data.summary)];
      if (data.unreadable) nodes.push(para('One of the settings files could not be read, so its settings are being ignored. Whoever installed Lightwork needs to repair it.'));
      data.sections.forEach(function (section) {
        var details = el('details', 'settings-details');
        details.appendChild(el('summary', null, section.name + ' (' + plural(section.keys.length, 'setting') + ')'));
        details.appendChild(table(['Setting', 'Part', 'Value', 'Comes from', 'Change'], section.keys.map(function (k) {
          var change;
          if (k.href) { change = el('a', 'btn btn--ghost', k.link_label); change.href = k.href; }
          else { change = el('span', 'muted', k.reason || 'Only in the installation settings file'); }
          return [k.setting, k.where, k.value, k.source, change];
        })));
        nodes.push(details);
      });
      show('config', nodes);
      say('config', '');
    } catch (failure) { say('config', await failText(failure, 'read the settings')); }
  };
  runners['settings-file'] = async function () {
    say('config', 'Checking the settings file…');
    try {
      var data = await call(BASE + '/settings-file');
      var nodes = [para(data.summary)];
      if (data.can_update) {
        var update = el('button', 'btn', 'Update the settings file');
        update.type = 'button';
        update.addEventListener('click', updateSettingsFile);
        nodes.push(update);
      }
      nodes.push(technical(data.technical));
      show('config', nodes);
      say('config', '');
    } catch (failure) { say('config', await failText(failure, 'check the settings file')); }
  };
  async function updateSettingsFile() {
    if (!await confirmed('Update the settings file? A dated backup copy of the current file is kept next to it first.', 'Update')) return;
    say('config', 'Updating the settings file…');
    try {
      var data = await call(BASE + '/settings-file/update', 'POST', {confirm: true});
      show('config', [para(data.summary + (data.backup ? ' The previous file was kept as a backup copy.' : '')), technical(data.technical)]);
      say('config', 'Settings file updated.');
    } catch (failure) { say('config', await failText(failure, 'update the settings file')); }
  }
  runners['database-updates'] = async function () {
    say('database', 'Checking for waiting database updates…');
    try {
      var data = await call(BASE + '/database-updates');
      show('database', [list([{label: 'Database updates', value: data.summary, ok: data.ok && !data.needs_pause,
        yes: data.pending ? 'Safe to apply' : 'Up to date', no: 'Plan a pause'}]), technical(data.technical)]);
      say('database', '');
    } catch (failure) { say('database', await failText(failure, 'check for database updates')); }
  };
  runners.separation = async function () {
    say('database', 'Checking workspace separation…');
    try {
      var data = await call(BASE + '/database-separation');
      var nodes = [para(data.summary)];
      if (data.rows && data.rows.length) {
        nodes.push(table(['Records', 'State'], data.rows.map(function (r) { return [r.records, r.state]; })));
      }
      nodes.push(technical(data.technical));
      show('database', nodes);
      say('database', '');
    } catch (failure) { say('database', await failText(failure, 'check workspace separation')); }
  };
  runners.fingerprint = async function () {
    say('upkeep', 'Reading the fingerprint…');
    try {
      var data = await call(BASE + '/key-fingerprint');
      var nodes = [para(data.summary)];
      if (data.available) {
        var code = el('code', 'ops-fingerprint', data.fingerprint);
        var copy = el('button', 'btn', 'Copy fingerprint');
        copy.type = 'button';
        copy.addEventListener('click', async function () {
          try { await navigator.clipboard.writeText(data.fingerprint); say('upkeep', 'Fingerprint copied.'); }
          catch (e) { say('upkeep', 'Select the fingerprint and copy it.'); }
        });
        nodes.push(code, copy);
      }
      show('upkeep', nodes);
      say('upkeep', '');
    } catch (failure) { say('upkeep', await failText(failure, 'read the fingerprint')); }
  };
  runners['local-models'] = async function () {
    say('upkeep', 'Reading the plan…');
    try {
      var data = await call(BASE + '/local-models');
      show('upkeep', [para(data.summary), data.facts ? list(data.facts) : null, technical(data.technical)]);
      say('upkeep', '');
    } catch (failure) { say('upkeep', await failText(failure, 'read the plan')); }
  };
  runners.receipts = async function () {
    if (!await confirmed('Clear the stored text of chat messages that were delivered long ago? The record that each was delivered is kept.', 'Tidy up')) return;
    say('upkeep', 'Tidying up message receipts…');
    try {
      var data = await call(BASE + '/message-receipts/tidy', 'POST', {confirm: true});
      show('upkeep', [para(data.summary)]);
      say('upkeep', 'Done.');
    } catch (failure) { say('upkeep', await failText(failure, 'tidy up message receipts')); }
  };

  // ---- background jobs -----------------------------------------------------------
  async function follow(job, name, done) {
    var current = job;
    for (var i = 0; i < 600 && current.state === 'running'; i++) {
      await new Promise(function (resolve) { setTimeout(resolve, 1000); });
      try { current = (await call(BASE + '/jobs/' + encodeURIComponent(current.id))).job; }
      catch (failure) { say(name, await failText(failure, 'check progress')); return; }
    }
    if (current.state === 'done') done(current.result || {});
    else if (current.state === 'failed') say(name, current.error || 'It did not finish.');
    else say(name, 'Still working. Check back in a few minutes.');
    if (current.record_warning) say(name, (current.state === 'done' ? 'The work finished. ' : '') +
      'Its result could not be added to the activity record. Ask your administrator to reconcile it before continuing.');
  }
  runners.components = async function () {
    if (!await confirmed('Prepare the connection components now? This rebuilds them in Lightwork\'s program folder.', 'Prepare')) return;
    say('upkeep', 'Preparing connection components…');
    try {
      var data = await call(BASE + '/connection-components', 'POST', {confirm: true});
      await follow(data.job, 'upkeep', function (result) {
        show('upkeep', [para(result.summary), list((result.prepared || []).map(function (n) { return {label: n, ok: true, yes: 'Prepared'}; }))]);
        say('upkeep', 'Done.');
      });
    } catch (failure) { say('upkeep', await failText(failure, 'prepare the connection components')); }
  };

  // ---- workspaces pickers -----------------------------------------------------------
  async function loadWorkspaces() {
    var pickers = Array.prototype.slice.call(document.querySelectorAll('[data-ops-workspaces]'));
    try {
      var rows = await call('/api/v1/admin/tenants');
      pickers.forEach(function (select) {
        select.textContent = '';
        if (!rows.length) { select.appendChild(el('option', null, 'No workspaces yet')); select.value = ''; select.disabled = true; return; }
        select.appendChild(el('option', null, 'Choose a workspace')).value = '';
        rows.forEach(function (w) { var o = el('option', null, w.display_name || (window.mvHuman ? window.mvHuman(w.id) : w.id)); o.value = w.id; select.appendChild(o); });
      });
    } catch (failure) {
      pickers.forEach(function (select) { select.textContent = ''; select.appendChild(el('option', null, 'Workspaces could not be loaded')).value = ''; });
    }
  }
  var olderForm = q('[data-ops-form="older-records"]');
  var olderAssign = q('[data-ops-run="older-assign"]');
  if (olderForm) olderForm.addEventListener('submit', async function (event) {
    event.preventDefault();
    var workspace = olderForm.elements.workspace.value;
    olderAssign.hidden = true;
    if (!workspace) { say('older-records', 'Choose a workspace first.'); return; }
    say('older-records', 'Counting older records…');
    try {
      var data = await call(BASE + '/older-records/preview', 'POST', {workspace: workspace});
      show('older-records', [para(data.summary), data.rows.length ? table(['Records', 'Would be assigned'], data.rows.map(function (r) { return [r.records, r.count.toLocaleString()]; })) : null]);
      olderAssign.hidden = !data.total;
      say('older-records', '');
    } catch (failure) { say('older-records', await failText(failure, 'count the older records')); }
  });
  if (olderAssign) olderAssign.addEventListener('click', async function () {
    var select = olderForm.elements.workspace;
    var name = select.options[select.selectedIndex] ? select.options[select.selectedIndex].textContent : 'this workspace';
    if (!await confirmed('Assign every older record without a workspace to ' + name + '? People in that workspace will see them. This can\'t be undone here.', 'Assign')) return;
    olderAssign.hidden = true;
    say('older-records', 'Assigning older records…');
    try {
      var data = await call(BASE + '/older-records/assign', 'POST', {workspace: select.value, confirm: true});
      await follow(data.job, 'older-records', function (result) { show('older-records', [para(result.summary)]); say('older-records', 'Done.'); });
    } catch (failure) { say('older-records', await failText(failure, 'assign the older records')); }
  });

  // ---- moves ----------------------------------------------------------------------
  var learningMove = q('[data-ops-run="learning-move"]');
  runners.learning = async function () {
    say('learning', 'Checking…');
    try {
      var data = await call(BASE + '/learning-move');
      learningMove.hidden = !(data.ready && data.waiting);
      say('learning', data.summary);
    } catch (failure) { say('learning', await failText(failure, 'check the learned items')); }
  };
  runners['learning-move'] = async function () {
    if (!await confirmed('Move the learned items into the shared records? The files on this computer are kept as backups.', 'Move')) return;
    learningMove.hidden = true;
    say('learning', 'Moving learned items…');
    try {
      var data = await call(BASE + '/learning-move', 'POST', {confirm: true});
      say('learning', data.summary);
    } catch (failure) { say('learning', await failText(failure, 'move the learned items')); }
  };
  var taskForm = q('[data-ops-form="task-records"]');
  var taskCancel = q('[data-ops-run="task-cancel"]');
  function renderTasks(data) {
    var nodes = [para(data.summary)];
    if (data.scheduled) nodes.push(para('Scheduled on ' + when(data.scheduled.requested_at) + '.'));
    var last = data.last_result;
    if (last) {
      nodes.push(list([{label: 'Last move', value: last.summary, ok: last.state === 'done', yes: 'Finished', no: 'Did not finish'}]));
      var rows = [];
      if (last.technical) rows.push(last.technical);
      if (last.receipt) Object.keys(last.receipt).forEach(function (k) { rows.push((window.mvHuman ? window.mvHuman(k) : k) + ': ' + last.receipt[k]); });
      nodes.push(technical(rows));
    }
    taskCancel.hidden = !data.scheduled;
    show('task-records', nodes);
  }
  runners['task-records'] = async function () {
    try { renderTasks(await call(BASE + '/task-records')); }
    catch (failure) { say('task-records', await failText(failure, 'check the task records')); }
  };
  if (taskForm) taskForm.addEventListener('submit', async function (event) {
    event.preventDefault();
    var workspace = taskForm.elements.workspace.value;
    if (!workspace) { say('task-records', 'Choose a workspace first.'); return; }
    if (!await confirmed('Schedule the move for the next time Lightwork starts? Restart Lightwork when it is quiet; the move runs before any other work.', 'Schedule')) return;
    say('task-records', 'Scheduling…');
    try {
      renderTasks(await call(BASE + '/task-records/schedule', 'POST', {workspace: workspace, confirm: true}));
      say('task-records', 'Scheduled.');
    } catch (failure) { say('task-records', await failText(failure, 'schedule the move')); }
  });
  runners['task-cancel'] = async function () {
    if (!await confirmed('Cancel the scheduled move? Nothing is moved.', 'Cancel the move')) return;
    try {
      renderTasks(await call(BASE + '/task-records/cancel', 'POST', {confirm: true}));
      say('task-records', 'The scheduled move was cancelled.');
    } catch (failure) { say('task-records', await failText(failure, 'cancel the move')); }
  };

  var consentMove = q('[data-ops-run="consent-move"]');
  function consentTable(rows) {
    return table(['Workspace', 'Consent records', 'How many', 'Result'], rows.map(function (r) {
      return [r.workspace, r.store, r.records.toLocaleString(), r.result];
    }));
  }
  runners.consent = async function () {
    say('consent', 'Checking…');
    if (consentMove) consentMove.hidden = true;
    try {
      var data = await call(BASE + '/consent-records');
      if (consentMove) consentMove.hidden = !data.ready;
      show('consent', [para(data.summary), data.stores.length ? consentTable(data.stores) : null]);
      say('consent', '');
    } catch (failure) { say('consent', await failText(failure, 'check the consent records')); }
  };
  runners['consent-move'] = async function () {
    if (!await confirmed('Copy the consent records into the shared database? Parts the shared database already holds other records for are left out, and the files on this computer are kept.', 'Copy')) return;
    if (consentMove) consentMove.hidden = true;
    say('consent', 'Copying consent records…');
    try {
      var data = await call(BASE + '/consent-records/move', 'POST', {confirm: true});
      await follow(data.job, 'consent', function (result) {
        var nodes = [para(result.summary)];
        if (result.refused && result.refused.length) {
          nodes.push(table(['Workspace', 'Consent records', 'Why they were not copied'], result.refused.map(function (r) {
            return [r.workspace, r.store, r.reason];
          })));
        }
        show('consent', nodes);
        say('consent', 'Done.');
      });
    } catch (failure) { say('consent', await failText(failure, 'copy the consent records')); }
  };

  // ---- tidy up old records in every workspace ------------------------------------
  var cleanupGo = q('[data-ops-run="cleanup-all-go"]');
  function periods() {
    var form = q('[data-maintenance-cleanup]');
    return {days: Number(form ? form.elements.days.value : 90), activity_days: Number(form ? form.elements.activity_days.value : 30)};
  }
  function sweepTable(rows) {
    return table(['Workspace', 'Conversations', 'Task activity'], rows.map(function (r) {
      if (r.empty) return [r.workspace, 'No records yet', ''];
      return [r.workspace, r.conversations == null ? 'Counted when it runs' : r.conversations.toLocaleString(),
        (r.activity || 0).toLocaleString()];
    }));
  }
  runners['cleanup-all'] = async function () {
    if (cleanupGo) cleanupGo.hidden = true;
    say('cleanup-all', 'Counting in every workspace…');
    try {
      var p = periods();
      var data = await call(BASE + '/all-workspaces-cleanup?' + new URLSearchParams({days: p.days, activity_days: p.activity_days}).toString());
      show('cleanup-all', [para(data.summary), data.workspaces.length ? sweepTable(data.workspaces) : null]);
      if (cleanupGo) cleanupGo.hidden = !(data.total_conversations || data.total_activity || data.workspaces.some(function (r) { return r.conversations == null && !r.empty; }));
      say('cleanup-all', '');
    } catch (failure) { say('cleanup-all', await failText(failure, 'count the old records')); }
  };
  runners['cleanup-all-go'] = async function () {
    if (!await confirmed('Remove old conversations and task activity from every workspace? Finished tasks and their results stay. This can\'t be undone.', 'Remove')) return;
    cleanupGo.hidden = true;
    say('cleanup-all', 'Tidying up every workspace…');
    try {
      var p = periods();
      var data = await call(BASE + '/all-workspaces-cleanup', 'POST', {days: p.days, activity_days: p.activity_days, confirm: true});
      await follow(data.job, 'cleanup-all', function (result) {
        show('cleanup-all', [para(result.summary), sweepTable(result.workspaces || [])]);
        say('cleanup-all', 'Done.');
      });
    } catch (failure) { say('cleanup-all', await failText(failure, 'tidy up every workspace')); }
  };

  // ---- release checks ---------------------------------------------------------------
  var baselines = q('[data-ops-baselines]');
  async function loadBaselines() {
    try {
      var data = await call(BASE + '/release-checks');
      baselines.textContent = '';
      if (!data.releases.length) { baselines.appendChild(el('option', null, 'No baseline recorded yet')).value = ''; return; }
      data.releases.forEach(function (r) { var o = el('option', null, 'Version ' + r); o.value = r; baselines.appendChild(o); });
    } catch (failure) {
      baselines.textContent = '';
      baselines.appendChild(el('option', null, 'Baselines could not be loaded')).value = '';
    }
  }
  runners['canary-baseline'] = async function () {
    if (!await confirmed('Record today\'s performance as the baseline for this version? An earlier baseline for the same version is replaced.', 'Record')) return;
    say('canary', 'Measuring…');
    try {
      var data = await call(BASE + '/release-checks/baseline', 'POST', {confirm: true});
      say('canary', data.summary);
      await loadBaselines();
    } catch (failure) { say('canary', await failText(failure, 'record the baseline')); }
  };
  var canaryForm = q('[data-ops-form="canary-compare"]');
  if (canaryForm) canaryForm.addEventListener('submit', async function (event) {
    event.preventDefault();
    var baseline = canaryForm.elements.baseline.value;
    if (!baseline) { say('canary', 'Record a baseline first.'); return; }
    say('canary', 'Comparing…');
    try {
      var params = new URLSearchParams({baseline: baseline, tolerance: canaryForm.elements.tolerance.value});
      var data = await call(BASE + '/release-checks/compare?' + params.toString());
      show('canary', [para(data.summary), table(['Measure', 'Baseline', 'Now', 'Change', 'Result'], data.rows.map(function (r) {
        var change = r.change == null ? '' : (r.change >= 0 ? '+' : '') + Math.round(r.change * 1000) / 10 + '%';
        return [r.measure, r.before, r.now, change, badge(r.ok, r.result, r.result)];
      }))]);
      say('canary', '');
    } catch (failure) { say('canary', await failText(failure, 'compare with the baseline')); }
  });

  document.querySelectorAll('[data-ops-run]').forEach(function (button) {
    var name = button.getAttribute('data-ops-run');
    if (!runners[name]) return;
    button.addEventListener('click', function () { runners[name](); });
  });
  var loaded = false;
  function loadOnce() {
    if (loaded) return;
    loaded = true;
    loadServices(); loadWorkspaces(); loadBaselines(); runners['task-records']();
  }
  if (!root.closest('[hidden]') && !root.hidden) loadOnce();
  document.querySelectorAll('[data-settings-tab="maintenance"]').forEach(function (tab) { tab.addEventListener('click', loadOnce); });
  window.mvMaintenanceOps = {load: loadOnce, runners: runners};
})();
