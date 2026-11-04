// Turn a final compliance scope into a reviewed task plan: lists on load, a
// button per row, choices instead of typed references.
(function () {
  'use strict';
  var R = window.LwRecords;
  var app = document.getElementById('csa-app');
  if (!R || !app) return;
  var API = '/api/v1/compliance/scope-actions';
  var SCOPING = '/api/v1/compliance/scoping';
  var canAdmin = app.getAttribute('data-can-admin') === 'true';
  var statusEl = document.getElementById('csa-status');
  var data = { catalogs: [], plans: [], reports: [], can_create_tasks: false };
  var scopes = [];

  var STATUS = {
    pending_review: ['Waiting for approval', 'warn'], published: ['Ready to use', 'active'],
    draft: ['Waiting for approval', 'warn'], approved: ['Approved', 'info'],
    applied: ['Tasks created', 'active'], no_change: ['Up to date', 'active'], rolled_back: ['Tasks undone', 'idle'],
  };
  var STATES = { not_started: 'Not started', not_implemented: 'Not in place yet', planned: 'Planned' };
  var CADENCE = { one_time: 'Once', monthly: 'Every month', quarterly: 'Every quarter', annual: 'Every year', continuous: 'Continuously' };
  var KIND = { collect: 'Collect', refresh: 'Refresh', review: 'Review' };
  var ROLE = { first_line: 'Business owner', second_line: 'Risk and compliance owner', control_owner: 'Control owner', evidence_owner: 'Evidence owner' };

  function say(text) { window.mvStatus(statusEl, text); }
  function fail(f, action) { say(R.errorText(f, action)); }
  function label(ref) {
    return R.human(String(ref || '').replace(/^(ref|evidence):/, '').replace(/^(question|framework|control|overlap|evidence|catalog|mapping)[-_]/, '').replace(/-[a-f0-9]{12}$/, ''));
  }
  function badge(value) { var s = STATUS[value] || [R.human(value), 'info']; return R.badge(s[0], s[1]); }
  function find(list, key, value) { return list.filter(function (r) { return r[key] === value; })[0]; }
  function scopeName(scopeId) {
    var s = find(scopes, 'scope_id', scopeId);
    return s ? (s.frameworks.map(label).join(', ') || 'Scope') : 'Scope';
  }

  function load() {
    return Promise.all([
      R.call('GET', API + '/records'),
      R.call('GET', SCOPING + '/records').catch(function () { return { scopes: [] }; }),
    ]).then(function (both) {
      data = both[0];
      scopes = (both[1].scopes || []);
      say('');
      render();
    }).catch(function (f) {
      if (f && f.status === 409) { say('Choose a workspace first, then come back to this page.'); return; }
      fail(f, 'load your records');
    });
  }

  function render() {
    var planned = {};
    data.plans.forEach(function (p) { planned[p.scope_id] = true; });
    var finals = scopes.filter(function (s) { return s.status === 'finalized'; });
    R.table(document.getElementById('csa-scopes'), [
      { label: 'Frameworks', value: function (s) { return s.frameworks.map(label).join(', ') || 'Scope'; } },
      { label: 'Controls', value: function (s) { return s.controls; } },
      { label: 'Task plan', value: function (s) { return planned[s.scope_id] ? 'Proposed' : 'None yet'; } },
    ], finals, [
      { label: 'Propose tasks', kind: 'primary', run: proposeTasks },
    ], { text: 'No final scopes yet. Finish a scope on the “Find which controls apply” page first.',
         action: { label: 'Go to scoping', run: function () { location.href = '/compliance/scoping'; } } });

    R.table(document.getElementById('csa-plans'), [
      { label: 'Scope', value: function (p) { return scopeName(p.scope_id); } },
      { label: 'Controls', value: function (p) { return p.controls; } },
      { label: 'Evidence tasks', value: function (p) { return p.evidence_tasks; } },
      { label: 'Status', value: function (p) { return badge(p.status); } },
      { label: 'Proposed', value: function (p) { return R.day(p.created_at); } },
    ], data.plans, [
      { label: 'View tasks', run: viewPlan },
      { label: 'Approve', kind: 'primary', when: function (p) { return canAdmin && p.status === 'draft'; }, run: approvePlan },
      { label: 'Create the tasks', kind: 'primary', when: function (p) { return canAdmin && data.can_create_tasks && p.status === 'approved'; }, run: function (p, b) { execute(p, 'apply', b); } },
      { label: 'Sync tasks', when: function (p) { return canAdmin && data.can_create_tasks && (p.status === 'applied' || p.status === 'no_change'); }, run: function (p, b) { execute(p, 'reconcile', b); } },
      { label: 'Undo tasks', kind: 'danger', when: function (p) { return canAdmin && data.can_create_tasks && (p.status === 'applied' || p.status === 'no_change'); }, run: function (p, b) { execute(p, 'rollback', b); } },
      { label: 'Create report', when: function (p) { return p.status !== 'draft'; }, run: createReport },
    ], { text: 'No task plans yet. Use “Propose tasks” on a final scope above.' });

    R.table(document.getElementById('csa-reports'), [
      { label: 'Plan for', value: function (e) { var p = find(data.plans, 'plan_id', e.plan_id); return p ? scopeName(p.scope_id) : 'Plan'; } },
      { label: 'Created', value: function (e) { return R.when(e.created_at); } },
    ], data.reports, [{ label: 'Download', run: downloadReport }],
    { text: 'No reports yet. Use “Create report” on an approved plan.' });

    R.table(document.getElementById('csa-catalogs'), [
      { label: 'Mapping', value: function (c) { return label(c.catalog_id); } },
      { label: 'Version', value: function (c) { return c.version; } },
      { label: 'Entries', value: function (c) { return c.entries; } },
      { label: 'Status', value: function (c) { return badge(c.status); } },
    ], data.catalogs, [
      { label: 'Approve for use', kind: 'primary', when: function (c) { return canAdmin && c.status !== 'published'; }, run: approveCatalog },
    ], { text: 'No mappings yet. Add one from a file your compliance team provides.' });

    if (!data.can_create_tasks && data.plans.length) {
      say('Task creation in other systems is not connected, so approved plans stay as lists you can view and download.');
    }
  }

  function proposeTasks(scope) {
    var ready = data.catalogs.filter(function (c) { return c.status === 'published'; });
    if (!ready.length) { say('No mapping is approved for use yet. Add one below and have an administrator approve it.'); return; }
    R.form('Propose tasks', [
      { key: 'c', label: 'Mapping', type: 'select', required: true, default: '0',
        options: ready.map(function (c, i) { return { value: String(i), label: label(c.catalog_id) + ' (version ' + c.version + ')' }; }) },
      { key: 'until', label: 'Keep the plan until', type: 'date', required: true, default: R.isoDateIn(365 * 3) },
    ], 'Propose').then(function (values) {
      if (!values) return;
      var c = ready[parseInt(values.c || '0', 10)];
      var until = R.toEpoch(values.until);
      if (!until || until * 1000 <= Date.now()) { say('Choose a date in the future.'); return; }
      return R.call('PUT', API + '/scopes/' + encodeURIComponent(scope.scope_id) + '/plans/' + encodeURIComponent(R.newId('plan')), {
        catalog_id: c.catalog_id, catalog_version: c.version, expected_scope_revision: scope.revision,
        retained_until: until, idempotency_key: R.newKey(),
      }).then(function () { say('Tasks proposed. A second person must approve the plan.'); return load(); });
    }).catch(function (f) {
      if (f && f.status === 409) { say('The mapping does not cover every control in this scope, or the scope changed. Ask your compliance team for an updated mapping.'); return; }
      fail(f, 'propose the tasks');
    });
  }

  function viewPlan(p) {
    R.call('GET', API + '/plans/' + encodeURIComponent(p.plan_id)).then(function (plan) {
      var box = document.getElementById('csa-plan-detail');
      box.textContent = '';
      box.appendChild(R.el('h2', '', 'Proposed tasks'));
      box.appendChild(R.el('h3', '', 'Controls to put in place'));
      var c = R.el('div');
      R.table(c, [
        { label: 'Control', value: function (i) { return label(i.control_ref); } },
        { label: 'Target', value: function (i) { return STATES[i.desired_state] || R.human(i.desired_state); } },
        { label: 'Owner', value: function (i) { return label(i.owner_ref) + ' (' + (ROLE[i.owner_role] || R.human(i.owner_role)) + ')'; } },
        { label: 'Why', value: function (i) { return (i.reason_codes || []).map(R.human).join(', '); } },
      ], plan.control_intents, null, { text: 'No controls.' });
      box.appendChild(c);
      box.appendChild(R.el('h3', '', 'Evidence to collect'));
      var e = R.el('div');
      R.table(e, [
        { label: 'Evidence', value: function (i) { return label(i.evidence_mapping_ref); } },
        { label: 'Task', value: function (i) { return KIND[i.task_kind] || R.human(i.task_kind); } },
        { label: 'How often', value: function (i) { return CADENCE[i.cadence] || R.human(i.cadence); } },
        { label: 'Owner', value: function (i) { return label(i.owner_ref); } },
      ], plan.evidence_task_intents, null, { text: 'No evidence tasks.' });
      box.appendChild(e);
      box.hidden = false;
      box.scrollIntoView({ block: 'start' });
    }).catch(function (f) { fail(f, 'open the plan'); });
  }

  function approvePlan(p) {
    R.confirm('Approve this task plan? You must not be the person who proposed it.', 'Approve').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/plans/' + encodeURIComponent(p.plan_id) + '/approve', { expected_revision: p.revision, idempotency_key: R.newKey() })
        .then(function () { say('Plan approved.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('A different administrator from the person who proposed the plan must approve it.'); return; }
          fail(f, 'approve the plan');
        });
    });
  }

  var EXEC = {
    apply: ['Create these tasks in your connected task system now?', 'Create tasks', 'Tasks created.', 'create the tasks'],
    reconcile: ['Check the tasks in your connected task system and bring them back in line with the plan?', 'Sync', 'Tasks are in sync.', 'sync the tasks'],
    rollback: ['Undo the tasks this plan created in your connected task system?', 'Undo tasks', 'Tasks undone.', 'undo the tasks'],
  };
  function execute(p, op, button) {
    var e = EXEC[op];
    R.confirm(e[0], e[1]).then(function (ok) {
      if (!ok) return;
      button.disabled = true;
      R.call('POST', API + '/plans/' + encodeURIComponent(p.plan_id) + '/' + op, { expected_revision: p.revision, idempotency_key: R.newKey() })
        .then(function () { say(e[2]); return load(); })
        .catch(function (f) { button.disabled = false; fail(f, e[3]); });
    });
  }

  function createReport(p) {
    R.call('POST', API + '/plans/' + encodeURIComponent(p.plan_id) + '/report', { idempotency_key: R.newKey() })
      .then(function () { say('Report created. Use Download to save it.'); return load(); })
      .catch(function (f) {
        if (f && f.status === 503) { say('Report signing is not set up yet. Ask the person who installed Lightwork to add the report signing key.'); return; }
        fail(f, 'create the report');
      });
  }

  function downloadReport(e) {
    R.call('GET', API + '/exports/' + encodeURIComponent(e.export_id))
      .then(function (body) { R.download('compliance-task-plan-report.json', body); say('Report downloaded.'); })
      .catch(function (f) { fail(f, 'download the report'); });
  }

  function approveCatalog(c) {
    R.confirm('Approve the “' + label(c.catalog_id) + '” mapping for use? It can then be used to propose tasks.', 'Approve').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/catalogs/' + encodeURIComponent(c.catalog_id) + '/versions/' + c.version + '/approve',
        { expected_revision: c.revision, idempotency_key: R.newKey() })
        .then(function () { say('Mapping approved.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('A different administrator from the person who added it must approve it.'); return; }
          fail(f, 'approve the mapping');
        });
    });
  }

  document.getElementById('csa-add-catalog').addEventListener('click', function () {
    window.location.assign('/compliance/scope-actions/mapping');
  });

  var integrity = document.getElementById('csa-integrity');
  if (integrity) integrity.addEventListener('click', function () {
    R.call('GET', API + '/integrity').then(function () { say('All records are intact.'); })
      .catch(function (f) { fail(f, 'check the records'); });
  });

  load();
})();
