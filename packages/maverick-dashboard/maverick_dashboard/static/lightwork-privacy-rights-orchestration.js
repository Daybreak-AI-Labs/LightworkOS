// Privacy requests as a case list with step buttons. References, versions
// and request keys are carried from the chosen row or generated here.
(function () {
  'use strict';
  var R = window.LwRecords;
  var app = document.getElementById('pro-app');
  if (!R || !app) return;
  var API = '/api/v1/privacy/rights-orchestration';
  var canAdmin = app.getAttribute('data-can-admin') === 'true';
  var canAudit = app.getAttribute('data-can-audit') === 'true';
  var statusEl = document.getElementById('pro-status');
  var cases = [];
  var sources = [];
  var current = null;

  var RIGHTS = [
    ['access', 'See a copy of their data'], ['portability', 'Move their data'],
    ['erasure', 'Delete their data'], ['rectification', 'Correct their data'],
    ['restriction', 'Limit use of their data'], ['objection', 'Object to use of their data'],
    ['opt_out', 'Opt out of sale or sharing'],
  ];
  var RIGHT_LABEL = {};
  RIGHTS.forEach(function (r) { RIGHT_LABEL[r[0]] = r[1]; });
  var PHASE = {
    discover: 'Find their records', retrieve: 'Copy their records', redact: 'Hide other people’s details',
    delete: 'Delete their records', verify_delete: 'Check the deletion', rectify: 'Correct their records',
    restrict: 'Limit use', opt_out: 'Opt them out',
  };
  var TASK_STATE = {
    planned: ['Waiting', 'info'], pending: ['Waiting for approval', 'warn'], leased: ['In progress', 'info'],
    acked: ['Done in the system', 'info'], complete: ['Complete', 'active'], ambiguous: ['Needs checking', 'warn'],
    dead_letter: ['Failed', 'blocked'],
  };
  var IDENTITY = {
    unverified: ['Not checked', 'warn'], pending: ['Being checked', 'info'], verified: ['Confirmed', 'active'],
    rejected: ['Rejected', 'blocked'], expired: ['Expired', 'warn'],
  };
  var ADAPTERS = {
    microsoft_graph_users: 'Microsoft 365 users', google_workspace_users: 'Google Workspace users',
    salesforce_contacts: 'Salesforce contacts', servicenow_users: 'ServiceNow users',
  };

  function say(text) { window.mvStatus(statusEl, text); }
  function fail(f, action) { say(R.errorText(f, action)); }
  function badge(map, value) { var s = map[value] || [R.human(value), 'info']; return R.badge(s[0], s[1]); }
  function sourceName(id) {
    var s = sources.filter(function (x) { return x.source_id === id; })[0];
    if (!s) return R.human(id);
    return ADAPTERS[s.adapter_ref] || R.human(s.source_id);
  }
  function rightsText(list) { return (list || []).map(function (r) { return RIGHT_LABEL[r] || R.human(r); }).join(', '); }
  function caseName(c) { return rightsText(c.rights) + ' · opened ' + R.day(c.created_at); }

  function load() {
    return Promise.all([R.call('GET', API + '/cases'), R.call('GET', API + '/sources')]).then(function (both) {
      cases = both[0].items || [];
      sources = both[1].items || [];
      say('');
      renderCases();
      renderSources();
      if (current) {
        var fresh = cases.filter(function (c) { return c.case_id === current.case_id; })[0];
        if (fresh) openCase(fresh);
      }
    }).catch(function (f) {
      if (f && f.status === 409) { say('Choose a workspace first, then come back to this page.'); return; }
      fail(f, 'load the requests');
    });
  }

  function renderCases() {
    R.table(document.getElementById('pro-cases'), [
      { label: 'They asked to', value: function (c) { return rightsText(c.rights); } },
      { label: 'Identity', value: function (c) { return badge(IDENTITY, c.identity_status); } },
      { label: 'Status', value: function (c) { return c.status === 'closed' ? R.badge('Closed', 'idle') : c.closure_approved_by ? R.badge('Ready to close', 'info') : R.badge('Open', 'info'); } },
      { label: 'Opened', value: function (c) { return R.day(c.created_at); } },
      { label: 'Keep until', value: function (c) { return R.day(c.retained_until); } },
    ], cases, [{ label: 'Open', kind: 'primary', run: openCase }],
    { text: 'No requests yet.', action: { label: 'New request', run: newCase } });
  }

  function renderSources() {
    R.table(document.getElementById('pro-sources'), [
      { label: 'System', value: function (s) { return ADAPTERS[s.adapter_ref] || R.human(s.source_id); } },
      { label: 'Name', value: function (s) { return R.human(s.source_id); } },
      { label: 'Can', value: function (s) { return (s.capabilities || []).map(function (p) { return PHASE[p] || R.human(p); }).join(', '); } },
      { label: 'Status', value: function (s) { return R.badge(s.state === 'active' ? 'Active' : R.human(s.state), s.state === 'active' ? 'active' : 'idle'); } },
    ], sources, null, { text: canAdmin ? 'No systems connected yet. Use “Add a system”.' : 'No systems connected yet. Ask an administrator to add one.' });
  }

  // ---- new request --------------------------------------------------------
  function newCase() {
    var fields = [
      { key: 'person', label: 'Person’s email or customer ID', type: 'text', required: true,
        help: 'Stored only in a protected form; it is never shown again.' },
      { key: 'ticket', label: 'Your ticket or reference number', type: 'text', required: true },
    ];
    RIGHTS.forEach(function (r) { fields.push({ key: 'r_' + r[0], label: r[1], type: 'bool', default: r[0] === 'access' }); });
    fields.push({ key: 'until', label: 'Keep the record until', type: 'date', required: true, default: R.isoDateIn(365 * 3) });
    R.form('New request', fields, 'Open request').then(function (v) {
      if (!v) return;
      var rights = RIGHTS.map(function (r) { return r[0]; }).filter(function (k) { return v['r_' + k]; });
      if (!rights.length) { say('Choose at least one thing the person asked for.'); return; }
      var until = R.toEpoch(v.until);
      if (!until || until * 1000 <= Date.now()) { say('Choose a date in the future.'); return; }
      return R.call('PUT', API + '/cases/' + encodeURIComponent(R.newId('request')), {
        request_version: 1, external_request_ref: v.ticket, subject_reference: v.person,
        rights: rights, retained_until: until, idempotency_key: R.newKey(),
      }).then(function (created) {
        say('Request opened. Next, confirm who the person is.');
        current = created;
        return load();
      });
    }).catch(function (f) { fail(f, 'open the request'); });
  }
  document.getElementById('pro-new-case').addEventListener('click', newCase);

  // ---- one request --------------------------------------------------------
  function openCase(c) {
    current = c;
    var panel = document.getElementById('pro-case');
    document.getElementById('pro-case-title').textContent = 'Request: ' + rightsText(c.rights);
    var sum = document.getElementById('pro-case-summary');
    sum.textContent = '';
    var p = R.el('p');
    p.appendChild(document.createTextNode('Identity: '));
    p.appendChild(badge(IDENTITY, c.identity_status));
    p.appendChild(document.createTextNode(' · Legal hold: ' + (c.legal_hold ? 'on' : 'off') +
      ' · Deletion blocked by a retention rule: ' + (c.retention_blocks_deletion ? 'yes' : 'no') +
      ' · Opened ' + R.day(c.created_at) + ' · Keep until ' + R.day(c.retained_until)));
    sum.appendChild(p);
    renderSteps(c);
    panel.hidden = false;
    R.call('GET', API + '/cases/' + encodeURIComponent(c.case_id) + '/work').then(function (work) {
      if (!canAdmin || !canAudit) { renderWork(c, work, []); return; }
      return R.call('GET', API + '/callbacks?state=dead_letter&limit=1000').then(function (failed) {
        renderWork(c, work, failed.items || []);
        if (failed.count === 1000) say('This view shows the first 1,000 failed steps. Resolve some and refresh to see the rest.');
      }).catch(function (f) {
        renderWork(c, work, []);
        fail(f, 'check failed system work');
      });
    }).catch(function (f) { fail(f, 'load the work for this request'); });
  }

  function step(box, label, kind, handler) { box.appendChild(R.button(label, kind, handler)); }

  function renderSteps(c) {
    var box = document.getElementById('pro-case-steps');
    box.textContent = '';
    if (c.status === 'closed') {
      step(box, 'Download the record', 'ghost', function () { exportCase(c); });
      return;
    }
    if (canAdmin) step(box, 'Record identity check', c.identity_status === 'verified' ? 'ghost' : 'primary', function () { identity(c); });
    step(box, 'Search a system', 'ghost', function () { planSource(c); });
    step(box, 'Check completeness', 'ghost', function () { manifest(c); });
    step(box, 'Record the response file', 'ghost', function () { responsePackage(c); });
    if (canAdmin) step(box, c.legal_hold ? 'Lift legal hold' : 'Place legal hold', 'ghost', function () { legalHold(c); });
    if (canAdmin) step(box, 'Record a retention rule', 'ghost', function () { retentionRule(c); });
    if (canAdmin && !c.closure_approved_by) step(box, 'Approve closing', 'ghost', function () { approveClosure(c); });
    if (c.closure_approved_by) step(box, 'Close request', 'primary', function () { closeCase(c); });
    step(box, 'Download the record', 'ghost', function () { exportCase(c); });
  }

  function renderWork(c, work, failedCallbacks) {
    var failedByTask = {};
    var evidenceById = {};
    (work.evidence || []).forEach(function (e) { evidenceById[e.evidence_id] = e; });
    document.getElementById('pro-evidence-review').hidden = true;
    failedCallbacks.forEach(function (callback) {
      if (callback.case_id === c.case_id && callback.state === 'dead_letter') failedByTask[callback.task_id] = callback;
    });
    R.table(document.getElementById('pro-case-tasks'), [
      { label: 'System', value: function (t) { return sourceName(t.source_id); } },
      { label: 'Step', value: function (t) { return PHASE[t.phase] || R.human(t.phase); } },
      { label: 'Status', value: function (t) {
        if (failedByTask[t.task_id]) return R.badge('Needs attention', 'blocked');
        var e = evidenceById[t.evidence_id];
        if (t.state === 'complete' && e && e.evidence_origin === 'manual_attestation') return R.badge('Complete by manual statement', 'warn');
        if (t.state === 'complete' && e && e.evidence_origin === 'legacy_unattributed') return R.badge('Complete; evidence origin unknown', 'warn');
        return badge(TASK_STATE, t.state);
      } },
      { label: 'Evidence basis', value: function (t) {
        var e = evidenceById[t.evidence_id];
        return e ? evidenceSummary(e) : 'No result recorded';
      } },
    ], work.tasks, [
      { label: 'Approve deletion', kind: 'danger', when: function (t) { return canAdmin && t.destructive && !t.approved_by && c.status !== 'closed'; }, run: function (t) { approveDestructive(t); } },
      { label: 'Try again', when: function (t) { return canAdmin && !!failedByTask[t.task_id] && c.status !== 'closed'; }, run: function (t) { retryFailedWork(c, t, failedByTask[t.task_id]); } },
      { label: 'Record manual statement', when: function (t) { return t.phase === 'redact' && t.state === 'planned' && c.status !== 'closed'; }, run: function (t) { recordResult(c, t); } },
      { label: 'Review original evidence', when: function (t) { return !!evidenceById[t.evidence_id]; }, run: function (t) { reviewEvidence(evidenceById[t.evidence_id]); } },
    ], { text: 'No systems searched yet. Use “Search a system”.' });
    R.table(document.getElementById('pro-case-manifests'), [
      { label: 'Checked', value: function (m) { return R.when(m.created_at); } },
      { label: 'Systems covered', value: function (m) { return (m.covered_source_ids || []).map(sourceName).join(', ') || 'None'; } },
      { label: 'Not covered', value: function (m) { return (m.uncovered_sources || []).map(function (u) { return sourceName(u.source_id) + (u.reason ? ' (' + R.human(u.reason) + ')' : ''); }).join(', ') || 'None'; } },
      { label: 'Manual statements', value: function (m) { return (m.manually_attested_source_ids || []).map(sourceName).join(', ') || 'None recorded in this check'; } },
      { label: 'Evidence origin unknown', value: function (m) { return (m.unattributed_source_ids || []).map(sourceName).join(', ') || 'None recorded in this check'; } },
    ], work.manifests, null, { text: 'Not checked yet. Use “Check completeness” once each system is done.' });
  }

  function evidenceSummary(e) {
    if (e.evidence_origin === 'manual_attestation') return 'Manually attested; independently unverified';
    if (e.evidence_origin !== 'provider_runtime') return 'Older evidence; origin not established';
    if (e.verification_basis === 'provider_active_record_absence') return 'No match in the system’s active-record lookup; retained copies unknown';
    return 'Connected-system response; review its retention result';
  }

  function reviewEvidence(e) {
    var panel = document.getElementById('pro-evidence-review');
    var box = document.getElementById('pro-evidence-details');
    box.textContent = '';
    var fields = [
      ['System', sourceName(e.source_id)], ['Step', PHASE[e.phase] || R.human(e.phase)],
      ['Recorded result', R.human(e.status)], ['Evidence basis', evidenceSummary(e)],
      ['What this establishes', e.verification_summary || 'The origin of this older evidence was not recorded. Verification is not established.'],
      ['Records involved', e.record_count], ['Recorded', R.when(e.created_at)],
      ['Retention observation', e.provider_retention_state ? R.human(e.provider_retention_state) : 'Not established'],
    ];
    var dl = R.el('dl');
    fields.forEach(function (field) { dl.appendChild(R.el('dt', '', field[0])); dl.appendChild(R.el('dd', '', field[1])); });
    box.appendChild(dl);
    var technical = R.el('details');
    technical.appendChild(R.el('summary', '', 'Exact evidence references'));
    technical.appendChild(R.el('pre', 'pro-output', JSON.stringify(e, null, 2)));
    box.appendChild(technical);
    panel.hidden = false;
    panel.scrollIntoView({ block: 'nearest' });
  }

  function retryFailedWork(c, t, callback) {
    R.confirm('Check the connection to ' + sourceName(t.source_id) + ' before trying “' + (PHASE[t.phase] || R.human(t.phase)) + '” again. This work may run automatically once retried.', 'Try again').then(function (ok) {
      if (!ok) return;
      return R.call('POST', API + '/callbacks/' + encodeURIComponent(callback.callback_id) + '/requeue', {
        expected_revision: callback.revision, idempotency_key: R.newKey(),
      }).then(function () { return load().then(function () { say('Retry requested. The connected system may be checked again automatically.'); }); })
        .catch(function (f) { fail(f, 'retry the system work'); });
    });
  }

  function proof(prefix) {
    return R.pickFile().then(function (file) {
      if (!file) return null;
      return R.fingerprint(file).then(function (fp) {
        return { sha256: fp.sha256, ref: prefix + '-' + R.slug(file.name, 'document'), selectedName: file.name };
      });
    });
  }

  function identity(c) {
    R.form('Record identity check', [
      { key: 'status', label: 'Result', type: 'select', required: true, default: 'verified', options: [
        { value: 'verified', label: 'Confirmed who they are' }, { value: 'pending', label: 'Still checking' },
        { value: 'rejected', label: 'Could not confirm (reject)' }, { value: 'expired', label: 'Check has expired' },
      ] },
    ], 'Choose proof document').then(function (v) {
      if (!v) return null;
      return proof('identity').then(function (pf) {
        if (!pf && v.status === 'verified') { say('Attach the document that proves who they are.'); return null; }
        var body = { status: v.status, expected_revision: c.revision, idempotency_key: R.newKey() };
        if (pf) { body.evidence_sha256 = pf.sha256; body.evidence_ref = pf.ref; }
        return R.call('POST', API + '/cases/' + encodeURIComponent(c.case_id) + '/identity-verification', body)
          .then(function () { say('Identity check recorded.'); return load(); });
      });
    }).catch(function (f) { fail(f, 'record the identity check'); });
  }

  function legalHold(c) {
    var on = !c.legal_hold;
    R.confirm(on ? 'Place a legal hold? Nothing in this request can be deleted while the hold is on. You will be asked for the hold notice.'
      : 'Lift the legal hold? Deletion work can then continue. You will be asked for the release notice.', on ? 'Place hold' : 'Lift hold').then(function (ok) {
      if (!ok) return null;
      return proof('legal-hold').then(function (pf) {
        if (!pf) { say('Attach the legal hold notice to continue.'); return null; }
        return R.call('POST', API + '/cases/' + encodeURIComponent(c.case_id) + '/legal-hold', {
          active: on, evidence_sha256: pf.sha256, evidence_ref: pf.ref, expected_revision: c.revision, idempotency_key: R.newKey(),
        }).then(function () { say(on ? 'Legal hold placed.' : 'Legal hold lifted.'); return load(); });
      });
    }).catch(function (f) { fail(f, 'change the legal hold'); });
  }

  function retentionRule(c) {
    R.form('Record a retention rule', [
      { key: 'blocks', label: 'Must some of this data be kept by law?', type: 'select', default: 'yes', options: [
        { value: 'yes', label: 'Yes, deletion is blocked' }, { value: 'no', label: 'No, deletion may go ahead' },
      ] },
      { key: 'rule', label: 'Which rule', type: 'text', required: true, placeholder: 'For example: tax records 7 years' },
    ], 'Choose supporting document').then(function (v) {
      if (!v) return null;
      return proof('retention').then(function (pf) {
        if (!pf) { say('Attach the document that shows the rule.'); return null; }
        return R.call('POST', API + '/cases/' + encodeURIComponent(c.case_id) + '/retention-gate', {
          blocks_deletion: v.blocks === 'yes', rule_ref: R.slug(v.rule, 'rule'), evidence_sha256: pf.sha256,
          expected_revision: c.revision, idempotency_key: R.newKey(),
        }).then(function () { say('Retention rule recorded.'); return load(); });
      });
    }).catch(function (f) { fail(f, 'record the retention rule'); });
  }

  function planSource(c) {
    var active = sources.filter(function (s) { return s.state === 'active'; });
    if (!active.length) { say(canAdmin ? 'Add a connected system first.' : 'No systems are connected yet. Ask an administrator to add one.'); return; }
    R.form('Search a system', [
      { key: 's', label: 'System', type: 'select', required: true, default: '0',
        options: active.map(function (s, i) { return { value: String(i), label: (ADAPTERS[s.adapter_ref] || R.human(s.source_id)) + ' – ' + R.human(s.source_id) }; }) },
    ], 'Plan the work').then(function (v) {
      if (!v) return;
      var s = active[parseInt(v.s || '0', 10)];
      return R.call('POST', API + '/cases/' + encodeURIComponent(c.case_id) + '/sources/' + encodeURIComponent(s.source_id) + '/plan', {
        phases: null, max_attempts: 3, expected_case_revision: c.revision, idempotency_key: R.newKey(),
      }).then(function () { say('Work planned. Steps that delete data need approval from a second administrator.'); return load(); });
    }).catch(function (f) {
      if (f && f.status === 409) { say('This step is not possible yet. Confirm the person’s identity first, and check there is no legal hold.'); return; }
      fail(f, 'plan the work');
    });
  }

  function approveDestructive(t) {
    R.confirm('Approve deleting this person’s records in ' + sourceName(t.source_id) + '? This cannot be undone once it runs.', 'Approve deletion').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/tasks/' + encodeURIComponent(t.task_id) + '/approve-destructive', { expected_revision: t.revision, idempotency_key: R.newKey() })
        .then(function () { say('Deletion approved.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('A different administrator from the person who planned the work must approve it.'); return; }
          fail(f, 'approve the deletion');
        });
    });
  }

  function recordResult(c, t) {
    R.form('Record your manual statement: ' + (PHASE[t.phase] || R.human(t.phase)), [
      { key: 'status', label: 'What happened', type: 'select', default: 'complete', options: [
        { value: 'complete', label: 'Done' }, { value: 'not_found', label: 'No records found' },
        { value: 'partial', label: 'Partly done' }, { value: 'failed', label: 'Failed' },
      ] },
      { key: 'count', label: 'Records involved', type: 'number', default: 0, required: true },
    ], 'Choose supporting document').then(function (v) {
      if (!v) return null;
      var count = parseInt(v.count, 10);
      if (!(count >= 0)) { say('Enter how many records were involved (0 or more).'); return null; }
      return proof('receipt').then(function (pf) {
        if (!pf) { say('Choose the document supporting your statement. Lightwork records its fingerprint without independently checking its contents.'); return null; }
        return R.confirm('Record your statement for ' + sourceName(t.source_id) + ': ' + (PHASE[t.phase] || R.human(t.phase)) +
          ', result ' + R.human(v.status) + ', ' + count + ' records, supporting document ' + pf.selectedName + '. This saves your statement and the chosen document’s fingerprint. ' +
          'Lightwork does not independently verify the document or deletion in the connected system. ' +
          (v.status === 'complete' || v.status === 'not_found' ? 'This marks the workflow step complete and may allow closure after independent approval.' : 'The workflow step remains incomplete.'), 'Record manual statement').then(function (confirmed) {
          if (!confirmed) return null;
          return R.call('PUT', API + '/cases/' + encodeURIComponent(c.case_id) + '/sources/' + encodeURIComponent(t.source_id) +
          '/phases/' + encodeURIComponent(t.phase) + '/evidence/' + encodeURIComponent(R.newId('evidence')), {
          manual_attestation: true,
          status: v.status, provider_evidence_sha256: pf.sha256, record_count: count, opaque_ref: pf.ref,
          expected_task_revision: t.revision, idempotency_key: R.newKey(),
          }).then(function () { say('Your manual statement was recorded. Independent verification remains unconfirmed.'); return load(); });
        });
      });
    }).catch(function (f) {
      if (f && f.status === 409) { say('This system has not finished its work yet. Try again after it has run.'); return; }
      fail(f, 'record the result');
    });
  }

  function manifest(c) {
    R.call('PUT', API + '/cases/' + encodeURIComponent(c.case_id) + '/manifests/' + encodeURIComponent(R.newId('check')), {
      expected_case_revision: c.revision, idempotency_key: R.newKey(),
    }).then(function () { say('Completeness checked. See the list below.'); return load(); })
      .catch(function (f) { fail(f, 'check completeness'); });
  }

  function responsePackage(c) {
    R.form('Record the response file', [
      { key: 'name', label: 'Name of the stored file', type: 'text', required: true, placeholder: 'For example: response for ticket 4521' },
      { key: 'store', label: 'Where the encryption key is kept', type: 'select', default: 'vault', options: [
        { value: 'vault', label: 'Key vault' }, { value: 'secret', label: 'Secret manager' }, { value: 'env', label: 'Server setting' },
      ] },
      { key: 'key', label: 'Key name (from your administrator)', type: 'text', required: true },
      { key: 'expires', label: 'File available until', type: 'date', required: true, default: R.isoDateIn(30) },
    ], 'Choose the file').then(function (v) {
      if (!v) return null;
      var expires = R.toEpoch(v.expires);
      if (!expires || expires * 1000 <= Date.now()) { say('Choose a date in the future.'); return null; }
      var keyName = String(v.key || '').trim().replace(/[^A-Za-z0-9_.:-]+/g, '-').replace(/^[^A-Za-z0-9]+/, '');
      if (!keyName) { say('Enter the key name your administrator gave you.'); return null; }
      return R.pickFile().then(function (file) {
        if (!file) return null;
        return R.fingerprint(file).then(function (fp) {
          return R.call('PUT', API + '/cases/' + encodeURIComponent(c.case_id) + '/packages/' + encodeURIComponent(R.newId('package')), {
            object_ref: R.slug(v.name, 'response'), package_sha256: fp.sha256, encryption_key_ref: v.store + ':' + keyName,
            expires_at: expires, expected_case_revision: c.revision, idempotency_key: R.newKey(),
          }).then(function () { say('Response file recorded.'); return load(); });
        });
      });
    }).catch(function (f) { fail(f, 'record the response file'); });
  }

  function approveClosure(c) {
    R.confirm('Approve closing this request? Review the original evidence for every system first. Manually recorded statements remain independently unverified, and an active-record lookup does not prove permanent removal from retained copies or backups. Closing records workflow completion. You must not be the person who opened it.', 'Approve').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/cases/' + encodeURIComponent(c.case_id) + '/closure/approve', { expected_revision: c.revision, idempotency_key: R.newKey() })
        .then(function () { say('Closing approved. The person who opened the request can now close it.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('Someone other than the person who opened the request must approve closing it.'); return; }
          if (f && f.status === 409) { say('This request is not ready to close yet. Finish each system’s work and check completeness first.'); return; }
          fail(f, 'approve closing the request');
        });
    });
  }

  function closeCase(c) {
    R.confirm('Close this request? It can no longer be changed. Closure records workflow completion and does not certify deletion. The original evidence retains each manual statement or connected-system observation.', 'Close request').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/cases/' + encodeURIComponent(c.case_id) + '/close', { expected_revision: c.revision, idempotency_key: R.newKey() })
        .then(function () { say('Request closed.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('Only the person who opened the request can close it.'); return; }
          fail(f, 'close the request');
        });
    });
  }

  function exportCase(c) {
    R.call('PUT', API + '/cases/' + encodeURIComponent(c.case_id) + '/exports/' + encodeURIComponent(R.newId('record')), {
      retained_until: c.retained_until, idempotency_key: R.newKey(),
    }).then(function (exp) { R.download('privacy-request-record.json', exp); say('Record downloaded.'); })
      .catch(function (f) { fail(f, 'download the record'); });
  }

  // ---- systems and maintenance --------------------------------------------
  var add = document.getElementById('pro-add-source');
  if (add) add.addEventListener('click', function () {
    var phases = Object.keys(PHASE);
    var fields = [
      { key: 'adapter', label: 'System', type: 'select', default: 'microsoft_graph_users',
        options: Object.keys(ADAPTERS).map(function (k) { return { value: k, label: ADAPTERS[k] }; }) },
      { key: 'name', label: 'Name for this connection', type: 'text', required: true, placeholder: 'For example: Company Microsoft 365' },
      { key: 'store', label: 'Where its sign-in secret is kept', type: 'select', default: 'vault', options: [
        { value: 'vault', label: 'Key vault' }, { value: 'secret', label: 'Secret manager' }, { value: 'env', label: 'Server setting' },
      ] },
      { key: 'secret', label: 'Secret name (from your administrator)', type: 'text', required: true },
    ];
    phases.forEach(function (p) { fields.push({ key: 'p_' + p, label: 'Allow: ' + PHASE[p], type: 'bool', default: p === 'discover' || p === 'retrieve' }); });
    R.form('Add a system', fields, 'Add').then(function (v) {
      if (!v) return;
      var caps = phases.filter(function (p) { return v['p_' + p]; });
      if (!caps.length) { say('Allow at least one step.'); return; }
      var secret = String(v.secret || '').trim().replace(/[^A-Za-z0-9_.:-]+/g, '-').replace(/^[^A-Za-z0-9]+/, '');
      if (!secret) { say('Enter the secret name your administrator gave you.'); return; }
      var id = R.slug(v.name, 'system');
      var existing = sources.filter(function (s) { return s.source_id === id; })[0];
      return R.call('PUT', API + '/sources/' + encodeURIComponent(id), {
        adapter_ref: v.adapter, credential_ref: v.store + ':' + secret, capabilities: caps,
        expected_revision: existing ? existing.revision : 0, idempotency_key: R.newKey(),
      }).then(function () { say('System added.'); return load(); });
    }).catch(function (f) { fail(f, 'add the system'); });
  });

  function maintenance(id, message, okText, run) {
    var b = document.getElementById(id);
    if (!b) return;
    b.addEventListener('click', function () {
      (message ? R.confirm(message, okText) : Promise.resolve(true)).then(function (ok) {
        if (!ok) return;
        b.disabled = true;
        run().then(function (text) { say(text); return load(); })
          .catch(function (f) {
            if (f && f.status === 503) { say('The connection to your systems is not set up yet. Ask the person who installed Lightwork.'); return; }
            fail(f, 'finish that');
          })
          .then(function () { b.disabled = false; });
      });
    });
  }
  maintenance('pro-run', 'Run the waiting work in your connected systems now? Approved deletions will be carried out.', 'Run now', function () {
    return R.call('POST', API + '/source-runtime/run', { run_id: R.newKey() }).then(function () { return 'Waiting work has been run.'; });
  });
  maintenance('pro-reconcile', null, null, function () {
    return R.call('POST', API + '/source-runtime/reconcile', { run_id: R.newKey() }).then(function () { return 'Uncertain deletions re-checked.'; });
  });
  maintenance('pro-purge', 'Permanently delete every request record whose keep-until date has passed?', 'Delete', function () {
    return R.call('POST', API + '/retention/purge', { cutoff: Math.floor(Date.now() / 1000), idempotency_key: R.newKey() }).then(function () { return 'Expired records deleted.'; });
  });
  maintenance('pro-integrity', null, null, function () {
    return R.call('GET', API + '/integrity').then(function () { return 'All records are intact.'; });
  });

  load();
})();
