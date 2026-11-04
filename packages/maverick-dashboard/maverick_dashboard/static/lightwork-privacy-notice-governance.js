// Privacy notice versions as a guided workflow: versions listed on load with
// a button per step (submit, approve as a role, schedule, withdraw, roll
// back), a form with choices and file pickers for a new version, and plain
// results. Fingerprints are computed on the server from the chosen files.
(function () {
  'use strict';
  var R = window.LwRecords;
  var app = document.getElementById('png-app');
  if (!R || !app) return;
  var API = '/api/v1/privacy/notices';
  var canAdmin = app.getAttribute('data-can-admin') === 'true';
  var statusEl = document.getElementById('png-status');
  var data = { policies: [], releases: [], approvals: [], proposals: [], records: [], queue: {} };

  var STATE = {
    draft: ['Draft', 'idle'], review: ['Waiting for approval', 'warn'], approved: ['Approved', 'info'],
    scheduled: ['Scheduled', 'info'], published: ['Live', 'active'], rolled_back: ['Rolled back', 'idle'],
    withdrawn: ['Withdrawn', 'idle'],
  };
  var ROLE = { privacy: 'Privacy', legal: 'Legal', brand: 'Brand', accessibility: 'Accessibility' };
  var PROPOSAL = { pending_review: ['Waiting for review', 'warn'], approved: ['Accepted', 'active'], rejected: ['Rejected', 'idle'] };

  function say(text) { window.mvStatus(statusEl, text); }
  function fail(f, action) {
    var detail = f && f.detail;
    if (f && f.status === 403 && detail === 'This API key does not have a scope that allows this. Create a key with the scope you need on your account page.') {
      say('This access key is not allowed to make approval decisions. Use a key with approval permission and installation administrator access.');
      return;
    }
    var refusals = {
      'the release author cannot approve their own release': 'A different person must approve this notice version.',
      'a role or authenticated human already approved this release': 'This person or approval role has already approved this notice version.',
      'only the authenticated approver can revoke this approval': 'Only the person who gave this approval can withdraw it.',
      'update proposal requires a reviewer distinct from its creator': 'A different person must review this update proposal.'
    };
    if (f && f.status === 403 && Object.prototype.hasOwnProperty.call(refusals, detail)) {
      say(refusals[detail]); return;
    }
    var plain = f && f.status === 503 && window.mvPlainDetail ? window.mvPlainDetail(detail) : '';
    say(plain || R.errorText(f, action));
  }
  function badge(map, v) { var s = map[v] || [R.human(v), 'info']; return R.badge(s[0], s[1]); }
  function name(id) { return R.human(id); }
  function checkedValues(nameAttr) {
    return Array.prototype.map.call(document.querySelectorAll('input[name="' + nameAttr + '"]:checked'), function (c) { return c.value; });
  }
  function days(seconds) { var d = Math.round(seconds / 86400); return d + (d === 1 ? ' day' : ' days'); }

  document.addEventListener("lightwork:notice-proposal-saved", function () { load(); });
  function load() {
    return R.call('GET', API + '/records').then(function (body) {
      data = body;
      if (statusEl.textContent.indexOf('Loading') === 0) say('');
      render();
    }).catch(function (f) {
      if (f && f.status === 409) { say('Choose a workspace first, then come back to this page.'); return; }
      fail(f, 'load your notices');
    });
  }

  function approvalsFor(r) {
    return data.approvals.filter(function (a) { return a.notice_id === r.notice_id && a.version === r.version && !a.revoked; });
  }

  function render() {
    R.table(document.getElementById('png-releases'), [
      { label: 'Notice', value: function (r) { return name(r.notice_id); } },
      { label: 'Version', value: function (r) { return r.version; } },
      { label: 'Website or app', value: function (r) { return name(r.property_id); } },
      { label: 'Status', value: function (r) { return badge(STATE, r.state); } },
      { label: 'Approved by', value: function (r) {
        var got = approvalsFor(r).map(function (a) { return ROLE[a.role] || R.human(a.role); });
        return got.length ? got.join(', ') + ' (' + got.length + ' of ' + r.quorum + ')' : 'Nobody yet';
      } },
      { label: 'Goes live', value: function (r) { return r.activate_at ? R.when(r.activate_at) : R.day(r.effective_from); } },
    ], data.releases, [
      { label: 'Send for approval', kind: 'primary', when: function (r) { return r.state === 'draft'; }, run: submit },
      { label: 'Approve', kind: 'primary', when: function (r) { return canAdmin && (r.state === 'review' || r.state === 'approved') && remainingRoles(r).length; }, run: approve },
      { label: 'Withdraw my approval', when: function (r) { return canAdmin && (r.state === 'review' || r.state === 'approved') && approvalsFor(r).length; }, run: revokeApproval },
      { label: 'Schedule publishing', kind: 'primary', when: function (r) { return canAdmin && r.state === 'approved'; }, run: schedule },
      { label: 'Withdraw', kind: 'danger', when: function (r) { return canAdmin && r.state === 'published'; }, run: withdraw },
      { label: 'Roll back', kind: 'danger', when: function (r) { return canAdmin && r.state === 'published' && earlierLive(r).length; }, run: rollback },
      { label: 'Download signed record', when: function (r) { return r.state !== 'draft'; }, run: record },
    ], { text: 'No notice versions yet.', action: { label: 'New notice version', run: openReleaseForm } });

    R.table(document.getElementById('png-policies'), [
      { label: 'Rule', value: function (p) { return name(p.policy_id); } },
      { label: 'Who must approve', value: function (p) { return p.required_roles.map(function (x) { return ROLE[x] || R.human(x); }).join(', '); } },
      { label: 'Approvals needed', value: function (p) { return p.quorum; } },
      { label: 'Approvals last', value: function (p) { return days(p.approval_ttl_seconds); } },
    ], data.policies, [
      { label: 'Change', when: function () { return canAdmin; }, run: editPolicy },
    ], { text: canAdmin ? 'No approval rules yet. Add one before creating a notice version.' : 'No approval rules yet. Ask an administrator to add one.' });

    R.table(document.getElementById('png-proposals'), [
      { label: 'Notice', value: function (p) { return name(p.notice_id) + ' (from version ' + p.base_version + ')'; } },
      { label: 'Why', value: function (p) { return p.reason_codes.map(R.human).join(', '); } },
      { label: 'Law references', value: function (p) { return p.citations; } },
      { label: 'Status', value: function (p) { return badge(PROPOSAL, p.status); } },
    ], data.proposals, [
      { label: 'Accept', kind: 'primary', when: function (p) { return canAdmin && p.status === 'pending_review'; }, run: function (p) { reviewProposal(p, 'approved'); } },
      { label: 'Reject', when: function (p) { return canAdmin && p.status === 'pending_review'; }, run: function (p) { reviewProposal(p, 'rejected'); } },
    ], { text: 'No suggested updates.' });

    R.table(document.getElementById('png-records'), [
      { label: 'Notice', value: function (e) { return name(e.notice_id); } },
      { label: 'Created', value: function (e) { return R.when(e.created_at); } },
    ], data.records, [{ label: 'Download', run: downloadRecord }], { text: 'No signed records yet. Records appear here when a notice version is published.' });

    var q = data.queue || {};
    var waiting = (q.pending || 0) + (q.leased || 0);
    document.getElementById('png-sched').textContent = waiting
      ? waiting + ' update(s) waiting to be published.' + ((q.dead_letter || 0) ? ' ' + q.dead_letter + ' failed and need attention.' : '')
      : 'Nothing is waiting to be published.' + ((q.dead_letter || 0) ? ' ' + q.dead_letter + ' failed and need attention.' : '');

    var noticeSelect = document.getElementById('png-notice');
    var chosen = noticeSelect.value;
    noticeSelect.textContent = '';
    var fresh = R.el('option', '', 'A new notice'); fresh.value = ''; noticeSelect.appendChild(fresh);
    unique(data.releases.map(function (r) { return r.notice_id; })).forEach(function (id) {
      var o = R.el('option', '', name(id)); o.value = id; noticeSelect.appendChild(o);
    });
    noticeSelect.value = chosen;
    var policySelect = document.getElementById('png-policy');
    policySelect.textContent = '';
    data.policies.forEach(function (p) { var o = R.el('option', '', name(p.policy_id)); o.value = p.policy_id; policySelect.appendChild(o); });
    var props = document.getElementById('png-eff-property');
    props.textContent = '';
    unique(data.releases.map(function (r) { return r.property_id; })).forEach(function (id) {
      var o = R.el('option', '', name(id)); o.value = id; props.appendChild(o);
    });
  }

  function unique(list) { return list.filter(function (v, i) { return list.indexOf(v) === i; }); }
  function remainingRoles(r) {
    var done = approvalsFor(r).map(function (a) { return a.role; });
    return r.required_roles.filter(function (x) { return done.indexOf(x) < 0; });
  }
  function earlierLive(r) {
    return data.releases.filter(function (x) { return x.notice_id === r.notice_id && x.version < r.version; });
  }

  // ---- steps --------------------------------------------------------------
  function post(r, path, body, done, action) {
    return R.call('POST', API + '/releases/' + encodeURIComponent(r.notice_id) + '/versions/' + r.version + path, body)
      .then(function () { say(done); return load(); })
      .catch(function (f) {
        if (f && f.status === 409) { say('This version changed or is not ready for this step. The list has been refreshed.'); load(); return; }
        fail(f, action);
      });
  }

  function submit(r) {
    R.confirm('Send version ' + r.version + ' of “' + name(r.notice_id) + '” for approval? It can no longer be changed.', 'Send for approval').then(function (ok) {
      if (ok) post(r, '/submit', { expected_revision: r.revision, idempotency_key: R.newKey() }, 'Sent for approval.', 'send it for approval');
    });
  }

  function approve(r) {
    var roles = remainingRoles(r);
    R.form('Approve version ' + r.version, [
      { key: 'role', label: 'Approve as', type: 'select', default: roles[0], options: roles.map(function (x) { return { value: x, label: ROLE[x] || R.human(x) }; }) },
    ], 'Approve').then(function (v) {
      if (!v) return;
      post(r, '/approvals', { role: v.role, expected_release_sha256: r.release_sha256, expected_revision: r.revision, idempotency_key: R.newKey() },
        'Approval recorded.', 'record the approval');
    });
  }

  function revokeApproval(r) {
    var mine = approvalsFor(r);
    R.form('Withdraw an approval', [
      { key: 'i', label: 'Approval', type: 'select', default: '0', options: mine.map(function (a, i) { return { value: String(i), label: ROLE[a.role] || R.human(a.role) }; }) },
    ], 'Next').then(function (v) {
      if (!v) return null;
      var a = mine[parseInt(v.i || '0', 10)];
      return R.confirm('Withdraw the ' + (ROLE[a.role] || a.role) + ' approval? Only the person who gave it can do this.', 'Withdraw').then(function (ok) {
        if (!ok) return;
        R.call('POST', API + '/releases/' + encodeURIComponent(r.notice_id) + '/versions/' + r.version + '/approvals/' + encodeURIComponent(a.role) + '/revoke',
          { expected_approval_revision: a.revision, idempotency_key: R.newKey() })
          .then(function () { say('Approval withdrawn.'); return load(); })
          .catch(function (f) {
            fail(f, 'withdraw the approval');
          });
      });
    });
  }

  function schedule(r) {
    R.form('Schedule publishing', [
      { key: 'at', label: 'Publish on', type: 'date', required: true, default: new Date().toISOString().slice(0, 10) },
    ], 'Schedule').then(function (v) {
      if (!v) return;
      var at = Math.max(Math.floor(Date.now() / 1000) + 60, R.toEpoch(v.at) - 86399);
      post(r, '/schedule', { activate_at: at, expected_release_sha256: r.release_sha256, max_attempts: 5, expected_revision: r.revision, idempotency_key: R.newKey() },
        'Publishing scheduled.', 'schedule publishing');
    });
  }

  var REASONS = [
    { value: 'legal-change', label: 'The law changed' }, { value: 'error-in-notice', label: 'The notice has an error' },
    { value: 'business-change', label: 'Our business changed' }, { value: 'regulator-request', label: 'A regulator asked us to' },
  ];
  function withdraw(r) {
    R.form('Withdraw version ' + r.version, [
      { key: 'reason', label: 'Why', type: 'select', default: 'error-in-notice', options: REASONS },
    ], 'Next').then(function (v) {
      if (!v) return null;
      return R.confirm('Withdraw the live version of “' + name(r.notice_id) + '”? It stops being shown.', 'Withdraw').then(function (ok) {
        if (ok) post(r, '/withdraw', { reason_code: v.reason, max_attempts: 5, expected_revision: r.revision, idempotency_key: R.newKey() }, 'Withdrawn.', 'withdraw the version');
      });
    });
  }
  function rollback(r) {
    var earlier = earlierLive(r);
    R.form('Roll back version ' + r.version, [
      { key: 'target', label: 'Go back to version', type: 'select', default: String(earlier[0].version), options: earlier.map(function (x) { return { value: String(x.version), label: 'Version ' + x.version }; }) },
      { key: 'reason', label: 'Why', type: 'select', default: 'error-in-notice', options: REASONS },
    ], 'Next').then(function (v) {
      if (!v) return null;
      return R.confirm('Replace the live version with version ' + v.target + '?', 'Roll back').then(function (ok) {
        if (ok) post(r, '/rollback', { target_version: parseInt(v.target, 10), reason_code: v.reason, max_attempts: 5, expected_revision: r.revision, idempotency_key: R.newKey() }, 'Rolled back.', 'roll back');
      });
    });
  }

  function record(r) {
    R.call('POST', API + '/releases/' + encodeURIComponent(r.notice_id) + '/record', { retained_until: r.retained_until, idempotency_key: R.newKey() })
      .then(function (rec) { R.download('privacy-notice-record.json', rec); say('Signed record downloaded.'); return load(); })
      .catch(function (f) {
        if (f && f.status === 503) { say('Signed records are not set up yet. Ask the person who installed Lightwork to add the record signing key.'); return; }
        fail(f, 'create the signed record');
      });
  }
  function downloadRecord(e) {
    R.call('GET', API + '/exports/' + encodeURIComponent(e.export_id))
      .then(function (rec) { R.download('privacy-notice-record.json', rec); say('Signed record downloaded.'); })
      .catch(function (f) { fail(f, 'download the record'); });
  }

  function reviewProposal(p, decision) {
    R.call('GET', '/api/v1/privacy/notice-proposals/proposal?identity=' + encodeURIComponent(p.proposal_id)).then(function (card) {
      var message = card.notice + ' · based on version ' + card.base_version + '. Reasons: ' + card.reasons.join('; ') + '.\n' + card.references.map(function (ref) { return ref.label + (ref.version ? ' · version ' + ref.version : '') + '. ' + ref.source_name + '. ' + ref.citation_labels.join('; '); }).join('\n') + '\n' + card.notice_scope;
      return R.confirm(message + (decision === 'approved' ? '\nAccept this recorded proposal? You must be a different person from its author.' : '\nReject this proposal?'), decision === 'approved' ? 'Accept recorded proposal' : 'Reject').then(function (ok) {
        if (!ok) return;
        return R.call('POST', API + '/update-proposals/' + encodeURIComponent(p.proposal_id) + '/review', {decision: decision, expected_revision: card.revision, idempotency_key: R.newKey()}).then(function () { say(decision === 'approved' ? 'Recorded proposal accepted. Nothing was published.' : 'Proposal rejected.'); return load(); });
      });
    }).catch(function (f) { fail(f, 'review the update'); });
  }

  // ---- approval rules -------------------------------------------------------
  function editPolicy(existing) {
    var fields = [];
    if (!existing || !existing.policy_id) fields.push({ key: 'name', label: 'Rule name', type: 'text', required: true, placeholder: 'For example: Standard approval' });
    Object.keys(ROLE).forEach(function (role) {
      fields.push({ key: 'r_' + role, label: 'Needs ' + ROLE[role] + ' approval', type: 'bool', default: existing && existing.required_roles ? existing.required_roles.indexOf(role) >= 0 : role === 'privacy' || role === 'legal' });
    });
    fields.push({ key: 'quorum', label: 'How many approvals are needed', type: 'select', default: String(existing && existing.quorum ? existing.quorum : 2), options: ['1', '2', '3', '4'] });
    fields.push({ key: 'ttl', label: 'An approval lasts', type: 'select', default: String(existing && existing.approval_ttl_seconds ? existing.approval_ttl_seconds : 30 * 86400), options: [
      { value: String(7 * 86400), label: '7 days' }, { value: String(30 * 86400), label: '30 days' },
      { value: String(90 * 86400), label: '90 days' }, { value: String(365 * 86400), label: '1 year' },
    ] });
    R.form(existing && existing.policy_id ? 'Change approval rule' : 'Add an approval rule', fields, 'Save').then(function (v) {
      if (!v) return;
      var roles = Object.keys(ROLE).filter(function (role) { return v['r_' + role]; });
      var quorum = parseInt(v.quorum, 10);
      if (!roles.length) { say('Choose at least one role that must approve.'); return; }
      if (quorum > roles.length) { say('The number of approvals cannot be more than the number of roles chosen. Lower the number or choose more roles.'); return; }
      var id = existing && existing.policy_id ? existing.policy_id : R.slug(v.name, 'approval-rule');
      return R.call('PUT', API + '/approval-policies/' + encodeURIComponent(id), {
        required_roles: roles, quorum: quorum, approval_ttl_seconds: parseInt(v.ttl, 10),
        expected_revision: existing && existing.revision ? existing.revision : 0, idempotency_key: R.newKey(),
      }).then(function () { say('Approval rule saved.'); return load(); });
    }).catch(function (f) { fail(f, 'save the approval rule'); });
  }
  var newPolicy = document.getElementById('png-new-policy');
  if (newPolicy) newPolicy.addEventListener('click', function () { editPolicy(null); });

  // ---- new version ----------------------------------------------------------
  function openReleaseForm() {
    if (!data.policies.length) { say('Add an approval rule first.'); return; }
    var panel = document.getElementById('png-release-panel');
    document.getElementById('png-from').value = R.isoDateIn(0);
    document.getElementById('png-until').value = R.isoDateIn(365);
    document.getElementById('png-keep').value = R.isoDateIn(365 * 7);
    panel.hidden = false;
    panel.scrollIntoView({ block: 'start' });
  }
  document.getElementById('png-new-version').addEventListener('click', openReleaseForm);
  document.getElementById('png-release-cancel').addEventListener('click', function () { document.getElementById('png-release-panel').hidden = true; });

  document.getElementById('png-release-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (window.LightworkPrivacyNoticeVersions) window.LightworkPrivacyNoticeVersions.save();
    else say('The protected version controls are still loading. Nothing was saved.');
  });

  // ---- which version is live ------------------------------------------------
  document.getElementById('png-effective').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var prop = document.getElementById('png-eff-property').value;
    if (!prop) { say('There are no notices yet. Create a notice first, then check which version is live.'); return; }
    var q = '?jurisdiction=' + encodeURIComponent(document.getElementById('png-eff-jur').value) +
      '&locale=' + encodeURIComponent(document.getElementById('png-eff-lang').value);
    var at = R.toEpoch(document.getElementById('png-eff-at').value);
    if (at) q += '&at=' + at;
    var out = document.getElementById('png-eff-result');
    R.call('GET', API + '/effective/' + encodeURIComponent(prop) + q).then(function (r) {
      out.textContent = r && r.version ? 'Version ' + r.version + ' of “' + name(r.notice_id) + '” is live there.' : 'No version is live there.';
    }).catch(function (f) {
      out.textContent = f && f.status === 404 ? 'No version is live there at that time.' : R.errorText(f, 'check which version is live');
    });
  });

  // ---- scheduled publishing and maintenance ---------------------------------
  var runOnce = document.getElementById('png-run-once');
  if (runOnce) runOnce.addEventListener('click', function () {
    R.confirm('Publish every scheduled update that is due now? This updates Lightwork’s consent publishing records.', 'Publish now').then(function (ok) {
      if (!ok) return;
      runOnce.disabled = true;
      R.call('POST', API + '/publication-runtime/run-once', {}).then(function () { say('Scheduled updates published.'); return load(); })
        .catch(function (f) {
          if (f && (f.status === 409 || f.status === 503)) { say('Publishing is not connected for this workspace yet. Ask the person who installed Lightwork.'); return; }
          fail(f, 'publish the scheduled updates');
        })
        .then(function () { runOnce.disabled = false; });
    });
  });
  var purge = document.getElementById('png-purge');
  if (purge) purge.addEventListener('click', function () {
    R.confirm('Permanently delete notice records whose keep-until date has passed?', 'Delete').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/retention/purge', { cutoff: Math.floor(Date.now() / 1000), idempotency_key: R.newKey() })
        .then(function () { say('Expired records deleted.'); return load(); })
        .catch(function (f) { fail(f, 'delete expired records'); });
    });
  });
  var integrity = document.getElementById('png-integrity');
  if (integrity) integrity.addEventListener('click', function () {
    R.call('GET', API + '/integrity').then(function () { say('All records are intact.'); })
      .catch(function (f) { fail(f, 'check the records'); });
  });

  load();
})();
