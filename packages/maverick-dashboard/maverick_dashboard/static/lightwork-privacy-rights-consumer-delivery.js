// One-time download codes for answered privacy requests. Closed requests and
// their response files come from the request list; each code is looked up by
// a reference derived from its response file, so no one types an ID.
(function () {
  'use strict';
  var R = window.LwRecords;
  var app = document.getElementById('prcd-app');
  if (!R || !app) return;
  var API = '/api/v1/privacy/rights-consumer-delivery';
  var CASES = '/api/v1/privacy/rights-orchestration';
  var canAdmin = app.getAttribute('data-can-admin') === 'true';
  var statusEl = document.getElementById('prcd-status');
  var readyEl = document.getElementById('prcd-ready');
  var MAX_CODES = 5;
  var ready = false;

  var RIGHT = {
    access: 'See a copy of their data', portability: 'Move their data', erasure: 'Delete their data',
    rectification: 'Correct their data', restriction: 'Limit use', objection: 'Object to use', opt_out: 'Opt out',
  };
  var STATE = {
    active: ['Waiting to be used', 'info'], redeemed: ['Used', 'active'], claimed: ['Downloaded', 'active'],
    revoked: ['Revoked', 'idle'], expired: ['Expired', 'idle'], exhausted: ['Too many tries', 'warn'],
  };

  function say(text) { window.mvStatus(statusEl, text); }
  function fail(f, action) { say(R.errorText(f, action)); }
  function codeId(pkg, n) { return ('code-' + pkg.package_id + '-' + n).slice(0, 128); }

  function status() {
    return R.call('GET', API + '/status').then(function (st) {
      var comp = st.production_composition || {};
      ready = comp.operator_mint_ready === true;
      readyEl.textContent = ready
        ? 'Ready: download codes can be created.'
        : 'Not ready yet: this installation cannot yet confirm who the recipient is, so codes cannot be created. Ask the person who installed Lightwork to set up recipient sign-in for your privacy portal.';
    }).catch(function (f) { readyEl.textContent = R.errorText(f, 'check whether codes can be created'); });
  }

  // The newest existing code for a response file (codes are numbered 1..5).
  function latestCode(pkg) {
    var found = null;
    var chain = Promise.resolve();
    for (var n = 1; n <= MAX_CODES; n++) {
      (function (i) {
        chain = chain.then(function (stop) {
          if (stop) return true;
          return R.call('GET', API + '/deliveries/' + encodeURIComponent(codeId(pkg, i))).then(function (d) {
            found = { n: i, delivery: d }; return false;
          }).catch(function (f) { if (f && f.status === 404) return true; throw f; });
        });
      })(n);
    }
    return chain.then(function () { return found; });
  }

  function load() {
    return R.call('GET', CASES + '/cases').then(function (body) {
      var closed = (body.items || []).filter(function (c) { return c.status === 'closed'; });
      return Promise.all(closed.map(function (c) {
        return R.call('GET', CASES + '/cases/' + encodeURIComponent(c.case_id) + '/work').then(function (w) {
          return (w.packages || []).map(function (p) { return { kase: c, pkg: p }; });
        });
      }));
    }).then(function (groups) {
      var rows = [].concat.apply([], groups);
      return Promise.all(rows.map(function (row) {
        return latestCode(row.pkg).then(function (code) { row.code = code; return row; });
      }));
    }).then(function (rows) {
      render(rows);
    }).catch(function (f) {
      if (f && f.status === 409) { say('Choose a workspace first, then come back to this page.'); return; }
      if (f && f.status === 403) { say('Privacy request handling is turned off, so there are no answered requests to show.'); return; }
      fail(f, 'load the answered requests');
    });
  }

  function render(rows) {
    R.table(document.getElementById('prcd-packages'), [
      { label: 'Request', value: function (r) { return (r.kase.rights || []).map(function (x) { return RIGHT[x] || R.human(x); }).join(', '); } },
      { label: 'Closed', value: function (r) { return R.day(r.kase.updated_at); } },
      { label: 'Response file available until', value: function (r) { return R.day(r.pkg.expires_at); } },
      { label: 'Latest code', value: function (r) {
        if (!r.code) return 'None yet';
        var s = STATE[r.code.delivery.status] || [R.human(r.code.delivery.status), 'info'];
        return R.badge(s[0], s[1]);
      } },
    ], rows, [
      { label: 'Create download code', kind: 'primary', when: function (r) { return canAdmin && ready && (!r.code || r.code.n < MAX_CODES) && r.pkg.expires_at * 1000 > Date.now(); }, run: mint },
      { label: 'Revoke code', kind: 'danger', when: function (r) { return canAdmin && r.code && r.code.delivery.status === 'active'; }, run: revoke },
      { label: 'Download evidence record', when: function (r) { return !!r.code; }, run: evidence },
    ], { text: 'No answered requests yet. Close a request with a recorded response file on the Privacy requests page first.',
         action: { label: 'Go to privacy requests', run: function () { location.href = '/privacy/rights-orchestration'; } } });
  }

  function mint(r) {
    R.form('Create a download code', [
      { key: 'ttl', label: 'Code works for', type: 'select', default: '600', options: [
        { value: '300', label: '5 minutes' }, { value: '600', label: '10 minutes' }, { value: '900', label: '15 minutes' },
      ] },
      { key: 'until', label: 'Keep a record of this code until', type: 'date', required: true, default: R.isoDateIn(365) },
    ], 'Choose sign-in receipt').then(function (v) {
      if (!v) return null;
      var until = R.toEpoch(v.until);
      if (!until || until * 1000 <= Date.now()) { say('Choose a date in the future.'); return null; }
      say('Choose the receipt that shows the person signed in again to prove who they are.');
      return R.pickFile().then(function (file) {
        if (!file) { say('A sign-in receipt is needed to create a code.'); return null; }
        return R.fingerprint(file).then(function (fp) {
          var n = r.code ? r.code.n + 1 : 1;
          return R.call('PUT', API + '/deliveries/' + encodeURIComponent(codeId(r.pkg, n)), {
            case_id: r.kase.case_id, package_id: r.pkg.package_id, reauthentication_receipt_sha256: fp.sha256,
            ttl_seconds: parseInt(v.ttl || '600', 10), retained_until: until, max_attempts: 3,
            min_attempt_interval_seconds: 1, idempotency_key: R.newKey(),
          }).then(function (res) {
            if (!res.capability) { say('The code was already created and cannot be shown again. Revoke it and create a new one.'); return load(); }
            document.getElementById('prcd-link').value = res.capability;
            document.getElementById('prcd-link-box').hidden = false;
            document.getElementById('prcd-link').focus();
            say('Code created. Copy it now; it will not be shown again.');
            return load();
          });
        });
      });
    }).catch(function (f) {
      if (f && f.status === 403) { say('A code cannot be created: the request must be closed, and the person must have signed in again.'); return; }
      fail(f, 'create the code');
    });
  }

  function revoke(r) {
    R.form('Revoke the download code', [
      { key: 'reason', label: 'Why', type: 'select', default: 'sent-to-wrong-person', options: [
        { value: 'sent-to-wrong-person', label: 'Sent to the wrong person' },
        { value: 'requester-asked', label: 'The person asked us to' },
        { value: 'replaced', label: 'Replaced by a new code' },
        { value: 'security-concern', label: 'Security concern' },
      ] },
    ], 'Next').then(function (v) {
      if (!v) return null;
      return R.confirm('Revoke this code? It will stop working immediately.', 'Revoke').then(function (ok) {
        if (!ok) return null;
        return R.call('POST', API + '/deliveries/' + encodeURIComponent(codeId(r.pkg, r.code.n)) + '/revoke', {
          reason_code: v.reason, expected_revision: r.code.delivery.revision, idempotency_key: R.newKey(),
        }).then(function () { say('Code revoked.'); return load(); });
      });
    }).catch(function (f) { fail(f, 'revoke the code'); });
  }

  function evidence(r) {
    R.call('POST', API + '/deliveries/' + encodeURIComponent(codeId(r.pkg, r.code.n)) + '/evidence-record', { idempotency_key: R.newKey() })
      .then(function (rec) { R.download('download-code-record.json', rec); say('Evidence record downloaded.'); })
      .catch(function (f) {
        if (f && f.status === 503) { say('Evidence records are not set up yet. Ask the person who installed Lightwork to add the record signing key.'); return; }
        fail(f, 'download the evidence record');
      });
  }

  document.getElementById('prcd-copy').addEventListener('click', function () {
    if (window.mvCopy) window.mvCopy(document.getElementById('prcd-link').value);
  });
  document.getElementById('prcd-done').addEventListener('click', function () {
    document.getElementById('prcd-link').value = '';
    document.getElementById('prcd-link-box').hidden = true;
  });

  var purge = document.getElementById('prcd-purge');
  if (purge) purge.addEventListener('click', function () {
    R.confirm('Permanently delete code records whose keep-until date has passed?', 'Delete').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/retention/purge', { cutoff: Math.floor(Date.now() / 1000), idempotency_key: R.newKey() })
        .then(function () { say('Expired code records deleted.'); return load(); })
        .catch(function (f) { fail(f, 'delete expired records'); });
    });
  });
  var integrity = document.getElementById('prcd-integrity');
  if (integrity) integrity.addEventListener('click', function () {
    R.call('GET', API + '/integrity').then(function () { say('All records are intact.'); })
      .catch(function (f) { fail(f, 'check the records'); });
  });

  status().then(load);
})();
