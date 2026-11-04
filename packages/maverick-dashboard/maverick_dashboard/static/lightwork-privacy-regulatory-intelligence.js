// Privacy law research: ask questions with ticked places, read answers with
// numbered sources, save reports and alerts, and (administrators) add sources
// and legal texts from forms with choices. Records load on arrival.
(function () {
  'use strict';
  var R = window.LwRecords;
  var app = document.getElementById('pri-app');
  if (!R || !app) return;
  var API = '/api/v1/privacy/regulatory-intelligence';
  var canAdmin = app.getAttribute('data-can-admin') === 'true';
  var statusEl = document.getElementById('pri-status');
  var sources = [];
  var data = { documents: [], trackers: [], reports: [] };

  var PLACE = {};
  Array.prototype.forEach.call(document.querySelectorAll('input[name="pri-where"]'), function (c) {
    PLACE[c.value] = c.parentNode.textContent.trim();
  });
  var SOURCE_STATE = { pending: ['Waiting for approval', 'warn'], active: ['Approved', 'active'], rejected: ['Rejected', 'idle'], revoked: ['No longer used', 'idle'] };
  var TYPE = {
    law: 'Law', regulation: 'Regulation', authority_guidance: 'Regulator guidance', case_law: 'Court decision',
    enforcement_action: 'Enforcement action', regulatory_update: 'Regulatory update', standard: 'Standard',
  };

  function say(text) { window.mvStatus(statusEl, text); }
  function fail(f, action) { say(R.errorText(f, action)); }
  function place(code) { return PLACE[code] || code; }
  function ticked(name) {
    return Array.prototype.map.call(document.querySelectorAll('input[name="' + name + '"]:checked'), function (c) { return c.value; });
  }
  function badge(map, v) { var s = map[v] || [R.human(v), 'info']; return R.badge(s[0], s[1]); }

  function load() {
    return Promise.all([R.call('GET', API + '/sources'), R.call('GET', API + '/records')]).then(function (both) {
      sources = both[0].items || [];
      data = both[1];
      say(sources.some(function (s) { return s.state === 'active'; }) ? '' :
        (canAdmin ? 'No approved sources yet. Add a source below, then ask a different administrator to approve it.' : 'No approved sources yet. Ask an administrator to add one.'));
      render();
    }).catch(function (f) {
      if (f && f.status === 409) { say('Choose a workspace first, then come back to this page.'); return; }
      fail(f, 'load your research');
    });
  }

  function render() {
    R.table(document.getElementById('pri-sources'), [
      { label: 'Source', value: function (s) { return s.name; } },
      { label: 'Covers', value: function (s) { return s.jurisdictions.map(place).join(', '); } },
      { label: 'Status', value: function (s) { return badge(SOURCE_STATE, s.state); } },
    ], sources, [
      { label: 'Approve use', kind: 'primary', when: function (s) { return canAdmin && s.state === 'pending'; }, run: function (s) { reviewSource(s, true); } },
      { label: 'Reject', when: function (s) { return canAdmin && s.state === 'pending'; }, run: function (s) { reviewSource(s, false); } },
      { label: 'Stop using', kind: 'danger', when: function (s) { return canAdmin && s.state === 'active'; }, run: revokeSource },
    ], { text: 'No sources yet. Add a source above to follow it.' });

    R.table(document.getElementById('pri-documents'), [
      { label: 'Title', value: function (d) { return d.title; } },
      { label: 'Where', value: function (d) { return place(d.jurisdiction); } },
      { label: 'Kind', value: function (d) { return TYPE[d.document_type] || R.human(d.document_type); } },
      { label: 'Published', value: function (d) { return d.publication_date; } },
      { label: 'Version', value: function (d) { return d.version; } },
    ], data.documents, [
      { label: 'Send alerts about it', run: alertDocument },
    ], { text: 'No legal texts yet. Texts appear here after a source is read.' });

    R.table(document.getElementById('pri-trackers'), [
      { label: 'Question', value: function (t) { return t.query; } },
      { label: 'Where', value: function (t) { return t.jurisdictions.map(place).join(', '); } },
      { label: 'How often', value: function (t) { return every(t.cadence_seconds); } },
      { label: 'Next check', value: function (t) { return t.state === 'active' ? R.when(t.next_run_at) : 'Stopped'; } },
    ], data.trackers, [
      { label: 'Stop alerts', kind: 'danger', when: function (t) { return t.state === 'active'; }, run: stopTracker },
    ], { text: 'No alerts yet. Ask a question above and use “Alert me when this changes”.' });

    R.table(document.getElementById('pri-reports'), [
      { label: 'Question', value: function (r) { return r.query; } },
      { label: 'Where', value: function (r) { return r.jurisdictions.map(place).join(', '); } },
      { label: 'Sources found', value: function (r) { return r.evidence; } },
      { label: 'Saved', value: function (r) { return R.when(r.created_at); } },
    ], data.reports, [
      { label: 'Open', run: openReport },
      { label: 'Download', run: downloadReport },
    ], { text: 'No saved reports yet. Ask a question above and use “Save as a report”.' });

    var sel = document.getElementById('pri-doc-source');
    if (sel) {
      sel.textContent = '';
      sources.filter(function (s) { return s.state === 'active'; }).forEach(function (s) {
        var o = R.el('option', '', s.name); o.value = s.source_id; sel.appendChild(o);
      });
    }
  }

  function every(seconds) {
    if (seconds <= 86400) return 'Every day';
    if (seconds <= 7 * 86400) return 'Every week';
    return 'Every month';
  }

  // ---- asking questions -----------------------------------------------------
  function question() { return (document.getElementById('pri-question').value || '').trim(); }
  function asOf() { return document.getElementById('pri-asof').value || null; }

  function citeList(cites) {
    var ol = R.el('ol', 'pri-cites');
    (cites || []).forEach(function (c) {
      var li = R.el('li');
      if (c.uri && /^https:\/\//.test(c.uri)) {
        var a = R.el('a', '', c.title || 'Source'); a.href = c.uri; a.target = '_blank'; a.rel = 'noopener noreferrer';
        li.appendChild(a);
      } else {
        li.appendChild(document.createTextNode(c.title || 'Source'));
      }
      if (c.pinpoint) li.appendChild(document.createTextNode(' – ' + c.pinpoint));
      ol.appendChild(li);
    });
    return ol;
  }

  function renderAnswer(box, ans, heading) {
    if (heading) box.appendChild(R.el('h3', '', heading));
    if (ans.status !== 'grounded') {
      box.appendChild(R.el('p', '', 'There is not enough evidence in your approved sources to answer this. Try other wording, other places, or add more legal texts.'));
      return;
    }
    box.appendChild(R.el('p', 'pri-answer', ans.answer));
    if ((ans.citations || []).length) {
      box.appendChild(R.el('p', 'muted', 'Sources:'));
      box.appendChild(citeList(ans.citations));
    }
  }

  document.getElementById('pri-research').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var action = (ev.submitter && ev.submitter.value) || 'research';
    var q = question();
    var where = ticked('pri-where');
    if (!q) { say('Type your question first.'); return; }
    if (action === 'compare' && where.length < 2) { say('Tick at least two places to compare.'); return; }
    var out = document.getElementById('pri-answer');
    out.textContent = 'Looking…';
    var body = { query: q, jurisdictions: where.length ? where : null, as_of: asOf() };
    var call;
    if (action === 'research') { body.minimum_evidence = 1; body.limit = 10; call = R.call('POST', API + '/research', body); }
    else if (action === 'compare') { call = R.call('POST', API + '/compare', { query: q, jurisdictions: where, minimum_evidence_per_jurisdiction: 1, as_of: asOf() }); }
    else { body.limit = 20; call = R.call('POST', API + '/search', body); }
    call.then(function (res) {
      out.textContent = '';
      if (action === 'research') {
        renderAnswer(out, res);
      } else if (action === 'compare') {
        Object.keys(res.answers || {}).forEach(function (code) { renderAnswer(out, res.answers[code], place(code)); });
      } else {
        var hits = res.items || [];
        if (!hits.length) { out.appendChild(R.el('p', '', 'No matching passages in your approved sources.')); return; }
        hits.forEach(function (h) {
          out.appendChild(R.el('h3', '', h.title + ' (' + place(h.jurisdiction) + ')'));
          out.appendChild(R.el('p', '', h.excerpt));
          out.appendChild(citeList(h.citations));
        });
      }
      out.appendChild(R.el('p', 'muted', 'This supports your research. It is not legal advice.'));
      say('');
    }).catch(function (f) { out.textContent = ''; fail(f, 'answer the question'); });
  });

  document.getElementById('pri-save-report').addEventListener('click', function () {
    var q = question();
    var where = ticked('pri-where');
    if (!q || !where.length) { say('Type a question and tick at least one place first.'); return; }
    R.form('Save as a report', [
      { key: 'keep', label: 'Keep the report for', type: 'select', default: '94608000', options: [
        { value: '31536000', label: '1 year' }, { value: '94608000', label: '3 years' }, { value: '220752000', label: '7 years' },
      ] },
    ], 'Save').then(function (v) {
      if (!v) return;
      return R.call('PUT', API + '/reports/' + encodeURIComponent(R.newId('report')), {
        query: q, jurisdictions: where, retention_seconds: parseInt(v.keep, 10), idempotency_key: R.newKey(),
      }).then(function () { say('Report saved.'); return load(); });
    }).catch(function (f) { fail(f, 'save the report'); });
  });

  document.getElementById('pri-track').addEventListener('click', function () {
    var q = question();
    var where = ticked('pri-where');
    if (!q || !where.length) { say('Type a question and tick at least one place first.'); return; }
    R.form('Alert me when this changes', [
      { key: 'every', label: 'Check', type: 'select', default: '604800', options: [
        { value: '86400', label: 'Every day' }, { value: '604800', label: 'Every week' }, { value: '2592000', label: 'Every month' },
      ] },
      { key: 'to', label: 'Send alerts to', type: 'text', required: true, default: 'privacy-team',
        help: 'The name of the alert list your administrator set up.' },
    ], 'Save alert').then(function (v) {
      if (!v) return;
      var id = R.slug(q, 'alert').slice(0, 60) + '-' + R.newId('a').slice(-6);
      return R.call('PUT', API + '/subscriptions/' + encodeURIComponent(id), {
        query: q, jurisdictions: where, destination_ref: R.slug(v.to, 'privacy-team'),
        cadence_seconds: parseInt(v.every, 10), expected_revision: 0, idempotency_key: R.newKey(),
      }).then(function () { say('Alert saved.'); return load(); });
    }).catch(function (f) { fail(f, 'save the alert'); });
  });

  function stopTracker(t) {
    R.confirm('Stop alerts for “' + t.query + '”?', 'Stop alerts').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/subscriptions/' + encodeURIComponent(t.subscription_id) + '/revoke', { expected_revision: t.revision })
        .then(function () { say('Alerts stopped.'); return load(); })
        .catch(function (f) { fail(f, 'stop the alerts'); });
    });
  }

  function openReport(r) {
    R.call('GET', API + '/reports/' + encodeURIComponent(r.report_id)).then(function (rep) {
      var out = document.getElementById('pri-answer');
      out.textContent = '';
      out.appendChild(R.el('h3', '', 'Report: ' + rep.query));
      (rep.evidence || []).forEach(function (h) {
        out.appendChild(R.el('h4', '', h.title + ' (' + place(h.jurisdiction) + ')'));
        out.appendChild(R.el('p', '', h.excerpt));
      });
      out.appendChild(citeList(rep.citations));
      if (rep.disclaimer) out.appendChild(R.el('p', 'muted', 'This supports your research. It is not legal advice.'));
      out.scrollIntoView({ block: 'start' });
    }).catch(function (f) { fail(f, 'open the report'); });
  }
  function downloadReport(r) {
    R.call('GET', API + '/reports/' + encodeURIComponent(r.report_id))
      .then(function (rep) { R.download('privacy-law-report.json', rep); say('Report downloaded.'); })
      .catch(function (f) { fail(f, 'download the report'); });
  }

  function alertDocument(d) {
    R.confirm('Check every active alert against “' + d.title + '” and queue alerts for any that match?', 'Check alerts').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/documents/' + encodeURIComponent(d.document_id) + '/alerts', { version: d.version })
        .then(function (res) { say((res.count || 0) + ' alert(s) queued.'); })
        .catch(function (f) { fail(f, 'queue the alerts'); });
    });
  }

  // ---- sources (administrators) ----------------------------------------------
  function reviewSource(s, approve) {
    R.form(approve ? 'Approve this source' : 'Reject this source', [
      { key: 'why', label: approve ? 'What did you check?' : 'Why reject it?', type: 'text', required: true,
        placeholder: approve ? 'For example: licence and origin checked' : '' },
    ], approve ? 'Approve' : 'Reject').then(function (v) {
      if (!v) return;
      return R.call('POST', API + '/sources/' + encodeURIComponent(s.source_id) + '/review', {
        expected_revision: s.revision, rationale: v.why, approved: approve, idempotency_key: R.newKey(),
      }).then(function () { say(approve ? 'Source approved.' : 'Source rejected.'); return load(); });
    }).catch(function (f) {
      if (f && f.status === 403) { say('A different administrator from the person who added the source must review it.'); return; }
      fail(f, 'review the source');
    });
  }

  function revokeSource(s) {
    R.form('Stop using this source', [
      { key: 'why', label: 'Why', type: 'text', required: true, placeholder: 'For example: licence ended' },
    ], 'Next').then(function (v) {
      if (!v) return null;
      return R.confirm('Stop using “' + s.name + '”? Its texts will no longer be used for answers, alerts, reports or sharing.', 'Stop using').then(function (ok) {
        if (!ok) return null;
        return R.call('POST', API + '/sources/' + encodeURIComponent(s.source_id) + '/revoke', {
          expected_revision: s.revision, reason: v.why, idempotency_key: R.newKey(),
        }).then(function () { say('Source no longer used.'); return load(); });
      });
    }).catch(function (f) { fail(f, 'stop using the source'); });
  }

  function show(panelId, open) {
    var p = document.getElementById(panelId);
    if (!p) return;
    p.hidden = !open;
    if (open) p.scrollIntoView({ block: 'start' });
  }
  var newSource = document.getElementById('pri-new-source');
  if (newSource) newSource.addEventListener('click', function () { show('pri-source-panel', true); });
  var cancelSource = document.getElementById('pri-source-cancel');
  if (cancelSource) cancelSource.addEventListener('click', function () { show('pri-source-panel', false); });

  var sourceForm = document.getElementById('pri-source');
  if (sourceForm) sourceForm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var name = document.getElementById('pri-src-name').value.trim();
    var body = {
      name: name,
      license_ref: document.getElementById('pri-src-license').value.trim(),
      rights_basis: document.getElementById('pri-src-rights').value.trim(),
      allowed_uses: ticked('pri-src-use'),
      provenance_uri: document.getElementById('pri-src-origin').value.trim(),
      jurisdictions: ticked('pri-src-where'),
      authorities: ticked('pri-src-authority'),
      document_types: ticked('pri-src-type'),
      languages: ticked('pri-src-lang'),
      retention_seconds: parseInt(document.getElementById('pri-src-keep').value, 10),
      expected_revision: 0,
      idempotency_key: R.newKey(),
    };
    var missing = [];
    if (!body.jurisdictions.length) missing.push('the places it covers');
    if (!body.authorities.length) missing.push('who issues the texts');
    if (!body.document_types.length) missing.push('the kinds of text');
    if (!body.languages.length) missing.push('a language');
    if (!body.allowed_uses.length) missing.push('what it may be used for');
    if (missing.length) { say('Choose ' + missing.join(', ') + '.'); return; }
    var id = R.slug(name, 'source');
    var existing = sources.filter(function (s) { return s.source_id === id; })[0];
    if (existing) body.expected_revision = existing.revision;
    R.call('PUT', API + '/sources/' + encodeURIComponent(id), body).then(function () {
      sourceForm.reset();
      show('pri-source-panel', false);
      say('Source added. A different administrator must approve it before it is used.');
      return load();
    }).catch(function (f) { fail(f, 'add the source'); });
  });

  var newDoc = document.getElementById('pri-new-document');
  if (newDoc) newDoc.addEventListener('click', function () {
    if (!sources.some(function (s) { return s.state === 'active'; })) { say('Add and approve a source first.'); return; }
    document.getElementById('pri-doc-published').value = document.getElementById('pri-doc-published').value || R.isoDateIn(0);
    show('pri-document-panel', true);
  });
  var cancelDoc = document.getElementById('pri-document-cancel');
  if (cancelDoc) cancelDoc.addEventListener('click', function () { show('pri-document-panel', false); });
  var docFile = document.getElementById('pri-doc-file');
  if (docFile) docFile.addEventListener('change', function () {
    var f = docFile.files && docFile.files[0];
    if (!f) return;
    f.text().then(function (text) { document.getElementById('pri-doc-text').value = text; say('Text loaded from the file.'); })
      .catch(function () { say('That file could not be read. Choose a plain text file.'); });
  });

  var docForm = document.getElementById('pri-document');
  if (docForm) docForm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var title = document.getElementById('pri-doc-title').value.trim();
    var text = document.getElementById('pri-doc-text').value;
    if (!text.trim()) { say('Paste the text or load it from a file.'); return; }
    var link = document.getElementById('pri-doc-link').value.trim();
    if (!/^https:\/\//.test(link)) { say('The link to the official text must start with https://'); return; }
    var id = R.slug(title, 'legal-text');
    var latest = data.documents.filter(function (d) { return d.document_id === id; }).reduce(function (n, d) { return Math.max(n, d.version); }, 0);
    R.fingerprint(new Blob([text], { type: 'text/plain' })).then(function (fp) {
      return R.call('PUT', API + '/documents/' + encodeURIComponent(id), {
        source_id: document.getElementById('pri-doc-source').value,
        title: title,
        jurisdiction: document.getElementById('pri-doc-where').value,
        authority: document.getElementById('pri-doc-authority').value,
        document_type: document.getElementById('pri-doc-type').value,
        language: document.getElementById('pri-doc-lang').value,
        publication_date: document.getElementById('pri-doc-published').value,
        effective_date: document.getElementById('pri-doc-effective').value || null,
        superseded_date: document.getElementById('pri-doc-superseded').value || null,
        citations: [{ citation_id: 'official', title: title, uri: link, pinpoint: document.getElementById('pri-doc-section').value.trim() }],
        content: text,
        content_sha256: fp.sha256,
        expected_latest_version: latest,
        idempotency_key: R.newKey(),
      });
    }).then(function () {
      docForm.reset();
      show('pri-document-panel', false);
      say('Legal text added.');
      return load();
    }).catch(function (f) {
      if (f && f.status === 422) { say('Some details need fixing. Check that the source covers this place, issuer, kind and language.'); return; }
      fail(f, 'add the legal text');
    });
  });

  // ---- maintenance -------------------------------------------------------------
  document.getElementById('pri-integrity').addEventListener('click', function () {
    R.call('GET', API + '/integrity').then(function () { say('All records are intact.'); })
      .catch(function (f) { fail(f, 'check the records'); });
  });
  var send = document.getElementById('pri-send-alerts');
  if (send) send.addEventListener('click', function () {
    R.confirm('Send the alerts that are due now by email?', 'Send alerts').then(function (ok) {
      if (!ok) return;
      send.disabled = true;
      R.call('POST', API + '/deliveries/run', { limit: 10, lease_seconds: 60, base_backoff_seconds: 30, maximum_backoff_seconds: 86400 })
        .then(function (res) {
          var sent = (res && (res.delivered || res.sent)) || 0;
          say(sent ? sent + ' alert(s) sent.' : 'Due alerts processed.');
        })
        .catch(function (f) {
          if (f && f.status === 503) { say('Alert emails are not set up yet. Ask the person who installed Lightwork.'); return; }
          fail(f, 'send the alerts');
        })
        .then(function () { send.disabled = false; });
    });
  });
  var purge = document.getElementById('pri-purge');
  if (purge) purge.addEventListener('click', function () {
    R.confirm('Permanently delete legal texts and shares whose keep-until date has passed? The history of what was done is kept.', 'Delete').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/retention/purge', {}).then(function () { say('Expired texts deleted.'); return load(); })
        .catch(function (f) { fail(f, 'delete expired texts'); });
    });
  });

  load();
})();
