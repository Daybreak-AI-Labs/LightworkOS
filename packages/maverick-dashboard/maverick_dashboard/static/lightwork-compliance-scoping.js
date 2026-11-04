// Compliance scoping as a guided workflow: record lists on load, a button per
// row, forms with choices instead of typed references. Record references,
// versions and request keys come from the chosen row or are generated.
(function () {
  'use strict';
  var R = window.LwRecords;
  var app = document.getElementById('cs-app');
  if (!R || !app) return;
  var API = '/api/v1/compliance/scoping';
  var canAdmin = app.getAttribute('data-can-admin') === 'true';
  var statusEl = document.getElementById('cs-status');
  var records = { questionnaires: [], assessments: [], scopes: [], reports: [] };
  var answering = null;
  var names = {};

  var STATUS = {
    pending_review: ['Waiting for approval', 'warn'], published: ['Ready to use', 'active'],
    open: ['In progress', 'info'], scoped: ['Scope worked out', 'active'],
    draft: ['Waiting for approval', 'warn'], approved: ['Approved', 'info'], finalized: ['Final', 'active'],
  };
  var DOMAINS = {
    organization: 'Your organization', industry: 'Industry', jurisdiction: 'Where you operate',
    data: 'Data you handle', system: 'Your systems', vendor: 'Vendors', ai: 'AI use', operational: 'Operations',
  };
  var ROLES = [
    ['first_line', 'Business owner'], ['second_line', 'Risk and compliance owner'],
    ['control_owner', 'Control owner'], ['evidence_owner', 'Evidence owner'],
  ];

  function say(text) { window.mvStatus(statusEl, text); }
  function fail(failure, action) { say(R.errorText(failure, action)); }
  function statusBadge(value) {
    var s = STATUS[value] || [R.human(value), 'info'];
    return R.badge(s[0], s[1]);
  }
  // "ref:question-org-size" -> "Org size"; "framework-eu-privacy" -> "Eu privacy".
  function label(ref) {
    return names[ref] || R.human(String(ref || '').replace(/^(ref|evidence):/, '').replace(/^(question|framework|control|overlap)[-_]/, ''));
  }
  function questionnaireName(id, version) {
    var q = records.questionnaires.find(function (row) { return row.questionnaire_id === id && (!version || row.version === version); });
    return (q && q.display_names && q.display_names[id] || label(id)) + (version ? ' (version ' + version + ')' : '');
  }

  function load() {
    return R.call('GET', API + '/records').then(function (body) {
      records = body;
      names = {};
      records.questionnaires.slice().reverse().forEach(function (q) { Object.assign(names, q.display_names || {}); });
      render();
      say(records.assessments.length ? '' : 'Start an assessment to work out which controls apply to you.');
    }).catch(function (f) {
      if (f && f.status === 409) { say('Choose a workspace first, then come back to this page.'); return; }
      fail(f, 'load your records');
    });
  }

  function render() {
    var scopedAssessments = {};
    records.scopes.forEach(function (s) { scopedAssessments[s.assessment_id] = true; });

    R.table(document.getElementById('cs-assessments'), [
      { label: 'Questionnaire', value: function (a) { return questionnaireName(a.questionnaire_id, a.questionnaire_version); } },
      { label: 'Answers saved', value: function (a) { return a.answered; } },
      { label: 'Status', value: function (a) { return statusBadge(a.status); } },
      { label: 'Started', value: function (a) { return R.day(a.created_at); } },
      { label: 'Keep until', value: function (a) { return R.day(a.retained_until); } },
    ], records.assessments, [
      { label: 'Answer questions', kind: 'primary', when: function (a) { return a.status === 'open'; }, run: openAnswers },
      { label: 'Work out scope', when: function (a) { return a.status === 'open' && !scopedAssessments[a.assessment_id]; }, run: computeScope },
    ], { text: 'No assessments yet.', action: { label: 'Start an assessment', run: startAssessment } });

    R.table(document.getElementById('cs-scopes'), [
      { label: 'From assessment', value: function (s) { var a = find('assessments', 'assessment_id', s.assessment_id); return a ? questionnaireName(a.questionnaire_id, a.questionnaire_version) : 'Assessment'; } },
      { label: 'Frameworks', value: function (s) { return s.frameworks.map(label).join(', '); } },
      { label: 'Controls', value: function (s) { return s.controls; } },
      { label: 'Status', value: function (s) { return statusBadge(s.status); } },
    ], records.scopes, [
      { label: 'View', run: viewScope },
      { label: 'Approve', kind: 'primary', when: function (s) { return canAdmin && s.status === 'draft'; }, run: approveScope },
      { label: 'Make final', kind: 'primary', when: function (s) { return s.status === 'approved'; }, run: finalizeScope },
      { label: 'Create report', when: function (s) { return s.status === 'finalized'; }, run: createReport },
    ], { text: 'No scopes yet. Answer every question in an assessment, then use “Work out scope”.' });

    R.table(document.getElementById('cs-reports'), [
      { label: 'Scope', value: function (e) { var s = find('scopes', 'scope_id', e.scope_id); return s ? s.frameworks.map(label).join(', ') || 'Scope' : 'Scope'; } },
      { label: 'Created', value: function (e) { return R.when(e.created_at); } },
    ], records.reports, [
      { label: 'Download', run: downloadReport },
    ], { text: 'No reports yet. Make a scope final, then use “Create report”.' });

    var latest = {};
    records.questionnaires.forEach(function (q) { latest[q.questionnaire_id] = Math.max(latest[q.questionnaire_id] || 0, q.version); });
    R.table(document.getElementById('cs-questionnaires'), [
      { label: 'Questionnaire', value: function (q) { return q.display_names && q.display_names[q.questionnaire_id] || label(q.questionnaire_id); } },
      { label: 'Version', value: function (q) { return q.version; } },
      { label: 'Questions', value: function (q) { return q.questions; } },
      { label: 'Status', value: function (q) { return statusBadge(q.status); } },
    ], records.questionnaires, [
      { label: 'Approve for use', kind: 'primary', when: function (q) { return canAdmin && q.status !== 'published'; }, run: publishQuestionnaire },
      { label: 'Review a new version', run: function (q) { window.LightworkComplianceQuestionnaire.open(q.questionnaire_id); } },
    ], { text: 'No questionnaires yet. Build one here and have a different administrator approve it.' });
  }

  function find(kind, key, value) {
    return (records[kind] || []).filter(function (r) { return r[key] === value; })[0];
  }

  // ---- questionnaires -----------------------------------------------------
  function showQuestionnaireReview(q, parent) {
    var labels = q.display_names || {}, questions = {};
    function named(ref) { return labels[ref] || R.human(String(ref || '').replace(/^ref:/, '')); }
    function add(tag, text, host) { var node = R.el(tag, '', text); host.appendChild(node); return node; }
    (q.questions || []).forEach(function (item) { questions[item.question_id] = item; });
    function condition(c) {
      if (!c) return 'Always';
      var question = questions[c.question_id], value = c.value;
      if (!question) return 'Unavailable question · approval is paused';
      var answer = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : typeof value === 'number' ? String(value) :
        (Array.isArray(value) ? value : [value]).map(named).join(' / ');
      return named(question.question_ref) + ' ' + ({equals: 'is', not_equals: 'is not', contains: 'includes', in: 'is any of', greater_or_equal: 'is at least', less_or_equal: 'is at most'}[c.operator] || R.human(c.operator)) + ' ' + answer;
    }
    var kinds = {boolean: 'Yes or no', integer: 'Whole number', single_choice: 'Choose one', multi_choice: 'Choose several', opaque_ref: 'Named item'};
    if (q.studio_source && q.studio_source.studio_id) add('p', 'Imported from Compliance studio: ' + R.human(q.studio_source.studio_id) + ' · ' + R.human(q.studio_source.form_id) + ' · version ' + q.studio_source.version + '. This questionnaire is a separate immutable version.', parent);
    q.questions.forEach(function (item, index) {
      var card = add('section', undefined, parent); card.className = 'panel cs-stack';
      add('h4', (index + 1) + '. ' + named(item.question_ref), card);
      add('p', DOMAINS[item.domain] + ' · ' + (kinds[item.answer_type] || R.human(item.answer_type)) + ' · ' + (item.required ? 'Answer required' : 'Optional answer'), card);
      if (item.options.length) add('p', 'Choices: ' + item.options.map(named).join(' / '), card);
      add('p', 'Appears: ' + condition(item.condition), card);
    });
    q.rules.forEach(function (item, index) {
      var card = add('section', undefined, parent); card.className = 'panel cs-stack';
      add('h4', 'Rule ' + (index + 1) + ' · ' + named(item.framework_ref), card);
      add('p', 'Controls: ' + item.control_refs.map(named).join(' / '), card);
      if (item.overlap_refs.length) add('p', 'Shared requirements: ' + item.overlap_refs.map(named).join(' / '), card);
      add('p', 'Reason: ' + named(item.reason_code), card);
      add('p', 'Applies: ' + (item.conditions.length ? item.conditions.map(condition).join(' AND ') : 'Always'), card);
    });
  }
  async function publishQuestionnaire(q) {
    var full;
    try { full = await R.call('GET', API + '/questionnaires/' + encodeURIComponent(q.questionnaire_id) + '/versions/' + q.version); }
    catch (f) { fail(f, 'read the questionnaire for approval'); return; }
    if (full.revision !== q.revision || full.status !== 'pending_review') { say('This saved version changed. Refresh its current details before approving it.'); return; }
    var message = document.getElementById('mv-confirm-msg'), dialog = document.getElementById('mv-confirm');
    if (!message || !dialog || typeof dialog.showModal !== 'function' || dialog.open) { say('The complete approval review is unavailable. Keep this saved version and reopen its full controls before approving.'); return; }
    var answer = R.confirm('Review every question, choice and scope rule in “' + questionnaireName(q.questionnaire_id, q.version) + '” below. Approving makes this exact saved version available for new assessments. A different administrator from its creator must approve it. Existing assessments keep their original version.', 'Approve for use');
    var detail = null, current = true;
    function invalidate() { current = false; if (detail) detail.remove(); if (dialog.open) dialog.dispatchEvent(new Event('cancel', {cancelable: true})); }
    var events = ['lightwork:account-context-changed', 'lightwork:workspace-changed', 'lightwork:copilot-context-changed'];
    events.forEach(function (event) { document.addEventListener(event, invalidate); }); window.addEventListener('lightwork:context-changed', invalidate);
    if (dialog.open) { detail = document.createElement('div'); message.insertAdjacentElement('afterend', detail); showQuestionnaireReview(full, detail); }
    var ok;
    try { ok = await answer; } finally { if (detail) detail.remove(); events.forEach(function (event) { document.removeEventListener(event, invalidate); }); window.removeEventListener('lightwork:context-changed', invalidate); }
      if (!ok || !current) return;
      R.call('POST', API + '/questionnaires/' + encodeURIComponent(q.questionnaire_id) + '/versions/' + q.version + '/publish',
        { expected_revision: q.revision, idempotency_key: R.newKey() })
        .then(function () { say('Questionnaire approved.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('A different administrator from the person who added it must approve it.'); return; }
          fail(f, 'approve the questionnaire');
        });
  }

  document.getElementById('cs-add-questionnaire').addEventListener('click', function () { window.LightworkComplianceQuestionnaire.open(); });
  document.addEventListener('lightwork:questionnaire-saved', load);
  document.getElementById('cs-import-questionnaire').addEventListener('click', function () {
    R.form('Add a questionnaire', [
      { key: 'name', label: 'Questionnaire name', type: 'text', required: true, placeholder: 'For example: Annual scoping' },
    ], 'Choose file').then(function (values) {
      if (!values) return null;
      return R.pickFile('.json,application/json').then(function (file) {
        if (!file) return null;
        return file.text().then(function (text) {
          var parsed;
          try { parsed = JSON.parse(text); } catch (e) { parsed = null; }
          if (!parsed || !Array.isArray(parsed.questions) || !Array.isArray(parsed.rules)) {
            say('That file is not a questionnaire file. Ask your compliance team for the questionnaire file.');
            return null;
          }
          var id = R.slug(values.name, 'questionnaire');
          var existing = records.questionnaires.filter(function (q) { return q.questionnaire_id === id; })
            .reduce(function (n, q) { return Math.max(n, q.version); }, 0);
          return R.call('PUT', API + '/questionnaires/' + encodeURIComponent(id) + '/versions', {
            questions: parsed.questions, rules: parsed.rules,
            expected_latest_version: existing, idempotency_key: R.newKey(),
          }).then(function () {
            say('Questionnaire added. A different administrator must approve it before it can be used.');
            return load();
          });
        });
      });
    }).catch(function (f) { fail(f, 'add the questionnaire'); });
  });

  // ---- assessments --------------------------------------------------------
  function startAssessment() {
    var ready = records.questionnaires.filter(function (q) { return q.status === 'published'; });
    if (!ready.length) { say('No questionnaire is approved for use yet. Add one below and have an administrator approve it.'); return; }
    R.form('Start an assessment', [
      { key: 'q', label: 'Questionnaire', type: 'select', required: true, default: '0',
        options: ready.map(function (q, i) { return { value: String(i), label: questionnaireName(q.questionnaire_id, q.version) }; }) },
      { key: 'until', label: 'Keep the records until', type: 'date', required: true, default: R.isoDateIn(365 * 3) },
    ], 'Start').then(function (values) {
      if (!values) return;
      var q = ready[parseInt(values.q || '0', 10)];
      var until = R.toEpoch(values.until);
      if (!until || until * 1000 <= Date.now()) { say('Choose a date in the future.'); return; }
      return R.call('PUT', API + '/assessments/' + encodeURIComponent(R.newId('assessment')), {
        questionnaire_id: q.questionnaire_id, questionnaire_version: q.version,
        retained_until: until, idempotency_key: R.newKey(),
      }).then(function (created) {
        say('Assessment started. Answer the questions next.');
        return load().then(function () { openAnswers(find('assessments', 'assessment_id', created.assessment_id) || created); });
      });
    }).catch(function (f) { fail(f, 'start the assessment'); });
  }
  document.getElementById('cs-new-assessment').addEventListener('click', startAssessment);

  function fieldFor(q, index) {
    var wrap = R.el('fieldset', 'panel');
    var legend = R.el('legend', '', q.display_name || label(q.question_ref));
    wrap.appendChild(legend);
    wrap.appendChild(R.el('p', 'muted', DOMAINS[q.domain] || R.human(q.domain)));
    var id = 'cs-q-' + index;
    var control;
    if (q.answer_type === 'boolean') {
      control = R.el('div');
      ['true', 'false'].forEach(function (v) {
        var l = R.el('label');
        var r = R.el('input'); r.type = 'radio'; r.name = id; r.value = v;
        l.appendChild(r); l.appendChild(document.createTextNode(v === 'true' ? ' Yes ' : ' No '));
        control.appendChild(l);
      });
    } else if (q.answer_type === 'single_choice') {
      control = R.el('select', 'select'); control.id = id;
      var blank = R.el('option', '', 'Choose an answer'); blank.value = ''; control.appendChild(blank);
      q.options.forEach(function (o) { var op = R.el('option', '', (q.option_labels || {})[o] || label(o)); op.value = o; control.appendChild(op); });
      var lab = R.el('label', '', 'Answer'); lab.setAttribute('for', id); wrap.appendChild(lab);
    } else if (q.answer_type === 'multi_choice') {
      control = R.el('div');
      q.options.forEach(function (o, j) {
        var l = R.el('label');
        var c = R.el('input'); c.type = 'checkbox'; c.name = id; c.value = o; c.id = id + '-' + j;
        l.appendChild(c); l.appendChild(document.createTextNode(' ' + ((q.option_labels || {})[o] || label(o)) + ' '));
        control.appendChild(l);
      });
    } else if (q.answer_type === 'integer') {
      control = R.el('input', 'input'); control.type = 'number'; control.min = '0'; control.step = '1'; control.id = id;
      var labN = R.el('label', '', 'Number'); labN.setAttribute('for', id); wrap.appendChild(labN);
    } else {
      control = R.el('input', 'input'); control.type = 'text'; control.id = id; control.maxLength = 100;
      control.placeholder = 'Name of the item this refers to';
      var labT = R.el('label', '', 'Answer'); labT.setAttribute('for', id); wrap.appendChild(labT);
    }
    wrap.appendChild(control);
    var fileId = id + '-evidence';
    var fl = R.el('label', '', 'Supporting document'); fl.setAttribute('for', fileId);
    var file = R.el('input', 'input'); file.type = 'file'; file.id = fileId;
    wrap.appendChild(fl); wrap.appendChild(file);
    wrap.dataset.index = String(index);
    return wrap;
  }

  function readAnswer(q, index) {
    var id = 'cs-q-' + index;
    if (q.answer_type === 'boolean') {
      var picked = document.querySelector('input[name="' + id + '"]:checked');
      return picked ? picked.value === 'true' : undefined;
    }
    if (q.answer_type === 'multi_choice') {
      var boxes = document.querySelectorAll('input[name="' + id + '"]:checked');
      var values = Array.prototype.map.call(boxes, function (b) { return b.value; });
      return values.length ? values : undefined;
    }
    var v = (document.getElementById(id).value || '').trim();
    if (!v) return undefined;
    if (q.answer_type === 'integer') return parseInt(v, 10);
    if (q.answer_type === 'opaque_ref') return 'ref:' + R.slug(v);
    return v;
  }

  function openAnswers(a) {
    R.call('GET', API + '/assessments/' + encodeURIComponent(a.assessment_id) + '/required-questions').then(function (body) {
      var items = body.items || [];
      if (!items.length) { say('Every question is answered. Use “Work out scope” next.'); document.getElementById('cs-answer').hidden = true; return; }
      answering = { assessment: a, questions: items, revision: a.revision };
      var form = document.getElementById('cs-answer-form');
      form.textContent = '';
      items.forEach(function (q, i) { form.appendChild(fieldFor(q, i)); });
      var panel = document.getElementById('cs-answer');
      panel.hidden = false;
      panel.scrollIntoView({ block: 'start' });
      say(items.length + ' question(s) to answer.');
    }).catch(function (f) { fail(f, 'load the questions'); });
  }

  document.getElementById('cs-answer-close').addEventListener('click', function () {
    document.getElementById('cs-answer').hidden = true; answering = null;
  });

  document.getElementById('cs-answer-save').addEventListener('click', function () {
    if (!answering) return;
    var work = [];
    answering.questions.forEach(function (q, i) {
      var value = readAnswer(q, i);
      if (value === undefined) return;
      var file = document.getElementById('cs-q-' + i + '-evidence').files[0];
      work.push({ q: q, value: value, file: file });
    });
    if (!work.length) { say('Answer at least one question first.'); return; }
    var missing = work.filter(function (w) { return !w.file; });
    if (missing.length) { say('Attach a supporting document for each answer (' + missing.length + ' missing).'); return; }
    var saved = 0;
    var chain = Promise.resolve();
    work.forEach(function (w) {
      chain = chain.then(function () {
        return R.fingerprint(w.file).then(function (fp) {
          return R.call('POST', API + '/assessments/' + encodeURIComponent(answering.assessment.assessment_id) +
            '/responses/' + encodeURIComponent(w.q.question_id), {
            value: w.value, evidence_sha256: fp.sha256,
            evidence_ref: 'evidence:' + R.slug(w.file.name, 'document'),
            expected_revision: answering.revision, idempotency_key: R.newKey(),
          });
        }).then(function (updated) { answering.revision = updated.revision; saved += 1; });
      });
    });
    chain.then(function () {
      say(saved + ' answer(s) saved.');
      var a = answering.assessment; a.revision = answering.revision;
      return load().then(function () { openAnswers(find('assessments', 'assessment_id', a.assessment_id) || a); });
    }).catch(function (f) { say((saved ? saved + ' answer(s) saved. ' : '') + R.errorText(f, 'save the next answer')); load(); });
  });

  function computeScope(a) {
    R.call('GET', API + '/assessments/' + encodeURIComponent(a.assessment_id) + '/required-questions').then(function (body) {
      if ((body.items || []).length) { say('Answer the remaining ' + body.items.length + ' question(s) first.'); openAnswers(a); return null; }
      return R.form('Who is responsible?', ROLES.map(function (r) {
        return { key: r[0], label: r[1], type: 'text', required: true, placeholder: 'Team or person' };
      }), 'Work out scope').then(function (values) {
        if (!values) return null;
        var assignments = {};
        ROLES.forEach(function (r) { assignments[r[0]] = 'ref:' + R.slug(values[r[0]], 'owner'); });
        return R.call('PUT', API + '/assessments/' + encodeURIComponent(a.assessment_id) + '/scopes/' + encodeURIComponent(R.newId('scope')), {
          responsibility_assignments: assignments, expected_assessment_revision: a.revision, idempotency_key: R.newKey(),
        }).then(function () { say('Scope worked out. A second person must approve it.'); return load(); });
      });
    }).catch(function (f) { fail(f, 'work out the scope'); });
  }

  // ---- scopes -------------------------------------------------------------
  function viewScope(s) {
    R.call('GET', API + '/scopes/' + encodeURIComponent(s.scope_id)).then(function (scope) {
      Object.assign(names, scope.display_names || {});
      var box = document.getElementById('cs-scope-detail');
      box.textContent = '';
      box.appendChild(R.el('h2', '', 'Scope results'));
      box.appendChild(R.el('p', '', 'Frameworks that apply: ' + (scope.applicable_frameworks.map(label).join(', ') || 'none')));
      var ctl = R.el('div');
      R.table(ctl, [
        { label: 'Control', value: function (c) { return label(c.control_ref); } },
        { label: 'Framework', value: function (c) { return label(c.framework_ref); } },
        { label: 'Why it applies', value: function (c) { return (c.reason_codes || []).map(label).join(', '); } },
      ], scope.control_applicability, null, { text: 'No controls apply.' });
      box.appendChild(ctl);
      var owners = scope.responsibility_assignments || {};
      box.appendChild(R.el('p', 'muted', ROLES.map(function (r) { return r[1] + ': ' + label(owners[r[0]]); }).join(' · ')));
      if ((scope.overlaps || []).length) {
        box.appendChild(R.el('h3', '', 'Where requirements overlap'));
        var ov = R.el('div');
        R.table(ov, [
          { label: 'Control', value: function (o) { return label(o.control_ref); } },
          { label: 'Framework', value: function (o) { return label(o.framework_ref); } },
          { label: 'Overlaps with', value: function (o) { return label(o.overlap_ref); } },
        ], scope.overlaps, null);
        box.appendChild(ov);
      }
      box.hidden = false;
      box.scrollIntoView({ block: 'start' });
    }).catch(function (f) { fail(f, 'open the scope'); });
  }

  function approveScope(s) {
    R.confirm('Approve this scope? You must not be the person who worked it out.', 'Approve').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/scopes/' + encodeURIComponent(s.scope_id) + '/approve', { expected_revision: s.revision, idempotency_key: R.newKey() })
        .then(function () { say('Scope approved. The person who worked it out can now make it final.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('A different administrator from the person who worked out the scope must approve it.'); return; }
          fail(f, 'approve the scope');
        });
    });
  }

  function finalizeScope(s) {
    R.confirm('Make this scope final? It can no longer be changed.', 'Make final').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/scopes/' + encodeURIComponent(s.scope_id) + '/finalize', { expected_revision: s.revision, idempotency_key: R.newKey() })
        .then(function () { say('Scope is final. You can now create a report.'); return load(); })
        .catch(function (f) {
          if (f && f.status === 403) { say('Only the person who worked out the scope can make it final.'); return; }
          fail(f, 'make the scope final');
        });
    });
  }

  function createReport(s) {
    R.call('POST', API + '/scopes/' + encodeURIComponent(s.scope_id) + '/report', { idempotency_key: R.newKey() })
      .then(function () { say('Report created. Use Download to save it.'); return load(); })
      .catch(function (f) {
        if (f && f.status === 403) { say('Report signing is not set up yet. Ask the person who installed Lightwork to add the report signing key.'); return; }
        fail(f, 'create the report');
      });
  }

  function downloadReport(e) {
    R.call('GET', API + '/exports/' + encodeURIComponent(e.export_id))
      .then(function (body) { R.download('compliance-scope-report.json', body); say('Report downloaded.'); })
      .catch(function (f) { fail(f, 'download the report'); });
  }

  // ---- maintenance --------------------------------------------------------
  var integrity = document.getElementById('cs-integrity');
  if (integrity) integrity.addEventListener('click', function () {
    R.call('GET', API + '/integrity').then(function () { say('All records are intact.'); })
      .catch(function (f) { fail(f, 'check the records'); });
  });
  var purge = document.getElementById('cs-purge');
  if (purge) purge.addEventListener('click', function () {
    R.confirm('Permanently delete every record whose keep-until date has passed?', 'Delete').then(function (ok) {
      if (!ok) return;
      R.call('POST', API + '/retention/purge', { cutoff: Math.floor(Date.now() / 1000), idempotency_key: R.newKey() })
        .then(function () { say('Expired records deleted.'); return load(); })
        .catch(function (f) { fail(f, 'delete expired records'); });
    });
  });

  load();
})();
