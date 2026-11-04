// Compliance page: turns each "what to do" into a button (switch a protection
// on, stop all work, set retention, export or erase a person's data, download
// auditor reports, run the EU AI Act self-check, search the control library).
(function () {
  'use strict';
  var doc = document;
  function $(id) { return doc.getElementById(id); }
  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  function confirmAction(message, okText) {
    return window.mvConfirm ? window.mvConfirm(message, { okText: okText }) : Promise.resolve(false);
  }
  function say(el, text) { window.mvStatus(el, text); }
  function getJSON(url) {
    return window.mvFetchJSON(url);
  }
  function post(url, body) {
    // The response itself: some answers are files (an export).
    return window.mvFetchJSON(url, {method: 'POST', body: body || {}, raw: true});
  }
  function saveBlob(blob, name) {
    var url = URL.createObjectURL(blob);
    var a = doc.createElement('a');
    a.href = url; a.download = name; doc.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  var status = $('cmp-status');

  // Auto-apply the regulation filter as soon as a choice is made.
  var framework = $('cmp-framework');
  if (framework && framework.form) {
    framework.addEventListener('change', function () { framework.form.submit(); });
  }

  // Protection switches.
  doc.addEventListener('click', function (ev) {
    var btn = ev.target && ev.target.closest ? ev.target.closest('[data-cmp-switch]') : null;
    if (!btn) return;
    var key = btn.getAttribute('data-cmp-switch');
    confirmAction(btn.getAttribute('data-cmp-confirm') || 'Turn this protection on?', 'Turn on').then(function (ok) {
      if (!ok) return;
      btn.disabled = true;
      post('/api/v1/compliance/switches/' + encodeURIComponent(key)).then(function (r) { return r.json(); }).then(function (body) {
        say(status, body.message || 'Saved.');
        if (body.active) setTimeout(function () { location.reload(); }, 800);
        else btn.disabled = false;
      }).catch(function (failure) {
        say(status, failure && failure.status === 409
          ? 'Set up sign-in for Lightwork first. Once this is on, everyone must sign in.'
          : errorText(failure, 'turn this protection on'));
        btn.disabled = false;
      });
    });
  });

  // Stop all running work.
  doc.addEventListener('click', function (ev) {
    var btn = ev.target && ev.target.closest ? ev.target.closest('[data-cmp-halt]') : null;
    if (!btn) return;
    confirmAction('Stop all running work now? Nothing new will start until someone resumes it from the Stop button at the top of the page.', 'Stop everything').then(function (ok) {
      if (!ok) return;
      post('/api/v1/halt', { reason: 'Stopped from the compliance page' }).then(function () {
        say(status, 'All work is stopped. Use the Stop button at the top of the page to resume.');
      }).catch(function (failure) { say(status, errorText(failure, 'stop the running work')); });
    });
  });

  // People: export and erase.
  var person = $('cmp-person');
  var peopleResult = $('cmp-people-result');
  function chosenPerson() {
    if (!person || !person.value) return null;
    var opt = person.options[person.selectedIndex];
    return { channel: opt.getAttribute('data-channel'), user: opt.getAttribute('data-user'), label: opt.textContent };
  }
  function loadPeople() {
    if (!person) return Promise.resolve();
    return getJSON('/api/v1/compliance/people').then(function (body) {
      person.textContent = '';
      var rows = body.people || [];
      var first = doc.createElement('option');
      first.value = '';
      first.textContent = rows.length ? 'Choose a person' : 'No one has talked with Lightwork yet';
      person.appendChild(first);
      rows.forEach(function (row, i) {
        var opt = doc.createElement('option');
        opt.value = String(i + 1);
        opt.setAttribute('data-channel', row.channel);
        opt.setAttribute('data-user', row.user);
        opt.setAttribute('data-name', row.person);
        opt.textContent = row.person + ' (' + row.channel_label + ', ' + row.conversations +
          (row.conversations === 1 ? ' conversation)' : ' conversations)');
        person.appendChild(opt);
      });
    }).catch(function (failure) {
      person.textContent = '';
      var opt = doc.createElement('option'); opt.value = ''; opt.textContent = 'People could not be loaded';
      person.appendChild(opt);
      say(peopleResult, errorText(failure, 'load the list of people'));
    });
  }
  var exportBtn = $('cmp-export');
  if (exportBtn) exportBtn.addEventListener('click', function () {
    var p = chosenPerson();
    if (!p) { say(peopleResult, 'Choose a person first.'); person.focus(); return; }
    exportBtn.disabled = true;
    post('/api/v1/compliance/people/export', { channel: p.channel, user: p.user }).then(function (r) {
      return r.blob();
    }).then(function (blob) {
      saveBlob(blob, 'lightwork-person-data.json');
      say(peopleResult, 'Their data has been downloaded. Send it to them securely.');
    }).catch(function (failure) {
      say(peopleResult, errorText(failure, 'export their data'));
    }).then(function () { exportBtn.disabled = false; });
  });
  var eraseBtn = $('cmp-erase');
  if (eraseBtn) eraseBtn.addEventListener('click', function () {
    var p = chosenPerson();
    if (!p) { say(peopleResult, 'Choose a person first.'); person.focus(); return; }
    confirmAction('Permanently erase everything Lightwork holds about ' + p.label +
      '? Their conversations, tasks and files are deleted and cannot be recovered. Download their data first if they asked for a copy.', 'Erase').then(function (ok) {
      if (!ok) return;
      eraseBtn.disabled = true;
      post('/api/v1/compliance/people/erase', { channel: p.channel, user: p.user }).then(function (r) {
        return r.json();
      }).then(function (body) {
        say(peopleResult, body.message || 'Erased.');
        return loadPeople();
      }).catch(function (failure) {
        say(peopleResult, errorText(failure, 'erase their data'));
      }).then(function () { eraseBtn.disabled = false; });
    });
  });

  // Reviewed retention is handled by lightwork-retention-maintenance.js.

  // Assessment downloads.
  var assessment = $('cmp-assessment');
  var assessmentResult = $('cmp-assessment-result');
  function loadAssessments() {
    if (!assessment) return Promise.resolve();
    return getJSON('/api/v1/compliance/assessments').then(function (body) {
      assessment.textContent = '';
      var rows = body.assessments || [];
      var first = doc.createElement('option'); first.value = '';
      first.textContent = rows.length ? 'Choose an assessment' : 'No assessments yet';
      assessment.appendChild(first);
      rows.forEach(function (row) {
        var opt = doc.createElement('option');
        opt.value = row.id;
        var when = window.mvWhen ? window.mvWhen(row.created_at) : '';
        var kind = window.mvHuman ? window.mvHuman(row.type) : row.type;
        opt.textContent = row.subject + (kind ? ' – ' + kind : '') + (when ? ' – ' + when : '');
        assessment.appendChild(opt);
      });
      if (!rows.length) say(assessmentResult, 'Start an assessment on the Assessments page, then come back to download it.');
    }).catch(function (failure) {
      assessment.textContent = '';
      var opt = doc.createElement('option'); opt.value = ''; opt.textContent = 'Assessments could not be loaded';
      assessment.appendChild(opt);
      say(assessmentResult, errorText(failure, 'load the assessments'));
    });
  }
  // Current-account protected file offers use lightwork-report-downloads.js.

  // EU AI Act self-check.
  var aiAct = $('cmp-ai-act');
  var aiActResult = $('cmp-ai-act-result');
  function list(title, items) {
    var wrap = doc.createElement('div');
    var h = doc.createElement('h3'); h.textContent = title; wrap.appendChild(h);
    var ul = doc.createElement('ul'); ul.className = 'cmp-list';
    items.forEach(function (text) { var li = doc.createElement('li'); li.textContent = text; ul.appendChild(li); });
    wrap.appendChild(ul);
    return wrap;
  }
  if (aiAct) aiAct.addEventListener('click', function () {
    getJSON('/api/v1/compliance/ai-act').then(function (body) {
      aiActResult.textContent = '';
      var p = doc.createElement('p');
      p.textContent = body.default_level + ' The AI notice is ' + (body.notice_on ? 'switched on.' : 'switched off. Turn it on above.');
      aiActResult.appendChild(p);
      aiActResult.appendChild(list('Make sure none of these banned uses apply', body.banned_uses || []));
      aiActResult.appendChild(list('Check whether you use AI for any of these high-risk purposes', body.high_risk_uses || []));
      aiActResult.appendChild(list('What each level requires', (body.duties || []).map(function (d) { return d.level + ': ' + d.text; })));
      if (body.note) { var n = doc.createElement('p'); n.className = 'muted'; n.textContent = body.note; aiActResult.appendChild(n); }
    }).catch(function (failure) { say(aiActResult, errorText(failure, 'run the self-check')); });
  });

  // Control finder.
  var finder = $('cmp-finder');
  var finderResult = $('cmp-finder-result');
  if (finder) finder.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var q = ($('cmp-finder-q').value || '').trim();
    if (!q) { say(finderResult, 'Describe the risk first.'); return; }
    getJSON('/api/v1/compliance/control-finder?q=' + encodeURIComponent(q)).then(function (body) {
      finderResult.textContent = '';
      var rows = body.controls || [];
      if (!rows.length) { say(finderResult, 'No matching controls. Try other words, such as "encryption" or "vendor".'); return; }
      var ul = doc.createElement('ul'); ul.className = 'cmp-list';
      rows.forEach(function (c) {
        var li = doc.createElement('li');
        var strong = doc.createElement('strong'); strong.textContent = c.title; li.appendChild(strong);
        var refs = (c.references || []).map(function (r) { return r.framework + ' ' + r.reference; }).join('; ');
        li.appendChild(doc.createTextNode(' (' + c.area + '). ' + refs));
        ul.appendChild(li);
      });
      finderResult.appendChild(ul);
    }).catch(function (failure) { say(finderResult, errorText(failure, 'search the controls')); });
  });

  loadPeople();
  loadAssessments();
})();
