// Value and proof read-outs for the Spend and Savings pages: where spend
// went, a suggested cap, why tasks failed, cheaper-over-time results,
// automatically approved actions (with Withdraw), outside agents, the record
// of decisions, signed downloads and a file check. Plain words only.
(function () {
  'use strict';
  var API = '/api/v1/value-proof';
  var spend = document.getElementById('vp-spend');
  var proof = document.getElementById('vp-proof');
  if (!spend && !proof) return;
  if (window.__lwValueProof) return;   // both pages include the script once each
  window.__lwValueProof = true;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function fill(id, node) { var box = $(id); if (!box) return; box.textContent = ''; if (node) box.appendChild(node); }
  // An empty card: the shared compact empty state when the page has it.
  function empty(id, title, body, action) {
    fill(id, window.mvEmpty ? window.mvEmpty(title, body, action, { compact: true }) : el('p', 'muted', title + '. ' + body));
  }
  function say(id, text) { window.mvStatus($(id), String(text || '')); }
  function money(n) {
    var v = Number(n) || 0;
    return window.mvMoney ? window.mvMoney(v) : '$' + v.toFixed(2);
  }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function errorText(failure, action) {
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, action) : 'Could not ' + action + '.';
  }
  function get(path) {
    return window.mvFetchJSON(API + path);
  }
  function post(path, body) {
    return window.mvFetchJSON(API + path, {method: 'POST', body: body || {}});
  }
  async function planError(failure, action) {
    var plain = failure && (failure.status === 409 || failure.status === 422) && window.mvPlainDetail ? window.mvPlainDetail(failure.detail) : '';
    if (plain) return plain;
    return errorText(failure, action);
  }
  function table(headers, rows) {
    var t = el('table');
    var head = el('thead'); var hr = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; hr.appendChild(th); });
    head.appendChild(hr); t.appendChild(head);
    var body = el('tbody');
    rows.forEach(function (cells) {
      var tr = el('tr');
      cells.forEach(function (c) {
        var td = el('td');
        if (c && c.nodeType) td.appendChild(c); else td.textContent = c;
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    t.appendChild(body);
    return t;
  }
  function failed(id, action) {
    return async function (failure) {
      if (failure && failure.status === 403) {
        fill(id, el('p', 'muted', 'Only administrators and auditors can ' + action + '.'));
        return;
      }
      fill(id, el('p', null, errorText(failure, action)));
    };
  }

  // ---- Spend page -------------------------------------------------------
  function loadRetro() {
    var top = $('vp-retro-top');
    return get('/cost-retro' + (top ? '?top=' + encodeURIComponent(top.value) : '')).then(function (d) {
      if (!d.tasks) {
        var start = spend && spend.getAttribute('data-can-start') === 'true';
        empty('vp-retro-summary', 'No task costs recorded yet',
          'Where spend went, and what to change, appears here as tasks finish.' + (start ? ' Start a task to see its cost.' : ''),
          start ? { label: 'Start a task', href: '/chat' } : null);
        return;
      }
      var line = money(d.total) + ' spent across ' + plural(d.tasks, 'task', 'tasks') + '.';
      if (d.failed_spend) line += ' ' + money(d.failed_spend) + ' (' + Math.round(d.failed_share * 100) + '%) went to tasks that failed.';
      say('vp-retro-summary', line);
      var advice = $('vp-retro-advice');
      advice.textContent = '';
      d.advice.forEach(function (a) { advice.appendChild(el('li', null, a)); });
      var rows = $('vp-retro-rows');
      rows.textContent = '';
      d.costliest.forEach(function (r) {
        var tr = el('tr');
        var td = el('td');
        var link = el('a', null, r.title || 'Task');
        link.href = '/chat/goal/' + encodeURIComponent(r.task);
        td.appendChild(link);
        tr.appendChild(td);
        tr.appendChild(el('td', null, money(r.cost)));
        tr.appendChild(el('td', null, r.failed ? 'Failed' : 'Finished'));
        rows.appendChild(tr);
      });
      $('vp-retro-table').hidden = !d.costliest.length;
    }).catch(async function (failure) {
      say('vp-retro-summary', failure && failure.status === 403
        ? 'Only administrators and auditors can see which tasks cost the most.'
        : errorText(failure, 'load where spend went'));
    });
  }
  function loadCap() {
    var fit = $('vp-cap-fit'), min = $('vp-cap-min');
    return get('/budget-tune' + (fit && min ? '?percentile=' + encodeURIComponent(fit.value) +
      '&min_samples=' + encodeURIComponent(min.value) : '')).then(function (d) {
      var share = { 75: 'three in four', 90: 'nine in ten', 95: '19 in 20' }[d.percentile || 90];
      if (!d.suggestions.length) {
        var lower = min && min.options.length && min.value !== min.options[0].value;
        empty('vp-cap', 'No suggestion yet', 'A suggested cap appears here after ' + d.minimum_tasks +
          ' finished tasks with costs.' + (lower ? ' Choose a smaller number under “Only suggest after” to see one sooner.' : ''));
        return;
      }
      fill('vp-cap', table(['For', 'Suggested cap', 'Based on'], d.suggestions.map(function (s) {
        return [s.for, money(s.cap), plural(s.tasks, 'task', 'tasks') + ' (' + share + ' cost up to ' + money(s.typical_high) + ')'];
      })));
    }).catch(failed('vp-cap', 'load the suggested cap'));
  }
  function loadFailures() {
    return get('/failures').then(function (d) {
      if (!d.total) {
        if (d.recording) empty('vp-fail', 'No failed tasks recorded', 'Good news. Reasons tasks fail appear here, most common first.');
        else empty('vp-fail', 'Failure reasons are not being recorded', 'Reasons tasks fail appear here once recording is on. Turn on failure recording on the Learning page.');
        return;
      }
      var top = Math.max.apply(null, d.reasons.map(function (r) { return r.count; }));
      fill('vp-fail', table(['Reason', 'Tasks', ''], d.reasons.map(function (r) {
        var bar = el('span', 'vp-bar');
        bar.style.width = Math.max(2, Math.round(r.count / top * 100)) + '%';
        bar.setAttribute('aria-hidden', 'true');
        return [r.reason, String(r.count), bar];
      })));
    }).catch(failed('vp-fail', 'load why tasks failed'));
  }

  // ---- Savings page -----------------------------------------------------
  var access = { admin: false, audit: false };
  function pct(n) { var v = Number(n) || 0; return (v > 0 ? '+' : '') + Math.round(v) + '%'; }
  function loadCompounding() {
    var win = $('vp-window');
    return get('/compounding' + (win ? '?window=' + encodeURIComponent(win.value) : '')).then(function (d) {
      if (!d.task_types.length) {
        fill('vp-comp', el('p', 'muted', 'Not enough repeated tasks yet. This appears once the same kind of task has run several times.'));
        return;
      }
      fill('vp-comp', table(['Kind of task', 'Tasks', 'Cost change', 'Success change', 'Verdict'], d.task_types.map(function (t) {
        return [t.name, String(t.runs), pct(t.cost_change_pct), pct(t.success_change * 100),
          t.improving ? 'Getting cheaper and no less reliable' : 'Not improving yet'];
      })));
    }).catch(failed('vp-comp', 'load the results'));
  }
  function loadDepartments() {
    var win = $('vp-window');
    return get('/departments' + (win ? '?window=' + encodeURIComponent(win.value) : '')).then(function (d) {
      if (!d.departments.length) {
        fill('vp-dept', el('p', 'muted', 'No department has enough tasks yet to show a trend. It appears once a department has run several tasks.'));
        return;
      }
      fill('vp-dept', table(['Department', 'Tasks', 'Cost per task then', 'Cost per task now', 'Verdict'], d.departments.map(function (x) {
        return [x.name, String(x.runs), money(x.cost_before), money(x.cost_now), x.improving ? 'Getting cheaper' : 'Not yet'];
      })));
    }).catch(failed('vp-dept', 'load the department results'));
  }
  function loadEarned() {
    return get('/earned-autonomy').then(function (d) {
      var rule = 'Evidence is assessed after ' + d.needs.outcomes + ' real outcomes, ' +
        d.needs.streak + ' correct predictions in a row and ' + d.needs.accuracy_pct + '% accuracy. This evidence does not grant approval.';
      var state = !d.enabled ? 'Evidence collection is off. ' + rule : rule;
      say('vp-ea-state', state);
      if (!d.actions.length) {
        fill('vp-ea', el('p', 'muted', 'No evidence yet. It builds up as checked actions run and their real outcomes come back.'));
        return;
      }
      fill('vp-ea', table(['Action', 'Now', 'Why'].concat(access.admin ? ['Actions'] : []), d.actions.map(function (a) {
        var row = [a.name, a.auto_approved ? 'Approved automatically' : 'No approval granted by evidence',
          a.confirmed + ' of ' + (a.confirmed + a.missed) + ' predictions matched what really happened; ' +
          a.streak + ' correct in a row'];
        if (access.admin) {
          if (a.evidence_qualified) {
            var b = el('button', 'btn btn--danger', 'Clear qualification');
            b.type = 'button';
            b.setAttribute('aria-label', 'Clear prediction qualification for ' + a.name);
            b.addEventListener('click', function () { withdraw(a, b); });
            row.push(b);
          } else row.push('—');
        }
        return row;
      })));
    }).catch(async function (failure) { say('vp-ea-state', errorText(failure, 'load automatic approvals')); });
  }
  async function withdraw(a, b) {
    if (!(await window.mvConfirm('Clear prediction qualification for "' + a.name + '"? Explicit consent grants will not change.',
      { okText: 'Clear' }))) return;
    b.disabled = true;
    try {
      await post('/earned-autonomy/revoke', { action: a.action });
      say('vp-proof-msg', 'Prediction qualification cleared for ' + a.name + '.');
      await loadEarned();
    } catch (failure) {
      say('vp-proof-msg', await planError(failure, 'clear prediction qualification'));
      b.disabled = false;
    }
  }
  function loadFleet() {
    return get('/fleet-memory').then(function (d) {
      if (!d.enabled) {
        fill('vp-fleet', el('p', 'muted', 'Shared memory for outside agents is turned off.'));
        return;
      }
      if (!d.agents.length) {
        var p = el('p', 'muted', 'No outside agents are registered yet. ');
        var link = el('a', null, 'Connect an outside agent'); link.href = '/external-agents';
        p.appendChild(link);
        fill('vp-fleet', p);
        return;
      }
      fill('vp-fleet', table(['Agent', 'Made by', 'Shared successes', 'Shared failures'], d.agents.map(function (a) {
        return [a.description || a.agent, a.vendor, String(a.worked), String(a.failed)];
      })));
    }).catch(failed('vp-fleet', 'load the outside agents'));
  }
  // Add an outside agent to the shared-memory list (fleet-memory --register).
  var fleetForm = $('vp-fleet-add');
  if (fleetForm) fleetForm.addEventListener('submit', async function (event) {
    event.preventDefault();
    var name = $('vp-fleet-name').value.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) {
      say('vp-fleet-msg', 'Use letters, numbers, dots and dashes for the agent name.');
      return;
    }
    var submit = fleetForm.querySelector('button[type=submit]');
    submit.disabled = true;
    try {
      await window.mvFetchJSON('/api/v1/workforce-ops/outside-agents', { method: 'POST', body: { vendor: $('vp-fleet-vendor').value, name: name, description: $('vp-fleet-about').value.trim() } });
      say('vp-fleet-msg', 'Added ' + name + '. It can now share what it learns.');
      fleetForm.reset();
      await loadFleet();
    } catch (failure) {
      say('vp-fleet-msg', await planError(failure, 'add the agent'));
    } finally {
      submit.disabled = false;
    }
  });
  function loadRecord() {
    return get('/record-stats').then(function (d) {
      var text = plural(d.records, 'decision', 'decisions') + ' on record: ' + plural(d.tasks, 'task', 'tasks') + ' and ' +
        plural(d.approvals, 'approval', 'approvals') + ' (' + d.human_decisions + ' decided by a person).';
      if (d.departments.length) {
        text += ' Busiest: ' + d.departments.slice(0, 3).map(function (x) { return x.name + ' (' + x.count + ')'; }).join(', ') + '.';
      }
      say('vp-rec', text);
    }).catch(async function (failure) { say('vp-rec', errorText(failure, 'load the record')); });
  }
  function download(link, action) {
    link.addEventListener('click', async function (event) {
      event.preventDefault();
      say('vp-proof-msg', 'Preparing the download…');
      try {
        var r = await window.mvFetchJSON(link.getAttribute('href'), { raw: true });
        var blob = await r.blob();
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = link.id === 'vp-rec-download' ? 'lightwork-operating-record.json' : 'lightwork-learning-statement.json';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
        say('vp-proof-msg', 'Download ready.');
      } catch (failure) {
        say('vp-proof-msg', await planError(failure, action));
      }
    });
  }
  var check = $('vp-check');
  if (check) {
    check.addEventListener('submit', async function (event) {
      event.preventDefault();
      var box = $('vp-check-result');
      box.textContent = '';
      var input = $('vp-check-file');
      var file = input.files && input.files[0];
      if (!file) { box.textContent = 'Choose a file first.'; return; }
      if (file.size > 10000000) { box.textContent = 'That file is too large to check here.'; return; }
      var kind = $('vp-check-kind').value;
      box.textContent = 'Checking…';
      try {
        var text = await file.text();
        var body = { document: text };
        var keyInput = $('vp-check-key');
        var keyFile = kind === 'memory' && keyInput && keyInput.files && keyInput.files[0];
        if (keyFile) {
          if (keyFile.size > 2000) { box.textContent = 'That key file is too large. Ask the other installation for its key file.'; return; }
          body.publisher_key = await keyFile.text();
        }
        var out = await post(kind === 'memory' ? '/memory-verify' : '/record-verify', body);
        box.textContent = '';
        if (kind === 'record') {
          box.appendChild(el('p', null, !out.intact
            ? 'This file could not be confirmed. It may have been changed, or it is not a signed Lightwork record. Ask for the original file.'
            : (out.from_this_installation
              ? 'This record is intact and was signed by this Lightwork installation. It holds ' + plural(out.records, 'decision', 'decisions') + '.'
              : 'The signature is valid for the key in this file, but who signed it has not been verified. Obtain the publisher’s key through a trusted channel before relying on its origin.')));
        } else {
          box.appendChild(el('p', null, out.intact
            ? (out.from_this_installation === false
              ? 'This learning statement is intact and was signed by the installation whose key you gave.'
              : 'This learning statement is intact and was signed by this Lightwork installation.')
            : (keyFile
              ? 'This learning statement could not be confirmed with that key. It may have been changed or signed by someone else. Check that you chose the right key.'
              : 'This learning statement could not be confirmed against this installation. It may have been changed or signed elsewhere. Ask for the original file.')));
          if (out.claims.length) {
            var ul = el('ul');
            out.claims.forEach(function (c) { ul.appendChild(el('li', null, c.claim + ': ' + c.result)); });
            box.appendChild(ul);
          }
        }
      } catch (failure) {
        box.textContent = await planError(failure, 'check the file');
      }
    });
  }

  if (spend) {
    loadRetro(); loadCap(); loadFailures();
    ['vp-retro-top'].forEach(function (id) { var n = $(id); if (n) n.addEventListener('change', loadRetro); });
    ['vp-cap-fit', 'vp-cap-min'].forEach(function (id) { var n = $(id); if (n) n.addEventListener('change', loadCap); });
  }
  if (proof) {
    get('/access').catch(function () { return access; }).then(function (a) {
      access = a || access;
      document.querySelectorAll('#vp-proof .vp-admin').forEach(function (n) { n.hidden = !access.admin; });
      loadEarned();
    });
    loadCompounding(); loadDepartments(); loadFleet(); loadRecord();
    var win = $('vp-window');
    if (win) win.addEventListener('change', function () { loadCompounding(); loadDepartments(); });
    var rec = $('vp-rec-download'); if (rec) download(rec, 'download the record');
    var mem = $('vp-mem-download'); if (mem) download(mem, 'download the learning statement');
  }
})();
