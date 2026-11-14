// Learned page: suggested instruction changes (list, suggest, apply, undo)
// and self-coaching read-outs (lesson results, clashes, what comes next,
// learning activity, hold-out check, run now). Plain words only; reference
// numbers stay inside collapsed "Technical details".
(function () {
  'use strict';
  var root = document.getElementById('llp-root');
  if (!root) return;
  var API = '/api/v1/learning-loop';
  var admin = root.getAttribute('data-admin') === '1';
  var instructionContext = '', instructionPending = null, instructionBusy = false, instructionLocked = false, instructionHistory = [], suggestionBusy = false;
  function $(id) { return document.getElementById(id); }
  function say(id, text) { window.mvStatus($(id), String(text || '')); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function when(ts) { return (typeof window.mvWhen === 'function' ? window.mvWhen(ts) : '') || ''; }
  function pct(rate) { return rate == null ? 'Not used yet' : Math.round(rate * 100) + '%'; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  // A failed request as one plain sentence. Our own refusals (409) carry a
  // sentence written for people; everything else uses the shared wording.
  async function problem(failure, action) {
    var plain = failure && failure.status === 409 && window.mvPlainDetail ? window.mvPlainDetail(failure.detail) : '';
    if (plain) return plain;
    if (failure && failure.status === 403 && action.indexOf('see') === 0) {
      return 'Only administrators and auditors can ' + action + '.';
    }
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, action) : 'Could not ' + action + '.';
  }
  function get(path) {
    return window.mvFetchJSON(API + path, { timeout: 15000, onAccess: lockInstructions });
  }
  function post(path, body) {
    return window.mvFetchJSON(API + path, {method: 'POST', body: body || {}, timeout: 15000, onAccess: lockInstructions});
  }
  function technical(pairs) {
    var box = el('details');
    box.appendChild(el('summary', null, 'Technical details'));
    var list = el('ul');
    pairs.forEach(function (p) { if (p[1] != null && p[1] !== '') list.appendChild(el('li', null, p[0] + ': ' + p[1])); });
    box.appendChild(list);
    return box;
  }

  // ---- suggested instruction changes ----------------------------------
  function lockInstructions() {
    instructionLocked = true; instructionPending = null; instructionBusy = false;
    instructionHistory = [];
    ['llp-ref-rows', 'llp-in-force', 'llp-original-message', 'llp-original-review', 'llp-original-choice'].forEach(function (id) { if ($(id)) $(id).textContent = ''; });
    var form = $('llp-propose');
    if (form) { form.reset(); Array.from(form.elements).forEach(function (field) { field.disabled = true; }); }
    if ($('llp-original')) $('llp-original').hidden = true;
    say('llp-ref-msg', 'Your account, workspace or access changed. Reload before reviewing instructions.');
  }
  function pendingKey() { return 'lightwork-instruction-decision:' + instructionContext; }
  function restorePending() {
    try {
      var value = JSON.parse(sessionStorage.getItem(pendingKey()) || 'null');
      if (value && value.context === instructionContext && /^[a-f0-9]{16}$/.test(value.proposal) &&
          /^[a-f0-9]{32}$/.test(value.operation_id) && /^[a-f0-9]{64}$/.test(value.revision) && typeof value.undo === 'boolean') instructionPending = value;
    } catch (_) { /* Never dispatch an unreadable original request. */ }
    showPending();
  }
  function showPending(message) {
    var box = $('llp-original');
    if (!box) return;
    box.hidden = (!instructionPending && !instructionHistory.length) || instructionLocked;
    if (!box.hidden) $('llp-original-message').textContent = message ||
      (instructionPending ? 'An original instruction decision needs checking. Check its saved result before applying or restoring again.' :
        'Choose a recent original decision to read its saved result. No instruction change is repeated.');
  }
  function clearPending() {
    try { sessionStorage.removeItem(pendingKey()); } catch (_) { /* The native result remains readable. */ }
    instructionPending = null;
  }
  function showReceipt(receipt) {
    say('llp-ref-msg', receipt.message + (receipt.recorded_at ? ' Recorded ' + when(receipt.recorded_at) + '.' : ''));
    if ($('llp-original-resolve')) $('llp-original-resolve').hidden = receipt.status !== 'unconfirmed' || receipt.hold_closed;
    if (receipt.status === 'confirmed' || receipt.status === 'aborted' || receipt.hold_closed) {
      clearPending(); showPending();
    } else showPending(receipt.message);
  }
  async function checkOriginal(b) {
    if (!instructionPending || instructionLocked || instructionBusy) return;
    var original = instructionPending, bound = instructionContext;
    instructionBusy = true; if (b) b.disabled = true;
    try {
      var result = original.successor ? await post('/instruction-holds/' + original.operation_id + '/receipt', {
        context: original.context, recovery_id: original.recovery_id || null
      }) : await post('/refinements/' + original.proposal + '/receipt', {
        revision: original.revision, operation_id: original.operation_id, context: original.context, undo: original.undo
      });
      if (instructionLocked || bound !== instructionContext || instructionPending !== original) return;
      if (result.receipt) showReceipt(result.receipt); else showPending(result.message);
      instructionBusy = false; await loadRefinements();
    } catch (failure) {
      if (failure.status === 401 || failure.status === 403) lockInstructions();
      else if (!instructionLocked) showPending(await problem(failure, 'check the original decision') + ' No change was repeated.');
    } finally { instructionBusy = false; if (b) b.disabled = false; }
  }
  if ($('llp-original-check')) $('llp-original-check').addEventListener('click', function () { checkOriginal(this); });
  if ($('llp-original-choice')) $('llp-original-choice').addEventListener('change', function () {
    if (instructionBusy || instructionLocked || instructionPending) return;
    var chosen = this.value === '' ? null : instructionHistory[Number(this.value)];
    if (!chosen) return;
    instructionPending = Object.assign({}, chosen); showPending();
  });
  function randomRequest() {
    var random = new Uint8Array(16); window.crypto.getRandomValues(random);
    return Array.from(random, function (v) { return v.toString(16).padStart(2, '0'); }).join('');
  }
  if ($('llp-original-resolve')) $('llp-original-resolve').addEventListener('click', async function () {
    if (!instructionPending || instructionBusy || instructionLocked) return;
    var original = instructionPending, b = this;
    instructionBusy = true; b.disabled = true;
    try {
      var input = { revision: original.revision, operation_id: original.operation_id, context: original.context, undo: original.undo };
      var review = original.successor ? await post('/instruction-holds/' + original.operation_id + '/review', {context: original.context}) :
        await post('/refinements/' + original.proposal + '/reconciliation-review', input);
      if (instructionLocked || instructionPending !== original) return;
      var box = $('llp-original-review'); box.textContent = '';
      box.appendChild(el('p', null, review.message));
      if (!review.instructions.length) box.appendChild(el('p', null, 'No instruction changes are currently in use.'));
      review.instructions.forEach(function (row) { box.appendChild(el('h4', null, row.title)); box.appendChild(el('p', null, row.text)); });
      if (!(await window.mvConfirm('Keep the complete current instructions shown above and close this hold? This is a new decision. The original result remains unconfirmed, and the original action is not repeated.',
        { okText: 'Keep reviewed instructions' })) || instructionLocked || instructionPending !== original) return;
      original.recovery_id = randomRequest(); sessionStorage.setItem(pendingKey(), JSON.stringify(original));
      var acceptance = {
        recovery_id: original.recovery_id, reconciliation_revision: review.revision, source_revision: review.source_revision,
        review_expires_at: review.review_expires_at, confirm: true, context: original.context
      };
      var result = original.successor ? await post('/instruction-holds/' + original.operation_id + '/accept', acceptance) :
        await post('/refinements/' + original.proposal + '/reconcile', Object.assign({}, input, acceptance));
      if (!instructionLocked && instructionPending === original && result.receipt) { showReceipt(result.receipt); box.textContent = ''; }
    } catch (failure) {
      if (!instructionLocked) showPending(await problem(failure, 'accept the reviewed current instructions') + ' Check the original result before another decision; nothing is automatically repeated.');
    } finally { instructionBusy = false; b.disabled = false; if (!instructionLocked) await loadRefinements(); }
  });
  window.addEventListener('lightwork:context-changed', lockInstructions);
  document.addEventListener('lightwork:copilot-context-changed', function (event) {
    if (!event.detail || event.detail.reason !== 'selection') lockInstructions();
  });
  function statusText(p) {
    if (p.status === 'applied') return 'In use since ' + (when(p.applied_at) || 'it was applied');
    if (p.status === 'reverted') return 'Undone ' + (when(p.reverted_at) || '');
    if (p.status === 'pending') return p.approval || 'Waiting to be applied';
    if (p.status === 'reconciled_absent') return 'Not in use after review';
    return typeof window.mvHuman === 'function' ? window.mvHuman(p.status) : p.status;
  }
  function refineRow(p) {
    var tr = el('tr');
    var what = el('td');
    what.appendChild(el('strong', null, p.title));
    what.appendChild(el('div', 'muted', p.target));
    what.appendChild(el('div', null, p.change));
    if (p.rationale) what.appendChild(el('div', 'muted', 'Why: ' + p.rationale));
    what.appendChild(technical([['Reference', p.technical && p.technical.reference],
      ['Approval number', p.technical && p.technical.approval_number],
      ['Fingerprint', p.technical && p.technical.fingerprint]]));
    tr.appendChild(what);
    tr.appendChild(el('td', null, p.failure));
    var st = el('td', null, statusText(p));
    if (p.proposed_at) st.appendChild(el('div', 'muted', 'Suggested ' + when(p.proposed_at)));
    tr.appendChild(st);
    if (admin) {
      var act = el('td');
      if (p.can_apply) act.appendChild(button('Apply', 'btn btn--primary', function (b) { applyChange(p, b); }));
      if (p.can_revert) act.appendChild(button('Undo', 'btn btn--danger', function (b) { undoChange(p, b); }));
      act.querySelectorAll('button').forEach(function (b) { b.disabled = instructionBusy || !!instructionPending || instructionLocked; });
      if (!p.can_apply && !p.can_revert) {
        if (p.status === 'pending') {
          var link = el('a', 'btn btn--ghost', 'Decide it under Approvals');
          link.href = '/approvals';
          act.appendChild(link);
        } else act.textContent = '—';
      }
      tr.appendChild(act);
    }
    Array.from(tr.cells).forEach(function (cell, index) { cell.setAttribute('data-label', ['Suggested change', 'What went wrong', 'Status', 'Actions'][index]); });
    return tr;
  }
  function button(label, cls, onClick) {
    var b = el('button', cls, label);
    b.type = 'button';
    b.addEventListener('click', function () { onClick(b); });
    return b;
  }
  function loadRefinements() {
    return get('/refinements').then(function (data) {
      if (instructionLocked) return;
      if (instructionContext && instructionContext !== data.context) { lockInstructions(); return; }
      if (!instructionContext) { instructionContext = data.context; restorePending(); }
      if (admin && !data.can_manage) { lockInstructions(); return; }
      instructionHistory = data.decisions || [];
      if (!instructionPending) {
        var unfinished = instructionHistory.find(function (row) { return row.unfinished; });
        if (unfinished) instructionPending = Object.assign({}, unfinished);
        else if (data.holds && data.holds.length) instructionPending = {
          proposal: '0'.repeat(16), revision: '0'.repeat(64), undo: false, successor: true,
          context: instructionContext, operation_id: data.holds[0].operation_id
        };
      }
      var originalChoices = $('llp-original-choice');
      if (originalChoices) {
        originalChoices.textContent = ''; var placeholder = el('option', null, 'Choose an original decision'); placeholder.value = ''; originalChoices.appendChild(placeholder);
        instructionHistory.forEach(function (row, index) {
          var choice = el('option', null, (row.undo ? 'Restore · ' : 'Apply · ') + row.title + ' · ' + when(row.started_at));
          choice.value = String(index); originalChoices.appendChild(choice);
        });
        originalChoices.disabled = instructionBusy || !!instructionPending;
      }
      showPending();
      if ($('llp-original-title')) $('llp-original-title').textContent = instructionPending && instructionPending.successor ? 'Review the hold on shared instructions' : 'Check your original decision';
      if ($('llp-original-check')) $('llp-original-check').textContent = instructionPending && instructionPending.successor ? 'Check this hold or my acceptance' : 'Check original result';
      if (instructionPending && instructionPending.successor) showPending('Shared instructions need review after an earlier unconfirmed action. Your own full review can close the hold without accessing, confirming or repeating the former person’s original decision.');
      var rows = $('llp-ref-rows');
      rows.textContent = '';
      var state = data.enabled
        ? (data.require_approval ? 'Suggestions are on. Each change needs an approval before it can be applied.'
          : 'Suggestions are on. Changes can be applied without a separate approval.')
        : 'Suggestions are turned off, so no new changes can be suggested. Changes already in use stay in use and can still be undone.' +
          (data.switch_place ? ' To turn them on, go to ' + data.switch_place + '.' : '');
      say('llp-ref-state', state);
      if (!data.enabled) {
        var on = el('a', 'btn btn--ghost', 'Open All settings');
        on.href = '/settings/all';
        $('llp-ref-state').appendChild(document.createTextNode(' '));
        $('llp-ref-state').appendChild(on);
      }
      if (!data.proposals.length) {
        var tr = el('tr');
        var td = el('td', null, admin && data.enabled
          ? 'No changes have been suggested yet. Use "Suggest a change" below when an agent keeps making the same mistake.'
          : 'No changes have been suggested yet. Suggestions appear here when an administrator makes one.');
        td.colSpan = admin ? 4 : 3;
        tr.appendChild(td);
        rows.appendChild(tr);
      } else {
        data.proposals.forEach(function (p) { rows.appendChild(refineRow(p)); });
      }
      var list = $('llp-in-force');
      list.textContent = '';
      if (!data.in_force.length) list.appendChild(el('li', 'muted', 'No suggested changes are in use.'));
      data.in_force.forEach(function (r) {
        var li = el('li');
        li.appendChild(el('strong', null, r.title + ' (' + r.target + ')'));
        li.appendChild(el('div', null, r.change));
        li.appendChild(el('div', 'muted', 'Applied ' + when(r.applied_at)));
        list.appendChild(li);
      });
      var box = $('llp-propose-box');
      if (box) box.hidden = !data.enabled;
      return data;
    }).catch(async function (failure) {
      if (instructionLocked) return;
      var rows = $('llp-ref-rows');
      rows.textContent = '';
      var tr = el('tr');
      var td = el('td', null, await problem(failure, 'load the suggested changes'));
      td.colSpan = admin ? 4 : 3;
      tr.appendChild(td);
      rows.appendChild(tr);
    });
  }
  // Before/after for a change: what the instructions say now and what they
  // will say, or which later changes an undo also removes.
  async function preview(p) {
    try {
      if (!instructionContext || instructionLocked || instructionPending) return null;
      return await get('/refinements/' + encodeURIComponent(p.id) + '/review?context=' + encodeURIComponent(instructionContext));
    } catch (failure) {
      say('llp-ref-msg', await problem(failure, 'show what would change'));
      return null;
    }
  }
  function previewBox(lines) {
    var box = el('div', 'llp-preview');
    box.setAttribute('role', 'status');
    lines.forEach(function (l) { box.appendChild(el('p', null, l[1] ? l[0] + ' ' + l[1] : l[0])); });
    return box;
  }
  function showPreview(b, box) {
    var cell = b.parentNode;
    var old = cell.querySelector('.llp-preview');
    if (old) old.remove();
    cell.appendChild(box);
  }
  async function decideInstruction(p, b, undo) {
    if (instructionBusy || instructionPending || instructionLocked) return;
    instructionBusy = true;
    b.disabled = true;
    var pv = await preview(p);
    if (!pv || instructionLocked || pv.context !== instructionContext) { instructionBusy = false; b.disabled = instructionLocked; return; }
    var lines = [];
    (pv.changes || []).forEach(function (change) {
      lines.push([change.title + ' · Current instructions:', change.before || '(nothing for this)']);
      lines.push([undo ? 'After restoring:' : 'After applying:', change.after || '(removed)']);
    });
    showPreview(b, previewBox(lines));
    var question = undo ? 'Undo "' + p.title + '"? Review every change above; earlier instructions may return and later changes may be removed.' :
      'Apply "' + p.title + '"? Review the full change above. Agents follow the approved instructions on new tasks, and a restore point is saved first.';
    if (!(await window.mvConfirm(question, { okText: undo ? 'Restore reviewed instructions' : 'Apply change' })) || instructionLocked) {
      instructionBusy = false; b.disabled = instructionLocked; return;
    }
    try {
      instructionPending = { proposal: p.id, revision: pv.revision, context: pv.context, undo: undo,
        operation_id: randomRequest() };
      sessionStorage.setItem(pendingKey(), JSON.stringify(instructionPending));
    } catch (_) {
      instructionPending = null; instructionBusy = false; b.disabled = false;
      say('llp-ref-msg', 'This browser could not keep the original request safely. Nothing was submitted. Enable private session storage and try again.'); return;
    }
    var original = instructionPending;
    showPending('Your reviewed decision is being saved. Its original request is kept for result checking.');
    say('llp-ref-msg', undo ? 'Restoring reviewed instructions…' : 'Applying reviewed instructions…');
    try {
      var result = await post('/refinements/' + encodeURIComponent(p.id) + (undo ? '/revert' : '/apply'), {
        revision: pv.revision, confirm: true, context: pv.context, source_revision: pv.source_revision,
        operation_id: original.operation_id, review_expires_at: pv.review_expires_at
      });
      if (instructionLocked || instructionPending !== original) return;
      if (result.receipt) showReceipt(result.receipt); else showPending();
    } catch (failure) {
      if (!instructionLocked && instructionPending === original) {
        if (failure.status === 409 || failure.status === 422) {
          clearPending(); showPending(); say('llp-ref-msg', await problem(failure, 'save this decision'));
        } else showPending('The reply was interrupted. Check the original result; do not submit the decision again.');
      }
    } finally { instructionBusy = false; if (!instructionLocked) await loadRefinements(); }
  }
  function applyChange(p, b) { return decideInstruction(p, b, false); }
  function undoChange(p, b) { return decideInstruction(p, b, true); }
  var form = $('llp-propose');
  function suggestionStamp() {
    return form ? JSON.stringify(['target', 'title', 'failure', 'change', 'rationale'].map(function (key) {
      return form.elements.namedItem(key).value;
    })) : '';
  }
  window.LightworkLearningInstructions = {
    openSuggestion: async function (context, isCurrent) {
      if (!form || !admin || instructionLocked || instructionBusy || suggestionBusy ||
          !/^[a-f0-9]{64}$/.test(context) || (typeof isCurrent === 'function' && !isCurrent())) return false;
      var entered = suggestionStamp(), current = await loadRefinements();
      if (!current || instructionLocked || !current.can_manage || !current.enabled ||
          current.context !== context || instructionContext !== context ||
          (typeof isCurrent === 'function' && !isCurrent())) return false;
      if (suggestionStamp() !== entered) {
        say('llp-ref-msg', 'Your suggestion changed while access was checked. It was kept; open the form again when ready.');
        return false;
      }
      $('llp-propose-box').open = true;
      $('llp-title').focus();
      return true;
    }
  };
  if (form) {
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (instructionLocked || instructionBusy || suggestionBusy || instructionPending) { showPending(); return; }
      if (!instructionContext) { say('llp-ref-msg', 'Wait for current suggestions to load before sending. Your entered text is kept.'); return; }
      var f = new FormData(form);
      var body = {};
      ['target', 'title', 'failure', 'change', 'rationale'].forEach(function (k) { body[k] = String(f.get(k) || '').trim(); });
      if (!body.title || !body.failure || !body.change || !body.rationale) {
        say('llp-ref-msg', 'Fill in every box before suggesting the change.');
        return;
      }
      var submit = form.querySelector('button[type=submit]');
      var submitted = suggestionStamp(), bound = instructionContext;
      suggestionBusy = true;
      instructionBusy = true;
      if (submit) submit.disabled = true;
      say('llp-ref-msg', 'Sending your suggestion…');
      try {
        var out = await post('/refinements', body);
        if (instructionLocked || bound !== instructionContext) return;
        var unchanged = suggestionStamp() === submitted;
        var savedMessage = out.needs_approval
          ? 'Suggestion saved. It now waits for approval on the Approvals page; then apply it here.'
          : 'Suggestion saved. You can apply it from the list.';
        say('llp-ref-msg', savedMessage + (unchanged ? '' : ' Your newer suggestion is kept in the form and has not been sent.'));
        if (unchanged) form.reset();
        instructionBusy = false;
        await loadRefinements();
      } catch (failure) {
        if (!instructionLocked) say('llp-ref-msg', await problem(failure, 'save the suggestion'));
      } finally {
        suggestionBusy = false;
        instructionBusy = false;
        if (submit) submit.disabled = instructionLocked;
      }
    });
  }

  // ---- self-coaching read-outs ------------------------------------------
  var picker = $('llp-model');
  var ownsModelSelection = true, publishingModelSelection = false;
  function model() { return picker && picker.value ? picker.value : ''; }
  function publishModel() {
    if (!ownsModelSelection) return;
    publishingModelSelection = true;
    try {
      document.dispatchEvent(new CustomEvent('lightwork:copilot-selection',
        { detail: { selection: model() ? { kind: 'learning_model', id: model() } : {} } }));
    } finally { publishingModelSelection = false; }
  }
  document.addEventListener('lightwork:copilot-selection', function (event) {
    if (!publishingModelSelection) ownsModelSelection = event.detail?.selection?.kind === 'learning_model';
  });
  async function withdrawLesson(row, reason, buttonEl) {
    var chosenModel = model();
    var why = reason.value.trim();
    if (why.length < 10) { say('llp-harness-msg', 'Explain why this lesson should be removed in at least 10 characters.'); return; }
    if (!(await window.mvConfirm('Remove this exact lesson for ' + row.scope_label + '? New work will no longer use it. Past work remains recorded.',
      { okText: 'Remove lesson' }))) return;
    buttonEl.disabled = true;
    say('llp-harness-msg', 'Removing the lesson…');
    try {
      await post('/lessons/withdraw', { model_id: chosenModel, token: row.token, reason: why, confirm: true });
      say('llp-harness-msg', 'Lesson removed. New work will no longer use it.');
    } catch (failure) {
      say('llp-harness-msg', await problem(failure, 'remove the lesson') + ' Refresh the results to check its current state.');
    } finally {
      await Promise.all([loadModels(), loadLog()]);
      buttonEl.disabled = false;
    }
  }
  function lessonAction(row) {
    var cell = el('td');
    var details = el('details');
    details.appendChild(el('summary', null, 'Remove lesson'));
    var label = el('label', null, 'Why remove this lesson?');
    var reason = el('textarea', 'textarea');
    reason.rows = 2;
    reason.maxLength = 1000;
    reason.required = true;
    label.appendChild(reason);
    details.appendChild(label);
    details.appendChild(el('p', 'muted', 'Only this lesson in this part of the work will be removed. Past work stays in the activity record.'));
    details.appendChild(button('Confirm removal', 'btn btn--danger', function (b) { withdrawLesson(row, reason, b); }));
    cell.appendChild(details);
    return cell;
  }
  function loadEfficacy() {
    var rows = $('llp-eff-rows');
    if (!model()) return Promise.resolve();
    return get('/efficacy?model_id=' + encodeURIComponent(model())).then(function (data) {
      rows.textContent = '';
      if (!data.lessons.length) {
        var tr = el('tr'); var td = el('td', null, 'This model has no currently available shared lessons.'); td.colSpan = admin ? 5 : 4;
        tr.appendChild(td); rows.appendChild(tr); return;
      }
      data.lessons.forEach(function (r) {
        var tr = el('tr');
        var lesson = el('td', null, r.text);
        lesson.appendChild(el('div', 'muted', r.scope_label));
        tr.appendChild(lesson);
        tr.appendChild(el('td', null, String(r.went_well)));
        tr.appendChild(el('td', null, String(r.did_not)));
        var rate = el('td', null, pct(r.rate));
        if (r.recent_rate != null) rate.appendChild(el('div', 'muted', 'Lately ' + pct(r.recent_rate)));
        tr.appendChild(rate);
        if (admin) tr.appendChild(lessonAction(r));
        rows.appendChild(tr);
      });
    }).catch(async function (failure) {
      rows.textContent = '';
      var tr = el('tr'); var td = el('td', null, await problem(failure, 'load the lesson results')); td.colSpan = admin ? 5 : 4;
      tr.appendChild(td); rows.appendChild(tr);
    });
  }
  function loadConflicts() {
    var list = $('llp-conf');
    if (!model()) return Promise.resolve();
    return get('/conflicts?model_id=' + encodeURIComponent(model())).then(function (data) {
      list.textContent = '';
      if (!data.pairs.length) { list.appendChild(el('li', 'muted', 'The wording check flagged no possible conflicts in currently shareable lessons. This does not establish that the guidance is correct.')); return; }
      data.pairs.forEach(function (p) {
        list.appendChild(el('li', null, '“' + p.first + '” may contradict “' + p.second + '”. Remove whichever is wrong from the lessons above.'));
      });
    }).catch(async function (failure) {
      list.textContent = '';
      list.appendChild(el('li', null, await problem(failure, 'check for clashing lessons')));
    });
  }
  function loadLog() {
    var list = $('llp-log');
    return get('/log?limit=30').then(function (data) {
      list.textContent = '';
      if (!data.events.length) { list.appendChild(el('li', 'muted', 'Nothing has been learned or removed yet. Each change appears here when it is adopted or removed.')); return; }
      data.events.forEach(function (e) {
        var li = el('li');
        li.appendChild(el('strong', null, (when(e.when) || 'Recently') + ': ' + e.what));
        if (e.lesson) li.appendChild(el('div', null, '“' + e.lesson + '”'));
        list.appendChild(li);
      });
    }).catch(async function (failure) {
      list.textContent = '';
      list.appendChild(el('li', 'muted', await problem(failure, 'see the learning activity')));
    });
  }
  function modelChanged() { publishModel(); return Promise.all([loadEfficacy(), loadConflicts()]); }
  function loadModels() {
    return get('/models').then(function (data) {
      var previous = model();
      picker.textContent = '';
      if (!data.models.length) {
        var empty = el('option', null, 'No models yet'); empty.value = '';
        picker.appendChild(empty);
        picker.disabled = true;
        $('llp-eff-rows').textContent = '';
        var row = el('tr'); var cell = el('td', null, 'No currently available shared lessons.'); cell.colSpan = admin ? 5 : 4;
        row.appendChild(cell); $('llp-eff-rows').appendChild(row);
        $('llp-conf').textContent = '';
        publishModel();
        return;
      }
      picker.disabled = false;
      data.models.forEach(function (m) {
        var o = el('option', null, m.label); o.value = m.value; picker.appendChild(o);
      });
      if (data.models.some(function (m) { return m.value === previous; })) picker.value = previous;
      return modelChanged();
    }).catch(async function (failure) {
      say('llp-harness-msg', await problem(failure, 'load the models'));
    });
  }
  if (picker) picker.addEventListener('change', function () { ownsModelSelection = true; modelChanged(); });

  var previewBtn = $('llp-preview-btn');
  if (previewBtn) previewBtn.addEventListener('click', async function () {
    var box = $('llp-preview');
    box.textContent = '';
    previewBtn.disabled = true;
    try {
      var support = $('llp-support') ? $('llp-support').value : '3';
      var data = await get('/preview?min_support=' + encodeURIComponent(support) +
        (model() ? '&model_id=' + encodeURIComponent(model()) : ''));
      if (!data.enabled) {
        box.appendChild(el('p', 'muted', 'Self-coaching is off, so there is nothing to preview.' +
          (data.switch_place ? ' Turn on ' + data.switch_place + '.' : '')));
      } else if (!data.weaknesses.length) {
        box.appendChild(el('p', 'muted', 'No repeated mistakes found in the last ' + plural(data.scanned, 'failure', 'failures') +
          ' (' + data.eligible + ' could be used for this model). Nothing would change.'));
      } else {
        var ul = el('ul');
        data.weaknesses.forEach(function (w) {
          var li = el('li');
          li.appendChild(el('strong', null, 'Seen ' + plural(w.times, 'time', 'times') + ': ' + w.pattern));
          if (w.would_add) li.appendChild(el('div', null, 'Would try the lesson: “' + w.would_add + '”'));
          ul.appendChild(li);
        });
        box.appendChild(ul);
        box.appendChild(el('p', 'muted', 'This is only a preview. Nothing was changed.'));
      }
    } catch (failure) {
      box.appendChild(el('p', null, await problem(failure, 'see the preview')));
    } finally {
      previewBtn.disabled = false;
    }
  });

  var holdoutBtn = $('llp-holdout-btn');
  if (holdoutBtn) holdoutBtn.addEventListener('click', async function () {
    var box = $('llp-holdout');
    box.textContent = '';
    holdoutBtn.disabled = true;
    try {
      var data = await get('/holdout');
      if (!data.configured) box.appendChild(el('p', 'muted', 'No hold-out record is set up, so there is nothing to check.'));
      else if (!data.verified) box.appendChild(el('p', null, 'The hold-out record did not pass the check. It may be incomplete or changed. Ask your administrator to look into it.'));
      else {
        box.appendChild(el('p', null, 'The stored history checks match: ' + plural(data.events, 'entry', 'entries') +
          ', ' + plural(data.checks_used, 'test use', 'test uses') + ' recorded.'));
        box.appendChild(el('p', 'muted', 'This checks the local record. It does not establish independent custody or detect replacement of the whole history without a separately retained copy.'));
        box.appendChild(technical([['Record', data.technical.ledger], ['Latest fingerprint', data.technical.latest_fingerprint]]));
      }
    } catch (failure) {
      box.appendChild(el('p', null, await problem(failure, 'see the hold-out check')));
    } finally {
      holdoutBtn.disabled = false;
    }
  });

  function reportBlock(r) {
    var div = el('div');
    var head = 'Found ' + plural(r.patterns_found, 'repeated mistake', 'repeated mistakes') + ', tried ' +
      plural(r.ideas_tried, 'idea', 'ideas') + ', ' + r.passed_testing + ' passed testing, ' +
      plural(r.adopted, 'new lesson', 'new lessons') + ' adopted, ' + plural(r.retired, 'old lesson', 'old lessons') + ' retired.';
    div.appendChild(el('p', null, head));
    if (r.paused_for_calibration) div.appendChild(el('p', 'muted', 'New lessons are paused until the quality checker is reliable again.'));
    else if (r.promotion_gate_off) div.appendChild(el('p', 'muted', 'Nothing new can be adopted until you turn on ' +
      (r.gate_place || 'adopting reviewed improvements on the Learning page') + '.'));
    if (r.new_lessons.length) {
      var ul = el('ul');
      r.new_lessons.forEach(function (ln) { ul.appendChild(el('li', null, ln)); });
      div.appendChild(ul);
    }
    return div;
  }
  // Learning pass and test-case check run as background jobs (see
  // lightwork-ops-jobs.js): the page shows progress and, for every model,
  // a Stop button.
  var J = window.LWJobs;
  function runUi(action, render, after) {
    return { status: $('llp-run-status'), out: $('llp-run-result'), action: action, render: render, after: after };
  }
  function loadPlan() {
    var cost = $('llp-cost');
    if (!cost || !J) return;
    J.request('/api/v1/learning-ops/self-harness/plan').then(function (d) {
      var parts = [d.spending_limit != null ? 'Each run can spend up to ' + J.money(d.spending_limit) + ' on testing.'
        : 'No testing spending limit is set, so the general limits apply.'];
      if (d.checker) parts.push('Answers are checked by ' + d.checker + '.');
      if (d.careful_testing) parts.push('Careful testing is on, so include the current standing instructions for new lessons to be adopted.');
      parts.push('It stops if learning is paused.');
      cost.textContent = parts.join(' ');
    }).catch(function () { /* the default sentence stays */ });
  }
  if (J) J.wire($('llp-quality-btn'), async function () {
    var remove = $('llp-quality-remove').checked;
    var msg = remove
      ? 'Check every test case now and remove the ones that are too easy to show whether a lesson helps? Each case is tried a couple of times, which uses part of the evaluation spending limit. Removed cases cannot be recovered here.'
      : 'Check every test case now? Each one is tried a couple of times, which uses part of the evaluation spending limit. Nothing is removed.';
    if (!(await window.mvConfirm(msg, { okText: remove ? 'Check and remove' : 'Check test cases' }))) return null;
    return { url: API + '/corpus-quality', init: { method: 'POST', json: { model_id: model() || null, remove_weak: remove, confirm: remove } } };
  }, runUi('check the test cases', function (data) {
    if (!data.configured) return el('p', 'muted', 'No test cases are set up yet, so there is nothing to check.');
    if (!data.cases.length) return el('p', 'muted', 'There are no test cases for this model yet.');
    var weak = data.cases.filter(function (c) { return !c.useful; }).length;
    var head = el('p', null, plural(data.cases.length, 'test case', 'test cases') + ' checked. ' +
      (weak ? weak + (weak === 1 ? ' is' : ' are') + ' too easy to show whether a lesson helps.' : 'All of them can show whether a lesson helps.') +
      (data.removed ? ' Removed ' + plural(data.removed, 'test case', 'test cases') + '.' : ''));
    var ul = el('ul');
    data.cases.forEach(function (c) {
      ul.appendChild(el('li', null, c.task + ': ' + (c.useful ? 'useful' : 'too easy') +
        (c.baseline_rate != null ? ' (passed ' + Math.round(c.baseline_rate * 100) + '% without help)' : '')));
    });
    return [head, ul];
  }));

  loadRefinements();
  loadModels();
  loadLog();
  loadPlan();
})();
