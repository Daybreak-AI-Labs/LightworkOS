/* Workspaces page: create by name, change plan and daily limit, pause,
   resume and remove. Every change goes through the admin workspace API. */
(function () {
  'use strict';
  var addMsg = document.getElementById('tenant-add-msg');
  var rowMsg = document.getElementById('tenant-quota-msg') || document.getElementById('removed-tenants-msg');
  var add = document.getElementById('tenant-add');
  var creating = false;

  function formStamp(form) {
    return JSON.stringify(Array.from(form.elements).filter(function (field) { return !!field.name; })
      .map(function (field) { return [field.name, field.value, !!field.checked]; }));
  }
  var emptyCreate = add ? formStamp(add) : '';
  function enteredCreate() { return add && formStamp(add) !== emptyCreate; }
  function shownInvitation() {
    var output = document.getElementById('tenant-onboard-out');
    var link = document.getElementById('tenant-onboard-link');
    return output && !output.hidden && link && !!link.value;
  }
  function keepPage() {
    var notice = document.getElementById('tenant-kept-work');
    if (notice || !addMsg) return;
    notice = document.createElement('p');
    notice.id = 'tenant-kept-work'; notice.className = 'muted tenants-msg';
    notice.textContent = 'The workspace list has changed. Your entered details and any invitation link stay here until you are ready to refresh. ';
    var refresh = document.createElement('button');
    refresh.type = 'button'; refresh.className = 'btn'; refresh.textContent = 'Refresh workspace list';
    refresh.addEventListener('click', async function () {
      if (creating) { addMsg.textContent = 'Wait for the workspace being created before refreshing.'; return; }
      var before = add ? formStamp(add) : '';
      if ((enteredCreate() || shownInvitation()) && !await window.mvConfirm(
        'Refresh the workspace list? Your unsaved workspace details and any invitation link shown only once will leave this page.',
        {okText: 'Refresh list'})) return;
      // Recheck after the confirmation waits: never interrupt a new creation.
      if (creating || (add && formStamp(add) !== before)) {
        addMsg.textContent = 'Your workspace details changed. They are kept here; choose Refresh workspace list again when ready.';
        return;
      }
      window.location.reload();
    });
    notice.appendChild(refresh); addMsg.after(notice);
  }

  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function send(url, method, body) {
    return (await window.mvFetchJSON(url, {method: method, body: body})) || {};
  }
  // A plain server explanation (a duplicate name), when it is one.
  function plainDetail(failure) {
    return window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
  }
  function reloadSoon() {
    window.setTimeout(function () {
      if (creating || enteredCreate() || shownInvitation()) { keepPage(); return; }
      window.location.reload();
    }, 350);
  }
  function base(id) { return '/api/v1/admin/tenants/' + encodeURIComponent(id); }
  function nameOf(id) {
    var row = document.querySelector('[data-tenant-row="' + (window.CSS && CSS.escape ? CSS.escape(id) : id) + '"]');
    return row ? row.dataset.tenantName : 'this workspace';
  }

  // "No limit" disables the amount; unticking asks for one.
  function syncLimit(form) {
    var box = form.querySelector('[data-limit-toggle]');
    var amount = form.querySelector('[data-limit-amount]');
    if (!box || !amount) return;
    amount.disabled = box.checked; amount.required = !box.checked;
  }
  document.querySelectorAll('[data-limit-toggle]').forEach(function (box) {
    var scope = box.closest('form');
    var amount = scope && scope.querySelector('[data-limit-amount]');
    if (!amount) return;
    box.addEventListener('change', function () {
      syncLimit(scope);
      if (!box.checked) amount.focus();
    });
  });
  function limitFrom(form) {
    var box = form.querySelector('[data-limit-toggle]');
    if (box && box.checked) return 0;
    var value = Number(form.querySelector('[data-limit-amount]').value);
    return isFinite(value) && value > 0 ? value : null;
  }

  if (add) {
    add.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (creating) return;
      var data = new FormData(add);
      var limit = limitFrom(add);
      var name = String(data.get('display_name') || '').trim();
      if (!name) { addMsg.textContent = 'Give the workspace a name.'; return; }
      if (limit === null) { addMsg.textContent = 'Enter a daily limit above $0, or tick "No daily limit".'; return; }
      var submitted = formStamp(add);
      var submit = add.querySelector('button[type="submit"]');
      creating = true; add.setAttribute('aria-busy', 'true');
      if (submit) submit.disabled = true;
      var adminEmail = String(data.get('admin_email') || '').trim();
      var out = document.getElementById('tenant-onboard-out');
      try {
        if (adminEmail && shownInvitation()) {
          addMsg.textContent = 'Save the invitation link already shown before creating another invitation.';
          if (!await window.mvConfirm(
            'Have you saved the invitation link currently shown? A new invitation will replace the only copy displayed here.',
            {okText: 'I saved the link'})) return;
          if (formStamp(add) !== submitted) {
            addMsg.textContent = 'Your workspace details changed while confirming. They are kept; choose Create workspace again when ready.';
            return;
          }
        }
        addMsg.textContent = 'Creating…';
        if (adminEmail) {
          // Workspace + its first administrator's invitation in one step. The
          // page does not reload: the invitation link is shown only once.
          var result = await send('/api/v1/admin/workspace-ops/onboard', 'POST', {
            display_name: name, plan: String(data.get('plan') || 'free'), max_daily_dollars: limit,
            admin_email: adminEmail, role: String(data.get('role') || 'admin')});
          addMsg.textContent = result.summary || ('Workspace "' + name + '" created and ' + adminEmail + ' invited.');
          if (window.mvToast) window.mvToast(addMsg.textContent);
          var link = document.getElementById('tenant-onboard-link');
          if (link && out && result.invite_link) {
            var identity = document.getElementById('tenant-onboard-identity');
            if (!identity) {
              identity = document.createElement('p');
              identity.id = 'tenant-onboard-identity'; identity.className = 'muted tenants-msg';
              out.insertBefore(identity, out.firstChild);
            }
            identity.textContent = 'Invitation for ' + adminEmail + ' in ' + name + '.';
            link.value = result.invite_link; out.hidden = false;
          }
          if (formStamp(add) === submitted) { add.reset(); syncLimit(add); }
          else addMsg.textContent += ' Your newer workspace details are kept.';
          return;
        }
        await send('/api/v1/admin/tenants', 'POST', {display_name: name, plan: String(data.get('plan') || 'free'), max_daily_dollars: limit});
        addMsg.textContent = 'Workspace "' + name + '" created.';
        if (formStamp(add) === submitted) { add.reset(); syncLimit(add); }
        else addMsg.textContent += ' Your newer workspace details are kept.';
        if (window.mvToastAfterReload) window.mvToastAfterReload('Workspace "' + name + '" created.');
        reloadSoon();
      } catch (failure) {
        var plain = plainDetail(failure);
        addMsg.textContent = plain || errorText(failure, 'create the workspace');
        if (window.mvToast) window.mvToast(addMsg.textContent, {error: true});
      } finally {
        creating = false; add.removeAttribute('aria-busy');
        if (submit) submit.disabled = false;
      }
    });
  }

  document.querySelectorAll('form.tenant-quota').forEach(function (form) {
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var id = form.getAttribute('data-tenant');
      var limit = limitFrom(form);
      if (limit === null) { rowMsg.textContent = 'Enter a daily limit above $0, or tick "No limit".'; return; }
      rowMsg.textContent = 'Saving…';
      try {
        await send(base(id) + '/quota', 'POST', {max_daily_dollars: limit});
        rowMsg.textContent = 'Daily limit for ' + nameOf(id) + ' is now ' + (limit ? (window.mvMoney ? window.mvMoney(limit) : '$' + limit) + ' a day' : 'no limit') + '.';
        if (window.mvToastAfterReload) window.mvToastAfterReload(rowMsg.textContent);
        reloadSoon();
      } catch (failure) { rowMsg.textContent = errorText(failure, 'save the daily limit'); }
    });
  });

  document.querySelectorAll('[data-tenant-plan]').forEach(function (select) {
    select.addEventListener('change', async function () {
      var id = select.dataset.tenantPlan;
      var plan = select.value;
      var ok = await window.mvConfirm('Move ' + nameOf(id) + ' to the ' + select.options[select.selectedIndex].textContent + ' plan? The features it can use change straight away.', {okText: 'Change plan'});
      if (!ok) { select.value = select.dataset.current; return; }
      rowMsg.textContent = 'Saving…';
      try {
        await send(base(id) + '/plan', 'POST', {plan: plan});
        select.dataset.current = plan;
        rowMsg.textContent = nameOf(id) + ' is now on the ' + select.options[select.selectedIndex].textContent + ' plan.';
        if (window.mvToast) window.mvToast(rowMsg.textContent);
      } catch (failure) {
        select.value = select.dataset.current;
        rowMsg.textContent = errorText(failure, 'change the plan');
      }
    });
  });

  var questions = {
    suspend: ['Pause {name}? No new work can start in it until you resume it. Nothing is deleted.', 'Pause workspace', 'pause the workspace', 'POST', '/suspend', '{name} is paused.'],
    // Resuming is routine and can be undone with Pause: no question.
    resume: ['', 'Resume', 'resume the workspace', 'POST', '/resume', '{name} is active again.'],
    delete: ['Remove {name} from the list? Access and member roles will be revoked. Its stored records stay on this computer for deliberate recovery.', 'Remove workspace', 'remove the workspace', 'DELETE', '', '{name} was removed.']
  };
  document.querySelectorAll('[data-tenant-action]').forEach(function (button) {
    button.addEventListener('click', async function () {
      var row = button.closest('[data-tenant-row]');
      var id = row.dataset.tenantRow;
      var q = questions[button.dataset.tenantAction];
      // Removing a workspace revokes everyone's access at once: the person
      // types REMOVE first.
      var removing = button.dataset.tenantAction === 'delete';
      var ok = !q[0] || await window.mvConfirm(q[0].replace('{name}', row.dataset.tenantName),
        {okText: q[1], danger: removing, typed: removing ? 'REMOVE' : undefined});
      if (!ok) return;
      button.disabled = true;
      rowMsg.textContent = 'Saving…';
      try {
        await send(base(id) + q[4], q[3]);
        rowMsg.textContent = q[5].replace('{name}', row.dataset.tenantName);
        if (window.mvToastAfterReload) window.mvToastAfterReload(rowMsg.textContent);
        reloadSoon();
      } catch (failure) {
        rowMsg.textContent = errorText(failure, q[2]);
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll('[data-tenant-restore]').forEach(function (button) {
    button.addEventListener('click', async function () {
      var row = button.closest('[data-removed-workspace]');
      var name = row.dataset.removedName;
      var ok = await window.mvConfirm('Restore ' + name + ' with its old records? It will stay paused, and former members will not regain access.', {okText: 'Restore paused workspace'});
      if (!ok) return;
      button.disabled = true;
      rowMsg.textContent = 'Restoring…';
      try {
        var restored = await send(base(row.dataset.removedWorkspace) + '/restore', 'POST');
        var restoredName = restored.display_name || name;
        rowMsg.textContent = restoredName + ' was restored as paused. Review it before resuming.';
        if (window.mvToastAfterReload) window.mvToastAfterReload(rowMsg.textContent);
        reloadSoon();
      } catch (failure) {
        var plain = plainDetail(failure);
        rowMsg.textContent = plain || errorText(failure, 'restore the workspace');
        button.disabled = false;
      }
    });
  });
})();

/* A single irreversible review, backed by the native retirement record. */
(function () {
  'use strict';
  var expectedLabels = ['Workspace', 'Removed', 'Records selected', 'What will happen', 'What remains', 'Other copies', 'If interrupted', 'Local work limit'];
  function element(tag, text, parent) {
    var result = document.createElement(tag);
    if (text !== undefined) result.textContent = text;
    if (parent) parent.appendChild(result);
    return result;
  }
  function renderReview(host, changes) {
    if (!Array.isArray(changes) || changes.length < 8 || changes.length > 9 ||
        changes.some(function (row, index) {
          return !row || Object.keys(row).sort().join(',') !== 'after,label' || typeof row.after !== 'string' ||
            !row.after.trim() || row.after.length > 2000 || row.label !== (expectedLabels[index] || 'Earlier unconfirmed erasure');
        })) return false;
    var list = element('dl', undefined, host);
    list.style.whiteSpace = 'pre-wrap'; list.style.overflowWrap = 'anywhere';
    changes.forEach(function (row) { element('dt', row.label, list); var text = element('dd', row.after, list); text.style.marginInlineStart = '0'; });
    return true;
  }
  window.LWWorkspaceErasure = Object.freeze({renderReview: renderReview});
  var panel = document.getElementById('workspace-erasure-review');
  if (!panel) return;
  var historyPanel = document.getElementById('workspace-erasure-history');
  var details = document.getElementById('workspace-erasure-details');
  var rows = document.getElementById('workspace-erasure-history-rows');
  var message = document.getElementById('workspace-erasure-message');
  var checkbox = document.getElementById('workspace-erasure-confirm');
  var applyButton = document.getElementById('workspace-erasure-apply');
  var originalButton = document.getElementById('workspace-erasure-original');
  var acknowledge = document.getElementById('workspace-erasure-acknowledge');
  var generation = 0, busy = false, selected = null, prepared = null, attempted = false, returnFocus = null;
  function clearReview() {
    prepared = null; attempted = false; checkbox.checked = false; applyButton.disabled = true;
    originalButton.hidden = true; panel.hidden = true; details.replaceChildren();
  }
  function lock(value) {
    busy = value;
    document.querySelectorAll('[data-workspace-erase],[data-workspace-erasure-history],#workspace-erasure-new-review').forEach(function (button) { button.disabled = value; });
    applyButton.disabled = value || attempted || !prepared || !checkbox.checked;
    originalButton.disabled = value;
  }
  function clear(event) {
    if (event && event.detail && (event.detail.selection_only || event.detail.kind === 'selection' || event.detail.reason === 'selection')) return;
    generation += 1; selected = null; clearReview(); rows.replaceChildren(); historyPanel.hidden = true;
    acknowledge.checked = false; message.textContent = 'Your account or workspace changed. Reopen Workspaces before another review.';
    var removed = document.getElementById('removed-workspaces'); if (removed) removed.hidden = true;
    lock(false);
  }
  async function request(path, method, body) {
    try { return await window.mvFetchJSON('/api/v1/workspace-erasure' + path, {method: method, body: body}); }
    catch (error) { if (error && (error.status === 401 || error.status === 403)) clear(); throw error; }
  }
  function plain(error) { return window.mvPlainDetail ? window.mvPlainDetail(error && error.detail) : ''; }
  async function review(workspace, previous) {
    if (busy) return;
    generation += 1; var stamp = generation; selected = workspace;
    clearReview(); acknowledge.checked = false; lock(true); message.textContent = 'Checking all remaining local records…';
    try {
      var value = await request('/review', 'POST', {workspace: workspace, acknowledge_previous: previous === true});
      if (stamp !== generation || selected !== workspace) return;
      if (!renderReview(details, value.changes)) throw new Error('incomplete-review');
      prepared = value; panel.hidden = false; message.textContent = 'Nothing has been erased. Review every consequence before confirming.';
      document.getElementById('workspace-erasure-title').focus();
    } catch (error) {
      if (stamp !== generation) return;
      clearReview(); message.textContent = plain(error) || 'The complete erasure review is unavailable. Nothing was submitted. Read existing results before another review.';
    } finally { if (stamp === generation) lock(false); }
  }
  function showResult(value, host) {
    var item = element('article', undefined, host); item.className = 'panel';
    element('h4', value.status === 'confirmed' ? 'Local records erased' : 'Original result unconfirmed', item);
    if (value.started_at) element('p', new Date(value.started_at * 1000).toLocaleString(), item);
    element('p', value.message, item);
    if (value.files !== undefined) element('p', value.files + ' files, ' + value.folders + ' folders and ' + value.bytes + ' bytes selected for this attempt.', item);
  }
  async function history(workspace) {
    if (busy) return;
    generation += 1; var stamp = generation; selected = workspace;
    clearReview(); rows.replaceChildren(); acknowledge.checked = false; historyPanel.hidden = true;
    lock(true); message.textContent = 'Reading original results; no erasure repeats…';
    try {
      var value = await request('/workspaces/' + encodeURIComponent(workspace) + '/history', 'GET');
      if (stamp !== generation || selected !== workspace) return;
      value.originals.forEach(function (result) { showResult(result, rows); });
      if (!value.originals.length) element('p', 'There are no original erasure results for your current account and workspace. This does not prove that another administrator never attempted erasure.', rows);
      historyPanel.hidden = false; message.textContent = 'Original results were read. Nothing was erased or repeated.';
      document.getElementById('workspace-erasure-history-title').focus();
    } catch (error) { if (stamp === generation) message.textContent = plain(error) || 'Original results are unavailable. No erasure was repeated.'; }
    finally { if (stamp === generation) lock(false); }
  }
  checkbox.addEventListener('change', function () { applyButton.disabled = busy || attempted || !prepared || !checkbox.checked; });
  document.querySelectorAll('[data-workspace-erase]').forEach(function (button) {
    button.addEventListener('click', function () { returnFocus = button; review(button.closest('[data-removed-workspace]').dataset.removedWorkspace, false); });
  });
  document.querySelectorAll('[data-workspace-erasure-history]').forEach(function (button) {
    button.addEventListener('click', function () { returnFocus = button; history(button.closest('[data-removed-workspace]').dataset.removedWorkspace); });
  });
  document.getElementById('workspace-erasure-new-review').addEventListener('click', function () {
    if (!acknowledge.checked) { message.textContent = 'Acknowledge the earlier unconfirmed result before a separately intentional cleanup review.'; acknowledge.focus(); return; }
    if (selected) review(selected, true);
  });
  document.getElementById('workspace-erasure-cancel').addEventListener('click', function () {
    if (busy) return;
    var hadAttempt = attempted;
    generation += 1; clearReview(); message.textContent = hadAttempt
      ? 'The review was closed. Earlier erasure results remain available. No further erasure was submitted.'
      : 'The review was closed. No erasure was submitted.';
    if (returnFocus && returnFocus.isConnected) returnFocus.focus();
  });
  applyButton.addEventListener('click', async function () {
    if (busy || attempted || !prepared || !checkbox.checked) return;
    var stamp = generation, reviewValue = prepared; attempted = true; lock(true);
    originalButton.hidden = false; message.textContent = 'Erasing only the exact reviewed local records…';
    try {
      var value = await request('/apply', 'POST', {token: reviewValue.token, confirmed: true});
      if (stamp !== generation) return;
      message.textContent = value.message;
      var target = document.querySelector('[data-removed-workspace="' + CSS.escape(selected) + '"] [data-tenant-restore]');
      if (target) target.disabled = true;
    } catch (error) {
      if (stamp === generation) message.textContent = plain(error) || 'The original erasure is unconfirmed. Records may already be erased. Check this original result; it will not repeat.';
    } finally { if (stamp === generation) lock(false); }
  });
  originalButton.addEventListener('click', async function () {
    if (busy || !prepared) return;
    var stamp = generation, reviewValue = prepared; lock(true);
    try {
      var value = await request('/original', 'POST', {token: reviewValue.token});
      if (stamp !== generation) return;
      message.textContent = value.message;
    } catch (error) { if (stamp === generation) message.textContent = plain(error) || 'This original result is unavailable. No erasure was repeated.'; }
    finally { if (stamp === generation) lock(false); }
  });
  ['lightwork:account-context-changed','lightwork:workspace-changed','lightwork:context-changed','lightwork:authority-changed','lightwork:copilot-context-changed'].forEach(function (name) { document.addEventListener(name, clear); });
  window.addEventListener('lightwork:context-changed', clear);
})();
