/* Ordinary choices, complete review and pure native result recovery. Existing
 * policy writers remain the sole owners of request, approval and closure. */
(function (root) {
  'use strict';
  var doc = root.document, API = '/api/v1/security/assurance', KEY = 'lightwork-policy-exception-original';
  var forms, hooks, state, held = null, generation = 0, dialog;
  var status = function (text) { var node = doc.getElementById('policy-exception-status'); if (node) { if (root.mvStatus) root.mvStatus(node, text); else node.textContent = text; } };
  var human = function (text) { return root.mvHuman ? root.mvHuman(text) : String(text || '').replace(/_/g, ' '); };
  var make = function (tag, text) { var node = doc.createElement(tag); if (text !== undefined) node.textContent = String(text); return node; };
  var call = function (path, body) { return root.mvFetchJSON(API + path, {method: body ? 'POST' : 'GET', cache: 'no-store', body: body}); };
  var stamp = function () { return JSON.stringify(forms.map(function (form) { return Array.from(form.querySelectorAll('input,select,textarea')).map(function (field) { return [field.name, field.value, field.checked]; }); })); };
  var policyName = function (row) { var v = (row.versions || []).find(function (item) { return item.version === row.active_version; }); return v && v.title || 'AI-use rules'; };
  var exceptionName = function (row) { return human(String(row.exception_key || '').replace(/-[0-9a-f]{8}-[0-9a-f-]{27}$/, '')); };
  function invalidate() { if (dialog) { dialog.remove(); dialog = null; } }
  function clearPrivate() {
    generation++; invalidate(); state = null;
    forms.forEach(function (form) { form.reset(); form.querySelectorAll('input[type="hidden"]').forEach(function (field) { field.value = ''; }); });
    doc.getElementById('policy-exception-policy').replaceChildren(new Option('Refresh to read current rules', ''));
    hooks.scope.child('asset_ids').setOptions([]); hooks.scope.child('statement_ids').setOptions([]);
    forms.forEach(function (form) { form.querySelectorAll('[data-pick-note]').forEach(function (node) { node.textContent = 'Refresh and choose a current record before continuing.'; }); });
    ['ai-policy-management-policies','ai-policy-management-exceptions','ai-policy-management-evaluations','ai-policy-record-result'].forEach(function (id) { var node = doc.getElementById(id); if (node) node.replaceChildren(); });
    doc.getElementById('policy-exception-controls').replaceChildren();
    doc.getElementById('policy-exception-result').replaceChildren();
    doc.getElementById('policy-exception-original').hidden = true;
    doc.getElementById('policy-exception-new').hidden = true;
  }
  // Nothing has been read yet (or private details were cleared): a failed read
  // must not leave "Loading…" placeholders behind. Once a read has succeeded,
  // the lists stay as read, including a correct "no safeguards recorded" note,
  // whatever later error (a refresh, or a form that was not complete) follows.
  function settleUnread() {
    if (state) return;
    var holder = doc.getElementById('policy-exception-controls'), select = doc.getElementById('policy-exception-policy');
    if (holder) holder.replaceChildren(make('p', 'Safeguards could not be read. Use Refresh to try again.'));
    if (select) select.replaceChildren(new Option('Refresh to read current rules', ''));
  }
  function problem(error) {
    if (error && [401,403,409].includes(error.status)) {
      clearPrivate(); status('Your account, workspace or access changed. Private exception details have been cleared. Refresh to continue.');
    } else {
      settleUnread();
      status(error && error instanceof Error && !error.status ? error.message : root.mvErrorText ? root.mvErrorText(error, 'read these exception controls') : 'These controls could not be read. Your entered work is kept.');
    }
  }
  function retain(value) {
    held = value;
    try { if (value) root.sessionStorage.setItem(KEY, JSON.stringify(value)); else root.sessionStorage.removeItem(KEY); } catch (_) {}
    forms.forEach(function (form) { form.querySelector('button[type="submit"]').disabled = !!held; });
    doc.getElementById('policy-exception-original').hidden = !held;
  }
  function ownHeld() { return held && state && held.context === state.context; }
  function show(record) {
    var target = doc.getElementById('policy-exception-result'); target.replaceChildren();
    target.append(make('h4', exceptionName(record)), make('p', 'Current status: ' + human(record.status)),
      make('p', 'Reason: ' + record.reason), make('p', 'Ends: ' + root.mvTimeAbsolute(record.expires_at)));
    if (record.closeout) target.append(make('p', 'Closure reason: ' + record.closeout.reason));
  }
  function choices(current) {
    hooks.scope.child('asset_ids').setOptions(current.assets.map(function (row) { return [row.value, row.label]; }));
    var selected = new Set(Array.from(doc.querySelectorAll('#policy-exception-controls input:checked')).map(function (field) { return field.value; }));
    var holder = doc.getElementById('policy-exception-controls'); holder.replaceChildren();
    current.controls.forEach(function (row) {
      var label = make('label'), field = make('input'); field.type = 'checkbox'; field.name = 'compensating_control_ids'; field.value = row.value;
      field.checked = selected.has(row.value); label.append(field, doc.createTextNode(' ' + row.label + ' · ' + human(row.status) + ' · ' + row.owner)); holder.append(label);
    });
    if (!current.controls.length) holder.append(make('p', 'No applicable safeguards are recorded. Add a control in Security before requesting an exception.'));
    var select = doc.getElementById('policy-exception-policy'), previous = forms[0].elements.policy_id.value;
    select.replaceChildren(new Option('Choose rules currently in use', ''));
    current.policies.filter(function (row) { return !!row.active_version; }).forEach(function (row) {
      select.append(new Option(policyName(row) + ' · Version ' + row.active_version, row.policy_id));
    });
    if (Array.from(select.options).some(function (option) { return option.value === previous; })) select.value = previous;
    forms.forEach(function (form) { form.querySelector('button[type="submit"]').disabled = !!held; });
  }
  async function refresh() {
    var turn = generation, current = await call('/pickers/policy-exceptions');
    if (turn !== generation) return false;
    if (state && current.context !== state.context) { clearPrivate(); status('Your account or workspace changed. Enter the exception again in the current workspace.'); return false; }
    state = current; choices(current);
    if (held && !ownHeld()) { clearPrivate(); status('The retained original belongs to another account or workspace. It has not been opened here.'); return false; }
    doc.getElementById('policy-exception-original').hidden = !held;
    status(current.notice); return true;
  }
  function selectedPolicy() {
    var form = forms[0], row = state.policies.find(function (item) { return item.policy_id === form.elements.policy_id.value; });
    if (!row || !row.active_version) throw new Error('Choose rules currently in use.');
    return row;
  }
  function choosePolicy(id) {
    var row = state && state.policies.find(function (item) { return item.policy_id === id; });
    forms[0].elements.policy_id.value = row ? row.policy_id : '';
    doc.getElementById('policy-exception-policy').value = row ? row.policy_id : '';
    forms[0].elements.policy_version.value = row && row.active_version || '';
    var version = row && row.versions.find(function (item) { return item.version === row.active_version; });
    hooks.scope.child('statement_ids').setOptions(version ? version.statements.map(function (item) { return [item.statement_id, item.text]; }) : []);
    invalidate();
  }
  function named(values, rows) {
    return values.map(function (value) { var row = rows.find(function (item) { return item.value === String(value).toLowerCase(); }); return row ? row.label : 'A saved choice no longer in the current inventory'; });
  }
  function details(body, row, kind) {
    var rule = state.policies.find(function (item) { return item.policy_id === body.policy_id; });
    var version = rule && rule.versions.find(function (item) { return item.version === body.policy_version; });
    var scope = body.scope, result = {
      'Action': kind === 'request' ? 'Request an exception; nothing is authorized yet' : kind === 'approve' ? 'Approve this exact exception until its end date' : 'Close this exception and end its authority',
      'Exception': kind === 'request' ? forms[0].elements.exception_key.value : exceptionName(row),
      'Rules': version ? version.title + ' · Version ' + version.version : 'The saved policy version',
      'Reason': body.reason, 'Ends': root.mvTimeAbsolute(body.expires_at),
      'AI systems covered': scope.asset_ids.length ? named(scope.asset_ids, state.assets) : ['Every AI system, subject to the other selected conditions'],
      'Rules covered': scope.statement_ids.length ? scope.statement_ids.map(function (id) { var item = version && version.statements.find(function (s) { return s.statement_id.toLowerCase() === id.toLowerCase(); }); return item ? item.text : 'A saved rule not in the current policy version'; }) : version ? version.statements.map(function (s) { return s.text; }) : ['The saved policy version’s rules; current wording is unavailable'],
      'Risk levels covered': scope.risk_tiers.length ? scope.risk_tiers.map(human) : ['Every risk level, subject to the other selected conditions'],
      'Other safeguards': body.compensating_control_ids.map(function (value) { var item = state.controls.find(function (control) { return control.value === String(value).toLowerCase(); }); return item ? item.label + ' · ' + human(item.status) + ' · ' + item.owner : 'A saved safeguard no longer in the current inventory'; })
    };
    ['jurisdictions','data_classes','deployment_types','asset_types','tags','use_case_tags'].forEach(function (key) {
      if ((scope[key] || []).length) result[human(key)] = scope[key].map(human);
    });
    if (kind === 'close') result['Closure reason'] = forms[2].elements.reason.value;
    return result;
  }
  function confirmReview(rows, after) {
    invalidate(); dialog = make('dialog'); dialog.className = 'panel policy-exception-dialog';
    dialog.append(make('h3', 'Review the complete exception'));
    Object.entries(rows).forEach(function (entry) { dialog.append(make('h4', entry[0]));
      if (Array.isArray(entry[1])) { var list = make('ul'); entry[1].forEach(function (text) { list.append(make('li', text)); }); dialog.append(list); }
      else dialog.append(make('p', entry[1])); });
    dialog.append(make('p', 'This records a business decision. Selecting a safeguard does not prove that it is implemented. A request needs a different administrator’s approval.'));
    var label = make('label'), check = make('input'); check.type = 'checkbox'; label.append(check, doc.createTextNode(' I reviewed every choice and consequence.'));
    var accept = make('button', 'Confirm reviewed action'), cancel = make('button', 'Keep editing'); accept.type = cancel.type = 'button'; accept.className = 'btn btn--primary'; cancel.className = 'btn btn--ghost'; accept.disabled = true;
    check.addEventListener('change', function () { accept.disabled = !check.checked; });
    cancel.addEventListener('click', invalidate); accept.addEventListener('click', function () { if (!check.checked || accept.disabled) return; accept.disabled = true; after().catch(problem); });
    dialog.append(label, accept, cancel); doc.body.append(dialog); dialog.addEventListener('cancel', invalidate); dialog.showModal();
  }
  async function review(kind, form) {
    if (held) { status('Read the original result before starting another action. Nothing will be repeated.'); return; }
    if (!form.reportValidity()) return;
    var turn = generation, before = stamp();
    if (!(await refresh()) || turn !== generation || stamp() !== before) { status('Your choices changed while records were read. Review them again.'); return; }
    var body, previous = null, full;
    if (kind === 'request') {
      var policy = selectedPolicy(), controls = Array.from(doc.querySelectorAll('#policy-exception-controls input:checked')).map(function (field) { return field.value; });
      if (!controls.length || controls.length > 128) throw new Error('Choose between one and 128 recorded safeguards.');
      var name = root.LWAssuranceForms.slug(form.elements.exception_key.value, 65);
      if (!name || !root.crypto || typeof root.crypto.randomUUID !== 'function') throw new Error('A secure request could not be prepared. Keep your entered work and refresh.');
      body = {exception_key: name + '-' + root.crypto.randomUUID(), policy_id: policy.policy_id, policy_version: policy.active_version,
        scope: await hooks.collectScope(), reason: form.elements.reason.value, compensating_control_ids: controls,
        expires_at: Number(new Date(form.elements.expires_at.value).getTime()) / 1000}; full = body;
    } else {
      previous = state.exceptions.find(function (item) { return item.exception_key === form.elements.exception_key.value; });
      if (!previous || previous.revision !== Number(form.elements.expected_revision.value)) throw new Error('This exception changed. Choose its current row and review again.');
      if (kind === 'approve' && previous.status !== 'pending') throw new Error('Only an exception waiting for approval can be approved.');
      if (kind === 'close' && previous.status === 'closed') throw new Error('This exception is already closed.');
      body = {expected_revision: previous.revision}; if (kind === 'close') body.reason = form.elements.reason.value;
      full = previous;
    }
    if (turn !== generation || stamp() !== before) return;
    var exactStamp = stamp(), revision = state.revision, context = state.context;
    confirmReview(details(full, previous, kind), async function () {
      var current = await call('/pickers/policy-exceptions');
      if (turn !== generation || current.context !== context || current.revision !== revision || stamp() !== exactStamp) {
        invalidate(); status('The exception, safeguards or your choices changed. Keep your draft and review the current records again.'); return;
      }
      var envelope = {kind: kind, context: context, body: body, previous: previous};
      retain(envelope); invalidate(); status('Recording the reviewed action…');
      try {
        var path = kind === 'request' ? '/ai-policy-management/exceptions' : '/ai-policy-management/exceptions/' + encodeURIComponent(previous.exception_key) + '/' + kind;
        await hooks.write(path, body); // the existing native controller/writer
        await readOriginal();
      } catch (error) {
        status('The reply did not confirm this action. Read its original result; do not submit it again.');
        if (error && [401,403].includes(error.status)) clearPrivate();
      }
    });
  }
  async function readOriginal() {
    if (!held) return;
    var envelope = held, turn = generation;
    var result = await call('/pickers/policy-exceptions/original', envelope);
    if (turn !== generation || held !== envelope) return;
    status(result.message + (result.notice ? ' ' + result.notice : ''));
    if (result.confirmed === true) {
      show(result.record); doc.getElementById('policy-exception-new').hidden = false;
      await hooks.reload();
    }
  }
  async function openReview(_descriptor, options) {
    options = options || {}; var turn = generation, before = stamp();
    if (options.isCurrent && !options.isCurrent()) return false;
    var catalog = await root.mvFetchJSON('/api/v1/copilot/product-operations/catalog', {method:'POST', body:{page:'/security/assurance',selection:{}}});
    if (turn !== generation || stamp() !== before || (options.isCurrent && !options.isCurrent())) return false;
    if (catalog.context !== options.context || !(catalog.operations || []).some(function (row) { return row.id === 'reviews.policy_exception_controls' && row.available; })) return false;
    if (!(await refresh()) || turn !== generation || stamp() !== before || (options.isCurrent && !options.isCurrent())) return false;
    var parent = forms[0].parentElement; while (parent) { if (parent.tagName === 'DETAILS') parent.open = true; parent = parent.parentElement; }
    forms[0].scrollIntoView({block:'start'}); doc.getElementById('policy-exception-policy').focus(); return true;
  }
  function mount(config) {
    hooks = config; forms = ['ai-policy-exception-request','ai-policy-exception-approve','ai-policy-exception-close'].map(function (id) { return doc.getElementById(id); });
    if (forms.some(function (form) { return !form; })) return;
    try { held = JSON.parse(root.sessionStorage.getItem(KEY) || 'null'); } catch (_) {}
    if (held && (!held.body || !['request','approve','close'].includes(held.kind) || !/^[0-9a-f]{64}$/.test(held.context))) held = null;
    if (held) retain(held);
    forms.forEach(function (form, index) { form.addEventListener('input', invalidate); form.addEventListener('change', invalidate);
      form.addEventListener('submit', function (event) { event.preventDefault(); review(['request','approve','close'][index], form).catch(problem); }); });
    doc.getElementById('policy-exception-policy').addEventListener('change', function (event) { if (state) choosePolicy(event.target.value); });
    doc.getElementById('policy-exception-refresh').addEventListener('click', function () { refresh().then(function (current) { if (current) return hooks.reload(); }).catch(problem); });
    doc.getElementById('policy-exception-original').addEventListener('click', function () { readOriginal().catch(problem); });
    doc.getElementById('policy-exception-new').addEventListener('click', function () { retain(null); doc.getElementById('policy-exception-new').hidden = true; refresh().catch(problem); });
    if (root.mvFetchJSON) refresh().catch(problem);
    else doc.addEventListener('DOMContentLoaded', function () { refresh().catch(problem); }, {once:true});
  }
  root.LightworkPolicyExceptions = {mount:mount, openReview:openReview, choosePolicy:choosePolicy, name:exceptionName};
})(window);
