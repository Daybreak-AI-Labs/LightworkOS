/* Existing-example withdrawal only. No enrollment, learning, or tool execution. */
(function () {
  'use strict';
  const card = document.getElementById('le-card');
  if (!card) return;
  const el = name => document.getElementById('le-' + name);
  const base = '/api/v1/flows/' + encodeURIComponent(card.dataset.flowId)
    + '/runs/' + encodeURIComponent(card.dataset.runId) + '/episode-capture';
  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  let record = null, busy = false, editing = false, known = false, recordId = null;
  const selection = Object.freeze({kind: 'flow_run', flow_id: card.dataset.flowId, run_id: card.dataset.runId});
  const home = document.createComment('Learning example controls');
  card.parentNode.insertBefore(home, card);
  let operation = null, prepared = null, returning = false, contextEpoch = 0;
  const operationId = 'learning_example.withdraw';
  const operationBase = '/api/v1/copilot/operations';
  function sameSelection(value) {
    return value && value.kind === selection.kind && value.flow_id === selection.flow_id && value.run_id === selection.run_id;
  }
  function validEnvelope(body) {
    return body && body.schema === 1 && sameSelection(body.selection) && hash(body.scope);
  }
  function clearDraft() {
    prepared = null; editing = false; el('reason').value = '';
    el('error').textContent = ''; el('reason').removeAttribute('aria-invalid');
  }
  function scopeChanged() {
    contextEpoch += 1;
    clearDraft(); record = null; recordId = null;
    unavailable('Your account, workspace, or selected work changed. Refresh status and review again.');
    message('Your earlier reason and confirmation have been cleared.');
  }
  function acceptEnvelope(body) {
    if (!validEnvelope(body)) return false;
    if (operation && operation.scope !== body.scope) { scopeChanged(); return false; }
    return true;
  }
  function finish() {
    busy = false; controls();
    if (returning) {
      returning = false; operation = null; prepared = null; record = null;
      refresh('Review the current status before continuing.');
    }
  }
  const copy = {
    accepted: ['Accepted example', 'This example passed its learning review. Permission to use it is checked separately.'],
    withdrawn: ['Use stopped', 'This example is no longer approved for future use. Previous work, review history and existing copies remain.'],
    expired: ['Expired', 'The retention period has ended. This example is no longer available for future use. Existing copies are not erased.'],
    rejected: ['Not accepted', 'This example was not accepted for learning.'],
    awaiting_review: ['Needs review', 'This completed example is waiting for its learning review.'],
    unusable: ['Not usable', 'This run did not produce an example that can be used for learning.'],
    enrolled: ['Being collected', 'This run has been selected as an example. Collection does not approve any action.'],
    capturing: ['Being collected', 'The approved run is still collecting its actual results.'],
    paused: ['Being collected', 'The run is paused. This example has not completed its learning review.']
  };
  function ready() {
    return record && record.status === 'accepted' && record.audit_status === 'delivered'
      && typeof record.id === 'string' && /^LAE-[a-f0-9]{32}$/.test(record.id)
      && record.withdrawal_available === true && Number.isSafeInteger(record.revision) && record.revision > 0
      && (operation || (hash(record.episode_sha256) && hash(record.review_sha256)));
  }
  function controls() {
    card.setAttribute('aria-busy', String(busy));
    el('refresh').disabled = busy;
    el('withdraw').hidden = !ready() || (editing && (!operation || prepared));
    el('withdraw').disabled = busy;
    el('form').hidden = !editing;
    el('reason').disabled = busy;
    el('confirm').disabled = busy || !ready() || !!(operation && !prepared);
    el('cancel').disabled = busy;
  }
  function message(text) { el('message').textContent = text || ''; }
  function pending() {
    prepared = null;
    record = null; card.hidden = false; known = true;
    el('status').textContent = 'Waiting for confirmation';
    el('description').textContent = 'The change is waiting for its audit record to be confirmed. Refresh status to check the result; do not submit it again.';
    message('Use has not been confirmed as stopped.');
  }
  function unavailable(text) {
    record = null; card.hidden = false;
    el('status').textContent = 'Status unavailable';
    el('description').textContent = text;
  }
  function display(body, note) {
    if (!body || typeof body !== 'object' || body.audit_status !== 'delivered'
        || !Object.prototype.hasOwnProperty.call(copy, body.status)
        || typeof body.id !== 'string' || !/^LAE-[a-f0-9]{32}$/.test(body.id)
        || !Number.isSafeInteger(body.revision) || body.revision < 1
        || (recordId !== null && body.id !== recordId)) {
      unavailable('We could not confirm this example’s current status. Refresh before taking another action.');
      message(note); return;
    }
    known = true; recordId = body.id; card.hidden = false;
    record = { id: body.id, revision: body.revision, status: body.status, audit_status: body.audit_status,
      withdrawal_available: body.withdrawal_available, episode_sha256: body.episode_sha256,
      review_sha256: body.review_sha256 };
    el('status').textContent = copy[record.status][0];
    el('description').textContent = copy[record.status][1];
    message(note);
    if (record.status === 'withdrawn') {
      editing = false; el('reason').value = ''; message('');
    } else if (editing && !ready()) {
      message('The reason is kept here, but this example cannot be changed right now. Refresh status before continuing.');
    } else if (record.status === 'accepted' && !ready()) {
      message('Stopping use is unavailable for this example right now. Refresh status to check again.');
    }
  }
  async function request(path, options, absolute = false) {
    // A refusal's body can carry the current record (an audit-pending
    // decision), so it is handed back with the status; no response text is
    // shown as customer copy.
    const opts = { cache: 'no-store', ...options, headers: { 'Content-Type': 'application/json', ...(options && options.headers) } };
    try { return { status: 200, ok: true, body: await window.mvFetchJSON(absolute ? path : base + path, opts) }; }
    catch (error) { return { status: error.status, ok: false, body: error.payload || null }; }
  }
  function auditPending(result) {
    return result.body && (result.body.status === 'audit_pending'
      || (result.body.detail && result.body.detail.status === 'audit_pending')
      || (operation && validEnvelope(result.body) && result.body.scope === operation.scope
        && result.body.record && result.body.record.status === 'audit_pending'));
  }
  async function refresh(note, restoreFocus = false) {
    if (busy) return;
    const started = contextEpoch;
    busy = true; record = null; prepared = null; controls();
    try {
      const result = operation
        ? await request(operationBase + '?flow_id=' + encodeURIComponent(selection.flow_id)
          + '&run_id=' + encodeURIComponent(selection.run_id), {method: 'GET'}, true)
        : await request('/withdrawal', { method: 'GET' });
      if (started !== contextEpoch) return;
      if (result.status === 404 && !known && !editing) {
        card.hidden = true;
      } else if (auditPending(result)) {
        pending();
      } else if (result.ok) {
        if (operation) {
          if (acceptEnvelope(result.body)) display(result.body.record, note);
          else if (recordId !== null) unavailable('We could not confirm the selected example. Refresh status before continuing.');
        } else display(result.body, note);
      } else {
        if (result.status === 401 || result.status === 403) clearDraft();
        unavailable(result.status === 401 || result.status === 403
          ? 'You do not currently have permission to manage this example. Your entered reason has been cleared.'
          : 'This example is unavailable or has changed. Refresh status to check again.');
        message(note);
      }
    } catch (_) {
      if (started !== contextEpoch) return;
      unavailable('We could not connect to check this example. Refresh status when the connection is available.');
      message(note);
    } finally {
      finish();
      if (started === contextEpoch && restoreFocus && !card.hidden) el('refresh').focus();
    }
  }
  function closeForm() {
    if (busy) return;
    prepared = null;
    editing = false; el('error').textContent = ''; el('reason').removeAttribute('aria-invalid');
    controls(); (ready() ? el('withdraw') : el('refresh')).focus();
  }
  async function openReview() {
    if (busy || !ready()) return;
    if (operation) {
      const started = contextEpoch;
      busy = true; prepared = null; controls(); message('Checking this example before your review…');
      try {
        const result = await request(operationBase + '/prepare', {method: 'POST', body: JSON.stringify({
          selection, operation_id: operationId, expected_scope: operation.scope
        })}, true);
        if (started !== contextEpoch) return;
        if (result.ok && acceptEnvelope(result.body) && result.body.operation_id === operationId
            && typeof result.body.token === 'string' && result.body.token.length > 0
            && Number.isFinite(result.body.expires_at) && result.body.expires_at * 1000 > Date.now()) {
          display(result.body.record, '');
          if (ready()) prepared = {token: result.body.token, expires_at: result.body.expires_at};
        } else {
          const code = result.body && result.body.detail && result.body.detail.code;
          if (result.status === 401 || result.status === 403 || code === 'operation_context_changed') scopeChanged();
          else { record = null; unavailable('This example changed or is unavailable. Refresh status before reviewing again.'); }
        }
      } catch (_) { if (started === contextEpoch) unavailable('We could not connect. Refresh status before reviewing again.'); }
      finally { finish(); }
      if (!prepared || !operation || busy) return;
    }
    editing = true; message(''); controls(); el('reason').focus();
  }
  el('withdraw').addEventListener('click', openReview);
  el('cancel').addEventListener('click', closeForm);
  el('form').addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && !busy) { event.preventDefault(); event.stopPropagation(); closeForm(); }
  });
  el('reason').addEventListener('input', function () {
    el('error').textContent = ''; el('reason').removeAttribute('aria-invalid');
  });
  el('refresh').addEventListener('click', function () {
    refresh(editing ? 'Status refreshed. Review the current state, then confirm again if you still want to stop using this example.' : '', true);
  });
  el('form').addEventListener('submit', async function (event) {
    event.preventDefault();
    if (busy || !editing || !ready()) return;
    if (operation && (!prepared || prepared.expires_at * 1000 <= Date.now())) {
      prepared = null; controls(); message('This review has expired. Choose “Stop using this example” to review it again.'); return;
    }
    const reason = el('reason').value.trim();
    if (!reason || reason.length > 2000) {
      el('error').textContent = !reason ? 'Enter a reason before confirming.' : 'Keep the reason to 2,000 characters or fewer.';
      el('reason').setAttribute('aria-invalid', 'true'); el('reason').focus(); return;
    }
    const expected = record;
    const started = contextEpoch;
    const reviewedOperation = operation && {scope: operation.scope, token: prepared.token};
    busy = true; controls(); message('Confirming your request…');
    let reconcile = '';
    try {
      const result = reviewedOperation
        ? await request(operationBase + '/execute', {method: 'POST', body: JSON.stringify({
          selection, operation_id: operationId, scope: reviewedOperation.scope,
          token: reviewedOperation.token, confirmed: true, rationale: reason
        })}, true)
        : await request('/withdraw', { method: 'POST', body: JSON.stringify({
        expected_revision: expected.revision, expected_episode_sha256: expected.episode_sha256,
        expected_review_sha256: expected.review_sha256, withdraw: true, rationale: reason
      }) });
      if (started !== contextEpoch) return;
      const body = reviewedOperation ? result.body && result.body.record : result.body;
      const bound = !reviewedOperation || (acceptEnvelope(result.body)
        && result.body.operation_id === operationId && result.body.outcome === 'confirmed');
      const changed = result.body && result.body.detail && result.body.detail.code === 'operation_context_changed';
      if (changed || result.status === 401 || result.status === 403) {
        scopeChanged();
      } else if (auditPending(result) || (reviewedOperation && validEnvelope(result.body)
          && result.body.scope === reviewedOperation.scope && result.body.outcome === 'audit_pending')) {
        pending();
      } else if (result.ok && bound && body && body.status === 'withdrawn'
          && body.audit_status === 'delivered' && body.id === expected.id
          && (reviewedOperation || (body.episode_sha256 === expected.episode_sha256
            && body.review_sha256 === expected.review_sha256))) {
        prepared = null; display(body, '');
        window.dispatchEvent(new Event('lightwork:product-state-changed'));
      } else {
        reconcile = result.status === 409
          ? 'The example changed while you were reviewing it. Your reason is kept. Review the refreshed status and confirm again if appropriate.'
          : 'We could not confirm your request. Checking the current status without sending the request again.';
      }
    } catch (_) {
      if (started !== contextEpoch) return;
      reconcile = 'The connection was interrupted. Checking the current status without sending your request again.';
    } finally {
      finish();
      if (started === contextEpoch && !reconcile) el('refresh').focus();
    }
    if (reconcile) {
      record = null; controls(); await refresh(reconcile);
      if (editing && ready()) el('reason').focus();
      else el('refresh').focus();
    }
  });
  window.LightworkLearningExample = Object.freeze({
    selection,
    attach(host, envelope) {
      if (busy || !host || !validEnvelope(envelope)) return false;
      if (!operation || operation.scope !== envelope.scope) clearDraft();
      if (operation && operation.scope !== envelope.scope) recordId = null;
      operation = {scope: envelope.scope}; prepared = null;
      host.appendChild(card);
      if (envelope.record && envelope.record.status === 'audit_pending') pending();
      else display(envelope.record, '');
      controls(); return true;
    },
    review: openReview,
    release() {
      home.parentNode.insertBefore(card, home.nextSibling);
      if (!operation) return;
      // The direct page has no server scope fingerprint. Drop a protected
      // Copilot draft before returning to that weaker status surface.
      contextEpoch += 1; clearDraft(); record = null; recordId = null;
      returning = true;
      if (!busy) finish();
    },
    invalidate() { scopeChanged(); controls(); },
    isBusy() { return busy; }
  });
  refresh('');
})();
