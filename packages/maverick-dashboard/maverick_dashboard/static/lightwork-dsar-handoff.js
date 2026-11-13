/* Metadata-only attestation of an exact collected package, never automatic delivery. */
(function () {
  'use strict';
  var panel = document.getElementById('dsar-package-handoff');
  if (!panel) return;
  var check = panel.querySelector('[data-handoff-check]'), form = panel.querySelector('[data-handoff-form]');
  var status = panel.querySelector('[data-handoff-status]'), current = null, busy = false;
  var requestId = panel.dataset.request, url = '/api/v1/privacy/dsar/' + encodeURIComponent(requestId) + '/package-handoff';
  var labels = {secure_portal: 'Secure requester portal', encrypted_email: 'Encrypted email', approved_transfer: 'Approved secure file transfer', in_person: 'Verified in-person handoff'};
  function text(el, value) { el.textContent = value; }
  function lock(value) {
    busy = value; check.disabled = value;
    panel.querySelectorAll('input,select,button').forEach(function (el) { el.disabled = value; });
  }
  async function call(method, body, route) {
    var controller = new AbortController(), deadline = setTimeout(function () { controller.abort(); }, 30000);
    try {
    var response = await fetch(url + (route || ''), {method: method, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
      headers: {'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined});
    if (!response.ok) {
      var reason;
      try { var data = await response.json(); reason = typeof data.detail === 'string' ? data.detail : ''; } catch (_) { reason = ''; }
      throw new Error(reason || (response.status === 403 ? 'Only an authorized privacy reviewer can record this package handoff.' : 'This could not be confirmed. Recheck saved statements before retrying.'));
    }
    return await response.json();
    } catch (error) {
      if (controller.signal.aborted || error instanceof TypeError)
        throw new Error('The result could not be confirmed. Recheck saved statements before retrying; do not send the package again.');
      throw error;
    } finally { clearTimeout(deadline); }
  }
  async function load() {
    current = await call('GET');
    panel.querySelector('[data-handoff-details]').hidden = false;
    text(panel.querySelector('[data-handoff-scope]'), current.scope);
    var words = {conversations: 'conversations', turns: 'messages', goals: 'work records', episodes: 'work attempts', facts: 'personal facts', fact_history: 'past fact versions', audit_events: 'activity entries'};
    text(panel.querySelector('[data-handoff-counts]'), current.package_available
      ? 'Verified collected package: ' + Object.keys(words).map(function (key) { return Number(current.counts[key] || 0) + ' ' + words[key]; }).join(', ') + '.'
      : 'This request is closed. Its collected package is unavailable; historical statements remain below.');
    var history = panel.querySelector('[data-handoff-history]'); history.replaceChildren();
    current.receipts.forEach(function (row) {
      var item = document.createElement('li');
      text(item, new Date(row.handed_at).toLocaleString() + ' · ' + (labels[row.channel] || 'Secure channel') + ' · ' + row.reference + '. Recorded by ' + row.recorded_by + ' on ' + new Date(row.recorded_at * 1000).toLocaleString() + '. Operator-recorded; requester receipt unverified.');
      history.appendChild(item);
      if (current.audit_pending) {
        var retry = document.createElement('button'); retry.type = 'button'; retry.className = 'btn btn--ghost';
        text(retry, 'Confirm saved activity'); item.appendChild(retry);
        retry.addEventListener('click', async function () {
          if (busy) return; lock(true); retry.disabled = true;
          try {
            var result = await call('POST', {receipt_id: row.id}, '/confirm-saved');
            await load(); text(status, result.message);
            window.dispatchEvent(new CustomEvent('lightwork:product-state-changed'));
          } catch (error) { text(status, error.message); }
          finally { lock(false); retry.disabled = false; }
        });
      }
    });
    if (!current.receipts.length) { var empty = document.createElement('li'); text(empty, 'No package handoff statement recorded.'); history.appendChild(empty); }
    form.hidden = !current.package_available;
    text(status, current.audit_pending ? 'A saved activity receipt is still pending. Recheck or retry the exact statement; do not send the package again.' : 'Current package and saved statements checked.');
    if (!form.elements.handed_at.value) {
      var now = new Date(); now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
      form.elements.handed_at.value = now.toISOString().slice(0, 16);
    }
  }
  check.addEventListener('click', async function () {
    if (busy) return; lock(true);
    try { await load(); } catch (error) { text(status, error.message); } finally { lock(false); }
  });
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (busy || !current || !form.reportValidity()) return;
    var date = new Date(form.elements.handed_at.value);
    if (Number.isNaN(date.getTime())) { text(status, 'Choose when you handed off this package.'); return; }
    var body = {binding: current.binding, channel: form.elements.channel.value,
      handed_at: date.toISOString(), reference: form.elements.reference.value,
      reviewed: form.elements.reviewed.checked, identity_checked: form.elements.identity_checked.checked, sent: form.elements.sent.checked};
    lock(true);
    try {
      var agreed = window.mvConfirm && await window.mvConfirm('Record your statement about the exact collected package you handed off through ' + labels[body.channel] + '? Lightwork will not send anything. This is not proof that the requester received it.', {okText: 'Record statement'});
      if (!agreed) return;
      var result = await call('POST', body); await load(); text(status, result.message);
      window.dispatchEvent(new CustomEvent('lightwork:product-state-changed'));
    } catch (error) { text(status, error.message + ' Your draft is kept. Recheck saved statements before retrying.'); }
    finally { lock(false); }
  });
  document.addEventListener('lightwork:product-operation-complete', function (event) {
    if (event.detail && event.detail.operation === 'artifacts.privacy_package_handoff' && !busy) {
      lock(true); load().catch(function (error) { text(status, error.message); }).finally(function () { lock(false); });
    }
  });
}());
