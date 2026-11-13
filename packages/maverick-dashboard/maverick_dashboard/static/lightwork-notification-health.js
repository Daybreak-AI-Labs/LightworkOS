(function () {
  'use strict';
  const summary = document.getElementById('notification-health-summary');
  if (!summary) return;
  const errors = document.getElementById('notification-health-error');
  const list = document.getElementById('notification-health-list');
  const test = document.getElementById('notification-test');
  const refresh = document.getElementById('notification-refresh');
  let busy = false, enabled = false, requestId = null;
  function setBusy(value) { busy = value; test.disabled = value || !enabled; refresh.disabled = value; }
  function render(state) {
    enabled = state.enabled && ['ntfy', 'pushover', 'slack', 'discord'].includes(state.backend);
    const last = state.last_success_at ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(state.last_success_at) : new Date(state.last_success_at * 1000).toLocaleString()) : 'No confirmed delivery in recent history';
    summary.textContent = state.enabled ? 'Current channel: ' + state.backend + '. Last accepted delivery: ' + last + '. Seen by a person: unknown.' : 'Delivery history is turned off. Enable it in All settings before sending a test.';
    list.replaceChildren();
    if (!state.receipts.length) list.textContent = 'No delivery receipts yet. Send a test message to confirm delivery; a saved configuration alone does not.';
    state.receipts.forEach(function (row) {
      const article = document.createElement('article');
      const title = document.createElement('h3');
      const labels = {queued:'Queued', sending:'Sending', delivered:'Accepted by service', failed:'Failed', unknown:'Unknown result'};
      title.textContent = row.backend + ' - ' + (labels[row.state] || 'Unknown result');
      const description = document.createElement('p'); description.textContent = row.message;
      const time = document.createElement('p'); time.className = 'muted'; time.textContent = (window.mvTimeAbsolute ? window.mvTimeAbsolute(row.updated_at) : new Date(row.updated_at * 1000).toLocaleString()) + ' · Attempt ' + row.attempts + ' · ' + (row.kind === 'test' ? 'Delivery test' : 'Organization alert');
      article.append(title, description, time);
      if (row.kind === 'test' && row.state === 'failed' && row.safe_to_retry && row.attempts < 3) {
        const retry = document.createElement('button'); retry.className = 'btn btn--ghost'; retry.textContent = 'Retry this refused test';
        retry.addEventListener('click', function () { if (!busy) request('/api/v1/notifications/retry', {receipt_id:row.id}); });
        article.appendChild(retry);
      }
      list.appendChild(article);
    });
  }
  async function request(url, body) {
    if (busy) return;
    setBusy(true); errors.hidden = true;
    try {
      const result = await window.mvFetchJSON(url, {method: body ? 'POST' : 'GET', body, plainDetail: true,
        onAccess: () => { enabled = false; list.replaceChildren(); }}, body ? 'send the test message' : 'check delivery');
      render(result);
      // A lost response keeps the same request ID for safe recovery.
      if (body && body.request_id) requestId = null;
    } catch (error) { errors.textContent = error.message || 'Could not check delivery. Refresh before sending again.'; errors.hidden = false; }
    finally { setBusy(false); }
  }
  test.addEventListener('click', function () {
    if (!requestId) requestId = (window.mvNewId ? window.mvNewId() : crypto.randomUUID());
    request('/api/v1/notifications/test', {request_id:requestId});
  });
  refresh.addEventListener('click', function () { request('/api/v1/notifications/delivery-status'); });
  request('/api/v1/notifications/delivery-status');
})();
