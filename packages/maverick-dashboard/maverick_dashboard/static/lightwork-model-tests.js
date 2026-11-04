(function () {
  'use strict';
  const root = document.getElementById('model-tests');
  if (!root) return;
  const el = id => document.getElementById('model-test-' + id);
  let context = '', review = null, busy = false, timer = null, enabled = false, visible = 50;
  const words = {prepared: 'Awaiting your confirmation', queued: 'Queued once; not replayed after interruption', executing: 'One request in progress', passed: 'Synthetic sample matched', not_matched: 'Response received; sample did not match', cancelled: 'Cancelled before dispatch', refused: 'Refused before dispatch', unknown: 'Unconfirmed outcome; check original accounting receipt'};
  async function request(path, body) {
    return window.mvFetchJSON('/api/v1/models/tests' + path, {cache: 'no-store', method: body ? 'POST' : 'GET', body, plainDetail: true},
      body ? 'record the model test' : 'load the model tests');
  }
  function controls() {
    el('review').disabled = busy || !enabled;
    el('confirm').disabled = busy || !review;
    el('abandon').disabled = busy || !review;
    el('refresh').disabled = busy;
  }
  function resetReview() { review = null; el('review-card').hidden = true; controls(); }
  function render(rows) {
    const history = el('history'); history.replaceChildren();
    if (!rows.length) { history.textContent = 'No model tests in this account and workspace.'; return; }
    rows.slice(0, visible).forEach(row => {
      const card = document.createElement('article'); card.className = 'settings-callout';
      const heading = document.createElement('h4'); heading.textContent = row.model + ' — ' + (words[row.state] || 'Status unavailable'); card.appendChild(heading);
      const text = document.createElement('p'); text.textContent = (window.mvTimeAbsolute ? window.mvTimeAbsolute(row.created_at) : new Date(row.created_at * 1000).toLocaleString()) + '. ' + (row.message || row.notice); card.appendChild(text);
      const scope = document.createElement('p'); scope.className = 'muted'; scope.textContent = row.scope; card.appendChild(scope);
      if (typeof row.latency_seconds === 'number') { const facts = document.createElement('p'); facts.textContent = 'Observed response time: ' + row.latency_seconds + ' seconds. Recorded usage: USD ' + row.recorded_dollars + '; this is not a final provider invoice.'; card.appendChild(facts); }
      if (row.may_still_be_running || ['prepared', 'queued', 'executing'].includes(row.state)) {
        const stop = document.createElement('button'); stop.type = 'button'; stop.className = 'btn'; stop.textContent = row.state === 'prepared' ? 'Cancel this review' : 'Request stop';
        stop.addEventListener('click', async () => { stop.disabled = true; try { await request('/' + row.id + '/cancel', {context}); if (review && review.id === row.id) resetReview(); await load(); } catch (error) { el('status').textContent = error.message; stop.disabled = false; } }); card.appendChild(stop);
      }
      if (row.state === 'unknown' || row.state === 'executing' || row.state === 'queued') { const link = document.createElement('a'); link.href = '/budget'; link.textContent = 'Check original spending receipts'; card.appendChild(link); }
      history.appendChild(card);
    });
    if (rows.length > visible) { const more = document.createElement('button'); more.type = 'button'; more.className = 'btn'; more.textContent = 'Show earlier receipts'; more.addEventListener('click', () => { visible += 50; render(rows); }); history.appendChild(more); }
  }
  async function load() {
    clearTimeout(timer);
    const value = await request('');
    if (context && context !== value.context) resetReview();
    context = value.context; enabled = value.enabled; controls(); render(value.checks);
    if (!enabled) el('status').textContent = value.blocked;
    if (value.checks.some(row => ['queued', 'executing'].includes(row.state))) timer = setTimeout(() => load().catch(error => { el('status').textContent = error.message; }), 2000);
  }
  el('form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !enabled) return;
    busy = true; resetReview(); el('status').textContent = 'Preparing a review; no generation has started.';
    try {
      const model = el('model').value === '__custom__' ? el('custom-value').value.trim() : el('model').value;
      const value = await request('/review', {context, model, kind: el('kind').value}); review = value.check;
      const caps = review.limits;
      el('review-text').textContent = 'Send one synthetic ' + (review.kind === 'vision' ? 'image' : 'text') + ' sample to ' + review.model + '. Limits: ' + (window.mvMoney ? window.mvMoney(caps.max_dollars) : 'USD ' + caps.max_dollars) + ', ' + caps.max_output_tokens + ' output tokens, ' + caps.max_wall_seconds + ' seconds local waiting. The provider may bill an interrupted request. No automatic retries or model failover. Only this test is affected.';
      el('review-card').hidden = false; el('review-card').focus(); el('status').textContent = 'Review the model, sample and limits before confirming.';
    } catch (error) { el('status').textContent = error.message; }
    finally { busy = false; controls(); }
  });
  el('confirm').addEventListener('click', async () => {
    if (busy || !review) return; busy = true; controls(); const id = review.id;
    try { await request('/' + id + '/execute', {context, confirmed: true}); el('status').textContent = 'This test was submitted once. Its original receipt will show the result.'; }
    catch (error) { el('status').textContent = error.message; }
    finally { resetReview(); busy = false; controls(); load().catch(error => { el('status').textContent = error.message; }); }
  });
  el('abandon').addEventListener('click', async () => {
    if (!review || busy) return; busy = true; controls();
    try { await request('/' + review.id + '/cancel', {context}); resetReview(); el('review').focus(); await load(); }
    catch (error) { el('status').textContent = error.message; }
    finally { busy = false; controls(); }
  });
  ['model', 'kind', 'custom-value'].forEach(id => el(id).addEventListener('change', resetReview));
  el('model').addEventListener('change', () => { el('custom').hidden = el('model').value !== '__custom__'; });
  el('custom').hidden = el('model').value !== '__custom__';
  el('refresh').addEventListener('click', () => load().catch(error => { el('status').textContent = error.message; }));
  controls(); load().catch(error => { el('status').textContent = error.message; });
})();
