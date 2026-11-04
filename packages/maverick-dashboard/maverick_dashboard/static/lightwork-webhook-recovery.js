'use strict';
(function () {
  const host = document.getElementById('webhook-change-recovery');
  if (!host) return;
  const choice = host.querySelector('select'), status = host.querySelector('[role="status"]');
  const check = host.querySelector('[data-check]'), refresh = host.querySelector('[data-refresh]');
  const detail = host.querySelector('[data-detail]');
  let value = null, busy = false, generation = 0;
  function lock(on) { busy = on; choice.disabled = on || !value; refresh.disabled = on; check.disabled = on || !selected()?.can_reconcile; }
  function selected() { return value?.records.find(row => row.id === choice.value); }
  function describe() { const row = selected(); detail.textContent = row ? row.status + '. ' + (row.explanation || row.summary) : 'Choose a saved change to review its exact recovery options.'; lock(busy); }
  async function request(path, body) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch('/settings/webhooks/recovery' + path, {method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal,
        headers: {'Accept': 'application/json', ...(body ? {'Content-Type': 'application/json'} : {})}, body: body ? JSON.stringify(body) : undefined});
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'The saved change could not be checked. Refresh before continuing.');
      return data;
    } finally { clearTimeout(timer); }
  }
  async function load(identity) {
    if (busy) return;
    const ticket = ++generation, chosen = identity || choice.value;
    lock(true); detail.textContent = '';
    try {
      const next = await request('');
      if (ticket !== generation) return;
      value = next; choice.replaceChildren(new Option('Choose a saved change', ''));
      next.records.forEach(row => choice.appendChild(new Option(row.label + ' · ' + row.status, row.id, false, row.id === chosen)));
      status.textContent = next.detail; describe();
    } catch (error) {
      if (ticket !== generation) return;
      value = null; choice.replaceChildren(new Option('Refresh to check saved changes', '')); status.textContent = error.message;
    } finally { lock(false); }
  }
  check.addEventListener('click', async () => {
    const row = selected(); if (busy || !row?.can_reconcile) return;
    const context = value.context, ticket = ++generation; let submitted = false, result, failure;
    lock(true);
    try {
      if (!window.mvConfirm || !await window.mvConfirm(row.summary + ' Record this verified check for “' + row.label + '”? No secret will be saved or sent again.', {okText: 'Record this check'})) return;
      if (ticket !== generation) return;
      submitted = true;
      result = await request('/' + encodeURIComponent(row.id) + '/check', {context, review: row.review, confirm: true});
    } catch (error) { failure = error; }
    finally { lock(false); }
    if (!submitted || ticket !== generation) return;
    await load(row.id);
    if (!value || value.context !== context) return;
    const checked = selected();
    status.textContent = result?.detail || (checked?.completed ?
      checked.status + '. The original saved outcome was checked after the response was lost. No change was repeated.' :
      (failure?.message || 'The outcome is uncertain.') + ' Refresh and review the saved result; no change was repeated.');
  });
  choice.addEventListener('change', describe); refresh.addEventListener('click', () => void load());
  document.addEventListener('lightwork:account-context-changed', () => { ++generation; value = null; choice.replaceChildren(new Option('Refresh to check saved changes', '')); detail.textContent = ''; lock(busy); if (!busy) void load(); });
  window.addEventListener('lightwork:product-state-changed', () => { if (!busy) void load(); });
  document.addEventListener('lightwork:product-operation-complete', () => { if (!busy) void load(); });
  lock(false); void load();
})();
