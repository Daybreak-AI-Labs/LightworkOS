'use strict';
(function () {
  const host = document.getElementById('instruction-capture');
  if (!host) return;
  const form = document.getElementById('instruction-capture-request');
  const task = form.elements.namedItem('task');
  const choice = document.getElementById('instruction-capture-choice');
  const status = document.getElementById('instruction-capture-status');
  const review = document.getElementById('instruction-capture-review');
  const setup = document.getElementById('instruction-capture-setup');
  const read = document.getElementById('instruction-capture-read');
  const withdraw = document.getElementById('instruction-capture-withdraw');
  const finish = document.getElementById('instruction-capture-finish');
  const text = document.getElementById('instruction-capture-text');
  const download = document.getElementById('instruction-capture-download');
  let state = null, current = null, busy = false, generation = 0, pendingRefresh = false;
  function clear() { current = null; text.value = ''; download.removeAttribute('href'); download.hidden = true; review.hidden = true; }
  function display(value) {
    clear(); current = value; review.hidden = false;
    document.getElementById('instruction-capture-title').textContent = value.title;
    document.getElementById('instruction-capture-origin').textContent = value.status + ' · ' + value.when + ' · ' + value.model + ' · ' + value.specialist;
    document.getElementById('instruction-capture-limit').textContent = value.explanation || value.detail || 'No captured text is available for this record.';
    text.value = value.instructions || ''; text.hidden = !value.captured;
    download.hidden = !value.captured;
    if (value.captured) download.href = '/api/v1/learning/instructions/' + encodeURIComponent(value.id) + '/download';
    withdraw.disabled = busy || !value.can_withdraw; finish.hidden = !value.can_finish;
    finish.textContent = value.result_pending ? 'Resolve completed capture' : 'Finish capture request';
  }
  function lock(value) {
    busy = value;
    host.querySelectorAll('button,select').forEach(item => { item.disabled = value; });
    if (!value) {
      form.querySelector('button').disabled = !state?.enabled || !task.value;
      read.disabled = !choice.value; setup.hidden = !state?.can_configure;
      withdraw.disabled = !current?.can_withdraw;
      if (pendingRefresh) { pendingRefresh = false; void refresh(); }
    }
  }
  async function request(path, body) {
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch('/api/v1/learning/instructions' + path, {
        method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal,
        headers: {'Accept': 'application/json', ...(body ? {'Content-Type': 'application/json'} : {})},
        body: body ? JSON.stringify(body) : undefined,
      });
      const value = await response.json();
      if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'The instruction record could not be checked. Refresh before continuing.');
      return value;
    } finally { clearTimeout(deadline); }
  }
  async function refresh(selected) {
    if (busy) { pendingRefresh = true; return; }
    const chosen = selected || choice.value || new URLSearchParams(window.location.search).get('record') || '', oldTask = task.value, ticket = ++generation;
    clear(); lock(true);
    try {
      const value = await request('');
      if (ticket !== generation) return;
      state = value;
      task.replaceChildren(new Option('Choose a task', ''));
      value.tasks.forEach(row => task.appendChild(new Option(row.label, row.value, false, String(row.value) === oldTask)));
      choice.replaceChildren(new Option('Choose a saved record', ''));
      value.records.forEach(row => choice.appendChild(new Option(row.title + ' · ' + row.when + ' · ' + row.status, row.id, false, row.id === chosen)));
      document.getElementById('instruction-capture-setting').textContent = value.enabled ? 'Instruction recording is on. Each task still needs separate consent.' : 'Instruction recording is off. An installation administrator can turn it on here.';
      setup.textContent = value.enabled ? 'Turn instruction recording off' : 'Turn instruction recording on';
      status.textContent = value.detail;
    } catch (error) {
      state = null; task.replaceChildren(new Option('Refresh to check tasks', '')); choice.replaceChildren(new Option('Refresh to check records', ''));
      status.textContent = error.message;
    } finally { lock(false); }
  }
  async function inspect() {
    if (busy || !state || !choice.value) return;
    const selected = choice.value, ticket = ++generation;
    clear(); lock(true);
    try {
      const value = await request('/' + encodeURIComponent(selected));
      if (ticket === generation && choice.value === selected) { display(value); status.textContent = value.status; }
    } catch (error) {
      clear();
      const row = state.records.find(item => item.id === selected);
      if (row && ticket === generation) display({...row, captured: false, can_finish: false, explanation: error.message});
      status.textContent = error.message;
    } finally { lock(false); }
  }
  async function mutate(path, body, prompt, identity) {
    if (busy || !state) return;
    const context = state.context;
    let submitted = false, result, failure;
    lock(true);
    try {
      const okText = path === '' ? 'Keep the instructions' : path === '/setup' ? (body.enabled ? 'Allow recording' : 'Turn recording off')
        : path.endsWith('/withdraw') ? 'Withdraw capture' : 'Finish capture';
      if (!window.mvConfirm || !await window.mvConfirm(prompt, {okText})) return;
      submitted = true;
      clear();
      result = await request(path, {...body, context, confirm: true});
    } catch (error) {
      failure = error;
      if (submitted) {
        try {
          const checked = identity ? await request('/' + encodeURIComponent(identity)) : await request('');
          if (identity) result = {record: checked, detail: checked.status + '. The saved state was checked after the response was lost; no action was repeated.'};
          else if (checked.enabled === body.enabled) result = {detail: 'The current recording setting was checked after the response was lost. No action was repeated.'};
        } catch (_) { /* Unknown outcome: preserve explicit readback recovery. */ }
      }
    } finally { lock(false); }
    if (!submitted) return;
    await refresh(identity);
    if (result?.record && state?.context === context) {
      // Request results contain metadata only. Fetch exact private text only on Review.
      display(result.record);
      if (result.record.can_finish) result.detail += result.record.result_pending ? ' Select Resolve completed capture to check the original result.' : ' Select Finish capture request to complete the original request.';
    }
    status.textContent = result?.detail || (failure?.message + ' The action may have been recorded. Refresh and review its current state before trying again.');
  }
  form.addEventListener('submit', event => {
    event.preventDefault(); if (!task.value) return;
    const operation = Array.from(crypto.getRandomValues(new Uint8Array(16)), value => value.toString(16).padStart(2, '0')).join('');
    const label = task.selectedOptions[0].textContent;
    void mutate('', {task: Number(task.value), operation}, 'Keep the instructions from “' + label + '” on its next successful AI call started after your consent, within 24 hours? A call already in progress cannot be recorded. Your preferences and guidance learned from permitted earlier work may be included. This does not start work, make another AI call or enable learning. Only your account can review this local record.', 'ISC-' + operation);
  });
  setup.addEventListener('click', () => void mutate('/setup', {enabled: !state.enabled, previous: state.enabled},
    state.enabled ? 'Turn instruction recording off? Existing records remain available for review or withdrawal. New calls will retain no instruction text.' : 'Allow instruction recording on this local installation? Private instruction text may be kept only after each task is separately authorized. No work or learning starts.', null));
  withdraw.addEventListener('click', () => {
    if (current) void mutate('/' + encodeURIComponent(current.id) + '/withdraw', {revision: current.revision}, 'Withdraw this capture? Its instruction text will no longer be available here. The decision record remains. Downloaded files are not recalled.', current.id);
  });
  finish.addEventListener('click', () => {
    if (current?.can_finish) void mutate('/' + encodeURIComponent(current.id) + '/finish', {revision: current.revision}, current.result_pending ? 'Resolve this completed call as withheld? No instruction text is available, no call is repeated, and no later call will be captured.' : 'Finish the original capture request for this task? It will wait for one successful model call started after this completion, within the original 24-hour limit. No new work starts.', current.id);
  });
  task.addEventListener('change', () => lock(false));
  choice.addEventListener('change', () => { ++generation; clear(); lock(false); });
  read.addEventListener('click', () => void inspect());
  document.getElementById('instruction-capture-refresh').addEventListener('click', () => void refresh());
  window.addEventListener('lightwork:product-state-changed', () => void refresh());
  document.addEventListener('lightwork:product-operation-complete', () => void refresh());
  document.addEventListener('lightwork:account-context-changed', () => { ++generation; clear(); state = null; void refresh(); });
  window.addEventListener('pagehide', clear);
  void refresh().then(() => { if (new URLSearchParams(window.location.search).has('record') && choice.value) void inspect(); });
})();
