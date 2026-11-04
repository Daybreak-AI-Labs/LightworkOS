'use strict';
(function () {
  const host = document.getElementById('local-flow-release');
  const form = document.getElementById('local-flow-release-form');
  const status = document.getElementById('local-flow-release-status');
  if (!host || !form || !status) return;
  let state = null, busy = false;
  const flow = form.elements.namedItem('flow_id');
  const run = form.elements.namedItem('practice_run');
  const comparison = form.elements.namedItem('comparison_id');
  const rules = document.getElementById('local-flow-release-rules');
  const open = document.getElementById('local-flow-release-open');
  const current = document.getElementById('local-flow-release-current');
  const included = document.getElementById('local-flow-release-included');
  function selected() { return state?.flows.find(row => row.id === flow.value); }
  function lock(value) { busy = value; form.querySelectorAll('button,input,select').forEach(control => { control.disabled = value; }); }
  async function request(path, body) {
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch('/api/v1/research/local-flow-release' + path, {
        method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal,
        headers: {'Accept': 'application/json', ...(body ? {'Content-Type': 'application/json'} : {})},
        body: body ? JSON.stringify(body) : undefined,
      });
      const value = await response.json();
      if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'The saved release could not be checked. Refresh before trying again.');
      return value;
    } finally { clearTimeout(deadline); }
  }
  function show() {
    const row = selected();
    const chosenRun = run.value;
    const chosenComparison = comparison.value;
    comparison.replaceChildren(new Option('Readiness only; no answer comparison', ''));
    (row?.comparisons || []).forEach(item => comparison.appendChild(new Option(item.cases + ' known cases · compared ' + new Date(item.when * 1000).toLocaleString(), item.id, false, item.id === chosenComparison)));
    document.getElementById('local-flow-release-compare').href = '/learning/flow-checks' + (row ? '?workflow=' + encodeURIComponent(row.id) : '');
    run.replaceChildren(new Option('Choose a practice run', ''));
    (row?.practice_runs || []).forEach(item => run.appendChild(new Option(row.name + ' · version ' + row.version + ' · practice completed ' + new Date(item.created * 1000).toLocaleString(), item.id, false, item.id === chosenRun)));
    current.textContent = row ? 'Saved version ' + row.version + ' · ' + (row.rules_only ? 'Complete workflow uses learned rules only' : row.root_rules_only ? 'Prepare rules-only behavior in the included workflows below' : 'May fall back to AI') + ' · ' + (row.published ? 'Published baseline version ' + row.baseline_version : 'Publish a baseline first') : '';
    included.replaceChildren(); included.hidden = !(row?.included_workflows || []).length;
    (row?.included_workflows || []).forEach(child => {
      const item = document.createElement('li'), link = document.createElement('a');
      link.href = child.href; link.textContent = child.name + ' · version ' + child.version;
      item.append(link, document.createTextNode(child.rules_only ? ' · uses learned rules only' : ' · prepare a rules-only draft before release'));
      included.appendChild(item);
    });
    open.hidden = !row; if (row) open.href = '/flows/designer/' + encodeURIComponent(row.id);
    rules.disabled = busy || !row || row.root_rules_only;
    form.querySelector('[type="submit"]').disabled = busy || !row || !row.rules_only || !row.practice_runs.length || !state?.enabled;
  }
  async function refresh() {
    if (busy) return;
    lock(true);
    const chosen = flow.value || new URLSearchParams(window.location.search).get('release_flow') || '';
    try {
      state = await request('');
      if (window.location.hash === '#local-flow-release') host.open = true;
      flow.replaceChildren(new Option('Choose a workflow', ''));
      state.flows.forEach(row => flow.appendChild(new Option(row.name + ' · version ' + row.version, row.id, false, row.id === chosen)));
      status.textContent = state.enabled ? state.detail : 'Release decisions are turned off. An installation administrator can enable them in All settings; your workflow draft can still be prepared.';
    } catch (_) { state = null; flow.replaceChildren(new Option('Refresh to check saved workflows', '')); status.textContent = 'Saved workflows could not be checked. Refresh when Lightwork is responding again.'; }
    finally { lock(false); show(); }
  }
  async function change(path) {
    if (busy) return;
    const row = selected();
    if (!row) return;
    const prompt = path === '/rules-only' ? 'Save a rule-only draft? If its learned rules cannot answer an input, it will stop instead of calling AI. Existing publication is unchanged.' : 'Authorize a current independent release administrator to publish only this exact reviewed version and restore its retained baseline? Its instructions, teaching examples and any selected real-case inputs, expected answers and comparison results are shared for that review. No release starts now.';
    const practice = run.value;
    const compared = comparison.value;
    const operationContext = state.context;
    let submitted = false, outcome = '';
    lock(true);
    try {
      const confirm = typeof window.mvConfirm === 'function' ? await window.mvConfirm(prompt, {okText: path === '/rules-only' ? 'Save rule-only draft' : 'Request release review'}) : window.confirm(prompt);
      if (!confirm) return;
      submitted = true;
      const result = await request(path, {context: state.context, confirm: true, flow_id: row.id,
        version: row.version, revision: row.revision, practice_run: path === '/prepare' ? practice : '',
        bundle_sha: row.bundle_sha,
        comparison_id: path === '/prepare' ? compared : ''});
      outcome = result.detail;
    } catch (_) { outcome = 'The reply could not be confirmed. No action was repeated. Inspect the refreshed saved versions and release decisions before continuing.'; }
    finally { lock(false); show(); }
    if (submitted) {
      await refresh();
      if (!state) outcome += ' Current saved state is unavailable; refresh before continuing.';
      else if (state.context !== operationContext) outcome = 'Your account or workspace changed. Review its current saved state before continuing.';
      else {
        const saved = selected();
        const prepared = state.prepared;
        if (path === '/rules-only' && saved?.revision === row.revision && saved?.version === row.version + 1 && saved?.root_rules_only)
          outcome += ' The current draft uses learned rules only. Check included workflows before publishing or practicing the complete version.';
        if (path === '/prepare' && prepared?.flow_id === row.id && prepared?.version === row.version && prepared?.bundle_sha === row.bundle_sha && prepared?.practice_run === practice && prepared?.comparison_id === compared)
          outcome = 'The exact release review is prepared and verified. Request independent approval below; no publication changed.';
      }
      status.textContent = outcome;
      document.dispatchEvent(new CustomEvent('lightwork:product-operation-complete', {detail: {source: 'local-flow-release'}}));
      document.getElementById('research-promotions-refresh')?.click();
    }
  }
  flow.addEventListener('change', show);
  rules.addEventListener('click', () => change('/rules-only'));
  form.addEventListener('submit', event => { event.preventDefault(); if (form.reportValidity()) change('/prepare'); });
  document.getElementById('local-flow-release-refresh').addEventListener('click', refresh);
  document.addEventListener('lightwork:product-operation-complete', event => { if (event.detail?.source !== 'local-flow-release') refresh(); });
  refresh();
})();
