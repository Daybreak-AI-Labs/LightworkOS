// Discover permitted business work and save native drafts; activation stays in Workflows.
(() => {
  'use strict';
  const root = document.getElementById('ekko-build');
  if (!root) return;
  const $ = id => document.getElementById(id);
  let generation = 0, context = '', enabled = false, busy = false, stopped = false;
  const scope = () => ({generation, device: window.LightworkEkkoDevice()});
  const current = value => value.generation === generation && value.device === window.LightworkEkkoDevice() && root.isConnected && location.pathname === '/ekko';
  const say = value => { $('ekko-build-message').textContent = value; };
  const el = (tag, value, style) => window.mvEl(tag, style || '', String(value));

  function lock(value) {
    busy = value;
    $('ekko-build-start').disabled = value || !enabled;
    $('ekko-build-scan').disabled = value;
    $('ekko-build-brief').disabled = value;
    $('ekko-build-stop').hidden = !value;
    root.setAttribute('aria-busy', String(value));
  }

  function reset() {
    generation++; context = ''; enabled = false; stopped = true;
    $('ekko-build-brief').value = ''; $('ekko-build-consent').checked = false;
    $('ekko-build-results').textContent = ''; $('ekko-build-sources').textContent = '';
    lock(false); say('Workspace or access changed. Use Find opportunities to check access again.');
  }

  async function request(path, body, original) {
    try {
      return await window.mvFetchJSON('/api/v1/ekko/build/' + path,
        {timeout: 60000, ...(body ? {method: 'POST', body} : {})}, 'find and build workflows');
    } catch (error) {
      if (current(original) && ([401,403].includes(error.status) || error.detail && error.detail.code === 'ekko_context_changed')) {
        window.LightworkEkkoDiscovery.close();
        document.dispatchEvent(new CustomEvent('lightwork:ekko-scope-reset'));
      }
      const detail = window.mvPlainDetail && window.mvPlainDetail(error.detail);
      throw new Error(detail || 'The result could not be confirmed. Use Find opportunities to inspect saved drafts before trying again.');
    }
  }

  async function options() {
    const original = scope();
    try {
      const value = await request('options', null, original);
      if (!current(original)) return;
      if (!value || !/^[a-f0-9]{64}$/.test(value.context || '') || typeof value.enabled !== 'boolean') throw new Error('Draft building could not be checked. Refresh this page.');
      context = value.context; enabled = value.enabled;
      $('ekko-build-off').hidden = enabled;
      $('ekko-build-availability').textContent = enabled ? 'Ready to discover and build private drafts. Nothing is published or run by building.' : 'Discovery is available; draft building is off.';
      lock(busy);
    } catch (error) { if (current(original)) say(error.message); }
  }

  function renderScan(value) {
    if (!value || !Array.isArray(value.proposals) || !Array.isArray(value.coverage) || !Array.isArray(value.missing) || !/^[a-f0-9]{64}$/.test(value.scan_revision || '')) throw new Error('Discovery could not be confirmed. Try Find opportunities again.');
    const list = $('ekko-build-results'); list.textContent = '';
    value.proposals.forEach(row => {
      const card = el('article', '', 'ekko-opportunity');
      card.appendChild(el('h3', row.label)); card.appendChild(el('p', row.source, 'ekko-note'));
      card.appendChild(el('p', row.state === 'existing' ? 'Existing workflow — kept as it is' : 'Ready for Ekko to build a draft', 'ekko-meta'));
      if (row.href && /^\/flows\/designer\/[A-Za-z0-9_-]+$/.test(row.href)) {
        const link = el('a', 'Review workflow', 'btn'); link.href = row.href; card.appendChild(link);
      }
      list.appendChild(card);
    });
    if (!value.proposals.length) list.appendChild(el('p', 'No business tasks are ready to build yet. Add work above or review a recorded opportunity.', 'ekko-note'));
    const sources = $('ekko-build-sources'); sources.textContent = '';
    [...value.coverage, ...value.missing].forEach(row => sources.appendChild(el('p', row.label + ': ' + row.message, 'ekko-note')));
    (value.connections || []).forEach(row => sources.appendChild(el('p', row.title + ': ' + row.reason, 'ekko-note')));
    if (value.missing.length) $('ekko-build-coverage').open = true;
  }

  async function discover(build) {
    if (busy) return;
    if (!context) await options();
    if (busy || !context) return;
    if (build && (!$('ekko-build-consent').checked || !enabled)) { say('Confirm that Ekko may save these workflow drafts before building.'); return; }
    const original = scope(), body = {device_id: original.device, context, brief: $('ekko-build-brief').value.trim()};
    let built = 0;
    stopped = false; lock(true); say('Finding business work and checking existing drafts…');
    try {
      let found = await request('scan', body, original);
      if (!current(original)) return;
      renderScan(found);
      if (!build) { say(found.ready + ' tasks ready to build; ' + found.existing + ' existing workflows.'); return; }
      for (let batch = 0; found.ready > 0 && !stopped && batch < 13; batch++) {
        say('Building workflows… ' + built + ' created in this pass. You can stop after the current batch.');
        const result = await request('drafts', {...body, scan_revision: found.scan_revision, acknowledge_draft_storage: true}, original);
        if (!current(original)) return;
        if (!result || !Array.isArray(result.results) || !Number.isInteger(result.built) || !Number.isInteger(result.blocked)) throw new Error('The build result could not be confirmed. Use Find opportunities to inspect saved drafts.');
        built += result.built;
        found = await request('scan', body, original);
        if (!current(original)) return;
        renderScan(found);
        if (result.blocked) {
          result.results.filter(row => row.state === 'blocked').forEach(row => $('ekko-build-sources').appendChild(el('p', row.label + ': ' + row.message, 'ekko-note')));
          $('ekko-build-coverage').open = true;
          say(built + ' workflows built. Some tasks need attention; inspect the details before continuing.'); return;
        }
      }
      say(built + ' workflows built; ' + found.existing + ' available to review. ' +
        (stopped ? 'Stopped after the last confirmed batch. ' : '') + (found.ready ? found.ready + ' tasks remain. ' : '') + 'Nothing was published or run.');
    } catch (error) { if (current(original)) say(error.message + ' Saved workflows are kept. Your additional task descriptions are still here.'); }
    finally { if (current(original)) lock(false); }
  }

  $('ekko-build-start').addEventListener('click', () => discover(true));
  $('ekko-build-scan').addEventListener('click', () => discover(false));
  $('ekko-build-stop').addEventListener('click', () => { stopped = true; say('Stopping after the current batch. Already saved drafts are kept.'); });
  document.addEventListener('lightwork:ekko-scope-reset', reset);
  document.addEventListener('lightwork:ekko-build-review', () => { $('ekko-build-heading').focus(); options(); });
  options();
})();
