(function () {
  'use strict';
  var root = document.getElementById('xa-executions');
  if (!root) return;
  var agent = root.dataset.agent, status = document.getElementById('xa-execution-status');
  var rows = document.getElementById('xa-execution-rows'), refresh = document.getElementById('xa-execution-refresh');
  var coverage = document.getElementById('xa-execution-coverage');
  var ask = document.getElementById('xa-execution-copilot'), busy = false, blocked = false, controller = null;
  function select(value) {
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail:{selection:value ? {kind:'external_agent', id:agent} : null}}));
  }
  function text(tag, value, parent) { var node = document.createElement(tag); node.textContent = value; parent.appendChild(node); return node; }
  function time(value) {
    return typeof value === 'number' && Number.isFinite(value)
      ? window.mvTimeAbsolute ? window.mvTimeAbsolute(value*1000) : new Date(value*1000).toLocaleString()
      : 'Time unavailable';
  }
  function render(data) {
    var older = rows.querySelector('[data-earlier-executions]'), wasOpen = older && older.open;
    var scope = data.execution_coverage;
    coverage.textContent = 'Showing '+scope.displayed_count+' of '+scope.retained_count+' retained records. Latest '+scope.limit+' at most, kept for '+(scope.retention_seconds/3600)+' hours. This is not a complete activity archive.';
    rows.replaceChildren();
    if (!data.execution_readback.length) {
      text('p', 'No connected changes remain in this local execution ledger. Older records may have expired.', rows);return;
    }
    var earlier = null;
    data.execution_readback.forEach(function (entry, index) {
      if (index === 3) {earlier = document.createElement('details');earlier.dataset.earlierExecutions = '';earlier.open = !!wasOpen;rows.appendChild(earlier);text('summary', 'Earlier retained changes ('+(data.execution_readback.length-3)+')',earlier);}
      var card = document.createElement('article');card.className = 'panel';card.style.marginTop = 'var(--space-3)';card.style.overflowWrap = 'anywhere';(earlier || rows).appendChild(card);
      text('h3', entry.connector+' · '+entry.action, card);
      text('p', entry.status, card).className = 'badge '+(entry.tone === 'active' ? 'active' : entry.tone === 'failure' ? 'failure' : 'idle');
      if (entry.notice) text('p', entry.notice, card);
      var dates = 'Requested '+time(entry.created_at);
      if (entry.claimed_at) dates += ' · Started '+time(entry.claimed_at);
      if (entry.finished_at) dates += ' · Recorded '+time(entry.finished_at);
      text('p', dates, card).className = 'muted';
      var reference = document.createElement('details');card.appendChild(reference);
      text('summary', 'Execution reference', reference);text('p', entry.execution_id, reference).style.overflowWrap = 'anywhere';
    });
  }
  async function load(open) {
    if (busy || blocked) return;
    busy = true;refresh.disabled = true;ask.disabled = true;
    controller = new AbortController();var timeout = setTimeout(function () {controller.abort();},15000);
    status.textContent = 'Checking saved connected changes…';
    try {
      var response = await fetch('/api/v1/external-agents/'+encodeURIComponent(agent), {credentials:'same-origin',cache:'no-store',signal:controller.signal});
      if ([401,403,404].indexOf(response.status)>=0) {
        blocked = true;rows.replaceChildren();coverage.textContent = '';select(false);
        throw new Error('This agent or your access changed. Reopen Outside agents to check your current access.');
      }
      if (!response.ok) throw new Error('Saved status could not be checked. Reload before deciding what to do next.');
      var data = await response.json();
      if (blocked || data.id !== agent || !Array.isArray(data.execution_readback) || data.execution_readback.length>20 || !data.execution_coverage)
        throw new Error('Saved status could not be confirmed. Reload before deciding what to do next.');
      render(data);status.textContent = 'Saved status is up to date. No connected change or retry was sent.';
      if (open) {select(true);var opener = document.getElementById('mv-copilot-fab');if (opener && opener.getAttribute('aria-expanded') !== 'true') opener.click();}
    } catch (error) {
      status.textContent = error.name === 'AbortError' ? 'Status could not be confirmed in time. No change or retry was sent. Reload saved status.'
        : error instanceof TypeError ? 'Could not connect to Lightwork. No change or retry was sent. Reload saved status.' : error.message;
    } finally {clearTimeout(timeout);controller = null;busy = false;refresh.disabled = blocked;ask.disabled = blocked;}
  }
  refresh.addEventListener('click', function () {load(false);});
  ask.addEventListener('click', function () {load(true);});
  window.addEventListener('pagehide', function () {blocked = true;if(controller)controller.abort();rows.replaceChildren();coverage.textContent = '';select(false);});
  window.addEventListener('pageshow', function(event){if(event.persisted)window.location.reload();});
  select(true);
}());
