/* Read-only startup evidence; refreshing never restarts or dispatches work. */
(function () {
  'use strict';
  var panel = document.getElementById('settings-runtime-status'); if (!panel) return;
  var summary = panel.querySelector('[data-runtime-summary]'), list = panel.querySelector('[data-runtime-items]');
  var button = panel.querySelector('[data-runtime-refresh]'), ids = [], controller = null, generation = 0;
  function add(tag, text, parent) { var item = document.createElement(tag); item.textContent = text; parent.appendChild(item); return item; }
  async function refresh() {
    if (controller) controller.abort();
    var started = ++generation; controller = new AbortController();
    var owned = controller, timeout = setTimeout(function () { owned.abort(); }, 15000);
    button.disabled = true; summary.textContent = 'Checking saved settings and recent service acknowledgements…';
    try {
      var query = new URLSearchParams(); ids.slice(0,100).forEach(function (id) { query.append('ids', id); });
      var response = await fetch('/api/v1/settings/runtime-status?' + query.toString(), {credentials:'same-origin', cache:'no-store', signal:owned.signal});
      if (!response.ok) throw new Error('unavailable');
      var data = await response.json(); if (started !== generation) return;
      list.replaceChildren();
      if (!data.enabled) { summary.textContent = data.message; return; }
      summary.textContent = 'Checked ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(data.checked_at) : new Date(data.checked_at * 1000).toLocaleString()) + '. ' + data.coverage;
      if (!data.items.length) { add('p', 'No saved restart-dependent settings are selected. New work reads current settings through its normal policy checks.', list); return; }
      data.items.forEach(function (item) {
        var section = add('section', '', list); add('h3', item.label, section);
        add('p', item.timing + '. ' + item.message, section);
        add('p', 'Affected area: ' + item.area + '. ' + item.scope, section);
        (item.processes || []).forEach(function (process) {
          add('p', process.consumer + ': startup revision ' + process.startup_revision.slice(0,12) +
            ', observed ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(process.checked_at) : new Date(process.checked_at * 1000).toLocaleString()) +
            (process.matches_saved ? ' — matches saved value.' : ' — restart still pending.'), section);
        });
      });
    } catch (_) { if (started === generation) summary.textContent = 'Runtime acknowledgement could not be confirmed. Your saved settings were not changed. Check the owning service and refresh here.'; }
    finally { clearTimeout(timeout); if (started === generation) { controller = null; button.disabled = false; } }
  }
  button.addEventListener('click', refresh);
  document.addEventListener('lightwork:settings-saved', function (event) { ids = event.detail.ids || []; refresh(); });
  window.addEventListener('pagehide', function () { generation += 1; if (controller) controller.abort(); });
}());
