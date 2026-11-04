(function () {
  'use strict';
  var root = document.getElementById('my-work'); if (!root) return;
  var rows = document.getElementById('my-work-rows'), status = document.getElementById('my-work-status'), coverage = document.getElementById('my-work-coverage');
  var button = document.getElementById('my-work-refresh'), filter = document.getElementById('my-work-filter');
  var model = null, timer = null, loading = false, failures = 0, generation = 0, denied = false;
  function node(tag, value) { var element = document.createElement(tag); element.textContent = value; return element; }
  function render() {
    rows.replaceChildren(); if (!model) return;
    var visible = model.items.filter(function (item) { return filter.value === 'all' || item.kind === filter.value; });
    visible.forEach(function (item) {
      var row = node('article', ''), title = node(root.dataset.rowHeading || 'h2', item.title), detail = node('p', item.state + ' — ' + item.detail), link = node('a', item.action);
      if (typeof item.href !== 'string' || !item.href.startsWith('/') || item.href.startsWith('//')) return;
      link.href = item.href; row.append(title, detail, link); rows.append(row);
    });
    if (!visible.length) rows.append(node('p', 'No matching work appeared in the checked sources. Review coverage above before treating this as all clear.'));
  }
  async function refresh() {
    clearTimeout(timer); if (loading || document.hidden || denied) return;
    loading = true; button.disabled = true; var started = ++generation;
    var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 12000);
    try {
      var response = await fetch('/api/v1/my-work', {credentials: 'same-origin', cache: 'no-store', signal: controller.signal});
      if (response.redirected || [401,403].includes(response.status)) { denied = true; throw new Error('access'); }
      if (!response.ok) throw new Error('unavailable');
      var fresh = await response.json(); if (started !== generation) return;
      if (fresh.context !== root.dataset.context) { denied = true; throw new Error('context'); }
      if (!Array.isArray(fresh.items) || !Array.isArray(fresh.coverage)) throw new Error('unreadable');
      model = fresh; failures = 0; coverage.replaceChildren();
      fresh.coverage.forEach(function (source) { coverage.append(node('li', source.source + ': ' + source.state + (source.state === 'partial' ? ' — open the source to see earlier work.' : ''))); });
      render(); status.textContent = 'Last checked ' + window.mvTimeAbsolute(fresh.generated_at) + '. Status is a recorded observation; external delivery needs its own verification.';
    } catch (_) {
      failures++;
      if (denied) { model = null; rows.replaceChildren(); coverage.replaceChildren(); status.textContent = 'Your account or access changed. Reload to review work for the current workspace.'; }
      else status.textContent = 'Refresh failed. Displayed rows are last-known observations. Use Refresh status to retry.';
    } finally {
      clearTimeout(timeout); loading = false; button.disabled = denied;
      if (!denied && failures < 3 && !document.hidden) timer = setTimeout(refresh, 15000);
    }
  }
  button.addEventListener('click', function () { failures = 0; refresh(); }); filter.addEventListener('change', render);
  document.addEventListener('visibilitychange', function () { clearTimeout(timer); if (!document.hidden) refresh(); });
  window.addEventListener('pagehide', function () { ++generation; clearTimeout(timer); denied = true; });
  refresh();
}());
