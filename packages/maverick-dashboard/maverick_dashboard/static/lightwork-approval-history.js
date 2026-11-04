(function () {
  'use strict';
  var button = document.getElementById('request-decision-more'); if (!button) return;
  var host = document.getElementById('request-decision-rows'), status = document.getElementById('request-decision-status'), cursor = null;
  button.addEventListener('click', async function () {
    button.disabled = true; status.textContent = 'Loading your decision history…';
    var controller = new AbortController(), deadline = setTimeout(function () { controller.abort(); }, 12000);
    try {
      var response = await fetch('/api/v1/approvals/history' + (cursor ? '?before_id=' + cursor : ''), {credentials: 'same-origin', cache: 'no-store', signal: controller.signal});
      if (!response.ok || response.redirected) { if ([401, 403].includes(response.status) || response.redirected) host.replaceChildren(); throw new Error('unavailable'); }
      var data = await response.json(); if (!Array.isArray(data.items)) throw new Error('unreadable');
      data.items.forEach(function (item) {
        var row = document.createElement('article'), title = document.createElement('h3'), state = document.createElement('p'), detail = document.createElement('p');
        title.textContent = item.action; state.textContent = 'Decision: ' + item.status + (item.decided_by ? ' by ' + item.decided_by : '') + (item.expires_at ? '. Request expires ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(item.expires_at) : new Date(item.expires_at * 1000).toLocaleString()) : ''); detail.textContent = item.summary;
        row.append(title, state, detail);
        if (item.before || item.after) { var preview = document.createElement('p'); preview.textContent = 'Reviewed change: ' + item.before + ' → ' + item.after; row.append(preview); }
        var execution = document.createElement('p'); execution.textContent = item.execution; row.append(execution);
        if (item.goal_id) { var link = document.createElement('a'); link.href = '/chat/goal/' + item.goal_id; link.textContent = 'Review current task'; row.append(link); }
        host.append(row);
      });
      cursor = data.before_id; button.hidden = !data.has_more; button.textContent = 'Load older decisions';
      status.textContent = data.items.length ? 'Your request history is up to date for this page.' : 'No decisions on your requests were found in this page.';
    } catch (_) { status.textContent = 'Your decision history could not be loaded. Try again.'; }
    finally { clearTimeout(deadline); button.disabled = false; }
  });
}());
