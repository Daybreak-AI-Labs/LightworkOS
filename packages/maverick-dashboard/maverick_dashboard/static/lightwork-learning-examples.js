/* Recent example inbox. Native run pages own detail, review and changes. */
(function () {
  'use strict';
  const list = document.getElementById('lex-list');
  if (!list) return;
  const status = document.getElementById('lex-status');
  const filter = document.getElementById('lex-filter');
  const refresh = document.getElementById('lex-refresh');
  const older = document.getElementById('lex-older');
  const labels = {
    enrolled: 'Being collected', capturing: 'Being collected', paused: 'Being collected',
    awaiting_review: 'Needs review', accepted: 'Reviewed and accepted', rejected: 'Not accepted',
    withdrawn: 'Use stopped', expired: 'Expired', unusable: 'Not usable', audit_pending: 'Waiting for confirmation'
  };
  let rows = [], busy = false, cursor = null;
  function node(tag, cls, value) {
    const element = document.createElement(tag);
    if (cls) element.className = cls;
    if (value !== undefined) element.textContent = value;
    return element;
  }
  function category(row) {
    if (row.audit_status !== 'delivered' || row.status === 'audit_pending') return 'review';
    if (row.status === 'awaiting_review') return 'review';
    if (row.status === 'accepted') return row.training_available ? 'ready' : 'permission';
    if (['withdrawn', 'expired', 'rejected', 'unusable'].includes(row.status)) return 'stopped';
    return 'all';
  }
  function detail(row) {
    if (row.audit_status !== 'delivered') return 'Its record is still being confirmed. Check its run before making another decision.';
    if (row.status === 'accepted' && row.training_available) return 'Allowed for learning now. Its permission will be checked again when used.';
    if (row.status === 'accepted') return 'Review the separate learning permission on its run page.';
    if (row.status === 'awaiting_review') return 'Review the actual inputs, actions and results on its run page.';
    if (row.status === 'withdrawn') return 'Future learning and learned actions from this example are stopped.';
    if (row.status === 'expired') return 'Its retention period ended; existing copies are not erased.';
    return 'Open the run to check its current status.';
  }
  function render() {
    list.replaceChildren();
    const selected = filter.value;
    const visible = rows.filter(row => selected === 'all' || category(row) === selected);
    for (const row of visible) {
      const item = node('li', 'lex__row');
      const body = node('div');
      body.append(node('div', 'lex__name', row.flow_name || 'Untitled flow'));
      const when = row.started && typeof window.mvWhen === 'function' ? window.mvWhen(row.started) : '';
      body.append(node('p', 'lex__meta', (labels[row.status] || 'Status unavailable') + (when ? ' · ' + when : '')));
      body.append(node('p', 'lex__meta', detail(row)));
      const link = node('a', 'btn btn--ghost', 'Open example');
      link.href = '/flows/' + encodeURIComponent(row.flow_id) + '/runs/' + encodeURIComponent(row.run_id);
      item.append(body, link); list.append(item);
    }
    status.textContent = !rows.length ? 'No learning examples found. Start a flow and choose to keep a run at its first approval.'
      : !visible.length ? 'No examples match this view.'
      : 'Showing ' + visible.length + ' of ' + rows.length + ' loaded examples' + (cursor ? '. Show older examples for more.' : '.');
  }
  async function load(append) {
    if (busy) return;
    if (!append) { rows = []; cursor = null; list.replaceChildren(); }
    busy = true; refresh.disabled = true; filter.disabled = true; older.disabled = true;
    status.textContent = 'Checking your examples…';
    let accessChanged = false;
    try {
      const response = await fetch('/api/v1/learning/examples' + (append && cursor ? '?cursor=' + encodeURIComponent(cursor) : ''),
        {credentials: 'same-origin', cache: 'no-store',
        headers: {Accept: 'application/json'}});
      if (!response.ok) { accessChanged = response.status === 401 || response.status === 403; throw new Error('unavailable'); }
      const result = await response.json();
      const page = Array.isArray(result.examples) ? result.examples : [];
      rows = Array.from(new Map((append ? rows.concat(page) : page)
        .map(row => [row.flow_id + '\u0000' + row.run_id, row])).values());
      cursor = typeof result.next_cursor === 'string' ? result.next_cursor : null;
      older.hidden = !cursor;
      if (result.available === false) {
        rows = []; cursor = null; list.replaceChildren(); older.hidden = true;
        status.textContent = 'Example collection is off. Ask an administrator to turn it on in Settings before keeping new examples.';
      } else render();
    } catch (_) {
      if (!append || accessChanged) { rows = []; cursor = null; list.replaceChildren(); older.hidden = true; }
      status.textContent = accessChanged ? 'Your access changed. Sign in again and refresh examples.'
        : 'Examples could not be checked. Refresh when your connection is available.';
    } finally {
      busy = false; refresh.disabled = false; filter.disabled = false; older.disabled = false;
    }
  }
  filter.addEventListener('change', render);
  refresh.addEventListener('click', () => load(false));
  older.addEventListener('click', () => load(true));
  load(false);
})();
