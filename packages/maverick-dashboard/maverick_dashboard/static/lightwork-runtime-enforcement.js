/* Protected native safeguard readback. No execution or replay controls. */
(() => {
  'use strict';
  const root = document.getElementById('runtime-enforcement');
  if (!root) return;
  const status = root.querySelector('[data-runtime-activity-status]');
  const items = root.querySelector('[data-runtime-activity-items]');
  const refresh = root.querySelector('[data-runtime-activity-refresh]');
  const previous = root.querySelector('[data-runtime-activity-previous]');
  const next = root.querySelector('[data-runtime-activity-next]');
  let generation = 0, offset = 0, context = '', busy = false, controller;
  const clear = () => {
    generation++; context = ''; offset = 0; items.replaceChildren();
    controller?.abort(); previous.hidden = next.hidden = true;
    status.textContent = 'Your account, workspace or access changed. Read current activity after signing in again.';
  };
  for (const event of ['workspace-changed', 'account-context-changed']) document.addEventListener(event, clear);
  for (const event of ['lightwork:workspace-changed', 'lightwork:account-context-changed']) window.addEventListener(event, clear);
  const add = (parent, tag, text) => { const node = document.createElement(tag); node.textContent = text; parent.append(node); return node; };
  const choices = { allow: 'Allowed', block: 'Stopped', restrict: 'Restricted', review: 'Needs review', redact: 'Hidden information removed' };
  function render(data) {
    items.replaceChildren();
    for (const row of data.items) {
      const card = add(items, 'article', ''); card.className = 'glass-card'; card.style.overflowWrap = 'anywhere';
      add(card, 'h4', row.system); add(card, 'p', row.meaning);
      add(card, 'p', new Date(row.time * 1000).toLocaleString() + ' · Safeguard choice: ' + (choices[row.checked_choice] || 'Not confirmed'));
      add(card, 'p', row.source_current ? 'Recorded for the current AI system version.' : 'Historical activity: the AI system version changed or is unavailable.');
      add(card, 'p', `${row.rules_checked} matched rules · ${row.controls_checked} named controls`);
      const details = add(card, 'details', ''); add(details, 'summary', 'Technical evidence');
      for (const [name, value] of Object.entries(row.evidence)) add(details, 'p', name.replaceAll('_', ' ') + ': ' + String(value));
    }
    if (!data.items.length) add(items, 'p', 'No saved connection attempts are shown. This does not prove that no outside action occurred.');
    previous.hidden = data.offset === 0; next.hidden = !data.has_more;
    status.textContent = `Showing ${data.items.length ? data.offset + 1 : 0}–${data.offset + data.items.length} of ${data.total} saved attempts. ` + data.notice;
  }
  async function load(expected = '', isCurrent = () => true) {
    if (busy || !isCurrent()) return false;
    busy = true; refresh.disabled = previous.disabled = next.disabled = true;
    const owned = ++generation; controller = new AbortController();
    status.textContent = 'Reading saved safeguard activity…';
    try {
      const response = await fetch('/api/v1/assurance/runtime-enforcement?offset=' + offset,
        { credentials: 'same-origin', cache: 'no-store', signal: controller.signal, headers: { Accept: 'application/json' } });
      if (owned !== generation || !isCurrent()) return false;
      if (!response.ok || response.redirected || !(response.headers.get('content-type') || '').includes('application/json')) {
        if ([401, 403, 409].includes(response.status)) { clear(); return false; }
        throw new Error('Saved activity could not be read. Nothing was sent or repeated.');
      }
      const data = await response.json();
      if (owned !== generation || !isCurrent()) return false;
      if (!/^[a-f0-9]{64}$/.test(data.context) || (expected && expected !== data.context)
          || (context && context !== data.context)) { clear(); return false; }
      context = data.context; render(data); return true;
    } catch (error) {
      if (owned === generation && error.name !== 'AbortError') status.textContent = 'Saved activity could not be read. Nothing was sent or repeated. Read current activity again when access is available.';
      return false;
    } finally {
      busy = false; refresh.disabled = previous.disabled = next.disabled = false;
    }
  }
  refresh.addEventListener('click', () => { offset = 0; load(); });
  previous.addEventListener('click', () => { offset = Math.max(0, offset - 50); load(); });
  next.addEventListener('click', () => { offset += 50; load(); });
  window.LightworkRuntimeEnforcement = Object.freeze({
    async open(expectedContext, isCurrent) {
      if (!/^[a-f0-9]{64}$/.test(expectedContext) || typeof isCurrent !== 'function' || !isCurrent()) return false;
      if (!await load(expectedContext, isCurrent) || !isCurrent()) return false;
      root.scrollIntoView({ block: 'start' }); refresh.focus(); return true;
    }
  });
})();
