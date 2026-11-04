/* Vendor link key: show its state and rotate it with a grace period. The key
   itself never reaches this page. Only installation administrators see it. */
(() => {
  'use strict';
  const root = document.getElementById('portal-key');
  if (!root) return;
  const api = '/api/v1/third-party/portal-routing-key';
  const el = (id) => document.getElementById('portal-key-' + id);
  let busy = false, state = null;
  const when = (seconds) => (window.mvTimeAbsolute ? window.mvTimeAbsolute(seconds) : new Date(seconds * 1000).toLocaleString());
  function render(data) {
    state = data;
    root.hidden = false;
    let text;
    if (data.managed_by_server) text = 'The link key is set on the server, so it is changed there.';
    else if (!data.configured) text = 'No link key has been made yet. Make one to give vendors working addresses.';
    else text = 'The link key was last changed ' + (data.rotated_at ? when(data.rotated_at) : 'by your installer') + '.';
    if (data.previous_keys_open) text += ' Older vendor addresses keep working until ' + when(data.grace_until) + '.';
    el('state').textContent = text;
    el('form').hidden = !!data.managed_by_server;
    el('rotate').textContent = data.configured ? 'Change the link key' : 'Make the link key';
    update();
  }
  function update() {
    el('rotate').disabled = busy || !state || state.managed_by_server || !el('confirm').checked;
  }
  async function load() {
    try {
      // A refusal (not an installation administrator) leaves it hidden.
      render(await window.mvFetchJSON(api, {cache: 'no-store'}));
    } catch (_) { /* stays hidden */ }
  }
  el('confirm').addEventListener('change', update);
  el('rotate').addEventListener('click', async () => {
    if (el('rotate').disabled) return;
    const hours = Number(el('grace').value);
    const ask = typeof window.mvConfirm === 'function' ? window.mvConfirm : null;
    const message = hours ? 'Change the vendor link key? Old vendor addresses keep working for the time you chose, then stop.'
                          : 'Change the vendor link key? Old vendor addresses stop working now.';
    if (ask && !(await ask(message, {okText: 'Change key'}))) return;
    busy = true; update();
    try {
      const response = await fetch(api + '/rotate', {method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
        body: JSON.stringify({confirm: true, grace_hours: hours})});
      if (!response.ok) {
        const reason = typeof window.mvErrorText === 'function' ? await window.mvErrorText(response, 'change the link key') : 'The link key could not be changed. Nothing was changed. Try again.';
        el('state').textContent = reason;
        return;
      }
      el('confirm').checked = false;
      render(await response.json());
      el('state').textContent = 'The link key was changed. ' + el('state').textContent;
    } catch (_) {
      el('state').textContent = 'The link key could not be changed. Refresh the page to check.';
    } finally { busy = false; update(); }
  });
  load();
})();
