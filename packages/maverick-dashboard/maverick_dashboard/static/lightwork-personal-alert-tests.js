(function () {
  'use strict';
  const root = document.querySelector('[data-private-alert-test]');
  if (!root) return;
  const find = key => root.querySelector('[data-alert-test-' + key + ']');
  const choice = find('choice'), status = find('status'), details = find('details'), ack = find('ack');
  let context = '', generation = 0, busy = false, review = null, pending = '', controller = null;
  function storageKey() { return 'lightwork.private-alert-test.' + context; }
  function invalidate() { review = null; ack.checked = false; find('confirm').hidden = true; details.hidden = true; details.replaceChildren(); find('send').disabled = true; }
  function lock(value) { busy = value; choice.disabled = value; find('review').disabled = value || !choice.value; find('send').disabled = value || !review || !ack.checked; find('original').disabled = value; }
  function clear() { generation++; if (controller) controller.abort(); context = ''; pending = ''; invalidate(); choice.replaceChildren(); find('original').hidden = true; lock(false); }
  function message(text) { status.textContent = text; }
  async function request(action, body) {
    controller = new AbortController(); const current = controller, timer = setTimeout(() => current.abort(), 20000);
    try {
      const response = await fetch('/api/v1/notifications/personal/tests/' + action, {method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: current.signal,
        headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: JSON.stringify(body)});
      const raw = await response.text(); if (raw.length > 32768) throw new Error('The complete response could not be read. Nothing was repeated.');
      const value = JSON.parse(raw);
      if (!response.ok) { if ([401,403].includes(response.status)) clear(); throw new Error(typeof value.detail === 'string' ? value.detail : 'This private test was refused. Nothing was repeated.'); }
      if (value.context !== context) { clear(); throw new Error('Your account or workspace changed. Reload notifications before continuing.'); }
      return value;
    } finally { clearTimeout(timer); if (controller === current) controller = null; }
  }
  document.addEventListener('lightwork:personal-notifications-state', event => {
    const state = event.detail; if (!state || typeof state.context !== 'string' || !/^[a-f0-9]{64}$/.test(state.context)) { clear(); return; }
    if (context && context !== state.context) clear(); context = state.context;
    const selected = choice.value, rows = ((state.private_delivery || {}).channels || []).filter(row => row.available);
    choice.replaceChildren(); const placeholder = document.createElement('option'); placeholder.value = ''; placeholder.textContent = rows.length ? 'Choose a verified private account' : 'No private account is ready'; choice.append(placeholder);
    rows.forEach(row => { const option = document.createElement('option'); option.value = row.id; option.textContent = 'Your verified private ' + row.channel.charAt(0).toUpperCase() + row.channel.slice(1) + ' account'; choice.append(option); });
    if (rows.some(row => row.id === selected)) choice.value = selected;
    else invalidate();
    try { pending = sessionStorage.getItem(storageKey()) || ''; } catch (_) { /* Native original records remain. */ }
    find('original').hidden = !pending; lock(busy);
  });
  choice.addEventListener('change', () => { invalidate(); lock(busy); }); ack.addEventListener('change', () => lock(busy));
  find('review').addEventListener('click', async () => {
    if (busy || !choice.value || !context) return; const started = generation, selected = choice.value; invalidate(); lock(true);
    try {
      const value = await request('review', {context, link: selected});
      if (generation !== started || choice.value !== selected) return;
      [value.recipient, value.text, value.notice].forEach(text => { const paragraph = document.createElement('p'); paragraph.textContent = text; details.append(paragraph); });
      review = value; details.hidden = false; find('confirm').hidden = false; message('Read the complete test, then confirm. Nothing has been sent.');
    } catch (error) { message(error.message); } finally { lock(false); }
  });
  find('send').addEventListener('click', async () => {
    if (busy || !review || !ack.checked) return; const started = generation, token = review.token; pending = token;
    try { sessionStorage.setItem(storageKey(), token); } catch (_) { /* Native original records remain. */ }
    find('original').hidden = false; invalidate(); lock(true);
    try { const value = await request('send', {token, confirmed: true}); if (generation === started) message(value.message); }
    catch (_) { if (generation === started) message('The send reply could not be confirmed. Read the original result; this test was not repeated.'); }
    finally { lock(false); }
  });
  find('original').addEventListener('click', async () => {
    if (busy || !pending || !context) return; const started = generation; lock(true);
    try { const value = await request('original', {token: pending}); if (generation === started) message(value.message); }
    catch (error) { if (generation === started) message(error.message); } finally { lock(false); }
  });
  ['lightwork:workspace-changed', 'lightwork:account-context-changed', 'lightwork:personal-notifications-cleared'].forEach(name => document.addEventListener(name, clear));
  window.addEventListener('pagehide', clear);
}());
