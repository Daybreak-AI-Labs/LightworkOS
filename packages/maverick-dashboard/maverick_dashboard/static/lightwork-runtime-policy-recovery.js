(() => {
  'use strict';
  const root = document.getElementById('runtime-policy-recovery');
  if (!root) return;
  const $ = id => document.getElementById('rpr-' + id);
  const status = $('status'), copies = $('copy'), originals = $('request');
  const api = '/api/v1/runtime-policy-recovery/';
  let context = null, generation = 0, review = null, busy = false, next = null, controller = null, pending = null;
  const date = at => new Date(at * 1000).toLocaleString();
  const say = text => { status.textContent = text; };
  const invalidate = () => { review = null; $('review-panel').hidden = true; $('confirm').checked = false; $('apply').disabled = true; };
  function clear() {
    generation++; controller?.abort(); context = null; pending = null; busy = false; invalidate();
    copies.replaceChildren(new Option('Choose a saved copy', ''));
    originals.replaceChildren(new Option('Choose an original request', ''));
    $('before').replaceChildren(); $('after').replaceChildren(); $('controls').hidden = true;
    $('original-result').textContent = ''; $('notice').textContent = ''; say('Your account, workspace or access changed. Load current choices again.');
  }
  async function request(path, body, signal) {
    const headers = {Accept: 'application/json'};
    if (body) headers['Content-Type'] = 'application/json';
    if (context) headers['X-Lightwork-Policy-Context'] = context;
    const response = await fetch(api + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', headers, body: body ? JSON.stringify(body) : undefined, signal});
    if (response.redirected || !response.headers.get('content-type')?.includes('application/json')) { clear(); throw Error('Sign in again before reading private settings.'); }
    const raw = await response.text();
    if (raw.length > 524288) throw Error('This complete response exceeds the supported size. Nothing was omitted from the review.');
    const value = JSON.parse(raw);
    if (!response.ok) {
      if ([401, 403, 409].includes(response.status) && /account|workspace|access|permission|administrator|sign.in/i.test(String(value.detail))) clear();
      throw Error(typeof value.detail === 'string' ? value.detail : 'This step could not be completed. Keep your choices and read the original result before another decision.');
    }
    if (context && value.context !== context) { clear(); throw Error('Your account or workspace changed. Private choices were cleared.'); }
    return value;
  }
  async function work(fn) {
    if (busy) return;
    busy = true; controller = new AbortController(); const started = generation;
    const timer = setTimeout(() => controller?.abort(), 15000);
    try { await fn(controller.signal, started); } catch (error) { if (started === generation) say(error.message || 'The reply was interrupted. Read the original request before another decision.'); }
    finally { clearTimeout(timer); if (started === generation) { busy = false; controller = null; } }
  }
  function fill(select, rows, label, append = false) {
    const previous = select.value;
    if (!append) select.replaceChildren(new Option(label, ''));
    for (const row of rows) if (![...select.options].some(option => option.value === row.value)) select.add(new Option(date(row.at) + (row.available === false ? ' — activity unconfirmed' : ''), row.value));
    if ([...select.options].some(option => option.value === previous)) select.value = previous;
  }
  async function load(signal, started, isCurrent = () => true, offset = 0) {
    const value = await request('catalog?offset=' + offset, null, signal);
    if (started !== generation || !isCurrent()) return false;
    context = value.context;
    if (!offset) { fill(copies, value.copies, 'Choose a saved copy'); $('notice').textContent = value.notice; $('controls').hidden = !value.enabled; }
    fill(originals, value.requests, 'Choose an original request', offset > 0); next = value.next_offset; $('more').hidden = next === null;
    if (pending && ![...originals.options].some(option => option.value === pending)) originals.add(new Option('My interrupted request', pending));
    if (!offset) say(value.enabled ? (value.copies.length ? 'Choose a retained copy for a complete review. Nothing has been restored.' : 'No trusted saved safety-settings copy is available. Nothing can be restored or reset from defaults.') : 'Backup and recovery is disabled. Your original request records remain readable.');
    return true;
  }
  function render(host, value, depth = 0) {
    if (depth > 12) throw Error('This full review contains an unsupported structure. Nothing was omitted or restored.');
    if (Array.isArray(value)) {
      if (!value.length) { const p = document.createElement('p'); p.textContent = 'None saved'; host.append(p); }
      for (const item of value) {
        const block = document.createElement('div'); block.className = 'panel'; block.style.cssText = 'padding:.6rem; margin:.5rem 0; overflow-wrap:anywhere; white-space:pre-wrap';
        if (item && typeof item === 'object' && !Array.isArray(item)) {
          if (Object.keys(item).sort().join(',') !== 'label,value' || typeof item.label !== 'string') throw Error('This complete review cannot be displayed. Nothing was restored.');
          const title = document.createElement('strong'); title.textContent = item.label; block.append(title); render(block, item.value, depth + 1);
        } else render(block, item, depth + 1);
        host.append(block);
      }
    } else if (value !== null && typeof value === 'object') throw Error('This complete review cannot be displayed. Nothing was restored.');
    else { const p = document.createElement('p'); p.style.cssText = 'white-space:pre-wrap;overflow-wrap:anywhere'; p.textContent = typeof value === 'boolean' ? value ? 'Yes' : 'No' : value === null ? 'Not set' : String(value); host.append(p); }
  }
  $('refresh').addEventListener('click', () => work((signal, started) => load(signal, started)));
  $('more').addEventListener('click', () => { if (next !== null) work((signal, started) => load(signal, started, () => true, next)); });
  copies.addEventListener('change', () => { generation++; controller?.abort(); busy = false; invalidate(); });
  $('review').addEventListener('click', () => work(async (signal, started) => {
    if (!copies.value || !context) throw Error('Load current choices and choose a saved copy.');
    const chosen = copies.value; invalidate();
    const value = await request('review', {snapshot: chosen, context}, signal);
    if (started !== generation || chosen !== copies.value) return;
    $('before').replaceChildren(); $('after').replaceChildren(); render($('before'), value.changes.before); render($('after'), value.changes.after);
    review = value; $('review-panel').hidden = false; say('Review every setting above. Nothing has been restored.'); $('confirm').focus();
  }));
  $('confirm').addEventListener('change', () => { $('apply').disabled = !review || !$('confirm').checked; });
  $('cancel').addEventListener('click', () => { invalidate(); say('Review cancelled. Nothing was restored.'); copies.focus(); });
  $('apply').addEventListener('click', () => work(async (signal, started) => {
    if (!review || !$('confirm').checked) return;
    const original = review; pending = original.operation;
    if (![...originals.options].some(option => option.value === pending)) originals.add(new Option('My latest reviewed request', pending));
    originals.value = pending; $('originals').open = true; invalidate();
    say('Restoring the exact reviewed copy. If the reply is interrupted, read this original request before another decision.');
    const result = await request('apply', {token: original.token, confirmed: true}, signal);
    if (started !== generation) return;
    $('original-result').textContent = result.message; say(result.message);
  }));
  $('read').addEventListener('click', () => work(async (signal, started) => {
    if (!originals.value || !context) throw Error('Load your original requests and choose one.');
    const chosen = originals.value; const result = await request('original/' + chosen, null, signal);
    if (started !== generation || chosen !== originals.value) return;
    $('original-result').textContent = result.message; say(result.message);
  }));
  window.LightworkRuntimePolicyRecovery = {open: async (expected, original, isCurrent = () => true) => {
    if (busy || !isCurrent()) return false;
    const started = generation; const check = new AbortController(); const timer = setTimeout(() => check.abort(), 15000);
    try {
      const value = await request('catalog', null, check.signal);
      if (started !== generation || !isCurrent() || value.context !== expected) return false;
      if (!context) { if (!await load(check.signal, started, isCurrent)) return false; }
      if (context !== expected || started !== generation || !isCurrent()) return false;
      if (original) $('originals').open = true;
      root.scrollIntoView({block: 'start'}); (original ? originals : copies).focus(); return true;
    } catch (_) { return false; } finally { clearTimeout(timer); }
  }};
  window.addEventListener('lightwork:context-changed', clear);
  for (const event of ['lightwork:workspace-changed', 'lightwork:account-context-changed']) document.addEventListener(event, clear);
  document.addEventListener('lightwork:copilot-context-changed', event => {
    if (event.detail?.reason === 'selection') { if (context && !busy) work(async (signal, started) => { await request('catalog', null, signal); if (started === generation) invalidate(); }); }
    else clear();
  });
})();
