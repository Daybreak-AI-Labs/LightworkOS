(() => {
  'use strict';
  const panel = document.querySelector('[data-channel-message-tests]');
  if (!panel) return;
  const find = name => panel.querySelector('[data-cmt-' + name + ']');
  const channel = find('channel'), choice = find('choice'), originals = find('original'), host = find('review-host');
  const base = '/api/v1/channels/message-test', supported = ['telegram', 'discord', 'whatsapp_cloud', 'mattermost'];
  let context = panel.dataset.context, generation = 0, reviewGeneration = 0, busy = false, next = '', historyNext = '', prepared = null, pending = '';
  const controllers = new Set(), say = text => { find('status').textContent = text; };
  const key = () => 'lightwork-chat-test-original:' + context, stamp = () => [context, reviewGeneration, channel.value, choice.value].join('|');
  function discard() { prepared = null; host.replaceChildren(); host.hidden = true; }
  function controls() {
    panel.querySelectorAll('button').forEach(button => { button.disabled = busy || !context; });
    find('review').disabled = busy || !context || !choice.value; find('read').disabled = busy || !context || !originals.value;
    const send = host.querySelector('[data-cmt-send]'), confirm = host.querySelector('[data-cmt-confirm]');
    if (send) send.disabled = busy || !prepared || !confirm?.checked;
  }
  function clear() {
    generation += 1; controllers.forEach(controller => controller.abort()); controllers.clear();
    try { sessionStorage.removeItem(key()); } catch (_) { /* Native history remains. */ }
    context = ''; pending = ''; next = ''; historyNext = ''; discard();
    choice.replaceChildren(new Option('Read conversations first…', '')); originals.replaceChildren(new Option('No original selected', ''));
    find('outcome').textContent = ''; say('Your account or access changed. Private conversation choices and outcomes were cleared. Reload Channels to continue.'); controls();
  }
  async function call(path, body) {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 20000); controllers.add(controller);
    try {
      const response = await fetch(base + path, { credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: controller.signal,
        ...(body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}) });
      if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('The chat response could not be read. Your choices are kept; read an original outcome after any interrupted send.');
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true }); let text = '', size = 0;
      while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength;
        if (size > 262144) { controller.abort(); throw new Error('This response is too large to review completely. Your choices are kept.'); }
        text += decoder.decode(part.value, { stream: true }); }
      text += decoder.decode(); const data = JSON.parse(text);
      if (!response.ok) {
        const detail = typeof data.detail === 'string' && data.detail.length <= 1200 ? data.detail : 'This chat operation was refused. Your choices are kept.';
        if ([401, 403].includes(response.status) || detail.startsWith('Your account or workspace changed')) clear();
        throw new Error(detail);
      }
      if (context && data.context && data.context !== context) { clear(); throw new Error('Your account or workspace changed. Private choices were cleared.'); }
      return data;
    } finally { clearTimeout(timeout); controllers.delete(controller); }
  }
  function options(target, choices, initial) {
    if (!Array.isArray(choices) || choices.length > 50 || choices.some(item => typeof item.value !== 'string' || typeof item.label !== 'string' || item.label.length > 400)) throw new Error('These choices could not be read completely. Read them again.');
    target.replaceChildren(new Option(initial, '')); choices.forEach(item => target.add(new Option(item.label, item.value)));
  }
  function retain(operation, label) {
    pending = operation; try { sessionStorage.setItem(key(), operation); } catch (_) { /* Native original history remains. */ }
    if (![...originals.options].some(option => option.value === operation)) originals.add(new Option(label || 'Interrupted or last confirmed test', operation));
    originals.value = operation; originals.closest('details').open = true; controls();
  }
  async function list(more) {
    if (busy || !context) return;
    const started = generation, current = stamp(); busy = true; controls(); discard();
    try { const data = await call('/conversations', { context, channel: channel.value, cursor: more ? next : '' });
      if (started !== generation || current !== stamp()) return;
      options(choice, data.choices, 'Choose a received conversation…'); next = data.next; find('more').hidden = !next; say(data.message);
    } catch (error) { if (started === generation) say(error.message); }
    finally { busy = false; controls(); }
  }
  async function history(more) {
    if (busy || !context) return;
    const started = generation, selected = originals.value; busy = true; controls();
    try { const data = await call('/history', { context, cursor: more ? historyNext : '' });
      if (started !== generation) return;
      const old = originals.selectedOptions[0]; options(originals, data.choices, 'Choose an original test…');
      if (selected && ![...originals.options].some(option => option.value === selected)) originals.add(new Option(old?.textContent || 'Last original test', selected));
      originals.value = selected; if (pending && !originals.value) retain(pending);
      historyNext = data.next; find('history-more').hidden = !historyNext;
      say(data.choices.length ? 'Choose an original to read its recorded outcome. Nothing is sent.' : 'No original tests were found on this page.' + (historyNext ? ' More records are available.' : ''));
    } catch (error) { if (started === generation) say(error.message); }
    finally { busy = false; controls(); }
  }
  async function read() {
    if (busy || !context || !originals.value) return;
    const started = generation, operation = originals.value; busy = true; controls();
    try { const data = await call('/original', { context, operation });
      if (started !== generation || originals.value !== operation) return;
      find('outcome').textContent = data.destination + ': ' + data.message; say('Original outcome read. No message was sent.');
    } catch (error) { if (started === generation) find('outcome').textContent = error.message; }
    finally { busy = false; controls(); }
  }
  function showReview(data, reviewed) {
    if (!data.review || Object.keys(data.review).length !== 6 || Object.values(data.review).some(value => typeof value !== 'string' || value.length > 2000)) throw new Error('The complete message review is unavailable. No message was sent.');
    discard(); const list = document.createElement('dl');
    Object.entries(data.review).forEach(([label, value]) => { const dt = document.createElement('dt'), dd = document.createElement('dd');
      dt.textContent = label; dd.textContent = value; dd.style.overflowWrap = 'anywhere'; list.append(dt, dd); });
    const label = document.createElement('label'), ack = document.createElement('input'); label.className = 'ch-toggle'; ack.type = 'checkbox'; ack.dataset.cmtConfirm = '';
    const text = document.createElement('span'); text.textContent = 'I reviewed this destination and the exact message to send.'; label.append(ack, text);
    const actions = document.createElement('div'), cancel = document.createElement('button'), send = document.createElement('button'); actions.className = 'ch-actions';
    cancel.type = send.type = 'button'; cancel.className = 'btn'; send.className = 'btn btn--primary'; send.dataset.cmtSend = ''; cancel.textContent = 'Cancel'; send.textContent = 'Send this test message';
    prepared = { operation: data.operation, stamp: reviewed }; ack.addEventListener('change', controls);
    cancel.addEventListener('click', () => { discard(); say('Review cancelled. No message was sent.'); controls(); find('review').focus(); });
    send.addEventListener('click', async () => {
      if (busy || !prepared || !ack.checked || prepared.stamp !== stamp()) return;
      const original = prepared.operation, started = generation; retain(original, data.review['Chat app'] + ' · ' + data.review.Destination);
      busy = true; discard(); controls();
      try { const result = await call('/send', { context, operation: original, confirmed: true });
        if (started !== generation) return;
        find('outcome').textContent = result.destination + ': ' + result.message; say(result.message);
      } catch (error) { if (started === generation) say(error.message + ' The original send may have arrived. Read its original outcome; do not repeat it.'); }
      finally { busy = false; controls(); }
    });
    actions.append(cancel, send); host.append(list, label, actions); host.hidden = false; ack.focus(); controls();
  }
  find('review').addEventListener('click', async () => {
    if (busy || !context || !choice.value) return;
    const started = generation, reviewed = stamp(); busy = true; discard(); controls();
    try { const data = await call('/review', { context, choice: choice.value });
      if (started !== generation || reviewed !== stamp()) return;
      showReview(data, reviewed); say('Read the complete destination and message before confirming.');
    } catch (error) { if (started === generation) say(error.message); }
    finally { busy = false; controls(); }
  });
  channel.addEventListener('change', () => { discard(); next = ''; choice.replaceChildren(new Option('Read conversations first…', '')); find('more').hidden = true; controls(); });
  choice.addEventListener('change', () => { discard(); controls(); }); originals.addEventListener('change', () => { find('outcome').textContent = ''; controls(); });
  find('load').addEventListener('click', () => list(false)); find('more').addEventListener('click', () => list(true));
  find('history').addEventListener('click', () => history(false)); find('history-more').addEventListener('click', () => history(true)); find('read').addEventListener('click', read);
  document.querySelectorAll('[data-cmt-open]').forEach(link => link.addEventListener('click', () => {
    if (!busy && (!choice.value || channel.value === link.dataset.cmtOpen)) {
      if (channel.value !== link.dataset.cmtOpen) { channel.value = link.dataset.cmtOpen; channel.dispatchEvent(new Event('change')); }
      find('load').focus();
    }
  }));
  document.addEventListener('lightwork:copilot-context-changed', event => { if (event.detail?.reason === 'selection') { reviewGeneration += 1; discard(); controls(); } else clear(); });
  ['lightwork:workspace-changed', 'lightwork:account-context-changed'].forEach(name => document.addEventListener(name, clear));
  window.addEventListener('lightwork:copilot-context-changed', clear); window.addEventListener('lightwork:draft-context-changed', clear);
  try { const stored = sessionStorage.getItem(key()); if (/^CHT-[a-f0-9]{32}$/.test(stored || '')) retain(stored); } catch (_) { /* Native history remains. */ }
  controls();
  window.LightworkChannelMessageTests = { async open(expected, name, isCurrent = () => true) {
    if (busy || !supported.includes(name) || !isCurrent() || expected !== context || (choice.value && channel.value !== name)) return false;
    const started = generation, current = stamp();
    try { const data = await call('/context');
      if (started !== generation || current !== stamp() || !isCurrent() || data.context !== expected) return false;
      if (channel.value !== name) { channel.value = name; channel.dispatchEvent(new Event('change')); }
      if (!isCurrent()) return false;
      panel.scrollIntoView({ block: 'start' }); find('load').focus(); return true;
    } catch (_) { return false; }
  }};
})();
