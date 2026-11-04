/* Separate Chat alternatives share native full review and exact original admission. */
(function () {
  'use strict';
  var root = document.getElementById('chat-message-actions'); if (!root) return;
  var expected = root.dataset.context, API = '/api/v1/chat/message-actions';
  var form = document.getElementById('chat-alternative-form'), message = document.getElementById('chat-alternative-message');
  var answerOnly = document.getElementById('chat-alternative-answer-only'), review = document.getElementById('chat-alternative-full-review');
  var status = document.getElementById('chat-alternative-status'), original = document.getElementById('chat-alternative-original'), link = document.getElementById('chat-alternative-open');
  var ready = null, plan = null, pending = '', busy = false, current = true, generation = 0, dirty = false, controllers = new Set(), recovery = null;
  var key = 'lightwork:chat-message-original:' + expected;
  try { pending = sessionStorage.getItem(key) || ''; } catch (_) { /* Encrypted draft recovery also retains the protected original. */ }
  if (pending.length > 1048576) pending = '';
  original.hidden = !pending;
  if (pending) root.hidden = false;
  function node(tag, text) { var item = document.createElement(tag); item.textContent = text; return item; }
  function say(text) { window.mvStatus(status, text); }
  function invalidate() { plan = null; review.replaceChildren(); review.hidden = true; }
  function clear() {
    current = false; generation += 1; controllers.forEach(function (item) { item.abort(); }); controllers.clear();
    message.value = ''; pending = ''; ready = null; dirty = false; invalidate(); link.hidden = original.hidden = true;
    Array.from(form.elements).forEach(function (item) { item.disabled = true; });
    if (recovery) recovery.dispose(); root.querySelectorAll('.draft-recovery').forEach(function (item) { item.remove(); });
    say('Your account, workspace or access changed. Private conversation work was cleared; reload Chat.');
  }
  async function call(path, body, ticket) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 20000); controllers.add(controller);
    try {
      var response = await fetch(API + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: body ? JSON.stringify(body) : undefined});
      if (response.redirected || response.status === 401 || response.status === 403 && response.headers.get('X-Lightwork-Feature-Off') !== 'chat_message_actions' || response.status === 404) { clear(); throw new Error('Your conversation access is unavailable. Reload Chat.'); }
      if (!/application\/json/i.test(response.headers.get('content-type') || '')) throw new Error('The request could not be confirmed. Your draft and original request are kept.');
      var text = await response.text(); if (text.length > 2097152) throw new Error('The complete conversation response is too large. Your draft is kept; nothing was repeated.');
      var value = JSON.parse(text);
      if (!current || ticket !== generation) throw new Error('This response belongs to an earlier view. Your current work was kept.');
      if (value.context && value.context !== expected) { clear(); throw new Error('Your account or workspace changed. Reload Chat.'); }
      if (!response.ok) {
        if (response.status === 409 && /account or workspace changed/.test(String(value.detail))) clear();
        throw new Error(typeof value.detail === 'string' ? value.detail : 'This request was refused. Your draft and original request were kept.');
      }
      return value;
    } catch (failure) {
      if (failure.name === 'AbortError') throw new Error('The response was interrupted. Keep your draft and read the original request before starting another attempt. Nothing was automatically repeated.');
      throw failure;
    } finally { clearTimeout(timer); controllers.delete(controller); }
  }
  function remember(token) { pending = token; original.hidden = false; try { sessionStorage.setItem(key, token); } catch (_) { /* Native encrypted recovery remains available. */ } if (recovery) recovery.changed(); }
  function outcome(value) {
    say(value.message); link.hidden = true;
    if (value.confirmed && Number.isSafeInteger(value.goal) && value.goal > 0 && value.href === '/chat/goal/' + value.goal) { link.href = value.href; link.hidden = false; }
  }
  async function open(expectedContext, goal, action, source, isCurrent, turn) {
    if (!current || busy || expectedContext !== expected || !Number.isSafeInteger(goal) || !['retry', 'edit', 'branch'].includes(action)) return false;
    busy = true; document.getElementById('chat-alternative-review').disabled = true;
    var ticket = generation;
    try {
      var data = await call('/' + goal + '/source?' + new URLSearchParams({action:action,context:expected}).toString() + (turn ? '&turn=' + turn : ''), null, ticket);
      if (!current || ticket !== generation || (isCurrent && !isCurrent())) return false;
      if (source && data.source !== source) throw new Error('The selected conversation changed. Your existing work was kept; choose its current message again.');
      if (dirty && ready && (ready.goal !== goal || ready.action !== action || ready.turn !== data.turn)) throw new Error('Your edited message is kept. Close and keep it, or finish this draft before choosing another message.');
      ready = data; invalidate(); root.hidden = false;
      document.getElementById('chat-alternative-title').textContent = {retry:'Try this answer again',edit:'Edit and resend your message',branch:'Branch from this answer'}[action];
      if (!dirty) message.value = data.message;
      message.readOnly = action === 'retry';
      say(data.notice); root.scrollIntoView({block:'nearest'}); message.focus(); return true;
    } finally { busy = false; if (current) document.getElementById('chat-alternative-review').disabled = false; }
  }
  function fullReview(value) {
    if (!Array.isArray(value.history) || value.history.length > 100 || !Array.isArray(value.files) || value.files.length > 128 || !Array.isArray(value.accounts) || value.accounts.length > 100 || value.accounts.some(function (account) { return !account || typeof account.name !== 'string'; }) || typeof value.message !== 'string' || !value.caps) throw new Error('The complete review is unavailable. Keep your draft and check current context.');
    if (value.history.some(function (row) { return !row || !['user','assistant'].includes(row.role) || typeof row.content !== 'string'; })) throw new Error('A retained message cannot be displayed completely. Nothing was started.');
    review.replaceChildren(node('h3', 'Review the separate conversation'), node('p', value.notice));
    var history = node('div', ''); history.id = 'chat-alternative-context'; history.tabIndex = 0;
    history.append(node('h4', 'Earlier messages to include'));
    if (!value.history.length) history.append(node('p', 'No earlier messages will be included.'));
    value.history.forEach(function (row) { history.append(node('h4', row.role === 'user' ? 'You' : 'Lightwork'), node('pre', row.content)); });
    history.append(node('h4', 'Your new message'), node('pre', value.message), node('h4', 'Files available to this new attempt'));
    if (!value.files.length) history.append(node('p', 'No files.'));
    value.files.forEach(function (file) { history.append(node('p', file.name + ' · ' + file.bytes.toLocaleString() + ' bytes')); });
    history.append(node('h4', 'Connected account restrictions'));
    if (!value.accounts.length) history.append(node('p', 'No specific connected account was selected in the original task. Current connection permissions and approval rules still apply if you allow actions.'));
    value.accounts.forEach(function (account) { history.append(node('p', account.name)); });
    history.append(node('p', value.answer_only ? 'Answer only. This conversation generates text without taking actions, including after Resume.' : 'Actions are allowed under your current permissions. This is new work and may repeat earlier changes.'),
      node('p', 'At most $' + value.caps.max_dollars.toFixed(2) + ' and ' + value.caps.max_wall_seconds + ' seconds under current operating limits.'));
    var acknowledge = node('label', ''), checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.id = 'chat-alternative-confirm';
    acknowledge.append(checkbox, document.createTextNode(' I reviewed all included messages, files, limits and the new attempt’s effects.'));
    var start = node('button', 'Start separate conversation'); start.type = 'button'; start.id = 'chat-alternative-start'; start.className = 'btn btn--primary'; start.disabled = true;
    checkbox.addEventListener('change', function () { start.disabled = !checkbox.checked || busy; });
    start.addEventListener('click', async function () {
      if (!plan || busy || !checkbox.checked) return;
      busy = true; start.disabled = true; var accepted = plan; remember(accepted.token); var ticket = generation;
      try {
        var result = await call('/apply', {token:accepted.token,confirmed:true}, ticket); outcome(result);
        if (result.confirmed && message.value === accepted.message && answerOnly.checked === accepted.answer_only) dirty = false;
        invalidate();
      }
      catch (failure) { if (current) { say(failure.message + ' Read original request before making a new decision.'); invalidate(); } }
      finally { busy = false; }
    });
    review.append(history, acknowledge, start); review.hidden = false;
  }
  form.addEventListener('input', function () { dirty = true; invalidate(); });
  form.addEventListener('submit', async function (event) {
    event.preventDefault(); if (!current || busy || !ready) { if (current) say('Choose a message action or check current context first.'); return; }
    busy = true; var ticket = generation, written = message.value;
    var submitted = {context:expected,goal:ready.goal,action:ready.action,turn:ready.turn,source:ready.source,message:written,answer_only:answerOnly.checked};
    var stamp = JSON.stringify(submitted);
    try {
      var value = await call('/review', submitted, ticket);
      if (!ready || stamp !== JSON.stringify({context:expected,goal:ready.goal,action:ready.action,turn:ready.turn,source:ready.source,message:message.value,answer_only:answerOnly.checked})) { say('Your choices changed while their review was loading. Review the current draft again.'); return; }
      fullReview(value); plan = value; say('Nothing has started. Review every included message and confirm this separate attempt.');
    } catch (failure) { if (current) say(failure.message); }
    finally { busy = false; }
  });
  original.addEventListener('click', async function () { if (!pending || busy || !current) return; busy = true; try { outcome(await call('/original', {token:pending}, generation)); } catch (failure) { if (current) say(failure.message); } finally { busy = false; } });
  document.getElementById('chat-alternative-current').addEventListener('click', async function () { if (!ready || busy) return; try { await open(expected, ready.goal, ready.action, null, null, ready.turn); } catch (failure) { if (current) say(failure.message); } });
  document.getElementById('chat-alternative-close').addEventListener('click', function () { root.hidden = true; });
  document.addEventListener('click', async function (event) {
    var button = event.target.closest('[data-chat-message-action]'); if (!button || button.disabled) return;
    try { await open(expected, Number(button.dataset.goal), button.dataset.chatMessageAction, null, null, button.dataset.turn ? Number(button.dataset.turn) : null); }
    catch (failure) { root.hidden = false; if (current) say(failure.message); }
  });
  function drafts() {
    if (recovery || !window.mvDraftRecovery) return;
    recovery = window.mvDraftRecovery.create({host:root,key:'chat-message-actions:' + root.dataset.goal,compact:true,
      read:function () { return {message:message.value,answer_only:answerOnly.checked,selected:ready ? {goal:ready.goal,action:ready.action,turn:ready.turn} : null,pending:pending}; },
      restore:function (draft) { if (!current) return; invalidate(); message.value = typeof draft.message === 'string' ? draft.message : ''; answerOnly.checked = draft.answer_only !== false; dirty = true;
        if (draft.selected && ['retry','edit','branch'].includes(draft.selected.action) && Number.isSafeInteger(draft.selected.goal)) ready = {goal:draft.selected.goal,action:draft.selected.action,turn:draft.selected.turn || null};
        if (typeof draft.pending === 'string' && draft.pending.length <= 1048576) remember(draft.pending);
        root.hidden = false; say('Your edited message and protected original request were restored. Check current context before a new review; nothing was repeated.'); }});
  }
  window.addEventListener('lightwork:drafts-ready', drafts); drafts();
  document.addEventListener('lightwork:task-projection', function (event) { document.querySelectorAll('[data-chat-message-action]').forEach(function (button) { if (button.dataset.permissionDisabled !== '1') button.disabled = !event.detail.terminal; }); });
  document.addEventListener('lightwork:task-access-lost', clear);
  ['lightwork:workspace-changed','lightwork:account-context-changed'].forEach(function (name) { document.addEventListener(name, clear); window.addEventListener(name, clear); });
  async function verifyContext(event) {
    if (event && event.detail && event.detail.reason === 'selection') return;
    if (!current) return;
    try { var value = await call('/context?context=' + expected, null, generation); if (!value.may_start) clear(); else invalidate(); }
    catch (failure) { if (current) { invalidate(); say(failure.message); } }
  }
  window.addEventListener('lightwork:copilot-context-changed', verifyContext);
  document.addEventListener('lightwork:copilot-context-changed', async function () { if (!ready || !current || busy) return; var ticket = generation;
    try { var value = await call('/' + ready.goal + '/source?' + new URLSearchParams({action:ready.action,context:expected}).toString() + (ready.turn ? '&turn=' + ready.turn : ''), null, ticket); if (ready.source && ready.source !== value.source) invalidate(); }
    catch (failure) { if (current) { invalidate(); say(failure.message); } } });
  window.LightworkChatMessageActions = {open:open};
})();
