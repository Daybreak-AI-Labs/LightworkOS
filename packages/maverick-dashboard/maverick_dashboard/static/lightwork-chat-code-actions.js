/* Local snippet copies reuse native saved-source permission and release checks. */
(function (root) {
  'use strict';
  var document = root.document, serial = 0, denied = false, sequence = 0;
  var page = root.location.pathname, match = /^\/chat\/goal\/([1-9]\d*)$/.exec(page);
  if (!match) return;
  var goal = Number(match[1]), controllers = new Set();
  function say(node, text) {
    if (root.LightworkI18n && !node.closest('[data-user-content]')) root.LightworkI18n.set(node, text);
    else {
      node.textContent = root.LightworkI18n ? root.LightworkI18n.text(text) : text;
      node.lang = root.LightworkI18n ? root.LightworkI18n.languageFor(text) : 'en';
      node.dir = node.lang === 'ar' ? 'rtl' : 'ltr';
    }
  }
  function context() { var panel = document.getElementById('answer-panel'); return panel && panel.dataset.context; }
  function draft() {
    var form = document.getElementById('answer-form');
    return form ? JSON.stringify(Array.from(form.elements).map(function (field) {
      return [field.name, field.value, field.checked, field.disabled];
    })) : '';
  }
  function clear() {
    denied = true; serial++; controllers.forEach(function (controller) { controller.abort(); }); controllers.clear();
    document.querySelectorAll('.chat-code-tools,.chat-code-fallback').forEach(function (item) {
      if (item.tagName === 'TEXTAREA') item.value = ''; item.remove();
    });
  }
  function selection(code) {
    var panel = code.closest('#answer-panel'), artifact = code.closest('.artifact'), result = code.closest('#result');
    if (panel && artifact) {
      var body = artifact.querySelector('.artifact__body');
      if (!body || !body.contains(code)) return null;
      return {host: body, body: {context: context(), source: 'artifact', goal: goal,
        version: panel.dataset.version, artifact: Array.from(panel.querySelectorAll('.artifacts > .artifact')).indexOf(artifact)}};
    }
    if (panel && result) return {host: result, body: {context: context(), source: 'answer', goal: goal, version: panel.dataset.version}};
    var turn = code.closest('[data-chat-code-goal][data-chat-code-turn]');
    if (!turn) return null;
    var source = turn.querySelector('textarea.turn-copy-source'), prose = turn.querySelector('.prose');
    if (!source || !prose || !prose.contains(code)) return null;
    return {host: prose, original: source.value, body: {context: context(), source: 'turn',
      goal: Number(turn.dataset.chatCodeGoal), turn: Number(turn.dataset.chatCodeTurn)}};
  }
  async function fingerprint(text) {
    var hash = await root.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(hash)).map(function (part) { return part.toString(16).padStart(2, '0'); }).join('');
  }
  async function saved(info, code, ticket) {
    if (info.original !== undefined) info.body.version = await fingerprint(info.original);
    if (denied || ticket !== serial || !code.isConnected || root.location.pathname !== page) throw new Error('This view changed. Reopen the current copy controls.');
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 12000); controllers.add(controller);
    try {
      var response = await fetch('/api/v1/chat/code-controls/' + goal + '/source', {method: 'POST', credentials: 'same-origin',
        cache: 'no-store', signal: controller.signal, headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: JSON.stringify(info.body)});
      if (response.redirected || response.status === 401 || response.status === 404) { clear(); throw new Error('Access to this saved message changed. Reopen the conversation.'); }
      var raw = await response.text(); if (raw.length > 3 * 1024 * 1024) throw new Error('The complete saved text could not be read. Use its document download.');
      var value; try { value = JSON.parse(raw); } catch (_) { throw new Error('The saved text could not be checked. Your draft is kept; try the read again.'); }
      if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'This copy was refused. Refresh the current saved message.');
      if (denied || ticket !== serial || !code.isConnected || root.location.pathname !== page || context() !== info.body.context ||
          value.context !== info.body.context || value.version !== info.body.version || typeof value.text !== 'string' || typeof value.plain !== 'boolean')
        throw new Error('The message or your access changed. Reopen the current copy controls.');
      var snippets = value.plain ? [value.text] : Array.from(root.lwMarkdown.render(value.text, document).querySelectorAll('pre > code')).map(function (item) { return item.textContent; });
      var index = Array.from(info.host.querySelectorAll('pre > code')).indexOf(code);
      if (index < 0 || snippets[index] !== code.textContent) throw new Error('This snippet changed. Refresh the saved answer before copying.');
      return snippets[index];
    } finally { clearTimeout(timer); controllers.delete(controller); }
  }
  function enhance() {
    if (denied || !root.lwMarkdown) return;
    root.lwMarkdown.upgrade(document);
    document.querySelectorAll('#result pre > code, .msg--agent .prose pre > code, #answer-panel .artifact__body > code, #answer-panel .artifact__body pre > code').forEach(function (code) {
      if (code.dataset.chatCodeBound || !selection(code)) return;
      code.dataset.chatCodeBound = '1';
      var pre = code.parentElement, tools = document.createElement('div'); tools.className = 'chat-code-tools';
      var button = document.createElement('button'); button.type = 'button'; button.className = 'btn btn--ghost'; say(button, 'Copy code');
      var status = document.createElement('span'); status.className = 'muted'; status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
      var fallback = document.createElement('textarea'); fallback.className = 'input chat-code-fallback'; fallback.readOnly = true; fallback.hidden = true;
      fallback.id = 'chat-code-source-' + (++sequence); fallback.setAttribute('aria-label', 'Snippet text to copy'); fallback.lang = 'und'; fallback.dir = 'auto'; fallback.dataset.userContent = '1';
      button.setAttribute('aria-controls', fallback.id); tools.append(button, status); pre.before(tools); pre.after(fallback);
      button.addEventListener('click', async function () {
        if (denied || button.disabled) return;
        var info = selection(code), ticket = serial, text = code.textContent; if (!info) return;
        button.disabled = true; fallback.value = ''; fallback.hidden = true; say(status, 'Checking the saved snippet…');
        function live() { return !denied && serial === ticket && code.isConnected && code.textContent === text && context() === info.body.context; }
        function selectText() {
          if (!live()) return; fallback.value = text; fallback.hidden = false; fallback.focus(); fallback.select();
          say(status, 'Copy was unavailable. The snippet is selected; press Ctrl+C or Command+C.');
        }
        try {
          text = await saved(info, code, ticket); if (!live()) return;
          if (!root.navigator.clipboard || !root.navigator.clipboard.writeText) { selectText(); return; }
          try { await root.navigator.clipboard.writeText(text); if (live()) say(status, 'Copied.'); }
          catch (_) { selectText(); }
        } catch (failure) {
          if (live()) say(status, failure.name === 'AbortError' ? 'The saved snippet could not be checked. Your draft is kept; try again.' : failure.message);
        } finally { if (button.isConnected) button.disabled = denied; }
      });
    });
  }
  async function openReview(descriptor, options) {
    if (denied || !descriptor || Object.keys(descriptor).length || !options || typeof options.isCurrent !== 'function' ||
        !/^[a-f0-9]{64}$/.test(options.context || '') || !options.isCurrent() || root.location.pathname !== page || !root.mvFetchJSON) return false;
    var ticket = serial, before = draft(), expected = context();
    function current() { return !denied && ticket === serial && options.isCurrent() && root.location.pathname === page && expected === context() && before === draft(); }
    var catalog = await root.mvFetchJSON('/api/v1/copilot/product-operations/catalog', {method: 'POST', cache: 'no-store', body: {page: page, selection: {kind: 'goal', id: goal}}});
    if (!current() || catalog.context !== options.context || !(catalog.operations || []).some(function (row) { return row.id === 'conversation.code_controls' && row.available; })) return false;
    enhance(); var button = document.querySelector('.chat-code-tools button:not(:disabled)'); if (!button || !current()) return false;
    button.scrollIntoView({block: 'nearest'}); button.focus(); return current() && document.activeElement === button;
  }
  var pending = false, observer = new MutationObserver(function () { if (pending || denied) return; pending = true;
    root.queueMicrotask(function () { pending = false; enhance(); }); });
  observer.observe(document.getElementById('cs-scroll') || document.body, {childList: true, subtree: true});
  document.addEventListener('lightwork:answer-panel-before-update', function () { serial++; });
  ['lightwork:task-access-lost', 'lightwork:workspace-changed', 'lightwork:account-context-changed'].forEach(function (event) { document.addEventListener(event, clear); root.addEventListener(event, clear); });
  root.addEventListener('pagehide', function () { clear(); observer.disconnect(); });
  root.LightworkChatCodeActions = {openReview: openReview}; enhance();
})(window);
