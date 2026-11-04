(function () {
  'use strict';
  var root = document.getElementById('earlier-history'); if (!root) return;
  var load = document.getElementById('history-load'), status = document.getElementById('history-status');
  var host = document.getElementById('history-turns'), before = root.dataset.before, seen = new Set();
  var complete = false, pending = null, printing = false;
  var MAX_PRINT_PAGES = 20, MAX_PRINT_TURNS = 1000, PRINT_DEADLINE_MS = 30000;
  function content(node, value) {
    node.textContent = String(value || ''); node.lang = 'und'; node.dir = 'auto'; node.dataset.userContent = '1';
    return node;
  }
  function appendTurn(batch, turn) {
    if (seen.has(turn.id)) return;
    seen.add(turn.id);
    var item = document.createElement('article'); item.className = 'msg msg--' + (turn.role === 'user' ? 'user' : 'agent');
    if (turn.role === 'assistant') { item.dataset.chatCodeGoal = String(turn.goal_id); item.dataset.chatCodeTurn = String(turn.id); }
    var label = document.createElement('strong'); label.textContent = turn.role === 'user' ? 'You' : 'Lightwork';
    var text = content(document.createElement('div'), turn.content); text.className = 'prose'; text.style.whiteSpace = 'pre-wrap';
    var link = document.createElement('a'); link.href = '/chat/goal/' + turn.goal_id; link.textContent = 'Open this turn';
    item.append(label, text, link); batch.append(item);
    if (turn.role === 'assistant') {
      var source = document.createElement('textarea'); source.className = 'turn-copy-source'; source.readOnly = true; source.hidden = true;
      source.setAttribute('aria-label', 'Earlier answer text to copy'); source.value = turn.content; item.append(source);
      if (window.lwMarkdown) window.lwMarkdown.renderInto(text, turn.content);
    }
    if (turn.role === 'user' && Array.isArray(turn.questions)) turn.questions.forEach(function (exchange) {
      var qa = document.createElement('div'); qa.className = 'qa';
      var question = content(document.createElement('p'), exchange.question); question.className = 'qa__q';
      var answer = document.createElement('div'); answer.className = 'msg msg--user';
      var bubble = content(document.createElement('div'), exchange.answer); bubble.className = 'bubble';
      answer.append(bubble); qa.append(question, answer); batch.append(qa);
    });
  }
  async function loadNext() {
    if (complete) return;
    if (pending) return pending;
    pending = (async function () {
      load.disabled = true; status.textContent = 'Loading earlier conversation…';
      var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 12000);
      try {
        var response = await fetch('/api/v1/goals/' + root.dataset.goal + '/thread-history' + (before ? '?before_id=' + before : ''),
          {credentials: 'same-origin', cache: 'no-store', signal: controller.signal});
        if (response.redirected || [401, 403, 404].includes(response.status)) {
          host.replaceChildren(); seen.clear(); before = root.dataset.before; complete = false;
          document.dispatchEvent(new CustomEvent('lightwork:task-access-lost'));
          throw new Error('Access to this conversation changed. Reopen it before printing.');
        }
        if (!response.ok) throw new Error('Earlier history could not be loaded. Retry before printing.');
        var data = await response.json();
        if (!Array.isArray(data.turns) || typeof data.has_more !== 'boolean' ||
            data.turns.some(function (turn) { return !turn || !Number.isSafeInteger(turn.id) ||
              !Number.isSafeInteger(turn.goal_id) || !['user', 'assistant'].includes(turn.role) || typeof turn.content !== 'string' ||
              (before && turn.id >= Number(before)) || (turn.role === 'user' &&
              (!Array.isArray(turn.questions) || turn.questions.some(function (exchange) {
                return !exchange || typeof exchange.question !== 'string' || typeof exchange.answer !== 'string';
              }))); }))
          throw new Error('Earlier history was incomplete. Retry before printing.');
        var next = data.before_id;
        if (data.has_more && (!data.turns.length || !Number.isSafeInteger(next) ||
            (before && next >= Number(before))))
          throw new Error('Earlier history did not advance. Retry before printing.');
        var batch = document.createDocumentFragment();
        data.turns.forEach(function (turn) { appendTurn(batch, turn); });
        host.prepend(batch); before = next || before; complete = !data.has_more; load.hidden = complete;
        status.textContent = complete ? 'Beginning of this conversation.' : 'Earlier messages loaded. More history is available.';
      } catch (error) {
        load.hidden = false;
        status.textContent = error.message || 'Earlier history could not be loaded. Retry; the current conversation and draft have been kept.';
        throw error;
      } finally { clearTimeout(timer); load.disabled = false; }
    })();
    try { return await pending; } finally { pending = null; }
  }
  load.addEventListener('click', function () { loadNext().catch(function () { /* The status offers a retry. */ }); });
  window.LightworkThreadHistory = {printConversation: async function (actionStatus) {
    if (printing) return;
    printing = true;
    if (actionStatus) actionStatus.textContent = 'Preparing every earlier message before printing…';
    try {
      var pages = 0, deadline = Date.now() + PRINT_DEADLINE_MS;
      while (!complete) {
        if (pages >= MAX_PRINT_PAGES || seen.size >= MAX_PRINT_TURNS)
          throw new Error('This conversation is too long to print at once. Use Download or share full history instead. Nothing was printed.');
        if (Date.now() >= deadline)
          throw new Error('Preparing the full conversation took too long. Nothing was printed. Try again or use Download or share full history.');
        await loadNext(); pages++;
      }
      if (seen.size > MAX_PRINT_TURNS)
        throw new Error('This conversation is too long to print at once. Use Download or share full history instead. Nothing was printed.');
      // A previously loaded transcript is still private page state. Recheck
      // access and the final history cursor immediately before opening Print.
      complete = false;
      if (Date.now() >= deadline)
        throw new Error('Preparing the full conversation took too long. Nothing was printed. Try again or use Download or share full history.');
      await loadNext();
      if (actionStatus) actionStatus.textContent = 'The complete loaded conversation is ready to print.';
      window.print();
    } catch (error) {
      if (actionStatus) actionStatus.textContent = /Nothing was printed\./.test(error.message || '')
        ? error.message : 'Could not load the full conversation. Nothing was printed. Retry after loading earlier messages.';
    } finally { printing = false; }
  }};
}());
