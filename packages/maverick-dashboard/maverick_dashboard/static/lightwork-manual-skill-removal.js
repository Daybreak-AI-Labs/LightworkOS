/* Ordinary reviewed removal: keep the card, submit once, read original result. */
(function () {
  'use strict';
  var root = document.getElementById('manual-skill-removal'); if (!root) return;
  var reviewBox = document.getElementById('manual-skill-review'), resultBox = document.getElementById('manual-skill-result');
  var status = document.getElementById('manual-skill-status'), choice = document.getElementById('manual-skill-original');
  var read = document.getElementById('manual-skill-read'), refresh = document.getElementById('manual-skill-refresh');
  var context = '', generation = 0, busy = false, key = 'lightwork-manual-skill-removal';
  var initial = new URL(location.href).searchParams.get('manual_removal'); if (!/^[a-f0-9]{32}$/.test(initial || '')) initial = '';
  function node(tag, text, parent) { var value = document.createElement(tag); if (text !== undefined) value.textContent = text; if (parent) parent.append(value); return value; }
  function lock(value) { busy = value; read.disabled = value || !choice.value; refresh.disabled = value; choice.disabled = value; document.querySelectorAll('[data-skill-remove]').forEach(function (button) { button.disabled = value || !context; }); }
  function clearAuthority() { generation++; context = ''; reviewBox.replaceChildren(); resultBox.replaceChildren(); choice.replaceChildren(node('option', 'Choose an original removal')); document.getElementById('installed-skills').replaceChildren(); status.textContent = 'Your account or access changed. Reload the Skills page to see current skills. Nothing was repeated.'; lock(false); }
  async function request(path, body) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 20000);
    try {
      var response = await fetch('/api/v1/manual-skill-removals' + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined, signal: controller.signal});
      var text = await response.text(); if (text.length > 1048576) throw new Error('This complete review is too large to display. Nothing was removed.');
      var value; try { value = JSON.parse(text); } catch (_) { value = {}; }
      if (!response.ok || response.redirected) { var error = new Error(typeof value.detail === 'string' ? value.detail : 'This removal could not be confirmed. Read its original result before a new decision.'); error.authority = response.redirected || response.status === 401 || response.status === 403; throw error; }
      if (context && value.context && value.context !== context) { var changed = new Error('Your account or workspace changed.'); changed.authority = true; throw changed; }
      return value;
    } finally { clearTimeout(timer); }
  }
  function failure(error) { if (error.authority) clearAuthority(); else status.textContent = error.name === 'AbortError' ? 'The reply was interrupted. Read the original result; nothing will be removed again automatically.' : error.message; }
  function selected(operation, label) { if (!Array.from(choice.options).some(function (option) { return option.value === operation; })) { var option = node('option', label, choice); option.value = operation; } choice.value = operation; }
  function show(result) {
    if (result.context !== context) { clearAuthority(); return; }
    resultBox.replaceChildren(); node('p', result.message, resultBox); if (result.current) node('p', result.current, resultBox); node('p', result.notice, resultBox);
    status.textContent = result.confirmed ? 'Your original removal is confirmed. Current skills are shown separately.' : 'The original removal is unconfirmed. Read current skills separately; no removal will be repeated automatically.';
    if (result.confirmed && result.name) {
      // A later replacement must stay visible even when the old removal is confirmed.
      if (result.current_state === 'absent') document.querySelectorAll('.skill-card[data-skill]').forEach(function (card) { if (card.dataset.skill === result.name) card.remove(); });
      else { var reload = node('a', 'Reload current saved skills', resultBox); reload.href = '/skills#sk-list-title'; }
    }
  }
  async function load() {
    if (busy) return; var current = ++generation, selectedValue = choice.value || initial; initial = ''; lock(true);
    try {
      var state = await request(''); if (current !== generation) return; context = state.context;
      var pending; try { pending = JSON.parse(sessionStorage.getItem(key) || 'null'); } catch (_) { pending = null; }
      if (pending && pending.context === context && /^[a-f0-9]{32}$/.test(pending.operation)) selectedValue = selectedValue || pending.operation;
      choice.replaceChildren(); var empty = node('option', 'Choose an original removal', choice); empty.value = '';
      state.requests.forEach(function (row) { var option = node('option', row.label, choice); option.value = row.value; });
      if (selectedValue) selected(selectedValue, 'Original request retained in this browser'); status.textContent = state.notice;
    } catch (error) { if (current === generation) failure(error); }
    finally { if (current === generation) lock(false); }
  }
  async function readOriginal() {
    if (busy || !context || !choice.value) return; var current = ++generation, operation = choice.value; lock(true); reviewBox.replaceChildren();
    try { var result = await request('/requests/' + encodeURIComponent(operation)); if (current === generation) show(result); }
    catch (error) { if (current === generation) failure(error); }
    finally { if (current === generation) lock(false); }
  }
  async function review(name) {
    if (busy || !context) return; var current = ++generation; lock(true); reviewBox.replaceChildren();
    try {
      var checked = await request('/review', {name: name, context: context}); if (current !== generation) return;
      node('h4', 'Review this exact saved skill removal', reviewBox);
      checked.changes.forEach(function (change) { node('h5', change.label, reviewBox); if (Array.isArray(change.after)) { var list = node('ul', undefined, reviewBox); change.after.forEach(function (value) { node('li', value, list); }); } else { var paragraph = node('p', change.after, reviewBox); paragraph.style.whiteSpace = 'pre-wrap'; } });
      var label = node('label', undefined, reviewBox), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode(' I reviewed this saved version and want to remove it.'));
      var apply = node('button', 'Remove reviewed skill', reviewBox); apply.type = 'button'; apply.className = 'btn btn--danger'; apply.disabled = true;
      consent.addEventListener('change', function () { apply.disabled = busy || !consent.checked; });
      apply.addEventListener('click', function () {
        if (busy || !consent.checked || current !== generation) return;
        try { sessionStorage.setItem(key, JSON.stringify({context: context, operation: checked.operation})); } catch (_) { status.textContent = 'This browser could not retain the original request. Allow site storage before removing; nothing was submitted.'; return; }
        selected(checked.operation, 'Original removal just reviewed'); lock(true); apply.disabled = true;
        // One action with a way back, like other deletes: the card
        // leaves at once and the reviewed removal is sent when the Undo time
        // is up (or the page is left). An undone removal sends nothing.
        var card = Array.prototype.find.call(document.querySelectorAll('.skill-card[data-skill]'), function (item) { return item.dataset.skill === name; });
        var title = card && card.querySelector('strong'), sent = false;
        if (card) card.hidden = true; reviewBox.hidden = true;
        status.textContent = 'The reviewed removal is sent when the Undo time is up.';
        window.mvUndo('Skill “{name}” removed. Agents stop using it from the next task.', {
          values: {name: title ? title.textContent.trim() : name}, action: 'remove the skill',
          run: async function (keepalive) {
            sent = true;
            var response = await fetch('/api/v1/manual-skill-removals/remove', {method: 'POST', credentials: 'same-origin', cache: 'no-store', keepalive: keepalive,
              headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token: checked.token, confirmed: true})});
            if (!response.ok) return response;
            var result = await response.json();
            if (current === generation) { reviewBox.replaceChildren(); reviewBox.hidden = false; show(result); }
            return {ok: true};
          },
          undo: function () {
            // A refused or lost reply keeps the retained request, so its original result can still be read.
            if (!sent) { try { sessionStorage.removeItem(key); } catch (_) { /* best effort */ } }
            if (card) card.hidden = false;
            reviewBox.hidden = false; reviewBox.replaceChildren();
            status.textContent = sent ? 'The removal could not be confirmed. Read its original result before a new decision.' : 'Removal undone. The skill was kept.';
            if (current === generation) lock(false);
          },
          done: function () { if (current === generation) lock(false); }
        });
      });
      var cancel = node('button', 'Cancel this review', reviewBox); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', function () { if (!busy) { reviewBox.replaceChildren(); status.textContent = 'Review cancelled. The skill was kept.'; } });
      status.textContent = 'Nothing has been removed. Review all current instructions before confirming.'; root.scrollIntoView({block: 'start'}); consent.focus();
    } catch (error) {
      if (current === generation) { failure(error); if (!error.authority && error.message.includes('Suggestions from completed work')) { var link = node('a', 'Open source-reviewed learned skills', reviewBox); link.href = '/skills#to-learned-skills'; } }
    } finally { if (current === generation) lock(false); }
  }
  read.addEventListener('click', readOriginal); choice.addEventListener('change', readOriginal); refresh.addEventListener('click', load);
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (event.detail && event.detail.reason === 'selection') { if (!busy) { reviewBox.replaceChildren(); load(); } } else { clearAuthority(); load(); } });
  window.addEventListener('lightwork:context-changed', function () { clearAuthority(); load(); });
  window.LightworkManualSkillRemoval = {review: review}; lock(false); load().then(function () { if (!busy && context && choice.value) readOriginal(); });
})();
