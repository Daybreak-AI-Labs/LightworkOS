(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let current = null, model = null, busy = false, generation = 0, page = 0;
  const pageSize = 50;
  const node = (tag, text) => { const item = document.createElement(tag); if (text !== undefined) item.textContent = text; return item; };
  const say = text => { $('par-status').textContent = text; };
  async function call(path, body) {
    const write = body && path !== '/explain';
    try {
      return await window.mvFetchJSON('/api/v1/access-requests' + path, {method: body ? 'POST' : 'GET', body, plainDetail: true, timeout: 15000},
        write ? 'save the access request' : 'load current permissions');
    } catch (error) {
      if (error.status === 401 || error.status === 403 || error.accessChanged) changed();
      else if (write && (!error.status || error.status === 503)) error.message = 'This request could not be confirmed. It may already be saved. Refresh current requests before trying again.';
      throw error;
    }
  }
  function explanation(parent, value) {
    parent.appendChild(node('p', value.label + ': ' + (value.allowed ? 'Your current policy allows this action.' : 'Your current policy blocks this action.') + ' Policy owner: ' + value.owner + '.'));
    const list = node('ul'); (value.layers || []).forEach(layer => list.appendChild(node('li', layer.source + ': ' + (layer.reason || layer.role || 'Current policy')))); parent.appendChild(list); parent.appendChild(node('p', value.limit));
  }
  function lock() {
    document.querySelectorAll('#par-explain input, #par-explain select, #par-explain button, #par-submit input, #par-submit textarea, #par-submit button, #par-cases input, #par-cases select, #par-cases textarea, #par-cases button').forEach(item => { item.disabled = busy || !model; });
    $('par-refresh').disabled = busy;
    const tools = $('par-kind').value === 'tool', available = model?.choices?.tools_available;
    $('par-capability').disabled = busy || !model || tools && !available;
    $('par-check').disabled = busy || !model || !$('par-capability').value || tools && !available;
    $('par-previous').disabled = busy || page === 0;
    $('par-next').disabled = busy || (page + 1) * pageSize >= matches().length;
  }
  function matches() {
    const choices = model?.choices?.[$('par-kind').value] || [], query = $('par-search').value.trim().toLocaleLowerCase();
    return choices.filter(choice => !query || choice.label.toLocaleLowerCase().includes(query));
  }
  function choices() {
    const tools = $('par-kind').value === 'tool', previous = $('par-capability').value, all = model?.choices?.[$('par-kind').value] || [], rows = matches();
    page = Math.min(page, Math.max(0, Math.ceil(rows.length / pageSize) - 1));
    const select = $('par-capability'); select.replaceChildren(new Option('Choose an action', ''));
    const displayed = rows.slice(page * pageSize, (page + 1) * pageSize), retained = all.find(choice => choice.value === previous);
    if (retained && !displayed.some(choice => choice.value === previous)) select.appendChild(new Option('Selected: ' + retained.label, retained.value));
    displayed.forEach(choice => select.appendChild(new Option(choice.label, choice.value)));
    select.value = retained ? previous : '';
    $('par-search-label').hidden = !tools; $('par-pages').hidden = !tools || rows.length <= pageSize;
    $('par-help').textContent = tools ? model?.choices?.tools_available ? (rows.length ? 'Actions ' + (page * pageSize + 1) + '–' + Math.min((page + 1) * pageSize, rows.length) + ' of ' + rows.length + '. ' : 'No matching actions. ') + model.choices.tools_notice : model?.choices?.tools_notice || 'Loading named actions.' : 'Choose what you need to do. Its current permission and responsible administrator are checked next.';
    lock();
  }
  async function load(started = generation) {
    clearReview();
    const next = await call(''); if (started !== generation) return;
    if (model && model.context !== next.context) { changed(); return; }
    model = next; say(model.enabled ? 'Current policy loaded. Reviews do not change permissions automatically.' : 'New permission requests are disabled. Current explanations and saved cases remain available.');
    choices();
    const cases = $('par-cases'); cases.replaceChildren();
    if (!model.records.length) cases.appendChild(node('p', 'No visible permission requests. Requests appear here when someone asks for more access.'));
    model.records.forEach(row => {
      const article = node('article'); article.className = 'panel'; article.appendChild(node('h3', row.label + ' — ' + ({requested: 'Requested', reviewing: 'Under review', denied: 'Declined', effective: 'Permission confirmed'}[row.status] || 'Saved request'))); article.appendChild(node('p', row.reason)); explanation(article, row.current);
      if (row.decision_note) article.appendChild(node('p', 'Reviewer: ' + row.decision_note));
      if (row.audit_pending) article.appendChild(node('p', 'The activity receipt is pending. Refresh before relying on this outcome.'));
      if (row.can_review && model.enabled) {
        const form = node('form'); form.dataset.draftRecovery = 'off'; const select = node('select'); select.className = 'select'; select.setAttribute('aria-label', 'Review result'); [['reviewing', 'Under review'], ['deny', 'Decline request'], ['confirm_effective', 'Confirm actual permission is effective']].forEach(choice => select.appendChild(new Option(choice[1], choice[0])));
        const label = node('label', 'Review explanation (shared with employee) '), note = node('textarea'); note.required = true; note.minLength = 10; note.maxLength = 1000; label.appendChild(note);
        const button = node('button', 'Record reviewed result'); button.type = 'submit'; button.className = 'btn'; form.append(select, label, button); form.onsubmit = event => { event.preventDefault(); act(() => call('/' + encodeURIComponent(row.id) + '/decision', {expected_revision: row.revision, decision: select.value, note: note.value})); }; article.appendChild(form);
      }
      cases.appendChild(article);
    });
    lock();
  }
  async function act(operation) { if (busy) return; busy = true; lock(); const started = generation; try { await operation(); if (started === generation) await load(started); } catch (error) { if (started === generation) say(error.message); } finally { if (started === generation) { busy = false; lock(); } } }
  function clearReview() { current = null; $('par-submit').hidden = true; $('par-explanation').replaceChildren(); }
  $('par-kind').onchange = () => { page = 0; $('par-search').value = ''; $('par-capability').value = ''; clearReview(); choices(); };
  $('par-capability').onchange = () => { clearReview(); lock(); };
  $('par-search').oninput = () => { page = 0; clearReview(); choices(); };
  $('par-previous').onclick = () => { page--; choices(); }; $('par-next').onclick = () => { page++; choices(); };
  $('par-explain').onsubmit = async event => { event.preventDefault(); if (busy || !model || !$('par-capability').value) return; const started = generation, bound = model.context, body = {kind: $('par-kind').value, capability: $('par-capability').value}; busy = true; clearReview(); lock(); try { const value = await call('/explain', body); if (started !== generation) return; if (value.context !== bound) { changed(); return; } current = value; explanation($('par-explanation'), current); $('par-submit').hidden = !model.enabled || current.allowed; $('par-confirm').checked = false; } catch (error) { if (started === generation) say(error.message); } finally { if (started === generation) { busy = false; lock(); } } };
  $('par-submit').onsubmit = event => { event.preventDefault(); if (!current || !$('par-confirm').checked) return; act(() => call('', {kind: current.kind, capability: current.capability, snapshot: current.snapshot, reason: $('par-reason').value, confirm_shared_with_reviewer: true})); };
  function changed(event) {
    if (event?.detail?.reason === 'selection') return;
    generation++; model = null; busy = false; page = 0; clearReview(); $('par-reason').value = ''; $('par-confirm').checked = false; $('par-cases').replaceChildren(); $('par-capability').replaceChildren(new Option('Choose an action', '')); $('par-search').value = ''; $('par-help').textContent = 'Refresh for current named actions.'; say('Your account, workspace or access changed. Refresh current permissions before continuing.'); lock();
  }
  ['lightwork:workspace-changed', 'lightwork:account-context-changed', 'lightwork:copilot-context-changed'].forEach(name => document.addEventListener(name, changed));
  window.addEventListener('lightwork:context-changed', changed);
  async function refresh() { if (busy) return; busy = true; lock(); const started = generation; try { await load(started); } catch (error) { if (started === generation) say(error.message); } finally { if (started === generation) { busy = false; lock(); } } }
  $('par-refresh').onclick = refresh; lock(); refresh();
})();
