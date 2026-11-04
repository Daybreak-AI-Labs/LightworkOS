'use strict';
(function () {
  function renderReview(container, changes) {
    if (!container || !Array.isArray(changes) || changes.length > 512 || changes.some(row => !row || Object.keys(row).sort().join(',') !== 'after,label' || typeof row.label !== 'string' || typeof row.after !== 'string') || new TextEncoder().encode(JSON.stringify(changes)).length > 131072) throw new Error('The complete review cannot be displayed. No part was shortened; nothing can be confirmed.');
    const list = document.createElement('dl');
    list.style.minWidth = '0'; list.style.overflowWrap = 'anywhere';
    changes.forEach(row => { const title = document.createElement('dt'), body = document.createElement('dd'); title.textContent = row.label; body.textContent = row.after; body.style.whiteSpace = 'pre-wrap'; body.style.marginInlineStart = 'var(--space-3)'; list.append(title, body); });
    container.replaceChildren(list); return true;
  }
  window.LightworkJointRules = {renderReview};
  const host = document.getElementById('joint-rules'); if (!host) return;
  const by = name => document.getElementById('ji-' + name), picks = [by('first'), by('second')], sections = [by('first-cases'), by('second-cases')];
  const api = '/api/v1/learning/rules-together', storage = 'lightwork-joint-rule-original', calls = new Set();
  let context = '', state = null, prepared = null, pending = null, qualified = null, busy = false, generation = 0, dirty = false, publishing = false;
  function node(tag, text, parent) { const value = document.createElement(tag); if (text !== undefined) value.textContent = String(text); if (parent) parent.appendChild(value); return value; }
  function display(value) { if (value === null || value === undefined) return 'No value'; if (typeof value === 'boolean') return value ? 'Yes' : 'No'; if (Array.isArray(value)) return value.map(display).join('\n'); if (typeof value === 'object') return Object.entries(value).map(([name, item]) => name.replaceAll('_', ' ') + ': ' + display(item)).join('\n'); return String(value); }
  function outputs(value) { return Object.entries(value).map(([name, item]) => name.replaceAll('_', ' ') + ': ' + (item.present ? display(item.value) : 'Not produced')).join('\n'); }
  function invalidate() { prepared = null; by('preview').hidden = true; by('preview').replaceChildren(); }
  function lock(value) { busy = value; host.setAttribute('aria-busy', String(value)); host.querySelectorAll('input,select,button').forEach(item => item.disabled = value); if (!value) { by('review').disabled = !state?.enabled || !state.rules?.[0] || !state.rules?.[1]; const button = by('preview').querySelector('[data-confirm]'); if (button) button.disabled = !by('preview').querySelector('input')?.checked; } }
  function selection(value) { publishing = true; try { document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: value}})); } finally { publishing = false; } }
  function clear() { ++generation; calls.forEach(value => value.abort()); context = ''; state = prepared = pending = qualified = null; dirty = false; picks.forEach(value => value.replaceChildren(new Option('Refresh in the current account', ''))); sections.forEach(value => value.replaceChildren()); by('history').replaceChildren(new Option('Refresh original requests', '')); by('result').replaceChildren(); by('run').hidden = true; by('inputs').replaceChildren(); invalidate(); by('error').textContent = ''; by('status').textContent = 'Private rules and entered work were cleared because your account, workspace or access changed.'; lock(false); }
  async function request(path, body, expected = context) {
    const controller = new AbortController(); calls.add(controller);
    const F = 'This result could not be confirmed. Read the original outcome without repeating work.';
    const T = 'The reply could not be confirmed. Entered work is kept. Read the original outcome without repeating it.';
    const A = 'Sign in with current permission before reading private local rules.';
    try {
      const value = await window.mvFetchJSON(api + path, {method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal,
        headers: expected ? {'X-Lightwork-Joint-Context': expected} : {}, body: body || undefined, timeout: 35000,
        serverDetail: F, messages: {401: A, 403: A, timeout: T, offline: T, unreadable: T},
        onAccess: clear, contextChange: /account, workspace or access changed/, onContextChange: clear}, 'check the rules together');
      if (expected && value.context && value.context !== expected) { clear(); throw new Error('Your account or workspace changed. Private work was cleared.'); }
      return value;
    } finally { calls.delete(controller); }
  }
  function kept() { return sections.map(section => Array.from(section.querySelectorAll('[data-case]')).filter(value => value.checked).map(value => value.dataset.case)); }
  function adopt(next, selected = kept()) {
    picks.forEach((pick, index) => { const desired = next.rules[index]?.flow || ''; pick.replaceChildren(new Option(index ? 'Choose another rule' : 'Choose a rule', '')); next.flows.forEach(item => pick.appendChild(new Option(item.label, item.value))); pick.value = desired; });
    sections.forEach((section, index) => { section.replaceChildren(); const rule = next.rules[index]; if (!rule) return; node('p', rule.name + ' · published version ' + rule.version, section).className = 'muted';
      rule.cases.forEach(item => { const block = node('div', undefined, section); block.className = 'ji-case stack'; const label = node('label', undefined, block); label.className = 'ji-check'; const check = node('input', undefined, label); check.type = 'checkbox'; check.dataset.case = item.value; check.checked = selected[index]?.includes(item.value) || false; node('span', item.label, label); const details = node('details', undefined, block); node('summary', 'Original starting values', details); node('p', item.values, details).className = 'ji-values'; });
      if (!rule.cases.length) node('p', 'Retain two complete original cases with current reuse permission first.', section).className = 'muted'; });
    state = next; by('disabled').hidden = next.enabled; invalidate();
  }
  async function history() { const value = await request('/history'); by('history').replaceChildren(new Option('Choose an original request', '')); value.choices.forEach(item => by('history').appendChild(new Option(item.label, item.value))); if (pending?.context === context) { if (!value.choices.some(item => item.value === pending.id)) by('history').appendChild(new Option('Original request · check outcome', pending.id)); by('history').value = pending.id; } }
  function query(first, second) { return '?first=' + encodeURIComponent(first) + '&second=' + encodeURIComponent(second); }
  async function replace(next, selected, started) {
    const changed = state && state.revision !== next.revision;
    if (dirty && changed && (typeof window.mvConfirm !== 'function' || !await window.mvConfirm('The rules or permitted original cases changed. Replace current selections with the current choices?', {okText: 'Replace current selections'}) || started !== generation)) { if (started === generation) picks.forEach((pick, index) => pick.value = state.rules[index]?.flow || ''); return false; }
    if (started !== generation) return false; adopt(next, changed ? [[], []] : selected); return true;
  }
  async function refresh(first = picks[0].value, second = picks[1].value) {
    if (busy) return; const started = ++generation, selected = kept(); lock(true); invalidate(); by('error').textContent = '';
    try { const next = await request(query(first, second)); if (started !== generation) return; context = next.context; if (!await replace(next, selected, started)) { by('error').textContent = 'Entered selections remain visible. Explicitly replace changed source choices before a new review.'; return; }
      if (!pending) { try { const saved = JSON.parse(sessionStorage.getItem(storage) || 'null'); if (saved?.context === context && /^PJI-[a-f0-9]{32}$/.test(saved.id)) pending = saved; } catch (_) {} }
      await history(); if (started === generation) by('status').textContent = next.enabled ? 'Choose two different rules and at least two original cases for each.' : 'Joint local checks are off. Your original requests remain available below.';
    } catch (error) { if (started === generation) { state = null; by('error').textContent = error.message; } } finally { if (started === generation) lock(false); }
  }
  function field(name, declaration) { const parent = by('inputs'), label = node('label', name.replaceAll('_', ' '), parent); let input;
    if (declaration.type === 'boolean') { input = node('select', undefined, parent); input.append(new Option('Choose an answer', ''), new Option('Yes', 'yes'), new Option('No', 'no')); input.className = 'select'; }
    else { input = node('input', undefined, parent); input.type = 'number'; input.min = String(declaration.min); input.max = String(declaration.max); input.step = '1'; input.className = 'input'; }
    input.id = 'ji-value-' + Object.keys(qualified.result.inputs).indexOf(name); label.htmlFor = input.id; input.required = true; input.dataset.input = name; input.dataset.kind = declaration.type;
  }
  function describeCell(cell, value, parent) { const block = node('details', undefined, parent); node('summary', display(cell.inputs).replaceAll('\n', ' · ') + ' · ' + (cell.unambiguous ? 'One supported result' : 'Unresolved'), block);
    node('p', 'Safe orders: ' + (cell.safe_orders.length ? cell.safe_orders.map(order => order.map(index => value.rules[index]).join(' → ')).join(' / ') : 'Neither order preserves both separate results'), block);
    cell.references.forEach((row, index) => node('p', value.rules[index] + ' / fresh separate result\n' + outputs(row.outputs) + '\nComplete: ' + display(row.complete), block).className = 'ji-values');
    cell.orders.forEach(row => { const details = node('details', undefined, block); node('summary', row.order.map(index => value.rules[index]).join(' → ') + ' · ' + (row.safe ? 'Both results preserved' : 'Results not preserved'), details); Object.entries(row.outputs).forEach(([index, values]) => node('p', value.rules[Number(index)] + '\n' + outputs(values), details).className = 'ji-values'); node('p', 'Final local values\n' + display(row.final), details).className = 'ji-values'; });
    cell.repeated.forEach(row => node('p', value.rules[row.procedure] + ' / repeated local state unchanged: ' + display(row.same_local_state) + '. This is not permission to repeat an outside action.', block));
  }
  function render(value) { qualified = null; by('run').hidden = true; by('inputs').replaceChildren(); by('result').replaceChildren(); node('h3', value.confirmed ? 'Original request complete' : 'Original request not confirmed complete', by('result')); node('p', value.message, by('result'));
    if (!value.current) return; const result = value.result;
    if (!result) { if (value.observations?.length) node('p', value.observations.length + ' complete starting-state observations were retained before work stopped. The entire check is not confirmed complete.', by('result')); return; }
    if (value.kind === 'qualify') { node('h4', result.qualified ? 'Checked local order rules are available' : 'Combined behavior remains unresolved', by('result')); node('p', result.cells.filter(cell => cell.unambiguous).length + ' of ' + result.cells.length + ' starting states have one supported combined result. Every safe order is retained; differing final results remain unresolved.', by('result'));
      const details = node('details', undefined, by('result')); node('summary', 'All checked starting states and separate results', details); result.cells.forEach(cell => describeCell(cell, value, details));
      const work = node('details', undefined, by('result')); node('summary', 'Work performed and separate comparison', work); node('p', result.native_runs + ' native rule calls; ' + result.native_steps + ' observed local calculation boundaries; ' + result.guard_searches + ' bounded order-rule searches. The separate complete order enumeration matched: ' + display(result.same_information_orders_matched) + '. Complete calculation: ' + Math.round(result.elapsed_ms) + ' ms. Reviewing and admitting work, saving the final result and browser time are additional.', work);
      const hazards = node('details', undefined, by('result')); node('summary', 'Shared values and changes another rule reads', hazards); result.hazards.forEach(row => node('p', value.rules[row.first] + ' before ' + value.rules[row.second] + '\nChanges values the second rule reads: ' + (row.changes_read_values.join(', ') || 'None') + '\nBoth update: ' + (row.shared_updates.join(', ') || 'None'), hazards).className = 'ji-values');
      if (result.qualified) { qualified = value; by('run').hidden = false; Object.entries(result.inputs).forEach(([name, declaration]) => field(name, declaration)); selection({kind: 'joint_rule', id: value.id}); }
    } else { node('p', 'Complete combined execution: ' + display(result.complete), by('result')); Object.entries(result.results).forEach(([index, values]) => node('p', value.rules[Number(index)] + '\n' + outputs(values), by('result')).className = 'ji-values'); }
  }
  async function read() { if (busy) return; const identifier = by('history').value || pending?.id; if (!identifier) { by('error').textContent = 'Choose an original request first.'; return; } const started = generation; lock(true); by('error').textContent = ''; try { const value = await request('/original/' + encodeURIComponent(identifier)); if (started === generation) render(value); } catch (error) { if (started === generation) { by('result').replaceChildren(); by('error').textContent = error.message; } } finally { if (started === generation) lock(false); } }
  async function review(kind = 'qualify') {
    if (busy || kind === 'qualify' && !state?.enabled) return; const started = generation; let choices;
    try { if (kind === 'run') { if (!qualified || !by('run').reportValidity()) return; const inputs = {}; by('inputs').querySelectorAll('[data-input]').forEach(input => { const value = input.dataset.kind === 'boolean' ? input.value === 'yes' : Number(input.value); if (input.dataset.kind === 'integer' && !Number.isSafeInteger(value)) throw new Error('Enter a whole number inside its displayed bounds.'); inputs[input.dataset.input] = value; }); choices = {kind, original: qualified.id, inputs}; }
      else { const selected = kept(); if (selected.some(rows => rows.length < 2) || selected.flat().length > 8) throw new Error('Choose at least two original cases for each rule, up to eight total.'); choices = {kind, first: picks[0].value, second: picks[1].value, evidence: selected.flat()}; }
    } catch (error) { by('error').textContent = error.message; return; }
    lock(true); invalidate(); by('error').textContent = '';
    try { const value = await request('/review', {...choices, context, revision: state?.revision || '0'.repeat(64)}); if (started !== generation) return;
      if (!Array.isArray(value.changes) || value.changes.length > 512 || value.changes.some(row => !row || Object.keys(row).sort().join(',') !== 'after,label' || typeof row.label !== 'string' || typeof row.after !== 'string')) throw new Error('The complete review cannot be displayed. No confirmation is available.');
      prepared = value; const preview = by('preview'); renderReview(preview, value.changes); preview.hidden = false; preview.prepend(node('h3', 'Review the complete combined local work')); const label = node('label', undefined, preview); label.className = 'ji-check'; const consent = node('input', undefined, label); consent.type = 'checkbox'; node('span', 'I reviewed both complete rules, original local cases, shared starting bounds, full work allowance and current permission. I authorize only this displayed local calculation.', label); const button = node('button', 'Confirm complete joint work', preview); button.type = 'button'; button.className = 'btn btn--primary'; button.dataset.confirm = ''; button.disabled = true; consent.addEventListener('change', () => button.disabled = busy || !consent.checked); button.addEventListener('click', () => void apply()); const cancel = node('button', 'Cancel this review', preview); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', invalidate); preview.scrollIntoView({block: 'start'});
    } catch (error) { if (started === generation) by('error').textContent = error.message; } finally { if (started === generation) lock(false); }
  }
  async function apply() { if (busy || !prepared || !by('preview').querySelector('input')?.checked) return; const value = prepared, started = generation; pending = {id: value.operation, context}; try { sessionStorage.setItem(storage, JSON.stringify(pending)); } catch (_) {} lock(true); by('error').textContent = '';
    try { const saved = await request('/apply', {token: value.token, confirmed: true}); if (started !== generation) return; dirty = false; invalidate(); render(saved); await history(); }
    catch (error) { if (started === generation) { invalidate(); by('error').textContent = error.message; by('status').textContent = 'Read the original outcome below. Uncertain work never repeats or resumes automatically.'; if (!Array.from(by('history').options).some(item => item.value === pending.id)) by('history').appendChild(new Option('Original request · check outcome', pending.id)); by('history').value = pending.id; } } finally { if (started === generation) lock(false); }
  }
  async function open(value, stillCurrent = () => true) { if (!value || value.context !== context || typeof value.first !== 'string' || typeof value.second !== 'string' || busy || !stillCurrent()) return false; const started = generation, next = await request(query(value.first, value.second)); if (started !== generation || busy || !stillCurrent() || !next.enabled || !next.flows.some(row => row.value === value.first) || !next.flows.some(row => row.value === value.second)) return false;
    const replacing = !state || state.revision !== next.revision; if (dirty && replacing && (typeof window.mvConfirm !== 'function' || !await window.mvConfirm('Opening these rules replaces current original-case selections. Continue?', {okText: 'Replace current selections'}) || started !== generation || busy || !stillCurrent())) return false;
    if (!stillCurrent()) return false; adopt(next, replacing ? [[], []] : kept()); by('author-h').focus(); return true;
  }
  window.LightworkJointRules = {open, renderReview};
  picks.forEach(pick => pick.addEventListener('change', () => void refresh())); by('form').addEventListener('input', event => { if (!picks.includes(event.target)) dirty = true; invalidate(); }); by('run').addEventListener('input', () => { dirty = true; invalidate(); }); by('refresh').addEventListener('click', () => void refresh()); by('review').addEventListener('click', () => void review()); by('run-review').addEventListener('click', () => void review('run')); by('read').addEventListener('click', () => void read());
  window.addEventListener('beforeunload', event => { if (dirty && !busy) { event.preventDefault(); event.returnValue = ''; } }); document.addEventListener('lightwork:workspace-changed', clear); document.addEventListener('lightwork:account-context-changed', clear); window.addEventListener('lightwork:context-changed', clear); document.addEventListener('lightwork:copilot-context-changed', event => { if (!publishing && event.detail?.reason !== 'selection') clear(); });
  const params = new URLSearchParams(location.search); void refresh(params.get('first') || '', params.get('second') || '').then(() => { const identifier = params.get('original'); if (/^PJI-[a-f0-9]{32}$/.test(identifier || '')) { pending = {id: identifier, context}; if (!Array.from(by('history').options).some(item => item.value === identifier)) by('history').appendChild(new Option('Original request · check outcome', identifier)); by('history').value = identifier; void read(); } });
})();
