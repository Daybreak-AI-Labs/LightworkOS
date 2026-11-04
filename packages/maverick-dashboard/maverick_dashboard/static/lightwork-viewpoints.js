/* Reviewed, owned viewpoints and original-result recovery. No automatic AI replay. */
(() => {
  'use strict';
  const form = document.getElementById('vp-form'); if (!form) return;
  const question = document.getElementById('vp-question'), rounds = document.getElementById('vp-rounds');
  const forSide = document.getElementById('vp-for'), againstSide = document.getElementById('vp-against');
  const button = document.getElementById('vp-run'), refresh = document.getElementById('vp-refresh');
  const original = document.getElementById('vp-original'), picker = document.getElementById('vp-saved');
  const setup = document.getElementById('vp-setup');
  const status = document.getElementById('vp-status'), result = document.getElementById('vp-result'), preview = document.getElementById('vp-review');
  const SIDE = {for: 'The case for', against: 'The case against'};
  const VERDICT = {for: 'The judge found the case for stronger.', against: 'The judge found the case against stronger.', draw: 'The judge found both sides equally strong.'};
  let current = null, pending = null, reviewed = null, generation = 0, busy = false, dirty = false, recovery = null, ownsSelection = false;
  function product(node, text, values) {
    if (window.LightworkI18n) window.LightworkI18n.set(node, text, values);
    else node.textContent = text.replace(/\{(\w+)\}/g, (_, key) => values && values[key] !== undefined ? values[key] : _);
  }
  function make(tag, text, source = false) {
    const node = document.createElement(tag);
    if (text !== undefined) {
      if (source) {node.textContent = text; node.lang = 'und'; node.dir = 'auto'; node.dataset.userContent = '1';}
      else product(node, text);
    }
    return node;
  }
  function say(text) {product(status, text);}
  function invalidate() {reviewed = null; preview.replaceChildren();}
  function lock(value) {
    busy = value;
    [question, rounds, forSide, againstSide, picker, refresh].forEach(node => {node.disabled = value;});
    button.disabled = value || !current?.ready;
    original.disabled = value; original.hidden = !pending;
    button.setAttribute('aria-busy', String(value));
  }
  function choice() {
    return {question: question.value, rounds: Number(rounds.value), for_side: forSide.value || null, against_side: againstSide.value || null};
  }
  function selection(operation) {
    ownsSelection = !!operation;
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: operation ? {kind: 'viewpoints', operation} : {}}}));
  }
  function saved(context) {
    if (!context) return null;
    try {const value = JSON.parse(sessionStorage.getItem('viewpoints-original:' + context) || 'null'); return value?.context === context && /^[a-f0-9]{32}$/.test(value.operation) ? value : null;} catch (_) {return null;}
  }
  function remember(operation, context) {
    pending = {operation, context};
    sessionStorage.setItem('viewpoints-original:' + context, JSON.stringify(pending));
    original.hidden = false;
  }
  async function request(path, body) {
    const F = 'The request could not be checked. Your entered question is kept.';
    return window.mvFetchJSON('/api/v1/viewpoints' + path, {method: body ? 'POST' : 'GET', cache: 'no-store',
      headers: current?.context ? {'X-Lightwork-Viewpoints-Context': current.context} : {}, body: body || undefined, timeout: 20000,
      serverDetail: F, messages: {timeout: F, offline: F, unreadable: F},
      onAccess: () => {}, onContextChange: (error) => { error.accessChanged = true; }}, 'check the viewpoints');
  }
  function valid(data) {
    return data && (data.ran === false && typeof data.message === 'string' || data.ran === true && Array.isArray(data.turns) && data.turns.length <= 6 &&
      data.turns.every(turn => turn && Object.hasOwn(SIDE, turn.side) && typeof turn.text === 'string') &&
      Object.hasOwn(VERDICT, data.verdict) && typeof data.reason === 'string' && typeof data.key_point === 'string' && Number.isFinite(data.cost));
  }
  function showAnswers(data) {
    const verdict = make('section'); verdict.className = 'cs-viewpoints__verdict';
    verdict.append(make('h3', 'Verdict'), make('p', VERDICT[data.verdict]));
    if (data.reason) {const line = make('p'); line.append(make('span', 'Why:'), ' ', make('span', data.reason, true)); verdict.append(line);}
    if (data.key_point) {const line = make('p'); line.append(make('span', 'The point that decided it:'), ' ', make('span', data.key_point, true)); verdict.append(line);}
    result.append(verdict);
    for (const side of ['for', 'against']) {
      const turns = data.turns.filter(turn => turn.side === side); if (!turns.length) continue;
      const block = make('section'); block.className = 'cs-viewpoints__side'; block.append(make('h3', SIDE[side]));
      const list = make('ol'); turns.forEach(turn => list.append(make('li', turn.text, true))); block.append(list); result.append(block);
    }
    const line = make('p'); line.className = 'muted';
    product(line, 'This cost {cost}. It is advice to help you decide; no task or external action was started.', {cost: window.mvMoney ? window.mvMoney(data.cost) : '$' + data.cost.toFixed(4)});
    result.append(line);
  }
  function showOriginal(row) {
    result.replaceChildren(); result.hidden = false; result.append(make('h3', 'Your original viewpoints'), make('p', row.message));
    if (row.question) {result.append(make('h4', 'Original question'), make('p', row.question, true));}
    if (row.confirmed && valid(row.result)) {
      if (row.result.ran) showAnswers(row.result); else result.append(make('p', row.result.message));
    }
    say(row.confirmed ? 'Original answers are shown below. No new AI work was started.' : row.message);
  }
  function recoveryReady() {
    if (recovery || !current || !window.mvDraftRecovery) return;
    recovery = window.mvDraftRecovery.create({host: form, key: 'two-viewpoints', compact: true, read: choice,
      restore(value) {
        if (busy || !current || !value || Object.keys(value).sort().join(',') !== 'against_side,for_side,question,rounds' ||
            typeof value.question !== 'string' || value.question.length > 2000 || ![1, 2, 3].includes(value.rounds) ||
            [value.for_side, value.against_side].some(side => side !== null && (typeof side !== 'string' || side.length > 300)))
          throw new Error('Refresh current viewpoints choices before restoring. Your entered question is kept.');
        question.value = value.question; rounds.value = String(value.rounds); forSide.value = value.for_side || ''; againstSide.value = value.against_side || '';
        invalidate(); dirty = true; lock(false); say('Your draft is restored for review. No AI work was started.');
      }});
  }
  async function load() {
    if (busy) return; const started = ++generation; invalidate(); lock(true);
    try {
      const state = await request(''); if (started !== generation) return;
      if (current && current.context !== state.context) {changed(); return;}
      current = state; const chosen = picker.value; picker.replaceChildren();
      setup.hidden = state.ready;
      const empty = make('option', 'Choose an original question'); empty.value = ''; picker.append(empty);
      state.history.forEach(row => {const node = make('option', row.label + ' · ' + new Date(row.created_at * 1000).toLocaleString(), true); node.value = row.value; picker.append(node);});
      picker.value = state.history.some(row => row.value === chosen) ? chosen : '';
      pending = saved(state.context); recoveryReady(); say(state.ready ? 'Review your question and spending before starting. Original answers are available below.' : state.message);
    } catch (error) {if (started === generation) {if (error.accessChanged) {changed(); return;} current = null; say('Current choices are unavailable. Your entered question is kept. Refresh before starting.');}}
    finally {if (started === generation) lock(false);}
  }
  async function readOriginal(operation, select = true) {
    if (busy || !current) return; const started = ++generation; invalidate(); lock(true);
    try {
      const row = await request('/requests/' + operation); if (started !== generation) return;
      if (row.context !== current.context) {changed(); return;}
      remember(operation, row.context); showOriginal(row); if (select) selection(operation);
      if (!row.confirmed && row.worker === 'running') setTimeout(() => {if (started === generation) readOriginal(operation, false);}, 1500);
    } catch (error) {if (started === generation) {if (error.accessChanged) {changed(); return;} say('The original answer could not be checked. Nothing was repeated; your entered question is kept.');}}
    finally {if (started === generation) lock(false);}
  }
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !current?.ready || !form.reportValidity()) return;
    const started = ++generation, entered = choice(); invalidate(); lock(true);
    try {
      const row = await request('/review', {...entered, context: current.context, revision: current.revision}); if (started !== generation) return;
      reviewed = row; preview.append(make('h3', 'Review this complete AI request'));
      const fields = make('dl'); row.changes.forEach(change => {fields.append(make('dt', change.label), make('dd', String(change.after), true));}); preview.append(fields);
      const label = make('label'), check = make('input'); check.type = 'checkbox'; label.append(check, ' ', make('span', 'I reviewed the full question, positions, connected model and spending.'));
      const apply = make('button', 'Start reviewed viewpoints'); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.disabled = true;
      check.addEventListener('change', () => {apply.disabled = busy || !check.checked;});
      apply.addEventListener('click', async () => {
        if (busy || !check.checked || reviewed !== row || started !== generation || JSON.stringify(choice()) !== JSON.stringify(entered)) return;
        try {remember(row.operation, row.context);} catch (_) {say('The original request could not be kept in this browser. Nothing was submitted. Allow site storage before continuing.'); return;}
        lock(true); apply.disabled = true;
        try {
          const receipt = await request('/apply', {token: row.token, confirmed: true}); if (started !== generation) return;
          invalidate(); dirty = false; if (recovery) recovery.clear(); showOriginal(receipt); selection(row.operation);
        } catch (error) {if (started === generation) {if (error.accessChanged) {changed(); return;} invalidate(); say('The original reply is unconfirmed. Check original outcome before another request. Nothing will be repeated automatically.');}}
        finally {if (started === generation) lock(false);}
        if (started === generation) void readOriginal(row.operation, false);
      });
      const cancel = make('button', 'Cancel this review'); cancel.type = 'button'; cancel.className = 'btn btn--ghost';
      cancel.addEventListener('click', () => {if (!busy) {invalidate(); button.focus();}});
      preview.append(label, apply, cancel); say('No AI work has started. Review every field before confirming.'); check.focus();
    } catch (error) {if (started === generation) {if (error.accessChanged) {changed(); return;} say(error.message);}}
    finally {if (started === generation) lock(false);}
  });
  [question, rounds, forSide, againstSide].forEach(node => node.addEventListener('input', () => {invalidate(); dirty = !!question.value || !!forSide.value || !!againstSide.value;}));
  picker.addEventListener('change', () => {if (picker.value) void readOriginal(picker.value);});
  original.addEventListener('click', () => {if (pending) void readOriginal(pending.operation);});
  refresh.addEventListener('click', () => void load());
  function changed() {
    generation++; current = pending = null; invalidate(); dirty = false;
    if (recovery) {recovery.dispose(); recovery.panel.remove(); recovery = null;}
    question.value = forSide.value = againstSide.value = ''; rounds.value = '2'; picker.replaceChildren(); result.replaceChildren(); result.hidden = true;
    setup.hidden = true;
    if (ownsSelection) selection(''); say('Your account, workspace or access changed. Refresh before continuing.'); lock(false);
  }
  window.addEventListener('beforeunload', event => {if (dirty || busy && reviewed) {event.preventDefault(); event.returnValue = '';}});
  window.addEventListener('lightwork:drafts-ready', recoveryReady);
  document.addEventListener('lightwork:workspace-changed', changed); document.addEventListener('lightwork:account-context-changed', changed); window.addEventListener('lightwork:context-changed', changed);
  document.addEventListener('lightwork:copilot-context-changed', event => {if (event.detail?.reason !== 'selection') changed(event);});
  document.addEventListener('lightwork:copilot-selection', event => {if (event.detail?.selection?.kind !== 'viewpoints') ownsSelection = false;});
  document.addEventListener('lightwork:product-operation-complete', event => {if (event.detail?.operation === 'tasks.get_viewpoints') {invalidate(); if (!busy) void load();}});
  const initial = new URLSearchParams(location.search).get('viewpoints_request');
  void load().then(() => {if (current && /^[a-f0-9]{32}$/.test(initial || '')) {document.getElementById('viewpoints').open = true; void readOriginal(initial);}});
})();
