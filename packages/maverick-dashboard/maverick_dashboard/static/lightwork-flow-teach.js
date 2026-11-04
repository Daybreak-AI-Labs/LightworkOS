// "Teach this flow": teach an AI step from examples, build a flow from reviewed
// runs, and learn from signed examples. Every learning call is checked on the
// server; this page only collects choices, shows plain results and saves the
// resulting draft through the normal flow save when the person asks.
(() => {
  'use strict';
  const root = document.getElementById('flow-teach');
  if (!root) return;
  const flowId = root.dataset.flow || '';
  const enc = encodeURIComponent(flowId);
  const $ = id => document.getElementById(id);
  const KIND = { integer: 'Whole number', string: 'Text', boolean: 'Yes or no' };
  const STATUS = { accepted: 'Reviewed and accepted', awaiting_review: 'Waiting for review', rejected: 'Not accepted',
    withdrawn: 'No longer used', expired: 'Expired', none: 'Not collected as an example' };
  const state = { overview: null, flow: null, artifact: null, recipe: null, pkg: null, bundles: [], trust: null,
    question: null, draft: null, draftMode: null, busy: false, ruleStep: null, artifactWire: null };
  let authoringGeneration = 0, accountGeneration = 0, acquiredDraft = null;
  root.addEventListener('input', () => { authoringGeneration++; });
  root.addEventListener('change', () => { authoringGeneration++; });
  function acquisitionContextChanged(event) {
    if (event.detail && event.detail.reason === 'selection') return;
    accountGeneration++;
    if (acquiredDraft) {
      if (state.draft === acquiredDraft.flow) { state.draft = null; $('ft-save').hidden = true; }
      acquiredDraft = null;
      if ($('ft-acquisition-review')) $('ft-acquisition-review').remove();
      syncNextActions();
    }
  }
  ['lightwork:account-context-changed', 'lightwork:workspace-changed', 'lightwork:copilot-context-changed'].forEach(name => {
    window.addEventListener(name, acquisitionContextChanged);
    document.addEventListener(name, acquisitionContextChanged);
  });
  window.addEventListener('lightwork:context-changed', acquisitionContextChanged);

  function make(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function say(text, id) { window.mvStatus($(id || 'ft-status'), text); }
  function human(value) { return typeof window.mvHuman === 'function' ? window.mvHuman(value) : String(value).replace(/[_.-]+/g, ' '); }
  function failText(failure, what) {
    const plain = failure instanceof Error && typeof window.mvPlainDetail === 'function' && window.mvPlainDetail(failure.message);
    if (plain) return plain;
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, what) : 'Could not ' + what + '. Try again.';
  }
  async function api(path, body, method, source) {
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    const current = source || (state.overview && state.overview.flow);
    if (body !== undefined && path.startsWith('/api/v1/flows/' + enc + '/teach/') && current && current.version && current.revision) {
      headers['X-Lightwork-Flow-Version'] = String(current.version);
      headers['X-Lightwork-Flow-Revision'] = current.revision;
      if (current.context) headers['X-Lightwork-Teaching-Context'] = current.context;
    }
    const rulePath = path.startsWith('/api/v1/flows/' + enc + '/teach/rule/');
    const draftPath = path.endsWith('/draft') && path.startsWith('/api/v1/flows/');
    const questionPath = path.startsWith('/api/v1/flows/' + enc + '/operator-questions');
    if (rulePath || draftPath || questionPath || path === '/api/v1/flows/' + enc || path === '/api/v1/flows') {
      const response = await fetch(path, {method: method || (body === undefined ? 'GET' : 'POST'), cache: 'no-store',
        credentials: 'same-origin', headers, body: body === undefined ? undefined : typeof body === 'string' ? body : ruleBody(body)});
      if (!response.ok) throw response;
      return FDRecipeInputs.responseJson(response);
    }
    return window.mvFetchJSON(path, {method: method || (body === undefined ? 'GET' : 'POST'), cache: 'no-store', headers, body});
  }
  function whole(text, limit) {
    if (!/^-?(0|[1-9]\d*)$/.test(text) || text === '-0' || text.length > 26) return null;
    const value = BigInt(text);
    return value < -limit || value > limit ? null : text;
  }
  // Only reviewed whole-number answers and retained native artifacts use exact
  // JSON literals. Ordinary inputs stay within the native safe integer bounds.
  function ruleBody(body) {
    return '{' + Object.keys(body).map(key => {
      let value;
      if (key === 'artifact') {
        if (body.artifact !== state.artifact || !state.artifactWire) throw new Error('Load the current rule before continuing.');
        const holder = FDRecipeInputs.parseText('{"artifact":' + state.artifactWire + '}');
        if (JSON.stringify(holder.artifact) !== JSON.stringify(body.artifact)) throw new Error('The learned rule changed. Load it again.');
        value = FDRecipeInputs.fieldText(holder, 'artifact');
      } else if (key === 'flow') value = FDRecipeInputs.flowText(body.flow);
      else if (key === 'output' && $('tq-answer-wrap').querySelector('[data-kind]')?.dataset.kind === 'integer') {
        value = whole(String(body.output), 1000000000000000000000000n);
        if (value === null) throw new Error('Enter the complete whole-number answer within the supported range.');
      }
      else if (key === 'examples') value = '[' + body.examples.map(example => {
        const integer = (body.output_kind || state.artifact && state.artifact.spec.output_type || $('tr-output').value) === 'integer';
        const answer = integer ? whole(String(example.output), 1000000000000000000000000n) : JSON.stringify(example.output);
        if (answer === null) throw new Error('Enter each whole-number answer in full, within the supported range.');
        return '{"inputs":' + JSON.stringify(example.inputs) + ',"output":' + answer + '}';
      }).join(',') + ']';
      else value = JSON.stringify(body[key]);
      return JSON.stringify(key) + ':' + value;
    }).join(',') + '}';
  }
  function syncNextActions() {
    const readyRecipe = Boolean(state.recipe) && !state.busy;
    const readyPackage = Boolean(state.pkg) && !state.busy;
    const signedReady = root.dataset.lineage === '1';
    ['sg-files', 'sg-trust', 'sg-package'].forEach(id => { if ($(id)) $(id).disabled = state.busy; });
    if ($('rc-more')) $('rc-more').disabled = !readyRecipe;
    if ($('rc-draft')) $('rc-draft').disabled = !readyRecipe;
    $('sg-refine').disabled = !readyPackage || !signedReady;
    $('sg-inspect').disabled = !readyPackage;
    $('sg-download').disabled = !readyPackage;
    $('sg-approve').disabled = !readyPackage || !signedReady;
    $('ft-save-go').disabled = !state.draft || state.busy || Boolean(acquiredDraft && !acquiredDraft.accepted.checked);
    $('ft-save-cancel').disabled = state.busy;
  }
  async function guarded(what, action, statusId) {
    if (state.busy) { say('Still finishing the last step. Try again in a moment.', statusId); return; }
    state.busy = true;
    root.setAttribute('aria-busy', 'true');
    syncNextActions();
    try { return await action(); } catch (failure) { say(failText(failure, what), statusId); return { status: 'unconfirmed' }; }
    finally { state.busy = false; root.setAttribute('aria-busy', 'false'); syncNextActions(); }
  }
  function readJsonFile(file) {
    return new Promise((resolve, reject) => {
      if (!file || file.size > 8 * 1024 * 1024) { reject(new Error('too large')); return; }
      const reader = new FileReader();
      reader.onload = () => { try { resolve(JSON.parse(String(reader.result || ''))); } catch (e) { reject(e); } };
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }
  function download(name, value) {
    const blob = new Blob([JSON.stringify(value)], { type: 'application/json' });
    const link = make('a');
    link.href = URL.createObjectURL(blob); link.download = name;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  // ---- saving drafts through the normal flow save --------------------------------
  function offerSave(draft, note, mode) {
    if (!acquiredDraft || acquiredDraft.flow !== draft) acquiredDraft = null;
    if (!acquiredDraft && $('ft-acquisition-review')) $('ft-acquisition-review').remove();
    state.draft = draft; state.draftMode = mode;
    $('ft-save-note').textContent = note;
    $('ft-save-go').textContent = mode === 'new' ? 'Save as a new flow' : 'Save as the flow’s next version';
    $('ft-save').hidden = false;
    syncNextActions();
    if (!state.busy) $('ft-save-go').focus();
  }
  $('ft-save-cancel').addEventListener('click', () => { state.draft = null; acquiredDraft = null;
    if ($('ft-acquisition-review')) $('ft-acquisition-review').remove();
    $('ft-save').hidden = true; syncNextActions(); say('Nothing was saved.'); });
  $('ft-save-go').addEventListener('click', () => guarded('save the flow', async () => {
    if (!state.draft) return;
    const draft = state.draft, acquisition = acquiredDraft, generation = accountGeneration;
    if (acquisition && !acquisition.accepted.checked) { say('Review the complete local rule and choose its separate acceptance first.'); return; }
    const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(state.draftMode === 'new'
      ? 'Save this as a new flow? It is not published or run until you choose to.'
      : 'Save this change as the flow’s next version? The published version keeps running until you publish again.',
      { okText: 'Save' });
    if (!ok) return;
    if (generation !== accountGeneration || state.draft !== draft || acquiredDraft !== acquisition) {
      say('Your current work was kept. Review the current flow and access before saving.'); return;
    }
    if (acquisition) {
      const current = await readAcquiredDraft(acquisition.id);
      if (generation !== accountGeneration || state.draft !== draft || acquiredDraft !== acquisition ||
          current.context !== acquisition.context || !sameSource(current.base, acquisition.source) ||
          current.flow_json !== acquisition.json || FDRecipeInputs.flowText(draft) !== acquisition.reviewed ||
          !acquisition.accepted.checked || JSON.stringify(current.adoption_review) !== JSON.stringify(acquisition.rows)) {
        say('The flow, examples or access changed. Your draft was kept. Return to the learning result and review its current draft again.'); return;
      }
    }
    const saved = await api('/api/v1/flows', acquisition
      ? '{"flow":' + acquisition.json + ',"acquisition":' + JSON.stringify(acquisition.id) + ',"acquisition_acceptance":true}' : { flow: draft });
    $('ft-save').hidden = true;
    state.draft = null;
    acquiredDraft = null;
    if ($('ft-acquisition-review')) $('ft-acquisition-review').remove();
    const link = make('a', null, 'Open it in the flow designer');
    link.href = '/flows/designer/' + encodeURIComponent(saved.id);
    $('ft-status').replaceChildren('Saved (version ' + saved.version + '). Publishing stays a separate step. ', link);
    if (state.draftMode !== 'new') await loadOverview();
  }));

  // ---- rules for a step ------------------------------------------------------------
  function inputRow(decl) {
    const row = make('div');
    const n = $('tr-inputs').children.length;
    const field = (label, control) => { const l = make('label', 'ft__cell', label); l.append(control); return l; };
    const name = make('input', 'input'); name.type = 'text'; name.maxLength = 64; name.value = decl.name || ('input_' + (n + 1));
    name.dataset.role = 'name';
    const kind = make('select', 'select'); kind.dataset.role = 'kind';
    Object.keys(KIND).forEach(k => { const o = make('option', null, KIND[k]); o.value = k; kind.append(o); });
    kind.value = decl.kind || 'string';
    const min = make('input', 'input'); min.type = 'number'; min.step = '1'; min.value = decl.min != null ? decl.min : 0; min.dataset.role = 'min';
    const max = make('input', 'input'); max.type = 'number'; max.step = '1'; max.value = decl.max != null ? decl.max : 100; max.dataset.role = 'max';
    const len = make('input', 'input'); len.type = 'number'; len.min = '1'; len.max = '1024'; len.value = decl.max_length || 200; len.dataset.role = 'len';
    const minL = field('Smallest', min), maxL = field('Largest', max), lenL = field('Longest text', len);
    const remove = make('button', 'btn btn--ghost', 'Remove'); remove.type = 'button';
    remove.setAttribute('aria-label', 'Remove this input');
    remove.addEventListener('click', () => { if ($('tr-inputs').children.length > 1) { row.remove(); renderExamples(); } });
    const sync = () => { minL.hidden = maxL.hidden = kind.value !== 'integer'; lenL.hidden = kind.value !== 'string'; renderExamples(); };
    kind.addEventListener('change', sync); name.addEventListener('change', renderExamples);
    row.append(field('Name', name), field('Kind', kind), minL, maxL, lenL, remove);
    $('tr-inputs').append(row);
    minL.hidden = maxL.hidden = kind.value !== 'integer'; lenL.hidden = kind.value !== 'string';
  }
  function declarations() {
    return Array.from($('tr-inputs').children).map(row => {
      const get = role => row.querySelector('[data-role="' + role + '"]');
      const decl = { name: get('name').value.trim(), kind: get('kind').value };
      if (decl.kind === 'integer') { decl.min = Number(get('min').value); decl.max = Number(get('max').value); }
      if (decl.kind === 'string') decl.max_length = Number(get('len').value);
      return decl;
    });
  }
  function valueControl(kind, value, label) {
    let control;
    if (kind === 'boolean') {
      control = make('select', 'select');
      [['true', 'Yes'], ['false', 'No']].forEach(([v, t]) => { const o = make('option', null, t); o.value = v; control.append(o); });
      control.value = value === false ? 'false' : 'true';
    } else {
      control = make('input', 'input');
      control.type = 'text';
      if (kind === 'integer') { control.inputMode = 'numeric'; control.required = true; control.pattern = '-?(0|[1-9][0-9]*)'; }
      control.value = value == null ? '' : String(value);
    }
    control.dataset.kind = kind;
    const wrap = make('label', 'ft__cell', label);
    wrap.append(control);
    return wrap;
  }
  function readValue(control) {
    if (control.dataset.kind === 'boolean') return control.value === 'true';
    if (control.dataset.kind === 'integer') {
      if (!control.value.trim()) return null;
      const exact = whole(control.value.trim(), control.dataset.answer ? 1000000000000000000000000n : 1000000000000n);
      return exact === null ? null : control.dataset.answer ? exact : Number(exact);
    }
    return control.value;
  }
  function exampleRow(values) {
    const row = make('div');
    declarations().forEach(decl => {
      const cell = valueControl(decl.kind, values ? values.inputs[decl.name] : null, human(decl.name));
      cell.querySelector('[data-kind]').dataset.input = decl.name;
      row.append(cell);
    });
    const answer = valueControl($('tr-output').value, values ? values.output : null, 'Right answer');
    answer.querySelector('[data-kind]').dataset.answer = '1';
    const remove = make('button', 'btn btn--ghost', 'Remove'); remove.type = 'button';
    remove.setAttribute('aria-label', 'Remove this example');
    remove.addEventListener('click', () => row.remove());
    row.append(answer, remove);
    $('tr-examples').append(row);
  }
  function examples() {
    return Array.from($('tr-examples').children).map(row => {
      const inputs = {};
      row.querySelectorAll('[data-input]').forEach(c => { inputs[c.dataset.input] = readValue(c); });
      return { inputs: inputs, output: readValue(row.querySelector('[data-answer]')) };
    });
  }
  function examplesReady() {
    for (const row of $('tr-inputs').children) {
      const get = role => row.querySelector('[data-role="' + role + '"]');
      if (get('kind').value === 'integer') {
        const low = whole(get('min').value.trim(), 1000000000000n), high = whole(get('max').value.trim(), 1000000000000n);
        if (low === null || high === null || BigInt(low) > BigInt(high)) {
          say('Choose complete whole-number input limits between −1,000,000,000,000 and 1,000,000,000,000.'); get('min').focus(); return false;
        }
      } else if (get('kind').value === 'string' && (!/^\d+$/.test(get('len').value) || Number(get('len').value) < 1 || Number(get('len').value) > 1024)) {
        say('Choose a longest text length between 1 and 1,024.'); get('len').focus(); return false;
      }
    }
    for (const control of $('tr-examples').querySelectorAll('[data-input],[data-answer]')) {
      control.setCustomValidity(control.dataset.kind === 'integer' && readValue(control) === null
        ? 'Enter a whole number in the supported range.' : '');
      if (!control.checkValidity()) {
        control.reportValidity(); control.focus();
        say('Complete the highlighted example value before learning.');
        return false;
      }
    }
    return true;
  }
  function renderExamples() {
    const kept = Array.from($('tr-examples').children).map(row => {
      const inputs = {}, read = control => control.dataset.kind === 'boolean' ? control.value === 'true' : control.value;
      row.querySelectorAll('[data-input]').forEach(control => { inputs[control.dataset.input] = read(control); });
      return {inputs, output: read(row.querySelector('[data-answer]'))};
    });
    $('tr-examples').replaceChildren();
    (kept.length ? kept : [null, null]).forEach(v => exampleRow(v));
  }
  function showRule(artifact, summary, exact) {
    state.artifact = artifact;
    state.artifactWire = exact;
    state.ruleStep = selectedStep();
    $('tr-summary').textContent = summary.rules + (summary.rules === 1 ? ' rule fits' : ' rules fit') + ' your '
      + summary.examples + (summary.examples === 1 ? ' example.' : ' examples.')
      + (summary.rules > 1 ? ' Where they disagree, the step asks its assistant.' : '');
    const box = $('tr-try');
    box.replaceChildren();
    const row = make('div');
    (summary.inputs || []).forEach(i => {
      const cell = valueControl(i.kind, null, human(i.name));
      cell.querySelector('[data-kind]').dataset.input = i.name;
      row.append(cell);
    });
    box.append(row);
    $('tr-result').hidden = false;
    $('tr-more').hidden = false;
    $('tr-try-out').textContent = '';
  }
  function constants() {
    const values = $('tr-constants').value.split(',').map(v => v.trim()).filter(Boolean);
    if (values.length > 8) throw new Error('Use at most eight constants. Your entered values were kept.');
    return values.map(v => {
      if (/^-?\d+$/.test(v)) {
        const exact = whole(v, 1000000000000n);
        if (exact === null) throw new Error('Whole-number constants must be between −1,000,000,000,000 and 1,000,000,000,000.');
        return Number(exact);
      }
      if (/^(yes|true)$/i.test(v)) return true;
      if (/^(no|false)$/i.test(v)) return false;
      if (Array.from(v).length > 1024) throw new Error('Each text constant must have at most 1,024 characters. Your text was kept.');
      return v;
    });
  }
  function selectedStep() { return $('tr-step').value; }
  function stepInfo() { return (state.overview && state.overview.steps || []).find(s => s.id === selectedStep()); }
  function showCurrent() {
    const step = stepInfo();
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', { detail: {
      selection: Object.assign({ kind: 'flow', id: flowId }, step ? { node_id: step.id } : {})
    } }));
    $('tr-current-actions').hidden = !(step && step.rule);
    if (!step) { $('tr-current').textContent = ''; return; }
    $('tr-current').textContent = !step.ready ? 'This step needs instructions and a place to keep its answer before it can learn a rule.'
      : step.rule ? 'This step has a learned rule from ' + step.rule.examples + ' examples.' : 'This step always asks its assistant.';
  }
  async function loadOverview() {
    state.overview = await api('/api/v1/flows/' + enc + '/teach');
    const select = $('tr-step');
    const before = select.value;
    select.replaceChildren();
    const steps = state.overview.steps || [];
    if (!steps.length) { const o = make('option', null, 'This flow has no AI steps'); o.value = ''; select.append(o); }
    steps.forEach(s => { const o = make('option', null, s.label + (s.rule ? ' (has a learned rule)' : '')); o.value = s.id; select.append(o); });
    if (before && steps.some(s => s.id === before)) select.value = before;
    showCurrent();
    const tools = $('rc-tools');
    if (tools) {
      tools.replaceChildren();
      (state.overview.tools || []).forEach(t => {
        const label = make('label');
        const box = make('input'); box.type = 'checkbox'; box.value = t; box.checked = true;
        label.append(box, ' ' + human(t));
        tools.append(label);
      });
      if (!(state.overview.tools || []).length) tools.append(make('p', 'muted', 'This flow has no actions yet.'));
    }
  }
  function sameSource(left, right) {
    return left && right && left.id === right.id && left.version === right.version && left.revision === right.revision;
  }
  async function readAcquiredDraft(id) {
    const response = await fetch('/api/v1/operator-acquisition/' + encodeURIComponent(id) + '/draft', {
      credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' }
    });
    if (!response.ok) throw response;
    const raw = await response.text();
    if (raw.length > 16 * 1024 * 1024) throw new Error('The complete learning review is too large to open safely.');
    const result = JSON.parse(raw);
    if (!result || result.saved !== false || result.published !== false || !/^[a-f0-9]{64}$/.test(result.context || '') ||
        typeof result.flow_json !== 'string' || !result.flow || result.flow.id !== flowId ||
        !sameSource(result.base, result.flow) || typeof result.note !== 'string' ||
        !Array.isArray(result.adoption_review) || !result.adoption_review.length || result.adoption_review.length > 1000 ||
        result.adoption_review.some(row => !row || typeof row !== 'object' || Array.isArray(row) ||
          Object.keys(row).sort().join(',') !== 'label,value' || typeof row.label !== 'string' || typeof row.value !== 'string') ||
        new TextEncoder().encode(JSON.stringify(result.adoption_review)).length > 6000000)
      throw new Error('The prepared learning result could not be confirmed.');
    result.flow = FDRecipeInputs.parseText(result.flow_json);
    if (!sameSource(result.base, result.flow)) throw new Error('The prepared learning result changed.');
    return result;
  }
  function showAcquisitionReview(rows) {
    if ($('ft-acquisition-review')) $('ft-acquisition-review').remove();
    const section = make('section', 'panel ft__section'); section.id = 'ft-acquisition-review';
    section.append(make('h2', null, 'Review and accept the local rule'));
    rows.forEach(row => {
      const detail = /^Recorded (source details|resulting definition)$/.test(row.label);
      const box = make(detail ? 'details' : 'div', 'ft__result');
      box.append(make(detail ? 'summary' : 'h3', null, row.label));
      const value = make('p', null, row.value); value.style.whiteSpace = 'pre-wrap'; value.style.overflowWrap = 'anywhere';
      box.append(value); section.append(box);
    });
    const label = make('label', 'ft__inline'), accepted = make('input'); accepted.type = 'checkbox';
    label.append(accepted, 'I reviewed the complete sources, examples and consequences, and independently accept this local rule.');
    accepted.addEventListener('change', syncNextActions); section.append(label);
    $('ft-save').before(section);
    return accepted;
  }
  async function receiveAcquisition(initialGeneration) {
    const id = new URLSearchParams(location.search).get('acquisition');
    if (!id) return false;
    if (!/^OAC-[a-f0-9]{32}$/.test(id)) { say('This learning result link does not work. Open the original learning result again.'); return true; }
    const source = state.overview && state.overview.flow, generation = accountGeneration;
    const entered = () => authoringGeneration !== initialGeneration || state.draft || state.artifact || state.recipe ||
      state.pkg || state.question || state.trust || state.bundles.length;
    const unchanged = () => generation === accountGeneration && !entered() &&
      sameSource(source, state.overview && state.overview.flow) && state.overview.flow.context === source.context;
    if (!source || entered()) { say('Your entered work was kept. The prepared learning result was not loaded.'); return true; }
    const result = await readAcquiredDraft(id);
    if (!unchanged() || result.context !== source.context || !sameSource(result.base, source)) {
      say('Your entered work was kept. The flow, examples or access changed; open the current learning result again.'); return true;
    }
    const latest = await api('/api/v1/flows/' + enc + '/teach');
    if (!unchanged() || !sameSource(latest.flow, source) || latest.flow.context !== source.context) {
      say('Your entered work was kept. The flow or access changed while the result loaded.'); return true;
    }
    acquiredDraft = { id, context: result.context, source, flow: result.flow,
      json: result.flow_json, reviewed: FDRecipeInputs.flowText(result.flow), rows: result.adoption_review,
      accepted: showAcquisitionReview(result.adoption_review) };
    offerSave(result.flow, result.note, 'update');
    say('The checked local rule is ready to review and save. Nothing was saved or published.');
    return true;
  }
  $('tr-step').addEventListener('change', showCurrent);
  $('tr-add-input').addEventListener('click', () => { if ($('tr-inputs').children.length < 6) { inputRow({}); renderExamples(); } });
  $('tr-add-example').addEventListener('click', () => { if ($('tr-examples').children.length < 64) exampleRow(null); });
  $('tr-output').addEventListener('change', renderExamples);
  async function learnRuleFromFields(source) {
    if (!examplesReady()) return { status: 'needs_input', message: 'Complete the highlighted example value on Teach before learning.' };
    const style = document.querySelector('input[name="tr-style"]:checked').value;
    const result = await api('/api/v1/flows/' + enc + '/teach/rule/learn', {
      inputs: declarations(), output_kind: $('tr-output').value, examples: examples(), constants: constants(),
      combined: style === 'combined', max_operations: Number($('tr-ops').value) || 3
    }, undefined, source);
    showRule(result.artifact, result.summary, FDRecipeInputs.fieldText(result, 'artifact'));
    say('Learned. Try some inputs, then use the rule in the step.');
    return { status: 'learned' };
  }
  $('tr-learn').addEventListener('click', () => guarded('learn from these examples', () => learnRuleFromFields()));
  async function refineRuleFromFields(source) {
    if (!state.artifact) return;
    if (!examplesReady()) return { status: 'needs_input', message: 'Complete the highlighted example value on Teach before adding it.' };
    const result = await api('/api/v1/flows/' + enc + '/teach/rule/add-examples', { artifact: state.artifact, examples: examples() }, undefined, source);
    showRule(result.artifact, result.summary, FDRecipeInputs.fieldText(result, 'artifact'));
    say('Added. The earlier examples were kept.');
    return { status: 'learned' };
  }
  $('tr-more').addEventListener('click', () => guarded('add these examples', () => refineRuleFromFields()));
  $('tr-try-go').addEventListener('click', () => guarded('try the rule', async () => {
    if (!state.artifact) return;
    const inputs = {};
    $('tr-try').querySelectorAll('[data-input]').forEach(c => { inputs[c.dataset.input] = readValue(c); });
    const result = await api('/api/v1/flows/' + enc + '/teach/rule/try', { artifact: state.artifact, inputs: inputs });
    const value = result.value === true ? 'Yes' : result.value === false ? 'No'
      : typeof result.value === 'number' ? FDRecipeInputs.fieldText(result, 'value') : result.value;
    $('tr-try-out').textContent = (result.answered ? 'Answer: ' + value + '. ' : '') + result.explanation;
  }, 'tr-try-out'));
  $('tr-attach').addEventListener('click', () => guarded('use the rule in this step', async () => {
    if (!state.artifact || !selectedStep()) { say('Choose a step first.'); return; }
    const result = await api('/api/v1/flows/' + enc + '/teach/rule/attach', { artifact: state.artifact, node_id: selectedStep() });
    offerSave(result.draft, result.note, 'update');
  }));
  $('tr-remove').addEventListener('click', () => guarded('remove the learned rule', async () => {
    const result = await api('/api/v1/flows/' + enc + '/teach/rule/remove', { node_id: selectedStep() });
    offerSave(result.draft, result.note, 'update');
  }));
  async function loadCurrentRule() {
    const flow = await api('/api/v1/flows/' + enc);
    const node = (flow.nodes || []).find ? (flow.nodes || []).find(n => n.id === selectedStep()) : (flow.nodes || {})[selectedStep()];
    const holder = node && node.learned_operator
      ? FDRecipeInputs.parseText(FDRecipeInputs.fieldText(node, 'learned_operator')) : null;
    const artifact = holder && holder.artifact;
    if (!artifact) { say('This step has no learned rule.'); return; }
    const spec = artifact.spec || {};
    $('tr-inputs').replaceChildren();
    Object.keys(spec.inputs || {}).sort().forEach(name => inputRow(Object.assign({ name: name, kind: spec.inputs[name].type }, spec.inputs[name])));
    $('tr-output').value = spec.output_type || 'string';
    $('tr-examples').replaceChildren();
    exampleRow(null);
    showRule(artifact, { rules: (artifact.candidates || []).length || 1, examples: artifact.example_count || 0,
      inputs: Object.keys(spec.inputs || {}).sort().map(n => ({ name: n, kind: spec.inputs[n].type })) }, FDRecipeInputs.fieldText(holder, 'artifact'));
    say('The current rule is loaded. Add examples to improve it, or try it.');
    return { status: 'ready' };
  }
  $('tr-use-current').addEventListener('click', () => guarded('load the current rule', loadCurrentRule));

  // ---- questions about unclear cases (existing reviewed-question routes) -----------
  if ($('tq-ask')) {
    $('tq-ask').addEventListener('click', () => guarded('find an unclear case', async () => {
      const step = stepInfo();
      if (!step || !step.rule) { say('Choose a step with a saved learned rule first.', 'tq-status'); return; }
      const f = state.overview.flow;
      const record = await api('/api/v1/flows/' + enc + '/operator-questions', { node_id: step.id, version: f.version, revision: f.revision });
      state.question = record;
      if (record.status === 'draft_ready') { await reviewedDraft(record.id); return; }
      if (record.status !== 'awaiting_answer' || !record.question || !record.question.inputs) {
        $('tq-case').hidden = true;
        say(record.status === 'equivalent' ? 'Every rule gives the same answer for every possible input. There is nothing to ask.'
          : 'No unclear case was found in the time allowed. The rules may still disagree on inputs not checked.', 'tq-status');
        return;
      }
      const inputs = record.question.inputs;
      const question = FDRecipeInputs.parseText(FDRecipeInputs.fieldText(record, 'question'));
      const predictions = FDRecipeInputs.parseText(FDRecipeInputs.fieldText(question, 'predictions'));
      $('tq-inputs').textContent = 'For ' + Object.keys(inputs).map(k => human(k) + ' = ' + inputs[k]).join(', ') + ', the rules answer: '
        + predictions.map(p => (typeof p.output === 'number' ? FDRecipeInputs.fieldText(p, 'output') : String(p.output))
          + ' (' + p.candidate_count + ')').join(' or ') + '.';
      const kind = (step.rule && step.rule.output_kind) || 'string';
      const wrap = $('tq-answer-wrap');
      wrap.replaceChildren(valueControl(kind, null, 'The right answer'));
      wrap.querySelector('[data-kind]').dataset.answer = '1';
      $('tq-case').hidden = false;
      say('What should the answer be?', 'tq-status');
    }, 'tq-status'));
    $('tq-answer').addEventListener('click', () => guarded('record your answer', async () => {
      const record = state.question;
      if (!record) return;
      const reason = $('tq-reason').value.trim();
      if (!reason) { say('Say briefly why this is the right answer.', 'tq-status'); return; }
      const control = $('tq-answer-wrap').querySelector('[data-kind]'), output = readValue(control);
      if (output === null) { say('Enter the complete whole-number answer within the supported range.', 'tq-status'); control.focus(); return; }
      const answered = await api('/api/v1/flows/' + enc + '/operator-questions/' + record.id + '/answer',
        { expected_revision: record.revision, output: output, reviewed: true, rationale: reason });
      $('tq-case').hidden = true;
      if (answered.status === 'draft_ready') await reviewedDraft(record.id);
      else say('Your answer was recorded.', 'tq-status');
    }, 'tq-status'));
  }
  async function reviewedDraft(questionId) {
    const result = await api('/api/v1/flows/' + enc + '/operator-questions/' + questionId + '/draft');
    offerSave(result.flow, 'Your answer was added to the step’s rule. Save to keep it; publishing stays separate.', 'update');
    say('Your answer is ready to save.', 'tq-status');
  }

  // ---- flows from reviewed runs ------------------------------------------------------
  function runRow(run, name, eligible) {
    const item = make('div');
    const label = make('label');
    const box = make('input'); box.type = 'checkbox'; box.value = run.run_id; box.name = name; box.disabled = !eligible;
    const when = run.started && typeof window.mvWhen === 'function' ? window.mvWhen(run.started) : 'Run';
    const permission = run.status === 'accepted' && !run.can_learn
      ? (run.grant ? ' · Learning permission ended' : ' · Allow learning from its run page first') : '';
    label.append(box, ' ' + when + ' · ' + (STATUS[run.status] || human(run.status)) + permission);
    item.append(label);
    const review = make('a', 'btn btn--ghost', 'Open run and learning review');
    review.href = '/flows/' + enc + '/runs/' + encodeURIComponent(run.run_id);
    review.target = '_blank'; review.rel = 'noopener';
    review.setAttribute('aria-label', 'Open run and learning review in a new tab');
    item.append(review);
    return item;
  }
  function checked(name) { return Array.from(document.querySelectorAll('input[name="' + name + '"]:checked')).map(b => b.value); }
  async function loadRuns() {
    const selected = checked('rc-run');
    const data = await api('/api/v1/flows/' + enc + '/teach/examples');
    state.runs = data.runs || [];
    if ($('rc-runs')) {
      $('rc-runs').replaceChildren();
      if (!data.available) $('rc-runs').append(make('p', 'muted', data.message || 'Reviewed examples aren’t available.'));
      else if (!state.runs.length) $('rc-runs').append(make('p', 'muted', 'This flow has no runs yet. Run it, then review runs as examples.'));
      state.runs.forEach(run => $('rc-runs').append(runRow(run, 'rc-run', run.can_learn)));
      $('rc-runs').querySelectorAll('input[name="rc-run"]').forEach(box => { box.checked = !box.disabled && selected.includes(box.value); });
    }
    $('sg-runs').replaceChildren();
    const signable = root.dataset.lineage === '1' ? state.runs.filter(r => r.can_sign) : [];
    if (!signable.length) $('sg-runs').append(make('p', 'muted', root.dataset.lineage === '1'
      ? 'No runs are allowed for learning right now. Review a run and grant learning permission from its run page.'
      : 'Signed learning is not ready. An administrator can check it in Settings.'));
    signable.forEach(run => {
      const row = runRow(run, 'sg-run', true);
      const button = make('button', 'btn btn--ghost', 'Make a signed copy'); button.type = 'button';
      button.addEventListener('click', () => guarded('make a signed copy', async () => {
        const bundle = await api('/api/v1/flows/' + enc + '/runs/' + encodeURIComponent(run.run_id) + '/episode-capture/signed-export',
          { expected_revision: run.revision, expected_episode_sha256: run.episode, expected_grant_sha256: run.grant });
        addBundle(bundle, 'Signed copy of a run');
      }));
      row.append(button);
      $('sg-runs').append(row);
    });
  }
  function syncRecipeStyle() {
    if (!$('rc-style')) return;
    $('rc-ops-wrap').hidden = $('rc-style').value === 'plain';
  }
  if ($('rc-learn')) {
    if ($('rc-refresh')) $('rc-refresh').addEventListener('click', () => guarded('refresh reviewed examples', async () => {
      await loadRuns(); say('The current example list is ready. Your learning result is kept.');
    }));
    $('rc-style').addEventListener('change', syncRecipeStyle);
    $('rc-learn').addEventListener('click', () => guarded('learn from these runs', async () => {
      const runs = checked('rc-run');
      if (runs.length < 2) { say('Choose at least two reviewed runs.'); return; }
      const allowed = Array.from($('rc-tools').querySelectorAll('input:checked')).map(b => b.value);
      if (!allowed.length) { say('Choose at least one action the new flow may use.'); return; }
      const result = await api('/api/v1/flows/' + enc + '/teach/recipe/learn', { run_ids: runs, tools: allowed,
        style: $('rc-style').value, max_operations: Number($('rc-ops').value) || 2 });
      showRecipe(result);
    }));
    $('rc-more').addEventListener('click', () => guarded('add these runs', () => refineRecipeFromFields()));
    $('rc-draft').addEventListener('click', () => guarded('make the new flow', async () => {
      const name = $('rc-name').value.trim();
      if (!name) { say('Name the new flow first.'); $('rc-name').focus(); return; }
      if (!state.recipe) { say('Choose reviewed runs and learn from them first.'); return; }
      const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
        'Approve the signed examples for this new flow? Future actions will check that each example is still allowed for learning.',
        { okText: 'Approve and prepare flow' });
      if (!ok) return;
      const result = await api('/api/v1/flows/' + enc + '/teach/recipe/draft', { package: state.recipe, name: name, teaching: $('rc-teach').checked });
      offerSave(result.draft, result.note, 'new');
    }));
  }
  function describeLearned(summary) {
    return 'Learned from ' + summary.runs + (summary.runs === 1 ? ' run' : ' runs') + ': '
      + (summary.actions || []).map(human).join(', then ') + '.'
      + (summary.choice ? ' The last action is a choice between two actions.' : '')
      + (summary.alternatives > 1 ? ' Some details can be worked out in more than one way, so the new flow asks before each action.' : '');
  }
  function showRecipe(result) {
    state.recipe = result.package;
    document.querySelectorAll('input[name="rc-run"]:checked').forEach(box => { box.checked = false; });
    $('rc-summary').textContent = describeLearned(result.summary);
    $('rc-teach-wrap').hidden = !result.summary.choice;
    $('rc-result').hidden = false; $('rc-more').hidden = false;
    syncNextActions();
    if (!$('rc-name').value) $('rc-name').value = (state.overview && state.overview.flow.name ? state.overview.flow.name + ' (learned)' : 'Learned flow');
    say('Learned. Name the new flow and make it, or add more runs.');
  }
  async function refineRecipeFromFields(source) {
    const runs = checked('rc-run');
    if (!state.recipe || !runs.length) { say('Open a learned procedure and choose the additional runs to add.'); return { status: 'needs_input' }; }
    const expected = {};
    for (const id of runs) {
      const row = (state.runs || []).find(item => item.run_id === id);
      if (!row || !row.can_learn) { say('A chosen example is no longer available. Refresh its review.'); return { status: 'unconfirmed' }; }
      expected[id] = { revision: row.revision, episode: row.episode, grant: row.grant };
    }
    showRecipe(await api('/api/v1/flows/' + enc + '/teach/recipe/refine',
      { package: state.recipe, run_ids: runs, expected_runs: expected }, undefined, source));
    await loadRuns();
    return { status: 'learned' };
  }
  window.LightworkFlowTeach = {
    showTeachingInputs: function (mode) {
      const target = $(mode === 'recipe_refine' ? 'rc-runs' : 'tr-examples');
      if (!target) return;
      target.scrollIntoView({ block: 'center', behavior: 'auto' });
      const input = target.querySelector('input,select,textarea');
      if (input) input.focus();
    },
    showRuleReview: function () {
      if (!state.artifact) return;
      $('tr-result').scrollIntoView({ block: 'center', behavior: 'auto' });
      const input = $('tr-try').querySelector('input,select,textarea');
      if (input) input.focus();
    },
    perform: async function (review) {
      const current = state.overview && state.overview.flow;
      if (!review || !['recipe_refine', 'rule_teach', 'rule_refine'].includes(review.mode) || review.flow_id !== flowId || !current || current.version !== review.version ||
          current.revision !== review.revision || (review.context && current.context !== review.context) ||
          (review.mode !== 'recipe_refine' && selectedStep() !== review.node_id))
        return { status: 'stale', message: 'The selected flow or step changed. Refresh Copilot before continuing.' };
      if (state.draft) return { status: 'needs_input', message: 'Save or cancel your current draft before preparing another learning result.' };
      const what = review.mode === 'recipe_refine' ? 'add these runs' : review.mode === 'rule_refine' ? 'add these examples' : 'learn from these examples';
      return guarded(what, async () => {
        if (review.mode === 'rule_refine' && (!state.artifact || state.ruleStep !== review.node_id)) {
          await loadCurrentRule();
          $('tr-examples').scrollIntoView({ block: 'center', behavior: 'auto' });
          return { status: 'needs_input', message: 'The saved rule is loaded. Enter the additional examples on Teach, then use this control again.' };
        }
        const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
          review.mode === 'recipe_refine' ? 'Add the selected reviewed runs to the current learned procedure? Its earlier signed sources are kept. Nothing is saved or published.' :
            'Learn from the current labelled examples on Teach? Review their inputs and answers first. Nothing is saved or published.',
          { okText: review.mode === 'rule_teach' ? 'Learn rule' : 'Add examples' });
        if (!ok) return { status: 'cancelled' };
        return review.mode === 'recipe_refine' ? refineRecipeFromFields(review) :
          review.mode === 'rule_refine' ? refineRuleFromFields(review) : learnRuleFromFields(review);
      });
    },
    acceptRecipe: async function (selectedFlow, result) {
      if (selectedFlow !== flowId || state.busy || !$('rc-result') || !result ||
          state.draft || !result.package || !result.summary || result.approved !== false) return false;
      if (state.recipe && (typeof window.mvConfirm !== 'function' || !await window.mvConfirm(
        'Replace the current unsaved learning result with this one? Saved flows are unchanged.',
        { okText: 'Review this result' }))) return false;
      if (state.busy || state.draft) return false;
      showRecipe(result);
      return true;
    },
    showRecipeReview: function () {
      if (!state.recipe || !$('rc-name')) return;
      $('rc-result').scrollIntoView({ block: 'center', behavior: 'auto' });
      $('rc-name').focus();
    }
  };

  // ---- signed examples ------------------------------------------------------------------
  async function addBundle(bundle, label) {
    const check = await api('/api/v1/flow-teach/signed-copy/check', { bundle: bundle, trust: state.trust || undefined });
    const item = make('li', 'mv-row');
    item.append(make('span', 'mv-row__title', label), make('span', 'muted', check.genuine
      ? ' · Genuine and unchanged. ' + check.withdrawal : ' · ' + check.message));
    if (check.genuine) {
      state.bundles.push(bundle);
      const save = make('button', 'btn btn--ghost', 'Download'); save.type = 'button';
      save.addEventListener('click', () => download('signed-example-' + state.bundles.length + '.json', bundle));
      item.append(save);
    }
    $('sg-set').append(item);
    say(check.genuine ? 'Signed example added.' : 'That signed example can’t be used.');
  }
  $('sg-files').addEventListener('change', () => guarded('read the signed examples', async () => {
    for (const file of Array.from($('sg-files').files || []).slice(0, 32)) {
      const value = await readJsonFile(file);
      const list = Array.isArray(value) ? value : [value];
      for (const bundle of list.slice(0, 32)) await addBundle(bundle, file.name);
    }
    $('sg-files').value = '';
  }));
  $('sg-trust').addEventListener('change', () => guarded('read the trust file', async () => {
    const file = $('sg-trust').files && $('sg-trust').files[0];
    state.trust = file ? await readJsonFile(file) : null;
    say(file ? 'The chosen trust file only previews who signed an example. Learning uses this workspace’s keys.' : 'Signed examples are checked against this workspace’s keys.');
  }));
  $('sg-package').addEventListener('change', () => guarded('open the learned file', async () => {
    const file = $('sg-package').files && $('sg-package').files[0];
    if (!file) return;
    const pkg = await readJsonFile(file);
    showPackage({ package: pkg, summary: { runs: (pkg.artifact && pkg.artifact.episode_count) || 0, actions: [], alternatives: 0 } });
  }));
  function showPackage(result) {
    state.pkg = result.package;
    $('sg-summary').textContent = describeLearned(result.summary) + ' It isn’t approved for governed use yet.';
    $('sg-result').hidden = false; $('sg-refine').hidden = false; $('sg-steps').replaceChildren();
    syncNextActions();
  }
  $('sg-learn').addEventListener('click', () => guarded('learn from the signed examples', async () => {
    if (state.bundles.length < 2) { say('Add at least two signed examples.'); return; }
    const style = $('sg-style').value;
    const tools = Array.from(new Set(state.bundles.flatMap(b => ((b.body || {}).contract || {}).allowed_tools || [])));
    if (style === 'workflow' || style === 'memory') {
      const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
        'Learn from these signed examples and approve the result for governed use now? Withdrawing any of the examples later stops it.',
        { okText: 'Learn and approve' });
      if (!ok) return;
    }
    const result = await api('/api/v1/flow-teach/signed/learn', { bundles: state.bundles, tools: tools.slice(0, 8), style: style });
    if (result.package) showPackage(result);
    else { say('Learned and approved for governed use.'); await loadApproved(); }
  }));
  $('sg-refine').addEventListener('click', () => guarded('add the signed examples', async () => {
    if (!state.pkg || !state.bundles.length) { say('Add signed examples first.'); return; }
    showPackage(await api('/api/v1/flow-teach/signed/refine', { package: state.pkg, bundles: state.bundles }));
  }));
  $('sg-inspect').addEventListener('click', () => guarded('show it as a flow', async () => {
    if (!state.pkg) return;
    const result = await api('/api/v1/flow-teach/signed/inspect', { package: state.pkg, name: 'Learned flow' });
    const list = $('sg-steps');
    list.replaceChildren();
    (result.steps || []).forEach(s => list.append(make('li', null, human(s.kind) + ': ' + human(s.label))));
    say(result.note);
  }));
  $('sg-download').addEventListener('click', () => { if (state.pkg) download('learned-recipe.json', state.pkg); });
  $('sg-approve').addEventListener('click', () => guarded('approve it for governed use', async () => {
    if (!state.pkg) return;
    const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
      'Approve this learned recipe for governed use in this workspace? Withdrawing any of its signed examples later stops it.',
      { okText: 'Approve' });
    if (!ok) return;
    await api('/api/v1/flows/recipe-lineage', { package: state.pkg });
    say('Approved. Make a flow from it in the list below.');
    await loadApproved();
  }));
  async function loadApproved() {
    let data;
    try { data = await api('/api/v1/flow-teach/approved'); } catch (_) { return; }
    const list = $('sg-approved');
    list.replaceChildren();
    if (!(data.recipes || []).length) { list.append(make('li', 'muted', 'No approved recipes yet. Teach a flow above and approve its recipe.')); return; }
    data.recipes.forEach(r => {
      const item = make('li', 'mv-row');
      const when = r.approved_at && typeof window.mvWhen === 'function' ? window.mvWhen(r.approved_at) : '';
      item.append(make('span', 'mv-row__title', 'Recipe approved ' + when), make('span', 'badge', human(r.status)));
      if (r.status === 'admitted') {
        const button = make('button', 'btn btn--ghost', 'Make a flow from it'); button.type = 'button';
        button.addEventListener('click', () => guarded('make a flow from it', async () => {
          const name = (state.overview && state.overview.flow.name ? state.overview.flow.name : 'Learned') + ' (approved recipe)';
          const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) + '-' + Math.random().toString(16).slice(2, 8);
          const draft = await api('/api/v1/flows/recipe-lineage/' + encodeURIComponent(r.id) + '/draft', { flow_id: id, name: name, teaching: false });
          offerSave(draft, 'A new flow from the approved recipe. Every action waits for approval. Save to keep it.', 'new');
        }));
        item.append(button);
      }
      list.append(item);
    });
  }

  // ---- start ---------------------------------------------------------------------------
  if ($('ft-refresh')) $('ft-refresh').addEventListener('click', () => guarded('refresh the flow', async () => {
    await loadOverview(); await loadRuns();
    say('The flow and examples are refreshed. Review the current step before continuing; your unsaved learning result is kept.');
  }));
  inputRow({ name: 'amount', kind: 'integer', min: 0, max: 1000 });
  renderExamples();
  syncRecipeStyle();
  syncNextActions();
  const initialAuthoringGeneration = authoringGeneration;
  guarded('load this flow', async () => {
    await loadOverview();
    await loadRuns();
    await loadApproved();
    if (!await receiveAcquisition(initialAuthoringGeneration)) say('');
  });
})();
