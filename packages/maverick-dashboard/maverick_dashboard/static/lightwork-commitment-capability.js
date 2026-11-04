(function () {
  'use strict';
  const $ = id => document.getElementById(id), api = '/api/v1/commitment-capability';
  const actionNames = {create:'Entered additional-work review',edit:'Replaced additional-work review',report:'Recorded completed trial report',test:'Ran local rule qualification',scope:'Reviewed source permission',withdraw:'Withdrew observation use',release:'Released waiting for unknown result',remove:'Removed current qualification'};
  const historyRoot = $('ccl-history');
  let historyContext = '', historyBusy = false, historyGeneration = 0;
  function clearHistory() { historyGeneration++; historyContext = ''; $('ccl-history-select').replaceChildren(new Option('Refresh your own originals', '')); $('ccl-history-result').replaceChildren(); }
  async function historical(path) {
    const stamp = historyGeneration;
    const value = await window.mvFetchJSON(api + path, {cache:'no-store', plainDetail:true, onAccess:clearPrivate, accessStatuses:[401,403,404]}, 'read your exact original qualification result');
    if (stamp !== historyGeneration) throw new Error('The selected context changed. Refresh your own original requests.');
    if (historyContext && historyContext !== value.context) { clearPrivate(); throw new Error('Your account or workspace changed. Refresh your own original requests.'); }
    historyContext = value.context; return value;
  }
  async function refreshHistory() {
    if (historyBusy) return; historyBusy = true;
    try { const value = await historical('/history'); $('ccl-history-select').replaceChildren(new Option('Choose an exact original request', '')); value.choices.forEach(row => $('ccl-history-select').add(new Option(row.label, row.value))); $('ccl-history-message').textContent = value.choices.length ? 'Only your own retained originals are listed. Current model or source permission is not granted by reading.' : 'No retained qualification requests are available to this account and workspace.'; }
    catch (error) { $('ccl-history-message').textContent = error.message; } finally { historyBusy = false; }
  }
  if (historyRoot) {
    $('ccl-history-refresh').onclick = refreshHistory;
    $('ccl-history-read').onclick = async () => {
      if (historyBusy) return; const reference = $('ccl-history-select').value; if (!reference) return;
      historyBusy = true;
      try { const [identifier,operation] = reference.split('|'), value = await historical('/original/' + identifier + '/' + operation), receipt = value.receipt, out = $('ccl-history-result'); out.replaceChildren();
        for (const line of [receipt.parent_name || 'Saved Promise review',actionNames[receipt.action] + ' · ' + (value.confirmed ? 'Recorded result' : 'Original result unknown'),
          value.message,'Actor: ' + receipt.actor + '. Recorded: ' + new Date(receipt.recorded_at * 1000).toLocaleString() + '.',
          receipt.result?.known === false ? 'No known Yes/No local observation was recorded.' : typeof receipt.result?.outcome === 'boolean' ? 'Original local rule outcome: ' + (receipt.result.outcome ? 'Yes' : 'No') : 'No local rule outcome is claimed by this original.',
          'Historical result only. No current model, availability, source permission or business action is confirmed.']) { const node = document.createElement('p'); node.textContent = line; out.append(node); }
        $('ccl-history-message').textContent = value.message;
      } catch (error) { $('ccl-history-message').textContent = error.message; } finally { historyBusy = false; }
    };
    document.addEventListener('lightwork:commitment-review', event => { if (!event.detail?.review) clearHistory(); });
    window.addEventListener('lightwork:context-changed', clearHistory);
    document.addEventListener('lightwork:workspace-changed', clearHistory);
    document.addEventListener('lightwork:account-context-changed', clearHistory);
    refreshHistory();
  }
  const root = $('ccl-panel');
  if (!root) return;
  let parent = null, current = null, review = null, busy = false, generation = 0, choices = [];
  const rowCounters = {offer:0, addition:0};
  const el = (tag, value) => { const node = document.createElement(tag); if (value !== undefined) node.textContent = String(value); return node; };
  const say = value => { $('ccl-message').textContent = value; };
  const date = value => new Date(value * 1000).toLocaleString();
  const local = value => { const d = new Date(value); if (!value || Number.isNaN(d.getTime())) throw new Error('Enter a complete date and time.'); return d.getTime() / 1000; };
  const inputDate = value => { const d = new Date(value * 1000), pad = v => String(v).padStart(2, '0'); return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const key = () => parent ? 'lightwork:commitment-capability:' + parent.context : '';
  function remembered() { try { return JSON.parse(sessionStorage.getItem(key()) || 'null'); } catch (_) { return null; } }
  function remember(value) { if (!key()) return; if (value) sessionStorage.setItem(key(), JSON.stringify(value)); else sessionStorage.removeItem(key()); }
  function lock(value) { busy = value; root.inert = value; root.setAttribute('aria-busy', String(value)); root.querySelectorAll('button,input,select,textarea').forEach(node => { node.disabled = value; }); }
  function clearPrivate() {
    if (!root) { clearHistory(); return; }
    generation++; parent = null; current = null; review = null; choices = []; root.hidden = true; $('ccl-review').hidden = true;
    root.querySelectorAll('input,textarea').forEach(node => { node.value = ''; });
    for (const name of ['ccl-results','ccl-originals','ccl-review-changes','ccl-offers','ccl-additions','ccl-requirements']) $(name).replaceChildren();
    for (const name of ['flow_id','output']) $('ccl-test').elements[name].replaceChildren(); $('ccl-withdraw').elements.observation.replaceChildren();
    clearHistory(); lock(false);
  }
  async function request(path, method = 'GET', body) {
    const selected = parent;
    if (!selected) throw new Error('Open an owned current Promise review first.');
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 20000);
    try {
      const result = await window.mvFetchJSON(api + path, {method, cache:'no-store', body, signal:abort.signal, plainDetail:true,
        headers:{'Content-Type':'application/json'}, onAccess:clearPrivate, accessStatuses:[401,403,404], messages:{offline:'The reply was interrupted. Read the exact original request; nothing repeats automatically.'}}, 'review additional work');
      if (parent !== selected || result.context !== selected.context) { clearPrivate(); throw new Error('The selected account, workspace or Promise review changed. Reload it.'); }
      return result;
    } finally { clearTimeout(timer); }
  }
  function rowIdentity(kind, container, retained) {
    if (retained) { const suffix = retained.match(new RegExp('^' + kind + '-(\\d+)$')); if (suffix) rowCounters[kind] = Math.max(rowCounters[kind], Number(suffix[1])); return retained; }
    let identifier;
    do { identifier = kind + '-' + (++rowCounters[kind]); } while (Array.from(container.children).some(row => row.dataset.id === identifier));
    return identifier;
  }
  function field(parentNode, label, name, type, value, min, max) {
    const wrap = el('label', label), input = el('input'); input.className = 'input'; input.name = name; input.type = type; input.required = true;
    if (value !== undefined) input.value = value;
    if (min !== undefined) input.min = min; if (max !== undefined) input.max = max;
    if (type === 'text') input.maxLength = 200;
    wrap.append(input); parentNode.append(wrap); return input;
  }
  function offer(row) {
    const container = $('ccl-offers');
    if (container.children.length >= 4) { say('This review supports four complete additional offers.'); return; }
    const section = el('section'); section.className = 'cmv-card'; section.dataset.id = rowIdentity('offer', container, row?.id);
    field(section, 'Additional offer name', 'offer-label', 'text', row?.label);
    field(section, 'Work quantity for this offer', 'offer-units', 'number', row?.units || 1, 1, 1000);
    const remove = el('button', 'Remove this offer'); remove.type = 'button'; remove.className = 'btn'; remove.onclick = () => section.remove(); section.append(remove); container.append(section);
  }
  function addition(row) {
    const container = $('ccl-additions');
    if (container.children.length >= 6) { say('This review supports six complete possible additions.'); return; }
    const section = el('section'); section.className = 'cmv-card'; section.dataset.id = rowIdentity('addition', container, row?.id);
    field(section, 'Possible addition name', 'addition-label', 'text', row?.label);
    const wrap = el('label', 'Resource'), select = el('select'); select.name = 'addition-kind'; select.className = 'input'; select.add(new Option('Material', 'material')); select.add(new Option('Work capacity', 'capacity')); select.value = row?.kind || 'material'; wrap.append(select); section.append(wrap);
    field(section, 'Possible additional units', 'addition-units', 'number', row?.units || 1, 1, 100000);
    field(section, 'Possibly ready by', 'addition-ready', 'datetime-local', row ? inputDate(row.ready_at) : '');
    field(section, 'Declared cost points for this addition', 'addition-cost', 'number', row?.cost || 0, 0, 100000);
    const basisWrap = el('label', 'Basis for reported availability and permission'), basis = el('textarea'); basis.name = 'addition-basis'; basis.className = 'input'; basis.required = true; basis.minLength = 10; basis.maxLength = 2000; basis.rows = 2; basis.value = row?.basis || ''; basisWrap.append(basis); section.append(basisWrap);
    const remove = el('button', 'Remove this possible addition'); remove.type = 'button'; remove.className = 'btn'; remove.onclick = () => section.remove(); section.append(remove); container.append(section);
  }
  function fillModel(model) {
    const form = $('ccl-model'); form.reset(); $('ccl-offers').replaceChildren(); $('ccl-additions').replaceChildren(); $('ccl-requirements').replaceChildren();
    for (const [name, label] of [['material_per_unit','Possible material units per work unit'],['capacity_per_unit','Possible work-capacity units per work unit'],['shared_setup','Possible shared setup capacity for combined offers']]) {
      const section = el('section'); section.className = 'cmv-card'; section.dataset.requirement = name; section.append(el('p', label));
      for (let index = 0; index < 3; index++) { const input = field(section, 'Possibility ' + (index + 1), name + '-' + index, 'number', model?.requirements[name][index] ?? (index === 0 ? (name === 'shared_setup' ? 0 : 1) : ''), name === 'shared_setup' ? 0 : 1, 100); input.required = index === 0; }
      $('ccl-requirements').append(section);
    }
    (model?.offers || [null, null]).forEach(offer); (model?.additions || [null]).forEach(addition);
    if (model) {
      form.elements.due_at.value = inputDate(model.offers[0].due_at);
      for (const name of ['max_addition_cost','test_limit','test_effort','test_cost','basis']) form.elements[name].value = model[name];
      form.elements.expires_at.value = inputDate(model.expires_at);
    }
  }
  function authoredModel() {
    const form = $('ccl-model'), data = new FormData(form), due = local(data.get('due_at'));
    const offers = Array.from($('ccl-offers').children).map(row => ({id:row.dataset.id, label:row.querySelector('[name=offer-label]').value,
      units:Number(row.querySelector('[name=offer-units]').value), due_at:due}));
    const additions = Array.from($('ccl-additions').children).map(row => ({id:row.dataset.id, label:row.querySelector('[name=addition-label]').value,
      kind:row.querySelector('[name=addition-kind]').value, units:Number(row.querySelector('[name=addition-units]').value), ready_at:local(row.querySelector('[name=addition-ready]').value),
      cost:Number(row.querySelector('[name=addition-cost]').value), basis:row.querySelector('[name=addition-basis]').value}));
    const requirements = {};
    for (const row of $('ccl-requirements').children) requirements[row.dataset.requirement] = Array.from(row.querySelectorAll('input')).filter(input => input.value !== '').map(input => Number(input.value));
    return {offers, additions, requirements, max_addition_cost:Number(data.get('max_addition_cost')), test_limit:Number(data.get('test_limit')),
      test_effort:Number(data.get('test_effort')), test_cost:Number(data.get('test_cost')), expires_at:local(data.get('expires_at')), basis:data.get('basis')};
  }
  function reviewRows(container, rows) {
    if (!Array.isArray(rows) || rows.length > 10000 || rows.reduce((sum, row) => sum + String(row.label).length + String(row.after).length, 0) > 1200000) throw new Error('The complete review is too large to display safely. Nothing was truncated or confirmed.');
    container.replaceChildren();
    let recorded;
    for (const row of rows) { const item = el('section'); item.className = 'cmv-card'; item.append(el('h4', row.label)); const text = el('p', row.after); text.style.whiteSpace = 'pre-wrap'; text.style.overflowWrap = 'anywhere'; item.append(text);
      if (row.label.startsWith('Recorded source details')) { if (!recorded) { recorded = el('details'); recorded.append(el('summary','Recorded source details')); container.append(recorded); } recorded.append(item); }
      else container.append(item);
    }
    return true;
  }
  async function openAuthor(details, {isCurrent} = {}) {
    const keys = ['context','parent','parent_binding'];
    if (!details || Object.keys(details).sort().join('|') !== keys.join('|') ||
        !/^[a-f0-9]{64}$/.test(details.context) || !/^CMV-[a-f0-9]{48}$/.test(details.parent) || !/^[a-f0-9]{64}$/.test(details.parent_binding) ||
        typeof isCurrent !== 'function') {
      throw new Error('The complete-form link could not be verified. Reopen the current Promise review.');
    }
    const selected = parent, stamp = generation;
    const valid = () => isCurrent() && parent === selected && generation === stamp && selected?.id === details.parent &&
      selected.context === details.context && !root.hidden && !busy;
    if (!valid()) throw new Error('The selected account, workspace or Promise review changed. Reopen its complete form.');
    const fresh = await request('/author/' + details.parent + '?context=' + details.context + '&parent_binding=' + details.parent_binding);
    if (!valid() || Object.keys(fresh).sort().join('|') !== keys.join('|') || keys.some(key => fresh[key] !== details[key])) {
      throw new Error('The current source or selection changed. Review the current Promise before opening its complete form.');
    }
    focusAuthor();
    say('The complete additional-work form is open. Your entered draft was kept; nothing was saved or run.');
    return true;
  }
  function focusAuthor() { root.open = true; $('ccl-author').open = true; const summary = $('ccl-author').querySelector('summary'); summary.scrollIntoView({block:'start'}); summary.focus(); }
  window.LWCommitmentCapability = {renderReview:reviewRows,openAuthor};
  async function prepare(action, values) {
    if (busy || !parent) return;
    lock(true); say('Preparing the complete accepted-work and source review…');
    try {
      review = await request('/review', 'POST', {context:parent.context, parent:parent.id, action, arguments:values});
      reviewRows($('ccl-review-changes'), review.changes); $('ccl-review').hidden = false;
      say('Review every source and the exact change below. Nothing has been confirmed.');
    } catch (error) { review = null; say(error.message); } finally { lock(false); if (review) { $('ccl-review-title').scrollIntoView({block:'start'}); $('ccl-review-title').focus(); } }
  }
  function card(container, title, lines) { const node = el('section'); node.className = 'cmv-card'; node.append(el('h3', title)); lines.forEach(line => node.append(el('p', line))); container.append(node); return node; }
  function render(value) {
    current = value; const out = $('ccl-results'); out.replaceChildren(); $('ccl-current-controls').hidden = !value.exists || value.removed;
    $('ccl-originals').replaceChildren(); $('ccl-release').hidden = !value.pending;
    if (!value.exists) { say('Enter possible requirements and additions for this owned Promise review.'); return; }
    const evaluation = value.evaluation, model = value.model;
    const label = ids => ids.map(id => model.offers.find(row => row.id === id)?.label || model.additions.find(row => row.id === id)?.label || id).join(', ');
    card(out, value.removed ? 'Current qualification removed' : evaluation.status === 'conditional' ? 'Conditional support within the entered possibilities' : 'Unknown',
      [evaluation.meaning, 'Accepted work: ' + evaluation.accepted_state + '. Current observations: ' + evaluation.current_observations + '. Remaining explanations: ' + evaluation.surviving_models.length + '.',
        'Remaining shared allowance for this Promise review: ' + evaluation.allowance.tests + ' tests and ' + evaluation.allowance.effort_points + ' effort points.',
        value.source_changed ? 'The accepted-work source changed. Review current source permission before another qualification.' : 'Source permission: ' + (value.consent ? 'Allowed until ' + date(model.expires_at) : 'Withdrawn')]);
    for (const row of evaluation.already_supported) card(out, 'Already supported by the entered quantities', [label(row.offers) + ' · ' + row.quantity + ' work units. No addition is needed in the surviving entered explanations. Physical availability remains reported.']);
    for (const row of evaluation.frontier) card(out, 'Possible additions for ' + label(row.offers), ['Together: ' + label(row.additions) + '.',
      'Additional work quantity: ' + row.quantity + '. Declared addition cost: ' + row.cost + ' points.',
      'Safe within all ' + row.safe_in_surviving_models + ' surviving entered explanations, with every accepted commitment protected jointly. No smaller subset of these additions supports these same offers.',
      'Conditional on the displayed reported availability, timing, permission and assumptions. No purchase or promise has occurred.']);
    if (!evaluation.frontier.length && !evaluation.already_supported.length) card(out, 'No currently supported additional work', [evaluation.reason || 'The current possibilities do not establish an affordable addition bundle for these offers. Entered possibilities may be incomplete; the result stays unknown.']);
    if (evaluation.next_test) card(out, 'One useful next local test', ['Additional work: ' + label(evaluation.next_test.offers) + '. Hypothetical additions: ' + (label(evaluation.next_test.additions) || 'None') + '.',
      'Exact rule inputs: total work ' + evaluation.next_test.inputs.quantity + ', combined offers ' + evaluation.next_test.inputs.offers + ', remaining material ' + evaluation.next_test.inputs.material + ', remaining capacity ' + evaluation.next_test.inputs.capacity + '.',
      evaluation.next_test.objective, 'Consumes one test and ' + evaluation.next_test.effort_points + ' effort points. It can rule out at least ' + evaluation.next_test.worst_case_models_eliminated + ' current explanations if these rules return a known Yes/No answer.']);
    else card(out, 'No useful next local test within the current allowance', ['Unknown remains unknown when the entered possibilities, source permission or qualification allowance cannot resolve it.']);
    const engineering = el('details'); engineering.append(el('summary','How this bounded check works')); engineering.append(el('p', 'All entered requirement combinations and all offer/addition subsets are checked. This uses finite version-space elimination and exhaustive same-information acquisition and abduction; no advantage over that complete comparator is claimed. Shared setup is charged once for several combined offers; physical production sequences and rates are outside this review.'));
    for (const row of evaluation.surviving_models) engineering.append(el('p', 'Material per work unit: ' + row.material_per_unit + '; capacity per work unit: ' + row.capacity_per_unit + '; shared setup capacity: ' + row.shared_setup + '.'));
    out.append(engineering);
    const withdrawn = $('ccl-withdraw').elements.observation; withdrawn.replaceChildren(new Option('Choose an observation', ''));
    for (const observation of value.observations) {
      card(out, observation.quality === 'native_local_rule' ? 'Recorded local rule result' : 'Reported completed trial', ['Result: ' + (observation.outcome ? 'Yes' : 'No') + '. ' + observation.basis,
        'Use permission: ' + (observation.consent ? 'Allowed' : 'Withdrawn') + '. Current source: ' + (observation.source_current ? 'Available' : 'Unavailable') + '. Review again by ' + date(observation.expires_at) + '.',
        'Inputs: work ' + observation.inputs.quantity + ', offers ' + observation.inputs.offers + ', material ' + observation.inputs.material + ', capacity ' + observation.inputs.capacity + '.']);
      if (observation.consent) withdrawn.add(new Option((observation.quality === 'native_local_rule' ? 'Local rules' : 'Operator trial') + ' · ' + date(observation.observed_at) + ' · ' + observation.basis, observation.id));
    }
    for (const original of value.originals) { const button = el('button', 'Read original · ' + actionNames[original.action] + ' · ' + (original.state === 'confirmed' ? 'Recorded result' : 'Original result unknown')); button.type = 'button'; button.className = 'btn'; button.onclick = () => readOriginal(value.id, original.operation); $('ccl-originals').append(button); }
  }
  async function reload() { if (parent) render(await request('/' + parent.id)); }
  async function readOriginal(identifier, operation) {
    if (busy) return;
    lock(true);
    try { const result = await request('/original/' + identifier + '/' + operation); say(result.message); card($('ccl-originals'), 'Exact original result', [actionNames[result.receipt.action] + ' · ' + (result.confirmed ? 'Recorded result' : 'Original result unknown'),
      'Actor: ' + result.receipt.actor + '. Recorded ' + date(result.receipt.recorded_at) + '.', result.receipt.result?.known === false ? 'The local rules did not produce a known Yes/No observation.' : result.receipt.result?.outcome === undefined ? 'No local test outcome is claimed by this receipt.' : 'Original local outcome: ' + (result.receipt.result.outcome ? 'Yes' : 'No')]);
      if (result.confirmed) remember(null);
    } catch (error) { say(error.message); } finally { lock(false); }
  }
  function outputChoices() { const form = $('ccl-test'); form.elements.output.replaceChildren(new Option('Choose a named result', '')); (choices.find(row => row.value === form.elements.flow_id.value)?.outputs || []).forEach(name => form.elements.output.add(new Option(name.replace(/_/g, ' '), name))); }
  document.addEventListener('lightwork:commitment-review', async event => {
    const previousParent = parent?.id, previousFlow = $('ccl-test').elements.flow_id.value, previousOutput = $('ccl-test').elements.output.value;
    generation++; review = null; $('ccl-review').hidden = true;
    parent = event.detail?.review || null; current = null; root.hidden = !parent || parent.archived || !parent.owner_can_confirm;
    if (root.hidden) { clearPrivate(); return; }
    const stamp = generation; fillModel(null); lock(true); say('Loading the current accepted-work source and owned rule choices…');
    try {
      const value = await request('/' + parent.id); if (generation !== stamp) return; render(value); if (value.exists) fillModel(value.model);
      const sources = await request('/choices'); if (generation !== stamp) return; choices = sources.choices; const flow = $('ccl-test').elements.flow_id; flow.replaceChildren(new Option('Choose current owned published rules', '')); choices.forEach(row => flow.add(new Option(row.label, row.value)));
      if (previousParent === parent.id && choices.some(row => row.value === previousFlow)) flow.value = previousFlow;
      outputChoices(); if (previousParent === parent.id && choices.find(row => row.value === flow.value)?.outputs.includes(previousOutput)) $('ccl-test').elements.output.value = previousOutput;
      say(value.exists ? (value.removed ? 'Current qualification removed. Read earlier originals below.' : 'The current qualification result is shown. Earlier originals remain separate.') : 'Enter possible requirements and additions for this owned Promise review.');
    } catch (error) { if (generation === stamp) say(error.message); }
    finally { if (generation === stamp) { lock(false); if (parent && previousParent !== parent.id && window.location.hash === '#ccl-author') focusAuthor(); } }
  });
  window.addEventListener('lightwork:context-changed', clearPrivate);
  document.addEventListener('lightwork:workspace-changed', clearPrivate);
  document.addEventListener('lightwork:account-context-changed', clearPrivate);
  $('ccl-add-offer').onclick = () => offer(); $('ccl-add-addition').onclick = () => addition(); $('ccl-test').elements.flow_id.onchange = outputChoices;
  $('ccl-model').onsubmit = event => { event.preventDefault(); try { prepare(current?.exists ? 'edit' : 'create', authoredModel()); } catch (error) { say(error.message); } };
  for (const action of ['test','report','scope','withdraw','release']) $('ccl-' + action).onsubmit = event => {
    event.preventDefault(); try { const data = new FormData(event.target); let values;
      if (action === 'report') values = {inputs:Object.fromEntries(['quantity','offers','material','capacity'].map(name => [name, Number(data.get(name))])), outcome:data.get('outcome') === 'true', basis:data.get('basis'), expires_at:local(data.get('expires_at'))};
      else if (action === 'scope') values = {allowed:data.get('allowed') === 'true', expires_at:local(data.get('expires_at')), basis:data.get('basis')};
      else if (action === 'release') values = {acknowledge_unknown:data.has('acknowledge_unknown')};
      else values = Object.fromEntries(data);
      prepare(action, values);
    } catch (error) { say(error.message); }
  };
  $('ccl-remove').onclick = () => prepare('remove', {});
  $('ccl-cancel').onclick = () => { review = null; $('ccl-review').hidden = true; say('Canceled. Nothing was confirmed.'); };
  $('ccl-confirm').onclick = async () => {
    if (busy || !review) return;
    const exact = review; lock(true); remember({id:exact.id, operation:exact.operation, parent:parent.id});
    try { const result = await request('/apply', 'POST', {token:exact.token, confirmed:true}); say(result.message); review = null; $('ccl-review').hidden = true; if (result.confirmed) remember(null); await reload(); }
    catch (error) { review = null; $('ccl-review').hidden = true; say(error.message + ' Read the waiting original request before another action.'); }
    finally { lock(false); }
  };
  $('ccl-recover').onclick = () => { const value = remembered(); if (value && value.parent === parent?.id) readOriginal(value.id, value.operation); else say('No waiting opaque request reference is saved for this Promise review. Use the original request buttons.'); };
})();
