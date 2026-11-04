(function () {
  'use strict';
  const root = document.querySelector('[data-knowledge-sources]');
  if (!root) return;
  const API = '/api/v1/knowledge/sources', form = root.querySelector('[data-ks-form]');
  const fields = form.elements;
  const status = root.querySelector('[data-ks-status]'), list = root.querySelector('[data-ks-list]');
  const editor = root.querySelector('[data-ks-editor]'), containers = root.querySelector('[data-ks-containers]');
  const reviewHost = root.querySelector('[data-ks-review]'), originalHost = root.querySelector('[data-ks-original]');
  const originalMessage = root.querySelector('[data-ks-original-message]'), originalOutput = root.querySelector('[data-ks-original-output]');
  const storageKey = 'lightwork.knowledge-source.original.v1';
  let state, generation = 0, selected = {}, editingRevision = 0, pending, submitted = false, busy = false;
  function node(tag, text, parent) { const value = document.createElement(tag); if (text !== undefined) value.textContent = text; if (parent) parent.append(value); return value; }
  function message(text) { status.textContent = text; status.focus({preventScroll: true}); status.scrollIntoView({block: 'nearest'}); }
  function display(parent, value, budget = {nodes: 10000}, depth = 0) {
    if (--budget.nodes < 0 || depth > 15) throw new Error('The complete native source review exceeds its display limit. Nothing can be confirmed.');
    if (Array.isArray(value)) { const ul = node('ul', undefined, parent); value.forEach(child => display(node('li', undefined, ul), child, budget, depth + 1)); }
    else if (value && typeof value === 'object') { const dl = node('dl', undefined, parent); Object.entries(value).forEach(([key, child]) => { node('dt', key.replace(/_/g, ' '), dl); display(node('dd', undefined, dl), child, budget, depth + 1); }); }
    else node('span', value === null || value === undefined || value === '' ? 'None' : typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value), parent);
  }
  async function request(path, body, epoch = generation) {
    let response, value;
    try { response = await fetch(API + path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', headers: body === undefined ? {} : {'Content-Type': 'application/json'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})}); value = await response.json(); }
    catch (_) { throw new Error('The reply could not be confirmed. Read the retained original; nothing will be repeated automatically.'); }
    if (epoch !== generation) throw new Error('Your current source or account changed. Reload its complete review.');
    if ([401,403].includes(response.status)) { generation++; state = undefined; list.replaceChildren(); reviewHost.replaceChildren(); reviewHost.hidden = true; editor.hidden = true; originalHost.hidden = true; originalOutput.replaceChildren(); form.reset(); selected = {}; throw new Error(typeof value.detail === 'string' ? value.detail : 'Current access is unavailable.'); }
    if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'This Knowledge source outcome is unavailable.');
    return value;
  }
  function choices(select, rows, placeholder) { select.replaceChildren(); const empty = node('option', placeholder, select); empty.value = ''; rows.forEach(row => { const option = node('option', row.label || row.value, select); option.value = row.value; }); }
  function date(value) { return value ? new Date(value * 1000).toLocaleString() : 'Not recorded'; }
  function words(value) { return String(value || '').replace(/_/g, ' '); }
  function datasetReference(value) { return value ? {'Saved source': value.asset_id, 'Edition': value.version, 'Verification code': value.manifest_sha256} : 'No complete dataset version confirmed'; }
  function approval(value) { return ({draft: 'Imported; awaiting a different person’s approval', approved: 'Approved for its permitted specialist use', unavailable: 'Current approval unavailable', blocked: 'Specialist use blocked'})[value] || words(value || 'No imported edition'); }
  function refreshResult(job) {
    return {'Original refresh': job.id, 'Status': job.state, 'Outcome': job.message, 'Started': date(job.created_at),
      'Updated': date(job.updated_at), 'Documents or pages changed': job.changed || 0, 'Unchanged': job.unchanged || 0,
      'No longer listed in this dated snapshot': job.removed || 0, 'Recorded preparation cost in USD': job.observed_dollars || 0,
      'Preparation cost still unconfirmed in USD': job.unresolved_dollars || 0,
      'Document and page outcomes': (job.items || []).map(item => ({'Document or page': item.name, 'Outcome': words(item.state), 'Details': item.message, 'Coverage notes': item.coverage_notes || []})),
      'Exact imported dataset': datasetReference(job.reference)};
  }
  function showOutcome(parent, value) {
    parent.replaceChildren();
    if (value.source) { const source = value.source, plan = source.plan; display(parent, {'Status': value.state, 'Source': source.name,
      'Saved account': plan.binding.connection, 'Selected folder or space': plan.binding.selection, 'Purpose': plan.purpose.replace(/_/g, ' '),
      'Scheduled refreshes paused': source.paused, 'Current refresh status': words(source.state), 'Specialist use approval': approval(source.registry_state)}); }
    if (value.job) display(parent, refreshResult(value.job));
    if (value.draft) display(parent, {'Specialist decision': value.draft.action, 'Confirmed': value.draft.confirmed,
      'Saved complete draft': value.draft.draft || 'No draft confirmed', 'Outcome': value.draft.message});
    if (value.message) node('p', value.message, parent);
    if (value.publish) { const link = node('a', 'Open complete specialist Publish review', parent); link.href = value.publish; }
  }
  function invalidate() { pending = undefined; submitted = false; reviewHost.replaceChildren(); reviewHost.hidden = true; }
  function purposes() { const decision = state.permissions.find(row => row.decision_id === form.decision_id.value); choices(form.purpose, (decision?.purpose_codes || []).map(value => ({value, label: value.replace(/_/g, ' ')})), 'Choose the approved purpose'); }
  function accounts() {
    choices(form.connection, state.accounts.filter(row => row.kind === form.kind.value), 'Choose your named account');
    selected = {}; containers.replaceChildren(); invalidate();
  }
  async function addPicker(step, chosen, field, label) {
    const epoch = generation;
    const result = await request('/pick', {context: state.context, kind: form.kind.value, connection: form.connection.value, selection: chosen, step}, epoch);
    const wrapper = node('label', label + ' ', containers), select = node('select', undefined, wrapper); select.required = true;
    choices(select, result.items, 'Choose ' + label.toLowerCase());
    select.addEventListener('change', async () => {
      while (wrapper.nextSibling) wrapper.nextSibling.remove(); invalidate();
      selected = {...(field === 'site' ? {} : selected), ...chosen, [field]: select.value};
      if (field === 'drive') delete selected.folder;
      if (!select.value) return;
      try {
        if (field === 'site') await addPicker('drives', selected, 'drive', 'Library');
        else if (field === 'drive') await addPicker('folders', {drive: select.value}, 'folder', 'Folder');
        else if (field === 'folder') {
          const browse = node('button', 'Choose a subfolder', containers); browse.type = 'button'; browse.className = 'btn';
          browse.addEventListener('click', async () => { try { const parent = {...selected}; wrapper.remove(); browse.remove(); await addPicker('folders', form.kind.value === 'drive' ? {folder: parent.folder} : {drive: parent.drive, folder: parent.folder}, 'folder', 'Folder'); } catch (error) { message(error.message); } });
        }
      } catch (error) { message(error.message); }
    });
    return select;
  }
  async function pickStart() {
    selected = {}; containers.replaceChildren(); invalidate();
    if (!form.connection.value) return;
    const kind = form.kind.value;
    try {
      if (kind === 'sharepoint') await addPicker('sites', {}, 'site', 'SharePoint site');
      else if (kind === 'onedrive') await addPicker('drives', {}, 'drive', 'Drive');
      else if (kind === 'drive') await addPicker('folders', {}, 'folder', 'Folder');
      else await addPicker('spaces', {}, 'space', 'Confluence space');
    } catch (error) { message(error.message); }
  }
  function retain(value) { pending = value; try { sessionStorage.setItem(storageKey, JSON.stringify({context: value.context, token: value.token, operation: value.operation})); } catch (_) { throw new Error('The original request could not be retained in this browser. Nothing was submitted.'); } originalHost.hidden = false; originalMessage.textContent = 'Original intent ' + value.operation + ' is retained. Its read control never repeats the decision.'; }
  async function showReview(value) {
    invalidate(); reviewHost.hidden = false;
    if (!value || typeof value.token !== 'string' || !value.changes || typeof value.changes !== 'object' || JSON.stringify(value.changes).length > 1500000) throw new Error('The complete native review is unavailable.');
    Object.entries(value.changes).forEach(([label, consequence]) => {
      if (label === 'Complete specialist draft review') {
        if (!window.LWSpecialistDrafts?.renderReview) throw new Error('The complete specialist review is still loading. Reopen the attachment review.');
        node('h3', label, reviewHost); window.LWSpecialistDrafts.renderReview(node('div', undefined, reviewHost), consequence);
      } else { node('h3', label, reviewHost); display(reviewHost, consequence); }
    });
    node('p', value.notice || '', reviewHost);
    const label = node('label', undefined, reviewHost), accept = node('input', undefined, label); accept.type = 'checkbox'; label.append(document.createTextNode(' I reviewed this complete source decision and its consequences.'));
    const confirm = node('button', 'Confirm reviewed decision', reviewHost); confirm.type = 'button'; confirm.className = 'btn btn--primary'; confirm.disabled = true;
    pending = value; const epoch = generation;
    accept.addEventListener('change', () => { confirm.disabled = !accept.checked || submitted || busy || epoch !== generation; });
    confirm.addEventListener('click', async () => {
      if (!accept.checked || submitted || busy || epoch !== generation) return;
      try { retain(value); } catch (error) { message(error.message); return; }
      submitted = true; busy = true; confirm.disabled = true;
      try { const result = await request('/apply', {token: value.token, confirmed: true}, epoch); showOutcome(originalOutput, result); message(result.message); await load(false); }
      catch (error) { message(error.message); }
      finally { busy = false; }
    });
    reviewHost.scrollIntoView({block: 'start'}); accept.focus({preventScroll: true});
  }
  async function readOriginal() {
    let retained;
    try { retained = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch (_) { message('The browser could not read its retained original. Inspect source history.'); return; }
    if (!retained || retained.context !== state?.context) { message('Choose the original account and workspace before reading this retained decision.'); return; }
    try { const result = await request('/read-original', {token: retained.token, confirmed: true}); showOutcome(originalOutput, result); message(result.message); await load(false); }
    catch (error) { message(error.message); }
  }
  function sourceCard(source) {
    const card = node('article', undefined, list); card.className = 'panel'; node('h3', source.name, card);
    node('p', readersLabel(source.plan.binding.kind) + ' · ' + source.plan.binding.connection + ' · ' + source.plan.binding.origin, card);
    node('p', 'Refresh: ' + words(source.state) + ' · ' + source.item_count + ' imported documents or pages · ' + approval(source.registry_state), card);
    node('p', source.last_refresh ? 'Last refresh: ' + new Date(source.last_refresh * 1000).toLocaleString() : 'No completed refresh recorded', card);
    node('p', source.paused ? 'Scheduled refreshes paused' : source.next_refresh ? 'Next scheduled refresh: ' + new Date(source.next_refresh * 1000).toLocaleString() : 'Manual refresh only', card);
    if (source.reference) { const link = node('a', 'Open Research to review this exact dataset version', card); link.href = '/research'; node('p', 'Dataset: ' + source.reference.asset_id + ' · Version: ' + source.reference.version, card); }
    const edit = node('button', 'Review source settings', card); edit.type = 'button'; edit.className = 'btn'; edit.addEventListener('click', () => editSource(source));
    const refresh = node('button', 'Review refresh', card); refresh.type = 'button'; refresh.className = 'btn';
    const ackLabel = node('label', undefined, card), ack = node('input', undefined, ackLabel); ack.type = 'checkbox'; ackLabel.append(document.createTextNode(' I read an earlier uncertain original and intend a separate new refresh.')); ackLabel.hidden = !source.active_job;
    refresh.addEventListener('click', async () => { if (busy) return; try { await showReview(await request('/' + source.id + '/refresh-review', {context: state.context, acknowledge_unknown: ack.checked})); } catch (error) { message(error.message); } });
    const historyButton = node('button', 'Read refresh and file history', card), historyHost = node('div', undefined, card); historyButton.type = 'button'; historyButton.className = 'btn';
    async function historyPage(offset = 0) { try { const result = await request('/' + source.id + '/history?offset=' + offset);
      if (!offset) historyHost.replaceChildren(); node('p', 'Showing retained refreshes ' + (result.items.length ? offset + 1 : 0) + '–' + (offset + result.items.length) + ' of ' + result.total + '.', historyHost);
      result.items.forEach(job => display(historyHost, refreshResult(job)));
      if (result.next_offset !== null) { const more = node('button', 'Read older refresh history', historyHost); more.type = 'button'; more.className = 'btn'; more.addEventListener('click', () => { more.disabled = true; historyPage(result.next_offset); }); }
    } catch (error) { message(error.message); } }
    historyButton.addEventListener('click', () => historyPage());
    if (source.active_job) { display(historyHost, refreshResult(source.active_job)); const read = node('button', 'Read active original without repeating', card); read.className = 'btn'; read.addEventListener('click', async () => { try { const result = await request('/originals/' + source.active_job.id); historyHost.replaceChildren(); display(historyHost, refreshResult(result)); } catch (error) { message(error.message); } }); }
    const label = node('label', 'Specialist attachment ', card), specialist = node('select', undefined, label); choices(specialist, state.specialists, 'Choose a specialist');
    const attach = node('button', 'Review complete attachment draft', card); attach.type = 'button'; attach.className = 'btn';
    const olderLabel = node('label', undefined, card), older = node('input', undefined, olderLabel); older.type = 'checkbox'; olderLabel.append(document.createTextNode(' I read any earlier uncertain specialist decision and intend a separate attachment draft.'));
    attach.addEventListener('click', async () => { if (!specialist.value || busy) return; try { await showReview(await request('/' + source.id + '/attachment-review', {context: state.context, specialist: specialist.value, acknowledge_previous: older.checked})); } catch (error) { message(error.message); } });
  }
  function readersLabel(kind) { return state.kinds.find(row => row.value === kind)?.label || kind; }
  function editSource(source) {
    invalidate(); editor.open = true; editingRevision = source.revision;
    fields.name.value = source.plan.name; form.kind.value = source.plan.binding.kind; accounts(); form.connection.value = source.plan.binding.connection;
    form.decision_id.value = source.plan.decision_id; purposes(); form.purpose.value = source.plan.purpose;
    form.interval_seconds.value = String(source.plan.interval_seconds); form.max_dollars.value = String(source.plan.max_dollars); form.paused.checked = source.paused;
    selected = {...source.plan.binding.selection}; containers.replaceChildren(); display(containers, {'Saved container': selected});
    node('p', 'This preserves the reviewed container. Choose another account to pick a new container.', containers); editor.scrollIntoView({block: 'start'});
  }
  async function load(invalidateReview = true) {
    try { state = await request(''); list.replaceChildren(); state.sources.forEach(sourceCard); if (!state.sources.length) node('p', 'No saved remote sources yet. Add a source below.', list);
      if (invalidateReview) { invalidate(); choices(form.kind, state.kinds, 'Choose company source'); choices(form.decision_id, state.permissions.map(row => ({value: row.decision_id, label: row.asset_id + ' · ' + row.purpose_codes.map(words).join(', ')})), 'Choose current permission'); editingRevision = 0; }
      editor.hidden = false;
      root.querySelector('[data-ks-permission-state]').textContent = state.permission_state !== 'available'
        ? 'Current data-use permissions could not be checked (' + state.permission_state + '). Resolve this in Data use before saving a source.'
        : state.permissions.length ? 'Only actual currently valid analysis permissions are offered.' : 'No current analysis permission was found. Review data-use permissions first.';
      form.decision_id.disabled = state.permission_state !== 'available';
      let retained; try { retained = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch (_) {} if (retained?.context === state.context) { originalHost.hidden = false; originalMessage.textContent = 'Original intent ' + retained.operation + ' is retained. Read it before considering a separate new request.'; }
      if (invalidateReview) message('Current sources loaded. Status reads do not fetch provider documents.');
    } catch (error) { message(error.message); }
  }
  form.kind.addEventListener('change', accounts); form.connection.addEventListener('change', pickStart); form.decision_id.addEventListener('change', () => { purposes(); invalidate(); });
  form.addEventListener('input', () => { generation++; invalidate(); });
  form.addEventListener('submit', async event => { event.preventDefault(); if (!state || busy) return; try { await showReview(await request('/save-review', {context: state.context, name: fields.name.value, kind: form.kind.value, connection: form.connection.value, selection: selected, decision_id: form.decision_id.value, purpose: form.purpose.value, interval_seconds: Number(form.interval_seconds.value), max_dollars: Number(form.max_dollars.value), expected_revision: editingRevision, paused: form.paused.checked})); } catch (error) { message(error.message); } });
  root.querySelector('[data-ks-reload]').addEventListener('click', () => load()); root.querySelector('[data-ks-read-original]').addEventListener('click', readOriginal);
  document.addEventListener('lightwork:copilot-context-changed', event => { if (event.detail?.reason === 'selection') return; generation++; state = undefined; list.replaceChildren(); invalidate(); editor.hidden = true; originalHost.hidden = true; originalOutput.replaceChildren(); form.reset(); selected = {}; message('Your current account changed. Reload sources before continuing.'); });
  load();
}());
