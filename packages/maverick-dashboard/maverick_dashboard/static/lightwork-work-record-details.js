// Business details use named controls; native reviews own permissions and versions.
(function () {
  'use strict';
  const root = document.getElementById('wrd-root');
  if (!root) return;
  const get = id => document.getElementById('wrd-' + id), API = '/api/v1/work-details';
  const context = root.dataset.context, storage = 'lightwork.work-details.v1:' + context;
  const formats = {text: 'Text', number: 'Number', boolean: 'Yes or no', date: 'Date', choice: 'Choose one'};
  const stages = {pending: 'Pending', running: 'In progress', done: 'Done', failed: 'Needs attention', stopped: 'Stopped', blocked: 'Waiting', approved: 'Approved', draft: 'Draft'};
  let state = null, schemaDraft = null, detailsDraft = null, draftFields = [], draftStages = [];
  let schemaDirty = false, detailsDirty = false, pending = null, lastOriginal = null, busy = false, lost = false, serial = 0;
  let kind = 'task', record = '', pages = [''], page = 0, choices = null, handoff = null;
  const requests = new Set(), controls = new Map();
  const clone = value => JSON.parse(JSON.stringify(value));
  const plain = value => value && typeof value === 'object' && !Array.isArray(value);
  const hex = (value, length) => typeof value === 'string' && new RegExp('^[a-f0-9]{' + length + '}$').test(value);
  const string = (value, length) => typeof value === 'string' && value.length <= length;
  const number = value => Number.isSafeInteger(value) && value >= 0;
  function product(node, source, values = {}) {
    if (window.LightworkI18n) window.LightworkI18n.set(node, source, values);
    else { node.textContent = source.replace(/\{(\w+)\}/g, (_, key) => String(values[key] ?? '')); node.lang = 'en'; }
    return node;
  }
  function user(node, value) { node.textContent = String(value ?? ''); node.lang = 'und'; node.dir = 'auto'; node.dataset.userContent = ''; return node; }
  function node(tag, source, parent) { const item = product(document.createElement(tag), source); if (parent) parent.append(item); return item; }
  function userNode(tag, value, parent) { const item = user(document.createElement(tag), value); if (parent) parent.append(item); return item; }
  function say(source, focus = false) { product(get('status'), source); if (focus) get('status').focus(); }
  function problem(source, code = '') { return Object.assign(new Error(source), {productSource: source, code}); }
  function button(source, parent, action) {
    const item = node('button', source, parent); item.type = 'button'; item.className = 'btn btn--ghost'; item.addEventListener('click', action); return item;
  }
  function definition(field, fresh = false) {
    return plain(field) && (hex(field.id, 32) || fresh && field.id === '') && string(field.label, 100) &&
      Object.hasOwn(formats, field.type) && typeof field.required === 'boolean' && Array.isArray(field.options) && field.options.length <= 20 &&
      field.options.every(row => plain(row) && (hex(row.id, 32) || fresh && row.id === '') && string(row.label, 100));
  }
  function named(row, fresh = false) { return plain(row) && (hex(row.id, 32) || fresh && row.id === '') && string(row.label, 100); }
  function typed(value) { return value === null || typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value) || string(value, 4000); }
  function validState(value) {
    return plain(value) && value.context === context && typeof value.enabled === 'boolean' && string(value.notice, 4000) && string(value.kind, 80) &&
      Array.isArray(value.kinds) && value.kinds.length <= 20 && value.kinds.every(row => plain(row) && string(row.value, 80) && string(row.label, 200)) &&
      plain(value.schema) && number(value.schema.revision) && Array.isArray(value.schema.fields) && value.schema.fields.length <= 20 && value.schema.fields.every(row => definition(row)) &&
      Array.isArray(value.schema.stages) && value.schema.stages.length <= 12 && value.schema.stages.every(row => named(row)) && typeof value.can_define === 'boolean' && typeof value.can_edit === 'boolean' &&
      (value.source === null || plain(value.source) && string(value.source.value, 256) && string(value.source.label, 1000) && string(value.source.status, 200) && hex(value.source.revision, 64)) &&
      plain(value.details) && number(value.details.revision) && plain(value.details.values) && Object.keys(value.details.values).length <= 100 && Object.values(value.details.values).every(typed) &&
      (value.details.stage === null || hex(value.details.stage, 32)) && Array.isArray(value.details.retained) &&
      value.details.retained.every(row => plain(row) && definition(row.field) && typed(row.value)) && (value.details.saved_stage === null || named(value.details.saved_stage));
  }
  function validChanges(rows) { return Array.isArray(rows) && rows.length <= 100 && rows.every(row => plain(row) && string(row.label, 1000) && (typed(row.before) || string(row.before, 64000)) && (typed(row.after) || string(row.after, 64000))); }
  function validReview(value) {
    return plain(value) && value.context === context && hex(value.operation, 32) && string(value.token, 500000) && value.token.length > 0 &&
      typeof value.expires_at === 'number' && Number.isFinite(value.expires_at) && plain(value.normalized_draft) && plain(value.summary) &&
      string(value.summary.heading, 1000) && string(value.summary.kind, 200) && string(value.summary.record, 1000) && string(value.summary.status, 200) &&
      validChanges(value.summary.changes) && string(value.summary.notice, 4000);
  }
  function retainedDraft() { return {kind, record, schema: schemaDraft, details: detailsDraft, fields: draftFields, stages: draftStages, schema_dirty: schemaDirty, details_dirty: detailsDirty}; }
  function remember() {
    if (lost) return false;
    try { sessionStorage.setItem(storage, JSON.stringify({context, draft: retainedDraft(), pending, last_original: lastOriginal})); return true; }
    catch (_) { say('This browser could not keep your review for reload recovery. Keep this page open until the original save is confirmed.'); return false; }
  }
  function forget() { try { sessionStorage.removeItem(storage); } catch (_) { /* No private copy can be removed from unavailable storage. */ } }
  function clearPrivate() {
    lost = true; serial += 1; requests.forEach(item => item.abort()); requests.clear(); forget();
    state = schemaDraft = detailsDraft = pending = lastOriginal = choices = null; draftFields = []; draftStages = []; controls.clear();
    kind = ''; record = ''; schemaDirty = detailsDirty = false;
    for (const id of ['kind', 'records', 'page', 'history-note', 'values-heading', 'record-note', 'value-fields', 'definition-fields', 'definition-stages', 'review-note', 'review-details', 'original-details', 'recovery-status']) get(id).replaceChildren();
    get('search').value = ''; for (const id of ['values', 'definitions', 'review', 'recovery', 'original']) get(id).hidden = true;
    say('Your account, workspace, or access changed. Private details were cleared. Sign in with current access and reload this page.', true); lock(false);
  }
  function current(attempt) { return !lost && attempt === serial && (!handoff || handoff.isCurrent()); }
  async function call(method, path, body) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000), attempt = serial;
    requests.add(controller);
    try {
      const response = await fetch(API + path, {method, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: {'Content-Type': 'application/json', Accept: 'application/json', 'X-Lightwork-Review-Context': context}, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
      if (response.redirected || response.status === 401 || response.status === 403) { clearPrivate(); throw problem('Your access changed. Reload this page after signing in again.'); }
      const raw = await response.text();
      if (new TextEncoder().encode(raw).byteLength > 32 * 1024 * 1024) throw problem('The saved details exceeded the safe display size. Nothing was sent. Ask an administrator to review this record.');
      let value; try { value = JSON.parse(raw); } catch (_) { throw problem('The reply could not be read. Your draft is still here.'); }
      const code = plain(value?.detail) ? value.detail.code : '';
      if (code === 'workspace_context_changed' || code === 'context_changed' || value.context && value.context !== context) { clearPrivate(); throw problem('Your workspace changed. Reload this page.'); }
      if (!current(attempt)) throw problem('This view is no longer current. Reload the page before continuing.');
      if (!response.ok) {
        const source = response.status === 409 ? 'Saved work changed. Your draft is still here. Refresh the work and review against the current saved version.' :
          response.status === 404 ? 'This work is unavailable or you no longer have access. Choose work you can open.' :
            response.status === 400 || response.status === 422 ? 'Some details need fixing. Check the field names, answers, and stages before reviewing again.' :
              'The request could not be confirmed. Your draft is still here. Check the original save before sending another change.';
        const error = problem(source, String(response.status)); error.notSaved = plain(value.detail) && value.detail.not_saved === true; throw error;
      }
      return value;
    } catch (error) {
      if (error.productSource) throw error;
      throw problem(controller.signal.aborted ? 'The check timed out. Your draft is still here. Check the original save before sending another change.' : 'The reply was not confirmed. Your draft is still here. Check the original save before sending another change.');
    } finally { clearTimeout(timer); requests.delete(controller); }
  }
  function lock(on) {
    busy = on; root.setAttribute('aria-busy', String(on));
    root.querySelectorAll('button,input,select,textarea').forEach(item => item.disabled = on || lost);
    if (on || lost) return;
    const uncertain = !!pending?.save_started;
    get('save').disabled = !pending || uncertain || pending.refused || !state?.enabled;
    get('cancel').disabled = !pending || uncertain;
    get('original').hidden = !uncertain && !lastOriginal; get('original').disabled = !uncertain && !lastOriginal;
    get('previous').disabled = uncertain || page === 0;
    get('next').disabled = uncertain || !choices || choices.complete || !choices.cursor;
    get('kind').disabled = uncertain || !state?.enabled;
    get('values-review').disabled = uncertain || !state?.can_edit || !state?.source;
    get('definition-review').disabled = uncertain || !state?.can_define;
    if (!state?.can_edit) get('values-form').querySelectorAll('input,select,button,textarea').forEach(item => item.disabled = true);
    if (!state?.can_define) get('definition-form').querySelectorAll('input,select,button,textarea').forEach(item => item.disabled = true);
    if (uncertain) root.querySelectorAll('input,select,textarea,button').forEach(item => { if (!['wrd-original', 'wrd-refresh'].includes(item.id)) item.disabled = true; });
    get('add-field').disabled = uncertain || !state?.can_define || schemaDraft?.fields.length >= 20;
    get('add-stage').disabled = uncertain || !state?.can_define || schemaDraft?.stages.length >= 12;
    root.querySelectorAll('[data-edge-disabled="true"]').forEach(item => item.disabled = true);
    if (!state?.enabled) root.querySelectorAll('button,input,select,textarea').forEach(item => { if (!['wrd-refresh', 'wrd-original'].includes(item.id)) item.disabled = true; });
  }
  async function action(work) {
    if (busy || lost) return false;
    lock(true);
    try { await work(); return true; }
    catch (error) { if (!lost) say(error.productSource || 'The action could not be completed. Your draft is still here.', true); return false; }
    finally { lock(false); }
  }
  function dirty(mode) {
    if (pending?.save_started) return;
    if (mode === 'schema') schemaDirty = true; else detailsDirty = true;
    pending = null; get('review').hidden = true; get('recovery').hidden = true; remember(); lock(false);
  }
  function labelStatus(value) { return stages[value] || String(value || '').replace(/_/g, ' ').replace(/^./, letter => letter.toUpperCase()); }
  function displayValue(value, field) {
    if (value === null || value === undefined || value === '') return 'Not entered';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (field?.type === 'choice') return field.options.find(row => row.id === value)?.label || 'Earlier saved choice';
    return String(value);
  }
  function pair(list, label, value, field) { userNode('dt', label, list); const item = userNode('dd', displayValue(value, field), list); if (value === null || value === undefined || value === '') product(item, 'Not entered'); }
  function field(label, type, value, parent, id, onInput, options = []) {
    const wrapper = document.createElement('div'); parent.append(wrapper);
    const caption = userNode('label', label, wrapper); caption.htmlFor = id;
    const control = document.createElement(type === 'select' ? 'select' : type === 'textarea' ? 'textarea' : 'input'); control.id = id; control.className = 'input';
    if (type === 'select') options.forEach(row => { const option = userNode('option', row.label, control); option.value = row.id; });
    else if (type === 'textarea') { control.rows = 4; control.maxLength = 4000; }
    else { control.type = type; if (type === 'text') control.maxLength = 4000; if (type === 'number') control.step = 'any'; }
    control.value = value == null ? '' : String(value); wrapper.append(control); control.addEventListener(type === 'select' ? 'change' : 'input', () => onInput(control.value)); return control;
  }
  function renderValues() {
    const host = get('value-fields'); host.replaceChildren(); controls.clear();
    get('values').hidden = !state?.source; if (!state?.source || !detailsDraft) return;
    user(get('values-heading'), state.source.label); user(get('record-note'), labelStatus(state.source.status));
    const stageRows = [{id: '', label: 'No business stage'}, ...state.schema.stages];
    if (detailsDraft.stage && !state.schema.stages.some(row => row.id === detailsDraft.stage)) stageRows.push({id: detailsDraft.stage, label: (draftStages.find(row => row.id === detailsDraft.stage)?.label || state.details.saved_stage?.label || 'Earlier business stage') + ' · no longer in this category'});
    field('Business stage', 'select', detailsDraft.stage, host, 'wrd-business-stage', value => { detailsDraft.stage = value || null; dirty('details'); }, stageRows);
    for (const entry of state.schema.fields) {
      const earlier = draftFields.find(row => row.id === entry.id);
      if (detailsDirty && earlier && earlier.type !== entry.type && Object.hasOwn(detailsDraft.values, entry.id)) {
        userNode('h3', entry.label, host); node('p', 'The answer format changed. Your earlier draft entry is kept below until you choose to use the current format.', host);
        const list = document.createElement('dl'); host.append(list); pair(list, earlier.label, detailsDraft.values[entry.id], earlier);
        const useCurrent = button('Use current answer format', host, () => {
          detailsDraft.values[entry.id] = null; draftFields = draftFields.filter(row => row.id !== entry.id); draftFields.push(clone(entry)); dirty('details'); renderValues(); lock(false); document.getElementById('wrd-value-' + entry.id).focus();
        }); useCurrent.setAttribute('aria-label', 'Use current answer format for ' + entry.label); continue;
      }
      const options = [{id: '', label: 'Choose an answer'}, ...entry.options];
      if (entry.type === 'boolean') options.splice(0, options.length, {id: '', label: 'Choose an answer'}, {id: 'true', label: 'Yes'}, {id: 'false', label: 'No'});
      const saved = detailsDraft.values[entry.id], kind = entry.type === 'choice' || entry.type === 'boolean' ? 'select' : entry.type === 'text' ? 'textarea' : entry.type;
      if (entry.type === 'choice' && saved && !entry.options.some(row => row.id === saved)) options.push({id: saved, label: draftFields.find(row => row.id === entry.id)?.options.find(row => row.id === saved)?.label || 'Earlier choice · select a current answer'});
      const input = field(entry.label + (entry.required ? ' · required' : ''), kind, saved, host, 'wrd-value-' + entry.id, value => {
        detailsDraft.values[entry.id] = value === '' ? null : entry.type === 'number' ? Number(value) : entry.type === 'boolean' ? value === 'true' : value; dirty('details');
      }, options); input.required = entry.required; controls.set(entry.id, input);
    }
    const removed = Object.keys(detailsDraft.values).filter(id => !state.schema.fields.some(row => row.id === id));
    if (removed.length) {
      node('h3', 'Earlier draft entries', host); node('p', 'These fields are no longer in this category. The entries below are kept in your draft until you choose what to do.', host);
      const list = document.createElement('dl'); host.append(list); removed.forEach(id => { const old = draftFields.find(row => row.id === id); pair(list, old?.label || 'Earlier field', detailsDraft.values[id], old); });
      button('Remove earlier entries from this draft', host, () => { removed.forEach(id => delete detailsDraft.values[id]); dirty('details'); renderValues(); say('Earlier entries were removed from your draft. Saved history was not changed.'); });
    }
    if (state.details.retained.length || state.details.saved_stage && !state.schema.stages.some(row => row.id === state.details.saved_stage.id)) {
      node('h3', 'Earlier saved details', host); node('p', 'These saved details belong to earlier category setup. They are retained separately from the fields you can edit above.', host);
      const list = document.createElement('dl'); host.append(list); state.details.retained.forEach(row => pair(list, row.field.label, row.value, row.field));
      if (state.details.saved_stage && !state.schema.stages.some(row => row.id === state.details.saved_stage.id)) pair(list, 'Earlier saved business stage', state.details.saved_stage.label);
    }
    if (!state.schema.fields.length && !state.schema.stages.length) node('p', 'This category has no business fields or stages yet. A workspace administrator can add them below.', host);
  }
  function rowActions(parent, rows, index, label, render, focusId) {
    const actions = document.createElement('div'); actions.className = 'wrd-actions'; parent.append(actions);
    function focus(target) { const item = document.getElementById(focusId(target)); if (item) item.focus(); else get('definition-review').focus(); }
    const up = button('Move up', actions, () => { if (!index) return; [rows[index - 1], rows[index]] = [rows[index], rows[index - 1]]; dirty('schema'); render(); focus(index - 1); }); up.disabled = index === 0;
    const down = button('Move down', actions, () => { if (index >= rows.length - 1) return; [rows[index + 1], rows[index]] = [rows[index], rows[index + 1]]; dirty('schema'); render(); focus(index + 1); }); down.disabled = index === rows.length - 1;
    const remove = button('Remove', actions, () => { rows.splice(index, 1); dirty('schema'); render(); focus(Math.min(index, rows.length - 1)); });
    up.setAttribute('aria-label', 'Move ' + label + ' up'); down.setAttribute('aria-label', 'Move ' + label + ' down'); remove.setAttribute('aria-label', 'Remove ' + label);
    [up, down].forEach(item => item.dataset.edgeDisabled = String(item.disabled));
  }
  function renderDefinitions() {
    const host = get('definition-fields'), stageHost = get('definition-stages'); host.replaceChildren(); stageHost.replaceChildren();
    get('definitions').hidden = !state?.can_define; if (!schemaDraft || !state?.can_define) return;
    schemaDraft.fields.forEach((entry, index) => {
      const group = document.createElement('fieldset'); host.append(group); const legend = node('legend', 'Business field {number}', group); product(legend, 'Business field {number}', {number: index + 1});
      const prefix = 'wrd-field-' + index;
      const name = field('Field name', 'text', entry.label, group, prefix + '-label', value => { entry.label = value; dirty('schema'); }); name.maxLength = 100; name.required = true;
      field('Answer format', 'select', entry.type, group, prefix + '-type', value => { entry.type = value; if (value !== 'choice') entry.options = []; dirty('schema'); renderDefinitions(); lock(false); document.getElementById(prefix + '-type').focus(); }, Object.entries(formats).map(([id, label]) => ({id, label})));
      const requiredLabel = node('label', 'An answer is required', group), required = document.createElement('input'); required.type = 'checkbox'; required.checked = entry.required; requiredLabel.prepend(required, ' '); required.addEventListener('change', () => { entry.required = required.checked; dirty('schema'); });
      if (entry.type === 'choice') {
        node('h4', 'Answer choices', group);
        entry.options.forEach((option, optionIndex) => {
          const choiceRow = document.createElement('div'); group.append(choiceRow);
          const choiceName = field('Choice ' + (optionIndex + 1) + ' name', 'text', option.label, choiceRow, prefix + '-choice-' + optionIndex, value => { option.label = value; dirty('schema'); }); choiceName.maxLength = 100; choiceName.required = true;
          rowActions(choiceRow, entry.options, optionIndex, 'choice ' + (optionIndex + 1) + ' in business field ' + (index + 1), renderDefinitions, position => prefix + '-choice-' + position);
        });
          const add = button('Add an answer choice', group, () => { entry.options.push({id: '', label: ''}); dirty('schema'); renderDefinitions(); lock(false); document.getElementById(prefix + '-choice-' + (entry.options.length - 1)).focus(); }); add.disabled = entry.options.length >= 20; add.dataset.edgeDisabled = String(add.disabled);
      }
      rowActions(group, schemaDraft.fields, index, 'business field ' + (index + 1), renderDefinitions, position => 'wrd-field-' + position + '-label');
    });
    schemaDraft.stages.forEach((entry, index) => {
      const group = document.createElement('fieldset'); stageHost.append(group); product(node('legend', 'Business stage {number}', group), 'Business stage {number}', {number: index + 1});
      const name = field('Stage name', 'text', entry.label, group, 'wrd-stage-' + index, value => { entry.label = value; dirty('schema'); }); name.maxLength = 100; name.required = true;
      rowActions(group, schemaDraft.stages, index, 'business stage ' + (index + 1), renderDefinitions, position => 'wrd-stage-' + position);
    });
    lock(busy);
  }
  function syncValues() {
    if (!state?.source || !detailsDraft) return;
    controls.forEach((control, id) => {
      const entry = state.schema.fields.find(row => row.id === id), value = control.value;
      detailsDraft.values[id] = value === '' ? null : entry.type === 'number' ? Number(value) : entry.type === 'boolean' ? value === 'true' : value;
    }); detailsDraft.stage = get('business-stage')?.value || null;
  }
  function installState(value, keep = true) {
    if (!validState(value) || value.kind !== kind || value.source && value.source.value !== record) throw problem('The saved details could not be checked. Your draft is still here. Refresh before saving.');
    if (state?.enabled && value.enabled && (state.can_define && !value.can_define || state.can_edit && !value.can_edit)) { clearPrivate(); throw problem('Your access changed. Private drafts were cleared. Reload with current access.'); }
    const changed = state && (state.schema.revision !== value.schema.revision || state.source?.revision !== value.source?.revision || state.details.revision !== value.details.revision);
    if (keep) syncValues();
    if (!keep || !schemaDirty || !schemaDraft) schemaDraft = clone({fields: value.schema.fields, stages: value.schema.stages});
    if (!keep || !detailsDirty || !detailsDraft) { detailsDraft = clone({values: value.details.values, stage: value.details.stage}); draftFields = clone(value.schema.fields); draftStages = clone(value.schema.stages); }
    state = value;
    product(get('history-note'), value.original_notice || 'Original results are retained for the latest 20 saves of each record or category setup. Older originals may no longer be available.');
    get('kind').replaceChildren(); value.kinds.forEach(row => { const option = userNode('option', row.label, get('kind')); option.value = row.value; }); get('kind').value = kind;
    if (changed && pending && !pending.save_started) { pending = null; get('review').hidden = true; }
    renderValues(); renderDefinitions(); remember();
    say(!value.enabled ? 'Business details are turned off. An administrator can turn them on in Settings. Earlier original saves can still be checked.' : changed && (schemaDirty || detailsDirty) ? 'Saved work changed. Your entries have been kept. Review your change against the current saved version before saving.' : value.notice || 'Choose work to view or update its business details.');
  }
  async function loadState(keep = true) {
    const result = await call('GET', '/state?' + new URLSearchParams({kind, record})); installState(result, keep);
  }
  async function loadChoices() {
    if (!state?.enabled) { choices = null; get('records').replaceChildren(); get('page').replaceChildren(); return; }
    const result = await call('POST', '/choices', {context, kind, query: get('search').value, cursor: pages[page]});
    if (!plain(result) || result.context !== context || !Array.isArray(result.items) || result.items.length > 100 || !result.items.every(row => plain(row) && string(row.value, 256) && string(row.label, 1000) && string(row.status, 200)) || !string(result.cursor, 32000) || typeof result.complete !== 'boolean') throw problem('The work list could not be checked. Keep your draft and try refreshing the list.');
    choices = result; get('records').replaceChildren();
    if (!result.items.length) node('p', 'No matching work is available to you in this category.', get('records'));
    result.items.forEach(row => {
      const item = button('', get('records'), () => action(() => selectRecord(row.value))); item.className = 'btn btn--ghost wrd-record';
      userNode('bdi', row.label, item); item.append(' · '); const status = userNode('span', labelStatus(row.status), item); if (Object.hasOwn(stages, row.status)) product(status, stages[row.status]);
      item.setAttribute('aria-pressed', String(row.value === record));
    });
    product(get('page'), 'Page {number}', {number: page + 1}); lock(busy);
  }
  async function allowDiscard() {
    if (pending?.save_started) { say('Check the original save before choosing different work.'); return false; }
    if (!schemaDirty && !detailsDirty && !pending) return true;
    return typeof window.mvConfirm === 'function' && !!await window.mvConfirm('Leave this draft and choose different work?', {okText: 'Choose different work', productCopy: true});
  }
  async function selectRecord(value) {
    if (value === record || !await allowDiscard()) return;
    record = value; detailsDirty = false; schemaDirty = false; pending = null; detailsDraft = null; get('review').hidden = true; get('recovery').hidden = true;
    await loadState(false); get('values-heading').focus(); await loadChoices();
  }
  function showChanges(parent, rows) {
    parent.replaceChildren();
    if (!rows.length) { node('p', 'No changes to saved details.', parent); return; }
    rows.forEach(row => { const group = document.createElement('section'); parent.append(group); userNode('h3', row.label, group); const list = document.createElement('dl'); group.append(list); pair(list, 'Before', row.before); pair(list, 'After', row.after); });
  }
  function showReview() {
    if (!pending?.review) return;
    const summary = pending.review.summary; user(get('review-heading'), summary.heading);
    user(get('review-note'), [summary.kind, summary.record, labelStatus(summary.status), summary.notice].filter(Boolean).join(' · '));
    showChanges(get('review-details'), summary.changes); get('review').hidden = false; get('review-heading').focus(); get('review').scrollIntoView({block: 'nearest'});
  }
  async function review(mode) {
    if (!state || pending?.save_started) return;
    syncValues();
    const draft = clone(mode === 'schema' ? schemaDraft : detailsDraft), result = await call('POST', '/review', {
      context, kind, record: mode === 'schema' ? '' : record, mode, expected_schema_revision: state.schema.revision,
      expected_details_revision: mode === 'schema' ? 0 : state.details.revision,
      expected_source: mode === 'schema' ? '0'.repeat(64) : state.source.revision, draft});
    if (!validReview(result)) throw problem('The review could not be checked. Nothing was saved. Keep your draft and review again.');
    pending = {operation: result.operation, token: result.token, mode, kind, record: mode === 'schema' ? '' : record,
      schema_revision: state.schema.revision, details_revision: state.details.revision, source_revision: state.source?.revision || '', save_started: false, review: result};
    remember(); showReview(); say('Review the saved starting details and your proposed change. Nothing has been saved yet.');
  }
  function uncertain() {
    get('recovery').hidden = false; product(get('recovery-note'), 'The reply to your save was not confirmed. Check that exact request before making another change.');
    product(get('recovery-status'), 'The original save has not been confirmed. No change will be sent again automatically.'); get('original').hidden = false; remember();
  }
  function validOriginal(value) {
    return plain(value) && value.context === context && typeof value.found === 'boolean' && typeof value.confirmed === 'boolean' &&
      ['confirmed', 'audit_pending', 'unavailable'].includes(value.state) && value.found === (value.state !== 'unavailable') && value.confirmed === value.found && (!value.found ? !value.confirmed :
        plain(value.original) && typeof value.original.confirmed === 'boolean' && value.confirmed === value.original.confirmed && value.state === value.original.state && validChanges(value.original.changes));
  }
  async function finishOriginal(value, envelope = pending) {
    if (!validOriginal(value)) throw problem('The original save could not be checked. No further change was sent.');
    const completing = envelope === pending && pending?.save_started;
    get('recovery').hidden = false;
    product(get('recovery-note'), 'This shows the result of that exact save. Later changes may be different.');
    if (value.found) showChanges(get('original-details'), value.original.changes);
    else { get('original-details').replaceChildren(); node('p', 'Original save history is unavailable.', get('original-details')); }
    if (envelope.review?.summary) get('original-details').prepend(userNode('h3', envelope.review.summary.record + ' · ' + envelope.review.summary.kind));
    if (!value.confirmed) {
      product(get('recovery-status'), value.state === 'audit_pending' ? 'The saved change is awaiting its audit record. Keep checking the original save. No change will be sent again automatically.' :
        'The original save is unconfirmed or its retained history is unavailable. Current matching values cannot confirm that earlier request. No change will be sent again automatically.');
      if (completing) pending.save_started = true; remember(); return;
    }
    if (completing) {
      const mode = pending.mode; lastOriginal = clone(pending); pending = null; get('review').hidden = true;
      if (mode === 'schema') schemaDirty = false; else detailsDirty = false;
    }
    remember();
    product(get('recovery-status'), value.state === 'audit_pending' ? 'The original save was confirmed. Its audit record is still awaiting completion.' : 'The original save was confirmed from its retained history.');
    try { await loadState(true); await loadChoices(); } catch (_) { say('The original save was confirmed. The latest view could not be refreshed. Refresh work before making another change.'); return; }
    say(completing ? value.state === 'audit_pending' ? 'Your change was saved. Its audit record is still awaiting completion.' : 'Your reviewed change was saved.' :
      value.state === 'audit_pending' ? 'The earlier original save is confirmed. Its audit record is still awaiting completion. Your current draft is kept.' : 'The earlier original save is confirmed. Your current draft is kept.', true);
    if (completing) window.dispatchEvent(new CustomEvent('lightwork:product-state-changed'));
  }
  async function checkOriginal() {
    const envelope = pending?.save_started ? pending : lastOriginal;
    if (!envelope) return; const value = await call('POST', '/original', {context, token: envelope.token}); await finishOriginal(value, envelope);
  }
  async function save() {
    if (!pending || pending.save_started) return;
    pending.save_started = true;
    if (!remember()) { pending.save_started = false; throw problem('This browser could not keep the exact original save for recovery. Nothing was sent. Allow session storage and review again before saving.'); }
    get('original-details').replaceChildren();
    uncertain();
    try { const result = await call('POST', '/save', {context, token: pending.token, confirmed: true}); await finishOriginal(result); }
    catch (error) {
      if (lost) return;
      if (error.notSaved) { pending.save_started = false; pending.refused = true; get('recovery').hidden = true; remember(); }
      else uncertain();
      throw error;
    }
  }
  function restore(saved) {
    if (!saved || saved.context !== context || !plain(saved.draft)) return;
    const draft = saved.draft;
    if (plain(draft.schema) && Array.isArray(draft.schema.fields) && draft.schema.fields.length <= 20 && draft.schema.fields.every(row => definition(row, true)) && Array.isArray(draft.schema.stages) && draft.schema.stages.length <= 12 && draft.schema.stages.every(row => named(row, true))) { schemaDraft = clone(draft.schema); schemaDirty = draft.schema_dirty === true; }
    if (plain(draft.details) && plain(draft.details.values) && Object.keys(draft.details.values).length <= 100 && Object.values(draft.details.values).every(typed)) {
      detailsDraft = clone(draft.details); detailsDirty = draft.details_dirty === true;
      if (Array.isArray(draft.fields) && draft.fields.length <= 20 && draft.fields.every(row => definition(row))) draftFields = clone(draft.fields);
      if (Array.isArray(draft.stages) && draft.stages.length <= 12 && draft.stages.every(row => named(row))) draftStages = clone(draft.stages);
    }
    const copy = saved.pending;
    const historical = saved.last_original;
    if (plain(historical) && hex(historical.operation, 32) && string(historical.token, 500000) && historical.token && ['schema', 'details'].includes(historical.mode)) lastOriginal = clone(historical);
    if (plain(copy) && hex(copy.operation, 32) && string(copy.token, 500000) && copy.token && ['schema', 'details'].includes(copy.mode) && copy.kind === kind && (copy.mode === 'schema' || copy.record === record)) {
      pending = clone(copy);
      if (pending.save_started) uncertain();
      else if (pending.schema_revision !== state.schema.revision || pending.mode === 'details' && (pending.details_revision !== state.details.revision || pending.source_revision !== state.source?.revision)) {
        pending = null; say('Saved work changed while this page was closed. Your draft is kept. Review it against the current saved version.');
      } else if (validReview(pending.review)) showReview(); else pending = null;
    }
    renderValues(); renderDefinitions(); remember();
  }
  async function refresh() { await loadState(true); await loadChoices(); if (pending?.save_started) { uncertain(); say('Your draft is kept. Check the original save to confirm its result.'); } }
  get('refresh').addEventListener('click', () => action(refresh));
  get('original').addEventListener('click', () => action(checkOriginal));
  get('search-form').addEventListener('submit', event => { event.preventDefault(); action(async () => { pages = ['']; page = 0; await loadChoices(); }); });
  get('previous').addEventListener('click', () => action(async () => { page -= 1; await loadChoices(); }));
  get('next').addEventListener('click', () => action(async () => { pages[page + 1] = choices.cursor; page += 1; await loadChoices(); }));
  get('kind').addEventListener('change', () => {
    const selected = get('kind').value; action(async () => {
      if (!await allowDiscard()) { get('kind').value = kind; return; }
      kind = selected; record = ''; schemaDirty = detailsDirty = false; schemaDraft = detailsDraft = pending = null; pages = ['']; page = 0; get('review').hidden = get('recovery').hidden = true;
      await loadState(false); await loadChoices();
    });
  });
  get('add-field').addEventListener('click', () => {
    if (busy || !schemaDraft || schemaDraft.fields.length >= 20) return;
    schemaDraft.fields.push({id: '', label: '', type: 'text', required: false, options: []}); dirty('schema'); renderDefinitions();
    document.getElementById('wrd-field-' + (schemaDraft.fields.length - 1) + '-label').focus();
  });
  get('add-stage').addEventListener('click', () => {
    if (busy || !schemaDraft || schemaDraft.stages.length >= 12) return;
    schemaDraft.stages.push({id: '', label: ''}); dirty('schema'); renderDefinitions(); document.getElementById('wrd-stage-' + (schemaDraft.stages.length - 1)).focus();
  });
  get('definition-form').addEventListener('submit', event => { event.preventDefault(); if (get('definition-form').reportValidity()) action(() => review('schema')); });
  get('values-form').addEventListener('submit', event => { event.preventDefault(); if (get('values-form').reportValidity()) action(() => review('details')); });
  get('definition-reset').addEventListener('click', () => action(async () => {
    if (schemaDirty && (!window.mvConfirm || !await window.mvConfirm('Replace your category setup draft with the saved setup?', {okText: 'Use saved setup', productCopy: true}))) return;
    schemaDirty = false; pending = null; get('review').hidden = true; await loadState(true); say('Saved category setup is shown. No change was sent.');
  }));
  get('values-reset').addEventListener('click', () => action(async () => {
    if (detailsDirty && (!window.mvConfirm || !await window.mvConfirm('Replace your business details draft with the saved details?', {okText: 'Use saved details', productCopy: true}))) return;
    detailsDirty = false; pending = null; get('review').hidden = true; await loadState(true); say('Saved business details are shown. No change was sent.');
  }));
  get('cancel').addEventListener('click', () => { if (busy || pending?.save_started) return; pending = null; get('review').hidden = true; remember(); lock(false); say('Review cancelled. Your draft is still here. No change was sent.'); (detailsDirty ? get('values-review') : get('definition-review')).focus(); });
  get('save').addEventListener('click', () => action(save));
  window.addEventListener('beforeunload', event => { if (!lost && (schemaDirty || detailsDirty || pending)) { event.preventDefault(); event.returnValue = ''; } });
  window.addEventListener('storage', event => { if (event.key === 'lightwork-workspace-changed') clearPrivate(); });
  ['lightwork:workspace-changed', 'lightwork:session-expired', 'lightwork:access-changed'].forEach(name => document.addEventListener(name, clearPrivate));
  window.LightworkWorkRecordDetails = {openReview: async function (payload, options) {
    if (!plain(payload) || Object.keys(payload).length || !options || options.context !== context || typeof options.isCurrent !== 'function' || !options.isCurrent() || location.pathname !== '/work-details' || lost) return false;
    const previous = handoff; handoff = options;
    try { const ok = await action(async () => { await refresh(); if (!options.isCurrent()) return; const target = pending?.save_started ? get('original') : !state?.enabled ? get('status') : get('kind'); target.focus(); target.scrollIntoView({block: 'nearest'}); }); return ok && options.isCurrent(); }
    finally { handoff = previous; }
  }};
  let saved;
  try { const raw = sessionStorage.getItem(storage); saved = raw && raw.length <= 2 * 1024 * 1024 ? JSON.parse(raw) : null; } catch (_) { saved = null; }
  if (saved?.context === context && plain(saved.draft) && string(saved.draft.kind, 80) && string(saved.draft.record, 256)) { kind = saved.draft.kind; record = saved.draft.record; }
  action(async () => { await loadState(false); restore(saved); await loadChoices(); if (pending?.save_started) { uncertain(); say('An earlier save needs confirmation. Check the original save before making another change.'); } });
})();
