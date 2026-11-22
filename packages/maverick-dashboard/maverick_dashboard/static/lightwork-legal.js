/* Matter-scoped controls use the same reviewed service operations as Copilot. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('legal-form')) return;
  const base = '/api/v1/legal';
  const collections = {sources: 'Evidence', contracts: 'Contracts', engagements: 'Outside counsel', invoices: 'Invoices', assignments: 'Assignments', obligations: 'Obligations', decisions: 'Decisions', packets: 'Counsel packets'};
  const links = {source_id: 'sources', source_ids: 'sources', contract_id: 'contracts', engagement_id: 'engagements', invoice_id: 'invoices', assignment_id: 'assignments', obligation_id: 'obligations', decision_id: 'decisions'};
  let view = null, matter = null, tab = 'assignments', token = null, busy = false, generation = 0, opener = null;
  const el = (tag, text, css) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (css) node.className = css; return node; };
  const pretty = value => String(value || '').replaceAll('_', ' ');
  const title = value => pretty(value).replace(/^./, first => first.toUpperCase());
  const money = (value, currency) => new Intl.NumberFormat(undefined, {style: 'currency', currency}).format(value / 100);
  const label = record => record.title || record.firm || record.reference || 'Record';
  const say = text => { $('legal-message').textContent = text; };
  const api = (path, body) => window.mvFetchJSON(base + path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: {'Accept': 'application/json', 'Content-Type': 'application/json'}, body,
    onAccess: error => { clearPrivate(); remember(); say(error.message); },
    serverDetail: 'This operation is unavailable. Check your current account, workspace and permissions.',
    messages: {unreadable: 'The response was interrupted. Check the original result before trying again.'}
  }, 'manage legal work');
  function button(text, fn, css = 'btn') { const node = el('button', text, css); node.type = 'button'; node.addEventListener('click', fn); return node; }
  function selectMatterContext() {
    const selection = matter ? {kind: 'legal_matter', id: matter.id} : {};
    window.LightworkCopilotEarlySelection = {selection};
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection}}));
  }
  function clearPrivate() {
    matter = null; token = null; view = null; generation++;
    for (const id of ['legal-matters', 'legal-records', 'legal-attention', 'legal-spend', 'legal-team', 'legal-metrics', 'legal-preview', 'legal-fields', 'legal-matter-title', 'legal-matter-objective', 'legal-matter-meta']) $(id).replaceChildren();
    $('legal-matter').hidden = true; $('legal-editor').hidden = true;
    if ($('legal-review').open) $('legal-review').close();
    selectMatterContext();
  }
  function remember() {
    try {
      if (token && view) sessionStorage.setItem('lightwork-legal-review', JSON.stringify({token, context: view.context}));
      else sessionStorage.removeItem('lightwork-legal-review');
    } catch (_) { /* The in-memory token still supports original-result recovery. */ }
  }
  function restore() {
    if (token || !view) return;
    try {
      const saved = JSON.parse(sessionStorage.getItem('lightwork-legal-review') || 'null');
      if (!saved) return;
      if (saved.context !== view.context) { remember(); return; }
      token = saved.token; $('legal-preview').replaceChildren(el('p', 'A previous operation may have completed. Check its original result before starting another.'));
      $('legal-confirm').disabled = true; $('legal-original').hidden = false; $('legal-review').showModal();
    } catch (_) { /* An invalid recovery marker cannot authorize a write. */ }
  }
  function renderMatters() {
    const host = $('legal-matters'); host.replaceChildren();
    const query = $('legal-search').value.toLowerCase();
    const rows = view.matters.filter(row => [row.title, row.department, row.area].join(' ').toLowerCase().includes(query));
    rows.forEach(row => host.appendChild(button(row.title + ' · ' + pretty(row.status), () => openMatter(row.id), 'btn legal-matter-button')));
    if (!rows.length) host.appendChild(el('p', query ? 'No matching matters.' : 'Open your first legal request to get started.', 'legal-empty'));
  }
  function renderOverview() {
    const metrics = $('legal-metrics'); metrics.replaceChildren();
    const counts = [['Open matters', view.matters.filter(row => row.status !== 'closed').length], ['Needs attention', view.attention.length], ['Overdue items', view.attention.filter(row => row.overdue).length], ['Digital workers', view.workers.length]];
    counts.forEach(([name, count]) => { const card = el('div', undefined, 'panel legal-metric'); card.append(el('span', name), el('strong', String(count))); metrics.appendChild(card); });
    const attention = $('legal-attention'); attention.replaceChildren();
    view.attention.forEach(row => { const card = el('div', undefined, 'legal-card'); card.append(el('strong', row.title), el('p', row.matter + ' · ' + pretty(row.state) + (row.due_date ? ' · ' + row.due_date : '') + (row.overdue ? ' · Overdue' : '')), button('Open matter', () => openMatter(row.matter_id))); attention.appendChild(card); });
    if (!view.attention.length) attention.appendChild(el('p', 'No recorded exceptions or upcoming items. Open a matter to add its work.', 'legal-empty'));
    const spend = $('legal-spend'); spend.replaceChildren();
    Object.entries(view.spend).forEach(([currency, totals]) => spend.appendChild(el('p', money(totals.invoiced, currency) + ' invoiced of ' + money(totals.budget, currency) + ' budgeted · ' + currency)));
    if (!Object.keys(view.spend).length) spend.appendChild(el('p', 'Engagement budgets and recorded invoices will appear here.'));
    const team = $('legal-team'); team.replaceChildren();
    view.workers.forEach(role => { const card = el('article', undefined, 'legal-card'); card.append(el('p', 'AI ' + role.level, 'legal-muted'), el('h3', role.title), el('p', role.deliverable), el('p', role.assignments + ' assignments · ' + role.accepted + ' accepted · ' + role.corrections + ' awaiting corrections', 'legal-muted')); if (matter) card.appendChild(button('Assign work', () => openEditor('assignment', {role_id: role.id}))); team.appendChild(card); });
    renderMatters();
  }
  async function refresh(keep = true) {
    const current = keep && matter ? matter.id : '';
    const oldContext = view?.context;
    const draft = keep && !$('legal-editor').hidden && view ? {action: $('legal-action').value, values: collect()} : null;
    try {
      const data = await api('');
      if (view && view.context !== data.context) { clearPrivate(); remember(); }
      view = data; renderOverview();
      if (current && view.matters.some(row => row.id === current)) await openMatter(current, true);
      if (draft && oldContext === view.context && (draft.action === 'create_matter' || matter?.id === current)) openEditor(draft.action, draft.values);
      say('Current authorized legal work · ' + view.as_of); restore();
    } catch (error) { clearPrivate(); say(error.message); }
  }
  async function openMatter(id, internal = false) {
    if (busy && !internal) return;
    const gen = ++generation;
    try {
      const data = await api('/matters/' + encodeURIComponent(id));
      if (gen !== generation) return;
      if (!view || data.context !== view.context) { clearPrivate(); say('Your account or workspace changed. Refresh to continue.'); return; }
      matter = data.matter; $('legal-overview').hidden = true; $('legal-matter').hidden = false; $('legal-editor').hidden = true;
      $('legal-matter-title').textContent = matter.title;
      $('legal-matter-objective').textContent = matter.objective;
      $('legal-matter-meta').textContent = [title(matter.area), title(matter.status), matter.department, 'Business owner: ' + matter.business_owner, 'Jurisdiction: ' + matter.jurisdiction, 'Supervisor: ' + matter.owner.replace(/^user:/, '')].join(' · ');
      selectMatterContext(); renderRecords(); renderOverview();
    } catch (error) { matter = null; $('legal-records').replaceChildren(); $('legal-matter').hidden = true; $('legal-editor').hidden = true; selectMatterContext(); say(error.message); }
  }
  function sourceLabel(id) { const source = (matter.sources || []).find(row => row.id === id); return source ? source.title + ' — ' + source.reference : 'Unavailable source'; }
  function recordDetails(row) {
    const dl = el('dl', undefined, 'legal-record');
    const hidden = new Set(['id', 'title', 'firm', 'state', 'sha256', 'attempts', 'source_ids', 'run_id', 'output', 'versions', 'source_id', 'role_id', 'engagement_id', 'contract_id', 'contract_source_id', 'deadline']);
    Object.entries(row).forEach(([key, value]) => {
      if (hidden.has(key) || value === '' || value === null || (Array.isArray(value) && !value.length)) return;
      let display = typeof value === 'object' ? value.join('\n') : String(value);
      if (key.endsWith('_at') && typeof value === 'number') display = new Date(value * 1000).toLocaleString();
      if (['budget', 'amount', 'max_hourly_rate', 'hourly_rate'].includes(key)) display = money(value, row.currency || 'USD');
      dl.append(el('dt', title(key)), el('dd', display));
    });
    if (row.source_id) dl.append(el('dt', 'Evidence'), el('dd', sourceLabel(row.source_id)));
    if (row.source_ids) dl.append(el('dt', 'Selected evidence'), el('dd', row.source_ids.map(sourceLabel).join('\n')));
    return dl;
  }
  function renderOutput(host, assignment) {
    if (!assignment.output) return;
    const output = assignment.output;
    host.append(el('h4', 'Draft for supervising counsel'), el('p', output.summary), el('p', output.draft));
    const sources = el('details'); sources.appendChild(el('summary', 'Supporting passages and open questions'));
    output.findings.forEach(finding => sources.append(el('p', finding.claim), el('blockquote', finding.quote), el('p', sourceLabel(finding.source_id), 'legal-muted')));
    output.questions.forEach(question => sources.appendChild(el('p', question)));
    host.appendChild(sources);
  }
  function renderRecords() {
    const tabs = $('legal-tabs'); tabs.replaceChildren();
    Object.entries(collections).forEach(([key, name]) => { const control = button(name + ' (' + matter[key].length + ')', () => { tab = key; renderRecords(); }); control.setAttribute('aria-pressed', String(tab === key)); tabs.appendChild(control); });
    const host = $('legal-records'); host.replaceChildren();
    const actions = {sources: 'source', contracts: 'contract', engagements: 'engagement', invoices: 'invoice', assignments: 'assignment', obligations: 'obligation', decisions: 'decision', packets: 'packet'};
    host.appendChild(button(view.operations[actions[tab]].label, () => openEditor(actions[tab]), 'btn btn--primary'));
    const rows = matter[tab];
    if (!rows.length) host.appendChild(el('p', 'No ' + collections[tab].toLowerCase() + ' recorded yet.', 'legal-empty'));
    rows.forEach(row => {
      const card = el('article', undefined, 'legal-card'); card.append(el('h3', label(row)), el('p', title(row.state || row.stage || row.status), 'legal-muted'));
      if (row.role_id) card.appendChild(el('p', view.workers.find(worker => worker.id === row.role_id)?.title || 'Digital worker'));
      const detail = el('details'); detail.append(el('summary', 'Details and evidence'), recordDetails(row)); card.appendChild(detail);
      if (tab === 'assignments') {
        renderOutput(card, row);
        if (['queued', 'changes_requested', 'failed'].includes(row.state)) card.appendChild(button('Review worker run', () => openEditor('run', {assignment_id: row.id})));
        if (!['accepted', 'cancelled'].includes(row.state)) card.appendChild(button('Review or cancel', () => openEditor('review_assignment', {assignment_id: row.id})));
        if (row.state === 'running') card.appendChild(el('p', 'Work has started. Refresh to check its saved result. An interrupted attempt is never restarted automatically. You can cancel it before creating a new assignment.'));
      }
      const reviews = {contracts: ['edit_contract', 'contract_id'], engagements: ['review_engagement', 'engagement_id'], invoices: ['review_invoice', 'invoice_id'], obligations: ['review_obligation', 'obligation_id'], decisions: ['review_decision', 'decision_id']};
      if (reviews[tab]) { const [action, key] = reviews[tab]; card.appendChild(button(view.operations[action].label, () => openEditor(action, {[key]: row.id, ...(action === 'edit_contract' ? row : {})}))); }
      if (tab === 'packets') { const download = el('a', 'Download reviewed packet', 'btn'); download.href = base + '/matters/' + encodeURIComponent(matter.id) + '/export?packet_id=' + encodeURIComponent(row.id); card.appendChild(download); }
      host.appendChild(card);
    });
    host.appendChild(button('More matter operations', () => openEditor('assignment')));
    const exportLink = el('a', 'Export matter record', 'btn'); exportLink.href = base + '/matters/' + encodeURIComponent(matter.id) + '/export'; host.appendChild(exportLink);
  }
  function optionsFor(name, prop) {
    if (name in links) { const options = (matter?.[links[name]] || []).map(row => [row.id, label(row)]); if (prop.default === '') options.unshift(['', 'No related contract']); return options; }
    if (name === 'role_id') return view.workers.map(row => [row.id, row.title]);
    if (name === 'principal') { const entries = new Map(view.members.map(row => [row.value, row.label])); (matter?.members || []).forEach(value => entries.set(value, value.replace(/^user:/, ''))); return Array.from(entries); }
    return (prop.enum || []).map(value => [value, title(value)]);
  }
  function renderFields(values = {}) {
    const action = $('legal-action').value, schema = view.operations[action].schema;
    const host = $('legal-fields'); host.replaceChildren();
    $('legal-action-help').textContent = action === 'run' ? 'Review the exact evidence and budget before sending it to your configured AI provider. The result is a draft for supervising counsel.' : action === 'source' ? 'Add source text with its origin. You can import a UTF-8 text or Markdown file. Preserve original files in your document system.' : 'Review the proposed change before saving. No external message, signature, filing or payment is sent.';
    Object.entries(schema.properties).forEach(([name, prop]) => {
      const options = optionsFor(name, prop), wrapper = el('div', undefined, 'legal-field');
      const isSelect = prop.enum || name in links || ['role_id', 'principal'].includes(name);
      let input;
      if (isSelect) { input = el('select', undefined, 'select'); input.multiple = prop.type === 'array'; options.forEach(([value, text]) => { const option = el('option', text); option.value = value; input.appendChild(option); }); }
      else if (prop.type === 'boolean') { input = el('input'); input.type = 'checkbox'; }
      else if (prop.maxLength > 500) { input = el('textarea', undefined, 'input'); input.rows = name === 'text' ? 10 : 3; wrapper.classList.add('legal-field--wide'); }
      else { input = el('input', undefined, 'input'); input.type = prop.type === 'number' || prop.type === 'integer' ? 'number' : name === 'due_date' ? 'date' : 'text'; }
      input.id = 'legal-input-' + name; input.name = name; input.required = (schema.required || []).includes(name);
      if (prop.maxLength) input.maxLength = prop.maxLength;
      if (prop.minimum !== undefined) input.min = prop.minimum;
      if (prop.maximum !== undefined) input.max = prop.maximum;
      if (prop.exclusiveMinimum !== undefined) input.min = 0.01;
      if (input.type === 'number') input.step = prop.type === 'integer' ? '1' : '0.01';
      if (prop.pattern) input.pattern = prop.pattern;
      const value = values[name] !== undefined ? values[name] : action === 'edit_matter' && matter && name in matter ? matter[name] : prop.default;
      if (input.multiple) Array.from(input.options).forEach(option => { option.selected = (value || []).includes(option.value); });
      else if (input.type === 'checkbox') input.checked = !!value;
      else if (value !== undefined) input.value = value;
      const lab = el('label', prop.title || title(name)); lab.htmlFor = input.id; wrapper.append(lab, input); host.appendChild(wrapper);
      if (name === 'text' && action === 'source') {
        const fileLabel = el('label', 'Import a text file'); fileLabel.htmlFor = 'legal-source-file';
        const file = el('input'); file.type = 'file'; file.id = 'legal-source-file'; file.accept = '.txt,.md,text/plain,text/markdown';
        file.addEventListener('change', async () => { const selected = file.files[0]; if (!selected) return; if (selected.size > 100000) { say('Choose a text file under 100 KB.'); return; } input.value = await selected.text(); if (!$('legal-input-title').value) $('legal-input-title').value = selected.name; });
        wrapper.append(fileLabel, file);
      }
    });
  }
  function openEditor(action, values = {}) {
    if (!view || busy) return;
    if (action !== 'create_matter' && !matter) { say('Select a matter first.'); return; }
    const select = $('legal-action'); select.replaceChildren();
    Object.entries(view.operations).filter(([key]) => action === 'create_matter' ? key === action : key !== 'create_matter').forEach(([key, value]) => { const option = el('option', value.label); option.value = key; select.appendChild(option); });
    select.value = action; $('legal-editor').hidden = false; renderFields(values); $('legal-editor').scrollIntoView({block: 'nearest'}); select.focus();
  }
  function collect() {
    const schema = view.operations[$('legal-action').value].schema, args = {};
    Object.entries(schema.properties).forEach(([name, prop]) => {
      const input = $('legal-input-' + name);
      args[name] = input.multiple ? Array.from(input.selectedOptions).map(option => option.value) : prop.type === 'boolean' ? input.checked : ['integer', 'number'].includes(prop.type) ? Number(input.value) : input.value;
    });
    return args;
  }
  function previewValue(value) {
    if (Array.isArray(value)) { const list = el('ul'); value.forEach(entry => { const li = el('li'); li.appendChild(previewValue(entry)); list.appendChild(li); }); return list; }
    if (value && typeof value === 'object') { const dl = el('dl', undefined, 'legal-record'); Object.entries(value).filter(([key]) => !['id', 'sha256', 'added_by'].includes(key)).forEach(([key, entry]) => { const dd = el('dd'); dd.appendChild(previewValue(entry)); dl.append(el('dt', title(key)), dd); }); return dl; }
    return el('p', String(value));
  }
  $('legal-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !view) return;
    if (token) { say('Check or close the outstanding review before starting another.'); return; }
    busy = true; $('legal-review-button').disabled = true;
    try {
      const action = $('legal-action').value;
      const data = await api('/review', {action, arguments: collect(), matter_id: action === 'create_matter' ? '' : matter.id, expected_revision: action === 'create_matter' ? 0 : matter.revision, context: view.context});
      token = data.token; opener = document.activeElement;
      $('legal-preview').replaceChildren(previewValue(data.preview)); $('legal-review-message').textContent = '';
      $('legal-confirm').disabled = false; $('legal-original').hidden = true; $('legal-review').showModal();
    } catch (error) { say(error.message); } finally { busy = false; $('legal-review-button').disabled = false; }
  });
  async function confirm(original = false) {
    if (busy || !token) return;
    busy = true; $('legal-confirm').disabled = true; $('legal-original').disabled = true;
    remember(); say('Recording or recovering the reviewed operation…'); $('legal-review-message').textContent = original ? 'Checking the original result…' : 'Recording the reviewed work. Digital drafting may take a little longer…';
    let savedId = '';
    try {
      const data = await api(original ? '/original' : '/confirm', {token, confirmed: !original});
      if (!data.matter) { token = null; remember(); $('legal-original').hidden = true; $('legal-review-message').textContent = 'No result is recorded. Nothing was repeated. Close this review and refresh before preparing another.'; return; }
      savedId = data.matter.id; token = null; remember(); $('legal-review').close(); $('legal-editor').hidden = true;
    } catch (error) { $('legal-review-message').textContent = error.message; $('legal-original').hidden = false; }
    finally { if (!savedId) busy = false; $('legal-original').disabled = false; }
    if (savedId) { await refresh(false); if (view) await openMatter(savedId, true); busy = false; say('The operation is recorded. Review the current matter and any worker output.'); }
  }
  $('legal-confirm').addEventListener('click', () => confirm(false));
  $('legal-original').addEventListener('click', () => confirm(true));
  $('legal-review-cancel').addEventListener('click', () => { if (busy) return; if (!$('legal-original').hidden) remember(); else { token = null; remember(); } $('legal-review').close(); opener?.focus(); });
  $('legal-review').addEventListener('cancel', event => { if (busy) { event.preventDefault(); return; } if ($('legal-original').hidden) { token = null; remember(); } });
  $('legal-action').addEventListener('change', () => renderFields());
  $('legal-editor-cancel').addEventListener('click', () => { $('legal-editor').hidden = true; });
  $('legal-new').addEventListener('click', () => openEditor('create_matter'));
  $('legal-edit').addEventListener('click', () => openEditor('edit_matter'));
  $('legal-refresh').addEventListener('click', () => { if (!busy) refresh(); });
  $('legal-search').addEventListener('input', () => { if (view) renderMatters(); });
  $('legal-back').addEventListener('click', () => { generation++; matter = null; $('legal-matter').hidden = true; $('legal-editor').hidden = true; $('legal-overview').hidden = false; selectMatterContext(); if (view) renderOverview(); });
  $('legal-team-toggle').addEventListener('click', () => { const section = $('legal-team-section'); section.hidden = !section.hidden; $('legal-team-toggle').setAttribute('aria-expanded', String(!section.hidden)); });
  refresh(false).then(() => { const id = window.location.hash.slice(1); if (view && view.matters.some(row => row.id === id)) openMatter(id); });
}());
