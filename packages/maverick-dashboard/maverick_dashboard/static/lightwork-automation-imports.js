/* Protected ordinary import review; private exports stay in memory. */
(function () {
  'use strict';
  const root = document.getElementById('auto-import-section');
  if (!root) return;
  const by = name => document.getElementById('air-' + name), form = by('form'), source = by('source'), mode = by('mode'), account = by('connection');
  const reviewBox = by('review-box'), result = by('result'), status = by('status'), error = by('error'), history = by('history');
  const storage = 'lightwork.automation-import.original.v1';
  let context = '', current = null, fileText = '', busy = false, generation = 0, pending = null, dirty = false, publishing = false;
  function node(tag, text, parent) { const item = document.createElement(tag); if (text !== undefined) item.textContent = String(text); if (parent) parent.append(item); return item; }
  function lock(value) { busy = value; root.querySelectorAll('button,input,select').forEach(item => { item.disabled = value; }); if (!value) { by('review').disabled = !current?.enabled; by('read').disabled = !history.value; } }
  function invalidate() { reviewBox.replaceChildren(); }
  function selected(id) { if (!id) return; publishing = true; try { document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: {kind: 'automation_import_request', id}}})); } finally { publishing = false; } }
  function fail(value) { error.textContent = value.message || 'Import information is unavailable. Entered work was kept.'; if (value.status === 401 || value.status === 403 || value.denied) clear(); }
  async function request(path, body, expected = context) {
    const F = 'Import information is unavailable. Entered work was kept.';
    try {
      // Only a redirect to sign-in counts as lost access here; a 401 or 403 is a refusal the page reads.
      const value = await window.mvFetchJSON('/api/v1/automation-imports' + path, {method: body === undefined ? 'GET' : 'POST', headers: expected ? {'X-Lightwork-Import-Context': expected} : {},
        body, serverDetail: F, messages: {unreadable: F}, accessStatuses: [], onAccess() {}}, 'read the import choices');
      if (!value) throw Object.assign(new Error(F), {status: 200});
      return value;
    } catch (failure) {
      failure.denied = !!failure.accessChanged || failure.headers?.get?.('X-Lightwork-Import-Context-Changed') === '1';
      throw failure;
    }
  }
  function setMode() {
    const found = current?.sources.find(row => row.value === source.value);
    mode.querySelector('[value="live"]').disabled = !found?.live;
    if (!found?.live) mode.value = 'file';
    const live = mode.value === 'live'; by('file-field').hidden = live; by('account-fields').hidden = !live; by('uipath-fields').hidden = !live || source.value !== 'uipath'; by('make-fields').hidden = !live || source.value !== 'make';
    by('source-help').textContent = found?.live ? 'Choose an exported file or a named connected account. The account is checked again before each read and each save.' : 'This platform requires an exported automation file. Lightwork does not fetch its definitions from an account.';
    const wanted = account.value; account.replaceChildren(new Option('Choose a connected account', ''));
    (current?.connections || []).filter(row => row.source === source.value).forEach(row => account.append(new Option(row.label + (row.ready ? '' : ' / needs credentials'), row.value)));
    if (Array.from(account.options).some(row => row.value === wanted)) account.value = wanted;
  }
  async function refresh(expected = context) {
    if (busy) return false;
    const started = ++generation, wanted = source.value; lock(true); error.textContent = ''; invalidate();
    try {
      const next = await request('', undefined, expected); if (started !== generation) return false;
      if (context && context !== next.context) { clear(); return false; }
      current = next; context = next.context; by('disabled').hidden = next.enabled; by('author').hidden = !next.enabled;
      source.replaceChildren(new Option('Choose a platform', '')); next.sources.forEach(row => source.append(new Option(row.label, row.value))); source.value = wanted;
      setMode();
      const saved = await request('/history'); if (started !== generation) return false;
      const original = history.value; history.replaceChildren(new Option('Choose an original request', '')); saved.choices.forEach(row => history.append(new Option(row.label, row.value)));
      if (!pending) { try { const kept = JSON.parse(sessionStorage.getItem(storage) || 'null'); if (kept?.context === context && /^AIR-[a-f0-9]{32}$/.test(kept.id)) pending = kept; } catch (_) {} }
      const wantedOriginal = original || pending?.id; if (wantedOriginal) { if (!Array.from(history.options).some(row => row.value === wantedOriginal)) history.append(new Option('Original request / check outcome', wantedOriginal)); history.value = wantedOriginal; }
      status.textContent = 'Current import choices are ready. Original history never repeats saved work.'; return true;
    } catch (failure) { if (started === generation) fail(failure); return false; }
    finally { if (started === generation) lock(false); }
  }
  function choices() {
    const live = mode.value === 'live';
    return {context, source: source.value, mode: mode.value, file_text: live ? '' : fileText, connection: live ? account.value : '', organization: live && source.value === 'uipath' ? by('organization').value : '', tenant_name: live && source.value === 'uipath' ? by('tenant').value : '',
      make_scope: live && source.value === 'make' ? by('make-scope').value : '', make_scope_id: live && source.value === 'make' && by('make-id').value ? Number(by('make-id').value) : null,
      as_flows: by('flows').checked, replace: Array.from(by('replace').querySelectorAll('input:checked')).map(item => item.value), budget_dollars: Number(by('dollars').value), budget_wall_seconds: Number(by('wall').value)};
  }
  function renderReview(rows) {
    if (!Array.isArray(rows) || rows.length < 4 || rows.length > 1000 || rows.some(row => !row || Object.keys(row).sort().join(',') !== 'after,label' || typeof row.label !== 'string' || typeof row.after !== 'string')) throw new Error('This complete review cannot be displayed. No drafts were submitted.');
    reviewBox.replaceChildren(); node('h3', 'Review every imported draft', reviewBox);
    rows.forEach(row => { node('h4', row.label, reviewBox); const value = node('p', row.after, reviewBox); value.style.whiteSpace = 'pre-wrap'; value.style.overflowWrap = 'anywhere'; });
  }
  function show(value) {
    result.replaceChildren(); by('originals').open = true; status.textContent = value.message;
    (value.items || []).forEach(item => { const block = node('div', undefined, result); block.className = 'panel'; node('h4', item.title, block); node('p', item.status, block);
      if (item.status !== 'Kept unchanged') { const builder = node('a', 'Review and publish these instructions', block); builder.href = '/workflow-builder?edit=' + encodeURIComponent(item.template); }
      if (item.flow) { const link = node('a', 'Open the visual draft', block); link.href = '/flows/designer/' + encodeURIComponent(item.flow); }
      node('p', 'This import left schedules and starts from other services off. Any later activation is a separate request.', block); });
    if (value.schedule) node('p', 'Future schedule accepted for ' + value.schedule.title + '. Use the schedules above to supervise, pause or retire future work.', result);
    (value.activation_choices || []).forEach(choice => {
      const fields = node('div', undefined, result); fields.className = 'panel stack'; node('h4', 'Activate original schedule: ' + choice.label, fields);
      node('p', 'First publish this exact draft in Workflow builder. Then fill its inputs and review one separate future schedule. This does not run the automation now.', fields);
      const inputs = [];
      const zoneLabel = node('label', 'Schedule timezone', fields), timezone = node('select', undefined, fields); timezone.className = 'input'; timezone.id = 'air-zone-' + choice.value; zoneLabel.htmlFor = timezone.id; timezone.append(new Option('Choose and confirm the intended timezone', ''));
      (current?.timezones || ['UTC']).forEach(zone => timezone.append(new Option(zone === 'UTC' ? 'Coordinated Universal Time (UTC)' : zone.replace(/_/g, ' '), zone)));
      if (choice.source_timezone && (current?.timezones || []).includes(choice.source_timezone)) { timezone.value = choice.source_timezone; node('p', 'The export names this timezone. Confirm it and the next scheduled starts in the full review.', fields); }
      else node('p', 'This export does not establish its original timezone. Choose the intended timezone; Lightwork will show the next scheduled starts before you confirm.', fields);
      timezone.addEventListener('change', invalidate);
      choice.params.forEach(name => { const label = node('label', name.replace(/_/g, ' '), fields), input = node('input', undefined, fields); input.className = 'input'; input.maxLength = 8000; input.id = 'air-param-' + choice.value + '-' + inputs.length; label.htmlFor = input.id; inputs.push([name, input]); input.addEventListener('input', invalidate); });
      const button = node('button', 'Review original schedule activation', fields); button.type = 'button'; button.className = 'btn btn--ghost';
      button.addEventListener('click', () => { if (!timezone.value) { error.textContent = 'Choose the intended schedule timezone before reviewing activation.'; return; } activationReview({context, original: value.id, item: choice.value, timezone: timezone.value, params: Object.fromEntries(inputs.map(([name, input]) => [name, input.value]))}); });
    });
  }
  async function readOriginal(id = history.value, publish = true, stillCurrent = () => true) {
    if (busy || !id) return false; const started = ++generation; lock(true); error.textContent = ''; invalidate();
    try { const value = await request('/original/' + encodeURIComponent(id)); if (started !== generation || !stillCurrent()) return false; show(value); history.value = id; if (publish) selected(id); return true; }
    catch (failure) { if (started === generation) fail(failure); return false; }
    finally { if (started === generation) lock(false); }
  }
  async function activationReview(body) {
    if (busy || !context) return; const started = ++generation; lock(true); invalidate(); error.textContent = '';
    try {
      const checked = await request('/review-activation', body); if (started !== generation) return; renderReview(checked.changes);
      const label = node('label', undefined, reviewBox), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode('I reviewed this exact published work, inputs and future spending. Activate its original recurring schedule once.'));
      const apply = node('button', 'Activate reviewed schedule', reviewBox); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.disabled = true; consent.addEventListener('change', () => { apply.disabled = busy || !consent.checked; });
      apply.addEventListener('click', async () => {
        if (busy || !consent.checked || started !== generation) return;
        pending = {context, id: checked.operation}; try { sessionStorage.setItem(storage, JSON.stringify(pending)); } catch (_) { error.textContent = 'Allow site storage before activation so its original request can be read. Nothing was activated.'; return; }
        history.append(new Option('Original activation just reviewed', pending.id)); history.value = pending.id; selected(pending.id); lock(true);
        try { const saved = await request('/apply', {token: checked.token, confirmed: true}); if (started === generation) { invalidate(); show(saved); } }
        catch (failure) { if (started === generation) { invalidate(); fail(failure); status.textContent = 'The original activation is unconfirmed. Read its original outcome; nothing will be submitted again automatically.'; } }
        finally { if (started === generation) lock(false); }
      });
      status.textContent = 'Complete schedule activation review ready. Future runs can spend money and affect connected services.';
    } catch (failure) { if (started === generation) fail(failure); }
    finally { if (started === generation) { lock(false); const button = reviewBox.querySelector('button.btn--primary'); if (button) button.disabled = true; } }
  }
  async function review(event) {
    event.preventDefault(); if (busy || !context || !current?.enabled) return;
    if (!source.value || (mode.value === 'file' && !fileText) || (mode.value === 'live' && !account.value)) { error.textContent = 'Choose a platform and its exported file or current connected account.'; return; }
    const started = ++generation, body = choices(); lock(true); error.textContent = ''; invalidate();
    try {
      const checked = await request('/review', body); if (started !== generation) return;
      renderReview(checked.changes); const prior = new Set(body.replace); by('replace').replaceChildren();
      checked.existing.forEach(row => { const label = node('label', undefined, by('replace')), check = node('input', undefined, label); check.type = 'checkbox'; check.value = row.value; check.checked = prior.has(row.value); label.append(document.createTextNode(' Replace my current draft: ' + row.label)); check.addEventListener('change', () => { invalidate(); dirty = true; status.textContent = 'Replacement choices changed. Check and review the complete import again.'; }); });
      const label = node('label', undefined, reviewBox), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode('I reviewed all instructions, replacements, spending limits and visual steps. Save these drafts and leave activation off.'));
      const actions = node('div', undefined, reviewBox); actions.className = 'btn-group'; const apply = node('button', 'Save reviewed drafts', actions); apply.type = 'button'; apply.className = 'btn btn--primary'; apply.disabled = true;
      const cancel = node('button', 'Cancel this review', actions); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.addEventListener('click', () => { if (!busy) { invalidate(); status.textContent = 'Review cancelled. Your chosen file and entered choices were kept.'; } });
      consent.addEventListener('change', () => { apply.disabled = busy || !consent.checked; });
      apply.addEventListener('click', async () => {
        if (busy || !consent.checked || started !== generation || JSON.stringify(choices()) !== JSON.stringify(body)) return;
        pending = {context, id: checked.operation}; try { sessionStorage.setItem(storage, JSON.stringify(pending)); } catch (_) { error.textContent = 'This browser cannot retain the original request reference. Allow site storage before saving; no drafts were submitted.'; return; }
        if (!Array.from(history.options).some(row => row.value === pending.id)) history.append(new Option('Original request just reviewed', pending.id)); history.value = pending.id; selected(pending.id);
        lock(true); apply.disabled = true; status.textContent = 'Saving reviewed drafts once…';
        try { const value = await request('/apply', {token: checked.token, confirmed: true}); if (started !== generation) return; invalidate(); show(value); if (value.confirmed) dirty = false; }
        catch (failure) { if (started === generation) { invalidate(); fail(failure); status.textContent = 'The original save is unconfirmed. Read its original outcome below; earlier saved items may remain. Nothing will repeat automatically.'; } }
        finally { if (started === generation) lock(false); }
      });
      status.textContent = 'Complete review ready. Every saved change stays a draft.';
    } catch (failure) { if (started === generation) fail(failure); }
    finally { if (started === generation) { lock(false); const confirm = reviewBox.querySelector('button.btn--primary'); if (confirm) confirm.disabled = true; } }
  }
  async function open(value, stillCurrent = () => true) {
    if (busy || !value || typeof value.context !== 'string' || !stillCurrent()) return false;
    const before = JSON.stringify(choices()), next = await request('', undefined, value.context); if (!stillCurrent() || (context && next.context !== context) || before !== JSON.stringify(choices())) return false;
    if (value.original) { if (!/^AIR-[a-f0-9]{32}$/.test(value.original)) return false; if (!await readOriginal(value.original, false, stillCurrent)) return false; if (!stillCurrent()) return false; }
    else { if (!next.enabled) return false; by('author').open = true; }
    if (!stillCurrent()) return false; const heading = document.getElementById('auto-import-h'); heading.focus(); heading.scrollIntoView({block: 'start'}); return true;
  }
  window.LightworkAutomationImports = {open};
  function clear() { ++generation; current = null; context = ''; pending = null; fileText = ''; dirty = false; form.reset(); source.replaceChildren(); account.replaceChildren(); by('replace').replaceChildren(); history.replaceChildren(); invalidate(); result.replaceChildren(); lock(true); busy = false; by('refresh').disabled = false; status.textContent = 'Your account, workspace or access changed. Private import details were cleared. Refresh to continue.'; try { sessionStorage.removeItem(storage); } catch (_) {} }
  by('file').addEventListener('change', async event => { const started = ++generation, file = event.target.files?.[0]; invalidate(); dirty = true; fileText = ''; if (!file) return; if (file.size > 512000) { error.textContent = 'Choose an export no larger than 512 KB.'; return; } lock(true); try { const value = await file.text(); if (started === generation) { fileText = value; status.textContent = 'Export selected. Its full translation will be reviewed before anything is saved.'; } } catch (_) { if (started === generation) error.textContent = 'This file could not be read. Choose the platform export again.'; } finally { if (started === generation) lock(false); } });
  form.addEventListener('submit', review); form.addEventListener('input', event => { if (event.target.id === 'air-file') return; dirty = true; invalidate(); });
  source.addEventListener('change', setMode); mode.addEventListener('change', setMode); by('refresh').addEventListener('click', () => refresh()); by('read').addEventListener('click', () => readOriginal()); history.addEventListener('change', () => { invalidate(); result.replaceChildren(); by('read').disabled = !history.value; if (history.value) selected(history.value); });
  document.addEventListener('lightwork:workspace-changed', clear); document.addEventListener('lightwork:account-context-changed', clear); window.addEventListener('lightwork:context-changed', clear); document.addEventListener('lightwork:copilot-context-changed', event => { if (!publishing && event.detail?.reason !== 'selection') clear(); });
  window.addEventListener('beforeunload', event => { if (dirty && !busy) { event.preventDefault(); event.returnValue = ''; } });
  refresh('').then(async ready => { if (!ready) return; const id = new URLSearchParams(location.search).get('import_original'); if (id && /^AIR-[a-f0-9]{32}$/.test(id)) { if (!Array.from(history.options).some(row => row.value === id)) history.append(new Option('Selected original request', id)); history.value = id; await readOriginal(id); } });
}());
