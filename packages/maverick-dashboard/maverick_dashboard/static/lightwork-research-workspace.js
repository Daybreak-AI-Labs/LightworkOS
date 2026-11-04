(() => {
  'use strict';
  const root = document.getElementById('research-lab');
  const status = document.getElementById('research-governed-status');
  if (!root || !status) return;

  const context = root.dataset.context || '';
  const byId = id => document.getElementById(id);
  const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const identifier = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value);
  let workspace = null;
  let busy = false;
  let programs = [];
  let executing = false;
  let heldRun = sessionStorage.getItem(`research-original:${context}`) || "";

  function element(tag, text, className) {
    const item = document.createElement(tag);
    if (text !== undefined) item.textContent = text;
    if (className) item.className = className;
    return item;
  }

  function message(text, error) {
    status.textContent = text;
    status.classList.toggle('error', !!error);
  }

  function setBusy(value) {
    busy = value;
    root.querySelectorAll('.research-workspace button, .research-workspace input, .research-workspace select, .research-workspace textarea')
      .forEach(control => { control.disabled = (value && !control.hasAttribute("data-live-execution-control")) || control.dataset.permanentDisabled === 'true'; });
    if (!value) syncConditionalFields();
  }

  async function api(path, method, body) {
    const value = await window.mvFetchJSON('/api/v1/research' + path, {method: method || 'GET', cache: 'no-store', body, plainDetail: true, messages: {
      409: 'Someone changed this. Refresh and check it again.',
      403: 'You do not have permission to do this. Ask an administrator.',
      422: 'Some details need fixing. Check what you entered and try again.',
      404: 'That item is not available in this workspace. Refresh the page to see the latest.'}});
    if (value && value.context && value.context !== context) {
      throw new Error('You switched account or workspace. Reload this page.');
    }
    return value;
  }

  function validReference(value, kind) {
    return value && (value.kind === 'dataset' || value.kind === 'model') &&
      (!kind || value.kind === kind) && identifier(value.asset_id) &&
      identifier(value.version) && sha(value.manifest_sha256) &&
      value.schema === 'lightwork.research-registry-ref.v1';
  }

  function validAsset(value, kind) {
    return value && validReference(value.reference, kind) && value.kind === kind &&
      ['draft', 'approved', 'revoked'].includes(value.state) &&
      Number.isSafeInteger(value.revision) && value.revision >= 1 &&
      Array.isArray(value.allowed_purposes) && Array.isArray(value.usage_constraints) &&
      value.eligibility && ['eligible', 'blocked', 'unavailable', 'awaiting_approval', 'revoked']
        .includes(value.eligibility.state);
  }

  function validRun(value) {
    return value && identifier(value.run_id) && typeof value.status === 'string' &&
      Number.isSafeInteger(value.revision) && value.revision >= 1 &&
      value.manifest && Array.isArray(value.manifest.dataset_refs) &&
      Array.isArray(value.attempts) && value.cost_summary &&
      typeof value.cost_summary.incomplete === 'boolean';
  }

  function validImpact(value) {
    return value && validReference(value.source) &&
      ['draft', 'approved', 'revoked'].includes(value.source_state) &&
      value.raw_deletion_removes_weight_influence === false && Array.isArray(value.derivatives) &&
      value.derivatives.every(row => validReference(row.reference) &&
        ['invalidate_dataset', 'retire_or_retrain_model'].includes(row.required_action));
  }

  function validate(value) {
    if (!value || value.context !== context || !value.registry ||
        !Array.isArray(value.registry.datasets) || value.registry.datasets.some(row => !validAsset(row, 'dataset')) ||
        !Array.isArray(value.registry.models) || value.registry.models.some(row => !validAsset(row, 'model')) ||
        typeof value.registry.can_review !== 'boolean' || !Array.isArray(value.governed_runs) ||
        value.governed_runs.some(row => !validRun(row)) || !value.governed_execution ||
        typeof value.governed_execution.available !== 'boolean') {
      throw new Error('The research lab could not be loaded correctly. Refresh the page.');
    }
    return value;
  }

  function sortedUnique(values) {
    return [...new Set(values.map(value => value.trim()).filter(Boolean))].sort();
  }

  function commaValues(value) {
    return sortedUnique(value.split(','));
  }

  function lineValues(value) {
    return sortedUnique(value.split(/\r?\n/));
  }

  function refKey(reference) {
    return `${reference.kind}:${reference.asset_id}:${reference.version}:${reference.manifest_sha256}`;
  }

  function sortRefs(values) {
    return values.sort((left, right) =>
      [left.asset_id, left.version, left.manifest_sha256].join('\0')
        .localeCompare([right.asset_id, right.version, right.manifest_sha256].join('\0')));
  }

  function selectedRefs(select, kind) {
    return sortRefs([...select.selectedOptions].map(option => JSON.parse(option.value)))
      .filter(reference => validReference(reference, kind));
  }

  function optional(form, name) {
    const value = form.elements[name].value.trim();
    return value || null;
  }

  function numberOrNull(form, name) {
    const value = form.elements[name].value.trim();
    return value === '' ? null : Number(value);
  }

  function refLabel(reference) {
    return `${human(reference.asset_id)} · version ${String(reference.version).replace(/^v/, '')}`;
  }

  function human(value) {
    return window.mvHuman ? window.mvHuman(value) : String(value || '').replace(/[_-]+/g, ' ');
  }

  function when(value) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(n) : new Date(n * 1000).toLocaleString()) : '';
  }

  function technical(item, rows) {
    const details = element('details', undefined, 'research-advanced');
    details.appendChild(element('summary', 'Technical details (for auditors)'));
    rows.filter(row => row[1] !== undefined && row[1] !== null && row[1] !== '').forEach(([label, value]) => details.appendChild(element('p', `${label}: ${value}`, 'muted')));
    item.appendChild(details);
  }

  const REASONS = [['no_longer_licensed', 'The license ended'], ['consent_withdrawn', 'Consent was withdrawn'],
    ['data_quality', 'The data is wrong or poor quality'], ['security_concern', 'A security concern'],
    ['operator_cancelled', 'No longer needed'], ['other', 'Another reason']];

  function reasonSelect() {
    const select = element('select'); select.className = 'input'; select.required = true;
    select.appendChild(new Option('Choose a reason', ''));
    REASONS.forEach(([value, label]) => select.appendChild(new Option(label, value)));
    return select;
  }

  // The supporting document is chosen as a file; the server records its fingerprint.
  function evidenceFile(labelText) {
    const label = element('label', labelText);
    const file = element('input'); file.type = 'file'; file.className = 'input'; file.required = true;
    const state = element('span', '', 'muted');
    const holder = {value: '', pending: null};
    file.addEventListener('change', () => {
      holder.value = '';
      const chosen = file.files && file.files[0];
      if (!chosen) return;
      state.textContent = `Reading ${chosen.name}…`;
      holder.pending = window.mvFetchJSON('/api/v1/research-files/fingerprint', {method:'POST',
        headers:{'Content-Type':'application/octet-stream'}, body:chosen}, 'read the file')
        .then(body => { holder.value = body.fingerprint; state.textContent = `Ready: ${chosen.name}`; })
        .catch(error => { state.textContent = window.mvErrorText ? window.mvErrorText(error, 'read the file') : 'Could not read the file. Choose the file again, or try a different file.'; });
    });
    label.append(file, state);
    return {label, holder};
  }

  function replaceOptions(select, assets, {multiple = true, blank = ''} = {}) {
    const selected = new Set([...select.selectedOptions].map(option => option.value));
    select.replaceChildren();
    if (!multiple) select.appendChild(new Option(blank, ''));
    assets.forEach(asset => {
      const value = JSON.stringify(asset.reference);
      const option = new Option(refLabel(asset.reference), value);
      option.selected = selected.has(value);
      select.appendChild(option);
    });
  }

  function decisionsAvailable() {
    return (workspace?.registry?.data_use_decisions?.items || []).length > 0;
  }

  function renderSelectors() {
    replaceOptions(byId('research-dataset-form').elements.parent_datasets, workspace.registry.datasets);
    replaceOptions(byId('research-model-form').elements.dataset_lineage, workspace.registry.datasets);
    replaceOptions(byId('research-model-form').elements.model_lineage, workspace.registry.models);
    renderRunSelectors();
    const decisionSelect = byId('research-dataset-form').elements.data_use_decision_choice;
    decisionSelect.replaceChildren(new Option(decisionsAvailable() ? 'Choose an approved use' : 'No approved uses yet', ''));
    const decisions = workspace.registry.data_use_decisions?.items || [];
    decisions.forEach(decision => {
      if (!identifier(decision.decision_id) || !sha(decision.decision_sha256) ||
          !identifier(decision.asset_id) || !['analyze', 'export', 'read', 'train'].includes(decision.action) ||
          !Array.isArray(decision.purpose_codes)) return;
      decisionSelect.appendChild(new Option(
        `${human(decision.asset_id)} · ${human(decision.action)} · for ${decision.purpose_codes.map(human).join(', ') || 'any purpose'}`,
        JSON.stringify(decision),
      ));
    });
  }

  function renderRunSelectors() {
    const form = byId('research-run-form');
    const purpose = form.elements.purpose.value.trim();
    const action = form.elements.action.value;
    const current = row => row.state === 'approved' && row.eligibility.state === 'eligible' &&
      (!purpose || row.allowed_purposes.includes(purpose));
    const datasets = workspace.registry.datasets.filter(row =>
      current(row) && row.data_use_action === action);
    const models = workspace.registry.models.filter(current);
    replaceOptions(form.elements.dataset_refs, datasets);
    if (form.elements.model_ref.tagName === 'SELECT') replaceOptions(form.elements.model_ref, models, {multiple:false, blank:'No model'});
  }

  function appendLineage(item, title, references) {
    if (!Array.isArray(references) || !references.length) return;
    item.appendChild(element('p', title, 'muted'));
    const list = element('ul', undefined, 'research-lineage');
    references.forEach(reference => list.appendChild(element('li', refLabel(reference))));
    item.appendChild(list);
  }

  function actionButton(label, work, className = 'btn') {
    const button = element('button', label, className);
    button.type = 'button';
    button.addEventListener('click', () => act(work));
    return button;
  }

  function assetActions(item, asset) {
    const actions = element('div', undefined, 'research-actions');
    actions.appendChild(actionButton('What depends on this?', async () => {
      const ref = asset.reference;
      const value = await api(`/registry/${encodeURIComponent(ref.kind)}/${encodeURIComponent(ref.asset_id)}/${encodeURIComponent(ref.version)}/impact?manifest_sha256=${encodeURIComponent(ref.manifest_sha256)}`);
      if (!validImpact(value)) throw new Error('The list of what depends on this could not be loaded. Try again.');
      renderImpact(value);
    }));
    if (workspace.registry.can_review && asset.state === 'draft') {
      actions.appendChild(actionButton('Approve', async () => {
        const ok = window.mvConfirm ? await window.mvConfirm('Approve this version for use in experiments?', {okText: 'Approve'}) : true;
        if (!ok) return;
        await api('/registry/approve', 'POST', {context, confirm:true,
          reference:asset.reference, expected_revision:asset.revision});
        message('Approved.');
        await refresh();
      }, 'btn btn--primary'));
    }
    item.appendChild(actions);
    if (workspace.registry.can_review && asset.state === 'approved') {
      const details = element('details', undefined, 'research-advanced');
      details.appendChild(element('summary', 'Stop using this version'));
      const form = element('form', undefined, 'research-form');
      const reasonLabel = element('label', 'Why');
      const reason = reasonSelect();
      reasonLabel.appendChild(reason);
      const evidence = evidenceFile('Supporting document');
      const confirmLabel = element('label', undefined, 'check');
      const confirm = element('input'); confirm.type = 'checkbox'; confirm.required = true;
      confirmLabel.append(confirm, document.createTextNode('I checked what depends on this version.'));
      const submit = element('button', 'Stop using this version', 'btn btn--danger'); submit.type = 'submit';
      form.append(reasonLabel, evidence.label, confirmLabel, submit);
      form.addEventListener('submit', event => {
        event.preventDefault();
        if (!form.reportValidity()) return;
        act(async () => {
          if (evidence.holder.pending) await evidence.holder.pending;
          if (!evidence.holder.value) throw new Error('Choose the supporting document again.');
          const ok = window.mvConfirm ? await window.mvConfirm('Stop using this version? Anything made from it is listed so it can be retired or rebuilt.', {okText: 'Stop using it'}) : true;
          if (!ok) return;
          const impact = await api(`/registry/${encodeURIComponent(asset.kind)}/${encodeURIComponent(asset.reference.asset_id)}/${encodeURIComponent(asset.reference.version)}/impact?manifest_sha256=${encodeURIComponent(asset.reference.manifest_sha256)}`);
          if (!validImpact(impact)) throw new Error('The list of what depends on this could not be loaded. Try again.');
          renderImpact(impact);
          await api('/registry/revoke', 'POST', {context, confirm:true, reference:asset.reference,
            expected_revision:asset.revision, reason_code:reason.value.trim(),
            evidence_sha256:evidence.holder.value});
          message('This version can no longer be used. Anything made from it is listed below.');
          await refresh();
        });
      });
      details.appendChild(form);
      item.appendChild(details);
    }
  }

  function renderAssets() {
    const list = byId('research-registry-items');
    list.replaceChildren();
    const assets = [...workspace.registry.datasets, ...workspace.registry.models];
    if (!assets.length) list.appendChild(element('li', 'No datasets or models yet. Add one above.'));
    const STATE = {draft: 'Waiting for approval', approved: 'Approved', revoked: 'No longer used'};
    const ELIGIBLE = {eligible: 'Ready to use', blocked: 'Blocked', unavailable: 'Not available', awaiting_approval: 'Waiting for approval', revoked: 'No longer used'};
    assets.forEach(asset => {
      const item = element('li', undefined, 'research-item');
      item.appendChild(element('strong', `${asset.kind === 'dataset' ? 'Dataset' : 'Model'}: ${refLabel(asset.reference)}`));
      const badge = element('span', STATE[asset.state] || human(asset.state), 'research-badge'); badge.dataset.state = asset.state;
      item.append(' ', badge);
      if (asset.provenance_kind === 'synthetic') item.append(' ', element('span', 'Generated test data', 'research-badge'));
      item.appendChild(element('p', `From: ${asset.source_ref}`));
      item.appendChild(element('p', `License: ${human(asset.license_id)} · May be used for: ${asset.allowed_purposes.map(human).join(', ')}`));
      item.appendChild(element('p', `Rules: ${asset.usage_constraints.map(human).join('; ')}`));
      item.appendChild(element('p', `Can it be used now: ${ELIGIBLE[asset.eligibility.state] || human(asset.eligibility.state)}${asset.eligibility.detail ? ` · ${asset.eligibility.detail}` : ''}`));
      const rows = [['Record fingerprint', asset.reference.manifest_sha256]];
      if (asset.kind === 'dataset') {
        item.appendChild(element('p', `Allowed action: ${human(asset.data_use_action)}`));
        appendLineage(item, 'Made from', asset.parent_datasets);
        if (asset.synthetic_provenance) {
          item.appendChild(element('p', `Generated by: ${human(asset.synthetic_provenance.generator_id)} version ${asset.synthetic_provenance.generator_version}`));
        }
        rows.push(['Data file fingerprint', asset.content_sha256], ['Data-use record', asset.data_use_decision_id],
          ['Consent record', asset.consent_record_id], ['Generator starting number', asset.synthetic_provenance?.seed]);
      } else {
        const exact = asset.immutable_provider_revision ? `version ${asset.immutable_provider_revision}` :
          `no exact version; used ${when(asset.observed_from)} to ${when(asset.observed_until)}`;
        item.appendChild(element('p', `AI model: ${asset.provider_model_identity} · ${exact}`));
        if (asset.reproducibility_limitation) item.appendChild(element('p', `Results may differ because: ${asset.reproducibility_limitation}`));
        appendLineage(item, 'Built from datasets', asset.dataset_lineage);
        appendLineage(item, 'Built from models', asset.model_lineage);
        rows.push(['Model file fingerprint', asset.artifact_sha256]);
      }
      if (asset.approval) item.appendChild(element('p', `Approved by ${String(asset.approval.approved_by || '').replace(/^user:/, '')}`, 'muted'));
      if (asset.revocation) item.appendChild(element('p', `No longer used: ${human(asset.revocation.reason_code)}`, 'error'));
      technical(item, rows);
      assetActions(item, asset);
      list.appendChild(item);
    });
  }

  function renderImpact(value) {
    const host = byId('research-impact');
    host.replaceChildren();
    host.appendChild(element('h4', 'What depends on it'));
    host.appendChild(element('p', `${value.derivatives.length} version${value.derivatives.length === 1 ? '' : 's'} made from it.`));
    const ACTION = {invalidate_dataset: 'stop using this dataset', retire_or_retrain_model: 'retire or retrain this model'};
    const list = element('ul', undefined, 'research-lineage');
    value.derivatives.forEach(row => list.appendChild(element('li',
      `${row.reference.kind === 'model' ? 'Model' : 'Dataset'} ${refLabel(row.reference)}: ${ACTION[row.required_action] || human(row.required_action)}`)));
    host.appendChild(list);
    host.appendChild(element('p', 'Deleting the original data does not remove what a model already learned from it. Models made from it must be retired, reviewed or retrained.', 'muted'));
  }

  function money(summary) {
    const values = Object.entries(summary.effective_amounts || {});
    const known = values.length ? values.map(([currency, amount]) => `${currency} ${amount}`).join(', ') : 'no financial amount recorded';
    return `${known}${summary.incomplete ? ' · some resource use has no verified financial price' : values.length ? ' · reported costs recorded' : ''}`;
  }

  function renderAttempt(run, attempt, item) {
    const details = element('details', undefined, 'research-costs');
    details.appendChild(element('summary', `Attempt ${attempt.number} · ${human(attempt.status)} · ${attempt.costs.length} cost${attempt.costs.length === 1 ? '' : 's'}`));
    if (!attempt.costs.length) details.appendChild(element('p', 'No costs recorded for this attempt.', 'muted'));
    attempt.costs.forEach(event => {
      const cost = event.cost;
      const known = cost.amount === null ? `not known yet (${human(cost.incomplete_reason)})` : `${cost.currency} ${cost.amount}`;
      details.appendChild(element('p', `${human(cost.category)} · ${human(cost.basis)} · ${known}`));
    });
    if (attempt.metrics.length) {
      details.appendChild(element('p', 'Results', 'muted'));
      const list = element('ul', undefined, 'research-lineage');
      attempt.metrics.forEach(metric => list.appendChild(element('li', `${human(metric.name)}: ${metric.value}`)));
      details.appendChild(list);
    }
    item.appendChild(details);
  }

  function runAction(item, run, label, suffix, allowed, className = 'btn') {
    if (!allowed) return;
    const button = actionButton(label, async () => {
      await api(`/governed-runs/${encodeURIComponent(run.run_id)}/${suffix}`, 'POST',
        {context, confirm:true, expected_revision:run.revision});
      message(`${label}: done.`);
      await refresh();
    }, className);
    if (suffix === 'start' && !workspace.governed_execution.available) {
      button.disabled = true;
      button.dataset.permanentDisabled = 'true';
      button.title = workspace.governed_execution.detail;
    }
    item.appendChild(button);
  }

  function cancellationForm(run) {
    const details = element('details', undefined, 'research-advanced');
    details.appendChild(element('summary', 'Cancel before it starts'));
    const form = element('form', undefined, 'research-form');
    const reasonLabel = element('label', 'Why');
    const reason = reasonSelect();
    reasonLabel.appendChild(reason);
    const evidence = evidenceFile('Supporting document (for example the request to cancel)');
    const confirmLabel = element('label', undefined, 'check');
    const confirm = element('input'); confirm.type = 'checkbox'; confirm.required = true;
    confirmLabel.append(confirm, document.createTextNode('Cancel this run before it starts.'));
    const submit = element('button', 'Cancel run', 'btn btn--danger'); submit.type = 'submit';
    form.append(reasonLabel, evidence.label, confirmLabel, submit);
    form.addEventListener('submit', event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      act(async () => {
        if (evidence.holder.pending) await evidence.holder.pending;
        if (!evidence.holder.value) throw new Error('Choose the supporting document again.');
        const ok = window.mvConfirm ? await window.mvConfirm('Cancel this run?', {okText: 'Cancel run'}) : true;
        if (!ok) return;
        await api(`/governed-runs/${encodeURIComponent(run.run_id)}/cancel`, 'POST', {context,
          confirm:true, expected_revision:run.revision, reason_code:reason.value.trim(),
          evidence_sha256:evidence.holder.value});
        message('Run cancelled before it started.');
        await refresh();
      });
    });
    details.appendChild(form);
    return details;
  }

  function renderRuns() {
    const list = byId('research-governed-runs');
    list.replaceChildren();
    if (!workspace.governed_runs.length) list.appendChild(element('li', 'No runs yet. Queue one above.'));
    workspace.governed_runs.forEach(run => {
      const item = element('li', undefined, 'research-item');
      item.appendChild(element('strong', `${human(run.manifest.experiment_id)} (${human(run.manifest.action)} for ${human(run.manifest.purpose).toLowerCase()})`));
      const badge = element('span', human(run.status), 'research-badge');
      badge.dataset.state = run.status; item.append(' ', badge);
      const caps = run.manifest.resource_caps;
      const minutes = Math.round(Number(caps.max_wall_seconds) / 60);
      const mb = Math.round(Number(caps.max_storage_bytes) / 1048576);
      item.appendChild(element('p', `Limits: ${minutes >= 1 ? minutes + ' minutes' : caps.max_wall_seconds + ' seconds'} · ${caps.max_provider_calls} AI calls · ${caps.currency} ${caps.max_cost} · ${mb} MB storage`));
      item.appendChild(element('p', `Cost so far: ${money(run.cost_summary)}`));
      technical(item, [['Run', run.run_id], ['Code version', run.manifest.code_revision],
        ['Setup', `${run.manifest.environment_id} ${run.manifest.environment_version}`], ['Starting number', run.manifest.seed]]);
      run.attempts.forEach(attempt => renderAttempt(run, attempt, item));
      const actions = element('div', undefined, 'research-actions');
      runAction(actions, run, 'Queue run', 'queue', run.can_manage && run.status === 'planned', 'btn btn--primary');
      executionActions(actions, run);
      runAction(actions, run, 'Try again', 'retry', run.can_manage && run.status === 'failed');
      const latest = run.attempts.at(-1);
      if (latest?.execution) {
        const facts = latest.execution;
        item.appendChild(element('p', facts.state === 'container_prepared' ? 'Local container prepared; execution outcome is not yet confirmed.' : facts.state === 'cleanup_verified' ? 'Container cleanup verified. The execution outcome is not confirmed; this run is not automatically repeated.' : `Actual container run: ${human(facts.reason)}. Cleanup ${facts.cleanup_verified ? 'verified' : 'not confirmed'}.`));
        if (facts.inspect_policy?.elapsed_seconds !== undefined) item.appendChild(element('p', `Observed local compute time: ${facts.inspect_policy.elapsed_seconds} seconds. Financial price is not independently metered.`));
      }
      if (latest?.stop_requested) item.appendChild(element('p', latest.execution?.cleanup_verified ?
        'Stop honored. Container cleanup verified.' : 'Stop requested. Waiting for the execution owner to confirm cleanup.'));
      if (run.status !== 'planned') actions.appendChild(actionButton('Download run record',
        () => downloadRun(run.run_id)));
      item.appendChild(actions);
      if (run.can_manage && ['planned', 'queued'].includes(run.status)) item.appendChild(cancellationForm(run));
      list.appendChild(item);
    });
  }

  function retainOriginal(runId) {
    heldRun = runId;
    sessionStorage.setItem(`research-original:${context}`, runId);
    updateOriginal();
  }
  function updateOriginal() {
    byId('research-read-original').hidden = !heldRun;
  }
  async function readOriginal() {
    if (!heldRun) return;
    const result = await api(`/governed-runs/${encodeURIComponent(heldRun)}/original`);
    if (!validRun(result.run)) throw new Error('The original run could not be verified. Nothing was restarted.');
    byId('research-original-status').textContent = `Original run: ${human(result.run.status)}. This read starts nothing and repeats no program.`;
    await refresh();
  }
  async function loadPrograms() {
    const result = await api('/execution-options');
    const select = byId('research-program-choice');
    const selected = select.value;
    programs = result.programs || [];
    select.replaceChildren(new Option(result.available ? 'Choose your saved program' : 'Complete Administrator setup first', ''));
    programs.forEach(program => select.appendChild(new Option(program.label, program.id)));
    if (programs.some(program => program.id === selected)) select.value = selected;
    byId('research-program-notice').textContent = result.detail;
    syncProgram();
  }
  function syncProgram() {
    const form = byId('research-run-form');
    const program = programs.find(value => value.id === form.elements.program_id.value);
    ['experiment_id','experiment_version','code_revision','code_sha256','environment_id','environment_version','environment_sha256','metric_protocol_sha256'].forEach(key => {
      form.elements[key].value = program?.[key] || '';
    });
  }
  async function reviewExecution(run) {
    const value = await api(`/governed-runs/${encodeURIComponent(run.run_id)}/execution-review`);
    if (!sha(value.review_sha256) || !Array.isArray(value.files) || !value.summary) throw new Error('The complete review could not be loaded.');
    const dialog = element('dialog', undefined, 'research-execution-review');
    dialog.setAttribute('aria-label', 'Complete run review');
    dialog.appendChild(element('h3', 'Complete run review'));
    const summary = value.summary;
    dialog.appendChild(element('p', `${summary.program} · ${summary.environment} · ${human(summary.purpose)}`));
    dialog.appendChild(element('p', `Correct-output check: ${summary.check}. Input size: ${summary.input_bytes} bytes.`));
    summary.datasets.forEach(dataset => dialog.appendChild(element('p', `Dataset: ${human(dataset.name)} · version ${dataset.version}`)));
    dialog.appendChild(element('p', `Limits: ${summary.caps.max_wall_seconds} seconds; ${Math.ceil(summary.caps.max_storage_bytes/1048576)} MB. ${summary.limits}`));
    dialog.appendChild(element('p', summary.data_format));
    value.files.forEach(file => { dialog.appendChild(element('h4', file.path)); dialog.appendChild(element('pre', file.text, 'research-source')); });
    const label = element('label', undefined, 'check');
    const check = element('input'); check.type = 'checkbox';
    label.append(check, document.createTextNode('I read every file and checked these exact datasets, limits and result check.'));
    const approve = element('button', 'Approve this run', 'btn btn--primary'); approve.type = 'button'; approve.disabled = true;
    const close = element('button', 'Close', 'btn btn--ghost'); close.type = 'button';
    const result = element('p', '', 'muted'); result.setAttribute('role', 'status');
    check.addEventListener('change', () => { approve.disabled = !check.checked || !value.can_approve; });
    if (!value.can_approve) result.textContent = 'A different administrator must approve this run. Reading the review starts nothing.';
    approve.addEventListener('click', async () => {
      approve.disabled = true;
      try {
        retainOriginal(run.run_id);
        await api(`/governed-runs/${encodeURIComponent(run.run_id)}/approve-execution`, 'POST', {context,confirm:true,expected_revision:value.revision,review_sha256:value.review_sha256});
        dialog.close(); message('Approved. Choose Start run separately to begin actual execution.'); await refresh();
      } catch (error) { result.textContent = `${error.message} Read the original run before repeating an uncertain request.`; }
    });
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => dialog.remove());
    dialog.append(label, approve, close, result); root.appendChild(dialog); dialog.showModal(); close.focus();
  }
  function executionActions(actions, run) {
    const attempt = run.attempts.at(-1);
    if (run.status === 'queued') {
      if (workspace.registry.can_review) actions.appendChild(actionButton('Read complete run review', () => reviewExecution(run)));
      if (run.can_start && attempt?.execution_approval && Number(attempt.execution_approval.expires_at)*1000 > Date.now()) {
        actions.appendChild(actionButton('Start run', async () => {
          if (executing) return;
          const ok = await window.mvConfirm('Start the exact independently approved program and datasets in the installed local container?', {okText:'Start run'});
          if (!ok) return;
          retainOriginal(run.run_id); executing = true;
          const timer = setInterval(() => { refresh().catch(error => message(error.message, true)); }, 1000);
          try {
            await api(`/governed-runs/${encodeURIComponent(run.run_id)}/start`, 'POST', {context,confirm:true,expected_revision:run.revision});
            await readOriginal(); message('Actual execution result and cleanup are retained in the original run.');
          } catch (error) { message(`${error.message} Read original run; an uncertain run is never started again automatically.`, true); }
          finally { executing = false; clearInterval(timer); }
        }, 'btn btn--primary'));
      }
    }
    if (run.can_stop && !attempt?.stop_requested) {
      const stop = element('button', 'Stop run', 'btn btn--danger'); stop.type = 'button'; stop.dataset.liveExecutionControl = 'true';
      stop.addEventListener('click', async () => {
        stop.disabled = true;
        try {
          const current = await api(`/governed-runs/${encodeURIComponent(run.run_id)}`);
          const latest = current.attempts?.at(-1);
          if (!validRun(current) || current.run_id !== run.run_id || current.manifest_sha256 !== run.manifest_sha256 ||
              current.status !== 'running' || latest?.number !== attempt.number || latest?.execution_owner !== attempt.execution_owner) {
            throw new Error('This run changed. Refresh its current status before choosing Stop.');
          }
          await api(`/governed-runs/${encodeURIComponent(run.run_id)}/stop`, 'POST', {context,confirm:true,expected_revision:current.revision});
          await refresh();
        }
        catch (error) { message(error.message, true); stop.disabled = false; }
      }); actions.appendChild(stop);
    }
    const original = element('button', 'Read original', 'btn btn--ghost'); original.type = 'button'; original.dataset.liveExecutionControl = 'true';
    original.addEventListener('click', () => { retainOriginal(run.run_id); readOriginal().catch(error => message(error.message, true)); }); actions.appendChild(original);
  }
  byId('research-program-choice').addEventListener('change', syncProgram);
  byId('research-read-original').dataset.liveExecutionControl = 'true';
  byId('research-read-original').addEventListener('click', () => readOriginal().catch(error => message(error.message, true)));
  byId('research-governed-refresh').dataset.liveExecutionControl = 'true';
  window.LightworkResearchExecution = {openReview: async (_descriptor, options = {}) => {
    const current = () => typeof options.isCurrent === 'function' && options.isCurrent() && location.pathname === '/research';
    if (!current() || Object.keys(_descriptor || {}).length) return false;
    const value = await api('/execution-options');
    if (!current() || !value.available || options.context !== value.context || value.context !== context) return false;
    const form = byId('research-run-form'); form.closest('details').open = true;
    form.scrollIntoView({block:'center'}); byId('research-program-choice').focus(); return true;
  }};

  async function downloadRun(runId) {
    let response;
    try {
      response = await window.mvFetchJSON(`/api/v1/research/governed-runs/${encodeURIComponent(runId)}/export`,
        {cache:'no-store', raw:true}, 'download the run record');
    } catch (error) {
      if (error.status) throw new Error('The run record is not available right now. Try again in a minute.');
      throw error;
    }
    const bytes = await boundedBytes(response, 2200000);
    let evidence;
    try { evidence = JSON.parse(new TextDecoder().decode(bytes)); }
    catch (_) { throw new Error('The run record could not be read. Try again.'); }
    if (!evidence || evidence.schema !== 'lightwork.research-run-export.v1' ||
        evidence.run?.run_id !== runId || !evidence.cost_summary ||
        evidence.data_statement?.contains_raw_customer_data !== false ||
        evidence.projection_statement?.contains_authority_credentials !== false ||
        evidence.projection_statement?.contains_resource_cost_source_locations !== false) {
      throw new Error('The run record did not match this run. Try again.');
    }
    const blob = new Blob([bytes], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const link = element('a'); link.href = url; link.download = `research-run-${runId}.json`;
    document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
    message('Run record downloaded.');
  }

  async function boundedBytes(response, maximum) {
    const declared = Number(response.headers?.get?.('content-length'));
    if (Number.isFinite(declared) && declared > maximum) {
      throw new Error('The run record is too large to download here.');
    }
    if (!response.body?.getReader) {
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > maximum) throw new Error('The run record is too large to download here.');
      return bytes;
    }
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        throw new Error('The run record is too large to download here.');
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    chunks.forEach(chunk => { bytes.set(chunk, offset); offset += chunk.byteLength; });
    return bytes;
  }

  function render(value) {
    workspace = validate(value);
    renderSelectors();
    renderAssets();
    renderRuns();
    const execution = workspace.governed_execution;
    byId('research-materialization-state').textContent = execution.available ?
      'The installed local executor is available. Each queued run needs a different administrator’s complete review and separate Start.' :
      'Runs can be planned and queued, but cannot start yet: starting is blocked before data access until an administrator connects where the data lives.';
    byId('research-registry-authority-state').textContent =
      (decisionsAvailable() ? 'Approved data uses: available. ' : 'Approved data uses: none yet. ') +
      (workspace.registry.consent_authority_available ?
        'Consent checks: ready.' :
        'Consent checks: not set up, so datasets that need consent cannot be approved yet.');
    message(`${workspace.registry.datasets.length} dataset${workspace.registry.datasets.length === 1 ? '' : 's'}, ${workspace.registry.models.length} model${workspace.registry.models.length === 1 ? '' : 's'} and ${workspace.governed_runs.length} run${workspace.governed_runs.length === 1 ? '' : 's'}.`);
    syncConditionalFields();
  }

  async function refresh() {
    render(await api(''));
    await loadPrograms();
    updateOriginal();
  }

  async function act(work) {
    if (busy) return;
    setBusy(true);
    try { await work(); }
    catch (error) { message(error.message || 'Something went wrong. Try again.', true); }
    finally { setBusy(false); }
  }

  function syncConditionalFields() {
    const dataset = byId('research-dataset-form');
    const synthetic = dataset.elements.provenance_kind.value === 'synthetic';
    byId('research-synthetic-fields').hidden = !synthetic;
    ['synthetic_generator_id', 'synthetic_generator_version', 'synthetic_generator_sha256',
      'synthetic_config_sha256', 'synthetic_seed'].forEach(name => {
      dataset.elements[name].required = synthetic;
    });
    dataset.elements.parent_datasets.required = dataset.elements.provenance_kind.value === 'derived';
    const consentBound = dataset.elements.consent_record_id.value.trim() !== '' ||
      dataset.elements.consent_evidence_sha256.value.trim() !== '';
    dataset.elements.consent_record_id.required = consentBound;
    dataset.elements.consent_evidence_sha256.required = consentBound;

    const model = byId('research-model-form');
    const trained = model.elements.provenance_kind.value === 'trained';
    byId('research-training-receipt-fields').hidden = !trained;
    ['training_receipt_id', 'training_receipt_sha256', 'training_dataset_sha256'].forEach(name => {
      model.elements[name].required = trained;
    });
    model.elements.dataset_lineage.required = trained;
    model.elements.model_lineage.required = trained;
    model.elements.dataset_lineage_purpose.required = trained ||
      model.elements.dataset_lineage.selectedOptions.length > 0;
    const pinned = model.elements.immutable_provider_revision.value.trim() !== '';
    model.elements.observed_from.required = !pinned;
    model.elements.observed_until.required = !pinned;
    model.elements.reproducibility_limitation.required = !pinned;
  }

  byId('research-governed-refresh').addEventListener('click', () => {
    if (executing) refresh().catch(error => message(error.message, true));
    else act(refresh);
  });
  byId('research-dataset-form').elements.data_use_decision_choice.addEventListener('change', event => {
    if (!event.currentTarget.value) return;
    const decision = JSON.parse(event.currentTarget.value);
    const form = byId('research-dataset-form');
    form.elements.data_use_decision_id.value = decision.decision_id;
    form.elements.data_use_decision_sha256.value = decision.decision_sha256;
    form.elements.data_use_action.value = decision.action;
    if (!form.elements.dataset_id.value) form.elements.dataset_id.value = decision.asset_id;
    if (!form.elements.allowed_purposes.value) {
      form.elements.allowed_purposes.value = decision.purpose_codes.join(', ');
    }
  });
  byId('research-dataset-form').elements.provenance_kind.addEventListener('change', syncConditionalFields);
  byId('research-dataset-form').elements.consent_record_id.addEventListener('input', syncConditionalFields);
  byId('research-dataset-form').elements.consent_evidence_sha256.addEventListener('input', syncConditionalFields);
  byId('research-model-form').elements.provenance_kind.addEventListener('change', syncConditionalFields);
  byId('research-model-form').elements.dataset_lineage.addEventListener('change', syncConditionalFields);
  byId('research-model-form').elements.immutable_provider_revision.addEventListener('input', syncConditionalFields);
  byId('research-run-form').elements.purpose.addEventListener('input', renderRunSelectors);
  byId('research-run-form').elements.action.addEventListener('change', renderRunSelectors);

  byId('research-dataset-form').addEventListener('submit', event => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const provenance = form.elements.provenance_kind.value;
    const payload = {context, confirm:true, dataset_id:form.elements.dataset_id.value.trim(),
      version:form.elements.version.value.trim(), source_ref:form.elements.source_ref.value.trim(),
      content_sha256:optional(form, 'content_sha256'), license_id:form.elements.license_id.value.trim(),
      license_evidence_sha256:form.elements.license_evidence_sha256.value.trim(),
      allowed_purposes:commaValues(form.elements.allowed_purposes.value),
      usage_constraints:lineValues(form.elements.usage_constraints.value),
      data_use_action:form.elements.data_use_action.value,
      data_use_decision_id:form.elements.data_use_decision_id.value.trim(),
      data_use_decision_sha256:form.elements.data_use_decision_sha256.value.trim(),
      consent_record_id:optional(form, 'consent_record_id'),
      consent_evidence_sha256:optional(form, 'consent_evidence_sha256'),
      parent_datasets:selectedRefs(form.elements.parent_datasets, 'dataset'),
      provenance_kind:provenance,
      synthetic_generator_id:syntheticValue(form, provenance, 'synthetic_generator_id'),
      synthetic_generator_version:syntheticValue(form, provenance, 'synthetic_generator_version'),
      synthetic_generator_sha256:syntheticValue(form, provenance, 'synthetic_generator_sha256'),
      synthetic_config_sha256:syntheticValue(form, provenance, 'synthetic_config_sha256'),
      synthetic_seed:provenance === 'synthetic' ? Number(form.elements.synthetic_seed.value) : null};
    act(async () => {
      await api('/registry/datasets', 'POST', payload);
      form.reset(); syncConditionalFields();
      message('Dataset added. It is waiting for approval.');
      await refresh();
    });
  });

  function syntheticValue(form, provenance, name) {
    return provenance === 'synthetic' ? form.elements[name].value.trim() : null;
  }

  byId('research-model-form').addEventListener('submit', event => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const trained = form.elements.provenance_kind.value === 'trained';
    const revision = optional(form, 'immutable_provider_revision');
    const payload = {context, confirm:true, model_id:form.elements.model_id.value.trim(),
      version:form.elements.version.value.trim(), source_ref:form.elements.source_ref.value.trim(),
      artifact_sha256:form.elements.artifact_sha256.value.trim(), license_id:form.elements.license_id.value.trim(),
      license_evidence_sha256:form.elements.license_evidence_sha256.value.trim(),
      allowed_purposes:commaValues(form.elements.allowed_purposes.value),
      usage_constraints:lineValues(form.elements.usage_constraints.value),
      provider_model_identity:form.elements.provider_model_identity.value.trim(),
      immutable_provider_revision:revision,
      observed_from:revision ? null : numberOrNull(form, 'observed_from'),
      observed_until:revision ? null : numberOrNull(form, 'observed_until'),
      reproducibility_limitation:revision ? null : optional(form, 'reproducibility_limitation'),
      dataset_lineage:selectedRefs(form.elements.dataset_lineage, 'dataset'),
      dataset_lineage_purpose:optional(form, 'dataset_lineage_purpose'),
      model_lineage:selectedRefs(form.elements.model_lineage, 'model'),
      provenance_kind:form.elements.provenance_kind.value,
      training_receipt_id:trained ? optional(form, 'training_receipt_id') : null,
      training_receipt_sha256:trained ? optional(form, 'training_receipt_sha256') : null,
      training_dataset_sha256:trained ? optional(form, 'training_dataset_sha256') : null};
    act(async () => {
      await api('/registry/models', 'POST', payload);
      form.reset(); syncConditionalFields();
      message('Model added. It is waiting for approval.');
      await refresh();
    });
  });

  byId('research-run-form').addEventListener('submit', event => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const modelValue = form.elements.model_ref.value;
    const payload = {context, confirm:true, run_id:form.elements.run_id.value.trim(),
      run_version:form.elements.run_version.value.trim(), experiment_id:form.elements.experiment_id.value.trim(),
      experiment_version:form.elements.experiment_version.value.trim(), purpose:form.elements.purpose.value.trim(),
      program_id:form.elements.program_id.value, action:form.elements.action.value, code_revision:form.elements.code_revision.value.trim(),
      code_sha256:form.elements.code_sha256.value.trim(), environment_id:form.elements.environment_id.value.trim(),
      environment_version:form.elements.environment_version.value.trim(),
      environment_sha256:form.elements.environment_sha256.value.trim(), seed:Number(form.elements.seed.value),
      dataset_refs:selectedRefs(form.elements.dataset_refs, 'dataset'),
      model_ref:modelValue ? JSON.parse(modelValue) : null,
      resource_caps:{max_wall_seconds:Number(form.elements.max_wall_seconds.value),
        max_provider_calls:Number(form.elements.max_provider_calls.value),
        max_storage_bytes:Number(form.elements.max_storage_bytes.value), max_cost:form.elements.max_cost.value.trim(),
        currency:form.elements.currency.value.trim()},
      metric_protocol_sha256:form.elements.metric_protocol_sha256.value.trim()};
    act(async () => {
      retainOriginal(payload.run_id);
      const planned = await api('/governed-runs', 'POST', payload);
      await api(`/governed-runs/${encodeURIComponent(planned.run_id)}/queue`, 'POST',
        {context, confirm:true, expected_revision:planned.revision});
      form.reset(); form.elements.run_version.value = 'v1'; form.elements.experiment_version.value = 'v1';
      form.elements.max_wall_seconds.value = '300'; form.elements.max_provider_calls.value = '0';
      form.elements.max_storage_bytes.value = '104857600'; form.elements.max_cost.value = '0';
      form.elements.currency.value = 'USD';
      message('Run queued for independent review. No program has started.');
      await refresh();
    });
  });

  if (!byId('research-run-form').elements.run_id.value) {
    byId('research-run-form').elements.run_id.value = `run-${crypto.randomUUID()}`;
  }
  syncConditionalFields();
  // A failed first load leaves nothing to show: say so in each list instead of
  // "Loading…" (the reason is also shown in the status line above them).
  async function firstLoad() {
    try {
      await refresh();
    } catch (error) {
      const why = action => (typeof window.mvErrorText === 'function' ? window.mvErrorText(error, action)
        : `Could not ${action}. Refresh the page to try again.`);
      byId('research-registry-items').replaceChildren(element('li', why('load datasets and models')));
      byId('research-governed-runs').replaceChildren(element('li', why('load runs')));
      throw error;
    }
  }
  act(firstLoad);
})();
