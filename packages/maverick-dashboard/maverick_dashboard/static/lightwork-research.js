(() => {
  'use strict';
  const root = document.getElementById('research-lab');
  if (!root) return;
  const byId = id => document.getElementById(id);
  const context = root.dataset.context || '';
  const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const identifiers = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value);
  let model = null;
  let selectedFiles = {};
  let fileSelectionGeneration = 0;
  let selectedReview = null;
  let busy = false;
  let settingsDirty = false;

  function element(tag, text, className) {
    const item = document.createElement(tag);
    if (text !== undefined) item.textContent = text;
    if (className) item.className = className;
    return item;
  }

  function human(value) {
    return window.mvHuman ? window.mvHuman(value) : String(value || '').replace(/_/g, ' ');
  }

  function person(value) {
    return String(value || '').replace(/^user:/, '');
  }

  function message(text, error) {
    byId('research-status').textContent = text;
    byId('research-status').classList.toggle('error', !!error);
  }

  function formValid(form) {
    return typeof form.checkValidity !== 'function' || form.checkValidity();
  }

  function validJob(row) {
    return row && identifiers(row.id) && Number.isSafeInteger(row.revision) && row.revision > 0 &&
      typeof row.status === 'string' && sha(row.input_sha256) && identifiers(row.evaluator_id);
  }

  function syncSettingsFields() {
    const form = byId('research-settings-form');
    const available = !!model?.settings && model.settings.writable === true &&
      sha(model.settings.settings_sha256);
    const enabled = available && form.elements.enable.checked;
    [...form.elements].forEach(control => {
      if (control.name !== 'enable' && control.name !== 'confirm') control.disabled = busy || !enabled;
    });
    form.elements.enable.disabled = busy || !available;
    form.elements.confirm.disabled = busy || !available;
    byId('research-add-evaluator').disabled = busy || !enabled;
    form.querySelectorAll('.research-evaluator button').forEach(button => {
      button.disabled = busy || !enabled;
    });
  }

  function syncControls() {
    const settingsForm = byId('research-settings-form');
    const submitForm = byId('research-submit');
    const settingsAvailable = !!model?.settings && model.settings.writable === true &&
      sha(model.settings.settings_sha256);
    const settingsEnabled = settingsAvailable && settingsForm.elements.enable.checked;
    syncSettingsFields();
    byId('research-refresh').disabled = busy;
    [...submitForm.elements].forEach(control => {
      control.disabled = busy || !model?.execution_available;
    });
    byId('research-settings-save').disabled = busy || !settingsAvailable ||
      !settingsForm.elements.confirm.checked || (settingsEnabled && !formValid(settingsForm));
    byId('research-submit-button').disabled = busy || !model?.execution_available ||
      !Object.keys(selectedFiles).length || !submitForm.elements.confirm.checked || !formValid(submitForm);
    byId('research-review-choice').disabled = busy;
    byId('research-open-review').disabled = busy || !byId('research-review-choice').value;
    const exactReview = selectedReview && validJob(selectedReview) && sha(selectedReview.review_sha256);
    byId('research-dispatch-confirm').disabled = busy || !exactReview;
    byId('research-dispatch').disabled = busy || !model?.can_dispatch || !model?.execution_available ||
      !exactReview || selectedReview.status !== 'queued' || !byId('research-dispatch-confirm').checked;
    byId('research-admin-cancel').disabled = busy || !exactReview ||
      !['queued', 'running'].includes(selectedReview.status);
    root.querySelectorAll('[data-research-job-cancel]').forEach(button => {
      button.disabled = busy;
    });
  }

  function setBusy(value) {
    busy = value;
    root.setAttribute('aria-busy', String(value));
    syncControls();
  }

  async function api(path, method, body) {
    const value = await window.mvFetchJSON('/api/v1/research' + path, {method: method || 'GET', cache: 'no-store', body, messages: {
      409: 'This research record changed. Refresh and review it again.',
      403: 'Your current account cannot perform that research action.',
      422: 'Some details need fixing. Check the highlighted fields and try again.'}});
    if (value && value.context && value.context !== context) {
      throw new Error('You switched account or workspace. Reload this page.');
    }
    return value;
  }

  function validate(data) {
    if (!data || data.context !== context || !Array.isArray(data.jobs) || data.jobs.some(row => !validJob(row)) ||
        !Array.isArray(data.review_queue) || data.review_queue.some(row => !validJob(row)) ||
        typeof data.can_dispatch !== 'boolean' || typeof data.execution_available !== 'boolean' ||
        !Array.isArray(data.evaluators) || data.evaluators.some(row => !identifiers(row.id) || !identifiers(row.version)) ||
        (data.settings !== null && (!data.settings || typeof data.settings.enabled !== 'boolean' ||
          typeof data.settings.valid !== 'boolean' || typeof data.settings.writable !== 'boolean' ||
          typeof data.settings.source !== 'string' || typeof data.settings.settings_sha256 !== 'string'))) {
      throw new Error('The research lab could not be loaded correctly. Refresh the page.');
    }
    return data;
  }

  function addEvaluator(value) {
    const row = element('div', undefined, 'research-evaluator');
    for (const [field, label, placeholder] of [
      ['id', 'Check name', 'For example: smoke'], ['version', 'Version', 'v1']]) {
      const wrapper = element('label', label);
      const input = element('input');
      input.className = 'input';
      input.dataset.field = field;
      input.required = true;
      input.maxLength = 64;
      input.pattern = '[A-Za-z0-9][A-Za-z0-9_-]{0,63}';
      input.title = 'Letters, numbers, dashes and underscores';
      input.placeholder = placeholder;
      input.value = value?.[field] || (field === 'version' ? 'v1' : '');
      wrapper.appendChild(input);
      row.appendChild(wrapper);
    }
    // The correct output is chosen as a file; the server records its
    // fingerprint (the page never asks anyone to type one).
    const expected = element('input');
    expected.type = 'hidden';
    expected.dataset.field = 'stdout_sha256';
    expected.value = value?.stdout_sha256 || '';
    const fileLabel = element('label', 'Correct output file');
    const file = element('input');
    file.type = 'file';
    file.className = 'input';
    file.required = !expected.value;
    const state = element('span', expected.value ? 'Saved' : 'Choose the file with the correct output', 'muted');
    file.addEventListener('change', async () => {
      const chosen = file.files && file.files[0];
      if (!chosen) return;
      state.textContent = `Reading ${chosen.name}…`;
      try {
        expected.value = (await window.mvFetchJSON('/api/v1/research-files/fingerprint', {method:'POST',
          headers:{'Content-Type':'application/octet-stream'}, body:chosen}, 'read the file')).fingerprint;
        state.textContent = `Ready: ${chosen.name}`;
        settingsDirty = true;
        syncControls();
      } catch (error) {
        state.textContent = window.mvErrorText ? window.mvErrorText(error, 'read the file') : 'Could not read the file. Choose the file again, or try a different file.';
      }
    });
    fileLabel.append(file, state);
    row.append(fileLabel, expected);
    const remove = element('button', 'Remove', 'btn');
    remove.type = 'button';
    remove.addEventListener('click', () => {
      row.remove();
      settingsDirty = true;
      syncControls();
    });
    row.appendChild(remove);
    byId('research-evaluators').appendChild(row);
  }

  function renderSettings(settings) {
    const panel = byId('research-settings');
    panel.hidden = !settings;
    if (!settings) return;
    const available = settings.writable === true && sha(settings.settings_sha256);
    byId('research-settings-readiness').textContent = settings.source === 'operator_overlay' ?
      'This setup is managed by your IT team and cannot be changed here. Ask your IT team to change it.' : available ?
      (settings.valid ? 'The saved setup is complete.' :
        'The saved setup is incomplete. Fill in every field, or turn experiments off.') :
      'The setup cannot be saved right now. Ask your IT team to check the installation settings.';
    if (settingsDirty) {
      syncControls();
      return;
    }
    const form = byId('research-settings-form');
    form.elements.enable.checked = settings.enabled === true;
    form.elements.image_id.value = settings.image_id || '';
    form.elements.queue_seconds.value = settings.queue_seconds || 3600;
    const limits = settings.limits || {};
    for (const [name, fallback] of Object.entries({timeout_seconds:10, output_bytes:65536,
      memory_bytes:134217728, scratch_bytes:16777216, pids:32, cpus:0.5})) {
      form.elements[name].value = limits[name] ?? fallback;
    }
    byId('research-evaluators').replaceChildren();
    (settings.evaluators || []).forEach(addEvaluator);
    if (!(settings.evaluators || []).length) addEvaluator();
    form.dataset.settingsSha256 = settings.settings_sha256 || '';
    form.elements.confirm.checked = false;
    syncControls();
  }

  function renderJobs(rows) {
    const list = byId('research-jobs');
    list.replaceChildren();
    if (!rows.length) list.appendChild(element('li', 'No research submissions yet. Submissions appear here once someone sends one.'));
    rows.forEach(row => {
      const item = element('li', undefined, 'research-item');
      item.appendChild(element('strong', `Submission ${row.id}`));
      item.appendChild(element('p', `Status: ${human(row.status)} · Check: ${row.evaluator_id}`));
      if (row.execution?.state) {
        item.appendChild(element('p', `Run: ${human(row.execution.state)}`));
      }
      const counts = row.evaluation?.counts;
      if (counts && Number.isSafeInteger(counts.passed) && counts.passed >= 0 &&
          Number.isSafeInteger(counts.failed) && counts.failed >= 0) {
        const outcome = counts.passed > 0 && counts.failed === 0 ? 'passed' : 'failed';
        item.appendChild(element('p', `Result: ${outcome === 'passed' ? 'Passed' : 'Failed'} (${counts.passed} passed, ${counts.failed} failed)`));
      }
      if (typeof row.next_action === 'string' && row.next_action.length <= 512) {
        item.appendChild(element('p', `Next step: ${row.next_action}`));
      }
      if (['queued', 'running'].includes(row.status)) {
        const cancel = element('button', row.status === 'queued' ? 'Cancel submission' : 'Request cancellation', 'btn');
        cancel.type = 'button';
        cancel.dataset.researchJobCancel = 'true';
        cancel.addEventListener('click', () => act(async () => {
          await api(`/jobs/${encodeURIComponent(row.id)}/cancel`, 'POST',
            {context, confirm:true, expected_revision:row.revision});
          message('Research submission cancelled.');
          await refresh();
        }));
        item.appendChild(cancel);
      }
      list.appendChild(item);
    });
  }

  function renderReviewQueue(rows, isAdministrator) {
    const panel = byId('research-review-panel');
    panel.hidden = !isAdministrator;
    if (!isAdministrator) return;
    const choice = byId('research-review-choice');
    choice.replaceChildren(new Option('Choose a submission', ''));
    rows.forEach(row => {
      choice.appendChild(new Option(`${human(row.status)} · ${person(row.submitted_by)} · submission ${row.id}`, row.id));
    });
  }

  function renderReviewDetail(review) {
    const host = byId('research-review-detail');
    host.replaceChildren();
    host.appendChild(element('p', `Sent by ${person(review.submitted_by) || 'someone'} · ${human(review.status)}`));
    const counts = review.evaluation?.counts;
    if (counts && Number.isSafeInteger(counts.passed) && counts.passed >= 0 &&
        Number.isSafeInteger(counts.failed) && counts.failed >= 0) {
      host.appendChild(element('p', `Correct-output check: ${counts.passed} passed · ${counts.failed} failed`));
    }
    const observation = review.observation;
    if (observation && Number.isSafeInteger(observation.exit_code) &&
        typeof observation.reason === 'string' && observation.reason.length <= 128) {
      host.appendChild(element('p', observation.exit_code === 0 ? 'The program finished normally.' :
        observation.exit_code === 137 ? 'The program was stopped because it used too much memory or time.' :
        `The program stopped with a problem (${human(observation.reason)}).`));
    }
    if (typeof review.next_action === 'string' && review.next_action.length <= 512) {
      host.appendChild(element('p', `Next step: ${review.next_action}`));
    }
    Object.entries(review.files || {}).sort().forEach(([name, source]) => {
      const details = element('details');
      details.append(element('summary', name), element('pre', source, 'research-source'));
      host.appendChild(details);
    });
  }

  function render(data) {
    model = validate(data);
    selectedReview = null;
    byId('research-review-detail').replaceChildren();
    byId('research-dispatch-confirm').checked = false;
    byId('research-readiness').textContent = data.execution_available ?
      `Ready. ${data.evaluators.length} correct-output check${data.evaluators.length === 1 ? '' : 's'} set up.` :
      'Experiments cannot run yet. Existing submissions can still be seen and cancelled; an administrator can finish the setup below.';
    const evaluator = byId('research-submit').elements.evaluator_id;
    evaluator.replaceChildren(new Option(data.evaluators.length ? 'Choose a check' : 'No check is set up yet', ''));
    data.evaluators.forEach(row => evaluator.appendChild(new Option(`${row.id} · ${row.version}`, row.id)));
    renderSettings(data.settings);
    renderJobs(data.jobs);
    renderReviewQueue(data.review_queue, !!data.settings);
    message(data.execution_available ? 'Ready.' :
      'Experiments need an administrator to finish the setup before they can run.');
    syncControls();
  }

  async function refresh() {
    render(await api(''));
  }

  async function act(work) {
    if (busy) return;
    setBusy(true);
    try {
      await work();
    } catch (error) {
      message(error.message || 'Something went wrong. Try again.', true);
    } finally {
      setBusy(false);
    }
  }

  byId('research-refresh').addEventListener('click', () => act(async () => {
    // Refresh is an explicit request to discard an outdated local edit and
    // load the current CAS revision after a conflict.
    settingsDirty = false;
    await refresh();
  }));
  byId('research-add-evaluator').addEventListener('click', () => {
    addEvaluator();
    settingsDirty = true;
    syncControls();
  });
  byId('research-settings-form').addEventListener('input', () => {
    if (busy) return;
    settingsDirty = true;
    syncControls();
  });
  byId('research-settings-form').addEventListener('submit', event => {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    if (!form.elements.confirm.checked || !sha(form.dataset.settingsSha256)) return;
    const enable = form.elements.enable.checked;
    if (enable && !form.reportValidity()) return;
    const payload = enable ? {context, confirm:true,
      expected_settings_sha256:form.dataset.settingsSha256, enable:true,
      image_id:form.elements.image_id.value.trim(), queue_seconds:Number(form.elements.queue_seconds.value),
      evaluators:[...byId('research-evaluators').querySelectorAll('.research-evaluator')].map(row => ({
        id: row.querySelector('[data-field="id"]').value.trim(),
        version: row.querySelector('[data-field="version"]').value.trim(),
        stdout_sha256: row.querySelector('[data-field="stdout_sha256"]').value.trim(),
      })),
      limits:{timeout_seconds:Number(form.elements.timeout_seconds.value), output_bytes:Number(form.elements.output_bytes.value),
        memory_bytes:Number(form.elements.memory_bytes.value), scratch_bytes:Number(form.elements.scratch_bytes.value),
        pids:Number(form.elements.pids.value), cpus:Number(form.elements.cpus.value)}} :
      {context, confirm:true, expected_settings_sha256:form.dataset.settingsSha256, enable:false};
    act(async () => {
      if (!enable) {
        await api('/settings', 'PUT', payload);
        settingsDirty = false;
        message('Experiments are turned off. Existing submissions can still be seen and cancelled.');
        await refresh();
        return;
      }
      await api('/settings', 'PUT', payload);
      settingsDirty = false;
      message('Setup saved. Waiting submissions need to be reviewed again.');
      await refresh();
    });
  });
  byId('research-submit').elements.files.addEventListener('change', event => {
    const form = byId('research-submit');
    const entry = form.elements.entrypoint;
    const generation = ++fileSelectionGeneration;
    const files = [...event.target.files];
    // Never retain a prior valid selection while validating a replacement.
    // Any failure leaves submission disabled until a fresh set succeeds.
    selectedFiles = {};
    byId('research-files').textContent = 'No files chosen.';
    entry.replaceChildren(new Option('Choose the file to start with', ''));
    form.elements.confirm.checked = false;
    syncControls();
    if (busy) {
      message('Wait for the current research action, then choose the source files again.', true);
      return;
    }
    act(async () => {
    if (!files.length || files.length > 64) throw new Error('Choose between 1 and 64 files.');
    const next = {};
    let bytes = 0;
    for (const file of files) {
      if (!file.name || Object.hasOwn(next, file.name)) throw new Error('Every source file needs a unique name.');
      const source = await file.text();
      if (generation !== fileSelectionGeneration) return;
      bytes += new Blob([source]).size;
      if (bytes > 262144) throw new Error('The chosen files are larger than 256 KB in total.');
      next[file.name] = source;
    }
    selectedFiles = next;
    byId('research-files').textContent = `${files.length} file${files.length === 1 ? '' : 's'} · ${Math.ceil(bytes / 1024)} KB`;
    Object.keys(next).filter(name => name.endsWith('.py')).sort().forEach(name => {
      entry.appendChild(new Option(name, name));
    });
    syncControls();
    });
  });
  byId('research-submit').addEventListener('input', syncControls);
  byId('research-submit').addEventListener('submit', event => {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const entrypoint = form.elements.entrypoint.value;
    const evaluatorId = form.elements.evaluator_id.value;
    if (!model?.execution_available || !form.reportValidity() || !form.elements.confirm.checked ||
        !Object.hasOwn(selectedFiles, entrypoint) ||
        !model.evaluators.some(row => row.id === evaluatorId)) return;
    const files = {...selectedFiles};
    act(async () => {
      await api('/jobs', 'POST', {context, confirm:true, files,
        evaluator_id:evaluatorId, entrypoint,
        idempotency_key:`ui-${crypto.randomUUID()}`});
      form.reset();
      fileSelectionGeneration += 1;
      selectedFiles = {};
      byId('research-files').textContent = 'Choose up to 64 text files, 256 KB in total.';
      message('Sent to an administrator for review.');
      await refresh();
    });
  });
  byId('research-review-choice').addEventListener('change', () => {
    selectedReview = null;
    byId('research-review-detail').replaceChildren();
    byId('research-dispatch-confirm').checked = false;
    syncControls();
  });
  byId('research-open-review').addEventListener('click', () => act(async () => {
    const id = byId('research-review-choice').value;
    if (!id) return;
    const review = await api(`/review/${encodeURIComponent(id)}`);
    if (byId('research-review-choice').value !== id || review?.id !== id ||
        !validJob(review) || !sha(review.review_sha256) || !review.files ||
        Object.values(review.files).some(value => typeof value !== 'string')) {
      selectedReview = null;
      throw new Error('The files could not be opened for review. Refresh and try again.');
    }
    selectedReview = review;
    renderReviewDetail(selectedReview);
    byId('research-dispatch-confirm').checked = false;
    syncControls();
  }));
  byId('research-dispatch-confirm').addEventListener('change', syncControls);
  byId('research-dispatch').addEventListener('click', () => act(async () => {
    if (!model?.can_dispatch || !model?.execution_available || !selectedReview ||
        !sha(selectedReview.review_sha256) || selectedReview.status !== 'queued' ||
        !byId('research-dispatch-confirm').checked) return;
    const reviewed = selectedReview;
    const result = await api(`/jobs/${encodeURIComponent(reviewed.id)}/run`, 'POST', {context, confirm:true,
      expected_revision:selectedReview.revision, review_sha256:selectedReview.review_sha256});
    if (!validJob(result) || result.id !== reviewed.id) {
      throw new Error('The result could not be confirmed. Refresh before doing anything else.');
    }
    const completedReview = {...reviewed, ...result};
    selectedReview = completedReview;
    renderReviewDetail(completedReview);
    byId('research-dispatch-confirm').checked = false;
    message('The reviewed program has finished. Its result is shown below.');
    syncControls();
    try {
      await refresh();
    } catch (_) {
      throw new Error('The program finished, but the list could not be refreshed. Its result is shown below; refresh the page to update the list.');
    }
    selectedReview = completedReview;
    renderReviewDetail(completedReview);
    byId('research-dispatch-confirm').checked = false;
    message('The reviewed program has finished. Its result is shown below.');
    syncControls();
  }));
  byId('research-admin-cancel').addEventListener('click', () => act(async () => {
    if (!selectedReview || !sha(selectedReview.review_sha256) ||
        !['queued', 'running'].includes(selectedReview.status)) return;
    await api(`/jobs/${encodeURIComponent(selectedReview.id)}/cancel`, 'POST',
      {context, confirm:true, expected_revision:selectedReview.revision});
    selectedReview = null;
    byId('research-review-detail').replaceChildren();
    message('Research submission cancelled.');
    await refresh();
  }));
  // A failed first load leaves nothing to show: say so where the page said
  // "Checking…" and "Loading…" (the reason is also shown in the status line).
  async function firstLoad() {
    try {
      await refresh();
    } catch (error) {
      const why = action => (typeof window.mvErrorText === 'function' ? window.mvErrorText(error, action)
        : `Could not ${action}. Refresh the page to try again.`);
      byId('research-readiness').textContent = why('check whether experiments can run');
      byId('research-jobs').replaceChildren(element('li', why('load your experiments')));
      throw error;
    }
  }
  act(firstLoad);
})();
