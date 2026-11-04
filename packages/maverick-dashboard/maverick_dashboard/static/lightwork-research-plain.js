// Plain controls for the Research lab. The page's forms keep their original
// field names (hidden); this script fills them from people-friendly controls:
// names become identifiers, versions count up, chosen files become
// fingerprints computed by the server, check boxes become lists and friendly
// units become seconds and bytes. The submit handlers in the other research
// scripts then send exactly what they always sent.
(() => {
  'use strict';
  const root = document.getElementById('research-lab');
  if (!root) return;
  const LABELS = {product_research: 'Product research', model_evaluation: 'Testing an AI model',
    quality_improvement: 'Improving quality', safety_testing: 'Safety testing', analytics: 'Business analysis'};
  let registry = {datasets: [], models: [], runs: []};
  const pending = new Map();

  function human(value) {
    if (LABELS[value]) return LABELS[value];
    return window.mvHuman ? window.mvHuman(value) : String(value || '').replace(/[_-]+/g, ' ');
  }

  function slug(text) {
    const value = String(text || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 100);
    return value || '';
  }

  function nextVersion(kind, id) {
    const rows = kind === 'model' ? registry.models : registry.datasets;
    let highest = 0;
    rows.forEach(row => {
      const ref = row.reference || {};
      if (ref.asset_id !== id) return;
      const match = /^v?(\d+)$/.exec(String(ref.version || ''));
      if (match) highest = Math.max(highest, Number(match[1]));
      else highest = Math.max(highest, 1);
    });
    return `v${highest + 1}`;
  }

  function hidden(form, name) { return form.elements[name]; }
  function say(text) { window.mvStatus(document.getElementById('research-governed-status'), text); }

  // Names -> identifiers (and the next free version for datasets and models).
  function syncSlug(input) {
    const form = input.form;
    const target = hidden(form, input.dataset.slugFor);
    if (!target) return;
    const id = slug(input.value);
    target.value = id;
    if (input.dataset.versionFor && hidden(form, input.dataset.versionFor)) {
      hidden(form, input.dataset.versionFor).value = id ? nextVersion(input.dataset.kind, id) : '';
    }
  }

  // Check boxes -> a comma or newline separated list.
  function syncChecks(fieldset) {
    const form = fieldset.form || fieldset.closest('form');
    const target = hidden(form, fieldset.dataset.joinInto);
    if (!target) return;
    const values = [...fieldset.querySelectorAll('input[type=checkbox]:checked')].map(box => box.value);
    target.value = fieldset.dataset.joinInto === 'usage_constraints' ? values.join('\n') : values.join(', ');
  }

  // A choice with "another…" -> the hidden value.
  function syncInto(select) {
    const form = select.form;
    const target = hidden(form, select.dataset.into);
    const other = form.querySelector(`[data-other-for="${select.dataset.into}"]`);
    if (other) {
      other.hidden = select.value !== '__other__';
      other.required = select.value === '__other__';
    }
    if (target) target.value = select.value === '__other__' ? (other ? other.value.trim() : '') : select.value;
  }

  function syncScale(select) {
    const form = select.form;
    const target = hidden(form, select.dataset.scaleInto);
    if (target) target.value = String(Math.round(Number(select.value) * Number(select.dataset.scale || 1) * 1000) / 1000);
    if (target) target.dispatchEvent(new Event('input', {bubbles: true}));
  }

  function syncEpoch(input) {
    const target = hidden(input.form, input.dataset.epochInto);
    if (!target) return;
    const time = input.value ? new Date(input.value).getTime() : NaN;
    target.value = Number.isFinite(time) ? String(Math.floor(time / 1000)) : '';
  }

  function randomSeed() {
    const bytes = new Uint32Array(1);
    (window.crypto || {}).getRandomValues ? window.crypto.getRandomValues(bytes) : (bytes[0] = Math.floor(Math.random() * 1e9));
    return String(bytes[0]);
  }

  function freshDefaults(form) {
    form.querySelectorAll('[data-random-seed]').forEach(input => { if (!input.value) input.value = randomSeed(); });
    if (form.elements.run_id && !form.elements.run_id.value) {
      form.elements.run_id.value = `run-${(window.crypto && crypto.randomUUID) ? crypto.randomUUID() : Date.now().toString(36)}`;
    }
    form.querySelectorAll('select[data-scale-into]').forEach(syncScale);
    form.querySelectorAll('[data-fingerprint-state]').forEach(state => { state.textContent = state.dataset.help || ''; });
  }

  // Chosen files -> fingerprints computed by the server (the file is not kept).
  async function fingerprint(input) {
    const form = input.form;
    const name = input.dataset.fingerprintFor;
    const target = hidden(form, name);
    const state = form.querySelector(`[data-fingerprint-state="${name}"]`);
    if (state && state.dataset.help === undefined) state.dataset.help = state.textContent;
    target.value = '';
    const file = input.files && input.files[0];
    if (!file) { if (state) state.textContent = state.dataset.help || ''; return; }
    const job = (async () => {
      if (state) state.textContent = `Reading ${file.name}…`;
      let body;
      try {
        body = await window.mvFetchJSON('/api/v1/research-files/fingerprint', {method: 'POST',
          headers: {'Content-Type': 'application/octet-stream'}, body: file,
          messages: {413: 'That file is too large. Ask your administrator to record it for you.'}}, 'read the file');
      } catch (error) {
        if (state) state.textContent = error.message;
        return;
      }
      if (input.files && input.files[0] === file) {
        target.value = body.fingerprint;
        if (state) state.textContent = `Ready: ${file.name}`;
        target.dispatchEvent(new Event('input', {bubbles: true}));
      }
    })();
    pending.set(input, job);
    try { await job; } finally { pending.delete(input); }
  }

  function renderPurposes() {
    const select = document.querySelector('#research-run-form select[name="purpose"]');
    if (!select) return;
    const current = select.value;
    const purposes = new Set();
    registry.datasets.forEach(row => {
      if (row.state === 'approved') (row.allowed_purposes || []).forEach(p => purposes.add(p));
    });
    select.replaceChildren(new Option(purposes.size ? 'Choose a purpose' : 'No approved datasets yet', ''));
    [...purposes].sort().forEach(p => select.appendChild(new Option(human(p), p)));
    if ([...purposes].includes(current)) select.value = current;
  }

  function renderExperiments() {
    const select = document.querySelector('#research-run-form [data-experiment]');
    if (!select) return;
    const current = select.value;
    const latest = new Map();
    registry.runs.forEach(run => {
      const manifest = run.manifest || {};
      if (manifest.experiment_id) latest.set(manifest.experiment_id, manifest.experiment_version || 'v1');
    });
    select.replaceChildren(new Option('A new experiment', '__new__'));
    [...latest.keys()].sort().forEach(id => {
      const option = new Option(human(id), id);
      option.dataset.version = latest.get(id);
      select.appendChild(option);
    });
    select.value = [...latest.keys()].includes(current) ? current : '__new__';
    syncExperiment(select);
  }

  function syncExperiment(select) {
    const form = select.form;
    const isNew = select.value === '__new__';
    const nameLabel = form.querySelector('[data-experiment-name]');
    const nameInput = nameLabel && nameLabel.querySelector('input');
    if (nameLabel) nameLabel.hidden = !isNew;
    if (nameInput) nameInput.required = isNew;
    if (isNew) {
      if (nameInput) syncSlug(nameInput);
      form.elements.experiment_version.value = 'v1';
    } else {
      form.elements.experiment_id.value = select.value;
      form.elements.experiment_version.value = select.selectedOptions[0].dataset.version || 'v1';
    }
  }

  async function renderCodeProjects() {
    const select = document.querySelector('#research-run-form [data-code-project]');
    if (!select) return;
    let repos = [];
    try {
      repos = ((await window.mvFetchJSON('/api/v1/code/heads')) || {}).repos || [];
    } catch (_) { repos = []; }
    select.replaceChildren(new Option(repos.length ? 'Choose a code project' : 'No code projects yet (add one on the Code page)', ''));
    repos.forEach(repo => select.appendChild(new Option(`${repo.name} (latest version)`, repo.head)));
    select.appendChild(new Option('Type the code version myself (for developers)', '__manual__'));
    let manual = select.parentNode.querySelector('[data-code-manual]');
    if (!manual) {
      manual = document.createElement('input');
      manual.className = 'input';
      manual.dataset.codeManual = 'true';
      manual.hidden = true;
      manual.maxLength = 71;
      manual.setAttribute('aria-label', 'Code version');
      manual.pattern = '(?:[a-f0-9]{40}|[a-f0-9]{64}|sha256:[a-f0-9]{64})';
      manual.addEventListener('input', () => { select.form.elements.code_revision.value = manual.value.trim(); });
      select.parentNode.appendChild(manual);
    }
  }

  async function loadRegistry() {
    try {
      const value = await window.mvFetchJSON('/api/v1/research', {cache: 'no-store'});
      if (value.context !== root.dataset.context) return;
      registry = {datasets: value.registry?.datasets || [], models: value.registry?.models || [], runs: value.governed_runs || []};
      renderPurposes();
      renderExperiments();
      document.querySelectorAll('[data-slug-for]').forEach(input => { if (input.value) syncSlug(input); });
    } catch (_) { /* the lists stay as they are */ }
  }

  root.addEventListener('input', event => {
    const el = event.target;
    if (el.matches('[data-slug-for]')) syncSlug(el);
    if (el.matches('[data-other-for]')) {
      const select = el.form.querySelector(`select[data-into="${el.dataset.otherFor}"]`);
      if (select) syncInto(select);
    }
  });
  root.addEventListener('change', event => {
    const el = event.target;
    if (el.closest('[data-join-into]') && el.type === 'checkbox') syncChecks(el.closest('[data-join-into]'));
    if (el.matches('select[data-into]')) syncInto(el);
    if (el.matches('select[data-scale-into]')) syncScale(el);
    if (el.matches('[data-epoch-into]')) syncEpoch(el);
    if (el.matches('[data-fingerprint-for]')) fingerprint(el);
    if (el.matches('[data-experiment]')) syncExperiment(el);
    if (el.matches('[data-code-project]')) {
      const manual = el.parentNode.querySelector('[data-code-manual]');
      if (manual) { manual.hidden = el.value !== '__manual__'; manual.required = el.value === '__manual__'; }
      el.form.elements.code_revision.value = el.value === '__manual__' ? (manual ? manual.value.trim() : '') : el.value;
    }
    if (el.name === 'data_use_decision_choice' && el.value) {
      // Tick the purposes the chosen permission allows (after the other
      // script copies them into the form).
      setTimeout(() => {
        let decision = null;
        try { decision = JSON.parse(el.value); } catch (_) { decision = null; }
        const fieldset = el.form.querySelector('[data-join-into="allowed_purposes"]');
        if (!decision || !fieldset) return;
        (decision.purpose_codes || []).forEach(code => {
          let box = [...fieldset.querySelectorAll('input[type=checkbox]')].find(b => b.value === code);
          if (!box) {
            const label = document.createElement('label');
            box = document.createElement('input'); box.type = 'checkbox'; box.value = code;
            label.append(box, document.createTextNode(' ' + human(code)));
            fieldset.appendChild(label);
          }
          box.checked = true;
        });
        syncChecks(fieldset);
        const nameInput = el.form.querySelector('[data-slug-for="dataset_id"]');
        if (nameInput && !nameInput.value && decision.asset_id) { nameInput.value = decision.asset_id; syncSlug(nameInput); }
      }, 0);
    }
  });

  // Runs before the page's own submit handlers: stop a submission that is
  // missing a list choice or is still reading a file.
  root.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', event => {
      form.querySelectorAll('[data-join-into]').forEach(syncChecks);
      form.querySelectorAll('select[data-into]').forEach(syncInto);
      let problem = '';
      form.querySelectorAll('[data-join-into][data-required="true"]').forEach(fieldset => {
        if (!fieldset.closest('[hidden]') && !fieldset.querySelector('input:checked')) problem = `Choose at least one option under “${fieldset.querySelector('legend').textContent}”.`;
      });
      form.querySelectorAll('[data-fingerprint-for]').forEach(input => {
        if (pending.has(input)) problem = 'Wait until the chosen files have been read.';
        else if (input.files && input.files.length && !hidden(form, input.dataset.fingerprintFor).value) problem = 'One of the chosen files could not be read. Choose it again.';
      });
      if (problem) {
        event.preventDefault();
        event.stopImmediatePropagation();
        say(problem);
      }
    });
    form.addEventListener('reset', () => setTimeout(() => {
      form.querySelectorAll('[data-join-into]').forEach(syncChecks);
      form.querySelectorAll('select[data-into]').forEach(syncInto);
      freshDefaults(form);
      loadRegistry();
    }, 0));
    freshDefaults(form);
  });
  root.querySelectorAll('[data-fingerprint-state]').forEach(state => { state.dataset.help = state.textContent; });

  // Keep the lists current after the other scripts refresh.
  const status = document.getElementById('research-governed-status');
  if (status && window.MutationObserver) {
    new MutationObserver(() => loadRegistry()).observe(status, {childList: true, characterData: true, subtree: true});
  }
  loadRegistry();
  renderCodeProjects();
})();
