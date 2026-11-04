'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');

const source = fs.readFileSync(
  path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-research-workspace.js'),
  'utf8',
);
const CONTEXT = 'c'.repeat(64);
const DIGEST = 'd'.repeat(64);
const tick = () => new Promise(resolve => setImmediate(resolve));

function html() {
  return `<div id="research-lab" data-context="${CONTEXT}">
    <p id="research-governed-status"></p><p id="research-materialization-state"></p><p id="research-registry-authority-state"></p>
    <button id="research-governed-refresh"></button><div id="research-impact"></div>
    <ul id="research-registry-items"></ul><ul id="research-governed-runs"></ul>
    <form id="research-dataset-form">
      <input name="dataset_id" required><input name="version" required><input name="source_ref" required>
      <input name="content_sha256" pattern="[a-f0-9]{64}" required><input name="license_id" required>
      <input name="license_evidence_sha256" pattern="[a-f0-9]{64}" required>
      <input name="allowed_purposes" required><textarea name="usage_constraints" required></textarea>
      <select name="data_use_action"><option value="analyze">analyze</option></select>
      <select name="data_use_decision_choice"><option value="">decision</option></select>
      <select name="provenance_kind"><option value="source">source</option><option value="derived">derived</option><option value="synthetic">synthetic</option></select>
      <input name="data_use_decision_id" required><input name="data_use_decision_sha256" pattern="[a-f0-9]{64}" required>
      <select name="parent_datasets" multiple></select><input name="consent_record_id"><input name="consent_evidence_sha256">
      <div id="research-synthetic-fields"><input name="synthetic_generator_id"><input name="synthetic_generator_version">
        <input name="synthetic_generator_sha256" pattern="[a-f0-9]{64}"><input name="synthetic_config_sha256" pattern="[a-f0-9]{64}">
        <input name="synthetic_seed" type="number"></div><input name="confirm" type="checkbox" required><button type="submit">dataset</button>
    </form>
    <form id="research-model-form">
      <input name="model_id"><input name="version"><input name="source_ref"><input name="artifact_sha256">
      <input name="license_id"><input name="license_evidence_sha256"><input name="allowed_purposes"><textarea name="usage_constraints"></textarea>
      <input name="provider_model_identity"><input name="immutable_provider_revision"><input name="observed_from" type="number">
      <input name="observed_until" type="number"><textarea name="reproducibility_limitation"></textarea>
      <select name="dataset_lineage" multiple></select><input name="dataset_lineage_purpose"><select name="model_lineage" multiple></select>
      <select name="provenance_kind"><option value="external">external</option><option value="trained">trained</option></select>
      <div id="research-training-receipt-fields"><input name="training_receipt_id"><input name="training_receipt_sha256"><input name="training_dataset_sha256"></div>
      <input name="confirm" type="checkbox"><button type="submit">model</button>
    </form>
    <form id="research-run-form">
      <select name="program_id" id="research-program-choice" required><option value="">Loading saved programs…</option></select>
      <p id="research-program-notice"></p>
      <input name="run_id" required><input name="run_version" value="v1" required><input name="experiment_id" required>
      <input name="experiment_version" value="v1" required><input name="purpose" required>
      <select name="action"><option value="analyze">analyze</option><option value="train">train</option></select>
      <select name="dataset_refs" multiple required></select><select name="model_ref"><option value="">none</option></select>
      <input name="code_revision" required><input name="code_sha256" pattern="[a-f0-9]{64}" required>
      <input name="environment_id" required><input name="environment_version" required>
      <input name="environment_sha256" pattern="[a-f0-9]{64}" required><input name="seed" type="number" required>
      <input name="max_wall_seconds" type="number" value="300" required><input name="max_provider_calls" type="number" value="0" required>
      <input name="max_storage_bytes" type="number" value="104857600" required><input name="max_cost" value="0" required>
      <input name="currency" value="USD" required><input name="metric_protocol_sha256" pattern="[a-f0-9]{64}" required>
      <input name="confirm" type="checkbox" required><button type="submit">run</button>
    </form>
    <p id="research-original-status" role="status" aria-live="polite"></p><button type="button" id="research-read-original" hidden>Read original run</button>
  </div>`;
}

function reference(kind, id, version = 'v1', digest = DIGEST) {
  return {kind, asset_id:id, version, manifest_sha256:digest,
    schema:'lightwork.research-registry-ref.v1'};
}

function dataset(changes = {}) {
  return {reference:reference('dataset', 'synthetic-cases'), kind:'dataset', state:'approved',
    revision:2, registered_by:'user:maker@example.test', created_at:1, updated_at:2,
    source_ref:'artifact:synthetic-cases/v1', license_id:'internal-test',
    license_evidence_sha256:'1'.repeat(64), allowed_purposes:['product_research'],
    usage_constraints:['local_only'], provenance_kind:'synthetic', content_sha256:'2'.repeat(64),
    data_use_action:'analyze', data_use_decision_id:'decision-1',
    data_use_decision_sha256:'3'.repeat(64), consent_record_id:null,
    consent_evidence_sha256:null, parent_datasets:[],
    synthetic_provenance:{generator_id:'fixture', generator_version:'v1', seed:7},
    eligibility:{state:'eligible', checked_purposes:['product_research'], detail:'Current checks passed.'},
    approval:{approved_by:'user:reviewer@example.test'}, revocation:null, ...changes};
}

function run(changes = {}) {
  return {run_id:'run-1', created_by:'user:researcher@example.test', status:'queued', revision:2,
    created_at:1, updated_at:2, manifest_sha256:'4'.repeat(64),
    manifest:{experiment_id:'baseline', experiment_version:'v1', action:'analyze',
      purpose:'product_research', seed:7, code_revision:'a'.repeat(40),
      environment_id:'local', environment_version:'v1', dataset_refs:[dataset().reference],
      resource_caps:{max_wall_seconds:60, max_provider_calls:0, max_storage_bytes:1024,
        max_cost:'0', currency:'USD'}},
    cost_summary:{effective_amounts:{USD:'1.25'}, incomplete:true, effective_event_count:2},
    attempts:[{number:1, status:'queued', costs:[
      {cost:{category:'compute', basis:'invoice', amount:'1.25', currency:'USD', quantity:null,
        unit:null, incomplete_reason:null, evidence_sha256:'5'.repeat(64), source_ref_sha256:'6'.repeat(64)}},
      {cost:{category:'storage', basis:'unknown', amount:null, currency:null, quantity:null,
        unit:null, incomplete_reason:'provider report pending', evidence_sha256:'7'.repeat(64), source_ref_sha256:'8'.repeat(64)}},
    ], metrics:[]}], ...changes};
}

function overview(changes = {}) {
  return {context:CONTEXT, registry:{datasets:[dataset()], models:[], can_review:true,
    truncated:false, consent_authority_available:false,
    training_receipt_verification:'server_policy_on_demand'}, governed_runs:[run()],
    governed_runs_truncated:false, governed_execution:{available:false, state:'unavailable',
      detail:'No trusted materialization adapter is configured.'}, ...changes};
}

async function settle() {
  for (let index = 0; index < 12; index += 1) await tick();
}

async function fixture(handler) {
  const dom = new JSDOM(html(), {url:'https://lightwork.test/research', runScripts:'outside-only'});
  const calls = [];
  dom.window.crypto.randomUUID = () => '00000000-0000-4000-8000-000000000001';
  dom.window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    const value = await handler(url, options, calls);
    return value && Object.hasOwn(value, 'ok') ? value : {ok:true, status:200,
      json:async () => value, blob:async () => new dom.window.Blob([JSON.stringify(value)])};
  };
  shell(dom.window);
  dom.window.eval(source);
  await settle();
  return {dom, window:dom.window, document:dom.window.document, calls};
}

test('renders explicit synthetic provenance and exact incomplete cost without enabling unavailable execution', async () => {
  const unsafe = '<img src=x onerror=alert(1)>';
  const value = overview({registry:{...overview().registry,
    datasets:[dataset({usage_constraints:[unsafe]})]}});
  const ui = await fixture(async () => value);
  assert.match(ui.document.getElementById('research-registry-items').textContent, /Generated test data/);
  assert.match(ui.document.getElementById('research-governed-runs').textContent, /USD 1.25/);
  assert.match(ui.document.getElementById('research-governed-runs').textContent, /some resource use has no verified financial price/);
  assert.match(ui.document.getElementById('research-governed-runs').textContent, /Storage · Unknown · not known yet \(Provider report pending\)/);
  assert.equal(ui.document.querySelector('#research-registry-items img'), null);
  const start = [...ui.document.querySelectorAll('#research-governed-runs button')]
    .find(button => button.textContent === 'Start run');
  // No independent approval and no execution: Start is not offered at all.
  assert.equal(start, undefined);
  assert.match(ui.document.getElementById('research-materialization-state').textContent, /blocked before data access/i);
  ui.dom.window.close();
});

test('registers a synthetic dataset with sorted purposes and explicit generator provenance', async () => {
  let submitted;
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/registry/datasets') && options.method === 'POST') {
      submitted = JSON.parse(options.body); return dataset({state:'draft', revision:1, approval:null});
    }
    return overview();
  });
  const form = ui.document.getElementById('research-dataset-form');
  Object.assign(form.elements.dataset_id, {value:'new-synthetic'});
  form.elements.version.value = 'v1'; form.elements.source_ref.value = 'artifact:new-synthetic/v1';
  form.elements.content_sha256.value = '1'.repeat(64); form.elements.license_id.value = 'internal-test';
  form.elements.license_evidence_sha256.value = '2'.repeat(64);
  form.elements.allowed_purposes.value = 'zeta, alpha, zeta';
  form.elements.usage_constraints.value = 'synthetic_only\nlocal_only';
  form.elements.data_use_decision_id.value = 'decision-1';
  form.elements.data_use_decision_sha256.value = '3'.repeat(64);
  form.elements.provenance_kind.value = 'synthetic';
  form.elements.provenance_kind.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  form.elements.synthetic_generator_id.value = 'fixture'; form.elements.synthetic_generator_version.value = 'v1';
  form.elements.synthetic_generator_sha256.value = '4'.repeat(64);
  form.elements.synthetic_config_sha256.value = '5'.repeat(64); form.elements.synthetic_seed.value = '17';
  form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.deepEqual(submitted.allowed_purposes, ['alpha', 'zeta']);
  assert.deepEqual(submitted.usage_constraints, ['local_only', 'synthetic_only']);
  assert.equal(submitted.provenance_kind, 'synthetic');
  assert.equal(submitted.synthetic_seed, 17);
  assert.equal(submitted.context, CONTEXT);
  ui.dom.window.close();
});

test('plans then queues an exact approved version with CAS', async () => {
  const mutations = [];
  const program = {id:'baseline-program', label:'Baseline program', experiment_id:'baseline', experiment_version:'v1',
    code_revision:'a'.repeat(40), code_sha256:'1'.repeat(64), environment_id:'local', environment_version:'v1',
    environment_sha256:'2'.repeat(64), metric_protocol_sha256:'3'.repeat(64)};
  const ui = await fixture(async (url, options) => {
    if (options.method === 'POST') {
      mutations.push({url, body:JSON.parse(options.body)});
      return options && url.endsWith('/governed-runs') ? run({status:'planned', revision:1}) : run();
    }
    if (url.endsWith('/execution-options')) return {context:CONTEXT, available:true, programs:[program], detail:'Ready.'};
    return overview({governed_runs:[]});
  });
  const form = ui.document.getElementById('research-run-form');
  // The code, setup and result check come from the chosen saved program.
  form.elements.program_id.value = 'baseline-program';
  form.elements.program_id.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  assert.equal(form.elements.code_sha256.value, '1'.repeat(64));
  form.elements.run_id.value = 'run-ui'; form.elements.purpose.value = 'product_research';
  form.elements.seed.value = '11';
  form.elements.dataset_refs.options[0].selected = true; form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.equal(mutations.length, 2);
  assert.equal(mutations[0].url, '/api/v1/research/governed-runs');
  assert.deepEqual(mutations[0].body.dataset_refs, [dataset().reference]);
  assert.equal(mutations[0].body.program_id, 'baseline-program');
  assert.equal(mutations[0].body.environment_sha256, '2'.repeat(64));
  assert.deepEqual(mutations[1], {url:'/api/v1/research/governed-runs/run-1/queue',
    body:{context:CONTEXT, confirm:true, expected_revision:1}});
  ui.dom.window.close();
});

test('known failed attempts expose an in-app retry bound to the current revision', async () => {
  let retry;
  const failed = run({status:'failed', revision:7, can_manage:true,
    attempts:[{...run().attempts[0], status:'failed'}]});
  // Only the person who manages the run is offered the retry.
  const other = await fixture(async () => overview({governed_runs:[{...failed, can_manage:false}]}));
  assert.equal([...other.document.querySelectorAll('#research-governed-runs button')]
    .find(item => item.textContent === 'Try again'), undefined);
  other.dom.window.close();
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/retry')) { retry = JSON.parse(options.body); return run({status:'planned', revision:8}); }
    return overview({governed_runs:[failed]});
  });
  const button = [...ui.document.querySelectorAll('#research-governed-runs button')]
    .find(item => item.textContent === 'Try again');
  button.click(); await settle();
  assert.deepEqual(retry, {context:CONTEXT, confirm:true, expected_revision:7});
  ui.dom.window.close();
});

test('a historically approved version with revoked current rights is absent from run selectors', async () => {
  const blocked = dataset({eligibility:{state:'blocked', checked_purposes:['product_research'],
    detail:'Current rights, consent, approval, or lineage no longer permits use.'}});
  const ui = await fixture(async () => overview({registry:{...overview().registry,
    datasets:[blocked]}, governed_runs:[]}));
  assert.equal(ui.document.getElementById('research-run-form').elements.dataset_refs.options.length, 0);
  assert.match(ui.document.getElementById('research-registry-items').textContent, /Can it be used now: Blocked/);
  ui.dom.window.close();
});

test('run selectors follow the exact purpose and action before a plan is submitted', async () => {
  const ui = await fixture(async () => overview({governed_runs:[]}));
  const form = ui.document.getElementById('research-run-form');
  const datasets = form.elements.dataset_refs;
  assert.equal(datasets.options.length, 1);

  form.elements.action.value = 'train';
  form.elements.action.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  assert.equal(datasets.options.length, 0);

  form.elements.action.value = 'analyze';
  form.elements.action.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  form.elements.purpose.value = 'different_purpose';
  form.elements.purpose.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  assert.equal(datasets.options.length, 0);

  form.elements.purpose.value = 'product_research';
  form.elements.purpose.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  assert.equal(datasets.options.length, 1);
  ui.dom.window.close();
});

test('paired consent and dataset-lineage fields become required together', async () => {
  const ui = await fixture(async () => overview({governed_runs:[]}));
  const datasetForm = ui.document.getElementById('research-dataset-form');
  datasetForm.elements.consent_record_id.value = 'consent-one';
  datasetForm.elements.consent_record_id.dispatchEvent(
    new ui.window.Event('input', {bubbles:true}),
  );
  assert.equal(datasetForm.elements.consent_record_id.required, true);
  assert.equal(datasetForm.elements.consent_evidence_sha256.required, true);

  const modelForm = ui.document.getElementById('research-model-form');
  modelForm.elements.dataset_lineage.options[0].selected = true;
  modelForm.elements.dataset_lineage.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  assert.equal(modelForm.elements.dataset_lineage_purpose.required, true);
  ui.dom.window.close();
});

test('a refused first load replaces both lists\' Loading with what happened', async () => {
  const dom = new JSDOM(html(), {url:'https://lightwork.test/research', runScripts:'outside-only'});
  const document = dom.window.document;
  for (const id of ['research-registry-items', 'research-governed-runs']) document.getElementById(id).innerHTML = '<li>Loading…</li>';
  dom.window.mvErrorText = (failure, action) => `Could not ${action}. Ask an administrator. (${failure.status})`;
  dom.window.fetch = async () => ({ok:false, status:403, json:async () => ({detail:'Current research workspace authority is required'})});
  shell(dom.window);
  dom.window.eval(source);
  await settle();
  assert.equal(document.getElementById('research-registry-items').textContent, 'Could not load datasets and models. Ask an administrator. (403)');
  assert.equal(document.getElementById('research-governed-runs').textContent, 'Could not load runs. Ask an administrator. (403)');
  assert.equal(document.getElementById('research-governed-status').textContent, 'You do not have permission to do this. Ask an administrator.');
  dom.window.close();
});
