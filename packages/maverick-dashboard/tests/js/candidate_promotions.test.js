'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');

const source = fs.readFileSync(
  path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-candidate-promotions.js'),
  'utf8',
);
const CONTEXT = 'c'.repeat(64);
const tick = () => new Promise(resolve => setImmediate(resolve));

function html() {
  return `<div id="research-lab" data-context="${CONTEXT}">
    <section id="research-promotions">
      <p id="research-promotions-status"></p><span id="research-promotions-readiness"></span>
      <button id="research-promotions-refresh"></button>
      <details id="research-promotion-proposal" hidden><form id="research-promotion-form">
        <input name="candidate_id" value="candidate-new" required>
        <select name="run_id" required><option value="">Choose a completed run</option></select>
        <select name="target_preset" required><option value="">Choose a target</option></select>
        <button type="submit">Create</button>
      </form></details>
      <ul id="research-promotions-list"></ul>
    </section>
  </div>`;
}

function candidate(changes = {}) {
  return {candidate_id:'candidate-1', state:'awaiting_review', revision:1,
    manifest_sha256:'1'.repeat(64), policy_sha256:'2'.repeat(64),
    study:{conclusion:'qualified', evaluator_id:'sealed-evaluator', evaluator_version:'v1'},
    run:{run_id:'run-1', output_artifact_sha256:'3'.repeat(64)},
    target:{target_id:'installed-app', expected_active_sha256:'4'.repeat(64)},
    lineage:[{kind:'dataset', asset_id:'cases', version:'v1'}],
    review:null, block:null, deployment:null, ...changes};
}

function overview(changes = {}) {
  return {context:CONTEXT, available:true, can_manage:true, can_propose:true,
    completed_runs:['run-1'],
    target_presets:[{preset_id:'installed-app', target_id:'installed-app'}],
    items:[candidate()],
    detail:'Current authority will be checked.', ...changes};
}

async function settle() {
  for (let index = 0; index < 10; index += 1) await tick();
}

async function fixture(handler) {
  const dom = new JSDOM(html(), {url:'https://lightwork.test/research', runScripts:'outside-only'});
  const calls = [];
  const prompts = [];
  dom.window.confirm = () => { throw new Error('native confirm must not be used'); };
  dom.window.mvConfirm = async (prompt, options) => { prompts.push({prompt, options}); return true; };
  dom.window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    const value = await handler(url, options, calls);
    if (value && value.__status) return {ok:false, status:value.__status, json:async () => value.body};
    return {ok:true, status:200, json:async () => value};
  };
  shell(dom.window);
  dom.window.eval(source);
  await settle();
  return {dom, window:dom.window, document:dom.window.document, calls, prompts};
}

test('renders unavailable installation as a readable blocked state', async () => {
  const ui = await fixture(async () => overview({available:false, items:[],
    can_propose:false, detail:'Configure trusted promotion controls.'}));
  assert.match(ui.document.getElementById('research-promotions-list').textContent,
    /not configured/i);
  assert.match(ui.document.getElementById('research-promotions-readiness').textContent,
    /trusted promotion controls/i);
  assert.match(ui.document.getElementById('research-promotions-status').textContent,
    /read-only/i);
  ui.dom.window.close();
});

test('creates a candidate request using only selected safe server names', async () => {
  let submitted;
  let reads = 0;
  const ui = await fixture(async (url, options) => {
    if (options.method === 'POST') {
      submitted = JSON.parse(options.body);
      return candidate({candidate_id:'candidate-new'});
    }
    reads += 1;
    return overview({items: reads > 1 ? [candidate({candidate_id:'candidate-new'})] : []});
  });
  const form = ui.document.getElementById('research-promotion-form');
  form.elements.run_id.value = 'run-1';
  form.elements.target_preset.value = 'installed-app';
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.equal(submitted.candidate_id, 'candidate-new');
  assert.equal(submitted.run_id, 'run-1');
  assert.equal(submitted.target_preset, 'installed-app');
  assert.deepEqual(Object.keys(submitted).sort(),
    ['candidate_id', 'confirm', 'context', 'run_id', 'target_preset']);
  assert.equal(Object.hasOwn(submitted, 'study'), false);
  assert.equal(Object.hasOwn(submitted, 'artifacts'), false);
  assert.equal(Object.hasOwn(submitted, 'target'), false);
  assert.equal(Object.hasOwn(submitted, 'resources'), false);
  assert.equal(Object.hasOwn(submitted, 'tenant'), false);
  assert.equal(Object.hasOwn(submitted, 'principal'), false);
  assert.equal(Object.hasOwn(submitted, 'authority'), false);
  ui.dom.window.close();
});

test('renders candidate evidence as text and hides management controls from researchers', async () => {
  const unsafe = '<img src=x onerror=alert(1)>';
  const ui = await fixture(async () => overview({can_manage:false, items:[candidate({
    candidate_id:'candidate-safe', block:{detail:unsafe, remediation:[]},
  })]}));
  const list = ui.document.getElementById('research-promotions-list');
  assert.match(list.textContent, /<img src=x/);
  assert.equal(list.querySelector('img'), null);
  assert.equal(list.querySelector('form'), null);
  assert.equal([...list.querySelectorAll('button')].length, 0);
  assert.match(list.textContent, /installed-app/);
  ui.dom.window.close();
});

test('keeps negative studies visible without an advancement control', async () => {
  const ui = await fixture(async () => overview({items:[candidate({
    state:'not_advancing',
    study:{conclusion:'negative', evaluator_id:'sealed-evaluator', evaluator_version:'v1'},
    block:{detail:'This result cannot advance to production.', remediation:[]},
  })]}));
  const list = ui.document.getElementById('research-promotions-list');
  assert.match(list.textContent, /negative/i);
  assert.match(list.textContent, /cannot advance/i);
  assert.equal([...list.querySelectorAll('button')].some(button => /Approve/.test(button.textContent)), false);
  ui.dom.window.close();
});

test('submits an independent app review with the current context and exact revision', async () => {
  let submitted;
  let reads = 0;
  const ui = await fixture(async (url, options) => {
    if (options.method === 'POST') {
      submitted = JSON.parse(options.body);
      return candidate({state:'authorized', revision:2});
    }
    reads += 1;
    return overview({items:[candidate({state:reads > 1 ? 'authorized' : 'awaiting_review',
      revision:reads > 1 ? 2 : 1})]});
  });
  const form = ui.document.querySelector('#research-promotions-list form');
  form.querySelector('textarea').value = 'Verified current rights and the rollback plan.';
  [...form.querySelectorAll('button')].find(button => /Approve/.test(button.textContent)).click();
  await settle();
  assert.deepEqual(submitted, {context:CONTEXT, confirm:true, expected_revision:1,
    approve:true, reason_code:'reviewed_scope',
    note:'Verified current rights and the rollback plan.'});
  assert.match(ui.document.getElementById('research-promotions-list').textContent, /Approved for preparation/);
  ui.dom.window.close();
});

test('staging requires the visible confirmation and never accepts browser authority fields', async () => {
  let submitted;
  const ui = await fixture(async (url, options) => {
    if (options.method === 'POST') {
      submitted = JSON.parse(options.body);
      return candidate({state:'staged', revision:3});
    }
    return overview({items:[candidate({state:'authorized', revision:2})]});
  });
  const stage = [...ui.document.querySelectorAll('#research-promotions-list button')]
    .find(button => button.textContent === 'Stage candidate');
  stage.click();
  await settle();
  assert.deepEqual(submitted, {context:CONTEXT, confirm:true, expected_revision:2});
  assert.equal(Object.hasOwn(submitted, 'tenant'), false);
  assert.equal(Object.hasOwn(submitted, 'principal'), false);
  assert.equal(Object.hasOwn(submitted, 'authority'), false);
  ui.dom.window.close();
});

test('actions confirm in the page dialog and failures read as plain sentences', async () => {
  const ui = await fixture(async (url, options) => {
    if (options.method === 'POST') return {__status:409, body:{detail:'expected_revision mismatch for candidate row'}};
    return overview({items:[candidate({state:'authorized', revision:2})]});
  });
  ui.window.mvErrorText = (failure, action) => 'Could not ' + action + '. This was changed since you opened it.';
  [...ui.document.querySelectorAll('#research-promotions-list button')]
    .find(button => button.textContent === 'Stage candidate').click();
  await settle();
  assert.equal(ui.prompts.length, 1);
  // The confirm button repeats the chosen action, not a generic word.
  assert.equal(ui.prompts[0].options.okText, 'Stage candidate');
  const shown = ui.document.getElementById('research-promotions').textContent;
  assert.match(shown, /Could not update this candidate\. This was changed since you opened it/);
  assert.doesNotMatch(shown, /expected_revision|mismatch/);
  ui.dom.window.close();
});

test('a refused first load clears the list\'s Loading and says what happened above it', async () => {
  const dom = new JSDOM(html(), {url:'https://lightwork.test/research', runScripts:'outside-only'});
  const document = dom.window.document;
  document.getElementById('research-promotions-list').innerHTML = '<li>Loading…</li>';
  dom.window.mvErrorText = (failure, action) => `Could not ${action}. Try again later. (${failure.status})`;
  dom.window.fetch = async () => ({ok:false, status:503, json:async () => ({detail:'unavailable'})});
  shell(dom.window);
  dom.window.eval(source);
  await settle();
  assert.equal(document.getElementById('research-promotions-list').textContent, '');
  assert.equal(document.getElementById('research-promotions-status').textContent, 'Could not load candidate promotions. Try again later. (503)');
  dom.window.close();
});
