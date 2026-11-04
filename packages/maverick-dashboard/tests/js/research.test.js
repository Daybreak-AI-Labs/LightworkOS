'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');

const source = fs.readFileSync(
  path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-research.js'),
  'utf8',
);
const CONTEXT = 'c'.repeat(64);
const DIGEST = 'd'.repeat(64);
const REVIEW = 'e'.repeat(64);
const OUTPUT = 'f'.repeat(64);
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

function html() {
  return `<div id="research-lab" data-context="${CONTEXT}">
    <p id="research-status"></p><p id="research-readiness"></p>
    <button id="research-refresh" type="button"></button>
    <details id="research-settings" hidden><p id="research-settings-readiness"></p>
      <form id="research-settings-form">
        <input name="enable" type="checkbox"><input name="image_id" required pattern="sha256:[a-f0-9]{64}">
        <input name="queue_seconds" type="number" min="30" max="86400" required value="3600">
        <div id="research-evaluators"></div><button id="research-add-evaluator" type="button"></button>
        <input name="timeout_seconds" type="number" min="0.1" max="300" step="0.1" required value="10">
        <input name="output_bytes" type="number" min="1024" max="1048576" required value="65536">
        <input name="memory_bytes" type="number" min="33554432" max="1073741824" required value="134217728">
        <input name="scratch_bytes" type="number" min="1048576" max="268435456" required value="16777216">
        <input name="pids" type="number" min="8" max="256" required value="32">
        <input name="cpus" type="number" min="0.1" max="2" step="0.1" required value="0.5">
        <input name="confirm" type="checkbox"><button id="research-settings-save" type="submit"></button>
      </form>
    </details>
    <form id="research-submit">
      <input name="files" type="file" multiple required><p id="research-files"></p>
      <select name="entrypoint" required><option value=""></option></select>
      <select name="evaluator_id" required><option value=""></option></select>
      <input name="confirm" type="checkbox"><button id="research-submit-button" type="submit"></button>
    </form>
    <ul id="research-jobs"></ul>
    <section id="research-review-panel" hidden>
      <select id="research-review-choice"><option value=""></option></select>
      <button id="research-open-review" type="button"></button><div id="research-review-detail"></div>
      <input id="research-dispatch-confirm" type="checkbox">
      <button id="research-dispatch" type="button"></button>
      <button id="research-admin-cancel" type="button"></button>
    </section>
  </div>`;
}

function job(changes = {}) {
  return {id:'research-1', revision:1, status:'queued', input_sha256:'a'.repeat(64),
    evaluator_id:'smoke', submitted_by:'user:researcher@example.test',
    next_action:'Await administrator review', ...changes};
}

function overview(changes = {}) {
  return {context:CONTEXT, jobs:[], review_queue:[], can_dispatch:true,
    execution_available:true, evaluators:[{id:'smoke', version:'v1'}],
    settings:{settings_sha256:DIGEST, enabled:true, valid:true, writable:true, source:'dashboard',
      image_id:`sha256:${'b'.repeat(64)}`, queue_seconds:3600,
      evaluators:[{id:'smoke', version:'v1', stdout_sha256:OUTPUT}],
      limits:{timeout_seconds:10, output_bytes:65536, memory_bytes:134217728,
        scratch_bytes:16777216, pids:32, cpus:0.5}}, ...changes};
}

async function fixture(handler) {
  const dom = new JSDOM(html(), {url:'https://lightwork.test/research', runScripts:'outside-only'});
  const calls = [];
  dom.window.crypto.randomUUID = () => '00000000-0000-4000-8000-000000000001';
  dom.window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    const value = await handler(url, options, calls);
    return value && Object.hasOwn(value, 'ok') ? value : {ok:true, status:200, json:async () => value};
  };
  shell(dom.window);
  dom.window.eval(source);
  await settle();
  return {dom, window:dom.window, document:dom.window.document, calls};
}

async function settle() {
  for (let index = 0; index < 10; index += 1) await tick();
}

test('disabled execution keeps recovery and exact-source review available without queue review tokens', async () => {
  const unsafe = '<img src=x onerror=alert(1)>';
  const row = job({status:'completed', evaluation:{counts:{passed:0, failed:1}}, next_action:unsafe});
  const queued = job();
  const ui = await fixture(async () => overview({execution_available:false, can_dispatch:false,
    evaluators:[], jobs:[row, job({id:'research-2', status:'running'})], review_queue:[queued],
    settings:{settings_sha256:DIGEST, enabled:false, valid:false, writable:true, source:'dashboard'}}));
  assert.equal(ui.document.getElementById('research-review-panel').hidden, false);
  assert.equal(ui.document.getElementById('research-review-choice').options.length, 2);
  assert.equal(ui.document.getElementById('research-dispatch').disabled, true);
  assert.equal(ui.document.querySelectorAll('[data-research-job-cancel]').length, 1);
  assert.match(ui.document.getElementById('research-jobs').textContent, /Result: Failed \(0 passed, 1 failed\)/);
  assert.match(ui.document.getElementById('research-jobs').textContent, /Next step: <img/);
  assert.equal(ui.document.querySelector('#research-jobs img'), null);
  ui.dom.window.close();
});

test('run stays blocked until an exact review token and explicit confirmation are both current', async () => {
  let runs = 0;
  const queued = job();
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/review/research-1')) return {...queued, files:{'main.py':'print("ok")'}, review_sha256:REVIEW};
    if (url.endsWith('/jobs/research-1/run')) { runs += 1; return job({status:'completed', revision:4}); }
    return overview({review_queue:[queued]});
  });
  const choice = ui.document.getElementById('research-review-choice');
  choice.value = 'research-1';
  choice.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  assert.equal(ui.document.getElementById('research-open-review').disabled, false);
  ui.document.getElementById('research-open-review').click();
  await settle();
  assert.match(ui.document.getElementById('research-review-detail').textContent, /print\("ok"\)/);
  assert.equal(ui.document.getElementById('research-dispatch').disabled, true);
  const confirm = ui.document.getElementById('research-dispatch-confirm');
  confirm.checked = true;
  confirm.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  assert.equal(ui.document.getElementById('research-dispatch').disabled, false);
  ui.document.getElementById('research-dispatch').click();
  await settle();
  assert.equal(runs, 1);
  const request = ui.calls.find(call => call.url.endsWith('/jobs/research-1/run'));
  assert.deepEqual(JSON.parse(request.options.body), {
    context:CONTEXT, confirm:true, expected_revision:1, review_sha256:REVIEW,
  });
  ui.dom.window.close();
});

test('an exact review cannot dispatch while execution authority is unavailable', async () => {
  let mutations = 0;
  const queued = job();
  const ui = await fixture(async (url, options) => {
    if (options.method === 'POST') mutations += 1;
    if (url.endsWith('/review/research-1')) return {...queued, files:{'main.py':'pass'}, review_sha256:REVIEW};
    return overview({execution_available:false, can_dispatch:false, evaluators:[], review_queue:[queued],
      settings:{settings_sha256:DIGEST, enabled:true, valid:false, writable:true, source:'dashboard'}});
  });
  const choice = ui.document.getElementById('research-review-choice');
  choice.value = 'research-1'; choice.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  ui.document.getElementById('research-open-review').click(); await settle();
  const confirm = ui.document.getElementById('research-dispatch-confirm');
  confirm.checked = true; confirm.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  assert.equal(ui.document.getElementById('research-dispatch').disabled, true);
  ui.document.getElementById('research-dispatch').click(); await settle();
  assert.equal(mutations, 0);
  assert.equal(ui.document.getElementById('research-admin-cancel').disabled, false);
  ui.dom.window.close();
});

test('administrator can disable a damaged profile without satisfying its blank evaluator fields', async () => {
  let saved;
  let reads = 0;
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/settings') && options.method === 'PUT') {
      saved = JSON.parse(options.body);
      return {context:CONTEXT, settings:{settings_sha256:'1'.repeat(64), enabled:false, valid:false,
        writable:true, source:'dashboard'}};
    }
    reads += 1;
    return overview({execution_available:false, can_dispatch:false, evaluators:[],
      settings:{settings_sha256:DIGEST, enabled:true, valid:false, writable:true, source:'dashboard'}});
  });
  const form = ui.document.getElementById('research-settings-form');
  form.elements.enable.checked = false;
  form.elements.image_id.value = '';
  form.querySelector('[data-field="id"]').value = '';
  form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.deepEqual(saved, {context:CONTEXT, confirm:true, expected_settings_sha256:DIGEST, enable:false});
  assert.ok(reads >= 2);
  ui.dom.window.close();
});

test('unavailable settings storage and wrong-context overviews fail closed', async t => {
  await t.test('unavailable settings', async () => {
    const ui = await fixture(async () => overview({execution_available:false, can_dispatch:false, evaluators:[],
      settings:{settings_sha256:'', enabled:false, valid:false, writable:false, source:'unavailable'}}));
    assert.equal(ui.document.getElementById('research-settings-save').disabled, true);
    assert.equal(ui.document.querySelector('#research-settings-form [name="enable"]').disabled, true);
    assert.match(ui.document.getElementById('research-settings-readiness').textContent, /cannot be saved right now/);
    ui.dom.window.close();
  });
  await t.test('operator-owned settings', async () => {
    const ui = await fixture(async () => overview({
      settings:{settings_sha256:DIGEST, enabled:true, valid:true,
        writable:false, source:'operator_overlay', image_id:`sha256:${'b'.repeat(64)}`,
        evaluators:[{id:'smoke', version:'v1', stdout_sha256:OUTPUT}],
        limits:{timeout_seconds:10, output_bytes:65536, memory_bytes:134217728,
          scratch_bytes:16777216, pids:32, cpus:0.5}},
    }));
    assert.equal(ui.document.getElementById('research-settings-save').disabled, true);
    assert.match(ui.document.getElementById('research-settings-readiness').textContent, /managed by your IT team and cannot be changed here/);
    ui.dom.window.close();
  });
  await t.test('wrong context', async () => {
    const ui = await fixture(async () => overview({context:'0'.repeat(64)}));
    assert.match(ui.document.getElementById('research-status').textContent, /switched account or workspace/i);
    assert.equal(ui.document.getElementById('research-submit-button').disabled, true);
    ui.dom.window.close();
  });
});

test('source submission carries only selected UTF-8 bytes and current reviewed fields', async () => {
  let submitted;
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/jobs') && options.method === 'POST') {
      submitted = JSON.parse(options.body);
      return job();
    }
    return overview();
  });
  const form = ui.document.getElementById('research-submit');
  const fakeFile = {name:'main.py', text:async () => 'print("accepted")\n'};
  Object.defineProperty(form.elements.files, 'files', {configurable:true, value:[fakeFile]});
  // JSDOM does not update the native file input's valueMissing flag when its
  // read-only FileList is replaced for a test. The application still checks
  // the selectedFiles map populated by the change handler.
  form.elements.files.required = false;
  form.elements.files.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  await settle();
  form.elements.entrypoint.value = 'main.py';
  form.elements.evaluator_id.value = 'smoke';
  form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  assert.equal(ui.document.getElementById('research-submit-button').disabled, false);
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.equal(submitted.context, CONTEXT);
  assert.deepEqual(submitted.files, {'main.py':'print("accepted")\n'});
  assert.equal(submitted.entrypoint, 'main.py');
  assert.equal(submitted.evaluator_id, 'smoke');
  assert.match(submitted.idempotency_key, /^ui-/);
  ui.dom.window.close();
});

test('refresh discards stale settings edits and loads the latest CAS revision', async () => {
  const latest = '1'.repeat(64);
  let reads = 0;
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/settings') && options.method === 'PUT') {
      return {ok:false, status:409, json:async () => ({detail:'changed'})};
    }
    reads += 1;
    return overview({settings:{...overview().settings,
      settings_sha256:reads > 1 ? latest : DIGEST,
      queue_seconds:reads > 1 ? 7200 : 3600}});
  });
  const form = ui.document.getElementById('research-settings-form');
  form.elements.queue_seconds.value = '4000';
  form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.match(ui.document.getElementById('research-status').textContent, /changed/i);

  ui.document.getElementById('research-refresh').click();
  await settle();
  assert.equal(form.dataset.settingsSha256, latest);
  assert.equal(form.elements.queue_seconds.value, '7200');
  ui.dom.window.close();
});

test('invalid replacement files clear an earlier valid submission selection', async () => {
  let submissions = 0;
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/jobs') && options.method === 'POST') submissions += 1;
    return overview();
  });
  const form = ui.document.getElementById('research-submit');
  form.elements.files.required = false;
  Object.defineProperty(form.elements.files, 'files', {configurable:true,
    value:[{name:'main.py', text:async () => 'print("valid")\n'}]});
  form.elements.files.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  await settle();
  form.elements.entrypoint.value = 'main.py';
  form.elements.evaluator_id.value = 'smoke';
  form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  assert.equal(ui.document.getElementById('research-submit-button').disabled, false);

  Object.defineProperty(form.elements.files, 'files', {configurable:true,
    value:[{name:'too-large.py', text:async () => 'x'.repeat(262145)}]});
  form.elements.files.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  await settle();
  assert.equal(ui.document.getElementById('research-submit-button').disabled, true);
  assert.equal(form.elements.entrypoint.options.length, 1);
  assert.match(ui.document.getElementById('research-files').textContent, /No files chosen/);
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.equal(submissions, 0);
  ui.dom.window.close();
});

test('a file change during refresh clears old source synchronously and cannot submit it', async () => {
  const refreshGate = deferred();
  let reads = 0;
  let submissions = 0;
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/jobs') && options.method === 'POST') submissions += 1;
    reads += 1;
    if (reads === 2) return refreshGate.promise;
    return overview();
  });
  const form = ui.document.getElementById('research-submit');
  form.elements.files.required = false;
  Object.defineProperty(form.elements.files, 'files', {configurable:true,
    value:[{name:'old.py', text:async () => 'print("old")\n'}]});
  form.elements.files.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  await settle();
  form.elements.entrypoint.value = 'old.py';
  form.elements.evaluator_id.value = 'smoke';
  form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  assert.equal(ui.document.getElementById('research-submit-button').disabled, false);

  ui.document.getElementById('research-refresh').click();
  await tick();
  assert.equal(form.elements.files.disabled, true);
  Object.defineProperty(form.elements.files, 'files', {configurable:true,
    value:[{name:'replacement.py', text:async () => 'print("replacement")\n'}]});
  form.elements.files.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  assert.equal(form.elements.confirm.checked, false);
  assert.equal(form.elements.entrypoint.options.length, 1);
  refreshGate.resolve(overview());
  await settle();
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await settle();
  assert.equal(submissions, 0);
  assert.equal(ui.document.getElementById('research-submit-button').disabled, true);
  ui.dom.window.close();
});

test('settings fields are frozen during save and the submitted snapshot cannot drift', async () => {
  const saveGate = deferred();
  let saved;
  let reads = 0;
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/settings') && options.method === 'PUT') {
      saved = JSON.parse(options.body);
      return saveGate.promise;
    }
    reads += 1;
    return overview({settings:{...overview().settings, queue_seconds:reads > 1 ? 5000 : 3600}});
  });
  const form = ui.document.getElementById('research-settings-form');
  form.elements.queue_seconds.value = '4000';
  form.elements.confirm.checked = true;
  form.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  form.dispatchEvent(new ui.window.Event('submit', {bubbles:true, cancelable:true}));
  await tick();
  assert.equal(form.elements.image_id.disabled, true);
  assert.equal(form.elements.queue_seconds.disabled, true);
  assert.equal(form.querySelector('[data-field="id"]').disabled, true);
  form.elements.queue_seconds.value = '9000';
  form.dispatchEvent(new ui.window.Event('input', {bubbles:true}));
  saveGate.resolve({context:CONTEXT, settings:overview().settings});
  await settle();
  assert.equal(saved.queue_seconds, 4000);
  assert.equal(form.elements.queue_seconds.value, '5000');
  ui.dom.window.close();
});

test('a delayed exact-source response cannot attach to a different review choice', async () => {
  const reviewGate = deferred();
  const first = job();
  const second = job({id:'research-2'});
  const ui = await fixture(async url => {
    if (url.endsWith('/review/research-1')) return reviewGate.promise;
    return overview({review_queue:[first, second]});
  });
  const choice = ui.document.getElementById('research-review-choice');
  choice.value = first.id;
  choice.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  ui.document.getElementById('research-open-review').click();
  await tick();
  assert.equal(choice.disabled, true);
  choice.value = second.id;
  choice.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  reviewGate.resolve({...first, files:{'main.py':'print("one")'}, review_sha256:REVIEW});
  await settle();
  assert.equal(ui.document.getElementById('research-review-detail').textContent, '');
  assert.equal(ui.document.getElementById('research-dispatch').disabled, true);
  assert.match(ui.document.getElementById('research-status').textContent, /could not be opened for review/);
  ui.dom.window.close();
});

test('an administrator keeps the exact cross-user evaluation result after dispatch', async () => {
  let completed = false;
  const queued = job();
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/review/research-1')) {
      return {...queued, files:{'main.py':'print("ok")'}, review_sha256:REVIEW};
    }
    if (url.endsWith('/jobs/research-1/run') && options.method === 'POST') {
      completed = true;
      return job({status:'completed', revision:4,
        evaluation:{counts:{passed:1, failed:0}},
        observation:{reason:'completed', exit_code:0},
        next_action:'Share the reviewed result.'});
    }
    return overview({review_queue:completed ? [] : [queued]});
  });
  const choice = ui.document.getElementById('research-review-choice');
  choice.value = queued.id;
  choice.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  ui.document.getElementById('research-open-review').click();
  await settle();
  const confirm = ui.document.getElementById('research-dispatch-confirm');
  confirm.checked = true;
  confirm.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  ui.document.getElementById('research-dispatch').click();
  await settle();
  const detail = ui.document.getElementById('research-review-detail').textContent;
  assert.match(detail, /1 passed · 0 failed/);
  assert.match(detail, /finished normally/);
  assert.match(detail, /Share the reviewed result/);
  assert.match(detail, /print\("ok"\)/);
  assert.equal(ui.document.getElementById('research-dispatch').disabled, true);
  ui.dom.window.close();
});

test('a completed cross-user run remains visible when the follow-up refresh fails', async () => {
  let ran = false;
  const queued = job();
  const ui = await fixture(async (url, options) => {
    if (url.endsWith('/review/research-1')) {
      return {...queued, files:{'main.py':'print("durable")'}, review_sha256:REVIEW};
    }
    if (url.endsWith('/jobs/research-1/run') && options.method === 'POST') {
      ran = true;
      return job({status:'completed', revision:4,
        evaluation:{counts:{passed:0, failed:1}},
        observation:{reason:'nonzero_exit', exit_code:7},
        next_action:'Inspect the exact failed output.'});
    }
    if (ran) return {ok:false, status:503, json:async () => ({detail:'private'})};
    return overview({review_queue:[queued]});
  });
  const choice = ui.document.getElementById('research-review-choice');
  choice.value = queued.id;
  choice.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  ui.document.getElementById('research-open-review').click();
  await settle();
  const confirm = ui.document.getElementById('research-dispatch-confirm');
  confirm.checked = true;
  confirm.dispatchEvent(new ui.window.Event('change', {bubbles:true}));
  ui.document.getElementById('research-dispatch').click();
  await settle();
  const detail = ui.document.getElementById('research-review-detail').textContent;
  assert.match(detail, /0 passed · 1 failed/);
  assert.match(detail, /stopped with a problem \(nonzero exit\)/i);
  assert.match(detail, /Inspect the exact failed output/);
  assert.match(detail, /print\("durable"\)/);
  assert.match(ui.document.getElementById('research-status').textContent,
    /program finished.*result is shown below/i);
  ui.dom.window.close();
});

test('a refused first load replaces Checking and Loading with what happened', async () => {
  const dom = new JSDOM(html(), {url:'https://lightwork.test/research', runScripts:'outside-only'});
  const document = dom.window.document;
  document.getElementById('research-readiness').textContent = 'Checking…';
  document.getElementById('research-jobs').innerHTML = '<li>Loading…</li>';
  dom.window.mvErrorText = (failure, action) => `Could not ${action}. Ask an administrator. (${failure.status})`;
  dom.window.fetch = async () => ({ok:false, status:403, json:async () => ({detail:'Current research workspace authority is required'})});
  shell(dom.window);
  dom.window.eval(source);
  await settle();
  assert.equal(document.getElementById('research-readiness').textContent,
    'Could not check whether experiments can run. Ask an administrator. (403)');
  assert.equal(document.getElementById('research-jobs').textContent, 'Could not load your experiments. Ask an administrator. (403)');
  assert.equal(document.getElementById('research-status').textContent, 'Your current account cannot perform that research action.');
  dom.window.close();
});
