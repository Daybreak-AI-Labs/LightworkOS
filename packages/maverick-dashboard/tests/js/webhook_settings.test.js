const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const {shell} = require('./_shell');
const base = path.join(__dirname, '../../maverick_dashboard');
const template = fs.readFileSync(path.join(base, 'templates/settings.html'), 'utf8');
const source = fs.readFileSync(path.join(base, 'static/lightwork-webhook-settings.js'), 'utf8');
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
function state(overrides = {}) { return { schema: 1, configured: false, outbound_configured: false, storage_writable: true, remove_keeps_outbound_configured: false, source: 'none', ownership: 'ignored', can_set: true,
  can_remove: false, app_copy_present: false, remove_keeps_configured: false, context: 'a'.repeat(64), expected_generation: 'MVKAR1:opaque-generation-a', ...overrides }; }
function reply(body, status = 200) { return { ok: status >= 200 && status < 300, status, json: async () => body }; }
async function harness(handler) {
  const dom = new JSDOM(template, { url: 'http://localhost/settings', runScripts: 'outside-only' });
  const calls = [];
  dom.window.fetch = async (url, init = {}) => { calls.push({ url, init }); return handler(url, init, calls); };
  shell(dom.window);
  dom.window.eval(source); await tick(); await tick();
  const get = name => dom.window.document.getElementById('wh-' + name);
  function enter(secret = 'synthetic-ui-key') { // pragma: allowlist secret
    get('secret').value = secret; get('secret').dispatchEvent(new dom.window.Event('input'));
    get('confirm').checked = true; get('confirm').dispatchEvent(new dom.window.Event('change'));
  }
  async function submit() { get('form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true })); await tick(); await tick(); }
  return { dom, calls, get, enter, submit, posts: () => calls.filter(row => row.init.method === 'POST') };
}

test('real Settings card loads current ownership without secrets or manual technical input', async () => {
  const h = await harness(async () => reply(state()));
  assert.match(h.get('state').textContent, /not set/);
  assert.equal(h.get('secret').type, 'password');
  assert.equal(h.get('secret').value, '');
  assert.equal(h.get('save').disabled, true);
  assert.doesNotMatch(h.get('form').textContent, /expected_generation|MVKAR1|JSON/);
  assert.notEqual(h.dom.window.document.activeElement, h.get('state'));
  h.dom.window.close();
});

test('active save needs deliberate confirmation and submits exact reviewed generation once', async () => {
  let release;
  const h = await harness(async (url, init) => init.method === 'POST' ? new Promise(resolve => { release = resolve; }) : reply(state()));
  h.enter(); await h.submit(); await h.submit();
  assert.equal(h.posts().length, 1);
  const body = new URLSearchParams(h.posts()[0].init.body.toString());
  assert.equal(body.get('expected_generation'), 'MVKAR1:opaque-generation-a');
  assert.equal(body.get('secret'), 'synthetic-ui-key');
  release(reply(state({ configured: true, outbound_configured: true, source: 'dashboard', can_remove: true, app_copy_present: true, result: 'active' })));
  await tick(); await tick();
  assert.match(h.get('state').textContent, /new signing secret is active/);
  assert.equal(h.get('secret').value, '');
  assert.equal(h.dom.window.document.activeElement, h.get('state'));
  h.dom.window.close();
});

test('deployment ownership blocks setting but gives an honest transfer limit', async () => {
  const h = await harness(async () => reply(state({ configured: true, source: 'external_secret', can_set: false })));
  h.enter(); await h.submit();
  assert.equal(h.posts().length, 0);
  assert.equal(h.get('secret').disabled, true);
  assert.equal(h.get('external').hidden, false);
  assert.match(h.get('external').textContent, /cannot make that transfer here/);
  h.dom.window.close();
});

test('removal explicitly warns when another secret remains active', async () => {
  const current = state({ configured: true, source: 'dashboard', can_remove: true, app_copy_present: true, remove_keeps_configured: true });
  const h = await harness(async (url, init) => reply(init.method === 'POST' ? state({ configured: true, source: 'config', result: 'app_copy_removed' }) : current));
  h.get('action').value = 'remove'; h.get('action').dispatchEvent(new h.dom.window.Event('change')); h.enter();
  assert.match(h.get('consequence').textContent, /does not turn off/);
  await h.submit();
  assert.equal(new URLSearchParams(h.posts()[0].init.body.toString()).get('secret'), '');
  assert.match(h.get('state').textContent, /existing secret remains active/);
  h.dom.window.close();
});

test('stale generation preserves entered work and requires a new deliberate confirmation', async () => {
  let gets = 0;
  const h = await harness(async (url, init) => init.method === 'POST' ? reply({ detail: 'never reflect server body' }, 409) : reply(state({ expected_generation: 'MVKAR1:generation-' + (++gets) })));
  h.enter(); await h.submit();
  assert.equal(h.get('secret').value, 'synthetic-ui-key');
  assert.equal(h.get('confirm').checked, false);
  assert.equal(h.get('save').disabled, true);
  assert.equal(h.posts().length, 1);
  assert.match(h.get('state').textContent, /settings changed/);
  assert.doesNotMatch(h.get('state').textContent, /never reflect/);
  h.dom.window.close();
});

test('uncertain network result reads back once without repeating the mutation or claiming success', async () => {
  const h = await harness(async (url, init) => { if (init.method === 'POST') throw new Error('synthetic transport secret'); return reply(state()); });
  h.enter(); await h.submit();
  assert.equal(h.posts().length, 1);
  assert.equal(h.calls.length, 3);
  assert.equal(h.get('secret').value, 'synthetic-ui-key');
  assert.match(h.get('state').textContent, /result is uncertain/);
  assert.doesNotMatch(h.get('state').textContent, /transport secret|is active/);
  h.dom.window.close();
});

test('lost authority clears the secret and disables the form', async () => {
  const h = await harness(async (url, init) => init.method === 'POST' ? reply({}, 403) : reply(state()));
  h.enter(); await h.submit();
  assert.equal(h.get('secret').value, '');
  assert.equal(h.get('save').disabled, true);
  assert.match(h.get('state').textContent, /administrator access changed/);
  h.dom.window.close();
});

test('malformed success is uncertain; no green state from a truthy response', async () => {
  const h = await harness(async (url, init) => reply(init.method === 'POST' ? { result: 'active', configured: true } : state()));
  h.enter(); await h.submit();
  assert.match(h.get('state').textContent, /result is uncertain/);
  assert.equal(h.get('secret').value, 'synthetic-ui-key');
  assert.equal(h.posts().length, 1);
  h.dom.window.close();
});

test('refresh failure preserves the entry but cannot enable another write', async () => {
  let count = 0;
  const h = await harness(async () => ++count === 1 ? reply(state()) : reply({}, 503));
  h.enter(); h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('secret').value, 'synthetic-ui-key');
  assert.equal(h.get('save').disabled, true);
  assert.equal(h.dom.window.document.activeElement, h.get('refresh'));
  assert.match(h.get('state').textContent, /could not be checked/);
  h.dom.window.close();
});

test('cancel clears local secret only and restores useful focus', async () => {
  const h = await harness(async () => reply(state()));
  h.enter(); h.get('cancel').click();
  assert.equal(h.get('secret').value, '');
  assert.equal(h.posts().length, 0);
  assert.equal(h.dom.window.document.activeElement, h.get('refresh'));
  h.dom.window.close();
});

test('another authorized account on refresh clears the first account draft', async () => {
  let reads = 0;
  const h = await harness(async () => reply(state({ context: (++reads === 1 ? 'a' : 'b').repeat(64) })));
  h.enter(); h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('secret').value, '');
  assert.equal(h.get('confirm').checked, false);
  assert.match(h.get('state').textContent, /account or workspace changed/);
  h.dom.window.close();
});

test('same account refresh keeps the entry but resets its confirmation', async () => {
  const h = await harness(async () => reply(state()));
  h.enter(); h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('secret').value, 'synthetic-ui-key');
  assert.equal(h.get('confirm').checked, false);
  h.dom.window.close();
});
