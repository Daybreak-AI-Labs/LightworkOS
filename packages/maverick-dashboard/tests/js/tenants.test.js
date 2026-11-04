'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-tenants.js'), 'utf8');
const markup = `<form id="tenant-add"><input name="display_name" value="Acme Finance"><select name="plan"><option value="pro" selected>Pro</option></select>
<input type="checkbox" name="no_limit" checked data-limit-toggle><input name="max_daily_dollars" data-limit-amount disabled><button>Create</button></form>
<p id="tenant-add-msg"></p><p id="tenant-quota-msg"></p>
<table><tr data-tenant-row="acme" data-tenant-name="Acme Inc"><td><select data-tenant-plan="acme" data-current="free"><option value="free" selected>Free</option><option value="pro">Pro</option></select></td>
<td><form class="tenant-quota" data-tenant="acme"><input type="checkbox" name="no_limit" data-limit-toggle><input name="max_daily_dollars" data-limit-amount value="25"><button>Save</button></form></td>
<td><button data-tenant-action="suspend">Pause</button><button data-tenant-action="delete">Remove</button></td></tr></table>`;

// The shell's shared helpers (mvFetchJSON) load before page scripts, as in
// base.html; this fixture's own stand-ins for the other helpers are kept.
function withShell(window) {
  const kept = Object.fromEntries(Object.keys(window).filter((k) => k.startsWith('mv')).map((k) => [k, window[k]]));
  if (!window.matchMedia) window.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-ui.js'), 'utf8'));
  Object.assign(window, kept);
}

async function fixture(answer = true, status = 201) {
  const dom = new JSDOM(markup, {url: 'https://lightwork.example/tenants', runScripts: 'outside-only'});
  const {window} = dom, calls = [], asked = [];
  window.fetch = async (url, options) => { calls.push({url, options}); return new Response('{"id":"acme-finance"}', {status}); };
  window.mvConfirm = async (message) => { asked.push(message); return answer; };
  window.mvErrorText = (_f, action) => 'Could not ' + action + '.';
  window.setTimeout = () => 0;
  withShell(window);
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };
  return {window, doc: window.document, calls, asked, settle};
}

test('creating sends a name and no typed id', async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById('tenant-add').dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  const body = JSON.parse(ui.calls[0].options.body);
  assert.deepEqual(body, {display_name: 'Acme Finance', plan: 'pro', max_daily_dollars: 0});
  assert.match(ui.doc.getElementById('tenant-add-msg').textContent, /created/);
});

test('duplicate workspace names show the server explanation', async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.window.mvPlainDetail = (detail) => detail;
  ui.window.fetch = async () => new Response(JSON.stringify({detail: 'A workspace with that name already exists. Choose another name.'}), {status: 409});
  ui.doc.getElementById('tenant-add').dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.equal(ui.doc.getElementById('tenant-add-msg').textContent, 'A workspace with that name already exists. Choose another name.');
});

test('pausing and removing ask first and do nothing when cancelled', async (t) => {
  const ui = await fixture(false);
  t.after(() => ui.window.close());
  ui.doc.querySelector('[data-tenant-action="suspend"]').click();
  ui.doc.querySelector('[data-tenant-action="delete"]').click();
  await ui.settle();
  assert.equal(ui.calls.length, 0);
  assert.match(ui.asked[0], /Pause Acme Inc\?/);
  assert.match(ui.asked[1], /Remove Acme Inc/);
});

test('daily limit posts the amount; failures read as sentences', async (t) => {
  const ui = await fixture(true, 500);
  t.after(() => ui.window.close());
  ui.doc.querySelector('form.tenant-quota').dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.equal(ui.calls[0].url, '/api/v1/admin/tenants/acme/quota');
  assert.deepEqual(JSON.parse(ui.calls[0].options.body), {max_daily_dollars: 25});
  assert.equal(ui.doc.getElementById('tenant-quota-msg').textContent, 'Could not save the daily limit.');
});
