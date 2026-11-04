'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const markup = fs.readFileSync(path.join(folder, 'templates/_portal_routing_key.html'), 'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
const initial = {managed_by_server: false, configured: true, rotated_at: 1700000000, previous_keys_open: 0, grace_until: null, grace_hours: [0, 1, 24, 72, 168, 720]};
async function fixture(respond) {
  const dom = new JSDOM(markup, {url: 'https://app.example/third-party/collaboration', runScripts: 'outside-only'}), w = dom.window, calls = [];
  w.fetch = async (url, options = {}) => { calls.push({url, options, body: options.body ? JSON.parse(options.body) : null}); return respond(url, options); };
  shell(w);
  w.eval(fs.readFileSync(path.join(folder, 'static/lightwork-portal-routing-key.js'), 'utf8'));
  const settle = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
  await settle();
  return {w, calls, settle, el: (id) => w.document.getElementById('portal-key-' + id), root: w.document.getElementById('portal-key')};
}
const ok = (data) => new Response(JSON.stringify(data), {headers: {'Content-Type': 'application/json'}});
test('people who are not installation administrators never see the panel', async (t) => {
  const ui = await fixture(() => new Response('{}', {status: 403}));
  t.after(() => ui.w.close());
  assert.equal(ui.root.hidden, true);
});
test('changing the key needs the understanding box and a confirmation, and sends the chosen grace period', async (t) => {
  const ui = await fixture((url) => ok(url.endsWith('/rotate') ? {...initial, previous_keys_open: 1, grace_until: 1700086400} : initial));
  t.after(() => ui.w.close());
  assert.equal(ui.root.hidden, false);
  assert.equal(ui.el('rotate').disabled, true);
  ui.el('confirm').checked = true; ui.el('confirm').dispatchEvent(new ui.w.Event('change'));
  let asked = ''; ui.w.mvConfirm = async (message) => { asked = message; return false; };
  ui.el('rotate').click(); await ui.settle();
  assert.match(asked, /Old vendor addresses keep working/);
  assert.equal(ui.calls.some((c) => c.url.endsWith('/rotate')), false);
  ui.w.mvConfirm = async () => true; ui.el('grace').value = '72';
  ui.el('rotate').click(); await ui.settle();
  const call = ui.calls.find((c) => c.url.endsWith('/rotate'));
  assert.deepEqual(call.body, {confirm: true, grace_hours: 72});
  assert.match(ui.el('state').textContent, /was changed/);
  assert.equal(ui.el('confirm').checked, false);
});
test('a key set on the server is explained and cannot be changed here', async (t) => {
  const ui = await fixture(() => ok({...initial, managed_by_server: true}));
  t.after(() => ui.w.close());
  assert.equal(ui.el('form').hidden, true);
  assert.match(ui.el('state').textContent, /set on the server/);
});
