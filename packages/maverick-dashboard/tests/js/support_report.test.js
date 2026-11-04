// Run with: node --test packages/maverick-dashboard/tests/js/support_report.test.js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const {shell} = require('./_shell');
const base = path.join(__dirname, '../../maverick_dashboard');
const source = fs.readFileSync(path.join(base, 'static/lightwork-support.js'), 'utf8');
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const page = `<section id="support-center" data-context="ctx"><button id="support-prepare"></button><p id="support-status"></p>
<section id="support-result" hidden><p id="support-reference"></p><ul id="support-readiness"></ul><div id="support-readable"></div>
<pre id="support-preview"></pre><input type="checkbox" id="support-confirm"><button id="support-download"></button></section></section>`;

function harness(fetchImpl) {
  const dom = new JSDOM(page, { runScripts: 'outside-only' });
  dom.window.fetch = fetchImpl;
  shell(dom.window);
  dom.window.eval(source);
  return dom;
}

test('the report is shown as readable rows, with the exact file kept under technical details', async () => {
  const bundle = { correlation_id: 'ref-1', generated_at: 'now', versions: { lightwork_core: '1.2.3' },
    readiness: { client_binding: 'ok', shield: 'not_configured' }, providers: { configured: true, known: ['anthropic'] } };
  const dom = harness(async () => ({ ok: true, status: 200, json: async () => ({ context: 'ctx', preview_id: 'a'.repeat(32), sha256: 'b'.repeat(64), bundle }) }));
  const d = dom.window.document;
  d.getElementById('support-prepare').click(); await tick(); await tick();
  const text = d.getElementById('support-readable').textContent;
  assert.match(text, /Lightwork core/i); assert.match(text, /1\.2\.3/); assert.match(text, /Yes/);
  assert.doesNotMatch(text, /[{}]/);
  assert.deepEqual(JSON.parse(d.getElementById('support-preview').textContent), bundle);
  assert.match(d.getElementById('support-readiness').textContent, /Safety controls: not configured/);
  dom.window.close();
});

test('a refusal with internal wording becomes a plain sentence', async () => {
  const dom = harness(async () => ({ ok: false, status: 409, json: async () => ({ detail: 'preview_id mismatch {x}' }) }));
  const d = dom.window.document;
  d.getElementById('support-prepare').click(); await tick(); await tick();
  assert.match(d.getElementById('support-status').textContent, /could not be confirmed/);
  assert.doesNotMatch(d.getElementById('support-status').textContent, /preview_id/);
  dom.window.close();
});
