"use strict";
// The practice-challenge page: a refusal that saved nothing must not leave the page waiting for an original.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(root, 'static/lightwork-approval-challenges.js'), 'utf8');
const raw = fs.readFileSync(path.join(root, 'templates/approval_challenges.html'), 'utf8');
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const STORAGE = 'lightwork:approval-challenge-original';

function reply(body, status = 200) {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  return {ok: status >= 200 && status < 300, status, body: {getReader() {
    let finished = false;
    return {read: async () => finished ? {done: true} : (finished = true, {done: false, value: bytes}),
            cancel: async () => {}, releaseLock() {}};
  }}};
}
const listing = {context: 'ctx', enabled: true, can_configure: false, offset: 0, total: 0, next: null, previous: null,
                 detail: 'Ready.', patterns: [{label: 'Change a limit', value: 'limit'}], records: []};

function page(fetch) {
  const html = raw.replace(/\{%[\s\S]*?%\}/g, '').replace(/\{\{[\s\S]*?\}\}/g, '');
  const dom = new JSDOM(html, {url: 'http://localhost/learning/approval-challenges', runScripts: 'outside-only'});
  dom.window.TextDecoder = TextDecoder;
  dom.window.fetch = fetch;
  dom.window.mvConfirm = async () => true;
  dom.window.eval(script);
  return dom;
}
async function submitGenerate(dom) {
  const d = dom.window.document;
  d.querySelector('#ac-generate select[name="family"]').value = 'limit';
  d.getElementById('ac-generate').dispatchEvent(new dom.window.Event('submit', {cancelable: true}));
  for (let i = 0; i < 6; i++) await tick();
}

test('a refusal that saved nothing leaves the page free to try again', async () => {
  const dom = page(async (url, options = {}) => options.method === 'POST'
    ? reply({detail: 'This workspace has 256 saved practice records. Remove one to make space.'}, 409)
    : reply(listing));
  await tick(); await tick();
  const d = dom.window.document;
  await submitGenerate(dom);
  assert.equal(dom.window.sessionStorage.getItem(STORAGE), null, 'no original is waited for');
  assert.match(d.getElementById('ac-status').textContent, /256 saved practice records/);
  assert.doesNotMatch(d.getElementById('ac-status').textContent, /outcome may be recorded/);
  assert.equal(d.querySelector('#ac-generate button').disabled, false, 'building a challenge is possible again');
  dom.window.close();
});

test('a failure that may have saved something still waits for its original', async () => {
  const dom = page(async (url, options = {}) => options.method === 'POST'
    ? reply({detail: 'The local challenge record could not be checked.'}, 503)
    : (url.includes('/ACP-') ? reply({detail: 'Not found.'}, 404) : reply(listing)));
  await tick(); await tick();
  const d = dom.window.document;
  await submitGenerate(dom);
  assert.ok(dom.window.sessionStorage.getItem(STORAGE), 'the original operation is kept for readback');
  assert.match(d.getElementById('ac-status').textContent, /outcome may be recorded/);
  assert.equal(d.querySelector('#ac-generate button').disabled, true);
  dom.window.close();
});
