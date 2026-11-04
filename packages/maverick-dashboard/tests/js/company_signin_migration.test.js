'use strict';
// The restricted company sign-in recovery sends the owner's authenticator code with the
// passphrase, and cancelling the review ends the proof on the server.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const assets = path.join(__dirname, '../../maverick_dashboard/static');
const script = fs.readFileSync(path.join(assets, 'lightwork-company-signin-migration.js'), 'utf8');
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };
const json = (status, body) => new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});
const RECOVERY = `<main data-company-migration data-recovery>
  <input data-owner-email value="owner@example.com">
  <input data-owner-password value="owner passphrase">
  <input data-owner-code value="">
  <select data-migration-choice disabled><option value="">Load first</option></select>
  <button data-migration-load></button>
  <button data-migration-review disabled></button>
  <div data-migration-full-review hidden></div>
  <div data-migration-confirm hidden><input type="checkbox" data-migration-ack><button data-migration-apply disabled></button><button data-migration-cancel></button></div>
  <p data-migration-message></p>
  <div data-migration-original-panel hidden><select data-migration-original></select><button data-migration-read-original></button></div>
  <p data-migration-next hidden></p>
</main>`;

function openRecovery(answer) {
  const dom = new JSDOM(RECOVERY, {url: 'https://lightwork.invalid/auth/company-signin-recovery', runScripts: 'outside-only'});
  const w = dom.window;
  w.TextDecoder = TextDecoder;
  w.fetch = async (url, options = {}) => answer(url, options);
  w.eval(script);
  return w.document;
}

test('the recovery lookup sends the owner code with the passphrase', async () => {
  const sent = [];
  const doc = openRecovery((url, options) => {
    sent.push({url, body: options.body ? JSON.parse(options.body) : null});
    return json(200, {context: 'a'.repeat(64), notice: 'n', checks: [], requests: []});
  });
  doc.querySelector('[data-owner-code]').value = '123456';
  doc.querySelector('[data-migration-load]').click();
  await settle();
  const lookup = sent.find(item => item.url === '/auth/company-signin-recovery/lookup');
  assert.deepEqual(lookup.body, {email: 'owner@example.com', password: 'owner passphrase', code: '123456'}); // pragma: allowlist secret - test fixture passphrase
});

test('cancelling the recovery review ends its proof on the server', async () => {
  const sent = [];
  const doc = openRecovery((url, options) => {
    sent.push({url, method: options.method});
    return json(200, {});
  });
  doc.querySelector('[data-migration-cancel]').click();
  await settle();
  assert.deepEqual(sent, [{url: '/auth/company-signin-recovery/cancel', method: 'POST'}]);
});
