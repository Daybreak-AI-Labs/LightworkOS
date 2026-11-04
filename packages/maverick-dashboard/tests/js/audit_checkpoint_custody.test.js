'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const base = path.resolve(__dirname, '../../maverick_dashboard');

async function page(t, reply) {
  const html = fs.readFileSync(path.join(base, 'templates/_audit_checkpoint_custody.html'), 'utf8')
    .replace(/<script[\s\S]*?<\/script>/g, '');
  const dom = new JSDOM(`<!doctype html><body>${html}</body>`, {runScripts: 'outside-only', url: 'https://lightwork.test/audit'});
  t.after(() => dom.window.close());
  const w = dom.window, calls = [];
  w.mvFetchJSON = async (url, options) => { calls.push({url, options}); return reply(url, options); };
  w.eval(fs.readFileSync(path.join(base, 'static/lightwork-audit-checkpoint-custody.js'), 'utf8'));
  for (let i = 0; i < 20; i += 1) await new Promise(resolve => setImmediate(resolve));
  return {w, d: w.document, calls};
}

test('a failed first read leaves no saved copy requests at Loading and keeps Refresh usable', async t => {
  const ui = await page(t, () => { const error = new Error('Could not read the checkpoint copy. Try again.'); error.status = 503; throw error; });
  assert.equal(ui.calls.length, 1);
  assert.doesNotMatch(ui.d.getElementById('acc-requests').textContent, /Loading/);
  assert.equal(ui.d.getElementById('acc-requests').textContent, 'Saved copy requests could not be read. Use Refresh choices to try again.');
  assert.equal(ui.d.getElementById('acc-status').textContent, 'Could not read the checkpoint copy. Try again.');
  assert.equal(ui.d.getElementById('acc-refresh').disabled, false);
  // With nothing read there is no account or checkpoint to act on, so the two
  // actions stay off until a Refresh succeeds instead of failing on a null.
  assert.equal(ui.d.getElementById('acc-review').disabled, true);
  assert.equal(ui.d.getElementById('acc-check').disabled, true);
});

test('a first read refused for lost access shows one instruction: sign in or reload, with every control locked', async t => {
  const ui = await page(t, (url, options) => {
    // The shared fetch helper clears private details before it throws.
    options.onAccess();
    const error = new Error('Your access changed.'); error.status = 401; error.accessChanged = true; throw error;
  });
  assert.equal(ui.calls.length, 1);
  assert.equal(ui.d.getElementById('acc-requests').textContent, '');
  assert.equal(ui.d.getElementById('acc-status').textContent,
    'Your access changed. Sign in or reload the current page before continuing. The saved Original reference was kept.');
  assert.equal(ui.d.getElementById('acc-refresh').disabled, true);
  assert.doesNotMatch(ui.d.getElementById('independent-checkpoint-custody').textContent, /Use Refresh choices/);
});
