'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-finance-sod-check.js'), 'utf8');
const template = fs.readFileSync(path.join(folder, 'templates/finance_board.html'), 'utf8');

// The separation-of-duties card exactly as the template ships it.
const card = template.slice(template.indexOf('<section class="fb-card fb-span6" aria-labelledby="fb-t-sod">'));
const MARKUP = card.slice(0, card.indexOf('</section>') + '</section>'.length);
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve)); };

function fixture(respond) {
  const dom = new JSDOM('<!doctype html><body>' + MARKUP + '</body>',
    {url: 'https://lightwork.example/finance/board', runScripts: 'outside-only'});
  const {window} = dom, calls = [];
  window.fetch = async (url, options = {}) => { calls.push({url, options}); return respond(); };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '. Please try again.';
  window.eval(script);
  return {window, calls, $: (id) => window.document.getElementById(id)};
}

test('the button runs the check and lists each problem in plain words', async () => {
  const h = fixture(() => new Response(JSON.stringify({
    ok: false, teams: 70, summary: '1 problem found across 70 finance AI teams.',
    findings: [{team: 'Finance payments desk', sentence: 'This team can both move money (release payment) and record entries (stage payment batch).'}],
    technical: ["SoD CONFLICT: compartment 'finance_payments_desk' spans incompatible duties"]
  }), {headers: {'Content-Type': 'application/json'}}));
  assert.equal(h.$('fb-sod-check').textContent, 'Check separation of duties');
  h.$('fb-sod-check').click();
  await settle();
  assert.deepEqual(h.calls.map((c) => c.url), ['/api/v1/finance/sod-check']);
  assert.equal(h.$('fb-sod-check-status').textContent, '1 problem found across 70 finance AI teams.');
  const out = h.$('fb-sod-check-out');
  assert.match(out.querySelector('li').textContent, /^Finance payments desk: This team can both move money/);
  const details = out.querySelector('details');
  assert.equal(details.open, false);
  assert.equal(details.querySelector('summary').textContent, 'Technical details');
  assert.match(details.querySelector('pre').textContent, /SoD CONFLICT/);
  assert.equal(h.$('fb-sod-check').disabled, false);
});

test('a clean check says so, and a failure is a plain sentence', async () => {
  let fail = false;
  const h = fixture(() => (fail ? new Response('<h1>no</h1>', {status: 500})
    : new Response(JSON.stringify({ok: true, teams: 70, summary: 'No problems found.', findings: [], technical: ['OK']}))));
  h.$('fb-sod-check').click();
  await settle();
  assert.equal(h.$('fb-sod-check-status').textContent, 'No problems found.');
  assert.equal(h.$('fb-sod-check-out').querySelector('ul'), null);
  fail = true;
  h.$('fb-sod-check').click();
  await settle();
  assert.equal(h.$('fb-sod-check-status').textContent, 'Could not check separation of duties. Please try again.');
  assert.equal(h.$('fb-sod-check-out').textContent, '');
});
