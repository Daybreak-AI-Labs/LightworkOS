'use strict';
// Settings history shows readable changes. Live: every row ended with
// "Revision: <64 hex> to <64 hex>" in the visible text.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-settings-review.js'), 'utf8');
const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)); };
const BEFORE = '36f1490a4c272190bbd707eff8b31bdbaad9a803ab68fd1c035257dd8a238d1e';
const AFTER = 'a730f236477dad3bf65382a789e5a5f4cc95a704219102fc9cb4038977fc0605';

test('settings history keeps revision fingerprints out of the readable change', async t => {
  const dom = new JSDOM(`<body><section id="settings-tools"><p data-tools-status></p>
    <button type="button" data-history>View settings history</button><ol data-history-items></ol></section></body>`,
  {url: 'https://lightwork.invalid/settings/all', runScripts: 'outside-only'});
  const {window} = dom; t.after(() => window.close());
  window.mvFetchJSON = async () => ({revision: 'r', coverage: 'Last 100 setting changes in the past 30 days.', items: [
    {id: 'features.x', label: 'Shared decision reviews', actor: 'dana@northwind.example', at: '2026-11-18T15:10:00+00:00',
     before: 'On', after: 'Off', before_revision: BEFORE, after_revision: AFTER, restorable: false},
    {id: 'features.y', label: 'Share preparation safely', actor: 'Google account', at: '2026-11-18T15:07:00+00:00',
     before: 'Off', after: 'On', before_revision: null, after_revision: null, restorable: false}]});
  window.eval(script);
  window.document.querySelector('[data-history]').click(); await settle();
  const rows = window.document.querySelectorAll('[data-history-items] li');
  assert.equal(rows.length, 2);
  const readable = rows[0].querySelector('pre').textContent;
  assert.equal(readable, 'Before: On\nAfter: Off');
  const details = rows[0].querySelector('details');
  assert.ok(details && !details.open, 'the fingerprints sit behind a closed toggle');
  assert.match(details.textContent, /36f1490a…/);
  assert.match(details.textContent, /a730f236…/);
  assert.ok(!window.document.body.textContent.includes(BEFORE) && !window.document.body.textContent.includes(AFTER));
  assert.equal(rows[1].querySelector('details'), null, 'a legacy row has no fingerprints to show');
});
